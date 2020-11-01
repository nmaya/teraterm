/*
 * Copyright (C) 1994-1998 T. Teranishi
 * (C) 2006-2020 TeraTerm Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* TTFILE.DLL, XMODEM protocol */
#include "teraterm.h"
#include "tttypes.h"
#include <stdio.h>

#include "ttcommon.h"
#include "ttlib.h"
#include "ftlib.h"
#include "win16api.h"

#include "xmodem.h"

/* XMODEM */
typedef struct {
  BYTE PktIn[1030], PktOut[1030];
  int PktBufCount, PktBufPtr;
  BYTE PktNum, PktNumSent;
  int PktNumOffset;
  int PktReadMode;
  WORD XMode, XOpt, TextFlag;
  WORD NAKMode;
  int NAKCount;
  WORD DataLen, CheckLen;
  BOOL CRRecv;
  int TOutShort;
  int TOutLong;
  int TOutInit;
  int TOutInitCRC;
  int TOutVLong;
  int CANCount;
} TXVar;
typedef TXVar far *PXVar;

/* prototypes */

/* XMODEM states */
#define XpktSOH 1
#define XpktBLK 2
#define XpktBLK2 3
#define XpktDATA 4

#define XnakNAK 1
#define XnakC 2

BOOL XParse(PFileVarProto fv, PComVar cv);
void XTimeOutProc(PFileVarProto fv, PComVar cv);
void XCancel(PFileVarProto fv, PComVar cv);
static int SetOptV(PFileVarProto fv, int request, va_list ap);

static int XRead1Byte(PFileVarProto fv, PXVar xv, PComVar cv, LPBYTE b)
{
	if (CommRead1Byte(cv, b) == 0)
		return 0;

	if (fv->LogFlag) {
		if (fv->LogState == 0) {
			// 残りのASCII表示を行う
			fv->FlushLogLineBuf = 1;
			FTLog1Byte(fv, 0);
			fv->FlushLogLineBuf = 0;

			fv->LogState = 1;
			fv->LogCount = 0;
			_lwrite(fv->LogFile, "\015\012<<<\015\012", 7);
		}
		FTLog1Byte(fv, *b);
	}
	return 1;
}

static int XWrite(PFileVarProto fv, PXVar xv, PComVar cv, PCHAR B, int C)
{
	int i, j;

	i = CommBinaryOut(cv, B, C);
	if (fv->LogFlag && (i > 0)) {
		if (fv->LogState != 0) {
			// 残りのASCII表示を行う
			fv->FlushLogLineBuf = 1;
			FTLog1Byte(fv, 0);
			fv->FlushLogLineBuf = 0;

			fv->LogState = 0;
			fv->LogCount = 0;
			_lwrite(fv->LogFile, "\015\012>>>\015\012", 7);
		}
		for (j = 0; j <= i - 1; j++)
			FTLog1Byte(fv, B[j]);
	}
	return i;
}

static void XSetOpt(PFileVarProto fv, PXVar xv, WORD Opt)
{
	char Tmp[21];

	xv->XOpt = Opt;

	strncpy_s(Tmp, sizeof(Tmp), "XMODEM (", _TRUNCATE);
	switch (xv->XOpt) {
	case XoptCheck:			/* Checksum */
		strncat_s(Tmp, sizeof(Tmp), "checksum)", _TRUNCATE);
		xv->DataLen = 128;
		xv->CheckLen = 1;
		break;
	case XoptCRC:				/* CRC */
		strncat_s(Tmp, sizeof(Tmp), "CRC)", _TRUNCATE);
		xv->DataLen = 128;
		xv->CheckLen = 2;
		break;
	case Xopt1kCRC:				/* 1k */
		strncat_s(Tmp, sizeof(Tmp), "1k)", _TRUNCATE);
		xv->DataLen = 1024;
		xv->CheckLen = 2;
		break;
	case Xopt1kCksum:			/* 1k with Checksum (unofficial) */
		strncat_s(Tmp, sizeof(Tmp), "1k*)", _TRUNCATE);
		xv->DataLen = 1024;
		xv->CheckLen = 1;
		break;
	}
	fv->SetDlgProtoText(fv, Tmp);
}

static void XSendNAK(PFileVarProto fv, PXVar xv, PComVar cv)
{
	BYTE b;
	int t;

	/* flush comm buffer */
	cv->InBuffCount = 0;
	cv->InPtr = 0;

	xv->NAKCount--;
	if (xv->NAKCount < 0) {
		if (xv->NAKMode == XnakC) {
			XSetOpt(fv, xv, XoptCheck);
			xv->NAKMode = XnakNAK;
			xv->NAKCount = 9;
		} else {
			XCancel(fv, cv);
			return;
		}
	}

	if (xv->NAKMode == XnakNAK) {
		b = NAK;
		if ((xv->PktNum == 0) && (xv->PktNumOffset == 0))
			t = xv->TOutInit;
		else
			t = xv->TOutLong;
	} else {
		b = 'C';
		t = xv->TOutInitCRC;
	}
	XWrite(fv, xv, cv, &b, 1);
	xv->PktReadMode = XpktSOH;
	FTSetTimeOut(fv, t);
}

static WORD XCalcCheck(PXVar xv, PCHAR PktBuf)
{
	int i;
	WORD Check;

	if (xv->CheckLen == 1) {	/* CheckSum */
		/* Calc sum */
		Check = 0;
		for (i = 0; i <= xv->DataLen - 1; i++)
			Check = Check + (BYTE) (PktBuf[3 + i]);
		return (Check & 0xff);
	} else {					/* CRC */
		Check = 0;
		for (i = 0; i <= xv->DataLen - 1; i++)
			Check = UpdateCRC(PktBuf[3 + i], Check);
		return (Check);
	}
}

static BOOL XCheckPacket(PXVar xv)
{
	WORD Check;

	Check = XCalcCheck(xv, xv->PktIn);
	if (xv->CheckLen == 1)		/* Checksum */
		return ((BYTE) Check == xv->PktIn[xv->DataLen + 3]);
	else
		return ((HIBYTE(Check) == xv->PktIn[xv->DataLen + 3]) &&
				(LOBYTE(Check) == xv->PktIn[xv->DataLen + 4]));
}

void XInit(PFileVarProto fv, PComVar cv, PTTSet ts)
{
	PXVar xv = fv->data;
	fv->LogFlag = ((ts->LogFlag & LOG_X) != 0);
	if (fv->LogFlag)
		fv->LogFile = _lcreat("XMODEM.LOG", 0);
	fv->LogState = 0;
	fv->LogCount = 0;

	fv->FileSize = 0;
	if ((xv->XMode == IdXSend) && fv->FileOpen) {
		fv->FileSize = fv->GetFSize(fv, fv->FullName);
		fv->InitDlgProgress(fv, &fv->ProgStat);
	} else {
		fv->ProgStat = -1;
	}
	fv->StartTime = GetTickCount();

	SetWindowText(fv->HWin, fv->DlgCaption);
	fv->SetDlgProtoFileName(fv, &(fv->FullName[fv->DirLen]));

	xv->PktNumOffset = 0;
	xv->PktNum = 0;
	xv->PktNumSent = 0;
	xv->PktBufCount = 0;
	xv->CRRecv = FALSE;
	xv->CANCount = 0;

	fv->ByteCount = 0;

	xv->TOutInit = ts->XmodemTimeOutInit;
	xv->TOutInitCRC = ts->XmodemTimeOutInitCRC;
	xv->TOutVLong = ts->XmodemTimeOutVLong;

	if (cv->PortType == IdTCPIP) {
		xv->TOutShort = ts->XmodemTimeOutVLong;
		xv->TOutLong = ts->XmodemTimeOutVLong;
	} else {
		xv->TOutShort = ts->XmodemTimeOutShort;
		xv->TOutLong = ts->XmodemTimeOutLong;
	}

	XSetOpt(fv, xv, xv->XOpt);

	if (xv->XOpt == XoptCheck || xv->XOpt == Xopt1kCksum) {
		xv->NAKMode = XnakNAK;
		xv->NAKCount = 10;
	} else {
		xv->NAKMode = XnakC;
		xv->NAKCount = 3;
	}

	switch (xv->XMode) {
	case IdXSend:
		xv->TextFlag = 0;

		// ファイル送信開始前に、"rx ファイル名"を自動的に呼び出す。(2007.12.20 yutaka)
		if (ts->XModemRcvCommand[0] != '\0') {
			char inistr[MAX_PATH + 10];
			_snprintf_s(inistr, sizeof(inistr), _TRUNCATE, "%s %s\015",
						ts->XModemRcvCommand, &(fv->FullName[fv->DirLen]));
			FTConvFName(inistr + strlen(ts->XModemRcvCommand) + 1);
			XWrite(fv, xv, cv, inistr, strlen(inistr));
		}

		FTSetTimeOut(fv, xv->TOutVLong);
		break;
	case IdXReceive:
		XSendNAK(fv, xv, cv);
		break;
	}
}

void XCancel(PFileVarProto fv, PComVar cv)
{
	PXVar xv = fv->data;
	// five cancels & five backspaces per spec
	BYTE cancel[] = { CAN, CAN, CAN, CAN, CAN, BS, BS, BS, BS, BS };

	XWrite(fv,xv,cv, (PCHAR)&cancel, sizeof(cancel));
	xv->XMode = 0;				// quit
}

void XTimeOutProc(PFileVarProto fv, PComVar cv)
{
	PXVar xv = fv->data;
	switch (xv->XMode) {
	case IdXSend:
		xv->XMode = 0;			// quit
		break;
	case IdXReceive:
		XSendNAK(fv, xv, cv);
		break;
	}
}

static BOOL XReadPacket(PFileVarProto fv, PComVar cv)
{
	PXVar xv = fv->data;
	BYTE b, d;
	int i, c;
	BOOL GetPkt = FALSE;

	for (c=XRead1Byte(fv, xv, cv, &b); (c > 0) && !GetPkt; c=XRead1Byte(fv, xv, cv, &b)) {
		switch (xv->PktReadMode) {
		case XpktSOH:
			switch (b) {
			case SOH:
				xv->PktIn[0] = b;
				xv->PktReadMode = XpktBLK;
				if (xv->XOpt == Xopt1kCRC)
					XSetOpt(fv, xv, XoptCRC);
				else if (xv->XOpt == Xopt1kCksum)
					XSetOpt(fv, xv, XoptCheck);
				FTSetTimeOut(fv, xv->TOutShort);
				break;
			case STX:
				xv->PktIn[0] = b;
				xv->PktReadMode = XpktBLK;
				if (xv->XOpt == XoptCRC)
					XSetOpt(fv, xv, Xopt1kCRC);
				else if (xv->XOpt == XoptCheck)
					XSetOpt(fv, xv, Xopt1kCksum);
				FTSetTimeOut(fv, xv->TOutShort);
				break;
			case EOT:
				b = ACK;
				fv->Success = TRUE;
				XWrite(fv, xv, cv, &b, 1);
				return FALSE;
				break;
			case CAN:
				xv->CANCount++;
				if (xv->CANCount <= 2) {
					continue;
				}
				else {
					return FALSE;
				}
				break;
			default:
				/* flush comm buffer */
				cv->InBuffCount = 0;
				cv->InPtr = 0;
				return TRUE;
				break;
			}
			xv->CANCount = 0;
			break;
		case XpktBLK:
			xv->PktIn[1] = b;
			xv->PktReadMode = XpktBLK2;
			FTSetTimeOut(fv, xv->TOutShort);
			break;
		case XpktBLK2:
			xv->PktIn[2] = b;
			if ((b ^ xv->PktIn[1]) == 0xff) {
				xv->PktBufPtr = 3;
				xv->PktBufCount = xv->DataLen + xv->CheckLen;
				xv->PktReadMode = XpktDATA;
				FTSetTimeOut(fv, xv->TOutShort);
			} else
				XSendNAK(fv, xv, cv);
			break;
		case XpktDATA:
			xv->PktIn[xv->PktBufPtr] = b;
			xv->PktBufPtr++;
			xv->PktBufCount--;
			GetPkt = xv->PktBufCount == 0;
			if (GetPkt) {
				FTSetTimeOut(fv, xv->TOutLong);
				xv->PktReadMode = XpktSOH;
			} else
				FTSetTimeOut(fv, xv->TOutShort);
			break;
		}
	}

	if (!GetPkt)
		return TRUE;

	if ((xv->PktIn[1] == 0) && (xv->PktNum == 0) &&
		(xv->PktNumOffset == 0)) {
		if (xv->NAKMode == XnakNAK)
			xv->NAKCount = 10;
		else
			xv->NAKCount = 3;
		XSendNAK(fv, xv, cv);
		return TRUE;
	}

	GetPkt = XCheckPacket(xv);
	if (!GetPkt) {
		XSendNAK(fv, xv, cv);
		return TRUE;
	}

	d = xv->PktIn[1] - xv->PktNum;
	if (d > 1) {
		XCancel(fv, cv);
		return FALSE;
	}

	/* send ACK */
	b = ACK;
	XWrite(fv, xv, cv, &b, 1);
	xv->NAKMode = XnakNAK;
	xv->NAKCount = 10;

	if (d == 0)
		return TRUE;
	xv->PktNum = xv->PktIn[1];
	if (xv->PktNum == 0)
		xv->PktNumOffset = xv->PktNumOffset + 256;

	c = xv->DataLen;
	if (xv->TextFlag > 0)
		while ((c > 0) && (xv->PktIn[2 + c] == 0x1A))
			c--;

	if (xv->TextFlag > 0)
		for (i = 0; i <= c - 1; i++) {
			b = xv->PktIn[3 + i];
			if ((b == LF) && (!xv->CRRecv))
				fv->WriteFile(fv, "\015", 1);
			if (xv->CRRecv && (b != LF))
				fv->WriteFile(fv, "\012", 1);
			xv->CRRecv = b == CR;
			fv->WriteFile(fv, &b, 1);
	} else
		fv->WriteFile(fv, &(xv->PktIn[3]), c);

	fv->ByteCount = fv->ByteCount + c;

	fv->SetDlgPaketNum(fv, xv->PktNumOffset + xv->PktNum);
	fv->SetDlgByteCount(fv, fv->ByteCount);
	fv->SetDlgTime(fv, fv->StartTime, fv->ByteCount);

	FTSetTimeOut(fv, xv->TOutLong);

	return TRUE;
}

static BOOL XSendPacket(PFileVarProto fv, PComVar cv)
{
	PXVar xv = fv->data;
	BYTE b;
	int i;
	BOOL SendFlag;
	WORD Check;

	SendFlag = FALSE;
	if (xv->PktBufCount == 0) {
		for (i=XRead1Byte(fv, xv, cv, &b); !SendFlag; i=XRead1Byte(fv, xv, cv, &b)) {
			if (i == 0)
				return TRUE;
			switch (b) {
			case ACK:
				if (!fv->FileOpen) {
					fv->Success = TRUE;
					return FALSE;
				} else if (xv->PktNumSent == (BYTE) (xv->PktNum + 1)) {
					xv->PktNum = xv->PktNumSent;
					if (xv->PktNum == 0)
						xv->PktNumOffset = xv->PktNumOffset + 256;
					SendFlag = TRUE;
				}
				break;
			case NAK:
				if (xv->PktNum == 0 && xv->PktNumOffset == 0) {
					if (xv->XOpt == XoptCRC) {
						// receiver wants to use checksum.
						XSetOpt(fv, xv, XoptCheck);
					} else if (xv->XOpt == Xopt1kCRC) {
						/* we wanted 1k with CRC, but the other end specified checksum */
						/* keep the 1k block, but move back to checksum mode.          */
						XSetOpt(fv, xv, Xopt1kCksum);
					}
				}
				SendFlag = TRUE;
				break;
			case CAN:
				xv->CANCount++;
				if (xv->CANCount <= 2) {
					continue;
				}
				else {
					return FALSE;
				}
				break;
			case 0x43:
				if ((xv->PktNum == 0) && (xv->PktNumOffset == 0) && (xv->PktNumSent == 0)) {
					if ((xv->XOpt == XoptCheck)) {
						XSetOpt(fv, xv, XoptCRC);
					}
					else if ((xv->XOpt == Xopt1kCksum)) {
						XSetOpt(fv, xv, Xopt1kCRC);
					}
					SendFlag = TRUE;
				}
				break;
			}
			xv->CANCount = 0;
		}
		// reset timeout timer
		FTSetTimeOut(fv, xv->TOutVLong);

		do {
			i = XRead1Byte(fv, xv, cv, &b);
		} while (i != 0);

		if (xv->PktNumSent == xv->PktNum) {	/* make a new packet */
			xv->PktNumSent++;
			if (xv->DataLen == 128)
				xv->PktOut[0] = SOH;
			else
				xv->PktOut[0] = STX;
			xv->PktOut[1] = xv->PktNumSent;
			xv->PktOut[2] = ~xv->PktNumSent;

			i = 1;
			while ((i <= xv->DataLen) && fv->FileOpen &&
				   (fv->ReadFile(fv, &b, 1) == 1)) {
				xv->PktOut[2 + i] = b;
				i++;
				fv->ByteCount++;
			}

			if (i > 1) {
				while (i <= xv->DataLen) {
					xv->PktOut[2 + i] = 0x1A;
					i++;
				}

				Check = XCalcCheck(xv, xv->PktOut);
				if (xv->CheckLen == 1)	/* Checksum */
					xv->PktOut[xv->DataLen + 3] = (BYTE) Check;
				else {
					xv->PktOut[xv->DataLen + 3] = HIBYTE(Check);
					xv->PktOut[xv->DataLen + 4] = LOBYTE(Check);
				}
				xv->PktBufCount = 3 + xv->DataLen + xv->CheckLen;
			} else {			/* send EOT */
				if (fv->FileOpen) {
					fv->Close(fv);
					fv->FileHandle = 0;
					fv->FileOpen = FALSE;
				}
				xv->PktOut[0] = EOT;
				xv->PktBufCount = 1;
			}
		} else {				/* resend packet */
			if (xv->PktOut[0] == EOT) {
				xv->PktBufCount = 1;
			} else {
				xv->PktBufCount = 3 + xv->DataLen + xv->CheckLen;
			}
		}
		xv->PktBufPtr = 0;
	}
	/* a NAK or C could have arrived while we were buffering.  Consume it. */
	do {
		i = XRead1Byte(fv, xv, cv, &b);
	} while (i != 0);

	i = 1;
	while ((xv->PktBufCount > 0) && (i > 0)) {
		b = xv->PktOut[xv->PktBufPtr];
		i = XWrite(fv, xv, cv, &b, 1);
		if (i > 0) {
			xv->PktBufCount--;
			xv->PktBufPtr++;
		}
	}

	if (xv->PktBufCount == 0) {
		if (xv->PktNumSent == 0) {
			fv->SetDlgPaketNum(fv, xv->PktNumOffset + 256);
		}
		else {
			fv->SetDlgPaketNum(fv, xv->PktNumOffset + xv->PktNumSent);
		}
		fv->SetDlgByteCount(fv, fv->ByteCount);
		fv->SetDlgPercent(fv, fv->ByteCount, fv->FileSize, &fv->ProgStat);
		fv->SetDlgTime(fv, fv->StartTime, fv->ByteCount);
	}

	return TRUE;
}

BOOL XParse(PFileVarProto fv, PComVar cv)
{
	PXVar xv = fv->data;
	switch (xv->XMode) {
	case IdXReceive:
		return XReadPacket(fv,cv);
	case IdXSend:
		return XSendPacket(fv,cv);
	default:
		return FALSE;
	}
}

static int SetOptV(PFileVarProto fv, int request, va_list ap)
{
	PXVar xv = fv->data;
	switch(request) {
	case XMODEM_MODE: {
		int Mode = va_arg(ap, int);
		xv->XMode = Mode;
		return 0;
	}
	case XMODEM_OPT: {
		WORD Opt1 = va_arg(ap, WORD);
		xv->XOpt = Opt1;
		return 0;
	}
	case XMODEM_TEXT_FLAG: {
		WORD Opt2 = va_arg(ap, WORD);
		xv->TextFlag = 1 - (Opt2 & 1);
		return 0;
	}
	}
	return -1;
}

BOOL XCreate(PFileVarProto fv)
{
	PXVar xv;
	xv = malloc(sizeof(TXVar));
	if (xv == NULL) {
		return FALSE;
	}
	memset(xv, 0, sizeof(*xv));
	fv->data = xv;

	fv->Init = XInit;
	fv->Parse = XParse;
	fv->TimeOutProc = XTimeOutProc;
	fv->Cancel = XCancel;
	fv->SetOptV = SetOptV;

	return TRUE;
}
