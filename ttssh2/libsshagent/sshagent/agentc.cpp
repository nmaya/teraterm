/*
 * Copyright (C) 2023- TeraTerm Project
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

#include <stdio.h>
#include <stdlib.h>
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#include <stdint.h>
#include <assert.h>
#include <vector>
#include <windows.h>
#include <Lmcons.h>	// for UNLEN
#include "libputty.h"
#include "sha256.h"

#define PUTTY_SHM		1	// pageant shared memory
#define PUTTY_NAMEDPIPE	1	// pageant named pipe
#define MS_NAMEDPIPE	1	// Microsoft agent

// SSH Agent
//	Message numbers
//	https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-5.1

// requests from the client to the agent
#define SSH_AGENTC_REQUEST_IDENTITIES			11
#define SSH_AGENTC_SIGN_REQUEST					13
#define SSH_AGENTC_ADD_IDENTITY					17
#define SSH_AGENTC_REMOVE_IDENTITY				18
#define SSH_AGENTC_REMOVE_ALL_IDENTITIES		19
#define SSH_AGENTC_EXTENSION					27

// replies from the agent to the client
#define SSH_AGENT_FAILURE						5
#define SSH_AGENT_SUCCESS						6
#define SSH_AGENT_EXTENSION_FAILURE				28
#define SSH_AGENT_IDENTITIES_ANSWER				12
#define SSH_AGENT_SIGN_RESPONSE					14

#if MS_NAMEDPIPE
static const char ms_namedpipe[] = "\\\\.\\pipe\\openssh-ssh-agent";
#endif

static uint32_t get_uint32(const uint8_t *p)
{
	return (((uint32_t)p[3]		 ) | ((uint32_t)p[2] <<	 8) |
			((uint32_t)p[1] << 16) | ((uint32_t)p[0] << 24));
}

/**
 *	pageant の named pipe名の一部
 *	from putty windows/utils/cryptapi.c
 *
 *	@param		realname	元になる文字列
 *	@return		named pipe名の一部
 *				サインイン中は同一文字列が返る
 *				不要になったら free()
 *
 *	TODO
 *		CryptProtectMemory() API は比較的新しい Windows のみと思われる
 */
static char *capi_obfuscate_string(const char *realname)
{
	char *cryptdata;
	int cryptlen;
	unsigned char digest[32];
	char retbuf[65];
	int i;

	cryptlen = (int)(strlen(realname) + 1);
	cryptlen += CRYPTPROTECTMEMORY_BLOCK_SIZE - 1;
	cryptlen /= CRYPTPROTECTMEMORY_BLOCK_SIZE;
	cryptlen *= CRYPTPROTECTMEMORY_BLOCK_SIZE;

	cryptdata = (char *)malloc(cryptlen);
	memset(cryptdata, 0, cryptlen);
	memcpy(cryptdata, realname, strlen(realname));

	/*
	 * CRYPTPROTECTMEMORY_CROSS_PROCESS causes CryptProtectMemory to
	 * use the same key in all processes with this user id, meaning
	 * that the next PuTTY process calling this function with the same
	 * input will get the same data.
	 *
	 * (Contrast with CryptProtectData, which invents a new session
	 * key every time since its API permits returning more data than
	 * was input, so calling _that_ and hashing the output would not
	 * be stable.)
	 *
	 * We don't worry too much if this doesn't work for some reason.
	 * Omitting this step still has _some_ privacy value (in that
	 * another user can test-hash things to confirm guesses as to
	 * where you might be connecting to, but cannot invert SHA-256 in
	 * the absence of any plausible guess). So we don't abort if we
	 * can't call CryptProtectMemory at all, or if it fails.
	 */
	CryptProtectMemory(cryptdata, cryptlen,
					   CRYPTPROTECTMEMORY_CROSS_PROCESS);

	/*
	 * We don't want to give away the length of the hostname either,
	 * so having got it back out of CryptProtectMemory we now hash it.
	 */
	assert(cryptlen == 16);
	uint8_t buf[4+16] = {0};
	buf[3] = 0x10;	// = 0x00000010
	memcpy(&buf[4], cryptdata, cryptlen);
	sha256(&buf[0], sizeof(buf), digest);
	free(cryptdata);

	/*
	 * Finally, make printable.
	 */
	retbuf[0] = 0;
	for (i = 0; i < 32; i++) {
		char s[4];
		sprintf_s(s, "%02x", digest[i]);
		strcat_s(retbuf, s);
	}

	return _strdup(retbuf);
}

/**
 *	pagent named pipe名
 *	from putty windows/utils/agent_named_pipe_name.c
 */
static char *agent_named_pipe_name(void)
{
	char user_name[UNLEN+1];
	DWORD len = _countof(user_name);
	BOOL r = GetUserNameA(user_name, &len);
	if (r == 0) {
		return NULL;
	}
	char *suffix = capi_obfuscate_string("Pageant");
	// asprintf(&pipename, "\\\\.\\pipe\\pageant.%s.%s", user_name, suffix);
	const char *base = "\\\\.\\pipe\\pageant.";
	size_t pipe_len = strlen(base) + 2 + strlen(user_name) + strlen(suffix);
	char *pipename = (char *)malloc(pipe_len);
	strcpy_s(pipename, pipe_len, base);
	strcat_s(pipename, pipe_len, user_name);
	strcat_s(pipename, pipe_len, ".");
	strcat_s(pipename, pipe_len, suffix);
	free(suffix);
	return pipename;
}

/**
 *	バッファ操作
 */
class Buffer {
public:
	virtual ~Buffer() {
		clear();
	}
	size_t size() const
	{
		return buf_.size();
	}
	void clear()
	{
		size_t size = buf_.size();
		if (size > 0) {
			SecureZeroMemory(&buf_[0], buf_.size());
			buf_.clear();
		}
	}
	void *GetPtr() const
	{
		if (buf_.size() == 0) {
			return NULL;
		}
		return (void *)&buf_[0];
	}
	void AppendArray(const void *ptr, size_t len) {
		const uint8_t *u8ptr = (uint8_t *)ptr;
		buf_.insert(buf_.end(), &u8ptr[0], &u8ptr[len]);
	}
	void AppendByte(uint8_t u8)
	{
		buf_.push_back(u8);
	}
	void AppendUint32(uint32_t u32)
	{
		buf_.push_back((u32 >> (8*3)) & 0xff);
		buf_.push_back((u32 >> (8*2)) & 0xff);
		buf_.push_back((u32 >> (8*1)) & 0xff);
		buf_.push_back((u32 >> (8*0)) & 0xff);
	}
	/**
	 *	mallocした領域に内容をコピーして返す
	 */
	void *GetMallocdBuf(size_t *size)
	{
		size_t len = buf_.size();
		*size = len;
		void *p = NULL;
		if (len > 0) {
			p = malloc(len);
			memcpy(p, &buf_[0], len);
		}
		return p;
	}
	/**
	 *	バッファの先頭に追加する
	 */
	void PrependUint32(uint32_t u32)
	{
		Buffer new_buf;
		new_buf.AppendUint32(u32);
		new_buf.buf_.insert(new_buf.buf_.end(), buf_.begin(), buf_.end());
		buf_.swap(new_buf.buf_);
	}
private:
	std::vector<uint8_t> buf_;
};

/**
 *	agentと通信,named pipe経由
 *	RLogin CMainFrame::WageantQuery() MainFrm.cpp を参考にした
 */
#if PUTTY_NAMEDPIPE || MS_NAMEDPIPE
static BOOL QueryNamedPipe(const char *pipename, const Buffer &request, Buffer &reply)
{
	int n, len;
	BOOL bRet = FALSE;
	DWORD readByte = 0;

	HANDLE hPipe = CreateFileA(pipename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPipe == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	// リクエスト送信
	const BYTE *pBuffer = (BYTE *)request.GetPtr();
	DWORD BufLen = (DWORD)request.size();
	while (BufLen > 0) {
		DWORD writeByte;
		if (!WriteFile(hPipe, pBuffer, BufLen, &writeByte, NULL)) {
			// 書き込みエラーが起きた、通信中に agent が落ちた?
			goto ENDOFRET;
		}
		pBuffer += writeByte;
		BufLen -= writeByte;
	}

	// リプライ受信
	reply.clear();
	BYTE readBuffer[4096];
	if (ReadFile(hPipe, readBuffer, 4, &readByte, NULL) && readByte == 4) {
		len = (readBuffer[0] << 24) | (readBuffer[1] << 16) | (readBuffer[2] << 8) | (readBuffer[3]);
		reply.AppendArray(readBuffer, 4);
		if (len > 0 && len < AGENT_MAX_MSGLEN) {
			for (n = 0; n < len;) {
				if (!ReadFile(hPipe, readBuffer, 4096, &readByte, NULL)) {
					reply.clear();
					break;
				}
				reply.AppendArray(readBuffer, readByte);
				n += readByte;
			}
		}
	}

	if (reply.size() > 0)
		bRet = TRUE;

ENDOFRET:
	CloseHandle(hPipe);
	SecureZeroMemory(readBuffer, sizeof(readBuffer));
	return bRet;
}
#endif

/**
 *	agent(pageant)と通信,共有メモリ経由
 *
 *	@retval	FALSE	エラー
 */
#if PUTTY_SHM
static BOOL QuerySHM(const Buffer &request, Buffer &reply)
{
	HWND hwnd;
	char mapname[25];
	HANDLE fmap = NULL;
	unsigned char *p = NULL;
	unsigned long len;
	BOOL ret = FALSE;
	const uint8_t *in = (uint8_t *)request.GetPtr();

	reply.clear();

	if ((len = get_uint32(in)) > AGENT_MAX_MSGLEN) {
		goto agent_error;
	}

	hwnd = FindWindowA("Pageant", "Pageant");
	if (!hwnd) {
		goto agent_error;
	}

	sprintf(mapname, "PageantRequest%08x", (unsigned)GetCurrentThreadId());
	fmap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
							  0, AGENT_MAX_MSGLEN, mapname);
	if (!fmap) {
		goto agent_error;
	}

	if ((p = (unsigned char *)MapViewOfFile(fmap, FILE_MAP_WRITE, 0, 0, 0)) == NULL) {
		goto agent_error;
	}

	COPYDATASTRUCT cds;
#define AGENT_COPYDATA_ID 0x804e50ba	// ?
	cds.dwData = AGENT_COPYDATA_ID;
	cds.cbData = (DWORD)(strlen(mapname) + 1);
	cds.lpData = mapname;

	memcpy(p, in, len + 4);
	if (SendMessageA(hwnd, WM_COPYDATA, (WPARAM)NULL, (LPARAM)&cds) > 0) {
		// 応答があった
		len = get_uint32(p);
		reply.AppendArray(p, len+4);
		ret = TRUE;
	}

agent_error:
	if (p) {
		UnmapViewOfFile(p);
	}
	if (fmap) {
		CloseHandle(fmap);
	}
	if (ret == 0) {
		reply.AppendUint32(5);
		reply.AppendByte(SSH_AGENT_FAILURE);
		ret = FALSE;
	}

	return ret;
}
#endif

static BOOL Query(const Buffer &request, Buffer &reply)
{
	BOOL r;

	reply.clear();
#if PUTTY_NAMEDPIPE
	char *pname = agent_named_pipe_name();
	if (pname != NULL) {
		r = QueryNamedPipe(pname, request, reply);
		free(pname);
		if (r) {
			goto finish;
		}
	}
#endif
#if PUTTY_SHM
	r = QuerySHM(request, reply);
	if (r) {
		goto finish;
	}
#endif
#if MS_NAMEDPIPE
	r = QueryNamedPipe(ms_namedpipe, request, reply);
	if (r) {
		goto finish;
	}
#endif
finish:
	return r;
}

// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-4.4
int putty_get_ssh2_keylist(unsigned char **keylist)
{
	Buffer req;
	req.AppendUint32(1);
	req.AppendByte(SSH_AGENTC_REQUEST_IDENTITIES);

	Buffer rep;
	Query(req, rep);

	// check
	const uint8_t *reply_ptr = (uint8_t *)rep.GetPtr();
	uint32_t reply_len = get_uint32(reply_ptr);
	if (rep.size() != reply_len + 4 || reply_ptr[4] != SSH_AGENT_IDENTITIES_ANSWER) {
		*keylist = NULL;
		return 0;
	}

	uint32_t key_blob_len = reply_len - (4+1);
	uint8_t *key_blob_ptr = (uint8_t *)malloc(key_blob_len);
	memcpy(key_blob_ptr, reply_ptr + (4+1), key_blob_len);

	*keylist = key_blob_ptr;
	return key_blob_len;
}

void *putty_sign_ssh2_key(unsigned char *pubkey,
						  unsigned char *data,
						  int datalen,
						  int *outlen,
						  int signflags)
{
	int pubkeylen = get_uint32(pubkey);

	Buffer req;
	req.AppendByte(SSH_AGENTC_SIGN_REQUEST);
	req.AppendArray(pubkey, 4 + pubkeylen);
	req.AppendUint32(datalen);
	req.AppendArray(data, datalen);
	req.AppendUint32(signflags);
	req.PrependUint32((uint32_t)req.size());

	Buffer rep;
	Query(req, rep);
	const uint8_t *reply_ptr = (uint8_t *)rep.GetPtr();

	if (rep.size() < 5 || reply_ptr[4] != SSH_AGENT_SIGN_RESPONSE) {
		return NULL;
	}

	size_t signed_blob_len = rep.size() - (4+1);
	void *signed_blob_ptr = malloc(signed_blob_len);
	memcpy(signed_blob_ptr, reply_ptr + (4+1), signed_blob_len);
	if (outlen)
		*outlen = (int)signed_blob_len;
	return signed_blob_ptr;
}

int putty_get_ssh1_keylist(unsigned char **keylist)
{
	return 0;
}

void *putty_hash_ssh1_challenge(unsigned char *pubkey,
								int pubkeylen,
								unsigned char *data,
								int datalen,
								unsigned char *session_id,
								int *outlen)
{
	return NULL;
}

int putty_get_ssh1_keylen(unsigned char *key, int maxlen)
{
	return 0;
}

const char *putty_get_version()
{
	return "libsshagent 0.1";
}

void putty_agent_query_synchronous(const void *req_ptr, int req_len, void **rep_ptr, int *rep_len)
{
	Buffer request;
	request.AppendArray(req_ptr, req_len);
	Buffer reply;
	Query(request, reply);
	size_t len;
	*rep_ptr = reply.GetMallocdBuf(&len);
	*rep_len = (int)len;
}

#if PUTTY_NAMEDPIPE
static BOOL CheckPuttyAgentNamedPipe()
{
	char *pname = agent_named_pipe_name();
	DWORD r = GetFileAttributesA(pname);
	free(pname);
	return r != INVALID_FILE_ATTRIBUTES ? TRUE : FALSE;
}
#endif

#if MS_NAMEDPIPE
static BOOL CheckMSAgentNamedPipe()
{
	DWORD r = GetFileAttributesA(ms_namedpipe);
	return r != INVALID_FILE_ATTRIBUTES ? TRUE : FALSE;
}
#endif

BOOL putty_agent_exists()
{
#if PUTTY_NAMEDPIPE
	if (CheckPuttyAgentNamedPipe()) {
		return TRUE;
	}
#endif
#if PUTTY_SHM
	HWND hwnd = FindWindowA("Pageant", "Pageant");
	if (hwnd) {
		return TRUE;
	}
#endif
#if MS_NAMEDPIPE
	if (CheckMSAgentNamedPipe()) {
		return TRUE;
	}
#endif
	return FALSE;
}

void safefree(void *p)
{
	free(p);
}
