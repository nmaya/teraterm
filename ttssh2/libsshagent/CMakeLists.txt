cmake_minimum_required(VERSION 3.11)
project(libsshagent)

# どの libsshagent を使用するか
#  すべて OFF の時、従来と同じ putty を使用する
option(SSHAGENT_SKELTON "use skelton" OFF)
option(SSHAGENT_NEXT "use next sshagent" OFF)

if(SSHAGENT_NEXT)
  add_subdirectory(sshagent)
elseif(SSHAGENT_SKELTON)
  add_subdirectory(skelton)
else()
  add_subdirectory(putty)
endif()

# for debug/test
#add_subdirectory(sshagent_tool)
