cmake_minimum_required(VERSION 3.11)
project(libsshagent)

# OFFのときputty の sshagent通信を使用
option(SSHAGENT_SKELTON "use skelton" OFF)

if(SSHAGENT_SKELTON)
  add_subdirectory(skelton)
else()
  add_subdirectory(putty)
endif()

# for debug/test
#add_subdirectory(sshagent_tool)
