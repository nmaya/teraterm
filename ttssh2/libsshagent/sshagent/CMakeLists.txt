set(PACKAGE_NAME "libsshagent")

project(${PACKAGE_NAME})

add_library(
  ${PACKAGE_NAME}
  ../libputty.h
  agentc.cpp
  sha256.cpp
  sha256.h
)

target_include_directories(
  ${PACKAGE_NAME}
  PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/..
)

target_link_libraries(
  ${PACKAGE_NAME}
  PRIVATE
  crypt32
)
