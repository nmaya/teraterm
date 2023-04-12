set(PACKAGE_NAME "libsshagent")

project(${PACKAGE_NAME})

add_library(
  ${PACKAGE_NAME}
  ../libputty.h
  skelton.c
)

target_include_directories(
  ${PACKAGE_NAME}
  PRIVATE
  ..
)
