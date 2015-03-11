cmake_minimum_required(VERSION 2.6)
project(LIBXBEE C)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

# General Headers
#include_directories(include/)

add_definitions(-DLIBXBEE_BUILD)
add_definitions(-DLIB_REVISION="")
add_definitions(-DLIB_COMMIT="")
add_definitions(-DLIB_COMMITTER="")
add_definitions(-DLIB_BUILDTIME="")
add_definitions(-DMODELIST="&mode_net, &mode_debug, &mode_xbeeZB")

add_subdirectory(modes/xbeeZB)

set(src
  conn.c
  frame.c
  log.c
  mutex.c
  net_callbacks.c
  net_io.c
  prepare.c
  thread.c
  ver.c
  xsys.c
  error.c
  ll.c
  mode.c
  net.c
  net_handlers.c
  pkt.c
  rx.c
  tx.c
  xbee.c
  )

add_library(xbee ${src})
target_link_libraries(xbee xbeeZB)
