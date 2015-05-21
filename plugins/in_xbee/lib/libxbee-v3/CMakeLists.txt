cmake_minimum_required(VERSION 2.6)
project(LIBXBEE C)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" )
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
endif()

# Definitions
add_definitions(-DLIBXBEE_BUILD)
add_definitions(-DLIB_REVISION="")
add_definitions(-DLIB_COMMIT="")
add_definitions(-DLIB_COMMITTER="")
add_definitions(-DLIB_BUILDTIME="")

# Subdirectory for xbeeZB mode
add_subdirectory(modes/net)
add_subdirectory(modes/debug)
add_subdirectory(modes/xbeeZB)

# XBee core sources
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

find_package(Threads)

# Linking...
add_library(xbee STATIC ${src})
target_link_libraries(xbee xbeeZB_mode xbeeNet_mode xbeeDebug_mode ${CMAKE_THREAD_LIBS_INIT} rt)
