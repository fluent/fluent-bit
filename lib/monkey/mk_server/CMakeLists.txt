set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(src
  monkey.c
  mk_lib.c
  mk_fifo.c
  mk_mimetype.c
  mk_vhost.c
  mk_header.c
  mk_config.c
  mk_user.c
  mk_utils.c
  mk_stream.c
  mk_scheduler.c
  mk_http.c
  mk_http_parser.c
  mk_http_thread.c
  mk_socket.c
  mk_net.c
  mk_clock.c
  mk_cache.c
  mk_server.c
  mk_kernel.c
  mk_plugin.c
  )

if(MK_HTTP2)
  set(src
    ${src}
    "mk_http2.c"
    )
endif()

# Always build a static library, thats our core :)
add_library(monkey-core-static STATIC ${src})
set_target_properties(monkey-core-static PROPERTIES OUTPUT_NAME monkey)
target_link_libraries(monkey-core-static mk_core ${CMAKE_THREAD_LIBS_INIT} ${STATIC_PLUGINS_LIBS} ${CMAKE_DL_LIBS} rbtree co)

message(STATUS "LINKING ${STATIC_PLUGINS_LIBS}")

if(NOT DEFINED MK_HAVE_REGEX)
 target_link_libraries(monkey-core-static regex)
endif()

# Linux Kqueue emulation
if(MK_HAVE_LINUX_KQUEUE)
  target_link_libraries(monkey-core-static kqueue)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "SunOS")
  target_link_libraries(monkey-core-static socket nsl)
endif()
