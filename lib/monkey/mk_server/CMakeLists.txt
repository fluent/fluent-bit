set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

set(src
  monkey.c
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
  mk_socket.c
  mk_clock.c
  mk_cache.c
  mk_server.c
  mk_kernel.c
  mk_plugin.c
  )

# Always build a static library, thats our core :)
add_library(monkey-core-static STATIC ${src})
set_target_properties(monkey-core-static PROPERTIES OUTPUT_NAME monkey)
target_link_libraries(monkey-core-static mk_core ${CMAKE_THREAD_LIBS_INIT} ${STATIC_PLUGINS_LIBS} ${CMAKE_DL_LIBS})

# Linux Kqueue emulation
if(WITH_LINUX_KQUEUE)
  target_link_libraries(monkey-core-static kqueue)
endif()
