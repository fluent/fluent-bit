set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

set(src
  ${src}
  flb_lib.c
  flb_log.c
  flb_uri.c
  flb_pack.c
  flb_sha1.c
  flb_kernel.c
  flb_input.c
  flb_output.c
  flb_config.c
  flb_network.c
  flb_utils.c
  flb_engine.c
  flb_engine_dispatch.c
  flb_task.c
  flb_scheduler.c
  flb_io.c
  flb_upstream.c
  flb_router.c
  flb_http_client.c
  flb_worker.c
  flb_plugin_proxy.c
  )

include_directories(
  .
  ../lib/
  ../lib/jsmn
  ../lib/msgpack-c-068041f/include
  ../lib/monkey/include/
  ${extra_headers}
  )

# Fluent Bit have TLS support
if(FLB_TLS)
  # Register the TLS interface and functions
  set(src
    ${src}
    "flb_io_tls.c"
    )

  # Make sure our output targets links to the TLS library
  set(extra_libs
    ${extra_libs}
    "mbedtls"
    )
endif()

if(FLB_HTTP)
  set(src
    ${src}
    "flb_http_server.c"
    )
endif()

if(FLB_STATS)
  set(src
    ${src}
    "flb_stats.c"
    )
  set(extra_libs
    ${extra_libs}
    "cJSON"
    "m"
    )
endif()

if(FLB_BUFFERING)
  set(src
    ${src}
    "flb_buffer.c"
    "flb_buffer_chunk.c"
    "flb_buffer_qchunk.c"
    )
endif()

if(FLB_FLUSH_LIBCO)
  set(extra_libs
    ${extra_libs}
    "co")
endif()

if(FLB_JEMALLOC)
  set(extra_libs
    ${extra_libs}
    "libjemalloc")
endif()

if(FLB_SQLDB)
  set(src
    ${src}
    "flb_sqldb.c"
    )
  set(extra_libs
    ${extra_libs}
    "sqlite3")
endif()

include(CheckSymbolExists)
check_symbol_exists(accept4 "sys/socket.h" HAVE_ACCEPT4)

# Core dependencies
set(FLB_DEPS
  mk_core
  jsmn
  msgpackc-static
  dl
  ${FLB_PLUGINS}
  ${extra_libs}
  )

set(FLB_PROXY_PLUGINS "")
if(FLB_PROXY_GO)
  set(FLB_PROXY_PLUGINS ${FLB_PROXY_PLUGINS} flb-plugin-proxy-go)
endif()

# Static Library
add_library(fluent-bit-static STATIC ${src})
target_link_libraries(fluent-bit-static ${FLB_DEPS} ${FLB_PROXY_PLUGINS})

set_target_properties(fluent-bit-static PROPERTIES OUTPUT_NAME fluent-bit)

if(FLB_JEMALLOC)
  target_link_libraries(fluent-bit-static libjemalloc)
endif()

if(FLB_HTTP)
  target_link_libraries(fluent-bit-static monkey-core-static ejson)
endif()

if(FLB_BUFFERING)
  target_link_libraries(fluent-bit-static sha1)
endif()

# Process Proxies
add_subdirectory(proxy)

# Executable
if(NOT FLB_WITHOUT_BIN)
  find_package (Threads)
  add_executable(fluent-bit-bin fluent-bit.c)

  if(FLB_JEMALLOC)
    target_link_libraries(fluent-bit-bin libjemalloc)
  endif()

  target_link_libraries(fluent-bit-bin fluent-bit-static ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

  target_link_libraries(fluent-bit-bin ${FLB_PROXY_PLUGINS})
  set_target_properties(fluent-bit-bin
    PROPERTIES
    OUTPUT_NAME ${FLB_OUT_NAME}
    ENABLE_EXPORTS ON)
  install(TARGETS fluent-bit-bin RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})

  # Detect init system, install systemd or init.d script
  if(IS_DIRECTORY /lib/systemd/system)
    set(FLB_SYSTEMD_SCRIPT "${PROJECT_SOURCE_DIR}/init/${FLB_OUT_NAME}.service")
    configure_file(
      "${PROJECT_SOURCE_DIR}/init/systemd.in"
      ${FLB_SYSTEMD_SCRIPT}
      )
    install(FILES ${FLB_SYSTEMD_SCRIPT} DESTINATION /lib/systemd/system)
    install(DIRECTORY DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/${FLB_OUT_NAME}/")
  else()
    # FIXME: should we support Sysv init script ?
  endif()

  install(FILES
    "${PROJECT_SOURCE_DIR}/conf/fluent-bit.conf"
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/${FLB_OUT_NAME}/"
    RENAME "${FLB_OUT_NAME}.conf")
endif()
