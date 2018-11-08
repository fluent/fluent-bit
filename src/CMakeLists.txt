add_definitions(-DFLB_CORE=1)

# Core Source
set(src
  ${src}
  flb_mp.c
  flb_api.c
  flb_lib.c
  flb_log.c
  flb_env.c
  flb_uri.c
  flb_hash.c
  flb_pack.c
  flb_sds.c

  flb_sha1.c
  flb_pipe.c
  flb_meta.c
  flb_kernel.c
  flb_input.c
  flb_filter.c
  flb_output.c
  flb_config.c
  flb_network.c
  flb_utils.c
  flb_engine.c
  flb_engine_dispatch.c
  flb_task.c
  flb_unescape.c
  flb_scheduler.c
  flb_io.c
  flb_upstream.c
  flb_upstream_ha.c
  flb_upstream_node.c
  flb_router.c
  flb_oauth2.c
  flb_http_client.c
  flb_worker.c
  flb_time.c
  flb_sosreport.c
  )

include_directories(
  .
  ../lib/
  ../lib/jsmn
  ../lib/msgpack-c-0b7cabd/include
  ../lib/monkey/include/
  ../lib/luajit-2.0.5/src/
  ${extra_headers}
  )

if(FLB_REGEX)
  set(src
    ${src}
    flb_parser.c
    flb_parser_regex.c
    flb_parser_json.c
    flb_parser_decoder.c
    flb_parser_ltsv.c
    flb_parser_logfmt.c
    )
endif()

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

if(FLB_PROXY_GO)
  set(src
    ${src}
    "flb_plugin_proxy.c"
    )
endif()

if(FLB_METRICS)
  set(src
    ${src}
    "flb_metrics.c"
    "flb_metrics_exporter.c"
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

if(FLB_LUAJIT)
  set(src
    ${src}
    "flb_luajit.c"
    )
endif()

# Link to libco
set(extra_libs
  ${extra_libs}
  "co")

if(FLB_JEMALLOC)
  set(extra_libs
    ${extra_libs}
    "libjemalloc")
endif()

if(FLB_REGEX)
  set(extra_libs
    ${extra_libs}
    "libonigmo")
  set(src
    ${src}
    "flb_regex.c"
    )
endif()

if(FLB_LUAJIT)
  set(extra_libs
    ${extra_libs}
    "libluajit")
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

if(FLB_STATIC_CONF)
  set(src
    ${src}
    "flb_config_static.c"
    )
endif()

include(CheckSymbolExists)
check_symbol_exists(accept4 "sys/socket.h" HAVE_ACCEPT4)

# Core dependencies
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  set(FLB_DEPS
    "ws2_32.lib"
    )
else()
  set(FLB_DEPS
    ${FLB_DEPS}
    ${CMAKE_DL_LIBS}
    m
    )
endif()

# Link timer library
if(NOT CMAKE_SYSTEM_NAME MATCHES "Darwin")
  set(FLB_DEPS
    ${FLB_DEPS}
    rt
    )
endif()

# HTTP Server
if(FLB_HTTP_SERVER)
  add_subdirectory(http_server)
endif()

# Proxy interfaces
add_subdirectory(proxy)

set(FLB_PROXY_PLUGINS "")
if(FLB_PROXY_GO)
  set(FLB_PROXY_PLUGINS ${FLB_PROXY_PLUGINS} flb-plugin-proxy-go)
endif()

# HTTP Server
if(FLB_HTTP_SERVER)
  set(FLB_DEPS
    ${FLB_DEPS}
    flb-http-server)
endif()


# Set static dependencies
set(FLB_DEPS
  ${FLB_DEPS}
  mk_core
  jsmn
  msgpackc-static
  ${FLB_PLUGINS}
  ${FLB_PROXY_PLUGINS}
  ${extra_libs}
  )

# Shared Library
if(FLB_SHARED_LIB)
  add_library(fluent-bit-shared SHARED ${src})
  add_sanitizers(fluent-bit-shared)
  target_link_libraries(fluent-bit-shared ${FLB_DEPS} -lpthread)
  set_target_properties(fluent-bit-shared
    PROPERTIES OUTPUT_NAME fluent-bit)

  # Library install routines
  install(TARGETS fluent-bit-shared LIBRARY DESTINATION lib)
endif()

# Static Library
add_library(fluent-bit-static STATIC ${src})
add_sanitizers(fluent-bit-static)
target_link_libraries(fluent-bit-static ${FLB_DEPS})

if(MSVC)
  # Rename the output for Windows environment to avoid naming issues
  set_target_properties(fluent-bit-static PROPERTIES OUTPUT_NAME libfluent-bit)
else()
  set_target_properties(fluent-bit-static PROPERTIES OUTPUT_NAME fluent-bit)
endif(MSVC)

if(FLB_JEMALLOC)
  target_link_libraries(fluent-bit-static libjemalloc)
endif()

# Binary / Executable
if(FLB_BINARY)
  find_package (Threads)
  add_executable(fluent-bit-bin fluent-bit.c)
  add_sanitizers(fluent-bit-bin)

  if(FLB_STATIC_CONF)
    add_dependencies(fluent-bit-bin flb-static-conf)
  endif()

  if(FLB_JEMALLOC)
    target_link_libraries(fluent-bit-bin libjemalloc)
  endif()

  if(FLB_BACKTRACE)
    target_link_libraries(fluent-bit-bin libbacktrace)
  endif()

  target_link_libraries(fluent-bit-bin fluent-bit-static ${CMAKE_THREAD_LIBS_INIT})

  set_target_properties(fluent-bit-bin
    PROPERTIES
    OUTPUT_NAME ${FLB_OUT_NAME}
    ENABLE_EXPORTS ON)
  install(TARGETS fluent-bit-bin RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})

  # Detect init system, install upstart, systemd or init.d script
  if(IS_DIRECTORY /usr/share/upstart)
    set(FLB_UPSTART_SCRIPT "${PROJECT_SOURCE_DIR}/init/${FLB_OUT_NAME}.conf")
    configure_file(
      "${PROJECT_SOURCE_DIR}/init/upstart.in"
      ${FLB_UPSTART_SCRIPT}
      )
    install(FILES ${FLB_UPSTART_SCRIPT} DESTINATION /etc/init)
    install(DIRECTORY DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}${FLB_OUT_NAME}/")
  elseif(IS_DIRECTORY /lib/systemd/system)
    set(FLB_SYSTEMD_SCRIPT "${PROJECT_SOURCE_DIR}/init/${FLB_OUT_NAME}.service")
    configure_file(
      "${PROJECT_SOURCE_DIR}/init/systemd.in"
      ${FLB_SYSTEMD_SCRIPT}
      )
    install(FILES ${FLB_SYSTEMD_SCRIPT} DESTINATION /lib/systemd/system)
    install(DIRECTORY DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}${FLB_OUT_NAME}/")
  else()
    # FIXME: should we support Sysv init script ?
  endif()

  install(FILES
    "${PROJECT_SOURCE_DIR}/conf/fluent-bit.conf"
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/${FLB_OUT_NAME}/"
    RENAME "${FLB_OUT_NAME}.conf")

  install(FILES
    "${PROJECT_SOURCE_DIR}/conf/parsers.conf"
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/${FLB_OUT_NAME}/")

endif()
