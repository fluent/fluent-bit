add_definitions(-DFLB_CORE=1)

# Core Source
set(src
  ${src}
  flb_mp.c
  flb_kv.c
  flb_api.c
  flb_lib.c
  flb_log.c
  flb_env.c
  flb_uri.c
  flb_hash.c
  flb_pack.c
  flb_pack_gelf.c
  flb_sds.c
  flb_pipe.c
  flb_meta.c
  flb_kernel.c
  flb_input.c
  flb_input_chunk.c
  flb_filter.c
  flb_output.c
  flb_config.c
  flb_config_map.c
  flb_socket.c
  flb_network.c
  flb_utils.c
  flb_slist.c
  flb_engine.c
  flb_engine_dispatch.c
  flb_task.c
  flb_unescape.c
  flb_scheduler.c
  flb_io.c
  flb_storage.c
  flb_upstream.c
  flb_upstream_ha.c
  flb_upstream_node.c
  flb_router.c
  flb_worker.c
  flb_thread.c
  flb_time.c
  flb_sosreport.c
  flb_sha512.c
  flb_random.c
  flb_plugin.c
  flb_gzip.c
  flb_http_client.c
  flb_callback.c
  flb_strptime.c
  flb_fstore.c
  )

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
set(src
  ${src}
  flb_dlfcn_win32.c
  )
endif()

if(FLB_PARSER)
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
    "flb_oauth2.c"
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

if(FLB_SIGNV4 AND FLB_TLS)
  set(src
    ${src}
    "flb_signv4.c"
    )
endif()

if(FLB_HTTP_CLIENT_DEBUG)
  set(src
    ${src}
    "flb_http_client_debug.c"
     )
endif()

if(FLB_AWS)
  set(src
    ${src}
    "aws/flb_aws_util.c"
    "aws/flb_aws_credentials.c"
    "aws/flb_aws_credentials_sts.c"
    "aws/flb_aws_credentials_ec2.c"
    "aws/flb_aws_credentials_http.c"
    "aws/flb_aws_credentials_profile.c"
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

set(extra_libs
  ${extra_libs}
  "rbtree")

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
    "crypt32.lib"
    "Bcrypt.lib"
    )
else()
  set(FLB_DEPS
    ${FLB_DEPS}
    ${CMAKE_DL_LIBS}
    m
    )
endif()

# Link timer library
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(FLB_DEPS
    ${FLB_DEPS}
    rt
    )
endif()


# Record Accessor
# ---------------
# Make sure it dependency is enabled
if(FLB_RECORD_ACCESSOR AND NOT FLB_REGEX)
  message(FATAL_ERROR
    "FLB_RECORD_ACCESSOR depends on FLB_REGEX, "
    "enable it with: -DFLB_REGEX=ON")
endif()

# Build record accessor files
if(FLB_RECORD_ACCESSOR)
  set(src
    ${src}
    "flb_record_accessor.c"
    "flb_ra_key.c"
    )
  add_subdirectory(record_accessor)
endif()

# Stream Processor
if(FLB_STREAM_PROCESSOR)
  add_subdirectory(stream_processor)
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
  msgpack-c-static
  mpack-static
  chunkio-static
  miniz
  xxhash
  ${FLB_PLUGINS}
  ${FLB_PROXY_PLUGINS}
  ${extra_libs}
  )

# UTF8 Encoding
if(FLB_UTF8_ENCODER)
set(FLB_DEPS
  ${FLB_DEPS}
  tutf8e
  )
endif()

# Record Accessor
if(FLB_RECORD_ACCESSOR)
  set(FLB_DEPS
    ${FLB_DEPS}
    flb-ra-parser
    )
endif()

# Stream Processor
if(FLB_STREAM_PROCESSOR)
  set(FLB_DEPS
    ${FLB_DEPS}
    flb-sp
    )
endif()

# Shared Library
if(FLB_SHARED_LIB)
  add_library(fluent-bit-shared SHARED ${src})
  add_sanitizers(fluent-bit-shared)
  set_target_properties(fluent-bit-shared
    PROPERTIES OUTPUT_NAME fluent-bit)

  # Windows doesn't provide pthread (see winpthreads.c in mk_core).
  if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    target_link_libraries(fluent-bit-shared ${FLB_DEPS})
  else()
    target_link_libraries(fluent-bit-shared ${FLB_DEPS} -lpthread)
  endif()

  if (MSVC)
    set_target_properties(fluent-bit-shared
      PROPERTIES PDB_NAME fluent-bit.dll)
    target_link_options(fluent-bit-shared
      PUBLIC /pdb:$<TARGET_PDB_FILE:fluent-bit-shared>)
  endif()

  # Library install routines
  install(TARGETS fluent-bit-shared
    LIBRARY DESTINATION ${FLB_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${FLB_INSTALL_BINDIR})
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
  if (FLB_SYSTEM_WINDOWS)
    add_executable(fluent-bit-bin fluent-bit.c flb_dump.c win32/winsvc.c)
  else()
    add_executable(fluent-bit-bin fluent-bit.c flb_dump.c)
  endif()
  add_sanitizers(fluent-bit-bin)


  if(FLB_STATIC_CONF)
    add_dependencies(fluent-bit-bin flb-static-conf)
  endif()

  if(FLB_REGEX)
    target_link_libraries(fluent-bit-bin libonigmo)
  endif()

  if(FLB_JEMALLOC)
    target_link_libraries(fluent-bit-bin libjemalloc)
  endif()

  if(FLB_BACKTRACE)
    add_definitions(-DFLB_DUMP_STACKTRACE=1)
    target_link_libraries(fluent-bit-bin libbacktrace)
  endif()

  target_link_libraries(fluent-bit-bin fluent-bit-static ${CMAKE_THREAD_LIBS_INIT})

  set_target_properties(fluent-bit-bin
    PROPERTIES
    OUTPUT_NAME ${FLB_OUT_NAME}
    ENABLE_EXPORTS ON)
  install(TARGETS fluent-bit-bin RUNTIME DESTINATION ${FLB_INSTALL_BINDIR})

  # Include PDB file (if available)
  if (MSVC)
    target_link_options(fluent-bit-bin
      PUBLIC /pdb:$<TARGET_PDB_FILE:fluent-bit-bin>)
    install(FILES $<TARGET_PDB_FILE:fluent-bit-bin>
      DESTINATION "${FLB_INSTALL_BINDIR}")
  endif()

  # Detect init system, install upstart, systemd or init.d script
  if(IS_DIRECTORY /lib/systemd/system)
    set(FLB_SYSTEMD_SCRIPT "${PROJECT_SOURCE_DIR}/init/${FLB_OUT_NAME}.service")
    configure_file(
      "${PROJECT_SOURCE_DIR}/init/systemd.in"
      ${FLB_SYSTEMD_SCRIPT}
      )
    install(FILES ${FLB_SYSTEMD_SCRIPT} DESTINATION /lib/systemd/system)
    install(DIRECTORY DESTINATION ${FLB_INSTALL_CONFDIR})
  elseif(IS_DIRECTORY /usr/share/upstart)
    set(FLB_UPSTART_SCRIPT "${PROJECT_SOURCE_DIR}/init/${FLB_OUT_NAME}.conf")
    configure_file(
      "${PROJECT_SOURCE_DIR}/init/upstart.in"
      ${FLB_UPSTART_SCRIPT}
      )
    install(FILES ${FLB_UPSTART_SCRIPT} DESTINATION /etc/init)
    install(DIRECTORY DESTINATION ${FLB_INSTALL_CONFDIR})
  else()
    # FIXME: should we support Sysv init script ?
  endif()

  install(FILES
    "${PROJECT_SOURCE_DIR}/conf/fluent-bit.conf"
    DESTINATION ${FLB_INSTALL_CONFDIR}
    RENAME "${FLB_OUT_NAME}.conf")

  install(FILES
    "${PROJECT_SOURCE_DIR}/conf/parsers.conf"
    DESTINATION ${FLB_INSTALL_CONFDIR})

  install(FILES
    "${PROJECT_SOURCE_DIR}/conf/plugins.conf"
    DESTINATION ${FLB_INSTALL_CONFDIR})

endif()
