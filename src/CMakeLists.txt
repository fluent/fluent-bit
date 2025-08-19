add_definitions(-DFLB_CORE=1)

# Core Source
set(src
  ${src}
  flb_mp.c
  flb_kv.c
  flb_api.c
  flb_csv.c
  flb_lib.c
  flb_log.c
  flb_env.c
  flb_file.c
  flb_uri.c
  flb_utf8.c
  flb_hash_table.c
  flb_help.c
  flb_pack.c
  flb_pack_json.c
  flb_pack_gelf.c
  flb_sds.c
  flb_sds_list.c
  flb_pipe.c
  flb_meta.c
  flb_kernel.c
  flb_custom.c
  flb_input.c
  flb_input_chunk.c
  flb_input_log.c
  flb_input_metric.c
  flb_input_trace.c
  flb_input_profiles.c
  flb_input_blob.c
  flb_input_thread.c
  flb_filter.c
  flb_output.c
  flb_output_thread.c
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
  flb_connection.c
  flb_downstream.c
  flb_upstream.c
  flb_upstream_ha.c
  flb_upstream_node.c
  flb_router.c
  flb_worker.c
  flb_coro.c
  flb_time.c
  flb_sosreport.c
  flb_hmac.c
  flb_hash.c
  flb_crypto.c
  flb_random.c
  flb_plugin.c
  flb_gzip.c
  flb_snappy.c
  flb_zstd.c
  flb_compression.c
  flb_http_common.c
  flb_http_client_http1.c
  flb_http_client_http2.c
  flb_http_client.c
  flb_callback.c
  flb_strptime.c
  flb_fstore.c
  flb_thread_pool.c
  flb_routes_mask.c
  flb_typecast.c
  flb_event.c
  flb_base64.c
  flb_ring_buffer.c
  flb_log_event_decoder.c
  flb_log_event_encoder.c
  flb_log_event_encoder_primitives.c
  flb_log_event_encoder_dynamic_field.c
  flb_processor.c
  flb_reload.c
  flb_supervisor.c
  flb_msgpack_append_message.c
  flb_notification.c
  flb_lock.c
  flb_cfl_ra_key.c
  flb_cfl_record_accessor.c
  flb_conditionals.c
  flb_mem.c
  flb_blob_db.c
  )

# Config format
set(src
  ${src}
  config_format/flb_config_format.c
  config_format/flb_cf_fluentbit.c
)
if(FLB_HAVE_LIBYAML)
  set(src
    ${src}
    config_format/flb_cf_yaml.c
    )
endif()

# OpenTelemetry Helpers
set(src
  ${src}
  opentelemetry/flb_opentelemetry_logs.c
  opentelemetry/flb_opentelemetry_utils.c
)

# Multiline subsystem
add_subdirectory(multiline)
set(src
  ${src}
  ${src_multiline}
  )

if(FLB_SYSTEM_WINDOWS)
  set(src
    ${src}
    flb_dlfcn_win32.c
    )
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W2")
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

if(FLB_AVRO_ENCODER)
  set(src
    ${src}
    flb_avro.c
    )
endif()

# Fluent Bit have TLS support
if(FLB_TLS)
  # Register the TLS interface and functions
  set(src
    ${src}
    "tls/flb_tls.c"
    "flb_oauth2.c"
    )

  # Make sure our output targets links to the TLS library
  set(extra_libs
    ${extra_libs}
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
    "flb_signv4_ng.c"
    )
endif()

if(FLB_HTTP_CLIENT_DEBUG)
  set(src
    ${src}
    "flb_http_client_debug.c"
     )
endif()

if (FLB_AWS_ERROR_REPORTER)
  set(src
    ${src}
    "aws/flb_aws_error_reporter.c"
    )
endif()

if(FLB_LUAJIT)
  set(src
    ${src}
    "flb_lua.c"
    "flb_luajit.c"
    )
endif()

if(FLB_KAFKA)
  set(src
    ${src}
    "flb_kafka.c"
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
    ${JEMALLOC_LIBRARIES})
endif()

if(FLB_REGEX)
  set(FLB_DEPS
    ${FLB_DEPS}
    onigmo-static)
  set(src
    ${src}
    "flb_regex.c"
    )
endif()

if(FLB_LUAJIT)
  set(extra_libs
    ${extra_libs}
    ${LUAJIT_LIBRARIES})
endif()

if(FLB_SQLDB)
  set(src
    ${src}
    "flb_sqldb.c"
    )
  set(extra_libs
    ${extra_libs}
    ${SQLITE_LIBRARIES})
endif()

if(FLB_STATIC_CONF)
  set(src
    ${src}
    "flb_config_static.c"
    )
endif()

if(FLB_CHUNK_TRACE)
  set(src
    ${src}
    "flb_chunk_trace.c"
    )
endif()

include(CheckSymbolExists)
check_symbol_exists(accept4 "sys/socket.h" HAVE_ACCEPT4)

# Core dependencies
if(FLB_SYSTEM_WINDOWS)
  set(FLB_DEPS
    "ws2_32.lib"
    "crypt32.lib"
    "Bcrypt.lib"
    "Shlwapi.lib"
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

if(FLB_SYSTEM_MACOS)
  set(FLB_DEPS
    ${FLB_DEPS}
    "-framework Foundation"
    "-framework IOKit"
    "-framework Security"
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

# AWS specific
if(FLB_AWS)
  add_subdirectory(aws)
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

# WASM runtime
if(FLB_WASM)
  add_subdirectory(wasm)
endif()

if(FLB_UNICODE_ENCODER)
  add_subdirectory(simdutf)
endif()

# WAMRC compiler
if(FLB_WAMRC)
  add_subdirectory(wamrc)
endif()

# HTTP Server
if(FLB_HTTP_SERVER)
  set(FLB_DEPS
    ${FLB_DEPS}
    flb-http-server)
endif()

# AVRO Encoding
if(FLB_AVRO_ENCODER)
set(FLB_DEPS
  ${FLB_DEPS}
  avro-static
  jansson
  )
endif()

# WASM runtime
if(FLB_WASM)
  set(FLB_DEPS
    ${FLB_DEPS}
    vmlib-static
    flb-wasm-static)
endif()

# Set static dependencies
set(FLB_DEPS
  ${FLB_DEPS}
  cfl-static
  fluent-otel-proto
  cprofiles-static
  cmetrics-static
  ctraces-static
  mk_core
  jsmn
  yyjson
  ${MSGPACK_LIBRARIES}
  mpack-static
  chunkio-static
  miniz
  ${LIBZSTD_LIBRARIES}

  ${FLB_PLUGINS}
  ${FLB_PROXY_PLUGINS}
  ${extra_libs}
  ${LIBCARES_LIBRARIES}
  snappy-c
  lwrb
  ${NGHTTP2_LIBRARIES}
  )

if(OPENSSL_FOUND)
  set(FLB_DEPS
    ${FLB_DEPS}
    OpenSSL::SSL
    )
endif()

# libyaml
if(FLB_HAVE_LIBYAML)
set(FLB_DEPS
  ${FLB_DEPS}
  yaml
  )
endif()

# UTF8 Encoding
if(FLB_UTF8_ENCODER)
set(FLB_DEPS
  ${FLB_DEPS}
  tutf8e
  )
endif()

# Unicode Encoding (UTF-16LE, UTF-16BE)
if(FLB_UNICODE_ENCODER)
set(FLB_DEPS
  ${FLB_DEPS}
  simdutf-static
  flb-simdutf-connector-static
  )
endif()

# AWS specific
if(FLB_AWS)
  set(FLB_DEPS
    ${FLB_DEPS}
    flb-aws
    )
endif()

# Record Accessor
if(FLB_RECORD_ACCESSOR)
  set(FLB_DEPS
    ${FLB_DEPS}
    flb-ra-parser
    )
endif()

set(FLB_DEPS
  ${FLB_DEPS}
  )

# Stream Processor
if(FLB_STREAM_PROCESSOR)
  set(FLB_DEPS
    ${FLB_DEPS}
    flb-sp
    )
endif()

# Unicode Conversions
add_subdirectory(unicode)
set(FLB_DEPS
  ${FLB_DEPS}
  flb-conv
  )
set(src
  ${src}
  flb_unicode.c
  )

if (MSVC)
set(flb_rc_files
  ${CMAKE_CURRENT_BINARY_DIR}/version.rc
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
  endif()

  # Library install routines
  install(TARGETS fluent-bit-shared
    LIBRARY DESTINATION ${FLB_INSTALL_LIBDIR}
    COMPONENT library
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
  target_link_libraries(fluent-bit-static ${JEMALLOC_LIBRARIES})
endif()

# Binary / Executable
if(FLB_BINARY)
  find_package (Threads)
  if (FLB_SYSTEM_WINDOWS)
    add_executable(fluent-bit-bin fluent-bit.c flb_dump.c win32/winsvc.c ${flb_rc_files})
  else()
    add_executable(fluent-bit-bin fluent-bit.c flb_dump.c)
  endif()
  if (MSVC)
    set_target_properties(fluent-bit-bin PROPERTIES IMPORT_SUFFIX ".exe.lib")
  endif(MSVC)
  add_sanitizers(fluent-bit-bin)

  if(FLB_STATIC_CONF)
    add_dependencies(fluent-bit-bin flb-static-conf)
  endif()

  # in_ebpf
  if(FLB_IN_EBPF)
    add_dependencies(fluent-bit-bin flb-ebpf-generate_skeletons)
  endif()

  if(FLB_REGEX)
    target_link_libraries(fluent-bit-bin onigmo-static)
  endif()

  if(FLB_JEMALLOC)
    target_link_libraries(fluent-bit-bin ${JEMALLOC_LIBRARIES})
  endif()

  if(FLB_BACKTRACE)
    add_definitions(-DFLB_DUMP_STACKTRACE=1)
    target_link_libraries(fluent-bit-bin ${LIBBACKTRACE_LIBRARIES})
  endif()

  target_link_libraries(fluent-bit-bin fluent-bit-static ${CMAKE_THREAD_LIBS_INIT})

  # KAFKA SPECIFIC
  if(FLB_SASL_ENABLED)
    target_link_libraries(fluent-bit-bin sasl2)
  endif()

  set_target_properties(fluent-bit-bin
    PROPERTIES
    OUTPUT_NAME ${FLB_OUT_NAME}
    ENABLE_EXPORTS ON)
  install(TARGETS fluent-bit-bin RUNTIME DESTINATION ${FLB_INSTALL_BINDIR} COMPONENT binary)

  # Include PDB file (if available)
  if (MSVC)
    target_link_options(fluent-bit-bin
      PUBLIC /pdb:$<TARGET_PDB_FILE:fluent-bit-bin>)
    install(FILES $<TARGET_PDB_FILE:fluent-bit-bin>
      DESTINATION "${FLB_INSTALL_BINDIR}")
  endif()

  # Detect init system, install upstart, systemd or init.d script

  # Handle issues with detection on some systems during build
  if(NOT SYSTEMD_UNITDIR AND IS_DIRECTORY /lib/systemd/system)
    set(SYSTEMD_UNITDIR  /lib/systemd/system)
  endif()

  if(SYSTEMD_UNITDIR)
    if (FLB_AMAZON_LINUX2)
      set(FLB_SYSTEMD_SCRIPT "${PROJECT_SOURCE_DIR}/init/${FLB_OUT_NAME}.service")
      configure_file(
        "${PROJECT_SOURCE_DIR}/init/az2-systemd.in"
        ${FLB_SYSTEMD_SCRIPT}
        )
      install(FILES ${FLB_SYSTEMD_SCRIPT} COMPONENT binary DESTINATION ${SYSTEMD_UNITDIR})
      install(DIRECTORY DESTINATION ${FLB_INSTALL_CONFDIR} COMPONENT binary)
      set(FLB_HOSTNAME_SYSTEMD_SCRIPT "${PROJECT_SOURCE_DIR}/init/sethostname.service")
      configure_file(
        "${PROJECT_SOURCE_DIR}/init/az2-sethostname.in"
        ${FLB_HOSTNAME_SYSTEMD_SCRIPT}
        )
      install(FILES ${FLB_HOSTNAME_SYSTEMD_SCRIPT} COMPONENT binary DESTINATION ${SYSTEMD_UNITDIR})
      install(DIRECTORY DESTINATION ${FLB_INSTALL_CONFDIR} COMPONENT binary)
    else()
      set(FLB_SYSTEMD_SCRIPT "${PROJECT_SOURCE_DIR}/init/${FLB_OUT_NAME}.service")
      configure_file(
        "${PROJECT_SOURCE_DIR}/init/systemd.in"
        ${FLB_SYSTEMD_SCRIPT}
        )
      install(FILES ${FLB_SYSTEMD_SCRIPT} COMPONENT binary DESTINATION ${SYSTEMD_UNITDIR})
      install(DIRECTORY DESTINATION ${FLB_INSTALL_CONFDIR} COMPONENT binary)
    endif()
  elseif(IS_DIRECTORY /usr/share/upstart)
    set(FLB_UPSTART_SCRIPT "${PROJECT_SOURCE_DIR}/init/${FLB_OUT_NAME}.conf")
    configure_file(
      "${PROJECT_SOURCE_DIR}/init/upstart.in"
      ${FLB_UPSTART_SCRIPT}
      )
    install(FILES ${FLB_UPSTART_SCRIPT} COMPONENT binary DESTINATION /etc/init)
    install(DIRECTORY DESTINATION COMPONENT binary ${FLB_INSTALL_CONFDIR})
  else()
    # FIXME: should we support Sysv init script ?
  endif()

  if(FLB_SYSTEM_WINDOWS)
    install(FILES
      "${PROJECT_SOURCE_DIR}/conf/fluent-bit-win32.conf"
      DESTINATION ${FLB_INSTALL_CONFDIR}
      COMPONENT binary
      RENAME "${FLB_OUT_NAME}.conf")
  elseif(FLB_SYSTEM_MACOS)
    install(FILES
      "${PROJECT_SOURCE_DIR}/conf/fluent-bit-macos.conf"
      DESTINATION ${FLB_INSTALL_CONFDIR}
      COMPONENT binary
      RENAME "${FLB_OUT_NAME}.conf")
  else()
    install(FILES
      "${PROJECT_SOURCE_DIR}/conf/fluent-bit.conf"
      DESTINATION ${FLB_INSTALL_CONFDIR}
      COMPONENT binary
      RENAME "${FLB_OUT_NAME}.conf")
  endif()

  install(FILES
    "${PROJECT_SOURCE_DIR}/conf/parsers.conf"
    COMPONENT binary
    DESTINATION ${FLB_INSTALL_CONFDIR})

  install(FILES
    "${PROJECT_SOURCE_DIR}/conf/plugins.conf"
    COMPONENT binary
    DESTINATION ${FLB_INSTALL_CONFDIR})

endif()
