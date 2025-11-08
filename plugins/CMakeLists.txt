set(flb_plugins "" CACHE INTERNAL "flb_plugins")

# REGISTER_CUSTOM_PLUGIN
macro(REGISTER_CUSTOM_PLUGIN name)
  string(FIND ${name} "=" pos)
  if(pos GREATER -1)
    string(REPLACE "=" ";" list ${name})
    list(GET list 0 p_name)
    list(GET list 1 p_path)
    message(STATUS "EXTERNAL CUSTOM PLUGIN name='${p_name}' path='${p_path}'")
  else()
    set(p_name ${name})
  endif()

  string(TOUPPER ${p_name} NAME)
  if(FLB_${NAME} OR p_path)
    set(FLB_IN_PLUGINS_DECL "${FLB_CUSTOM_PLUGINS_DECL}extern struct flb_custom_plugin ${p_name}_plugin;\n")

    # C code
    set(C_CODE          "    custom = flb_malloc(sizeof(struct flb_custom_plugin));\n")
    set(C_CODE "${C_CODE}    if (!custom) {\n")
    set(C_CODE "${C_CODE}        flb_errno();\n")
    set(C_CODE "${C_CODE}        return -1;\n")
    set(C_CODE "${C_CODE}    }\n")
    set(C_CODE "${C_CODE}    memcpy(custom, &${p_name}_plugin, sizeof(struct flb_custom_plugin));\n")
    set(C_CODE "${C_CODE}    mk_list_add(&custom->_head, &config->custom_plugins);\n\n")

    set(FLB_IN_PLUGINS_ADD "${FLB_CUSTOM_PLUGINS_ADD}${C_CODE}")

    if (p_path)
      add_subdirectory(${p_path} ${p_path})
    else()
      add_subdirectory(${p_name})
    endif()
    set(flb_plugins "${flb_plugins}flb-plugin-${p_name};")
  endif()
endmacro()

# REGISTER_IN_PLUGIN
macro(REGISTER_IN_PLUGIN name)
  string(FIND ${name} "=" pos)
  if(pos GREATER -1)
    string(REPLACE "=" ";" list ${name})
    list(GET list 0 p_name)
    list(GET list 1 p_path)
    message(STATUS "EXTERNAL IN PLUGIN name='${p_name}' path='${p_path}'")
  else()
    set(p_name ${name})
  endif()

  string(TOUPPER ${p_name} NAME)
  if(FLB_${NAME} OR p_path)
    set(FLB_IN_PLUGINS_DECL "${FLB_IN_PLUGINS_DECL}extern struct flb_input_plugin ${p_name}_plugin;\n")

    # C code
    set(C_CODE          "    in = flb_malloc(sizeof(struct flb_input_plugin));\n")
    set(C_CODE "${C_CODE}    if (!in) {\n")
    set(C_CODE "${C_CODE}        flb_errno();\n")
    set(C_CODE "${C_CODE}        return -1;\n")
    set(C_CODE "${C_CODE}    }\n")
    set(C_CODE "${C_CODE}    memcpy(in, &${p_name}_plugin, sizeof(struct flb_input_plugin));\n")
    set(C_CODE "${C_CODE}    mk_list_add(&in->_head, &config->in_plugins);\n\n")

    set(FLB_IN_PLUGINS_ADD "${FLB_IN_PLUGINS_ADD}${C_CODE}")

    if (p_path)
      add_subdirectory(${p_path} ${p_path})
    else()
      add_subdirectory(${p_name})
    endif()
    set(flb_plugins "${flb_plugins}flb-plugin-${p_name};")
  endif()
endmacro()

# REGISTER_OUT_PLUGIN
macro(REGISTER_OUT_PLUGIN name)
  set (extra_args ${ARGN})

  list(LENGTH extra_args extra_count)

  if (${extra_count} GREATER 0)
      list(GET extra_args 0 environment)
  else ()
    set(environment "c")
  endif ()

  string(TOUPPER ${environment} environment)

  string(FIND ${name} "=" pos)
  if(pos GREATER -1)
    string(REPLACE "=" ";" list ${name})
    list(GET list 0 p_name)
    list(GET list 1 p_path)
    message(STATUS "EXTERNAL OUT PLUGIN name='${p_name}' path='${p_path}'")
  else()
    set(p_name ${name})
  endif()

  string(TOUPPER ${p_name} NAME)
  if(FLB_${NAME} OR p_path)
    set(FLB_OUT_PLUGINS_DECL "${FLB_OUT_PLUGINS_DECL}extern struct flb_output_plugin ${p_name}_plugin;\n")

    # C code
    if(${environment} MATCHES "ZIG")
    set(C_CODE          "    out = flb_zig_native_output_plugin_init(&${p_name}_plugin);\n")
    else()
    set(C_CODE          "    out = flb_malloc(sizeof(struct flb_output_plugin));\n")
    endif()

    set(C_CODE "${C_CODE}    if (!out) {\n")
    set(C_CODE "${C_CODE}        flb_errno();\n")
    set(C_CODE "${C_CODE}        return -1;\n")
    set(C_CODE "${C_CODE}    }\n")

    if(${environment} MATCHES "ZIG")
    else()
    set(C_CODE "${C_CODE}    memcpy(out, &${p_name}_plugin, sizeof(struct flb_output_plugin));\n")
    endif()

    set(C_CODE "${C_CODE}    mk_list_add(&out->_head, &config->out_plugins);\n\n")

    set(FLB_OUT_PLUGINS_ADD "${FLB_OUT_PLUGINS_ADD}${C_CODE}")
    if (p_path)
      add_subdirectory(${p_path} ${p_path})
    else()
      add_subdirectory(${p_name})
    endif()
    set(flb_plugins "${flb_plugins}flb-plugin-${p_name};")
  endif()
endmacro()


# REGISTER_PROCESSOR_PLUGIN
macro(REGISTER_PROCESSOR_PLUGIN name)
  string(FIND ${name} "=" pos)
  if(pos GREATER -1)
    string(REPLACE "=" ";" list ${name})
    list(GET list 0 p_name)
    list(GET list 1 p_path)
    message(STATUS "EXTERNAL PROCESSOR PLUGIN name='${p_name}' path='${p_path}'")
  else()
    set(p_name ${name})
  endif()

  string(TOUPPER ${p_name} NAME)
  if(FLB_${NAME} OR p_path)
    set(FLB_PROCESSOR_PLUGINS_DECL "${FLB_PROCESSOR_PLUGINS_DECL}extern struct flb_processor_plugin ${p_name}_plugin;\n")

    # C code
    set(C_CODE          "    processor = flb_malloc(sizeof(struct flb_processor_plugin));\n")
    set(C_CODE "${C_CODE}    if (!processor) {\n")
    set(C_CODE "${C_CODE}        flb_errno();\n")
    set(C_CODE "${C_CODE}        return -1;\n")
    set(C_CODE "${C_CODE}    }\n")
    set(C_CODE "${C_CODE}    memcpy(processor, &${p_name}_plugin, sizeof(struct flb_processor_plugin));\n")
    set(C_CODE "${C_CODE}    mk_list_add(&processor->_head, &config->processor_plugins);\n\n")

    set(FLB_PROCESSOR_PLUGINS_ADD "${FLB_PROCESSOR_PLUGINS_ADD}${C_CODE}")
    if (p_path)
      add_subdirectory(${p_path} ${p_path})
    else()
      add_subdirectory(${p_name})
    endif()
    set(flb_plugins "${flb_plugins}flb-plugin-${p_name};")
  endif()
endmacro()

# REGISTER_FILTER_PLUGIN
macro(REGISTER_FILTER_PLUGIN name)
  string(FIND ${name} "=" pos)
  if(pos GREATER -1)
    string(REPLACE "=" ";" list ${name})
    list(GET list 0 p_name)
    list(GET list 1 p_path)
    message(STATUS "EXTERNAL FILTER PLUGIN name='${p_name}' path='${p_path}'")
  else()
    set(p_name ${name})
  endif()

  string(TOUPPER ${p_name} NAME)
  if(FLB_${NAME} OR p_path)
    set(FLB_FILTER_PLUGINS_DECL "${FLB_FILTER_PLUGINS_DECL}extern struct flb_filter_plugin ${p_name}_plugin;\n")

    # C code
    set(C_CODE          "    filter = flb_malloc(sizeof(struct flb_filter_plugin));\n")
    set(C_CODE "${C_CODE}    if (!filter) {\n")
    set(C_CODE "${C_CODE}        flb_errno();\n")
    set(C_CODE "${C_CODE}        return -1;\n")
    set(C_CODE "${C_CODE}    }\n")
    set(C_CODE "${C_CODE}    memcpy(filter, &${p_name}_plugin, sizeof(struct flb_filter_plugin));\n")
    set(C_CODE "${C_CODE}    mk_list_add(&filter->_head, &config->filter_plugins);\n\n")

    set(FLB_FILTER_PLUGINS_ADD "${FLB_FILTER_PLUGINS_ADD}${C_CODE}")
    if (p_path)
      add_subdirectory(${p_path} ${p_path})
    else()
      add_subdirectory(${p_name})
    endif()
    set(flb_plugins "${flb_plugins}flb-plugin-${p_name};")
  endif()
endmacro()

# FLB_PLUGIN: used by plugins to perform registration and linking
macro(FLB_PLUGIN name src deps)
  add_library(flb-plugin-${name} STATIC ${src})
  add_sanitizers(flb-plugin-${name})
  target_link_libraries(flb-plugin-${name} fluent-bit-static ${MSGPACK_LIBRARIES} ${deps})
endmacro()

# FLB_ZIG_PLUGIN: used by zig plugins to standardize the process
macro(FLB_ZIG_PLUGIN name deps)
  find_program(ZIG_PATH zig REQUIRED)

  get_property(include_dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)

  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/flb-plugin-${name}.o
    COMMAND ${CMAKE_COMMAND} -E env "FLB_ZIG_BUILD_INCLUDE_DIRECTORIES=${include_dirs}" ${ZIG_PATH} build --prefix "${CMAKE_CURRENT_BINARY_DIR}"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/build.zig
    VERBATIM
  )

  add_custom_target(zig-build-done
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/flb-plugin-${name}.o
  )

  if(NOT EXISTS "${CMAKE_CURRENT_BINARY_DIR}/dummy.c")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/dummy.c" "")
  endif()

  set(src
    ${CMAKE_CURRENT_BINARY_DIR}/dummy.c
    ${CMAKE_CURRENT_BINARY_DIR}/flb-plugin-${name}.o)

  FLB_PLUGIN(${name} "${src}" "${deps}")

  add_dependencies(flb-plugin-${name} zig-build-done)
endmacro()

# ======================
#  Plugins Registration
# ======================

# Custom Plugins
REGISTER_CUSTOM_PLUGIN("custom_calyptia")

REGISTER_IN_PLUGIN("in_blob")

# These plugins works only on Linux
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  REGISTER_IN_PLUGIN("in_cpu")
  REGISTER_IN_PLUGIN("in_mem")
  REGISTER_IN_PLUGIN("in_thermal")
  REGISTER_IN_PLUGIN("in_kmsg")
  REGISTER_IN_PLUGIN("in_proc")
  REGISTER_IN_PLUGIN("in_disk")
  REGISTER_IN_PLUGIN("in_systemd")
  REGISTER_IN_PLUGIN("in_netif")
  REGISTER_IN_PLUGIN("in_docker")
  REGISTER_IN_PLUGIN("in_docker_events")
  REGISTER_IN_PLUGIN("in_podman_metrics")
  REGISTER_IN_PLUGIN("in_process_exporter_metrics")
  REGISTER_IN_PLUGIN("in_ebpf")
  REGISTER_IN_PLUGIN("in_gpu_metrics")
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux" OR ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  REGISTER_IN_PLUGIN("in_node_exporter_metrics")
endif()

REGISTER_IN_PLUGIN("in_kubernetes_events")

if(FLB_KAFKA)
  REGISTER_IN_PLUGIN("in_kafka")
endif()

REGISTER_IN_PLUGIN("in_fluentbit_metrics")
REGISTER_IN_PLUGIN("in_prometheus_scrape")
REGISTER_IN_PLUGIN("in_prometheus_textfile")
REGISTER_IN_PLUGIN("in_emitter")
REGISTER_IN_PLUGIN("in_tail")
REGISTER_IN_PLUGIN("in_dummy")
REGISTER_IN_PLUGIN("in_head")
REGISTER_IN_PLUGIN("in_health")
REGISTER_IN_PLUGIN("in_http")
REGISTER_IN_PLUGIN("in_collectd")
REGISTER_IN_PLUGIN("in_statsd")
REGISTER_IN_PLUGIN("in_opentelemetry")
REGISTER_IN_PLUGIN("in_elasticsearch")
REGISTER_IN_PLUGIN("in_calyptia_fleet")
REGISTER_IN_PLUGIN("in_splunk")
REGISTER_IN_PLUGIN("in_prometheus_remote_write")

# Test the event loop messaging when used in threaded mode
REGISTER_IN_PLUGIN("in_event_test")

# Send different event types: logs, metrics and traces
REGISTER_IN_PLUGIN("in_event_type")


if (FLB_IN_STORAGE_BACKLOG)
  REGISTER_IN_PLUGIN("in_storage_backlog")
endif()

REGISTER_IN_PLUGIN("in_nginx_exporter_metrics")

if (FLB_STREAM_PROCESSOR)
  REGISTER_IN_PLUGIN("in_stream_processor")
endif()

if (FLB_SYSTEM_WINDOWS)
  REGISTER_IN_PLUGIN("in_winlog")
  REGISTER_IN_PLUGIN("in_winstat")
  REGISTER_IN_PLUGIN("in_winevtlog")
  REGISTER_IN_PLUGIN("in_windows_exporter_metrics")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W2")
else()
  REGISTER_IN_PLUGIN("in_serial")
endif()

if(FLB_REGEX)
  REGISTER_IN_PLUGIN("in_stdin")
endif()

if(FLB_PARSER)
  REGISTER_IN_PLUGIN("in_syslog")
  REGISTER_IN_PLUGIN("in_exec")
endif()

REGISTER_IN_PLUGIN("in_udp")

if(FLB_WASM)
  REGISTER_IN_PLUGIN("in_exec_wasi")
endif()

REGISTER_IN_PLUGIN("in_tcp")
REGISTER_IN_PLUGIN("in_unix_socket")
REGISTER_IN_PLUGIN("in_mqtt")
REGISTER_IN_PLUGIN("in_lib")
REGISTER_IN_PLUGIN("in_forward")
REGISTER_IN_PLUGIN("in_random")
REGISTER_IN_PLUGIN("in_amqp")

# PROCESSORS
# ==========
REGISTER_PROCESSOR_PLUGIN("processor_content_modifier")
REGISTER_PROCESSOR_PLUGIN("processor_labels")
REGISTER_PROCESSOR_PLUGIN("processor_metrics_selector")
REGISTER_PROCESSOR_PLUGIN("processor_opentelemetry_envelope")
REGISTER_PROCESSOR_PLUGIN("processor_sampling")
REGISTER_PROCESSOR_PLUGIN("processor_sql")

# OUTPUTS
# =======
REGISTER_OUT_PLUGIN("out_azure")
REGISTER_OUT_PLUGIN("out_azure_blob")
REGISTER_OUT_PLUGIN("out_azure_logs_ingestion")
REGISTER_OUT_PLUGIN("out_azure_kusto")
REGISTER_OUT_PLUGIN("out_bigquery")
REGISTER_OUT_PLUGIN("out_calyptia")
REGISTER_OUT_PLUGIN("out_counter")
REGISTER_OUT_PLUGIN("out_datadog")
REGISTER_OUT_PLUGIN("out_es")
REGISTER_OUT_PLUGIN("out_exit")
REGISTER_OUT_PLUGIN("out_file")
REGISTER_OUT_PLUGIN("out_forward")
REGISTER_OUT_PLUGIN("out_http")
REGISTER_OUT_PLUGIN("out_influxdb")
REGISTER_OUT_PLUGIN("out_logdna")
REGISTER_OUT_PLUGIN("out_loki")

if(FLB_KAFKA)
  REGISTER_OUT_PLUGIN("out_kafka")
endif()

REGISTER_OUT_PLUGIN("out_kafka_rest")
REGISTER_OUT_PLUGIN("out_nats")
REGISTER_OUT_PLUGIN("out_nrlogs")
REGISTER_OUT_PLUGIN("out_null")
REGISTER_OUT_PLUGIN("out_opensearch")
REGISTER_OUT_PLUGIN("out_oracle_log_analytics")

if (NOT CMAKE_SYSTEM_NAME MATCHES "Windows")
  REGISTER_OUT_PLUGIN("out_plot")
endif()

REGISTER_OUT_PLUGIN("out_pgsql")
REGISTER_OUT_PLUGIN("out_retry")
REGISTER_OUT_PLUGIN("out_skywalking")
REGISTER_OUT_PLUGIN("out_slack")
REGISTER_OUT_PLUGIN("out_splunk")
REGISTER_OUT_PLUGIN("out_stackdriver")
REGISTER_OUT_PLUGIN("out_stdout")
REGISTER_OUT_PLUGIN("out_syslog")
REGISTER_OUT_PLUGIN("out_tcp")
REGISTER_OUT_PLUGIN("out_udp")
REGISTER_OUT_PLUGIN("out_td")
REGISTER_OUT_PLUGIN("out_lib")
REGISTER_OUT_PLUGIN("out_flowcounter")
REGISTER_OUT_PLUGIN("out_gelf")
REGISTER_OUT_PLUGIN("out_websocket")
REGISTER_OUT_PLUGIN("out_cloudwatch_logs")
REGISTER_OUT_PLUGIN("out_kinesis_firehose")
REGISTER_OUT_PLUGIN("out_kinesis_streams")
REGISTER_OUT_PLUGIN("out_opentelemetry")
REGISTER_OUT_PLUGIN("out_prometheus_exporter")
REGISTER_OUT_PLUGIN("out_prometheus_remote_write")
REGISTER_OUT_PLUGIN("out_s3")
REGISTER_OUT_PLUGIN("out_vivo_exporter")
REGISTER_OUT_PLUGIN("out_chronicle")

if(FLB_ZIG)
REGISTER_OUT_PLUGIN("out_zig_demo" "zig")
endif()

# FILTERS
# =======
REGISTER_FILTER_PLUGIN("filter_alter_size")
REGISTER_FILTER_PLUGIN("filter_aws")
REGISTER_FILTER_PLUGIN("filter_checklist")
REGISTER_FILTER_PLUGIN("filter_ecs")
REGISTER_FILTER_PLUGIN("filter_record_modifier")
REGISTER_FILTER_PLUGIN("filter_sysinfo")
REGISTER_FILTER_PLUGIN("filter_throttle")
REGISTER_FILTER_PLUGIN("filter_throttle_size")
REGISTER_FILTER_PLUGIN("filter_tensorflow")
REGISTER_FILTER_PLUGIN("filter_type_converter")

if(FLB_REGEX)
  REGISTER_FILTER_PLUGIN("filter_kubernetes")
  REGISTER_FILTER_PLUGIN("filter_modify")
  REGISTER_FILTER_PLUGIN("filter_multiline")
  REGISTER_FILTER_PLUGIN("filter_nest")
  REGISTER_FILTER_PLUGIN("filter_parser")
endif()

if(FLB_RECORD_ACCESSOR)
  REGISTER_FILTER_PLUGIN("filter_expect")
  REGISTER_FILTER_PLUGIN("filter_grep")
  REGISTER_FILTER_PLUGIN("filter_rewrite_tag")
endif()

if(FLB_METRICS)
  REGISTER_FILTER_PLUGIN("filter_log_to_metrics")
endif()

if(FLB_LUAJIT)
  REGISTER_FILTER_PLUGIN("filter_lua")
endif()

REGISTER_FILTER_PLUGIN("filter_stdout")

REGISTER_FILTER_PLUGIN("filter_geoip2")

REGISTER_FILTER_PLUGIN("filter_nightfall")
if (FLB_WASM)
  REGISTER_FILTER_PLUGIN("filter_wasm")
endif ()

# Register external input and output plugins
if(EXT_IN_PLUGINS)
  string(REPLACE "," ";" plugins ${EXT_IN_PLUGINS})
  foreach(entry ${plugins})
    REGISTER_IN_PLUGIN(${entry})
  endforeach()
endif()

if(EXT_OUT_PLUGINS)
  string(REPLACE "," ";" plugins ${EXT_OUT_PLUGINS})
  foreach(entry ${plugins})
    REGISTER_OUT_PLUGIN(${entry})
  endforeach()
endif()

if(EXT_PROCESSOR_PLUGINS)
  string(REPLACE "," ";" plugins ${EXT_PROCESSOR_PLUGINS})
  foreach(entry ${plugins})
    REGISTER_PROCESSOR_PLUGIN(${entry})
  endforeach()
endif()

if(EXT_FILTER_PLUGINS)
  string(REPLACE "," ";" plugins ${EXT_FILTER_PLUGINS})
  foreach(entry ${plugins})
    REGISTER_FILTER_PLUGIN(${entry})
  endforeach()
endif()

# Generate the header from the template
configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_plugins.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_plugins.h"
  )

set(FLB_PLUGINS "${flb_plugins}" PARENT_SCOPE)
