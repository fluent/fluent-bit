set(flb_plugins "" CACHE INTERNAL "flb_plugins")

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
macro(REGISTER_OUT_PLUGIN name in_rust)
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
    set(C_CODE          "    out = flb_malloc(sizeof(struct flb_output_plugin));\n")
    set(C_CODE "${C_CODE}    if (!out) {\n")
    set(C_CODE "${C_CODE}        flb_errno();\n")
    set(C_CODE "${C_CODE}        return -1;\n")
    set(C_CODE "${C_CODE}    }\n")
    set(C_CODE "${C_CODE}    memcpy(out, &${p_name}_plugin, sizeof(struct flb_output_plugin));\n")
    set(C_CODE "${C_CODE}    mk_list_add(&out->_head, &config->out_plugins);\n\n")

    set(FLB_OUT_PLUGINS_ADD "${FLB_OUT_PLUGINS_ADD}${C_CODE}")
    if (${in_rust})
      message(STATUS "Skip the Rust plugin ${name} for now because the FLB_RUST_PLUGIN macro can not be defined beforehand. It will be added later in the top-level CMakeLists.txt.")
    elseif (p_path)
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
  target_link_libraries(flb-plugin-${name} fluent-bit-static msgpackc-static ${deps})
endmacro()

# ======================
#  Plugins Registration
# ======================

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
endif()

REGISTER_IN_PLUGIN("in_emitter")
REGISTER_IN_PLUGIN("in_tail")
REGISTER_IN_PLUGIN("in_dummy")
REGISTER_IN_PLUGIN("in_head")
REGISTER_IN_PLUGIN("in_health")
REGISTER_IN_PLUGIN("in_http")
REGISTER_IN_PLUGIN("in_collectd")
REGISTER_IN_PLUGIN("in_statsd")
REGISTER_IN_PLUGIN("in_storage_backlog")

if (FLB_STREAM_PROCESSOR)
  REGISTER_IN_PLUGIN("in_stream_processor")
endif()

if (FLB_SYSTEM_WINDOWS)
  REGISTER_IN_PLUGIN("in_winlog")
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

REGISTER_IN_PLUGIN("in_tcp")
REGISTER_IN_PLUGIN("in_mqtt")
REGISTER_IN_PLUGIN("in_lib")
REGISTER_IN_PLUGIN("in_forward")
REGISTER_IN_PLUGIN("in_random")
REGISTER_OUT_PLUGIN("out_azure" "NO")
REGISTER_OUT_PLUGIN("out_bigquery" "NO")
REGISTER_OUT_PLUGIN("out_counter" "NO")
REGISTER_OUT_PLUGIN("out_datadog" "NO")
REGISTER_OUT_PLUGIN("out_es" "NO")
REGISTER_OUT_PLUGIN("out_exit" "NO")
REGISTER_OUT_PLUGIN("out_file" "NO")
REGISTER_OUT_PLUGIN("out_forward" "NO")
REGISTER_OUT_PLUGIN("out_http" "NO")
REGISTER_OUT_PLUGIN("out_influxdb" "NO")
REGISTER_OUT_PLUGIN("out_kafka" "NO")
REGISTER_OUT_PLUGIN("out_kafka_rest" "NO")
REGISTER_OUT_PLUGIN("out_nats" "NO")
REGISTER_OUT_PLUGIN("out_null" "NO")
if (NOT CMAKE_SYSTEM_NAME MATCHES "Windows")
  REGISTER_OUT_PLUGIN("out_plot" "NO")
endif()
REGISTER_OUT_PLUGIN("out_retry" "NO")
REGISTER_OUT_PLUGIN("out_slack" "NO")
REGISTER_OUT_PLUGIN("out_splunk" "NO")
REGISTER_OUT_PLUGIN("out_stackdriver" "NO")
REGISTER_OUT_PLUGIN("out_stdout" "NO")
REGISTER_OUT_PLUGIN("out_tcp" "NO")
REGISTER_OUT_PLUGIN("out_td" "NO")
REGISTER_OUT_PLUGIN("out_lib" "NO")
REGISTER_OUT_PLUGIN("out_flowcounter" "NO")
REGISTER_OUT_PLUGIN("out_gelf" "NO")
REGISTER_OUT_PLUGIN("out_rust_stdout" "YES")

# FILTERS
# =======
REGISTER_FILTER_PLUGIN("filter_stdout")
REGISTER_FILTER_PLUGIN("filter_rewrite_tag")
REGISTER_FILTER_PLUGIN("filter_throttle")

if(FLB_REGEX)
  REGISTER_FILTER_PLUGIN("filter_grep")
  REGISTER_FILTER_PLUGIN("filter_kubernetes")
  REGISTER_FILTER_PLUGIN("filter_parser")
  REGISTER_FILTER_PLUGIN("filter_nest")
  REGISTER_FILTER_PLUGIN("filter_modify")
endif()

if(FLB_LUAJIT)
  REGISTER_FILTER_PLUGIN("filter_lua")
endif()

REGISTER_FILTER_PLUGIN("filter_record_modifier")
REGISTER_FILTER_PLUGIN("filter_aws")

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
    REGISTER_OUT_PLUGIN(${entry} "NO")
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
