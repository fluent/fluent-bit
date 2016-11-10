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
    set(FLB_IN_PLUGINS_ADD "${FLB_IN_PLUGINS_ADD}    in = &${p_name}_plugin;\n    mk_list_add(&in->_head, &config->in_plugins);\n\n")
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
    set(FLB_OUT_PLUGINS_ADD "${FLB_OUT_PLUGINS_ADD}    out = &${p_name}_plugin;\n    mk_list_add(&out->_head, &config->out_plugins);\n\n")
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
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
  add_library(flb-plugin-${name} STATIC ${src})
  target_link_libraries(flb-plugin-${name} fluent-bit-static msgpackc-static ${deps})
endmacro()


# ======================
#  Plugins Registration
# ======================

# These plugins works only on Linux
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  REGISTER_IN_PLUGIN("in_cpu")
  REGISTER_IN_PLUGIN("in_mem")
  REGISTER_IN_PLUGIN("in_kmsg")
endif()

REGISTER_IN_PLUGIN("in_xbee")
REGISTER_IN_PLUGIN("in_head")
REGISTER_IN_PLUGIN("in_health")
REGISTER_IN_PLUGIN("in_http")
REGISTER_IN_PLUGIN("in_serial")
REGISTER_IN_PLUGIN("in_stdin")
REGISTER_IN_PLUGIN("in_tail")
REGISTER_IN_PLUGIN("in_tcp")
REGISTER_IN_PLUGIN("in_mqtt")
REGISTER_IN_PLUGIN("in_lib")
REGISTER_IN_PLUGIN("in_forward")
REGISTER_IN_PLUGIN("in_random")
REGISTER_OUT_PLUGIN("out_es")
REGISTER_OUT_PLUGIN("out_forward")
REGISTER_OUT_PLUGIN("out_http")
REGISTER_OUT_PLUGIN("out_nats")
REGISTER_OUT_PLUGIN("out_null")
REGISTER_OUT_PLUGIN("out_plot")
REGISTER_OUT_PLUGIN("out_stdout")
REGISTER_OUT_PLUGIN("out_retry")
REGISTER_OUT_PLUGIN("out_td")
REGISTER_OUT_PLUGIN("out_lib")
REGISTER_OUT_PLUGIN("out_flowcount")

if(ENABLE_TESTS)
  REGISTER_OUT_PLUGIN("out_null")
endif()

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

# Generate the header from the template
configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_plugins.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_plugins.h"
  )

set(FLB_PLUGINS "${flb_plugins}" PARENT_SCOPE)
