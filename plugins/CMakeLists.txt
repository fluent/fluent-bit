set(flb_plugins "" CACHE INTERNAL "flb_plugins")

# REGISTER_IN_PLUGIN
macro(REGISTER_IN_PLUGIN name)
  string(TOUPPER ${name} NAME)
  if(WITH_${NAME})
    set(FLB_IN_PLUGINS_DECL "${FLB_IN_PLUGINS_DECL}struct flb_input_plugin ${name}_plugin;\n")
    set(FLB_IN_PLUGINS_ADD "${FLB_IN_PLUGINS_ADD}    in = &${name}_plugin;\n    mk_list_add(&in->_head, &config->inputs);\n\n")
    add_subdirectory(${name})
    set(flb_plugins "${flb_plugins}flb-plugin-${name};")
  endif()
endmacro()

# REGISTER_OUT_PLUGIN
macro(REGISTER_OUT_PLUGIN name)
  string(TOUPPER ${name} NAME)
  if(WITH_${NAME})
    set(FLB_OUT_PLUGINS_DECL "${FLB_OUT_PLUGINS_DECL}struct flb_output_plugin ${name}_plugin;\n")
    set(FLB_OUT_PLUGINS_ADD "${FLB_OUT_PLUGINS_ADD}    out = &${name}_plugin;\n    mk_list_add(&out->_head, &config->outputs);\n\n")
    add_subdirectory(${name})
    set(flb_plugins "${flb_plugins}flb-plugin-${name};")
  endif()
endmacro()

# FLB_PLUGIN: used by plugins to perform registration and linking
macro(FLB_PLUGIN name src deps)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
  add_library(flb-plugin-${name} STATIC ${src})
  target_link_libraries(flb-plugin-${name} ${deps})
endmacro()


# Try to register each plugin
REGISTER_IN_PLUGIN("in_xbee")
REGISTER_IN_PLUGIN("in_cpu")
REGISTER_IN_PLUGIN("in_mem")
REGISTER_IN_PLUGIN("in_kmsg")
REGISTER_OUT_PLUGIN("out_fluentd")
REGISTER_OUT_PLUGIN("out_td")
REGISTER_OUT_PLUGIN("out_stdout")

# Generate the header from the template
configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_plugins.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_plugins.h"
  )

set(FLB_PLUGINS "${flb_plugins}" PARENT_SCOPE)
