# REGISTER_IN_PLUGIN
macro(REGISTER_IN_PLUGIN name)
  string(TOUPPER ${name} NAME)
  if(WITH_IN_${NAME})
    set(FLB_IN_PLUGINS_DECL "${FLB_IN_PLUGINS_DECL}struct flb_input_plugin in_${name}_plugin;\n")
    set(FLB_IN_PLUGINS_ADD "${FLB_IN_PLUGINS_ADD}    in = &in_${name}_plugin;\n    mk_list_add(&in->_head, &config->inputs);\n\n")
  endif()
endmacro()

# REGISTER_OUT_PLUGIN
macro(REGISTER_OUT_PLUGIN name)
  string(TOUPPER ${name} NAME)
  if(WITH_OUT_${NAME})
    set(FLB_OUT_PLUGINS_DECL "${FLB_OUT_PLUGINS_DECL}struct flb_output_plugin out_${name}_plugin;\n")
    set(FLB_OUT_PLUGINS_ADD "${FLB_OUT_PLUGINS_ADD}    out = &out_${name}_plugin;\n    mk_list_add(&out->_head, &config->outputs);\n\n")
  endif()
endmacro()

# Try to register each plugin
REGISTER_IN_PLUGIN("xbee")
REGISTER_IN_PLUGIN("cpu")
REGISTER_IN_PLUGIN("kmsg")
REGISTER_OUT_PLUGIN("fluentd")
REGISTER_OUT_PLUGIN("td")

# Generate the header from the template
configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_plugins.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_plugins.h"
  )

# Install fluent-bit headers
file(GLOB headers "fluent-bit/*.h")
install(FILES ${headers}
        DESTINATION include/fluent-bit
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
