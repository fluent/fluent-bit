message(STATUS "Static configuration path => '${FLB_STATIC_CONF}'")

# Locate and process configuration files
file(GLOB files "${FLB_STATIC_CONF}/*.conf")

# Output directory for generated header files
set(CONF_DIR ${PROJECT_SOURCE_DIR}/include/fluent-bit/conf/)

# Iterate list creating custom commands for each entry
set(OUT_FILES "")
set(STATIC_DEPS "")
set(FLB_STATIC_CONF_ARR "")
set(FLB_STATIC_CONF_ARR_SIZE 0)
foreach(file ${files})
  # Convert configuration file using xxd-c
  message(STATUS "Processing configuration file: '${file}'")
  get_filename_component(in_file ${file} NAME)

  add_custom_target(
    flb-static-file-${in_file}.h ALL
    COMMAND xxd-c
    ARGS
    -i ${file}
    -o ${CONF_DIR}${in_file}.h
    -s ${in_file}
    DEPENDS ${file} xxd-c
    COMMENT "Generating static configuration file: ${in_file}.h"
    )
  LIST(APPEND OUT_FILES "${in_file}.h")
  LIST(APPEND STATIC_DEPS "flb-static-file-${in_file}.h")

  string(REPLACE "." "_" stname ${in_file})
  string(REPLACE "-" "_" stname ${stname})
  set(keyname ${in_file})
  set(stname "__${stname}")
  set(FLB_STATIC_CONF_ARR "${FLB_STATIC_CONF_ARR}{(unsigned char*) \"${keyname}\", ${stname}},\n    ")
  MATH(EXPR FLB_STATIC_CONF_ARR_SIZE "${FLB_STATIC_CONF_ARR_SIZE}+1")
endforeach()

# Generate main flb_static_conf.h header using the template
set(FLB_STATIC_CONF_INC "")
foreach(c ${OUT_FILES})
  set(FLB_STATIC_CONF_INC "${FLB_STATIC_CONF_INC}#include \"${c}\"\n")
endforeach()

configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/conf/flb_static_conf.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/conf/flb_static_conf.h"
  )

# Register the custom target, this will be a later dependency
# of fluent-bit-static target
add_custom_target(flb-static-conf DEPENDS ${STATIC_DEPS})
