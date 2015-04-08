if(WITH_XBEE)
  set(src ${src} in_xbee.c)
  set(extra_headers ../lib/libxbee-v3)
  set(extra_libs pthread rt)
endif()

set(src
  ${src}
  in_cpu.c
  in_kmsg.c
  flb_pack.c
  flb_input.c
  flb_output.c
  flb_config.c
  flb_network.c
  flb_utils.c
  flb_engine.c
  )

include_directories(
  ../lib/
  ../lib/jsmn
  ../lib/msgpack-0.5.9/src
  ${extra_headers}
  )

# Shared Library
add_library(fluent-bit-shared SHARED ${src})
set_target_properties(fluent-bit-shared
  PROPERTIES OUTPUT_NAME fluent-bit)

# Static Library
add_library(fluent-bit-static STATIC ${src})
set_target_properties(fluent-bit-static PROPERTIES
  OUTPUT_NAME fluent-bit)
set_target_properties(fluent-bit-static PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${FLB_ROOT}/library")

if(WITH_XBEE)
  set_target_properties(fluent-bit-shared PROPERTIES
    COMPILE_FLAGS -DFLB_HAVE_XBEE)
  target_link_libraries(fluent-bit-shared xbee ${extra_libs})

  set_target_properties(fluent-bit-static PROPERTIES
    COMPILE_FLAGS -DFLB_HAVE_XBEE)
  target_link_libraries(fluent-bit-static xbee ${extra_libs})
endif()

# Link dependencies to Fluent-Bit library core
target_link_libraries(fluent-bit-shared msgpack mk_config jsmn)
target_link_libraries(fluent-bit-static msgpack mk_config jsmn)

# Library install routines
install(TARGETS fluent-bit-shared LIBRARY DESTINATION lib)

# Executable
if(NOT WITHOUT_BIN)
  add_executable(fluent-bit-bin fluent-bit.c)
  target_link_libraries(fluent-bit-bin fluent-bit-static)
  set_target_properties(fluent-bit-bin
    PROPERTIES OUTPUT_NAME fluent-bit)
  install(TARGETS fluent-bit-bin RUNTIME DESTINATION bin)
endif()
