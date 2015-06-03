set(src
  ${src}
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

# Let the core aware about TLS/SSL if enabled
if(WITH_SSL_TLS)
  add_definitions(-DHAVE_SSL_TLS)
endif()

# Shared Library
add_library(fluent-bit-shared SHARED ${src})
set_target_properties(fluent-bit-shared
  PROPERTIES OUTPUT_NAME fluent-bit)

# Static Library
add_library(fluent-bit-static STATIC ${src})
set_target_properties(fluent-bit-static PROPERTIES
  OUTPUT_NAME fluent-bit)

# Link dependencies to Fluent-Bit library core
target_link_libraries(fluent-bit-shared msgpack mk_core jsmn ${FLB_PLUGINS})
target_link_libraries(fluent-bit-static msgpack mk_core jsmn ${FLB_PLUGINS})

# Library install routines
install(TARGETS fluent-bit-shared LIBRARY DESTINATION lib)

# Executable
if(NOT WITHOUT_BIN)
  find_package (Threads)
  add_executable(fluent-bit-bin fluent-bit.c)
  target_link_libraries(fluent-bit-bin fluent-bit-static ${CMAKE_THREAD_LIBS_INIT})
  set_target_properties(fluent-bit-bin
    PROPERTIES OUTPUT_NAME fluent-bit)
  install(TARGETS fluent-bit-bin RUNTIME DESTINATION bin)
endif()
