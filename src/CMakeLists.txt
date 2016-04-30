set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

set(src
  ${src}
  flb_lib.c
  flb_log.c
  flb_uri.c
  flb_pack.c
  flb_kernel.c
  flb_input.c
  flb_output.c
  flb_config.c
  flb_network.c
  flb_utils.c
  flb_engine.c
  flb_io.c
  flb_router.c
  flb_http_client.c
  )

include_directories(
  ../lib/
  ../lib/jsmn
  ../lib/msgpack-1.2.0/include
  ${extra_headers}
  )

# Fluent Bit have TLS support
if(WITH_TLS)
  # Register the TLS interface and functions
  set(src
    ${src}
    "flb_io_tls.c"
    )

  # Make sure our output targets links to the TLS library
  set(extra_libs
    ${extra_libs}
    "mbedtls"
    )
endif()

if(WITH_HTTP)
  set(src
    ${src}
    "flb_http_server.c"
    )
endif()

if(WITH_STATS)
  set(src
    ${src}
    "flb_stats.c"
    )
  set(extra_libs
    ${extra_libs}
    "cJSON"
    "m"
    )
endif()

include(CheckSymbolExists)
check_symbol_exists(accept4 "sys/socket.h" HAVE_ACCEPT4)

# Let the core aware about TLS/SSL if enabled
if(WITH_SSL_TLS)
  FLB_DEFINITION(HAVE_SSL_TLS)
endif()

# Core dependencies
set(FLB_DEPS
  mk_core
  jsmn
  ${extra_libs}
  ${FLB_PLUGINS}
  msgpack-static
  )

# Shared Library
if(NOT WITHOUT_SHARED_LIB)
  add_library(fluent-bit-shared SHARED ${src})
  target_link_libraries(fluent-bit-shared ${FLB_DEPS})

  set_target_properties(fluent-bit-shared
    PROPERTIES OUTPUT_NAME fluent-bit)

  # Library install routines
  install(TARGETS fluent-bit-shared LIBRARY DESTINATION lib)
endif()

# Static Library
add_library(fluent-bit-static STATIC ${src})
set_target_properties(fluent-bit-static PROPERTIES
  OUTPUT_NAME fluent-bit)
target_link_libraries(fluent-bit-static ${FLB_DEPS})

if(WITH_HTTP)
  target_link_libraries(fluent-bit-static monkey-core-static ejson)
endif()

# Executable
if(NOT WITHOUT_BIN)
  find_package (Threads)
  add_executable(fluent-bit-bin fluent-bit.c)
  target_link_libraries(fluent-bit-bin fluent-bit-static ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})
  set_target_properties(fluent-bit-bin
    PROPERTIES OUTPUT_NAME fluent-bit)
  install(TARGETS fluent-bit-bin RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
endif()
