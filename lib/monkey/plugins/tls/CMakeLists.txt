set(src
  tls.c
)

if(NOT WITH_MBEDTLS_SHARED)
  option(ENABLE_TESTING  OFF)
  option(ENABLE_PROGRAMS OFF)
  option(INSTALL_MBEDTLS_HEADERS OFF)
  set(MK_MBEDTLS_SRC ../../deps/mbedtls-2.4.2)
  add_subdirectory(${MK_MBEDTLS_SRC} ${CMAKE_BINARY_DIR}/mbedtls-2.4.2)
  include_directories(${MK_MBEDTLS_SRC}/include)
endif()

MONKEY_PLUGIN(tls "${src}")

MONKEY_PLUGIN_LINK_LIB(tls mbedtls)
add_subdirectory(conf)
