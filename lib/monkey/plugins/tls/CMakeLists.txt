set(src
  tls.c
)

if(NOT WITH_MBEDTLS_SHARED)
  set(MK_MBEDTLS_SRC ../../deps/mbedtls-2.0.0)
  add_subdirectory(${MK_MBEDTLS_SRC} ${CMAKE_BINARY_DIR}/mbedtls-2.0.0)
  include_directories(${MK_MBEDTLS_SRC}/include)
endif()

MONKEY_PLUGIN(tls "${src}")

MONKEY_PLUGIN_LINK_LIB(tls mbedtls)
add_subdirectory(conf)
