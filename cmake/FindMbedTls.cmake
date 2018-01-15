set(_MBEDTLS_REQUIRED_VARS MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARY)

find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h
  PATHS /usr/include /sw/include /usr/local/include)
mark_as_advanced(MBEDTLS_INCLUDE_DIR)

find_library(MBEDTLS_LIBRARY mbedtls
  PATHS /usr/lib /lib /sw/lib /usr/local/lib)
mark_as_advanced(MBEDTLS_LIBRARY)

if (MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIBRARY)
  SET(MBEDTLS_FOUND True)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MBEDTLS DEFAULT_MSG ${_MBEDTLS_REQUIRED_VARS})
