# Kafka CMake Configuration
# kafka.cmake - Clean version without internal AWS check
FLB_OPTION(RDKAFKA_BUILD_STATIC    On)
FLB_OPTION(RDKAFKA_BUILD_EXAMPLES Off)
FLB_OPTION(RDKAFKA_BUILD_TESTS    Off)
FLB_OPTION(ENABLE_LZ4_EXT         Off)

include(FindPkgConfig)

# Check for libsasl2 (required for SASL authentication)
set(FLB_SASL_ENABLED OFF)
if(PkgConfig_FOUND)
  pkg_check_modules(SASL libsasl2)
  if(SASL_FOUND)
    message(STATUS "Found libsasl2: ${SASL_VERSION}")
    set(FLB_SASL_ENABLED ON)
  else()
    message(WARNING "libsasl2 not found - SASL authentication will be disabled")
  endif()
else()
  message(WARNING "pkg-config not available - trying fallback SASL detection")
  # Fallback detection
  find_library(SASL2_LIB NAMES sasl2)
  find_path(SASL2_INCLUDE NAMES sasl/sasl.h)
  if(SASL2_LIB AND SASL2_INCLUDE)
    set(FLB_SASL_ENABLED ON)
    message(STATUS "Found libsasl2 via fallback: ${SASL2_LIB}")
  endif()
endif()

# OAuth Bearer support:
# - Windows: Built-in SASL, only needs SSL (no Cyrus SASL required)
# - Linux/macOS: Needs both SSL and Cyrus SASL
if(FLB_SYSTEM_WINDOWS)
  if(FLB_TLS)
    set(FLB_SASL_OAUTHBEARER_ENABLED ON)
  else()
    set(FLB_SASL_OAUTHBEARER_ENABLED OFF)
  endif()
else()
  # Non-Windows platforms: require Cyrus SASL
  set(FLB_SASL_OAUTHBEARER_ENABLED ${FLB_SASL_ENABLED})
endif()

# MSK IAM requires OAuth Bearer support
set(FLB_KAFKA_MSK_IAM_ENABLED ${FLB_SASL_OAUTHBEARER_ENABLED})

# Configure librdkafka options
# On Windows, enable WITH_SASL for SSPI support (built-in, no Cyrus needed)
# On other platforms, WITH_SASL depends on Cyrus SASL availability
if(FLB_SYSTEM_WINDOWS)
  FLB_OPTION(WITH_SASL ON)
else()
  FLB_OPTION(WITH_SASL ${FLB_SASL_ENABLED})
endif()
FLB_OPTION(WITH_SSL On)
FLB_OPTION(WITH_SASL_OAUTHBEARER ${FLB_SASL_OAUTHBEARER_ENABLED})
FLB_OPTION(WITH_SASL_CYRUS ${FLB_SASL_ENABLED})

# Export compile-time definitions using FLB_DEFINITION macro
if(FLB_SASL_ENABLED)
  FLB_DEFINITION(FLB_HAVE_KAFKA_SASL)
  message(STATUS "Kafka SASL authentication: ENABLED")
else()
  message(STATUS "Kafka SASL authentication: DISABLED")
endif()

if(FLB_SASL_OAUTHBEARER_ENABLED)
  FLB_DEFINITION(FLB_HAVE_KAFKA_OAUTHBEARER)
  message(STATUS "Kafka OAuth Bearer: ENABLED")
else()
  message(STATUS "Kafka OAuth Bearer: DISABLED")
endif()

# Disable Curl on macOS (if needed)
if (FLB_SYSTEM_MACOS)
  FLB_OPTION(WITH_CURL Off)
endif()

# Enable zstd compression for librdkafka using the library already resolved
# by the top-level zstd detection block (LIBZSTD_LIBRARIES is set for all
# cases: bundled, system CMake config, and system pkg-config fallback).
if(LIBZSTD_LIBRARIES)
  if(TARGET libzstd_static)
    # Bundled: force-inject vars — librdkafka's find_package(ZSTD) cannot
    # discover an in-tree target on its own.
    set(ZSTD_FOUND TRUE CACHE BOOL "" FORCE)
    set(ZSTD_INCLUDE_DIR "${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_ZSTD}/lib" CACHE PATH "" FORCE)
    set(ZSTD_LIBRARY_DEBUG libzstd_static CACHE STRING "" FORCE)
    set(ZSTD_LIBRARY_RELEASE libzstd_static CACHE STRING "" FORCE)
    set(ZSTD_LIBRARY libzstd_static CACHE STRING "" FORCE)
    FLB_OPTION(WITH_ZSTD ON)
    set(FLB_KAFKA_ZSTD_SOURCE "bundled")
  else()
    # System: clear stale bundled-sentinel entries and WITH_ZSTD so librdkafka
    # re-runs find_package(ZSTD) fresh and its option() sets its own default.
    # Preserve explicit caller overrides such as -DZSTD_LIBRARY=/custom/path.
    if(ZSTD_LIBRARY STREQUAL "libzstd_static")
      unset(ZSTD_FOUND CACHE)
      unset(ZSTD_INCLUDE_DIR CACHE)
      unset(ZSTD_LIBRARY CACHE)
      unset(ZSTD_LIBRARY_DEBUG CACHE)
      unset(ZSTD_LIBRARY_RELEASE CACHE)
      unset(WITH_ZSTD CACHE)
    endif()
    set(FLB_KAFKA_ZSTD_SOURCE "system")
  endif()
else()
  # FLB didn't find zstd. Clear stale bundled entries so librdkafka's
  # find_package/option() runs fresh and defaults to OFF.
  # Preserve user-supplied custom paths (ZSTD_LIBRARY != sentinel).
  if(ZSTD_LIBRARY STREQUAL "libzstd_static")
    unset(ZSTD_FOUND CACHE)
    unset(ZSTD_INCLUDE_DIR CACHE)
    unset(ZSTD_LIBRARY CACHE)
    unset(ZSTD_LIBRARY_DEBUG CACHE)
    unset(ZSTD_LIBRARY_RELEASE CACHE)
    unset(WITH_ZSTD CACHE)
  elseif(NOT ZSTD_LIBRARY)
    unset(WITH_ZSTD CACHE)
  endif()
  set(FLB_KAFKA_ZSTD_SOURCE "disabled")
endif()

include_directories(${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_RDKAFKA}/src/)

add_subdirectory(${FLB_PATH_LIB_RDKAFKA} EXCLUDE_FROM_ALL)

set(KAFKA_LIBRARIES "rdkafka")

# Summary of what's enabled
message(STATUS "=== Kafka Feature Summary ===")
message(STATUS "SASL Auth:     ${FLB_SASL_ENABLED}")
message(STATUS "OAuth Bearer:  ${FLB_SASL_OAUTHBEARER_ENABLED}")
message(STATUS "MSK IAM:       ${FLB_KAFKA_MSK_IAM_ENABLED}")
message(STATUS "ZSTD:          ${FLB_KAFKA_ZSTD_SOURCE}")
message(STATUS "===============================")
