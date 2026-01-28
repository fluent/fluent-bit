# Kafka CMake Configuration
FLB_OPTION(RDKAFKA_BUILD_STATIC    On)
FLB_OPTION(RDKAFKA_BUILD_EXAMPLES Off)
FLB_OPTION(RDKAFKA_BUILD_TESTS    Off)
FLB_OPTION(ENABLE_LZ4_EXT         Off)

include(FindPkgConfig)

# librdkafka has built-in support for:
# - SASL/PLAIN (built-in, no external deps)
# - SASL/SCRAM (built-in, no external deps)
# - SASL/OAUTHBEARER (built-in, no external deps)
# Only SASL/GSSAPI (Kerberos) requires cyrus-sasl library

# Check for cyrus-sasl (optional, only needed for GSSAPI/Kerberos)
set(FLB_SASL_CYRUS_ENABLED OFF)
if(PkgConfig_FOUND)
  pkg_check_modules(SASL libsasl2)
  if(SASL_FOUND)
    message(STATUS "Found cyrus-sasl: ${SASL_VERSION}")
    set(FLB_SASL_CYRUS_ENABLED ON)
  else()
    # Fallback detection when pkg-config finds no package
    find_library(SASL2_LIB NAMES sasl2)
    find_path(SASL2_INCLUDE NAMES sasl/sasl.h)
    if(SASL2_LIB AND SASL2_INCLUDE)
      set(FLB_SASL_CYRUS_ENABLED ON)
      set(SASL_LIBRARIES ${SASL2_LIB})
      set(SASL_INCLUDE_DIRS ${SASL2_INCLUDE})
      message(STATUS "Found cyrus-sasl via fallback: ${SASL2_LIB}")
    else()
      message(STATUS "cyrus-sasl not found - SASL/GSSAPI (Kerberos) will be disabled")
    endif()
  endif()
else()
  message(STATUS "pkg-config not available - trying fallback cyrus-sasl detection")
  find_library(SASL2_LIB NAMES sasl2)
  find_path(SASL2_INCLUDE NAMES sasl/sasl.h)
  if(SASL2_LIB AND SASL2_INCLUDE)
    set(FLB_SASL_CYRUS_ENABLED ON)
    set(SASL_LIBRARIES ${SASL2_LIB})
    set(SASL_INCLUDE_DIRS ${SASL2_INCLUDE})
    message(STATUS "Found cyrus-sasl via fallback: ${SASL2_LIB}")
  else()
    message(STATUS "cyrus-sasl not found - SASL/GSSAPI (Kerberos) will be disabled")
  endif()
endif()

# SASL is always enabled (built-in PLAIN/SCRAM/OAUTHBEARER support)
set(FLB_SASL_ENABLED ON)

# OAuth Bearer support:
# - Windows: Requires SSL/TLS
# - Linux/macOS: Built-in, always enabled (no external dependencies required)
if(FLB_SYSTEM_WINDOWS)
  if(FLB_TLS)
    set(FLB_SASL_OAUTHBEARER_ENABLED ON)
  else()
    set(FLB_SASL_OAUTHBEARER_ENABLED OFF)
  endif()
else()
  # Non-Windows platforms: OAuth Bearer is built-in, always enabled
  set(FLB_SASL_OAUTHBEARER_ENABLED ON)
endif()

# MSK IAM requires OAuth Bearer support
set(FLB_KAFKA_MSK_IAM_ENABLED ${FLB_SASL_OAUTHBEARER_ENABLED})

# Configure librdkafka options
# WITH_SASL is always ON for built-in SASL support (PLAIN/SCRAM/OAUTHBEARER)
# On Windows, this also enables SSPI support
FLB_OPTION(WITH_SASL ON)
FLB_OPTION(WITH_SSL On)                                        # SSL support
FLB_OPTION(WITH_SASL_OAUTHBEARER ${FLB_SASL_OAUTHBEARER_ENABLED})

# Explicitly set WITH_SASL_CYRUS based on detection
# Must use set(... CACHE BOOL ... FORCE) to override any cached value
if(FLB_SASL_CYRUS_ENABLED)
  set(WITH_SASL_CYRUS ON CACHE BOOL "Enable Cyrus SASL support" FORCE)
else()
  set(WITH_SASL_CYRUS OFF CACHE BOOL "Enable Cyrus SASL support" FORCE)
endif()

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

include_directories(${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_RDKAFKA}/src/)

add_subdirectory(${FLB_PATH_LIB_RDKAFKA} EXCLUDE_FROM_ALL)

set(KAFKA_LIBRARIES "rdkafka")

# Add SASL libraries if cyrus-sasl is enabled
if(FLB_SASL_CYRUS_ENABLED AND SASL_LIBRARIES)
  list(APPEND KAFKA_LIBRARIES ${SASL_LIBRARIES})
  message(STATUS "Added SASL libraries to Kafka: ${SASL_LIBRARIES}")
endif()

# Summary of what's enabled
message(STATUS "=== Kafka Feature Summary ===")
message(STATUS "SASL Auth:     ${FLB_SASL_ENABLED}")
message(STATUS "OAuth Bearer:  ${FLB_SASL_OAUTHBEARER_ENABLED}")
message(STATUS "MSK IAM:       ${FLB_KAFKA_MSK_IAM_ENABLED}")
message(STATUS "===============================")
