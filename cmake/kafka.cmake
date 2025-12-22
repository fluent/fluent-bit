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
FLB_OPTION(WITH_SASL ${FLB_SASL_ENABLED})
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

include_directories(${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_RDKAFKA}/src/)

add_subdirectory(${FLB_PATH_LIB_RDKAFKA} EXCLUDE_FROM_ALL)

set(KAFKA_LIBRARIES "rdkafka")

# Summary of what's enabled
message(STATUS "=== Kafka Feature Summary ===")
message(STATUS "SASL Auth:     ${FLB_SASL_ENABLED}")
message(STATUS "OAuth Bearer:  ${FLB_SASL_OAUTHBEARER_ENABLED}")
message(STATUS "MSK IAM:       ${FLB_KAFKA_MSK_IAM_ENABLED}")
message(STATUS "===============================")
