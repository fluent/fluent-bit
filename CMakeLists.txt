cmake_minimum_required(VERSION 2.8)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall ")
project(fluent-bit C)

# Output paths
set(FLB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/library")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/library")

# Build Options
option(WITH_ALL     "Enable all features"         No)
option(WITH_DEBUG   "Build with debug symbols"    No)
option(WITH_SSL_TLS "Build with SSL/TLS support"  No)
option(WITHOUT_BIN  "Do not build executable"     No)

# Build Plugins
option(WITH_IN_XBEE     "Enable XBee input plugin"            No)
option(WITH_IN_CPU      "Enable CPU input plugin"            Yes)
option(WITH_IN_MEM      "Enable Memory input plugin"         Yes)
option(WITH_IN_KMSG     "Enable Kernel log input plugin"     Yes)
option(WITH_OUT_FLUENTD "Enable Fluentd output plugin"       Yes)
option(WITH_OUT_TD      "Enable Treasure Data output plugin" Yes)
option(WITH_OUT_STDOUT  "Enable STDOUT output plugin"        Yes)

# Enable all features
if(WITH_ALL)
  set(WITH_DEBUG       1)
  set(WITH_SSL_TLS     1)
  set(WITH_IN_XBEE     1)
  set(WITH_IN_CPU      1)
  set(WITH_IN_MEM      1)
  set(WITH_OUT_FLUENTD 1)
  set(WITH_OUT_TD      1)
  set(WITH_OUT_STDOUT  1)
endif()

# Enable Debug symbols if specified
if(WITH_DEBUG)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

# General Headers
include_directories(include/ lib/ lib/msgpack-0.5.9/src)

# MSGPACK modification: disable the install routines.z
set(MSGPACK_NO_INSTALL 1)

# Lib: build the core libraries used by Fluent-Bit
add_subdirectory(lib/msgpack-0.5.9)
#add_subdirectory(lib/mk_config)
add_subdirectory(lib/mk_core)
add_subdirectory(lib/jsmn)

# SSL/TLS: add encryption support
if(WITH_SSL_TLS)
  add_definitions(-DHAVE_SSL_TLS)
  add_subdirectory(lib/mbedtls-1.3.10)
endif()

# Instruct CMake to build the Fluent Bit Core
add_subdirectory(include)
add_subdirectory(plugins)
add_subdirectory(src)
