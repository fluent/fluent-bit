cmake_minimum_required(VERSION 2.6)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall ")
project(FLUENT-BIT C)

# Output paths
set(FLB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/library")

# Build Options
option(WITH_ALL    "Enable all features" OFF)
option(WITH_XBEE   "Enable XBee support" OFF)
option(WITH_DEBUG  "Build with debug symbols" OFF)
option(WITHOUT_BIN "Do not build executable" OFF)

if(WITH_ALL)
  set(WITH_XBEE ON)
endif()

# Enable Debug symbols if specified
if(WITH_DEBUG)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

# General Headers
include_directories(include/)

# Lib: build the core libraries used by Fluent-Bit
add_subdirectory(lib/msgpack-0.5.9)
add_subdirectory(lib/mk_config)
add_subdirectory(lib/jsmn)

# XBee library: add support for XBee devices
if(WITH_XBEE)
  add_subdirectory(lib/libxbee-v3)
endif()

# Instruct CMake to build the Fluent Bit Core
add_subdirectory(src/)
