CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(FLUENT-BIT C)
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

# Build Options
OPTION(WITH_ALL    "Enable all features" OFF)
OPTION(WITH_XBEE   "Enable XBee support" OFF)
OPTION(WITH_DEBUG  "Build with debug symbols" OFF)
OPTION(WITHOUT_BIN "Do not build executable" OFF)

IF(WITH_ALL)
  SET(WITH_XBEE ON)
ENDIF()

# Enable Debug symbols if specified
IF(WITH_DEBUG)
  SET(CMAKE_BUILD_TYPE "Debug")
ENDIF()

# General Headers
INCLUDE_DIRECTORIES(include/)

# Lib: build the core libraries used by Fluent-Bit
ADD_SUBDIRECTORY(lib/msgpack-0.5.9)
ADD_SUBDIRECTORY(lib/mk_config)

# XBee library: add support for XBee devices
IF(WITH_XBEE)
  ADD_SUBDIRECTORY(lib/libxbee-v3)
ENDIF()

# Instruct CMake to build the Fluent Bit Core
ADD_SUBDIRECTORY(src/)
