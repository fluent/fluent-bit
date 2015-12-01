cmake_minimum_required(VERSION 2.8)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -Wno-deprecated-declarations ")
project(fluent-bit)

include(GNUInstallDirs)

# Output paths
set(FLB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/library")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/library")

# Fluent Bit Version
set(FLB_VERSION_MAJOR  0)
set(FLB_VERSION_MINOR  4)
set(FLB_VERSION_PATCH  0)
set(FLB_VERSION_STR "${FLB_VERSION_MAJOR}.${FLB_VERSION_MINOR}.${FLB_VERSION_PATCH}")

# Build Options
option(WITH_ALL      "Enable all features"         No)
option(WITH_DEBUG    "Build with debug symbols"    No)
option(WITH_TLS      "Build with SSL/TLS support"  No)
option(WITHOUT_BIN   "Do not build executable"     No)
option(WITH_STATS    "Enable stats support"       Yes)
option(WITH_VALGRIND "Enable Valgrind support"     No)

# Build Plugins
option(WITH_IN_XBEE     "Enable XBee input plugin"            No)
option(WITH_IN_CPU      "Enable CPU input plugin"            Yes)
option(WITH_IN_HTTP     "Enable HTTP input plugin"            No)
option(WITH_IN_MEM      "Enable Memory input plugin"         Yes)
option(WITH_IN_KMSG     "Enable Kernel log input plugin"     Yes)
option(WITH_IN_LIB      "Enable library mode input plugin"   Yes)
option(WITH_IN_SERIAL   "Enable Serial input plugin"         Yes)
option(WITH_IN_STDIN    "Enable Standard input plugin"       Yes)
option(WITH_IN_MQTT     "Enable MQTT Broker input plugin"     No)
option(WITH_OUT_FLUENTD "Enable Fluentd output plugin"       Yes)
option(WITH_OUT_TD      "Enable Treasure Data output plugin" Yes)
option(WITH_OUT_STDOUT  "Enable STDOUT output plugin"        Yes)
if(ENABLE_TESTS)
  option(WITH_OUT_NULL  "Enable dev null output plugin"        Yes)
endif()

# Enable all features
if(WITH_ALL)
  set(WITH_DEBUG       1)
  set(WITH_TLS         1)
  set(WITH_IN_XBEE     1)
  set(WITH_IN_CPU      1)
  set(WITH_IN_MEM      1)
  set(WITH_IN_KMSG     1)
  set(WITH_IN_MQTT     1)
  set(WITH_IN_SERIAL   1)
  set(WITH_IN_STDIN    1)
  set(WITH_OUT_FLUENTD 1)
  set(WITH_OUT_TD      1)
  set(WITH_OUT_STDOUT  1)
endif()

# Enable Debug symbols if specified
if(WITH_DEBUG)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

# General Headers
include_directories(
  include/
  lib/
  lib/msgpack-1.2.0/include
  lib/monkey/
  lib/monkey/mk_core/include
  )

# mk_core is aware about jemalloc usage, we need to disable this as
# fluent-bit do not use it.
set(WITH_SYSTEM_MALLOC  1 CACHE BOOL "Use system memory allocator")

# MsgPack options
option(MSGPACK_ENABLE_CXX             OFF)
option(MSGPACK_ENABLE_SHARED          OFF)
option(MSGPACK_BUILD_TESTS            OFF)
option(MSGPACK_BUILD_EXAMPLES         OFF)
add_subdirectory(lib/msgpack-1.2.0)

# Lib: build the core libraries used by Fluent-Bit
add_subdirectory(lib/jsmn)
if(WITH_IN_HTTP)
  option(WITHOUT_BIN     ON)
  option(WITHOUT_CONF    ON)
  set(WITHOUT_PLUGINS "auth,cgi,cheetah,dirlisting,fastcgi,logger,mandril,tls")
  add_subdirectory(lib/monkey)
else()
  add_subdirectory(lib/monkey/mk_core)
endif()

# SSL/TLS: add encryption support
if(WITH_OUT_TD)
  set(WITH_TLS ON)
endif()

if(WITH_TLS)
  add_definitions(-DHAVE_TLS)
  option(ENABLE_TESTING  OFF)
  option(ENABLE_PROGRAMS OFF)
  option(INSTALL_MBEDTLS_HEADERS OFF)
  add_subdirectory(lib/mbedtls-2.2.0)
  include_directories(lib/mbedtls-2.2.0/include)
endif()

if(WITH_STATS)
  add_definitions(-DHAVE_STATS)
  add_subdirectory(lib/cjson)
  include_directories(lib/cjson)
endif()

if(WITH_VALGRIND)
  add_definitions(-DUSE_VALGRIND)
endif()

configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_version.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_version.h"
  )

# Instruct CMake to build the Fluent Bit Core
add_subdirectory(include)
add_subdirectory(plugins)
add_subdirectory(src)
add_subdirectory(examples)

if(ENABLE_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
