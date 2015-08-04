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
option(WITH_IN_HTTP     "Enable HTTP input plugin"            No)
option(WITH_IN_MEM      "Enable Memory input plugin"         Yes)
option(WITH_IN_KMSG     "Enable Kernel log input plugin"     Yes)
option(WITH_IN_SERIAL   "Enable Serial input plugin"         Yes)
option(WITH_IN_STDIN    "Enable Standard input plugin"       Yes)
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
include_directories(include/ lib/ lib/msgpack-1.1.0/include lib/monkey/include)

# MSGPACK modification: disable the install routines.z
set(MSGPACK_NO_INSTALL 1)

# mk_core is aware about jemalloc usage, we need to disable this as
# fluent-bit do not use it.
set(WITH_SYSTEM_MALLOC  1 CACHE BOOL "Use system memory allocator")

# Lib: build the core libraries used by Fluent-Bit
add_subdirectory(lib/msgpack-1.1.0)
add_subdirectory(lib/jsmn)
if(WITH_IN_HTTP)
  set(WITHOUT_BIN     1 CACHE BOOL "Do not build binary")
  set(WITHOUT_CONF    1 CACHE BOOL "Skip configuration files")
  set(WITHOUT_PLUGINS "auth,cgi,cheetah,dirlisting,fastcgi,logger,mandril,tls")
  add_subdirectory(lib/monkey)
else()
  add_subdirectory(lib/monkey/mk_core)
endif()


# SSL/TLS: add encryption support
if(WITH_SSL_TLS)
  add_definitions(-DHAVE_SSL_TLS)
  add_subdirectory(lib/mbedtls-2.0.0)
endif()

# Instruct CMake to build the Fluent Bit Core
add_subdirectory(include)
add_subdirectory(plugins)
add_subdirectory(src)
