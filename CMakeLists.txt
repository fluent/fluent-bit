cmake_minimum_required(VERSION 2.8)
project(fluent-bit)

# Update CFLAGS
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC ")
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__=__FILE__")
endif()

include(GNUInstallDirs)
include(ExternalProject)
include(cmake/FindJournald.cmake)
include(cmake/FindMonkey.cmake)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/sanitizers-cmake/cmake" ${CMAKE_MODULE_PATH})
find_package(Sanitizers)

# Output paths
set(FLB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/library")

# Fluent Bit Version
set(FLB_VERSION_MAJOR  1)
set(FLB_VERSION_MINOR  0)
set(FLB_VERSION_PATCH  0)
set(FLB_VERSION_STR "${FLB_VERSION_MAJOR}.${FLB_VERSION_MINOR}.${FLB_VERSION_PATCH}")

# Build Options
option(FLB_ALL                "Enable all features"           No)
option(FLB_DEBUG              "Build with debug symbols"      No)
option(FLB_COVERAGE           "Build with code-coverage"      No)
option(FLB_JEMALLOC           "Build with Jemalloc support"   No)
option(FLB_REGEX              "Build wiht Regex support"     Yes)
option(FLB_TLS                "Build with SSL/TLS support"    No)
option(FLB_BINARY             "Build executable binary"      Yes)
option(FLB_EXAMPLES           "Build examples"               Yes)
option(FLB_SHARED_LIB         "Build shared library"         Yes)
option(FLB_VALGRIND           "Enable Valgrind support"       No)
option(FLB_TRACE              "Enable trace mode"             No)
option(FLB_TESTS_RUNTIME      "Enable runtime tests"          No)
option(FLB_TESTS_INTERNAL     "Enable internal tests"         No)
option(FLB_MTRACE             "Enable mtrace support"         No)
option(FLB_POSIX_TLS          "Force POSIX thread storage"    No)
option(FLB_INOTIFY            "Enable inotify support"       Yes)
option(FLB_SQLDB              "Enable SQL embedded DB"        No)
option(FLB_HTTP_SERVER        "Enable HTTP Server"            No)
option(FLB_BACKTRACE          "Enable stacktrace support"    Yes)
option(FLB_LUAJIT             "Enable Lua Scripting support" Yes)
option(FLB_STATIC_CONF        "Build binary using static configuration")
option(FLB_CORO_STACK_SIZE    "Set coroutine stack size")

# Metrics: Experimental Feature, disabled by default on 0.12 series
# but enabled in the upcoming 0.13 release. Note that development
# mode enable this feature.
option(FLB_METRICS            "Enable metrics support"       No)

# Proxy Plugins
option(FLB_PROXY_GO           "Enable Go plugins support"   Yes)

# Advanced options for Flushing methods
# =====================================
# Flush methods defines under what kind of context/environment the plugins
# flush callback is invoked. Since this is done through co-routines
# there are two options available:
#
# FLB_FLUSH_LIBCO: set by default, use lib/flb_libco implementation which
# supports amd64, arm, x86 and ppc.
#
# FLB_FLUSH_UCONTEXT (DEPRECATED): It uses POSIX ucontext for co-routines
# implementation.
# Despites this is POSIX deprecated, it's supported on Linux and BSD
# systems, but specific old-toolchains do not implement it.

# Build-in Plugins
option(FLB_IN_CPU          "Enable CPU input plugin"            Yes)
option(FLB_IN_DISK         "Enable Disk input plugin"           Yes)
option(FLB_IN_EXEC         "Enable Exec input plugin"           Yes)
option(FLB_IN_FORWARD      "Enable Forward input plugin"        Yes)
option(FLB_IN_HEALTH       "Enable Health input plugin"         Yes)
option(FLB_IN_HTTP         "Enable HTTP input plugin"            No)
option(FLB_IN_MEM          "Enable Memory input plugin"         Yes)
option(FLB_IN_KMSG         "Enable Kernel log input plugin"     Yes)
option(FLB_IN_LIB          "Enable library mode input plugin"   Yes)
option(FLB_IN_RANDOM       "Enable random input plugin"         Yes)
option(FLB_IN_SERIAL       "Enable Serial input plugin"         Yes)
option(FLB_IN_STDIN        "Enable Standard input plugin"       Yes)
option(FLB_IN_SYSLOG       "Enable Syslog input plugin"         Yes)
option(FLB_IN_TAIL         "Enable Tail input plugin"           Yes)
option(FLB_IN_TCP          "Enable TCP input plugin"            Yes)
option(FLB_IN_MQTT         "Enable MQTT Broker input plugin"    Yes)
option(FLB_IN_HEAD         "Enable Head input plugin"           Yes)
option(FLB_IN_PROC         "Enable Process input plugin"        Yes)
option(FLB_IN_SYSTEMD      "Enable Systemd input plugin"        Yes)
option(FLB_IN_DUMMY        "Enable Dummy input plugin"          Yes)
option(FLB_IN_NETIF        "Enable NetworkIF input plugin"      Yes)
option(FLB_OUT_AZURE       "Enable Azure output plugin"         Yes)
option(FLB_OUT_COUNTER     "Enable Counter output plugin"       Yes)
option(FLB_OUT_ES          "Enable Elasticsearch output plugin" Yes)
option(FLB_OUT_EXIT        "Enable Exit output plugin"          Yes)
option(FLB_OUT_FORWARD     "Enable Forward output plugin"       Yes)
option(FLB_OUT_GELF        "Enable GELF output plugin"          Yes)
option(FLB_OUT_HTTP        "Enable HTTP output plugin"          Yes)
option(FLB_OUT_INFLUXDB    "Enable InfluxDB output plugin"      Yes)
option(FLB_OUT_NATS        "Enable NATS output plugin"          Yes)
option(FLB_OUT_PLOT        "Enable Plot output plugin"          Yes)
option(FLB_OUT_FILE        "Enable file output plugin"          Yes)
option(FLB_OUT_TD          "Enable Treasure Data output plugin" Yes)
option(FLB_OUT_RETRY       "Enable Retry test output plugin"     No)
option(FLB_OUT_SPLUNK      "Enable Splunk output plugin"        Yes)
option(FLB_OUT_STACKDRIVER "Enable Stackdriver output plugin"   Yes)
option(FLB_OUT_STDOUT      "Enable STDOUT output plugin"        Yes)
option(FLB_OUT_LIB         "Enable library mode output plugin"  Yes)
option(FLB_OUT_NULL        "Enable dev null output plugin"      Yes)
option(FLB_OUT_FLOWCOUNTER "Enable flowcount output plugin"     Yes)
option(FLB_OUT_KAFKA       "Enable Kafka output plugin"          No)
option(FLB_OUT_KAFKA_REST  "Enable Kafka Rest output plugin"    Yes)
option(FLB_FILTER_GREP     "Enable grep filter"                 Yes)
option(FLB_FILTER_MODIFY   "Enable modify filter"               Yes)
option(FLB_FILTER_STDOUT   "Enable stdout filter"               Yes)
option(FLB_FILTER_PARSER   "Enable parser filter"               Yes)
option(FLB_FILTER_KUBERNETES "Enable kubernetes filter"         Yes)
option(FLB_FILTER_THROTTLE "Enable throttle filter"             Yes)
option(FLB_FILTER_RECORD_MODIFIER "Enable record_modifier filter" Yes)
option(FLB_FILTER_NEST     "Enable nest filter"                   Yes)
option(FLB_FILTER_LUA      "Enable Lua scripting filter"          Yes)

# Enable all features
if(FLB_ALL)
  # Global
  set(FLB_DEBUG        1)
  set(FLB_TLS          1)

  # Input plugins
  set(FLB_IN_CPU       1)
  set(FLB_IN_MEM       1)
  set(FLB_IN_KMSG      1)
  set(FLB_IN_MQTT      1)
  set(FLB_IN_SERIAL    1)
  set(FLB_IN_STDIN     1)
  set(FLB_IN_HEAD      1)
  set(FLB_IN_PROC      1)
  set(FLB_IN_DISK      1)
  set(FLB_IN_DUMMY     1)
  set(FLB_IN_NETIF     1)
  set(FLB_IN_EXEC      1)

  # Output plugins
  set(FLB_OUT_ES       1)
  set(FLB_OUT_FORWARD  1)
  set(FLB_OUT_GELF     1)
  set(FLB_OUT_HTTP     1)
  set(FLB_OUT_NATS     1)
  set(FLB_OUT_NULL     1)
  set(FLB_OUT_PLOT     1)
  set(FLB_OUT_FILE     1)
  set(FLB_OUT_RETRY    1)
  set(FLB_OUT_TD       1)
  set(FLB_OUT_STDOUT   1)
  set(FLB_OUT_LIB      1)
  set(FLB_OUT_FLOWCOUNTER 1)
endif()

if(FLB_DEV)
  set(FLB_DEBUG          On)
  set(FLB_TRACE          On)
  set(FLB_METRICS        On)
  set(FLB_HTTP_SERVER    On)
  set(FLB_TESTS_INTERNAL On)
endif()

if(FLB_COVERAGE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 --coverage -fprofile-arcs -ftest-coverage")
  set(CMAKE_BUILD_TYPE "Debug")
endif()

if(FLB_OUT_GELF)
  find_package( ZLIB )
  if ( NOT ZLIB_FOUND )
     set(FLB_OUT_GELF 0)
  endif()
endif()

# Macro to set definitions
macro(FLB_DEFINITION var)
  add_definitions(-D${var})
  set(FLB_BUILD_FLAGS "${FLB_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
  set(FLB_INFO_FLAGS "${FLB_INFO_FLAGS} ${var}")
endmacro()

macro(FLB_OPTION option value)
  set(${option} ${value} CACHE "" INTERNAL FORCE)
endmacro()

# Enable Debug symbols if specified
if(FLB_DEBUG)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

# Is sanitize_address defined ?
if(SANITIZE_ADDRESS)
  FLB_DEFINITION(FLB_HAVE_SANITIZE_ADDRESS)
endif()

# General Headers
include_directories(
  include/
  lib/
  lib/flb_libco
  lib/msgpack-3.1.1/include
  lib/chunkio/include
  lib/LuaJIT-2.1.0-beta3/src/
  ${MONKEY_INCLUDE_DIR}
  )

# On Windows, the core uses libevent
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  include_directories(
    lib/monkey/mk_core/deps/libevent/include
    ${PROJECT_BINARY_DIR}/lib/monkey/mk_core/deps/libevent/include
    )
endif()

# mk_core is aware about jemalloc usage, we need to disable this as
# fluent-bit do not use it.
set(WITH_SYSTEM_MALLOC  1 CACHE BOOL "Use system memory allocator")

# MsgPack options
option(MSGPACK_ENABLE_CXX             OFF)
option(MSGPACK_ENABLE_SHARED          OFF)
option(MSGPACK_BUILD_TESTS            OFF)
option(MSGPACK_BUILD_EXAMPLES         OFF)
add_subdirectory(lib/msgpack-3.1.1 EXCLUDE_FROM_ALL)

# Chunk I/O
FLB_OPTION(CIO_LIB_STATIC  ON)
FLB_OPTION(CIO_LIB_SHARED  OFF)
add_subdirectory(lib/chunkio EXCLUDE_FROM_ALL)

# Lib: build the core libraries used by Fluent-Bit
FLB_DEFINITION(JSMN_PARENT_LINKS)
FLB_DEFINITION(JSMN_STRICT)
add_subdirectory(lib/jsmn)

# Runtime Tests (filter_kubernetes) requires HTTP Server
if(FLB_TESTS_RUNTIME)
  FLB_OPTION(FLB_HTTP_SERVER  ON)
endif()

# MK Core
macro(MK_SET_OPTION option value)
  set(${option} ${value} CACHE "" INTERNAL FORCE)
endmacro()
MK_SET_OPTION(MK_SYSTEM_MALLOC  ON)
MK_SET_OPTION(MK_DEBUG          ON)

# Build Monkey HTTP Server
if(FLB_HTTP_SERVER)
  add_subdirectory(lib/monkey/ EXCLUDE_FROM_ALL)
else()
  add_subdirectory(lib/monkey/mk_core EXCLUDE_FROM_ALL)
endif()

# SSL/TLS: add encryption support
if(FLB_OUT_TD)
  set(FLB_TLS ON)
endif()

if(FLB_TLS)
  FLB_DEFINITION(FLB_HAVE_TLS)
  option(ENABLE_TESTING  OFF)
  option(ENABLE_PROGRAMS OFF)
  option(INSTALL_MBEDTLS_HEADERS OFF)
  add_subdirectory(lib/mbedtls-2.14.1 EXCLUDE_FROM_ALL)
  include_directories(lib/mbedtls-2.14.1/include)
endif()

# Metrics
if(FLB_METRICS)
  FLB_DEFINITION(FLB_HAVE_METRICS)
endif()

if(FLB_IN_TAIL)
  set(FLB_SQLDB ON)
endif()

if(FLB_SQLDB)
  FLB_DEFINITION(FLB_HAVE_SQLDB)
  add_subdirectory(lib/sqlite-amalgamation-3240000)
  include_directories(lib/sqlite-amalgamation-3240000)
endif()

if(FLB_TRACE)
  FLB_DEFINITION(FLB_HAVE_TRACE)
endif()

if(FLB_HTTP_SERVER)
  FLB_OPTION(FLB_METRICS ON)
  FLB_DEFINITION(FLB_HAVE_METRICS)
  FLB_DEFINITION(FLB_HAVE_HTTP_SERVER)
endif()

FLB_DEFINITION(FLB_HAVE_FLUSH_LIBCO)
if(NOT TARGET co)
  add_subdirectory(lib/flb_libco)
endif()

# Systemd Journald support
if(JOURNALD_FOUND)
  FLB_DEFINITION(FLB_HAVE_SYSTEMD)
else()
  FLB_OPTION(FLB_IN_SYSTEMD OFF)
endif()

# Valgrind support
check_c_source_compiles("
  #include <valgrind/valgrind.h>
  int main() {
     return 0;
  }" FLB_HAVE_VALGRIND)

if(FLB_VALGRIND OR FLB_HAVE_VALGRIND)
  FLB_DEFINITION(FLB_HAVE_VALGRIND)
endif()

# fork(2) support
check_c_source_compiles("
  #include <unistd.h>
  int main() {
     fork();
     return 0;
  }" FLB_HAVE_FORK)

if(FLB_HAVE_FORK)
  FLB_DEFINITION(FLB_HAVE_FORK)
endif()

# mtrace support
if(FLB_MTRACE)
  check_c_source_compiles("
    #include <mcheck.h>
    int main() {
       return 0;
    }" FLB_HAVE_MTRACE)

  if(FLB_HAVE_MTRACE AND FLB_DEBUG)
    FLB_DEFINITION(FLB_HAVE_MTRACE)
  endif()
endif()

# timespec_get() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     return timespec_get(&tm, TIME_UTC);
  }" FLB_HAVE_TIMESPEC_GET)
if(FLB_HAVE_TIMESPEC_GET)
  FLB_DEFINITION(FLB_HAVE_TIMESPEC_GET)
endif()

# Build tools/xxd-c
add_subdirectory(tools/xxd-c)

# Static configuration generator (using xxd-c)
if(FLB_STATIC_CONF)
  FLB_DEFINITION(FLB_HAVE_STATIC_CONF)
  add_subdirectory(gen_static_conf)
endif()

# Special definition to set the coroutine stack size
if(FLB_CORO_STACK_SIZE)
  add_definitions(-DFLB_CORO_STACK_SIZE=${FLB_CORO_STACK_SIZE})
  set(FLB_BUILD_FLAGS "${FLB_BUILD_FLAGS}#ifndef FLB_CORO_STACK_SIZE\n#define FLB_CORO_STACK_SIZE ${FLB_CORO_STACK_SIZE}\n#endif\n")
else()

endif()

# TD Agent options
if(FLB_TD)
  FLB_DEFINITION(FLB_IS_TD_AGENT)
  FLB_OPTION(FLB_JEMALLOC ON)
  set(FLB_PROG_NAME "TD Agent Bit")
  set(FLB_OUT_NAME "td-agent-bit")
  set(WITHOUT_HEADERS On)
else()
  set(FLB_PROG_NAME "Fluent Bit")
  set(FLB_OUT_NAME "fluent-bit")
endif()

if(FLB_PROXY_GO AND (NOT CMAKE_SYSTEM_NAME MATCHES "Windows"))
  FLB_DEFINITION(FLB_HAVE_PROXY_GO)
else()
  if(FLB_PROXY_GO)
    unset(FLB_PROXY_GO CACHE)
  endif()
endif()

if("${GNU_HOST}" STREQUAL "")
    set(AUTOCONF_HOST_OPT "")
else()
    set(AUTOCONF_HOST_OPT "--host=${GNU_HOST}")
endif()

# Memory Allocator
# ================
if(FLB_JEMALLOC AND ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  FLB_DEFINITION(FLB_HAVE_JEMALLOC)
  FLB_DEFINITION(JEMALLOC_MANGLE)

  # Link to Jemalloc as an external dependency
  ExternalProject_Add(jemalloc
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/jemalloc-5.1.0
    CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/lib/jemalloc-5.1.0/configure ${AUTOCONF_HOST_OPT} --with-lg-quantum=3 --enable-cc-silence --prefix=<INSTALL_DIR>
    CFLAGS=-std=gnu99\ -Wall\ -pipe\ -g3\ -O3\ -funroll-loops
    BUILD_COMMAND $(MAKE)
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/
    INSTALL_COMMAND $(MAKE) install_lib_static install_include)
  add_library(libjemalloc STATIC IMPORTED GLOBAL)
  set_target_properties(libjemalloc PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/lib/libjemalloc_pic.a")
  add_dependencies(libjemalloc jemalloc)
  include_directories("${CMAKE_CURRENT_BINARY_DIR}/include/")
else()
  FLB_OPTION(FLB_JEMALLOC OFF)
endif()

# LibBacktrace (friendly stacktrace support)
# =========================================
if(FLB_BACKTRACE)
  FLB_DEFINITION(FLB_HAVE_LIBBACKTRACE)
  ExternalProject_Add(backtrace
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/libbacktrace-5a99ff7f/
    CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/lib/libbacktrace-5a99ff7f/configure ${AUTOCONF_HOST_OPT} --prefix=<INSTALL_DIR> --enable-shared=no --enable-static=yes
    BUILD_COMMAND $(MAKE)
    )
  add_library(libbacktrace STATIC IMPORTED GLOBAL)
  set_target_properties(libbacktrace PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/backtrace-prefix/lib/libbacktrace.a")
  add_dependencies(libbacktrace backtrace)
  include_directories("${CMAKE_CURRENT_BINARY_DIR}/backtrace-prefix/include/")
endif()

# Onigmo (Regex Engine)
# =====================
if(FLB_REGEX)
  ExternalProject_Add(onigmo
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/onigmo
    CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/lib/onigmo/configure ${AUTOCONF_HOST_OPT} --with-pic --disable-shared --enable-static --prefix=<INSTALL_DIR>
    CFLAGS=-std=gnu99\ -Wall\ -pipe\ -g3\ -O3\ -funroll-loops
    BUILD_COMMAND $(MAKE)
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/
    INSTALL_COMMAND $(MAKE) install)
  add_library(libonigmo STATIC IMPORTED GLOBAL)
  set_target_properties(libonigmo PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/lib/libonigmo.a")
  add_dependencies(libonigmo onigmo)
  include_directories("${CMAKE_CURRENT_BINARY_DIR}/include/")
  FLB_DEFINITION(FLB_HAVE_REGEX)
endif()

# LuaJIT (Scripting Support)
# ==========================
if(FLB_LUAJIT)
  set(LUA_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib/LuaJIT-2.1.0-beta3)
  ExternalProject_Add(luajit
    SOURCE_DIR ${LUA_PATH}
    CONFIGURE_COMMAND ${LUA_PATH}/configure
    BUILD_COMMAND $(MAKE) BUILD_MODE=static XCFLAGS="-fPIC" -C ${LUA_PATH}
    INSTALL_COMMAND cp ${LUA_PATH}/src/libluajit.a "${CMAKE_CURRENT_BINARY_DIR}/lib/libluajit.a")
  add_library(libluajit STATIC IMPORTED GLOBAL)
  set_target_properties(libluajit PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/lib/libluajit.a")
  add_dependencies(libluajit luajit)
  include_directories("${CMAKE_CURRENT_BINARY_DIR}/include/")
  FLB_DEFINITION(FLB_HAVE_LUAJIT)
endif()

# Pthread Local Storage
# =====================
# By default we expect the compiler already support thread local storage
# through __thread type, otherwise Fluent Bit fallback to the old POSIX
# pthread mode (pthread_key_t), or it can be forced setting FLB_POSIX_TLS
# for testing/compatibility purposes.
if(NOT FLB_POSIX_TLS)
  check_c_source_compiles("
   __thread int a;
   int main() {
       __tls_get_addr(0);
       return 0;
   }" FLB_HAVE_C_TLS)
  if(FLB_HAVE_C_TLS)
    FLB_DEFINITION(FLB_HAVE_C_TLS)
  endif()
endif()

# accept(4)
check_c_source_compiles("
    #define _GNU_SOURCE
    #include <stdio.h>
    #include <sys/socket.h>
    int main() {
        accept4(0, NULL, NULL, 0);
        return 0;
    }" FLB_HAVE_ACCEPT4)
if(FLB_HAVE_ACCEPT4)
  FLB_DEFINITION(FLB_HAVE_ACCEPT4)
endif()

# inotify_init(2)
if(FLB_INOTIFY)
  check_c_source_compiles("
    #include <sys/inotify.h>
    int main() {
        return inotify_init1(0);
    }" FLB_HAVE_INOTIFY)
  if(FLB_HAVE_INOTIFY)
    FLB_DEFINITION(FLB_HAVE_INOTIFY)
  endif()
endif()

configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_info.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_info.h"
  )

configure_file(
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_version.h.in"
  "${PROJECT_SOURCE_DIR}/include/fluent-bit/flb_version.h"
  )

# Instruct CMake to build the Fluent Bit Core
add_subdirectory(include)
add_subdirectory(plugins)
add_subdirectory(src)

if(FLB_EXAMPLES)
  add_subdirectory(examples)
endif()

if(FLB_TESTS_RUNTIME)
  enable_testing()
  add_subdirectory(tests/runtime/)
endif()

if(FLB_TESTS_INTERNAL)
  enable_testing()
  add_subdirectory(tests/internal/)
endif()


### CPACK / RPM
set(CPACK_PACKAGE_VERSION ${FLB_VERSION_STR})
set(CPACK_GENERATOR "RPM")
set(CPACK_PACKAGE_NAME "td-agent-bit")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "Eduardo Silva <eduardo@treasure-data.com>")
set(CPACK_PACKAGE_VENDOR "Treasure Data")
set(CPACK_PACKAGING_INSTALL_PREFIX "/opt/td-agent-bit")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Daemons")
set(CPACK_RPM_PACKAGE_LICENSE "Apache v2.0")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/cpack/description")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Fast data collector for Linux")
set(CPACK_RPM_SPEC_MORE_DEFINE "%define ignore \#")
set(CPACK_RPM_USER_FILELIST
	"%ignore /lib"
	"%ignore /lib/systemd"
	"%ignore /lib/systemd/system"
	"%ignore /lib64"
	"%ignore /lib64/pkgconfig"
	"%ignore /opt"
	"%ignore /etc")
set(CPACK_PACKAGING_INSTALL_PREFIX "/")
include(CPack)
