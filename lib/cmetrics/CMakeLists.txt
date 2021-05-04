cmake_minimum_required(VERSION 2.8)
project(cmetrics C)

# CMetrics Version
set(CMT_VERSION_MAJOR  0)
set(CMT_VERSION_MINOR  1)
set(CMT_VERSION_PATCH  0)
set(CMT_VERSION_STR "${CMT_VERSION_MAJOR}.${CMT_VERSION_MINOR}.${CMT_VERSION_PATCH}")

# Include helpers
include(cmake/macros.cmake)
include(CheckCSourceCompiles)

# Configuration options
option(CMT_DEV     "Enable development mode"  No)
option(CMT_TESTS   "Enable unit testing"      No)

if(CMT_DEV)
  set(CMT_TESTS   Yes)
endif()

# Include headers and dependency headers
include_directories(
  include
  lib/monkey/include
  lib/xxHash-0.8.0/
  )

# timespec_get() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     return timespec_get(&tm, TIME_UTC);
  }" CMT_HAVE_TIMESPEC_GET)
if(CMT_HAVE_TIMESPEC_GET)
  CMT_DEFINITION(CMT_HAVE_TIMESPEC_GET)
endif()

# clock_get_time() support for macOS.
check_c_source_compiles("
  #include <mach/clock.h>
  #include <mach/mach.h>
  int main() {
      clock_serv_t cclock;
      mach_timespec_t mts;
      host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
      clock_get_time(cclock, &mts);
      return mach_port_deallocate(mach_task_self(), cclock);
  }" CMT_HAVE_CLOCK_GET_TIME)
if(CMT_HAVE_CLOCK_GET_TIME)
  CMT_DEFINITION(CMT_HAVE_CLOCK_GET_TIME)
endif()

# FIXME: MessagePack support
check_c_source_compiles("
  #include \"../../../lib/msgpack-c/include/msgpack.h\"
  int main() {
     msgpack_packer pck;
     msgpack_sbuffer sbuf;
     return 0;
  }" CMT_HAVE_MSGPACK)

configure_file(
  "${PROJECT_SOURCE_DIR}/include/cmetrics/cmt_info.h.in"
  "${PROJECT_SOURCE_DIR}/include/cmetrics/cmt_info.h"
  )

# xxHash
if(NOT TARGET xxhash)
  # Do something when target found
  set(XXHASH_BUILD_ENABLE_INLINE_API OFF)
  set(XXHASH_BUILD_XXHSUM OFF)
  set(BUILD_SHARED_LIBS OFF)
  add_subdirectory(lib/xxHash-0.8.0/cmake_unofficial EXCLUDE_FROM_ALL)
endif()

# mpack
if(NOT TARGET mpack-static)
  include_directories(lib/mpack/src/)
  add_subdirectory(lib/mpack EXCLUDE_FROM_ALL)
endif()

# Source code
add_subdirectory(src)

# Tests
if(CMT_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
