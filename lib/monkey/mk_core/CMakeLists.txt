include (CheckCSourceCompiles)

set(src
  mk_rconf.c
  mk_string.c
  mk_memory.c
  mk_event.c
  mk_utils.c
  )

# Headers
include_directories(../include/monkey/)

# It set's a definition and register into the mk_core_info.h file */
macro(MK_DEFINITION var)
  add_definitions(-D${var})
  set(MK_CORE_BUILD_FLAGS "${MK_CORE_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
endmacro()

# Set threading system
if (CMAKE_SYSTEM_NAME MATCHES "Windows")
  MK_DEFINITION(MK_THREADS_WIN32)
  set(src
    ${src}
    "external/winpthreads.c"
    )
  include_directories(deps/libevent/include)
  include_directories("${PROJECT_BINARY_DIR}/lib/monkey/mk_core/deps/libevent/include/")
  add_subdirectory(deps/)
else()
  MK_DEFINITION(MK_THREADS_POSIX)
endif()

# Check for full stat(2) support
check_c_source_compiles("
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <unistd.h>
  int main() {
    int x = S_IXUSR;
    S_ISLNK(0);
    return 0;
  }" HAVE_STAT_H)
if (HAVE_STAT_H)
  set(src "${src}"
    mk_file.c
    )
  MK_DEFINITION(MK_HAVE_STAT_H)
endif()

# Check if sys/uio.h exists
check_c_source_compiles("
  #include <sys/uio.h>
  int main() {
     return 0;
  }" HAVE_SYS_UIO_H)

if (HAVE_SYS_UIO_H)
  set(src "${src}"
    mk_iov.c
    )
  MK_DEFINITION(MK_HAVE_SYS_UIO_H)
endif()

# Check for unistd.h
check_c_source_compiles("
  #include <unistd.h>
  int main() {
     return 0;
  }" HAVE_UNISTD_H)
if (HAVE_UNISTD_H)
  MK_DEFINITION(MK_HAVE_UNISTD_H)
endif()

# Lookup event-loop mechanism: do we need to fallback to select(2) ?
check_c_source_compiles("
  #include <sys/epoll.h>
  int main() {
     return epoll_create(1);
  }" HAVE_EPOLL)

check_c_source_compiles("
  #include <sys/event.h>
  int main() {
     return kqueue();
  }" HAVE_KQUEUE)


if ((NOT HAVE_EPOLL AND NOT HAVE_KQUEUE) OR MK_USE_EVENT_SELECT)
  message(STATUS "Event loop backend > select(2)")
  MK_DEFINITION(MK_HAVE_EVENT_SELECT)
endif()

# Validate timerfd_create()
check_c_source_compiles("
  #include <sys/timerfd.h>
  int main() {
     return timerfd_create(CLOCK_REALTIME, 0);
  }" HAVE_TIMERFD_CREATE)

if (HAVE_TIMERFD_CREATE)
  MK_DEFINITION(MK_HAVE_TIMERFD_CREATE)
endif()

# Validate eventfd()
check_c_source_compiles("
  #include <sys/eventfd.h>
  int main() {
     return eventfd(0, EFD_CLOEXEC);
  }" HAVE_EVENTFD)

if (HAVE_EVENTFD)
  MK_DEFINITION(MK_HAVE_EVENTFD)
endif()

# Validate memrchr()
check_c_source_compiles("
   #define _GNU_SOURCE
   #include <string.h>
   int main() {
      memrchr(\"test\", 'e', 4);
      return 0;
   }" MK_HAVE_MEMRCHR)

include(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(memrchr MK_HAVE_MEMRCHR)

if (MK_HAVE_MEMRCHR)
  MK_DEFINITION(MK_HAVE_MEMRCHR)
endif()

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/../include/monkey/mk_core/mk_core_info.h.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/../include/monkey/mk_core/mk_core_info.h"
  )

add_library(mk_core STATIC ${src})
target_link_libraries(mk_core ${CMAKE_THREAD_LIBS_INIT})

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
  target_link_libraries(mk_core event)
endif()

if(NOT MK_SYSTEM_MALLOC)
  target_link_libraries(mk_core libjemalloc)
endif()
