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
  set(MK_CORE_INFO_DEFS "${MK_CORE_INFO_DEFS} ${var}")
endmacro()

# Set threading system
if (CMAKE_SYSTEM_NAME MATCHES "Windows")
  MK_DEFINITION(MK_THREADS_WIN32)
  set(src
    ${src}
    "external/winpthreads.c"
    )
  add_subdirectory(deps/)
else()
  if (MK_EVENT_LOOP_LIBEVENT)
    add_subdirectory(deps/)
  endif()
  MK_DEFINITION(MK_THREADS_POSIX)
endif()

# Check for full stat(2) support
check_c_source_compiles("
  #include <sys/types.h>
  #include <sys/stat.h>
  int main() {
    struct stat st;
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
  MK_DEFINITION(MK_HAVE_SYS_UIO_H)
endif()

# We need to compile mk_iov regardless of system UIO support
set(src "${src}"
  mk_iov.c
  )

check_c_source_compiles("
  #define _GNU_SOURCE
  #include <string.h>
  int main() {
     char  haystack[] = \"1234\";
     char  needle[] = \"23\";
     void *result;

     result = memmem(haystack, sizeof(haystack) - 1, needle, sizeof(needle) - 1);

     return (NULL != result);
  }" HAVE_MEMMEM)

if (HAVE_MEMMEM)
  MK_DEFINITION(MK_HAVE_MEMMEM)
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

# Check for a valid event loop mechanism

# select(2)
check_c_source_compiles("
  #include <stdio.h>
  #include <sys/select.h>
  int main() {
     fd_set rfds;
     struct timeval tv;
     return select(1, &rfds, NULL, NULL, &tv);
  }" HAVE_SELECT)

check_c_source_compiles("
  #include <poll.h>
  int main() {
     struct pollfd fds[1];
     fds[0].fd = 0;
     fds[0].events = POLLIN;
     return poll(fds, 1, 1);
  }" HAVE_POLL)

check_c_source_compiles("
  #include <sys/event.h>
  int main() {
     return kqueue();
  }" HAVE_KQUEUE)

check_c_source_compiles("
  #include <sys/epoll.h>
  int main() {
     return epoll_create(1);
  }" HAVE_EPOLL)

if (MK_EVENT_LOOP_SELECT)
  if (NOT HAVE_SELECT)
    message(FATAL_ERROR "Event loop backend > select(2) not available")
  else()
    message(STATUS "Event loop backend > select(2)")
    MK_DEFINITION(MK_EVENT_LOOP_SELECT)
  endif()
endif()

if (MK_EVENT_LOOP_POLL)
  if (NOT HAVE_POLL)
    message(FATAL_ERROR "Event loop backend > poll(2) not available")
  else()
    message(STATUS "Event loop backend > poll(2)")
    MK_DEFINITION(MK_EVENT_LOOP_POLL)
  endif()
endif()

if (MK_EVENT_LOOP_KQUEUE)
  if (NOT HAVE_KQUEUE)
    message(FATAL_ERROR "Event loop backend > kqueue(2) not available")
  else()
    message(STATUS "Event loop backend > kqueue(2)")
    MK_DEFINITION(MK_EVENT_LOOP_KQUEUE)
  endif()
endif()

if (MK_EVENT_LOOP_EPOLL)
  if (NOT HAVE_EPOLL)
    message(FATAL_ERROR "Event loop backend > epoll(2) not available")
  else()
    message(STATUS "Event loop backend > epoll(2)")
    MK_DEFINITION(MK_EVENT_LOOP_EPOLL)
  endif()
endif()

if (MK_EVENT_LOOP_LIBEVENT)
    message(STATUS "Event loop backend > libevent")
    MK_DEFINITION(MK_EVENT_LOOP_LIBEVENT)
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
  "${PROJECT_BINARY_DIR}/include/monkey/mk_core/mk_core_info.h"
  )

add_library(mk_core STATIC ${src})
target_link_libraries(mk_core ${CMAKE_THREAD_LIBS_INIT})

if (MK_EVENT_LOOP_LIBEVENT)
  target_link_libraries(mk_core event)
endif()
