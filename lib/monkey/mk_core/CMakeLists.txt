SET (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
include (CheckCSourceCompiles)

set(src
  mk_iov.c
  mk_file.c
  mk_rconf.c
  mk_string.c
  mk_memory.c
  mk_event.c
  mk_utils.c
  mk_rbtree.c
  mk_thread.c
  mk_thread_channel.c
  )

# It set's a definition and register into the mk_core_info.h file */
macro(MK_DEFINITION var)
  add_definitions(-D${var})
  set(MK_CORE_BUILD_FLAGS "${MK_CORE_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
endmacro()

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

if (NOT HAVE_EPOLL AND NOT HAVE_KQUEUE)
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

include_directories(include)
add_library(mk_core STATIC ${src})
target_link_libraries(mk_core ${CMAKE_THREAD_LIBS_INIT})

if(NOT MK_SYSTEM_MALLOC)
  target_link_libraries(mk_core libjemalloc)
endif()

add_subdirectory(include)
