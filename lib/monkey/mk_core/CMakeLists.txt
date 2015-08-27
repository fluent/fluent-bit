SET (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

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

include_directories(include)
add_library(mk_core STATIC ${src})
target_link_libraries(mk_core ${CMAKE_THREAD_LIBS_INIT})

if(NOT WITH_SYSTEM_MALLOC)
  target_link_libraries(mk_core libjemalloc)
endif()
