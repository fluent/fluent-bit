set(src
  ${src}
  raw_msgpack_api.c
  )

find_package (Threads)
# add_executable(raw_msgpack_api_test ${src})
# target_link_libraries(raw_msgpack_api_test fluent-bit-shared)
# target_link_libraries(raw_msgpack_api_test ${CMAKE_THREAD_LIBS_INIT})

add_library(raw_msgpack_api SHARED ${src})
target_link_libraries(raw_msgpack_api fluent-bit-shared)
target_link_libraries(raw_msgpack_api ${CMAKE_THREAD_LIBS_INIT})

