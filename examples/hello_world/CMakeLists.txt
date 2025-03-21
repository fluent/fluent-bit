set(src
  ${src}
  hello_world.c
  )

find_package (Threads)
add_executable(hello_world ${src})
target_link_libraries(hello_world fluent-bit-shared)
target_link_libraries(hello_world ${CMAKE_THREAD_LIBS_INIT})
