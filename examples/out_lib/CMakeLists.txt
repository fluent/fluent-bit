set(src
  ${src}
  out_lib.c
  )

find_package (Threads)
add_executable(out_lib ${src})
target_link_libraries(out_lib fluent-bit-shared)
target_link_libraries(out_lib ${CMAKE_THREAD_LIBS_INIT})
