project(td)

set(src
  ${src}
  td.cc
  )

find_package (Threads)
add_executable(td ${src})
target_link_libraries(td fluent-bit-shared)
target_link_libraries(td ${CMAKE_THREAD_LIBS_INIT})
