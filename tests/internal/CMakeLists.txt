find_package(Threads REQUIRED)

include_directories(cutest/)

set(UNIT_TESTS
  hashtable.c)

foreach(source_file ${UNIT_TESTS})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we flb-it-${source_file_we})
  add_executable(
    ${source_file_we}
    ${source_file}
    )

  if(FLB_JEMALLOC)
    target_link_libraries(${source_file_we} libjemalloc ${CMAKE_THREAD_LIBS_INIT})
  endif()

  target_link_libraries(${source_file_we} fluent-bit-static)

  add_test(${source_file_we} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we})
  if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR
      "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    set_property(TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -g -O3")
  endif()
endforeach()
