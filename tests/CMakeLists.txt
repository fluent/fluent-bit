find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

include_directories (
  ${GTEST_INCLUDE_DIRS}
  )

list(APPEND check_PROGRAMS
  flb_test_td.cpp
  flb_test_stdout.cpp
  flb_test_fluentd.cpp
  )

foreach(source_file ${check_PROGRAMS})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  add_executable(
    ${source_file_we}
    ${source_file}
    )
  target_link_libraries(${source_file_we}
    fluent-bit-static
    ${GTEST_BOTH_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    )
  add_test(${source_file_we} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we})
  if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR
      "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set_property(TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -g -O3")
  endif()
endforeach()
