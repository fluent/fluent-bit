set(UNIT_TESTS_FILES
  basic.c
  gauge.c
  counter.c
  untyped.c
  atomic_operations.c
  encoding.c
  cat.c
  issues.c
  )

# Prepare list of unit tests
foreach(source_file ${UNIT_TESTS_FILES})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we cmt-test-${source_file_we})

  add_executable(
    ${source_file_we}
    ${source_file}
    )

  target_link_libraries(${source_file_we} cmetrics-static)

if(NOT CMT_SYSTEM_WINDOWS)
  target_link_libraries(${source_file_we} pthread)
endif()

  add_test(NAME ${source_file_we}
    COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we}
    WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}/tests)
  set_tests_properties(${source_file_we} PROPERTIES LABELS "internal")
endforeach()
