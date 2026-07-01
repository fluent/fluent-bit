# if(MK_LIB_TEST)
#     add_executable(lib_test lib_test.c)
#     add_dependencies(lib_test monkey-core-static)
#     target_include_directories(lib_test PUBLIC BEFORE lib/acutest)
#     target_link_libraries(lib_test monkey-core-static)
#     add_test(NAME lib_test
#              COMMAND lib_test
#              WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}/build)
# endif()
set(UNIT_TESTS_FILES
  lib_server.c
  event_timeout.c
  )

# Prepare list of unit tests
foreach(source_file ${UNIT_TESTS_FILES})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we mk-test-${source_file_we})

  add_executable(
    ${source_file_we}
    ${source_file}
    )

  target_link_libraries(${source_file_we} monkey-core-static)

  add_test(NAME ${source_file_we}
    COMMAND ${CMAKE_BINARY_DIR}/tests/${source_file_we}
    WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}/tests)
endforeach()
