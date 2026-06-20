set(UNIT_TESTS_FILES
  profile.c
  msgpack_transcoder.c
  opentelemetry_transcoder.c
  text_encoder.c
  )

set(CPROF_TESTS_DATA_PATH "${CMAKE_CURRENT_SOURCE_DIR}/data")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cprof_tests_config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/cprof_tests_config.h"
  )

# Prepare list of unit tests
foreach(source_file ${UNIT_TESTS_FILES})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we cprof-test-${source_file_we})

  include_directories(${CMAKE_PROJECT_BINARY_DIR})

  add_executable(
    ${source_file_we}
    ${source_file}
    )

  target_link_libraries(${source_file_we} cprofiles-static mpack-static cfl-static fluent-otel-proto)

  add_test(NAME ${source_file_we}
     COMMAND ${CMAKE_BINARY_DIR}/tests/${source_file_we}
     WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}/tests)
  set_tests_properties(${source_file_we} PROPERTIES LABELS "internal")
endforeach()
