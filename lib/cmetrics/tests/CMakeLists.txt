set(UNIT_TESTS_FILES
  basic.c
  gauge.c
  counter.c
  summary.c
  histogram.c
  untyped.c
  atomic_operations.c
  encoding.c
  decoding.c
  cat.c
  issues.c
  null_label.c
  filter.c
  )

if (CMT_BUILD_PROMETHEUS_TEXT_DECODER)
    set(UNIT_TESTS_FILES
        ${UNIT_TESTS_FILES}
        prometheus_lexer.c
        prometheus_parser.c)
endif()

set(CMT_TESTS_DATA_PATH "${CMAKE_CURRENT_SOURCE_DIR}/data")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmt_tests_config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/cmt_tests_config.h"
  )

# Prepare list of unit tests
foreach(source_file ${UNIT_TESTS_FILES})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we cmt-test-${source_file_we})

  add_executable(
    ${source_file_we}
    ${source_file}
    util.c
    encode_output.c
    )

  target_link_libraries(${source_file_we} cmetrics-static cfl-static fluent-otel-proto)

if(NOT CMT_SYSTEM_WINDOWS)
  target_link_libraries(${source_file_we} pthread)
endif()

  add_test(NAME ${source_file_we}
    COMMAND ${CMAKE_BINARY_DIR}/tests/${source_file_we}
    WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}/tests)
  set_tests_properties(${source_file_we} PROPERTIES LABELS "internal")
endforeach()
