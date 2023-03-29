include_directories(lib/acutest)

set(UNIT_TESTS_FILES
  kv.c
  sds.c
  hash.c
  list.c
  variant.c
  )

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cfl_tests_internal.h.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/cfl_tests_internal.h"
  )

# Prepare list of unit tests
foreach(source_file ${UNIT_TESTS_FILES})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we cfl-test-${source_file_we})
  add_executable(
    ${source_file_we}
    ${source_file}
    )
  target_link_libraries(${source_file_we} cfl-static)

  if (CFL_SANITIZE_ADDRESS)
    add_sanitizers(${source_file_we})
  endif()

  add_test(${source_file_we} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we})
endforeach()
