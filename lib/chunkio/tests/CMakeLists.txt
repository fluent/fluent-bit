include_directories(lib/acutest)

set(UNIT_TESTS_FILES
  context.c
  memfs.c
  stream.c
  )
if(CIO_BACKEND_FILESYSTEM)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    fs.c
    metadata_update.c
    )
endif()

# Windows-specific inconsistency tests
if(WIN32 AND CIO_BACKEND_FILESYSTEM)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    fs_windows.c
    )
endif()

set(CIO_TESTS_DATA_PATH ${CMAKE_CURRENT_SOURCE_DIR}/)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cio_tests_internal.h.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/cio_tests_internal.h"
  )

# Prepare list of unit tests
foreach(source_file ${UNIT_TESTS_FILES})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we cio-test-${source_file_we})
  add_executable(
    ${source_file_we}
    ${source_file}
    )
  target_link_libraries(${source_file_we} chunkio-static)

  if (CIO_SANITIZE_ADDRESS)
    add_sanitizers(${source_file_we})
  endif()

  add_test(${source_file_we} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we})
endforeach()

# Perf tests for dev purposes: note these tests are not registered, they need to
# be executed manually
set(UNIT_PERF_TESTS
  fs_perf.c
  fs_fragmentation.c
  )
foreach(source_file ${UNIT_PERF_TESTS})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we cio-${source_file_we})
  add_executable(
    ${source_file_we}
    ${source_file}
    )
  target_link_libraries(${source_file_we} chunkio-static)

  if (CIO_SANITIZE_ADDRESS)
    add_sanitizers(${source_file_we})
  endif()
  #add_test(${source_file_we} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we})
endforeach()
