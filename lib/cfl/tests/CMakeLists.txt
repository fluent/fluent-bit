include_directories(lib/acutest)

set(UNIT_TESTS_FILES
  atomic_operations.c
  checksum.c
  headers.c
  kv.c
  kvlist.c
  array.c
  sds.c
  hash.c
  list.c
  variant.c
  object.c
  version.c
  utils.c
  )

if(NOT CFL_SYSTEM_WINDOWS)
  find_package(Threads REQUIRED)
endif()

set(PUBLIC_HEADERS
  cfl.h
  cfl_array.h
  cfl_atomic.h
  cfl_checksum.h
  cfl_compat.h
  cfl_container.h
  cfl_found.h
  cfl_hash.h
  cfl_info.h
  cfl_kv.h
  cfl_kvlist.h
  cfl_list.h
  cfl_log.h
  cfl_object.h
  cfl_sds.h
  cfl_time.h
  cfl_utils.h
  cfl_variant.h
  cfl_version.h
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

  if(source_file STREQUAL "atomic_operations.c" AND NOT CFL_SYSTEM_WINDOWS)
    target_link_libraries(${source_file_we} Threads::Threads)
  endif()

  if (CFL_SANITIZE_ADDRESS)
    add_sanitizers(${source_file_we})
  endif()

  add_test(${source_file_we} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we})
endforeach()

foreach(public_header ${PUBLIC_HEADERS})
  string(REPLACE "." "_" public_header_target ${public_header})
  set(public_header_source "${CMAKE_CURRENT_BINARY_DIR}/header_${public_header_target}.c")
  file(WRITE "${public_header_source}" "#include <cfl/${public_header}>\nint main(void) { return 0; }\n")

  add_executable(
    cfl-test-header-${public_header_target}
    ${public_header_source}
    )

  target_link_libraries(cfl-test-header-${public_header_target} cfl-static)

  if (CFL_SANITIZE_ADDRESS)
    add_sanitizers(cfl-test-header-${public_header_target})
  endif()

  add_test(cfl-test-header-${public_header_target}
           ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cfl-test-header-${public_header_target})
endforeach()
