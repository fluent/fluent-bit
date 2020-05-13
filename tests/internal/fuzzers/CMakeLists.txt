set(UNIT_TESTS_FILES
  flb_json_fuzzer.c
  parse_json_fuzzer.c
  parse_logfmt_fuzzer.c
  parse_ltsv_fuzzer.c
  )

# Prepare list of unit tests
foreach(source_file ${UNIT_TESTS_FILES})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we flb-it-fuzz-${source_file_we})

  add_executable(
    ${source_file_we}
    ${source_file} local_test.c
    )

  if(FLB_JEMALLOC)
    target_link_libraries(${source_file_we} libjemalloc ${CMAKE_THREAD_LIBS_INIT})
  else()
    target_link_libraries(${source_file_we} ${CMAKE_THREAD_LIBS_INIT})
  endif()

  if(FLB_STREAM_PROCESSOR)
    target_link_libraries(${source_file_we} flb-sp)
  endif()

  target_link_libraries(${source_file_we} fluent-bit-static)
endforeach()
