set(UNIT_TESTS_FILES
  aws_util_fuzzer.c
  aws_credentials_fuzzer.c
  base64_fuzzer.c
  engine_fuzzer.c
  cfl_record_accessor_fuzzer.c
  cmetrics_decode_fuzz.c
  cmetrics_decode_prometheus.c
  config_fuzzer.c
  config_random_fuzzer.c
  ctrace_fuzzer.c
  input_fuzzer.c
  signv4_fuzzer.c
  flb_json_fuzzer.c
  flb_mp_fuzzer.c
  filter_stdout_fuzzer.c
  fstore_fuzzer.c
  parser_fuzzer.c
  parse_json_fuzzer.c
  parse_logfmt_fuzzer.c
  parse_ltsv_fuzzer.c
  msgpack_parse_fuzzer.c
  msgpack_to_gelf_fuzzer.c
  multiline_fuzzer.c
  pack_json_state_fuzzer.c
  http_fuzzer.c
  strp_fuzzer.c
  utils_fuzzer.c
  config_map_fuzzer.c
  record_ac_fuzzer.c
  config_yaml_fuzzer.c
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
    target_link_libraries(${source_file_we} ${JEMALLOC_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  else()
    target_link_libraries(${source_file_we} ${CMAKE_THREAD_LIBS_INIT})
  endif()

  if(FLB_STREAM_PROCESSOR)
    target_link_libraries(${source_file_we} flb-sp)
  endif()

  target_link_libraries(${source_file_we} fluent-bit-static)

  if (FLB_TESTS_OSSFUZZ)
   add_executable(${source_file_we}_OSSFUZZ ${source_file})
   target_link_libraries(${source_file_we}_OSSFUZZ ${CMAKE_THREAD_LIBS_INIT})
   set_target_properties(${source_file_we}_OSSFUZZ PROPERTIES LINK_FLAGS $ENV{LIB_FUZZING_ENGINE})
   target_link_libraries(${source_file_we}_OSSFUZZ fluent-bit-static)
  endif()
endforeach()
