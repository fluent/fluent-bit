# Reuse native test sources with Node's WASM filesystem and pthread runtime.
# Native listeners, process control and host telemetry are unavailable here.
function(flb_wasm_test kind name source)
  get_filename_component(test_directory "${PROJECT_SOURCE_DIR}/tests/${source}" DIRECTORY)
  set(target "flb-${kind}-${name}")
  add_executable(${target} "${PROJECT_SOURCE_DIR}/tests/${source}")
  target_include_directories(${target} PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/${kind}"
    "${PROJECT_SOURCE_DIR}/tests/internal" "${PROJECT_SOURCE_DIR}/tests/runtime")
  target_compile_definitions(${target} PRIVATE FLB_TEST_INIT_NOP FLB_TEST_FINI_NOP)
  target_link_libraries(${target} fluent-bit-static)
  set_target_properties(${target} PROPERTIES LINK_FLAGS
    "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=8 -sSTACK_SIZE=1048576 -sALLOW_MEMORY_GROWTH=1 --embed-file ${test_directory}/data@${test_directory}/data")
  add_test(NAME ${target} COMMAND ${target} --no-exec ${ARGN})
  set_tests_properties(${target} PROPERTIES TIMEOUT 180 LABELS "${kind};wasm")
endfunction()

if(FLB_TESTS_INTERNAL)
  set(FLB_TESTS_DATA_PATH "${PROJECT_SOURCE_DIR}/tests/internal/")
  configure_file("${PROJECT_SOURCE_DIR}/tests/internal/flb_tests_internal.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/it/flb_tests_internal.h" @ONLY)
  foreach(name sds sds_list kv slist unit_sizes hashtable gzip compression zstd
      typecast base64 bucket_queue regex json parser_json parser_ltsv
      parser_regex parser_logfmt env log_event_decoder log_event_encoder uri
      msgpack_append_message endianness strptime csv)
    flb_wasm_test(it ${name} internal/${name}.c)
  endforeach()
  # The smart_flush case drains a native notification pipe until EAGAIN;
  # browser pipes use a different notification mechanism.
  flb_wasm_test(it ring_buffer internal/ring_buffer.c basic collector_bounded_pass)
  if(FLB_UNICODE_ENCODER)
    flb_wasm_test(it unicode internal/unicode.c)
  endif()
  if(FLB_RIPSER)
    flb_wasm_test(it ripser internal/ripser.c)
  endif()
endif()

if(FLB_TESTS_RUNTIME)
  set(FLB_TESTS_DATA_PATH "${PROJECT_SOURCE_DIR}/tests/runtime")
  configure_file("${PROJECT_SOURCE_DIR}/tests/runtime/flb_tests_runtime.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/rt/flb_tests_runtime.h" @ONLY)
  foreach(name filter_checklist filter_throttle_size filter_sysinfo processor_journald_otel)
    string(TOUPPER "FLB_${name}" plugin_option)
    if(${plugin_option})
      flb_wasm_test(rt ${name} runtime/${name}.c)
    endif()
  endforeach()
endif()
