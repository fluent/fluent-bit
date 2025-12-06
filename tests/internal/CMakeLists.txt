find_package(Threads REQUIRED)

include_directories(cutest/)

set(UNIT_TESTS_FILES
  pack.c
  pipe.c
  sds.c
  sds_list.c
  hmac.c
  crypto.c
  hash.c
  kv.c
  slist.c
  router.c
  router_config.c
  network.c
  unit_sizes.c
  hashtable.c
  http_client.c
  utils.c
  gzip.c
  zstd.c
  random.c
  config_map.c
  mp.c
  mp_chunk_cobj.c
  input_chunk.c
  input_chunk_routes.c
  flb_time.c
  file.c
  csv.c
  multiline.c
  typecast.c
  base64.c
  bucket_queue.c
  flb_event_loop.c
  ring_buffer.c
  regex.c
  parser_json.c
  parser_ltsv.c
  parser_regex.c
  parser_logfmt.c
  env.c
  log.c
  log_event_decoder.c
  log_event_encoder.c
  processor.c
  processor_conditional.c
  uri.c
  msgpack_append_message.c
  conditionals.c
  endianness.c
  task_map.c
  strptime.c
  storage_inherit.c
  unicode.c
  opentelemetry.c
  storage_dlq.c
)

if(FLB_OUT_AZURE_BLOB)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    azure_blob_path.c
    )
endif()

# TLS helpers
if(FLB_TLS)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    upstream_tls.c
    )
endif()

# Config format
set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    config_format.c
    config_format_fluentbit.c
)

if(FLB_HAVE_LIBYAML)
  set(UNIT_TESTS_FILES
      ${UNIT_TESTS_FILES}
      config_format_yaml.c
      )
endif()

if (NOT WIN32)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    gelf.c
    fstore.c
    reload.c
    )
endif()

if(FLB_PARSER)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    parser.c
    )
endif()

if(FLB_STREAM_PROCESSOR)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    stream_processor.c
    )
endif()

if(FLB_RECORD_ACCESSOR)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    record_accessor.c
    cfl_record_accessor.c
    )
endif()

if(FLB_METRICS)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    metrics.c
    )
endif()

if(FLB_SIGNV4)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    signv4.c
    )
endif()

if(FLB_AVRO_ENCODER)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    avro.c
    )
endif()

if(FLB_AWS)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    aws_util.c
    aws_compress.c
    aws_credentials.c
    aws_credentials_ec2.c
    aws_credentials_sts.c
    aws_credentials_http.c
    aws_credentials_profile.c
    )
  if(FLB_HAVE_AWS_CREDENTIAL_PROCESS)
    set(UNIT_TESTS_FILES
      ${UNIT_TESTS_FILES}
      aws_credentials_process.c
      )
  endif()
endif()

if(FLB_AWS_ERROR_REPORTER)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    error_reporter.c
    )
endif()

if(FLB_LUAJIT)
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    lua.c
    )
endif()

set(UNIT_TESTS_DATA
  data/tls/certificate.pem
  data/tls/private_key.pem
  data/pack/json_single_map_001.json
  data/pack/json_single_map_002.json
  data/parser/json.conf
  data/parser/regex.conf
  data/input_chunk/log/a_thousand_plus_one_bytes.log
  data/input_chunk/log/test_buffer_valid.log
  data/opentelemetry/logs.json
  )

set(FLB_TESTS_DATA_PATH ${CMAKE_CURRENT_SOURCE_DIR}/)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/flb_tests_internal.h.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/flb_tests_internal.h"
  )

# Move data files to the path the test binaries can find them
macro(FLB_TEST_COPY_DATA path)
  configure_file(${path} ${CMAKE_CURRENT_BINARY_DIR}/${path} COPYONLY)
endmacro()

foreach(test_data ${UNIT_TESTS_DATA})
  FLB_TEST_COPY_DATA(${test_data})
endforeach()

# Prepare list of unit tests function
function(prepare_unit_tests TEST_PREFIX SOURCEFILES)
  foreach(source_file ${SOURCEFILES})
    get_filename_component(source_file_we ${source_file} NAME_WE)
    set(source_file_we ${TEST_PREFIX}${source_file_we})
    if(FLB_WITHOUT_${source_file_we})
      message("Skipping test ${source_file_we}")
    else()
      add_executable(
        ${source_file_we}
        ${source_file}
        )
      add_sanitizers(${source_file_we})

      if(FLB_JEMALLOC)
        target_link_libraries(${source_file_we} ${JEMALLOC_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
      else()
        target_link_libraries(${source_file_we} ${CMAKE_THREAD_LIBS_INIT})
      endif()

      if(FLB_AWS)
        target_link_libraries(${source_file_we} flb-aws)
      endif()

      if(FLB_OUT_AZURE_BLOB AND "${source_file_we}" STREQUAL "flb-it-azure_blob_path")
        target_link_libraries(${source_file_we} flb-plugin-out_azure_blob)
      endif()

      if(FLB_STREAM_PROCESSOR)
        target_link_libraries(${source_file_we} flb-sp)
      endif()

      target_link_libraries(${source_file_we} fluent-bit-static cfl-static)

      if(FLB_AVRO_ENCODER)
        target_link_libraries(${source_file_we} avro-static jansson)
      endif()

      add_test(NAME ${source_file_we}
              COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we}
              WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}/build)
      set_tests_properties(${source_file_we} PROPERTIES LABELS "internal")
    endif()
  endforeach()
endfunction(prepare_unit_tests)

prepare_unit_tests(flb-it- "${UNIT_TESTS_FILES}")

if(FLB_TESTS_INTERNAL_FUZZ)
  add_subdirectory(fuzzers)
endif()
