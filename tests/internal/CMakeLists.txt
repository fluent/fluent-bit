find_package(Threads REQUIRED)

include_directories(cutest/)

set(UNIT_TESTS_FILES
  pack.c
  pipe.c
  sds.c
  sha512.c
  slist.c
  router.c
  network.c
  unit_sizes.c
  hashtable.c
  http_client.c
  utils.c
  gzip.c
  gelf.c
  config_map.c
  )

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

set(UNIT_TESTS_DATA
  data/pack/json_single_map_001.json
  data/pack/json_single_map_002.json
  data/parser/json.conf
  data/parser/regex.conf
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

# Prepare list of unit tests
foreach(source_file ${UNIT_TESTS_FILES})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we flb-it-${source_file_we})
  if(FLB_WITHOUT_${source_file_we})
    message("Skipping test ${source_file_we}")
  else()
    add_executable(
      ${source_file_we}
      ${source_file}
      )
    add_sanitizers(${source_file_we})

    if(FLB_JEMALLOC)
      target_link_libraries(${source_file_we} libjemalloc ${CMAKE_THREAD_LIBS_INIT})
    else()
      target_link_libraries(${source_file_we} ${CMAKE_THREAD_LIBS_INIT})
    endif()

    if(FLB_STREAM_PROCESSOR)
      target_link_libraries(${source_file_we} flb-sp)
    endif()

    target_link_libraries(${source_file_we} fluent-bit-static)

    add_test(NAME ${source_file_we}
            COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we}
            WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}/build)
    set_tests_properties(${source_file_we} PROPERTIES LABELS "internal")
  endif()
endforeach()

add_subdirectory(fuzzers)
