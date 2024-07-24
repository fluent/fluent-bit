find_package(Threads REQUIRED)

include_directories(acutest/)

define_property(GLOBAL PROPERTY CHECK_PROGRAMS
  BRIEF_DOCS "Runtime Test Programs"
  FULL_DOCS "Runtime Test Programs")
set_property(GLOBAL PROPERTY CHECK_PROGRAMS "")

# Macro to set definitions
macro(FLB_RT_TEST BUILT src)
  if (${BUILT})
    list(APPEND CHECK_PROGRAMS
      ${src}
      )
  endif()
endmacro()

# Macro to set definitions
macro(FLB_RT_CORE_TEST BUILT src)
    list(APPEND CHECK_PROGRAMS
      ${src}
      )
endmacro()

# Core
FLB_RT_CORE_TEST(FLB_COROUTINE_TIMEOUT    "core-timeout.c")

FLB_RT_TEST(FLB_CHUNK_TRACE "core_chunk_trace.c")

# Input Plugins
FLB_RT_TEST(FLB_IN_EVENT_TEST   "in_event_test.c")

if(FLB_OUT_LIB)
  # These plugins works only on Linux
  if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    FLB_RT_TEST(FLB_IN_CPU            "in_cpu.c")
    FLB_RT_TEST(FLB_IN_DISK           "in_disk.c")
    FLB_RT_TEST(FLB_IN_MEM            "in_mem.c")
    FLB_RT_TEST(FLB_IN_PROC           "in_proc.c")
    FLB_RT_TEST(FLB_IN_NETIF          "in_netif.c")
    FLB_RT_TEST(FLB_IN_PODMAN_METRICS "in_podman_metrics.c")
    FLB_RT_TEST(FLB_IN_DOCKER        "in_docker.c")
  endif()
  FLB_RT_TEST(FLB_IN_HEAD          "in_head.c")
  FLB_RT_TEST(FLB_IN_DUMMY         "in_dummy.c")
  FLB_RT_TEST(FLB_IN_HTTP          "in_http.c")
  FLB_RT_TEST(FLB_IN_ELASTICSEARCH "in_elasticsearch.c")
  FLB_RT_TEST(FLB_IN_MQTT          "in_mqtt.c")
  FLB_RT_TEST(FLB_IN_OPENTELEMETRY "in_opentelemetry.c")
  FLB_RT_TEST(FLB_IN_RANDOM        "in_random.c")
  FLB_RT_TEST(FLB_IN_STATSD        "in_statsd.c")
  FLB_RT_TEST(FLB_IN_SPLUNK        "in_splunk.c")
  FLB_RT_TEST(FLB_IN_SYSLOG        "in_syslog.c")
  FLB_RT_TEST(FLB_IN_TAIL          "in_tail.c")
  FLB_RT_TEST(FLB_IN_UDP           "in_udp.c")
  FLB_RT_TEST(FLB_IN_TCP          "in_tcp.c")
  FLB_RT_TEST(FLB_IN_FORWARD       "in_forward.c")
  FLB_RT_TEST(FLB_IN_FLUENTBIT_METRICS "in_fluentbit_metrics.c")
  FLB_RT_TEST(FLB_IN_KUBERNETES_EVENTS "in_kubernetes_events.c")
endif()

# Filter Plugins
if(FLB_IN_LIB AND FLB_OUT_LIB)
  FLB_RT_TEST(FLB_FILTER_AWS             "filter_aws.c")
  FLB_RT_TEST(FLB_FILTER_CHECKLIST       "filter_checklist.c")
  FLB_RT_TEST(FLB_FILTER_EXPECT          "filter_expect.c")
  FLB_RT_TEST(FLB_FILTER_STDOUT          "filter_stdout.c")
  FLB_RT_TEST(FLB_FILTER_GREP            "filter_grep.c")
  FLB_RT_TEST(FLB_FILTER_THROTTLE        "filter_throttle.c")
  FLB_RT_TEST(FLB_FILTER_THROTTLE_SIZE   "filter_throttle_size.c")
  FLB_RT_TEST(FLB_FILTER_NEST       "filter_nest.c")
  FLB_RT_TEST(FLB_FILTER_REWRITE_TAG  "filter_rewrite_tag.c")
  FLB_RT_TEST(FLB_FILTER_KUBERNETES "filter_kubernetes.c")
  FLB_RT_TEST(FLB_FILTER_PARSER     "filter_parser.c")
  FLB_RT_TEST(FLB_FILTER_MODIFY     "filter_modify.c")
  FLB_RT_TEST(FLB_FILTER_LUA        "filter_lua.c")
  FLB_RT_TEST(FLB_FILTER_TYPE_CONVERTER "filter_type_converter.c")
  FLB_RT_TEST(FLB_FILTER_RECORD_MODIFIER "filter_record_modifier.c")
  FLB_RT_TEST(FLB_FILTER_MULTILINE       "filter_multiline.c")
  FLB_RT_TEST(FLB_FILTER_SYSINFO         "filter_sysinfo.c")
  if (FLB_FILTER_WASM)
    FLB_RT_TEST(FLB_FILTER_WASM            "filter_wasm.c")
  endif ()
  FLB_RT_TEST(FLB_FILTER_ECS       "filter_ecs.c")
  FLB_RT_TEST(FLB_FILTER_LOG_TO_METRICS       "filter_log_to_metrics.c")
endif()


# Output Plugins
if(FLB_IN_LIB)
  FLB_RT_TEST(FLB_OUT_LIB              "core_engine.c")
  FLB_RT_TEST(FLB_OUT_LIB              "core_log.c")
  FLB_RT_TEST(FLB_OUT_LIB              "config_map_opts.c")
  FLB_RT_TEST(FLB_OUT_COUNTER          "out_counter.c")
  FLB_RT_TEST(FLB_OUT_DATADOG          "out_datadog.c")
  FLB_RT_TEST(FLB_OUT_SKYWALKING       "out_skywalking.c")
  FLB_RT_TEST(FLB_OUT_ES               "out_elasticsearch.c")
  FLB_RT_TEST(FLB_OUT_OPENSEARCH       "out_opensearch.c")
  FLB_RT_TEST(FLB_OUT_EXIT             "out_exit.c")
  FLB_RT_TEST(FLB_OUT_FLOWCOUNTER      "out_flowcounter.c")
  FLB_RT_TEST(FLB_OUT_FORWARD          "out_forward.c")
  FLB_RT_TEST(FLB_OUT_HTTP             "out_http.c")
  FLB_RT_TEST(FLB_OUT_LIB              "out_lib.c")
  FLB_RT_TEST(FLB_OUT_LOKI             "out_loki.c")
  FLB_RT_TEST(FLB_OUT_NULL             "out_null.c")
  FLB_RT_TEST(FLB_OUT_PLOT             "out_plot.c")
  FLB_RT_TEST(FLB_OUT_RETRY            "out_retry.c")
  FLB_RT_TEST(FLB_OUT_SPLUNK           "out_splunk.c")
  FLB_RT_TEST(FLB_OUT_STDOUT           "out_stdout.c")
  FLB_RT_TEST(FLB_OUT_SYSLOG           "out_syslog.c")
  FLB_RT_TEST(FLB_OUT_TCP              "out_tcp.c")

  if (FLB_RECORD_ACCESSOR)
    FLB_RT_TEST(FLB_OUT_STACKDRIVER      "out_stackdriver.c")
  endif()

  FLB_RT_TEST(FLB_OUT_CLOUDWATCH_LOGS   "out_cloudwatch.c")
  FLB_RT_TEST(FLB_OUT_KINESIS_FIREHOSE  "out_firehose.c")
  FLB_RT_TEST(FLB_OUT_KINESIS_STREAMS   "out_kinesis.c")
    # These plugins work only on Linux
  if(NOT FLB_SYSTEM_WINDOWS)
    FLB_RT_TEST(FLB_OUT_FILE              "out_file.c")
  endif()
  FLB_RT_TEST(FLB_OUT_S3                "out_s3.c")
  FLB_RT_TEST(FLB_OUT_TD                "out_td.c")

endif()

if (FLB_CUSTOM_CALYPTIA)
  FLB_RT_TEST(FLB_CUSTOM_CALYPTIA "custom_calyptia_test.c")
endif()

if (FLB_PROCESSOR_METRICS_SELECTOR)
  FLB_RT_TEST(FLB_PROCESSOR_METRICS_SELECTOR "processor_metrics_selector.c")
endif()

if (FLB_PROCESSOR_CONTENT_MODIFIER)
  FLB_RT_TEST(FLB_PROCESSOR_CONTENT_MODIFIER "processor_content_modifier.c")
endif()

# HTTP Client Debug (requires -DFLB_HTTP_CLIENT_DEBUG=On)
if(FLB_HTTP_CLIENT_DEBUG)
  FLB_RT_TEST(FLB_OUT_TD           "http_callbacks.c")
endif()

set(SYSTEMD_LIB, "")
if(FLB_HAVE_SYSTEMD)
    set(SYSTEMD_LIB, "systemd")
endif()

set(FLB_TESTS_DATA_PATH ${CMAKE_CURRENT_SOURCE_DIR})
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/flb_tests_runtime.h.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/flb_tests_runtime.h"
  )

foreach(source_file ${CHECK_PROGRAMS})
  get_filename_component(o_source_file_we ${source_file} NAME_WE)
  set(source_file_we flb-rt-${o_source_file_we})
  if(FLB_WITHOUT_${source_file_we})
    message("Skipping test ${source_file_we}")
  else()
    add_executable(
      ${source_file_we}
      ${source_file}
      )
    add_sanitizers(${source_file_we})
    target_link_libraries(${source_file_we}
      fluent-bit-static
      ${CMAKE_THREAD_LIBS_INIT}
      ${SYSTEMD_LIB}
      )
      if(FLB_AVRO_ENCODER)
        target_link_libraries(${source_file_we} avro-static jansson)
      endif()
    add_test(NAME ${source_file_we}
            COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${source_file_we}
            WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}/build)
    set_tests_properties(${source_file_we} PROPERTIES LABELS "runtime")
    set_property(TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-D${o_source_file_we}")
  endif()
endforeach()
