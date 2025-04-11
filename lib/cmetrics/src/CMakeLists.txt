if (CMT_BUILD_PROMETHEUS_DECODER)
    flex_target(cmt_decode_prometheus_lexer cmt_decode_prometheus.l
        "${FLEX_BISON_GENERATED_DIR}/cmt_decode_prometheus_lexer.c"
        DEFINES_FILE "${FLEX_BISON_GENERATED_DIR}/cmt_decode_prometheus_lexer.h"
        )
    bison_target(cmt_decode_prometheus_parser cmt_decode_prometheus.y
        "${FLEX_BISON_GENERATED_DIR}/cmt_decode_prometheus_parser.c")
    add_flex_bison_dependency(cmt_decode_prometheus_lexer cmt_decode_prometheus_parser)
endif()

set(src
  cmt_gauge.c
  cmt_counter.c
  cmt_untyped.c
  cmt_summary.c
  cmt_histogram.c
  cmt_metric.c
  cmt_metric_histogram.c
  cmt_map.c
  cmt_log.c
  cmt_opts.c
  cmt_time.c
  cmt_label.c
  cmt_cat.c
  cmt_filter.c
  cmetrics.c
  cmt_encode_opentelemetry.c
  cmt_decode_opentelemetry.c
  cmt_encode_prometheus.c
  cmt_encode_prometheus_remote_write.c
  cmt_decode_prometheus_remote_write.c
  cmt_encode_splunk_hec.c
  cmt_encode_cloudwatch_emf.c
  cmt_encode_text.c
  cmt_encode_influx.c
  cmt_encode_msgpack.c
  cmt_decode_msgpack.c
  cmt_decode_statsd.c
  cmt_mpack_utils.c

  # Prometheus related protobuf files
  external/remote.pb-c.c
  external/types.pb-c.c
  )


if (MSVC)
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cmt_atomic_msvc.c)
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cmt_atomic_clang.c)
elseif("${CMAKE_C_COMPILER_ID}" MATCHES "AppleClang")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cmt_atomic_clang.c)
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cmt_atomic_gcc.c)
else()
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cmt_atomic_generic.c)
endif()

message(STATUS "Compiler: ${CMAKE_C_COMPILER_ID}, Platform: ${CMAKE_SYSTEM_NAME}")

set(src
  ${src}
  ${PLATFORM_SPECIFIC_ATOMIC_MODULE}
  )

if (CMT_BUILD_PROMETHEUS_DECODER)
    set(src ${src}
        ${FLEX_cmt_decode_prometheus_lexer_OUTPUTS}
        ${BISON_cmt_decode_prometheus_parser_OUTPUTS}
        )
endif()

# Static Library
add_library(cmetrics-static STATIC ${src})
target_link_libraries(cmetrics-static mpack-static cfl-static fluent-otel-proto)

# Install Library
if(MSVC)
  # Rename the output for Windows environment to avoid naming issues
  set_target_properties(cmetrics-static PROPERTIES OUTPUT_NAME libcmetrics)
else()
  set_target_properties(cmetrics-static PROPERTIES OUTPUT_NAME cmetrics)
endif(MSVC)

install(TARGETS cmetrics-static
  RUNTIME DESTINATION ${CMT_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMT_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMT_INSTALL_LIBDIR}
  COMPONENT library)
