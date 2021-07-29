set(src
  cmt_gauge.c
  cmt_counter.c
  cmt_untyped.c
  cmt_metric.c
  cmt_map.c
  cmt_log.c
  cmt_opts.c
  cmt_time.c
  cmt_label.c
  cmetrics.c
  cmt_encode_prometheus.c
  cmt_encode_prometheus_remote_write.c
  cmt_encode_text.c
  cmt_encode_influx.c
  cmt_encode_msgpack.c
  cmt_decode_msgpack.c
  cmt_mpack_utils.c
  external/protobuf-c.c
  external/remote.pb-c.c
  external/types.pb-c.c
  )

if (${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cmt_atomic_clang.c)
elseif (${CMAKE_C_COMPILER_ID} MATCHES "AppleClang")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cmt_atomic_clang.c)
elseif (${CMAKE_C_COMPILER_ID} STREQUAL "GNU")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cmt_atomic_gcc.c)
elseif (${CMAKE_C_COMPILER_ID} STREQUAL "MSVC")
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cmt_atomic_msvc.c)
else()
  set(PLATFORM_SPECIFIC_ATOMIC_MODULE cmt_atomic_generic.c)
endif()

set(src
  ${src}
  ${PLATFORM_SPECIFIC_ATOMIC_MODULE}
  )

# Static Library
add_library(cmetrics-static STATIC ${src})
target_link_libraries(cmetrics-static xxhash mpack-static)

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
