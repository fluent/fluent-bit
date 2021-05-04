set(src
  cmt_gauge.c
  cmt_counter.c
  cmt_metric.c
  cmt_map.c
  cmt_log.c
  cmt_opts.c
  cmt_time.c
  cmetrics.c
  cmt_encode_prometheus.c
  cmt_encode_msgpack.c
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
