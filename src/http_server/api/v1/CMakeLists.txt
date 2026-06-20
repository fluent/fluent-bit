# api/v1
set(src
  uptime.c
  metrics.c
  storage.c
  plugins.c
  register.c
  health.c
  )

if(FLB_CHUNK_TRACE)
  set(src
    ${src}
    trace.c
  )
endif()

include_directories(${MONKEY_INCLUDE_DIR})
add_library(api-v1 STATIC ${src})
target_link_libraries(api-v1 monkey-core-static fluent-bit-static)
