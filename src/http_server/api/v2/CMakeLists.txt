# api/v2
set(src
  metrics.c
  reload.c
  register.c
  )

include_directories(${MONKEY_INCLUDE_DIR})
add_library(api-v2 STATIC ${src})
target_link_libraries(api-v2 monkey-core-static fluent-bit-static)
