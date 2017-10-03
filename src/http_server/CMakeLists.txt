# Core Source
set(src
  flb_hs.c
  )

include_directories(${MONKEY_INCLUDE_DIR})
add_library(flb-http-server STATIC ${src})
target_link_libraries(flb-http-server monkey-core-static)
