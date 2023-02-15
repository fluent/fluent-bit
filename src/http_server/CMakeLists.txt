if(NOT FLB_METRICS)
  message(FATAL_ERROR "FLB_HTTP_SERVER requires FLB_METRICS=On.")
endif()

# Core Source
set(src
  flb_hs.c
  flb_hs_endpoints.c
  flb_hs_utils.c
  )

# api/v1
add_subdirectory(api/v1)

# api/v2
add_subdirectory(api/v2)

include_directories(${MONKEY_INCLUDE_DIR})
add_library(flb-http-server STATIC ${src})
target_link_libraries(flb-http-server monkey-core-static api-v1 api-v2)
