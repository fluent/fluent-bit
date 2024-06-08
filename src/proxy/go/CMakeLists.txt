set(src
  go.c)

add_library(flb-plugin-proxy-go STATIC ${src})
if(FLB_JEMALLOC)
  target_link_libraries(flb-plugin-proxy-go ${JEMALLOC_LIBRARIES})
endif()
if(FLB_REGEX)
  target_link_libraries(flb-plugin-proxy-go onigmo-static)
endif()
