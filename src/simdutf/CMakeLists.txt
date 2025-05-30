include_directories (../../${FLB_PATH_LIB_SIMDUTF}/src/simdutf)

message(STATUS "include: ${FLB_PATH_LIB_SIMDUTF}/src/simdutf")

set(src
  flb_simdutf_connector.cpp)

add_library(flb-simdutf-connector-static STATIC ${src})
target_link_libraries(flb-simdutf-connector-static simdutf-static)
if(FLB_JEMALLOC)
  target_link_libraries(flb-simdutf-connector-static ${JEMALLOC_LIBRARIES})
endif()
