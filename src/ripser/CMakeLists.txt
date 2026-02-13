include_directories (../../${FLB_PATH_LIB_RIPSER})

message(STATUS "include: ${FLB_PATH_LIB_RIPSER}")

set(src
  flb_ripser_wrapper.cpp)

add_library(flb-ripser-wrapper-static STATIC ${src})
target_link_libraries(flb-ripser-wrapper-static ripser-static)
if(FLB_JEMALLOC)
  target_link_libraries(flb-ripser-wrapper-static ${JEMALLOC_LIBRARIES})
endif()
