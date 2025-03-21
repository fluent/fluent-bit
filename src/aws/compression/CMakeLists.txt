add_library(flb-aws-compress INTERFACE)

if(FLB_ARROW)
  add_subdirectory(arrow EXCLUDE_FROM_ALL)
  target_link_libraries(flb-aws-compress INTERFACE flb-aws-arrow)
endif()
