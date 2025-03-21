project(stream-processor C)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(parser)

set(src
  flb_sp.c
  flb_sp_key.c
  flb_sp_func_time.c
  flb_sp_func_record.c
  flb_sp_stream.c
  flb_sp_snapshot.c
  flb_sp_window.c
  flb_sp_groupby.c
  flb_sp_aggregate_func.c
  )

add_library(flb-sp STATIC ${src})
target_link_libraries(flb-sp rbtree)
target_link_libraries(flb-sp flb-sp-parser)
