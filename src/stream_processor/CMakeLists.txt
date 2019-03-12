cmake_minimum_required(VERSION 2.8)
project(stream-processor)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

add_subdirectory(parser)

set(src
  flb_sp.c
  flb_sp_func_time.c
  flb_sp_func_record.c
  flb_sp_stream.c
  flb_sp_window.c
  )

add_library(flb-sp STATIC ${src})
target_link_libraries(flb-sp flb-sp-parser)
