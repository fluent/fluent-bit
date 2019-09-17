cmake_minimum_required(VERSION 2.8)
project(flb-ssl)

set(src
  flb_ssl.c
  flb_ssl_config.c)

add_library(flb-ssl STATIC ${src})

if(FLB_JEMALLOC)
  target_link_libraries(flb-ssl libjemalloc)
endif()
