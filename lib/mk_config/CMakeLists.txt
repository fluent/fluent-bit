cmake_minimum_required(VERSION 2.8)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

set(src
  mk_string.c
  mk_config.c
)

add_library(mk_config STATIC ${src})
