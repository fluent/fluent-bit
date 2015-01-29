cmake_minimum_required(VERSION 2.8)

set(src
  mk_string.c
  mk_config.c
)

add_library(mk_config STATIC ${src})
