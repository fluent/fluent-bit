cmake_minimum_required(VERSION 2.8)

set(src
  jsmn.c
)

add_library(jsmn STATIC ${src})
