cmake_minimum_required(VERSION 2.8)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC ")
set(PROJ_CJSON cJSON)

project(${PROJ_CJSON} C)
set(SOURCES src/cJSON.c)

add_library(${PROJ_CJSON} STATIC ${HEADERS} ${SOURCES})
