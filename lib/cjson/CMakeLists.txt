cmake_minimum_required(VERSION 2.8)

set(PROJ_CJSON cJSON)

project(${PROJ_CJSON} C)

file(GLOB HEADERS cJSON.h)
set(SOURCES cJSON.c)

add_library(${PROJ_CJSON} STATIC ${HEADERS} ${SOURCES})
