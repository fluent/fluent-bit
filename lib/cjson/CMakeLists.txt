cmake_minimum_required(VERSION 2.8)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -D_POSIX_C_SOURCE=200112L")
add_definitions(-D__STRICT_ANSI__)
set(PROJ_CJSON cJSON)

project(${PROJ_CJSON} C)
set(SOURCES src/cJSON.c)

add_library(${PROJ_CJSON} STATIC ${HEADERS} ${SOURCES})

if(NOT CMAKE_SYSTEM_NAME MATCHES "Windows")
  target_link_libraries(${PROJ_CJSON} m)
endif()
