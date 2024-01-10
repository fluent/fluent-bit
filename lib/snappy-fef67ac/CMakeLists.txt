cmake_minimum_required(VERSION 2.8)
project(snappy-c C)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Include helpers
include(CheckCSourceCompiles)
include(GNUInstallDirs)

set(src
    snappy.c
    )

add_library(snappy-c STATIC ${src})
