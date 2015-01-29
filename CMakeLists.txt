cmake_minimum_required(VERSION 2.6)
project(FLUENT-BIT C)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")
include_directories(include/)
add_subdirectory(lib/mk_config)
add_subdirectory(src/)
