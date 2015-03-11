cmake_minimum_required(VERSION 2.6)
project(FLUENT-BIT C)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

# General Headers
include_directories(include/)

# Lib: mk_config
add_subdirectory(lib/msgpack-0.5.9)
add_subdirectory(lib/libxbee-v3)
add_subdirectory(lib/mk_config)

# Fluent Bit Core
add_subdirectory(src/)
