cmake_minimum_required(VERSION 3.20)
project(tutf8e C)

# Not supported: -std=c90 (lacks support for inline)
# Supported:     -std=gnu90, -std=c99 or -std=gnu99

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -Wall")

include_directories(include)
add_library(tutf8e STATIC src/tutf8e.c)
set_property(TARGET tutf8e PROPERTY C_STANDARD 99)
set_property(TARGET tutf8e PROPERTY C_EXTENSIONS OFF)

add_executable(tutf8e-test test/test.c)
target_link_libraries(tutf8e-test tutf8e)
set_property(TARGET tutf8e-test PROPERTY C_STANDARD 99)
set_property(TARGET tutf8e-test PROPERTY C_EXTENSIONS ON)
