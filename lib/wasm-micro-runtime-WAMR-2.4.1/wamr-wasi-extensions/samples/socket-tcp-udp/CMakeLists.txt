cmake_minimum_required(VERSION 3.14)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED YES)

project(socket-tcp-udp LANGUAGES C)
add_executable(socket-tcp-udp ${CMAKE_CURRENT_SOURCE_DIR}/../../../core/iwasm/libraries/lib-socket/test/tcp_udp.c)
find_package(wamr-wasi-socket REQUIRED)
target_link_libraries(socket-tcp-udp wamr-wasi-socket)
target_link_options(socket-tcp-udp PRIVATE -Wl,--max-memory=262144)
