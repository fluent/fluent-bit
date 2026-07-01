cmake_minimum_required(VERSION 3.14)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED YES)
set(CMAKE_C_EXTENSIONS NO)

project(socket-nslookup LANGUAGES C)
add_executable(socket-nslookup ${CMAKE_CURRENT_SOURCE_DIR}/../../../core/iwasm/libraries/lib-socket/test/nslookup.c)
find_package(wamr-wasi-socket REQUIRED)
target_link_libraries(socket-nslookup wamr-wasi-socket)
target_link_options(socket-nslookup PRIVATE -Wl,--max-memory=262144)
