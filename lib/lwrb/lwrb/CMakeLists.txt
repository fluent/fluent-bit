#cmake_minimum_required(VERSION 3.22)

# Register core library once and link it statically
add_library(lwrb STATIC
    ${CMAKE_CURRENT_LIST_DIR}/src/lwrb/lwrb.c
)

target_include_directories(lwrb PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/src/include
)

set_target_properties(lwrb PROPERTIES POSITION_INDEPENDENT_CODE ON)
