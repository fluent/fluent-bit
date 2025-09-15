cmake_minimum_required(VERSION 3.20)

# Setup project
project(LwLibPROJECT C)

# -------------------------------------------------
# This CMakeLists.txt is used only if it is a top-level file.
# Purpose of it is to be able to compile project in standalone way only
#
# When library sources are to be included in another project
# user shall use /lwrb/CMakeLists.txt instead
if (NOT PROJECT_IS_TOP_LEVEL)
    #message(FATAL_ERROR "This CMakeLists.txt can only be used as top-level. Use /lwrb/CMakeLists.txt for library include purpose")
endif()

# Set as executable
add_executable(${PROJECT_NAME})

# Add key executable block
target_sources(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/dev/main.c
    )

# Add key include paths
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/dev
    )

# Compilation definition information
target_compile_definitions(${PROJECT_NAME} PUBLIC
    WIN32
    _DEBUG
    CONSOLE
    LWRB_DEV
    )

# Add subdir with lwrb and link to project
add_subdirectory("lwrb" lwrb)
target_link_libraries(${PROJECT_NAME} lwrb)
