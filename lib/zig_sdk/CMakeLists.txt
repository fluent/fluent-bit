cmake_minimum_required(VERSION 3.15)
project(zig_sdk)

get_property(include_dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)

execute_process(
  COMMAND ${CMAKE_COMMAND} -E env
          "FLB_ZIG_BUILD_INCLUDE_DIRECTORIES=${include_dirs}"
          "FLB_ZIG_BUILD_BINARY_DIRECTORY=${PROJECT_BINARY_DIR}"
          zig build --build-file "${PROJECT_SOURCE_DIR}/build.zig" --prefix "${PROJECT_BINARY_DIR}"
)

#message(FATAL_ERROR "Hack hack hack")
