# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project(linux_perf_sample_wasm)

include(CMakePrintHelpers)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/../cmake)
find_package(WAMRC REQUIRED)

################ wasm  ################
add_executable(fib_wasm fib.c)
set_target_properties(fib_wasm PROPERTIES SUFFIX .wasm)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/fib_wasm.wasm DESTINATION . RENAME fib1.wasm)

add_executable(ackermann_wasm ackermann.c)
set_target_properties(ackermann_wasm PROPERTIES SUFFIX .wasm)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ackermann_wasm.wasm DESTINATION . RENAME ackermann1.wasm)


################ aot ################
add_custom_target(fib_aot
  ALL
  COMMAND ${WAMRC_BIN} --enable-linux-perf -o fib2.aot fib_wasm.wasm
  DEPENDS fib_wasm
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/fib2.aot DESTINATION .)

add_custom_target(ackermann_aot
  ALL
  COMMAND ${WAMRC_BIN} --enable-linux-perf -o ackermann2.aot ackermann_wasm.wasm
  DEPENDS ackermann_wasm
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ackermann2.aot DESTINATION .)
