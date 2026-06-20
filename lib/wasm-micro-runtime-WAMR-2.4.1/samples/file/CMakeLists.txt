# Copyright (C) 2022 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)
project(file)

################ wasm application ###############
add_subdirectory(src)

# Use ExternalProject to avoid incorporating WAMR library compilation flags into the
# compilation of the wasm application, which could lead to compatibility
# issues due to different targets.
# Like: clang: error: unsupported option '-arch' for target 'wasm32-wasi'
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/../cmake)
find_package(WASISDK REQUIRED)

include(ExternalProject)
ExternalProject_Add(wasm-app
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/wasm-app"
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -S ${CMAKE_CURRENT_SOURCE_DIR}/wasm-app -B build
                      -DWASI_SDK_PREFIX=${WASISDK_HOME}
                      -DCMAKE_TOOLCHAIN_FILE=${WASISDK_TOOLCHAIN}
  BUILD_COMMAND     ${CMAKE_COMMAND} --build build
  INSTALL_COMMAND   ${CMAKE_COMMAND} --install build --prefix ${CMAKE_CURRENT_BINARY_DIR}
)
