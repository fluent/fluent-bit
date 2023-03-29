# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.0)

project(bench-meshoptimizer)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/preparation.cmake)

################  MESHOPTIMIZER  ################
include(ExternalProject)

ExternalProject_Add(codecbench
  PREFIX codecbench
  GIT_REPOSITORY https://github.com/zeux/meshoptimizer.git
  GIT_TAG        master
  GIT_SHALLOW    ON
  GIT_PROGRESS   ON
  SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/meshoptimizer
  UPDATE_COMMAND git clean -fd && git checkout -- *
                   && ${CMAKE_COMMAND} -E echo "Applying patch"
                   && git apply ${CMAKE_CURRENT_SOURCE_DIR}/codecbench.patch
  CONFIGURE_COMMAND ${CMAKE_COMMAND}
                      -DWASI_SDK_PREFIX=${WASI_SDK_HOME}
                      -DCMAKE_TOOLCHAIN_FILE=${WASI_SDK_HOME}/share/cmake/wasi-sdk.cmake
                      -DCMAKE_SYSROOT=${WASI_SDK_HOME}/share/wasi-sysroot
                      ${CMAKE_CURRENT_SOURCE_DIR}/meshoptimizer
  BUILD_COMMAND  make codecbench
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy ./codecbench.wasm ${CMAKE_BINARY_DIR}/codecbench.wasm
)
