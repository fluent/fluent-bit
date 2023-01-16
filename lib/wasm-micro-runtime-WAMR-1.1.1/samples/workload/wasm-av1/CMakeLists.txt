# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 2.8...3.16)

project(av1_wasm)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/preparation.cmake)

#######################################
include(ExternalProject)

################ av1 ################
ExternalProject_Add(av1
  PREFIX av1
  GIT_REPOSITORY https://github.com/GoogleChromeLabs/wasm-av1.git
  GIT_TAG        master
  GIT_PROGRESS   ON
  GIT_SHALLOW    ON
  SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/av1
  UPDATE_COMMAND git clean -fd && git checkout -- *
                  && ${CMAKE_COMMAND} -E echo "Copying pre-installed CMakeLists.txt"
                  && ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.avx_wasm.txt CMakeLists.txt
                  && git apply ../av1-clang.patch
  CONFIGURE_COMMAND  ${CMAKE_COMMAND}
                      -DWASI_SDK_PREFIX=${WASI_SDK_HOME}
                      -DCMAKE_TOOLCHAIN_FILE=${WASI_SDK_HOME}/share/cmake/wasi-sdk.cmake
                      -DCMAKE_SYSROOT=${WASI_SDK_HOME}/share/wasi-sysroot
                      ${CMAKE_CURRENT_SOURCE_DIR}/av1
  BUILD_COMMAND     make testavx_opt
  INSTALL_COMMAND   ${CMAKE_COMMAND} -E copy testavx.opt.wasm ${CMAKE_CURRENT_BINARY_DIR}/testavx.wasm
)
