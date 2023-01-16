# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 2.8...3.16)

project(bwa_wasm)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/preparation.cmake)

#######################################
include(ExternalProject)

################ libz ################
ExternalProject_Add(libz_src
  GIT_REPOSITORY https://github.com/madler/zlib.git
  GIT_TAG        master
  GIT_PROGRESS   ON
  GIT_SHALLOW    ON
  SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/libz
  UPDATE_COMMAND    ""
  PATCH_COMMAND     ""
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   ""
)

################ bwa ################
ExternalProject_Add(bwa
  GIT_REPOSITORY https://github.com/lh3/bwa.git
  GIT_TAG        master
  GIT_PROGRESS   ON
  GIT_SHALLOW    ON
  SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/bwa
  DEPENDS        libz_src
  UPDATE_COMMAND git clean -ffdx && git checkout -- *
                  && ${CMAKE_COMMAND} -E echo "Copying pre-installed CMakeLists.txt"
                  && ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.bwa_wasm.txt CMakeLists.txt
                  && git apply ../bwa.patch
  CONFIGURE_COMMAND  ${CMAKE_COMMAND}
                       -DWASI_SDK_PREFIX=${WASI_SDK_HOME}
                       -DCMAKE_TOOLCHAIN_FILE=${WASI_SDK_HOME}/share/cmake/wasi-sdk.cmake
                       -DCMAKE_SYSROOT=${WASI_SDK_HOME}/share/wasi-sysroot
                       ${CMAKE_CURRENT_SOURCE_DIR}/bwa
  BUILD_COMMAND  make bwa_wasm_opt
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy ./bwa.opt.wasm ${CMAKE_BINARY_DIR}/bwa.wasm
)
