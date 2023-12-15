# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project(av1_wasm)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../cmake)

################ dependencies ################
find_package(Python3 REQUIRED)
find_package(WASISDK 16.0 REQUIRED)
execute_process(
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/../../../test-tools/pick-up-emscripten-headers/collect_files.py --install ../include --loglevel=ERROR
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
)

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
                      -DWASI_SDK_PREFIX=${WASISDK_HOME}
                      -DCMAKE_TOOLCHAIN_FILE=${WASISDK_TOOLCHAIN}
                      -DCMAKE_SYSROOT=${WASISDK_SYSROOT}
                       -DCMAKE_C_FLAGS=-isystem\ ${CMAKE_CURRENT_SOURCE_DIR}/../include/sse\ -isystem\ ${CMAKE_CURRENT_SOURCE_DIR}/../include/libc/musl
                      ${CMAKE_CURRENT_SOURCE_DIR}/av1
  BUILD_COMMAND     make testavx_opt -j 4
  INSTALL_COMMAND   ${CMAKE_COMMAND} -E copy_if_different
                      testavx.opt.wasm
                      ${CMAKE_CURRENT_SOURCE_DIR}/av1/third_party/samples/elephants_dream_480p24.ivf
                      ${CMAKE_CURRENT_BINARY_DIR}
)
