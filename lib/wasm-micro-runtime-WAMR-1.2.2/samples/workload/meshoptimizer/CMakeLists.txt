# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project(bench-meshoptimizer)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../cmake)

################ dependencies ################
find_package(Python3 REQUIRED)
find_package(WASISDK 16.0 REQUIRED)
execute_process(
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/../../../test-tools/pick-up-emscripten-headers/collect_files.py --install ../include --loglevel=ERROR
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
)

################  MESHOPTIMIZER  ################
include(ExternalProject)

ExternalProject_Add(codecbench
  PREFIX codecbench
  GIT_REPOSITORY https://github.com/zeux/meshoptimizer.git
  GIT_TAG        f734fd572aed5bf76e84d9ed62ca6f4f6c47d84e
  GIT_SHALLOW    OFF
  GIT_PROGRESS   ON
  SOURCE_DIR     ${CMAKE_CURRENT_SOURCE_DIR}/meshoptimizer
  UPDATE_COMMAND git clean -fd && git checkout -- *
                   && ${CMAKE_COMMAND} -E echo "Applying patch"
                   && git apply ${CMAKE_CURRENT_SOURCE_DIR}/codecbench.patch
  CONFIGURE_COMMAND ${CMAKE_COMMAND}
                      -DWASI_SDK_PREFIX=${WASISDK_HOME}
                      -DCMAKE_TOOLCHAIN_FILE=${WASISDK_TOOLCHAIN}
                      -DCMAKE_SYSROOT=${WASISDK_SYSROOT}
                      ${CMAKE_CURRENT_SOURCE_DIR}/meshoptimizer
  BUILD_COMMAND  make codecbench -j 4
  INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_if_different ./codecbench.wasm ${CMAKE_CURRENT_BINARY_DIR}/codecbench.wasm
)
