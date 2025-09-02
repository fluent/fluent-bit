# Copyright (C) 2019 Intel Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project(wasm_workloads)

#######################################
add_subdirectory(bwa)
add_subdirectory(meshoptimizer)
add_subdirectory(wasm-av1)

#######################################
include(ExternalProject)

################ iwasm ################
ExternalProject_Add(iwasm
  PREFIX
    iwasm-build
  BUILD_ALWAYS
    YES
  SOURCE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/../../product-mini/platforms/linux
  CONFIGURE_COMMAND
    ${CMAKE_COMMAND} -S ${CMAKE_CURRENT_SOURCE_DIR}/../../product-mini/platforms/linux -B build -DWAMR_BUILD_LIBC_EMCC=1
  BUILD_COMMAND
    ${CMAKE_COMMAND} --build build --parallel 4
  INSTALL_COMMAND
    # FIXME: replace with --install
    ${CMAKE_COMMAND} -E copy_if_different
      ${CMAKE_CURRENT_BINARY_DIR}/iwasm-build/src/iwasm-build/build/iwasm
      ${CMAKE_CURRENT_BINARY_DIR}/iwasm
)

################ wamrc ################
ExternalProject_Add(wamrc
  PREFIX
    wamrc-build
  BUILD_ALWAYS
    YES
  SOURCE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wamr-compiler
  CONFIGURE_COMMAND
    ${CMAKE_COMMAND} -S ${CMAKE_CURRENT_SOURCE_DIR}/../../wamr-compiler -B build
  BUILD_COMMAND
    ${CMAKE_COMMAND} --build build --parallel 4
  INSTALL_COMMAND
    # FIXME: replace with --install
    ${CMAKE_COMMAND} -E copy_if_different
      ${CMAKE_CURRENT_BINARY_DIR}/wamrc-build/src/wamrc-build/build/wamrc
      ${CMAKE_CURRENT_BINARY_DIR}/wamrc
)

################ .aot ################
add_custom_target(
  bwa_to_aot
  ALL
  DEPENDS
    bwa wamrc
  COMMAND
    ./wamrc -o bwa.aot ./bwa/bwa.wasm
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target(
  codecbench_to_aot
  ALL
  DEPENDS
    codecbench wamrc
  COMMAND
    ./wamrc -o codecbench.aot ./meshoptimizer/codecbench.wasm
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target(
  av1_to_aot
  ALL
  DEPENDS
    av1 wamrc
  COMMAND
    ./wamrc -o testavx.aot ./wasm-av1/testavx.opt.wasm
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
)

################ smoking test ################
include(CTest)

add_test(
  NAME
    run_bwa
  COMMAND
    ./iwasm --dir=. ./bwa.aot index ./bwa/hs38DH-extra.fa
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
)

add_test(
  NAME
    run_codecbench
  COMMAND
    ./iwasm codecbench.aot
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
)

add_test(
  NAME
    run_av1
  COMMAND
    ./iwasm --dir=. testavx.aot ./wasm-av1/elephants_dream_480p24.ivf
  WORKING_DIRECTORY
    ${CMAKE_CURRENT_BINARY_DIR}
)
