# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.14)

project(wasm-apps-aot-stack-frame)

set (WAMRC_OPTION --enable-dump-call-stack --bounds-checks=1 --enable-gc)

if (WAMR_BUILD_TARGET STREQUAL "X86_32")
      set (WAMRC_OPTION ${WAMRC_OPTION} --target=i386)
endif ()

add_custom_target(
      aot-stack-frame-test-wasm ALL

      # Step 1: Build wamrc
      COMMAND cmake -B ${CMAKE_CURRENT_BINARY_DIR}/build-wamrc 
                  -S ${WAMR_ROOT_DIR}/wamr-compiler
      COMMAND cmake --build ${CMAKE_CURRENT_BINARY_DIR}/build-wamrc

      # Step 2: Compile .wast to .wasm
      COMMAND /opt/wabt/bin/wat2wasm 
                  -o ${CMAKE_CURRENT_BINARY_DIR}/test.wasm ${CMAKE_CURRENT_LIST_DIR}/test.wast

      # Step 3: Compile .wasm to .aot using wamrc
      COMMAND ${CMAKE_CURRENT_BINARY_DIR}/build-wamrc/wamrc ${WAMRC_OPTION}
                  -o ${CMAKE_CURRENT_BINARY_DIR}/test.aot ${CMAKE_CURRENT_BINARY_DIR}/test.wasm

      # Step 4: Build binarydump tool
      COMMAND cmake -B ${CMAKE_CURRENT_BINARY_DIR}/build-binarydump 
                  -S ${WAMR_ROOT_DIR}/test-tools/binarydump-tool
      COMMAND cmake --build ${CMAKE_CURRENT_BINARY_DIR}/build-binarydump

      # Step 5: Generate .h file from .aot
      COMMAND ${CMAKE_CURRENT_BINARY_DIR}/build-binarydump/binarydump 
                  -o ${CMAKE_CURRENT_LIST_DIR}/test_aot.h 
                  -n test_aot
                  ${CMAKE_CURRENT_BINARY_DIR}/test.aot
)

