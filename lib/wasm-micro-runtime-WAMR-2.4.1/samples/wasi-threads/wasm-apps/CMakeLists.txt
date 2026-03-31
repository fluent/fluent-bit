# Copyright (C) 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)
project (wasi_threads_wasm)

set (CMAKE_BUILD_TYPE Debug)  # Otherwise no debug symbols (addr2line)

function (compile_sample SOURCE_FILE)
  get_filename_component (FILE_NAME ${SOURCE_FILE} NAME_WLE)
  set (WASM_MODULE ${FILE_NAME}.wasm)
  add_executable (${WASM_MODULE} ${SOURCE_FILE} ${ARGN})

  target_compile_options (${WASM_MODULE} PRIVATE
    -pthread -ftls-model=local-exec)

  target_link_options (${WASM_MODULE} PRIVATE
    -z stack-size=32768
    LINKER:--export=__heap_base
    LINKER:--export=__data_end
    LINKER:--shared-memory,--max-memory=1966080
    LINKER:--export=wasi_thread_start
    LINKER:--export=malloc
    LINKER:--export=free
  )

  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${WASM_MODULE} DESTINATION wasm-apps)
endfunction ()

compile_sample(no_pthread.c wasi_thread_start.S)
