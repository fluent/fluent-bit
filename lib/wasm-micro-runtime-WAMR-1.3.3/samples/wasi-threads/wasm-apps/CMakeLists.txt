# Copyright (C) 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

if (APPLE)
    set (HAVE_FLAG_SEARCH_PATHS_FIRST 0)
    set (CMAKE_C_LINK_FLAGS "")
    set (CMAKE_CXX_LINK_FLAGS "")
endif ()

if (NOT DEFINED WASI_SDK_DIR)
  set (WASI_SDK_DIR               "/opt/wasi-sdk")
endif ()

if (DEFINED WASI_SYSROOT)
  set (CMAKE_SYSROOT                "${WASI_SYSROOT}")
endif ()

set (CMAKE_C_COMPILER               "${WASI_SDK_DIR}/bin/clang")
set (CMAKE_ASM_COMPILER               "${WASI_SDK_DIR}/bin/clang")
set (CMAKE_EXE_LINKER_FLAGS         "-target wasm32-wasi-threads")

if ("$ENV{COLLECT_CODE_COVERAGE}" STREQUAL "1" OR COLLECT_CODE_COVERAGE EQUAL 1)
  set (CMAKE_C_FLAGS "")
  set (CMAKE_CXX_FLAGS "")
endif ()

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
endfunction ()

compile_sample(no_pthread.c wasi_thread_start.S)