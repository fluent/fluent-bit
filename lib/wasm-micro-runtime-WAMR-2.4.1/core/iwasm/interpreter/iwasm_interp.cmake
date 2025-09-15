# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (IWASM_INTERP_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions (-DWASM_ENABLE_INTERP=1)

include_directories(${IWASM_INTERP_DIR})

if (WAMR_BUILD_FAST_INTERP EQUAL 1)
    set (INTERPRETER     "wasm_interp_fast.c")
else ()
    set (INTERPRETER     "wasm_interp_classic.c")
endif ()

if (WAMR_BUILD_MINI_LOADER EQUAL 1)
    set (LOADER          "wasm_mini_loader.c")
else ()
    set (LOADER          "wasm_loader.c")
endif ()

file (GLOB_RECURSE source_all
    ${IWASM_INTERP_DIR}/${LOADER}
    ${IWASM_INTERP_DIR}/wasm_runtime.c
    ${IWASM_INTERP_DIR}/${INTERPRETER}
)

set (IWASM_INTERP_SOURCE ${source_all})

