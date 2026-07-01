/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

#include "wasm_export.h"

static uint32_t
test_module_malloc_wrapper(wasm_exec_env_t exec_env, uint32_t buf_size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    return wasm_runtime_module_malloc(module_inst, buf_size, NULL);
}

static void
test_module_free_wrapper(wasm_exec_env_t exec_env, uint32_t ptr)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    wasm_runtime_module_free(module_inst, ptr);
}

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }

static NativeSymbol native_symbols[] = {
    REG_NATIVE_FUNC(test_module_malloc, "(i)i"),
    REG_NATIVE_FUNC(test_module_free, "(i)")
};
/* clang-format on */

uint32_t
get_native_lib(char **p_module_name, NativeSymbol **p_native_symbols)
{
    *p_module_name = "env";
    *p_native_symbols = native_symbols;
    return sizeof(native_symbols) / sizeof(NativeSymbol);
}
