/*
 * Copyright (C) 2024 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

#include "wasm_export.h"

static int
dummy(wasm_exec_env_t exec_env)
{
    return 0;
}

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, dummy, signature, NULL }

static NativeSymbol native_symbols[] = {
    REG_NATIVE_FUNC(host_consume_stack_and_call_indirect, "(iii)i"),
    REG_NATIVE_FUNC(host_consume_stack, "(i)i"),
};
/* clang-format on */

uint32_t
get_native_lib(char **p_module_name, NativeSymbol **p_native_symbols)
{
    *p_module_name = "env";
    *p_native_symbols = native_symbols;
    return sizeof(native_symbols) / sizeof(NativeSymbol);
}
