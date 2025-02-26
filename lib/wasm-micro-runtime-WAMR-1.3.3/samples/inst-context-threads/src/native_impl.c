/*
 * Copyright (C) 2023 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stddef.h>
#include <stdio.h>

#include "wasm_export.h"
#include "my_context.h"

void
set_context(wasm_exec_env_t exec_env, int32_t n)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    printf("%s called on module inst %p\n", __func__, inst);
    struct my_context *ctx = &my_context;
    ctx->x = n;
    wasm_runtime_set_context_spread(inst, my_context_key, ctx);
}

int32_t
get_context(wasm_exec_env_t exec_env)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    printf("%s called on module inst %p\n", __func__, inst);
    struct my_context *ctx = wasm_runtime_get_context(inst, my_context_key);
    if (ctx == NULL) {
        return -1;
    }
    return ctx->x;
}
