/*
 * Copyright (C) 2023 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_export.h"
#include "my_context.h"

int32_t
add_native(wasm_exec_env_t exec_env, int32_t n)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    struct my_context *ctx = wasm_runtime_get_context(inst, my_context_key);
    return n + ctx->x;
}
