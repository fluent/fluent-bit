/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_common.h"
#include "bh_log.h"
#include "wasm_export.h"
#include "../interpreter/wasm.h"
#include "../common/wasm_runtime_common.h"
/* clang-format off */
#define validate_native_addr(addr, size) \
    wasm_runtime_validate_native_addr(module_inst, addr, size)

#define module_shared_malloc(size, p_native_addr) \
    wasm_runtime_shared_heap_malloc(module_inst, size, p_native_addr)

#define module_shared_free(offset) \
    wasm_runtime_shared_heap_free(module_inst, offset)
/* clang-format on */

static uint32
shared_heap_malloc_wrapper(wasm_exec_env_t exec_env, uint32 size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    return (uint32)module_shared_malloc((uint64)size, NULL);
}

static void
shared_heap_free_wrapper(wasm_exec_env_t exec_env, void *ptr)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    if (!validate_native_addr(ptr, (uint64)sizeof(uintptr_t))) {
        LOG_WARNING("Invalid app address");
        return;
    }

    module_shared_free(addr_native_to_app(ptr));
}

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }
/* clang-format on */

static NativeSymbol native_symbols_shared_heap[] = {
    REG_NATIVE_FUNC(shared_heap_malloc, "(i)i"),
    REG_NATIVE_FUNC(shared_heap_free, "(*)"),
};

uint32
get_lib_shared_heap_export_apis(NativeSymbol **p_shared_heap_apis)
{
    *p_shared_heap_apis = native_symbols_shared_heap;
    return sizeof(native_symbols_shared_heap) / sizeof(NativeSymbol);
}
