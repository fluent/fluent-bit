/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

/*
 * This example basically does the same thing as test_hello.c,
 * using wasm_export.h API.
 */

#include <stdio.h>
#include <stdlib.h>

#include "wasm_export.h"

static int
test_hello2_wrapper(wasm_exec_env_t exec_env, uint32_t nameaddr,
                    uint32_t resultaddr, uint32_t resultlen)
{
    /*
     * Perform wasm_runtime_malloc to check if the runtime has been
     * initialized as expected.
     * This would fail with "memory hasn't been initialize" error
     * unless we are not sharing a runtime with the loader app. (iwasm)
     */
    void *p = wasm_runtime_malloc(1);
    if (p == NULL) {
        return -1;
    }
    wasm_runtime_free(p);

    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    if (!wasm_runtime_validate_app_str_addr(inst, nameaddr)
        || !wasm_runtime_validate_app_addr(inst, resultaddr, resultlen)) {
        return -1;
    }
    const char *name = wasm_runtime_addr_app_to_native(inst, nameaddr);
    char *result = wasm_runtime_addr_app_to_native(inst, resultaddr);
    return snprintf(result, resultlen,
                    "Hello, %s. This is %s! Your wasm_module_inst_t is %p.\n",
                    name, __func__, inst);
}

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }

static NativeSymbol native_symbols[] = {
    REG_NATIVE_FUNC(test_hello2, "(iii)i")
};
/* clang-format on */

uint32_t
get_native_lib(char **p_module_name, NativeSymbol **p_native_symbols)
{
    *p_module_name = "env";
    *p_native_symbols = native_symbols;
    return sizeof(native_symbols) / sizeof(NativeSymbol);
}

int
init_native_lib()
{
    printf("%s in test_hello2.c called\n", __func__);
    return 0;
}

void
deinit_native_lib()
{
    printf("%s in test_hello2.c called\n", __func__);
}
