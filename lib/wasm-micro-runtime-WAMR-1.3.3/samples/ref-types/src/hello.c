/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_platform.h"
#include "bh_read_file.h"
#include "wasm_export.h"

#define USE_GLOBAL_HEAP_BUF 0

#if USE_GLOBAL_HEAP_BUF != 0
static char global_heap_buf[10 * 1024 * 1024] = { 0 };
#endif

static uintptr_t global_objects[10] = { 0 };

int32
local_cmp_externref(wasm_exec_env_t exec_env, uintptr_t externref_a,
                    uintptr_t externref_b)
{
    return externref_a == externref_b;
}

int32
local_chk_externref(wasm_exec_env_t exec_env, int32 index, uintptr_t externref)
{
    return externref == global_objects[index];
}

/* clang-format off */
static NativeSymbol native_symbols[] = {
    { "native-cmp-externref", local_cmp_externref, "(rr)i", NULL },
    { "native-chk-externref", local_chk_externref, "(ir)i", NULL },
};
/* clang-format on */

static inline void
local_set_externref(int32 index, uintptr_t externref)
{
    global_objects[index] = externref;
}

static WASMFunctionInstanceCommon *wasm_set_externref_ptr;
static WASMFunctionInstanceCommon *wasm_get_externref_ptr;
static WASMFunctionInstanceCommon *wasm_cmp_externref_ptr;

static bool
wasm_set_externref(wasm_exec_env_t exec_env, wasm_module_inst_t inst,
                   int32 index, uintptr_t externref)
{
    union {
        uintptr_t val;
        uint32 parts[2];
    } u;
    uint32 argv[3] = { 0 };

    if (!exec_env || !wasm_set_externref_ptr) {
        return false;
    }

    u.val = externref;
    argv[0] = index;
    argv[1] = u.parts[0];
    argv[2] = u.parts[1];
    if (!wasm_runtime_call_wasm(exec_env, wasm_set_externref_ptr, 2, argv)) {
        const char *exception;
        if ((exception = wasm_runtime_get_exception(inst))) {
            printf("Exception: %s\n", exception);
        }
        return false;
    }

    return true;
}

static bool
wasm_get_externref(wasm_exec_env_t exec_env, wasm_module_inst_t inst,
                   int32 index, uintptr_t *ret_externref)
{
    wasm_val_t results[1] = { 0 };

    if (!exec_env || !wasm_get_externref_ptr || !ret_externref) {
        return false;
    }

    if (!wasm_runtime_call_wasm_v(exec_env, wasm_get_externref_ptr, 1, results,
                                  1, index)) {
        const char *exception;
        if ((exception = wasm_runtime_get_exception(inst))) {
            printf("Exception: %s\n", exception);
        }
        return false;
    }

    if (WASM_ANYREF != results[0].kind) {
        return false;
    }

    *ret_externref = results[0].of.foreign;
    return true;
}

static bool
wasm_cmp_externref(wasm_exec_env_t exec_env, wasm_module_inst_t inst,
                   int32 index, uintptr_t externref, int32 *ret_result)
{
    wasm_val_t results[1] = { 0 };
    wasm_val_t arguments[2] = {
        { .kind = WASM_I32, .of.i32 = index },
        { .kind = WASM_ANYREF, .of.foreign = externref },
    };

    if (!exec_env || !wasm_cmp_externref_ptr || !ret_result) {
        return false;
    }

    if (!wasm_runtime_call_wasm_a(exec_env, wasm_cmp_externref_ptr, 1, results,
                                  2, arguments)) {
        const char *exception;
        if ((exception = wasm_runtime_get_exception(inst))) {
            printf("Exception: %s\n", exception);
        }
        return false;
    }

    if (results[0].kind != WASM_I32) {
        return false;
    }

    *ret_result = results[0].of.i32;
    return true;
}

static bool
set_and_cmp(wasm_exec_env_t exec_env, wasm_module_inst_t inst, int32 i,
            uintptr_t externref)
{
    int32 cmp_result = 0;
    uintptr_t wasm_externref = 0;

    wasm_set_externref(exec_env, inst, i, externref);
    local_set_externref(i, externref);

    wasm_get_externref(exec_env, inst, i, &wasm_externref);
    if (!local_chk_externref(exec_env, i, wasm_externref)) {
        printf("#%d, In host language world Wasm Externref 0x%lx Vs. Native "
               "Externref 0x%lx FAILED\n",
               i, wasm_externref, externref);
        return false;
    }

    if (!wasm_cmp_externref(exec_env, inst, i, global_objects[i], &cmp_result)
        || !cmp_result) {
        printf("#%d, In Wasm world Native Externref 0x%lx Vs, Wasm Externref "
               "FAILED\n",
               i, global_objects[i]);
        return false;
    }

    return true;
}

int
main(int argc, char *argv[])
{
    char *wasm_file = "hello.wasm";
    uint8 *wasm_file_buf = NULL;
    uint32 wasm_file_size;
    uint32 stack_size = 16 * 1024, heap_size = 16 * 1024;
    wasm_module_t wasm_module = NULL;
    wasm_module_inst_t wasm_module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    RuntimeInitArgs init_args;
    char error_buf[128] = { 0 };
#if WASM_ENABLE_LOG != 0
    int log_verbose_level = 2;
#endif
    const uint64 big_number = 0x123456789abc;

    memset(&init_args, 0, sizeof(RuntimeInitArgs));

#if USE_GLOBAL_HEAP_BUF != 0
    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);
#else
    init_args.mem_alloc_type = Alloc_With_Allocator;
    init_args.mem_alloc_option.allocator.malloc_func = malloc;
    init_args.mem_alloc_option.allocator.realloc_func = realloc;
    init_args.mem_alloc_option.allocator.free_func = free;
#endif

    init_args.n_native_symbols = sizeof(native_symbols) / sizeof(NativeSymbol);
    init_args.native_module_name = "env";
    init_args.native_symbols = native_symbols;

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

#if WASM_ENABLE_LOG != 0
    bh_log_set_verbose_level(log_verbose_level);
#endif

    /* load WASM byte buffer from WASM bin file */
    if (!(wasm_file_buf =
              (uint8 *)bh_read_file_to_buffer(wasm_file, &wasm_file_size)))
        goto fail;

    /* load WASM module */
    if (!(wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size,
                                          error_buf, sizeof(error_buf)))) {
        printf("%s\n", error_buf);
        goto fail;
    }

    /* instantiate the module */
    if (!(wasm_module_inst =
              wasm_runtime_instantiate(wasm_module, stack_size, heap_size,
                                       error_buf, sizeof(error_buf)))) {
        printf("%s\n", error_buf);
        goto fail;
    }

    /* create an execution env */
    if (!(exec_env =
              wasm_runtime_create_exec_env(wasm_module_inst, stack_size))) {
        printf("%s\n", "create exec env failed");
        goto fail;
    }

    /* lookup function instance */
    if (!(wasm_cmp_externref_ptr = wasm_runtime_lookup_function(
              wasm_module_inst, "cmp-externref", NULL))) {
        printf("%s\n", "lookup function cmp-externref failed");
        goto fail;
    }

    if (!(wasm_get_externref_ptr = wasm_runtime_lookup_function(
              wasm_module_inst, "get-externref", NULL))) {
        printf("%s\n", "lookup function get-externref failed");
        goto fail;
    }

    if (!(wasm_set_externref_ptr = wasm_runtime_lookup_function(
              wasm_module_inst, "set-externref", NULL))) {
        printf("%s\n", "lookup function set-externref failed");
        goto fail;
    }

    /* test with NULL */
    if (!set_and_cmp(exec_env, wasm_module_inst, 0, 0)
        || !set_and_cmp(exec_env, wasm_module_inst, 1, big_number + 1)
        || !set_and_cmp(exec_env, wasm_module_inst, 2, big_number + 2)
        || !set_and_cmp(exec_env, wasm_module_inst, 3, big_number + 3)) {
        goto fail;
    }

    printf("GREAT! PASS ALL CHKs\n");

fail:
    /* destroy exec env */
    if (exec_env) {
        wasm_runtime_destroy_exec_env(exec_env);
    }

    /* destroy the module instance */
    if (wasm_module_inst) {
        wasm_runtime_deinstantiate(wasm_module_inst);
    }

    /* unload the module */
    if (wasm_module) {
        wasm_runtime_unload(wasm_module);
    }

    /* free the file buffer */
    if (wasm_file_buf) {
        wasm_runtime_free(wasm_file_buf);
    }

    /* destroy runtime environment */
    wasm_runtime_destroy();
    return 0;
}
