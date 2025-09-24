
/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_export.h"
#include "bh_read_file.h"
#include "bh_getopt.h"
#include "my_context.h"

int32_t
add_native(int32_t n);
void *my_context_key;
struct my_context my_context;
int my_dtor_called;

wasm_module_inst_t module_inst = NULL;

void
print_usage(void)
{
    fprintf(stdout, "Options:\r\n");
    fprintf(stdout, "  -f [path of wasm file] \n");
}

void
my_context_dtor(wasm_module_inst_t inst, void *ctx)
{
    printf("%s called\n", __func__);
    my_dtor_called++;
    bh_assert(ctx == &my_context);
    bh_assert(inst == module_inst);
}

int
main(int argc, char *argv_main[])
{
    static char global_heap_buf[512 * 1024];
    char *buffer;
    char error_buf[128];
    int opt;
    char *wasm_path = NULL;

    wasm_module_t module = NULL;
    wasm_exec_env_t exec_env = NULL;
    uint32 buf_size, stack_size = 8092, heap_size = 8092;

    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    while ((opt = getopt(argc, argv_main, "hf:")) != -1) {
        switch (opt) {
            case 'f':
                wasm_path = optarg;
                break;
            case 'h':
                print_usage();
                return 0;
            case '?':
                print_usage();
                return 0;
        }
    }
    if (optind == 1) {
        print_usage();
        return 0;
    }

    // Define an array of NativeSymbol for the APIs to be exported.
    // Note: the array must be static defined since runtime
    //            will keep it after registration
    // For the function signature specifications, goto the link:
    // https://github.com/bytecodealliance/wasm-micro-runtime/blob/main/doc/export_native_api.md

    static NativeSymbol native_symbols[] = { { "add_native", add_native, "(i)i",
                                               NULL } };

    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

    // Native symbols need below registration phase
    init_args.n_native_symbols = sizeof(native_symbols) / sizeof(NativeSymbol);
    init_args.native_module_name = "env";
    init_args.native_symbols = native_symbols;

    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

    my_context_key = wasm_runtime_create_context_key(my_context_dtor);
    if (!my_context_key) {
        printf("wasm_runtime_create_context_key failed.\n");
        return -1;
    }

    buffer = bh_read_file_to_buffer(wasm_path, &buf_size);

    if (!buffer) {
        printf("Open wasm app file [%s] failed.\n", wasm_path);
        goto fail;
    }

    module = wasm_runtime_load((uint8 *)buffer, buf_size, error_buf,
                               sizeof(error_buf));
    if (!module) {
        printf("Load wasm module failed. error: %s\n", error_buf);
        goto fail;
    }

    module_inst = wasm_runtime_instantiate(module, stack_size, heap_size,
                                           error_buf, sizeof(error_buf));

    if (!module_inst) {
        printf("Instantiate wasm module failed. error: %s\n", error_buf);
        goto fail;
    }

    my_context.x = 100;
    wasm_runtime_set_context(module_inst, my_context_key, &my_context);

    exec_env = wasm_runtime_create_exec_env(module_inst, stack_size);
    if (!exec_env) {
        printf("Create wasm execution environment failed.\n");
        goto fail;
    }

    wasm_function_inst_t func3 =
        wasm_runtime_lookup_function(module_inst, "calculate");
    if (!func3) {
        printf("The wasm function calculate is not found.\n");
        goto fail;
    }

    uint32_t argv3[1] = { 3 };
    if (wasm_runtime_call_wasm(exec_env, func3, 1, argv3)) {
        uint32_t result = *(uint32_t *)argv3;
        printf("Native finished calling wasm function: calculate, return: %d\n",
               result);
        bh_assert(result == 103); /* argv3[0] + my_context.x */
    }
    else {
        printf("call wasm function calculate failed. error: %s\n",
               wasm_runtime_get_exception(module_inst));
        goto fail;
    }

fail:
    if (exec_env)
        wasm_runtime_destroy_exec_env(exec_env);
    if (module_inst) {
        bh_assert(my_dtor_called == 0);
        wasm_runtime_deinstantiate(module_inst);
        bh_assert(my_dtor_called == 1);
    }
    if (module)
        wasm_runtime_unload(module);
    if (buffer)
        BH_FREE(buffer);
    if (my_context_key)
        wasm_runtime_destroy_context_key(my_context_key);
    wasm_runtime_destroy();
    return 0;
}
