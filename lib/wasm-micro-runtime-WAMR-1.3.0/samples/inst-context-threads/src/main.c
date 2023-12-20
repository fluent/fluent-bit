
/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_export.h"
#include "bh_read_file.h"
#include "bh_getopt.h"
#include "my_context.h"

void
set_context(wasm_exec_env_t exec_env, int32_t n);
int32_t
get_context(wasm_exec_env_t exec_env);

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
    int exit_code = 1;

    wasm_module_t module = NULL;
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

    static NativeSymbol native_symbols[] = {
        { "set_context", set_context, "(i)", NULL },
        { "get_context", get_context, "()i", NULL },
    };

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

    char *args[] = {
        "testapp",
    };
    wasm_application_execute_main(module_inst, 1, args);
    const char *exc = wasm_runtime_get_exception(module_inst);
    if (exc != NULL) {
        printf("call wasm function calculate failed. error: %s\n", exc);
        goto fail;
    }

    exit_code = 0;
fail:
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
    return exit_code;
}
