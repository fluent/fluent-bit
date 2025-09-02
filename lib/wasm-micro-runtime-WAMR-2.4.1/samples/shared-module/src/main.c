
/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_export.h"
#include "bh_read_file.h"
#include "bh_getopt.h"

void
print_usage(void)
{
    fprintf(stdout, "Options:\r\n");
    fprintf(stdout, "  -f [path of wasm file] \n");
}

int
main(int argc, char *argv_main[])
{
    int exit_code = 1;
    static char global_heap_buf[512 * 1024];
    char *buffer;
    char error_buf[128];
    int opt;
    char *wasm_path = NULL;

    const unsigned int N = 4;
    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst[N];
    wasm_exec_env_t exec_env[N];
    const char *name_test_data_drop = "test_data_drop";
    const char *name_test_elem_drop = "test_elem_drop";
    wasm_function_inst_t func_test_data_drop[N];
    wasm_function_inst_t func_test_elem_drop[N];
    unsigned int i;
    unsigned int iter;
    uint32 buf_size, stack_size = 8092, heap_size = 8092;

    for (i = 0; i < N; i++) {
        module_inst[i] = NULL;
        exec_env[i] = NULL;
        func_test_data_drop[i] = NULL;
        func_test_elem_drop[i] = NULL;
    }

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

    memset(&init_args, 0, sizeof(init_args));
    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
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

    for (i = 0; i < N; i++) {
        module_inst[i] = wasm_runtime_instantiate(module, stack_size, heap_size,
                                                  error_buf, sizeof(error_buf));

        if (!module_inst[i]) {
            printf("Instantiate wasm module failed. error: %s\n", error_buf);
            goto fail;
        }

        exec_env[i] = wasm_runtime_create_exec_env(module_inst[i], stack_size);
        if (!exec_env[i]) {
            printf("Create wasm execution environment failed.\n");
            goto fail;
        }

        func_test_data_drop[i] =
            wasm_runtime_lookup_function(module_inst[i], name_test_data_drop);
        if (!func_test_data_drop[i]) {
            printf("The wasm function %s is not found.\n", name_test_data_drop);
            goto fail;
        }

        func_test_elem_drop[i] =
            wasm_runtime_lookup_function(module_inst[i], name_test_elem_drop);
        if (!func_test_elem_drop[i]) {
            printf("The wasm function %s is not found.\n", name_test_elem_drop);
            goto fail;
        }
    }

    for (iter = 0; iter < 2; iter++) {
        /*
         * as we drop data/table in the first iteration,
         * the later iterations should trap.
         */
        const bool should_trap = iter > 0;

        for (i = 0; i < N; i++) {
            uint32_t argv[1] = {};
            if (wasm_runtime_call_wasm(exec_env[i], func_test_data_drop[i], 0,
                                       argv)) {
                uint32_t result = argv[0];
                printf(
                    "Native finished calling wasm function: %s, return: %x\n",
                    name_test_data_drop, result);
                if (result != 0x64636261) { /* "abcd" */
                    printf("unexpected return value\n");
                    goto fail;
                }
                if (should_trap) {
                    printf("a trap is expected\n");
                    goto fail;
                }
            }
            else if (should_trap) {
                printf("call wasm function %s failed as expected. error: %s\n",
                       name_test_data_drop,
                       wasm_runtime_get_exception(module_inst[i]));
            }
            else {
                printf("call wasm function %s failed. error: %s\n",
                       name_test_data_drop,
                       wasm_runtime_get_exception(module_inst[i]));
                goto fail;
            }
        }

        for (i = 0; i < N; i++) {
            wasm_runtime_clear_exception(module_inst[i]);

            uint32_t argv[1] = {};
            if (wasm_runtime_call_wasm(exec_env[i], func_test_elem_drop[i], 0,
                                       argv)) {
                uint32_t result = argv[0];
                printf(
                    "Native finished calling wasm function: %s, return: %x\n",
                    name_test_elem_drop, result);
                if (result != 0) {
                    printf("unexpected return value\n");
                    goto fail;
                }
                if (should_trap) {
                    printf("a trap is expected\n");
                    goto fail;
                }
            }
            else if (should_trap) {
                printf("call wasm function %s failed as expected. error: %s\n",
                       name_test_elem_drop,
                       wasm_runtime_get_exception(module_inst[i]));
            }
            else {
                printf("call wasm function %s failed. error: %s\n",
                       name_test_elem_drop,
                       wasm_runtime_get_exception(module_inst[i]));
                goto fail;
            }
        }
    }

    exit_code = 0;
fail:
    for (i = 0; i < N; i++) {
        if (exec_env[i])
            wasm_runtime_destroy_exec_env(exec_env[i]);
        if (module_inst[i])
            wasm_runtime_deinstantiate(module_inst[i]);
    }
    if (module)
        wasm_runtime_unload(module);
    if (buffer)
        BH_FREE(buffer);
    wasm_runtime_destroy();
    return exit_code;
}
