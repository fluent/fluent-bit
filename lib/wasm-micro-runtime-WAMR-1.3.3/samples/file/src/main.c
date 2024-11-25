/*
 * Copyright (C) 2022 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_export.h"
#include "bh_read_file.h"

void
print_usage(void)
{
    fprintf(stdout, "Required arguments:\r\n");
    fprintf(stdout, "  -f [path of wasm file] \n");
    fprintf(stdout, "  -d [path of host directory] \n");
}

int
main(int argc, char *argv_main[])
{
    static char global_heap_buf[512 * 1024];
    char *buffer, error_buf[128];
    const char *wasm_path = NULL, *wasi_dir = NULL;
    int opt, main_result = 1;

    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    uint32 buf_size, stack_size = 8092, heap_size = 8092;

    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    while ((opt = getopt(argc, argv_main, "hf:d:")) != -1) {
        switch (opt) {
            case 'f':
                wasm_path = optarg;
                break;
            case 'd':
                wasi_dir = optarg;
                break;
            case 'h':
                print_usage();
                return 0;
            case '?':
                print_usage();
                return 0;
        }
    }
    if (wasm_path == NULL || wasi_dir == NULL) {
        print_usage();
        return 0;
    }

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

    module = wasm_runtime_load(buffer, buf_size, error_buf, sizeof(error_buf));
    if (!module) {
        printf("Load wasm module failed. error: %s\n", error_buf);
        goto fail;
    }

    wasm_runtime_set_wasi_args_ex(module, &wasi_dir, 1, NULL, 0, NULL, 0, NULL,
                                  0, 0, 1, 2);

    module_inst = wasm_runtime_instantiate(module, stack_size, heap_size,
                                           error_buf, sizeof(error_buf));

    if (!module_inst) {
        printf("Instantiate wasm module failed. error: %s\n", error_buf);
        goto fail;
    }

    exec_env = wasm_runtime_create_exec_env(module_inst, stack_size);
    if (!exec_env) {
        printf("Create wasm execution environment failed.\n");
        goto fail;
    }

    if (wasm_application_execute_main(module_inst, 0, NULL)) {
        main_result = wasm_runtime_get_wasi_exit_code(module_inst);
    }
    else {
        printf("call wasm function main failed. error: %s\n",
               wasm_runtime_get_exception(module_inst));
        goto fail;
    }

fail:
    if (exec_env)
        wasm_runtime_destroy_exec_env(exec_env);
    if (module_inst)
        wasm_runtime_deinstantiate(module_inst);
    if (module)
        wasm_runtime_unload(module);
    if (buffer)
        BH_FREE(buffer);
    wasm_runtime_destroy();
    return main_result;
}
