/*
 * Copyright (C) 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_export.h"
#include "bh_read_file.h"
#include "bh_getopt.h"

void
my_log(uint32 log_level, const char *file, int line, const char *fmt, ...)
{
    char buf[200];
    snprintf(buf, sizeof(buf), "[WamrLogger] %s\n", fmt);

    va_list ap;
    va_start(ap, fmt);
    vprintf(buf, ap);
    va_end(ap);
}

int
my_vprintf(const char *format, va_list ap)
{
    return vprintf(format, ap);
}

void
print_usage(void)
{
    fprintf(stdout, "Options:\r\n");
    fprintf(stdout, "  -f [path of wasm file] \n");
}

int
main(int argc, char *argv_main[])
{
    static char global_heap_buf[512 * 1024];
    char *buffer = NULL, error_buf[128];
    int opt;
    char *wasm_path = NULL;
    bool success;

    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    uint32 buf_size, stack_size = 8092, heap_size = 8092;
    LoadArgs load_args = { 0 };

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

    load_args.wasm_binary_freeable = true;
    module = wasm_runtime_load_ex((uint8 *)buffer, buf_size, &load_args,
                                  error_buf, sizeof(error_buf));
    if (!module) {
        printf("Load wasm module failed. error: %s\n", error_buf);
        goto fail;
    }

    if (wasm_runtime_is_underlying_binary_freeable(module)) {
        printf("Able to free wasm binary buffer.\n");
        wasm_runtime_free(buffer);
        buffer = NULL;
    }

    module_inst = wasm_runtime_instantiate(module, stack_size, heap_size,
                                           error_buf, sizeof(error_buf));
    if (!module_inst) {
        printf("Instantiate wasm module failed. error: %s.\n", error_buf);
        goto fail;
    }

    char *args[1] = { "3" };
    success = wasm_application_execute_func(module_inst, "mul7", 1, args);
    if (!success) {
        printf("Unable to execute function.\n");
        goto fail;
    }

fail:
    if (module_inst)
        wasm_runtime_deinstantiate(module_inst);
    if (module)
        wasm_runtime_unload(module);
    if (buffer)
        wasm_runtime_free(buffer);
    wasm_runtime_destroy();
    return 0;
}