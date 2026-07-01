
/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_export.h"
#include "bh_read_file.h"
#include "bh_getopt.h"

int
intToStr(int x, char *str, int str_len, int digit);
int
get_pow(int x, int y);
int32_t
calculate_native(int32_t n, int32_t func1, int32_t func2);

void
my_log(uint32 log_level, const char *file, int line, const char *fmt, ...)
{
    char buf[200];
    snprintf(buf, 200,
             log_level == WASM_LOG_LEVEL_VERBOSE ? "[WamrLogger - VERBOSE] %s"
                                                 : "[WamrLogger] %s",
             fmt);

    va_list ap;
    va_start(ap, fmt);
    vprintf(buf, ap);
    va_end(ap);
}

int
my_vprintf(const char *format, va_list ap)
{
    /* Print in blue */
    char buf[200];
    snprintf(buf, 200, "\x1b[34m%s\x1b[0m", format);
    return vprintf(buf, ap);
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
    char *buffer, error_buf[128];
    int opt;
    char *wasm_path = NULL;

    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    uint32 buf_size, stack_size = 8092, heap_size = 8092;
    wasm_function_inst_t func = NULL;
    wasm_function_inst_t func2 = NULL;
    char *native_buffer = NULL;
    uint64_t wasm_buffer = 0;

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
        {
            "intToStr", // the name of WASM function name
            intToStr,   // the native function pointer
            "(i*~i)i",  // the function prototype signature, avoid to use i32
            NULL        // attachment is NULL
        },
        {
            "get_pow", // the name of WASM function name
            get_pow,   // the native function pointer
            "(ii)i",   // the function prototype signature, avoid to use i32
            NULL       // attachment is NULL
        },
        { "calculate_native", calculate_native, "(iii)i", NULL }
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
    wasm_runtime_set_log_level(WASM_LOG_LEVEL_VERBOSE);

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

    exec_env = wasm_runtime_create_exec_env(module_inst, stack_size);
    if (!exec_env) {
        printf("Create wasm execution environment failed.\n");
        goto fail;
    }

    if (!(func = wasm_runtime_lookup_function(module_inst, "generate_float"))) {
        printf("The generate_float wasm function is not found.\n");
        goto fail;
    }

    wasm_val_t results[1] = { { .kind = WASM_F32, .of.f32 = 0 } };
    wasm_val_t arguments[3] = {
        { .kind = WASM_I32, .of.i32 = 10 },
        { .kind = WASM_F64, .of.f64 = 0.000101 },
        { .kind = WASM_F32, .of.f32 = 300.002 },
    };

    // pass 4 elements for function arguments
    if (!wasm_runtime_call_wasm_a(exec_env, func, 1, results, 3, arguments)) {
        printf("call wasm function generate_float failed. %s\n",
               wasm_runtime_get_exception(module_inst));
        goto fail;
    }

    float ret_val;
    ret_val = results[0].of.f32;
    printf("Native finished calling wasm function generate_float(), returned a "
           "float value: %ff\n",
           ret_val);

    // Next we will pass a buffer to the WASM function
    uint32 argv2[4];

    // must allocate buffer from wasm instance memory space (never use pointer
    // from host runtime)
    wasm_buffer =
        wasm_runtime_module_malloc(module_inst, 100, (void **)&native_buffer);

    memcpy(argv2, &ret_val, sizeof(float)); // the first argument
    argv2[1] = wasm_buffer; // the second argument is the wasm buffer address
    argv2[2] = 100;         //  the third argument is the wasm buffer size
    argv2[3] = 3; //  the last argument is the digits after decimal point for
                  //  converting float to string

    if (!(func2 =
              wasm_runtime_lookup_function(module_inst, "float_to_string"))) {
        printf(
            "The wasm function float_to_string wasm function is not found.\n");
        goto fail;
    }

    if (wasm_runtime_call_wasm(exec_env, func2, 4, argv2)) {
        printf("Native finished calling wasm function: float_to_string, "
               "returned a formatted string: %s\n",
               native_buffer);
    }
    else {
        printf("call wasm function float_to_string failed. error: %s\n",
               wasm_runtime_get_exception(module_inst));
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
        if (wasm_buffer)
            wasm_runtime_module_free(module_inst, (uint64)wasm_buffer);
        wasm_runtime_deinstantiate(module_inst);
    }
    if (module)
        wasm_runtime_unload(module);
    if (buffer)
        BH_FREE(buffer);
    wasm_runtime_destroy();
    return 0;
}
