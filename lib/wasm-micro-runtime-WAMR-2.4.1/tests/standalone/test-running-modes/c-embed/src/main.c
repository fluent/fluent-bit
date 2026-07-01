/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_read_file.h"
#include "wasm_export.h"

RunningMode
str_to_running_mode(char const *str)
{
    RunningMode running_mode = 0;
#if WASM_ENABLE_INTERP != 0
    if (!strcmp(str, "interp")) {
        running_mode = Mode_Interp;
    }
#endif
#if WASM_ENABLE_FAST_JIT != 0
    else if (!strcmp(str, "fast-jit")) {
        running_mode = Mode_Fast_JIT;
    }
#endif
#if WASM_ENABLE_JIT != 0
    else if (!strcmp(str, "llvm-jit")) {
        running_mode = Mode_LLVM_JIT;
    }
#endif
#if WASM_ENABLE_JIT != 0 && WASM_ENABLE_FAST_JIT != 0 \
    && WASM_ENABLE_LAZY_JIT != 0
    else if (!strcmp(str, "multi-tier-jit")) {
        running_mode = Mode_Multi_Tier_JIT;
    }
#endif
    return running_mode;
}

int
one_time_run_wasm(RunningMode default_running_mode,
                  RunningMode module_running_mode)
{
    char *buffer, *another_buffer, error_buf[128];
    wasm_module_t module = NULL, another_module = NULL;
    wasm_module_inst_t module_inst = NULL, another_module_inst = NULL;
    wasm_function_inst_t main_func = NULL, echo_func = NULL;
    wasm_exec_env_t exec_env = NULL, another_exec_env = NULL;
    uint32_t size, stack_size = 8092, heap_size = 8092;

    if (wasm_runtime_is_running_mode_supported(default_running_mode)) {
        printf("Support running mode: %d\n", default_running_mode);
    }
    else {
        printf("This runtime Doesn't support running mode: %d\n",
               default_running_mode);
        goto fail;
    }
    if (wasm_runtime_set_default_running_mode(default_running_mode)) {
        printf("Successfully set default running mode: %d\n",
               default_running_mode);
    }
    else {
        printf("Set default running mode: %d failed\n", default_running_mode);
        goto fail;
    }

    /* module 1 */
    if (!(buffer = bh_read_file_to_buffer("mytest.wasm", &size))) {
        printf("Open wasm app file %s failed.\n", "mytest.wasm");
        goto fail;
    }
    if (!(module = wasm_runtime_load((uint8_t *)buffer, size, error_buf,
                                     sizeof(error_buf)))) {
        printf("Load wasm module failed. error: %s\n", error_buf);
        goto fail;
    }
    if (!(module_inst = wasm_runtime_instantiate(
              module, stack_size, heap_size, error_buf, sizeof(error_buf)))) {
        printf("Instantiate wasm module failed. error: %s\n", error_buf);
        goto fail;
    }
    if (!(exec_env = wasm_runtime_create_exec_env(module_inst, stack_size))) {
        printf("Create wasm execution environment failed.\n");
        goto fail;
    }
    /* module 2 */
    if (!(another_buffer = bh_read_file_to_buffer("hello.wasm", &size))) {
        printf("Open wasm app file %s failed.\n", "hello.wasm");
        goto fail;
    }
    if (!(another_module = wasm_runtime_load((uint8_t *)another_buffer, size,
                                             error_buf, sizeof(error_buf)))) {
        printf("Load wasm module failed. error: %s\n", error_buf);
        goto fail;
    }
    if (!(another_module_inst =
              wasm_runtime_instantiate(another_module, stack_size, heap_size,
                                       error_buf, sizeof(error_buf)))) {
        printf("Instantiate wasm module failed. error: %s\n", error_buf);
        goto fail;
    }
    if (!(another_exec_env =
              wasm_runtime_create_exec_env(another_module_inst, stack_size))) {
        printf("Create wasm execution environment failed.\n");
        goto fail;
    }

    /* run main function in module 1 */
    uint32 wasm_argv[2];
    if (!(main_func =
              wasm_runtime_lookup_function(module_inst, "__main_argc_argv"))) {
        printf("The main wasm function from module 1 is not found.\n");
        goto fail;
    }

    wasm_argv[0] = 3;
    if (wasm_runtime_call_wasm(exec_env, main_func, 2, wasm_argv)) {
        printf("Run module 1 in running mode: %d\n",
               wasm_runtime_get_running_mode(module_inst));
        assert(default_running_mode
               == wasm_runtime_get_running_mode(module_inst));
        printf("Wasm main function return: %d\n", wasm_argv[0]);
    }
    else {
        printf("%s\n", wasm_runtime_get_exception(module_inst));
        goto fail;
    }

    /* run echo function in module 2 */
    if (!(wasm_runtime_set_running_mode(another_module_inst,
                                        module_running_mode))) {

        printf("Set running mode for module instance failed\n");
        goto fail;
    }
    if (!(echo_func =
              wasm_runtime_lookup_function(another_module_inst, "echo"))) {
        printf("The echo wasm function from module 2 is not found.\n");
        goto fail;
    }

    wasm_argv[0] = 5;
    if (wasm_runtime_call_wasm(another_exec_env, echo_func, 1, wasm_argv)) {
        printf("Run module 2 in running mode: %d\n",
               wasm_runtime_get_running_mode(another_module_inst));
        assert(module_running_mode
               == wasm_runtime_get_running_mode(another_module_inst));
        printf("Wasm echo function return: %d\n\n", wasm_argv[0]);
    }
    else {
        printf("%s\n", wasm_runtime_get_exception(another_module_inst));
        goto fail;
    }

fail:
    if (exec_env)
        wasm_runtime_destroy_exec_env(exec_env);
    if (another_exec_env)
        wasm_runtime_destroy_exec_env(another_exec_env);
    if (module_inst)
        wasm_runtime_deinstantiate(module_inst);
    if (another_module_inst)
        wasm_runtime_deinstantiate(another_module_inst);
    if (module)
        wasm_runtime_unload(module);
    if (another_module)
        wasm_runtime_unload(another_module);

    return 0;
}

int
main(int argc, char const *argv[])
{

    RunningMode default_running_mode = 0, module_running_mode = 0;

    for (argc--, argv++; argc > 0 && argv[0][0] == '-'; argc--, argv++) {
        if (!strncmp(argv[0], "--default-running-mode=", 23)) {
            default_running_mode = str_to_running_mode(argv[0] + 23);
        }
        else if (!strncmp(argv[0], "--module-running-mode=", 22)) {
            module_running_mode = str_to_running_mode(argv[0] + 22);
        }
    }

    /* all the runtime memory allocations are restricted in the global_heap_buf
     * array */
    static char global_heap_buf[512 * 1024];
    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));
    /* configure the memory allocator for the runtime */
    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

    /* initialize runtime environment with user configurations*/
    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

    for (int i = 0; i < 1; ++i) {
        one_time_run_wasm(default_running_mode, module_running_mode);
    }

    wasm_runtime_destroy();

    return 0;
}
