/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_export.h"
#include "bh_read_file.h"
#include "pthread.h"

#define THREAD_NUM 10

typedef struct ThreadArgs {
    wasm_exec_env_t exec_env;
    int start;
    int length;
} ThreadArgs;

void *
thread(void *arg)
{
    ThreadArgs *thread_arg = (ThreadArgs *)arg;
    wasm_exec_env_t exec_env = thread_arg->exec_env;
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasm_function_inst_t func;
    uint32 argv[2];

    if (!wasm_runtime_init_thread_env()) {
        printf("failed to initialize thread environment");
        return NULL;
    }

    func = wasm_runtime_lookup_function(module_inst, "sum", NULL);
    if (!func) {
        printf("failed to lookup function sum");
        wasm_runtime_destroy_thread_env();
        return NULL;
    }
    argv[0] = thread_arg->start;
    argv[1] = thread_arg->length;

    /* call the WASM function */
    if (!wasm_runtime_call_wasm(exec_env, func, 2, argv)) {
        printf("%s\n", wasm_runtime_get_exception(module_inst));
        wasm_runtime_destroy_thread_env();
        return NULL;
    }

    wasm_runtime_destroy_thread_env();
    return (void *)(uintptr_t)argv[0];
}

void *
wamr_thread_cb(wasm_exec_env_t exec_env, void *arg)
{
    ThreadArgs *thread_arg = (ThreadArgs *)arg;
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasm_function_inst_t func;
    uint32 argv[2];

    func = wasm_runtime_lookup_function(module_inst, "sum", NULL);
    if (!func) {
        printf("failed to lookup function sum");
        return NULL;
    }
    argv[0] = thread_arg->start;
    argv[1] = thread_arg->length;

    /* call the WASM function */
    if (!wasm_runtime_call_wasm(exec_env, func, 2, argv)) {
        printf("%s\n", wasm_runtime_get_exception(module_inst));
        return NULL;
    }

    return (void *)(uintptr_t)argv[0];
}

int
main(int argc, char *argv[])
{
    char *wasm_file = "wasm-apps/test.wasm";
    uint8 *wasm_file_buf = NULL;
    uint32 wasm_file_size, wasm_argv[2], i, threads_created;
    uint32 stack_size = 16 * 1024, heap_size = 16 * 1024;
    wasm_module_t wasm_module = NULL;
    wasm_module_inst_t wasm_module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    RuntimeInitArgs init_args;
    ThreadArgs thread_arg[THREAD_NUM];
    pthread_t tid[THREAD_NUM];
    wasm_thread_t wasm_tid[THREAD_NUM];
    uint32 result[THREAD_NUM], sum;
    wasm_function_inst_t func;
    char error_buf[128] = { 0 };

    memset(thread_arg, 0, sizeof(ThreadArgs) * THREAD_NUM);
    memset(&init_args, 0, sizeof(RuntimeInitArgs));
    init_args.mem_alloc_type = Alloc_With_Allocator;
    init_args.mem_alloc_option.allocator.malloc_func = malloc;
    init_args.mem_alloc_option.allocator.realloc_func = realloc;
    init_args.mem_alloc_option.allocator.free_func = free;
    init_args.max_thread_num = THREAD_NUM;

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

    /* load WASM byte buffer from WASM bin file */
    if (!(wasm_file_buf =
              (uint8 *)bh_read_file_to_buffer(wasm_file, &wasm_file_size)))
        goto fail1;

    /* load WASM module */
    if (!(wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size,
                                          error_buf, sizeof(error_buf)))) {
        printf("%s\n", error_buf);
        goto fail2;
    }

    /* instantiate the module */
    if (!(wasm_module_inst =
              wasm_runtime_instantiate(wasm_module, stack_size, heap_size,
                                       error_buf, sizeof(error_buf)))) {
        printf("%s\n", error_buf);
        goto fail3;
    }

    /* Create the first exec_env */
    if (!(exec_env =
              wasm_runtime_create_exec_env(wasm_module_inst, stack_size))) {
        printf("failed to create exec_env\n");
        goto fail4;
    }

    func = wasm_runtime_lookup_function(wasm_module_inst, "sum", NULL);
    if (!func) {
        printf("failed to lookup function sum");
        goto fail5;
    }
    wasm_argv[0] = 0;
    wasm_argv[1] = THREAD_NUM * 10;

    /*
     * Execute the wasm function in current thread, get the expect result
     */
    if (!wasm_runtime_call_wasm(exec_env, func, 2, wasm_argv)) {
        printf("%s\n", wasm_runtime_get_exception(wasm_module_inst));
    }
    printf("expect result: %d\n", wasm_argv[0]);

    /*
     * Run wasm function in multiple thread created by pthread_create
     */
    memset(thread_arg, 0, sizeof(ThreadArgs) * THREAD_NUM);
    for (i = 0; i < THREAD_NUM; i++) {
        wasm_exec_env_t new_exec_env;
        thread_arg[i].start = 10 * i;
        thread_arg[i].length = 10;

        /* spawn a new exec_env to be executed in other threads */
        new_exec_env = wasm_runtime_spawn_exec_env(exec_env);
        if (new_exec_env)
            thread_arg[i].exec_env = new_exec_env;
        else {
            printf("failed to spawn exec_env\n");
            break;
        }

        /* If we use:
            thread_arg[i].exec_env = exec_env,
            we may get wrong result */

        if (0 != pthread_create(&tid[i], NULL, thread, &thread_arg[i])) {
            printf("failed to create thread.\n");
            wasm_runtime_destroy_spawned_exec_env(new_exec_env);
            break;
        }
    }

    threads_created = i;

    sum = 0;
    memset(result, 0, sizeof(uint32) * THREAD_NUM);
    for (i = 0; i < threads_created; i++) {
        pthread_join(tid[i], (void **)&result[i]);
        sum += result[i];
        /* destroy the spawned exec_env */
        if (thread_arg[i].exec_env)
            wasm_runtime_destroy_spawned_exec_env(thread_arg[i].exec_env);
    }

    printf("[pthread]sum result: %d\n", sum);

    /*
     * Run wasm function in multiple thread created by wamr spawn API
     */
    memset(thread_arg, 0, sizeof(ThreadArgs) * THREAD_NUM);
    for (i = 0; i < THREAD_NUM; i++) {
        thread_arg[i].start = 10 * i;
        thread_arg[i].length = 10;

        /* No need to spawn exec_env manually */
        if (0
            != wasm_runtime_spawn_thread(exec_env, &wasm_tid[i], wamr_thread_cb,
                                         &thread_arg[i])) {
            printf("failed to spawn thread.\n");
            break;
        }
    }

    threads_created = i;

    sum = 0;
    memset(result, 0, sizeof(uint32) * THREAD_NUM);
    for (i = 0; i < threads_created; i++) {
        wasm_runtime_join_thread(wasm_tid[i], (void **)&result[i]);
        sum += result[i];
        /* No need to destroy the spawned exec_env */
    }
    printf("[spwan_thread]sum result: %d\n", sum);

fail5:
    wasm_runtime_destroy_exec_env(exec_env);

fail4:
    /* destroy the module instance */
    wasm_runtime_deinstantiate(wasm_module_inst);

fail3:
    /* unload the module */
    wasm_runtime_unload(wasm_module);

fail2:
    /* free the file buffer */
    wasm_runtime_free(wasm_file_buf);

fail1:
    /* destroy runtime environment */
    wasm_runtime_destroy();
    return 0;
}
