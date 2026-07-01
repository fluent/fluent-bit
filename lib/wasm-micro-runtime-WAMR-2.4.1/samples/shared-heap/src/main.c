/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_export.h"
#include "bh_platform.h"
#include "bh_read_file.h"

typedef struct thread_arg {
    bh_queue *queue;
    wasm_module_inst_t module_inst;
} thread_arg;

static void *
thread1_callback(void *arg)
{
    thread_arg *targ = arg;
    wasm_module_inst_t module_inst = targ->module_inst;
    bh_queue *queue = targ->queue;
    wasm_exec_env_t exec_env;
    wasm_function_inst_t my_shared_heap_malloc_func;
    wasm_function_inst_t my_shared_heap_free_func;
    uint32 i, argv[2];

    /* lookup wasm functions */
    if (!(my_shared_heap_malloc_func = wasm_runtime_lookup_function(
              module_inst, "my_shared_heap_malloc"))
        || !(my_shared_heap_free_func = wasm_runtime_lookup_function(
                 module_inst, "my_shared_heap_free"))) {
        printf("Failed to lookup function.\n");
    }

    /* create exec env */
    if (!(exec_env = wasm_runtime_create_exec_env(module_inst, 32768))) {
        printf("Failed to create exec env.\n");
        return NULL;
    }

    /* allocate memory with wasm_runtime_shared_heap_malloc and send it
       to wasm app2 */
    for (i = 0; i < 5; i++) {
        uint8 *buf;
        uint64 offset;

        offset = wasm_runtime_shared_heap_malloc(module_inst, 1024 * (i + 1),
                                                 (void **)&buf);

        if (offset == 0) {
            printf("Failed to allocate memory from shared heap\n");
            break;
        }

        snprintf(buf, 1024, "Hello, this is buf %u allocated from shared heap",
                 i + 1);

        printf("wasm app1 send buf: %s\n\n", buf);
        if (!bh_post_msg(queue, 1, buf, 1024 * (i + 1))) {
            printf("Failed to post message to queue\n");
            wasm_runtime_shared_heap_free(module_inst, offset);
            break;
        }
    }

    /* allocate memory by calling my_shared_heap_malloc function and send it
       to wasm app2 */
    for (i = 5; i < 10; i++) {
        uint8 *buf;

        argv[0] = 1024 * (i + 1);
        argv[1] = i + 1;
        wasm_runtime_call_wasm(exec_env, my_shared_heap_malloc_func, 2, argv);

        if (wasm_runtime_get_exception(module_inst)) {
            printf("Failed to call 'my_shared_heap_malloc' function: %s\n",
                   wasm_runtime_get_exception(module_inst));
            break;
        }
        if (argv[0] == 0) {
            printf("Failed to allocate memory from shared heap\n");
            break;
        }

        buf = wasm_runtime_addr_app_to_native(module_inst, argv[0]);

        printf("wasm app1 send buf: %s\n\n", buf);
        if (!bh_post_msg(queue, 1, buf, 1024 * (i + 1))) {
            printf("Failed to post message to queue\n");
            wasm_runtime_shared_heap_free(module_inst, argv[0]);
            break;
        }
    }

    wasm_runtime_destroy_exec_env(exec_env);

    return NULL;
}

static void
queue_callback(void *message, void *arg)
{
    bh_message_t msg = (bh_message_t)message;
    wasm_exec_env_t exec_env = arg;
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    wasm_function_inst_t print_buf_func;
    uint32 argv[2];

    /* lookup wasm function */
    if (!(print_buf_func =
              wasm_runtime_lookup_function(module_inst, "print_buf"))) {
        printf("Failed to lookup function.\n");
        return;
    }

    char *buf = bh_message_payload(msg);
    printf("wasm app's native queue received buf: %s\n\n", buf);

    /* call wasm function */
    argv[0] = wasm_runtime_addr_native_to_app(module_inst, buf);
    wasm_runtime_call_wasm(exec_env, print_buf_func, 1, argv);
    if (wasm_runtime_get_exception(module_inst)) {
        printf("Failed to call 'print_buf' function: %s\n",
               wasm_runtime_get_exception(module_inst));
    }
}

static void *
thread2_callback(void *arg)
{
    thread_arg *targ = arg;
    bh_queue *queue = targ->queue;
    wasm_module_inst_t module_inst = targ->module_inst;
    wasm_exec_env_t exec_env;

    /* create exec env */
    if (!(exec_env = wasm_runtime_create_exec_env(module_inst, 32768))) {
        printf("Failed to create exec env.\n");
        return NULL;
    }

    /* enter queue's message loop until bh_queue_exit_loop_run
       is called */
    bh_queue_enter_loop_run(queue, queue_callback, exec_env);

    wasm_runtime_destroy_exec_env(exec_env);

    return NULL;
}

static char global_heap_buf[512 * 1024];

int
main(int argc, char **argv)
{
    char *wasm_file1 = NULL, *wasm_file2 = NULL;
    uint8 *wasm_file1_buf = NULL, *wasm_file2_buf = NULL;
    uint32 wasm_file1_size, wasm_file2_size;
    wasm_module_t wasm_module1 = NULL, wasm_module2 = NULL;
    wasm_module_inst_t module_inst1 = NULL;
    wasm_module_inst_t module_inst2 = NULL;
    wasm_shared_heap_t shared_heap = NULL;
    bh_queue *queue = NULL;
    RuntimeInitArgs init_args;
    SharedHeapInitArgs heap_init_args;
    char error_buf[128] = { 0 };
    bool aot_mode = false;
    int ret = -1;

    if (argc > 1 && !strcmp(argv[1], "--aot"))
        aot_mode = true;

    if (!aot_mode)
        printf("Test shared heap in interpreter mode\n\n");
    else
        printf("Test shared heap in AOT mode\n\n");

    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

    /* init wasm runtime */
    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

    /* create queue */
    if (!(queue = bh_queue_create())) {
        printf("Create queue failed.\n");
        goto fail;
    }

    /* read wasm file */
    if (!aot_mode)
        wasm_file1 = "./wasm-apps/test1.wasm";
    else
        wasm_file1 = "./wasm-apps/test1.aot";
    if (!(wasm_file1_buf =
              bh_read_file_to_buffer(wasm_file1, &wasm_file1_size))) {
        printf("Open wasm file %s failed.\n", wasm_file1);
        goto fail;
    }

    /* load wasm file */
    wasm_module1 = wasm_runtime_load((uint8 *)wasm_file1_buf, wasm_file1_size,
                                     error_buf, sizeof(error_buf));
    if (!wasm_module1) {
        printf("Load wasm module failed. error: %s\n", error_buf);
        goto fail;
    }

    /* instantiate module */
    module_inst1 = wasm_runtime_instantiate(wasm_module1, 65536, 0, error_buf,
                                            sizeof(error_buf));
    if (!module_inst1) {
        printf("Instantiate wasm module failed. error: %s\n", error_buf);
        goto fail;
    }

    /* read wasm file */
    if (!aot_mode)
        wasm_file2 = "./wasm-apps/test2.wasm";
    else
        wasm_file2 = "./wasm-apps/test2.aot";
    if (!(wasm_file2_buf =
              bh_read_file_to_buffer(wasm_file2, &wasm_file2_size))) {
        printf("Open wasm file %s failed.\n", wasm_file1);
        goto fail;
    }

    /* load wasm file */
    wasm_module2 = wasm_runtime_load((uint8 *)wasm_file2_buf, wasm_file2_size,
                                     error_buf, sizeof(error_buf));
    if (!wasm_module2) {
        printf("Load wasm module failed. error: %s\n", error_buf);
        goto fail;
    }

    /* instantiate module */
    module_inst2 = wasm_runtime_instantiate(wasm_module2, 65536, 0, error_buf,
                                            sizeof(error_buf));
    if (!module_inst2) {
        printf("Instantiate wasm module failed. error: %s\n", error_buf);
        goto fail;
    }

    /* create shared heap */
    memset(&heap_init_args, 0, sizeof(heap_init_args));
    heap_init_args.size = 65536;
    shared_heap = wasm_runtime_create_shared_heap(&heap_init_args);
    if (!shared_heap) {
        printf("Create shared heap failed.\n");
        goto fail;
    }

    /* attach module instance 1 to the shared heap */
    if (!wasm_runtime_attach_shared_heap(module_inst1, shared_heap)) {
        printf("Attach shared heap failed.\n");
        goto fail;
    }

    /* attach module instance 2 to the shared heap */
    if (!wasm_runtime_attach_shared_heap(module_inst2, shared_heap)) {
        printf("Attach shared heap failed.\n");
        goto fail;
    }

    /* create thread 1 */
    thread_arg targ1 = { 0 };
    korp_tid tid1;
    targ1.queue = queue;
    targ1.module_inst = module_inst1;
    if (os_thread_create(&tid1, thread1_callback, &targ1,
                         APP_THREAD_STACK_SIZE_DEFAULT)) {
        printf("Failed to create thread 1\n");
        goto fail;
    }

    /* create thread 2 */
    thread_arg targ2 = { 0 };
    korp_tid tid2;
    targ2.queue = queue;
    targ2.module_inst = module_inst2;
    if (os_thread_create(&tid2, thread2_callback, &targ2,
                         APP_THREAD_STACK_SIZE_DEFAULT)) {
        printf("Failed to create thread 2\n");
        os_thread_join(tid1, NULL);
        goto fail;
    }

    /* wait until all messages are post to wasm app2 and wasm app2
       handles all of them, then exit the queue message loop */
    usleep(10000);
    bh_queue_exit_loop_run(queue);

    os_thread_join(tid1, NULL);
    os_thread_join(tid2, NULL);

    ret = 0;

fail:
    if (module_inst2)
        wasm_runtime_deinstantiate(module_inst2);

    if (module_inst1)
        wasm_runtime_deinstantiate(module_inst1);

    if (wasm_module2)
        wasm_runtime_unload(wasm_module2);

    if (wasm_module1)
        wasm_runtime_unload(wasm_module1);

    if (wasm_file2_buf)
        wasm_runtime_free(wasm_file2_buf);

    if (wasm_file1_buf)
        wasm_runtime_free(wasm_file1_buf);

    if (queue)
        bh_queue_destroy(queue);

    wasm_runtime_destroy();

    return ret;
}
