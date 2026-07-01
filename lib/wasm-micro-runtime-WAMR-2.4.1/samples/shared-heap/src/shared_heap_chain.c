/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_export.h"
#include "bh_platform.h"
#include "bh_read_file.h"

#define BUF_SIZE 4096
static char preallocated_buf[BUF_SIZE];

static bool
produce_data(wasm_module_inst_t module_inst, wasm_exec_env_t exec_env,
             bh_queue *queue, wasm_function_inst_t func, uint32 *argv,
             uint32 buf_size, bool free_on_fail)
{
    uint8 *buf;

    wasm_runtime_call_wasm(exec_env, func, 2, argv);

    if (wasm_runtime_get_exception(module_inst)) {
        printf("Failed to call function: %s\n",
               wasm_runtime_get_exception(module_inst));
        return false;
    }
    if (argv[0] == 0) {
        printf("Failed to allocate memory from shared heap\n");
        return false;
    }

    buf = wasm_runtime_addr_app_to_native(module_inst, argv[0]);
    printf("wasm app1 send buf: %s\n\n", buf);

    /* Passes wasm address directly between wasm apps since memory in shared
     * heap chain is viewed as single address space in wasm's perspective */
    buf = (uint8 *)(uintptr_t)argv[0];
    if (!bh_post_msg(queue, 1, buf, buf_size)) {
        printf("Failed to post message to queue\n");
        if (free_on_fail)
            wasm_runtime_shared_heap_free(module_inst, argv[0]);
        return false;
    }

    return true;
}

static void *
wasm_producer(wasm_module_inst_t module_inst, bh_queue *queue)
{
    wasm_exec_env_t exec_env;
    wasm_function_inst_t my_shared_heap_malloc_func, my_shared_heap_free_func,
        produce_str_func;
    uint32 i, argv[2];

    /* lookup wasm functions */
    if (!(my_shared_heap_malloc_func = wasm_runtime_lookup_function(
              module_inst, "my_shared_heap_malloc"))
        || !(my_shared_heap_free_func = wasm_runtime_lookup_function(
                 module_inst, "my_shared_heap_free"))
        || !(produce_str_func =
                 wasm_runtime_lookup_function(module_inst, "produce_str"))) {
        printf("Failed to lookup function.\n");
    }

    /* create exec env */
    if (!(exec_env = wasm_runtime_create_exec_env(module_inst, 32768))) {
        printf("Failed to create exec env.\n");
        return NULL;
    }

    /* allocate memory by calling my_shared_heap_malloc function and send it
       to wasm app2 */
    for (i = 0; i < 8; i++) {
        argv[0] = 1024 * (i + 1);
        argv[1] = i + 1;
        if (!produce_data(module_inst, exec_env, queue,
                          my_shared_heap_malloc_func, argv, 1024 * (i + 1),
                          true)) {
            break;
        }
    }

    /* use pre-allocated shared heap memory by calling produce_str function and
       send it to wasm app2, the pre-allocated shared heap is the last one in
       chain, so its end address is calculated from UIN32_MAX */
    uint32 wasm_start_addr = UINT32_MAX - BUF_SIZE + 1;
    for (i = 8; i < 16; i++) {
        argv[0] = wasm_start_addr + 512 * (i - 8);
        argv[1] = i + 1;
        if (!produce_data(module_inst, exec_env, queue, produce_str_func, argv,
                          512, false)) {
            break;
        }
    }

    wasm_runtime_destroy_exec_env(exec_env);

    return NULL;
}

static void
wasm_consumer(wasm_module_inst_t module_inst, bh_queue *queue)
{
    wasm_function_inst_t print_buf_func, consume_str_func;
    wasm_exec_env_t exec_env;
    uint32 argv[2], i;
    bh_message_t msg;
    char *buf;

    /* lookup wasm function */
    if (!(print_buf_func =
              wasm_runtime_lookup_function(module_inst, "print_buf"))
        || !(consume_str_func =
                 wasm_runtime_lookup_function(module_inst, "consume_str"))) {
        printf("Failed to lookup function.\n");
        return;
    }

    /* create exec env */
    if (!(exec_env = wasm_runtime_create_exec_env(module_inst, 32768))) {
        printf("Failed to create exec env.\n");
        return;
    }

    for (i = 0; i < 16; i++) {
        msg = bh_get_msg(queue, BHT_WAIT_FOREVER);
        if (!msg)
            return;
        buf = bh_message_payload(msg);

        /* call wasm function */
        argv[0] = (uint32)(uintptr_t)buf;
        if (i < 8)
            wasm_runtime_call_wasm(exec_env, print_buf_func, 1, argv);
        else
            wasm_runtime_call_wasm(exec_env, consume_str_func, 1, argv);

        if (wasm_runtime_get_exception(module_inst)) {
            printf(
                "Failed to call 'print_buf' or 'consumer_str' function: %s\n",
                wasm_runtime_get_exception(module_inst));
        }

        bh_free_msg(msg);
    }

    wasm_runtime_destroy_exec_env(exec_env);
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
    wasm_shared_heap_t shared_heap = NULL, shared_heap2 = NULL,
                       shared_heap_chain = NULL;
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
        wasm_file1 = "./wasm-apps/test1_chain.aot";
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
        wasm_file2 = "./wasm-apps/test2_chain.aot";
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

    /* create a preallocated shared heap */
    memset(&heap_init_args, 0, sizeof(heap_init_args));
    heap_init_args.pre_allocated_addr = preallocated_buf;
    heap_init_args.size = BUF_SIZE;
    shared_heap2 = wasm_runtime_create_shared_heap(&heap_init_args);
    if (!shared_heap2) {
        printf("Create preallocated shared heap failed\n");
        goto fail;
    }

    shared_heap_chain =
        wasm_runtime_chain_shared_heaps(shared_heap, shared_heap2);
    if (!shared_heap_chain) {
        printf("Create shared heap chain failed\n");
        goto fail;
    }

    /* attach module instance 1 to the shared heap */
    if (!wasm_runtime_attach_shared_heap(module_inst1, shared_heap_chain)) {
        printf("Attach shared heap failed.\n");
        goto fail;
    }

    /* attach module instance 2 to the shared heap */
    if (!wasm_runtime_attach_shared_heap(module_inst2, shared_heap_chain)) {
        printf("Attach shared heap failed.\n");
        goto fail;
    }

    /* wasm 1 produce shared data */
    wasm_producer(module_inst1, queue);

    /* wasm 2 consume shared data */
    wasm_consumer(module_inst2, queue);
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
