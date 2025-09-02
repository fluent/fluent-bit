/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * Copyright (C) 2020 TU Bergakademie Freiberg Karl Fessel
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <string.h>

#include "wasm_export.h"

#include <thread.h>

/* provide some test program */
#include "test_wasm.h"

#define DEFAULT_THREAD_STACKSIZE (6 * 1024)
#define DEFAULT_THREAD_PRIORITY 50

static int app_argc;
static char **app_argv;

static void *
app_instance_main(wasm_module_inst_t module_inst)
{
    const char *exception;

    wasm_application_execute_main(module_inst, app_argc, app_argv);
    if ((exception = wasm_runtime_get_exception(module_inst))) {
        puts(exception);
    }
    return NULL;
}

void *
iwasm_t(void *arg1)
{
    wasm_module_t wasm_module = (wasm_module_t)arg1;
    wasm_module_inst_t wasm_module_inst = NULL;
    char error_buf[128];

    /* instantiate the module */
    if (!(wasm_module_inst = wasm_runtime_instantiate(
              wasm_module, 8 * 1024, 8 * 1024, error_buf, sizeof(error_buf)))) {
        puts(error_buf);
    }
    else {
        app_instance_main(wasm_module_inst);
        /* destroy the module instance */
        wasm_runtime_deinstantiate(wasm_module_inst);
    }
    return NULL;
}

/* enable FUNC_ALLOC to use custom memory allocation functions */
#define FUNC_ALLOC

void *
iwasm_main(void *arg1)
{
    (void)arg1; /* unused */
    uint8_t *wasm_file_buf = NULL;
    unsigned wasm_file_buf_size = 0;
    wasm_module_t wasm_module = NULL;
    char error_buf[128];

    RuntimeInitArgs init_args;

    memset(&init_args, 0, sizeof(RuntimeInitArgs));
#if defined(FUNC_ALLOC) && WASM_ENABLE_GLOBAL_HEAP_POOL == 0
    init_args.mem_alloc_type = Alloc_With_Allocator;
    init_args.mem_alloc_option.allocator.malloc_func = malloc;
    init_args.mem_alloc_option.allocator.realloc_func = realloc;
    init_args.mem_alloc_option.allocator.free_func = free;
#elif WASM_ENABLE_GLOBAL_HEAP_POOL != 0
    static char global_heap_buf[WASM_GLOBAL_HEAP_SIZE] = { 0 };

    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);
#else
    init_args.mem_alloc_type = Alloc_With_System_Allocator;
#endif

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        puts("Init runtime environment failed.");
        return NULL;
    }

    /* load WASM byte buffer from byte buffer of include file */
    wasm_file_buf = (uint8_t *)wasm_test_file;
    wasm_file_buf_size = sizeof(wasm_test_file);

    /* load WASM module */
    if (!(wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_buf_size,
                                          error_buf, sizeof(error_buf)))) {
        puts(error_buf);
    }
    else {
        iwasm_t(wasm_module);
        wasm_runtime_unload(wasm_module);
    }

    wasm_runtime_destroy();
    return NULL;
}

bool
iwasm_init(void)
{
    /* clang-format off */
    struct {
        char *stack;
        int stacksize;
        uint8_t priority;
        int flags;
        thread_task_func_t task_func;
        void *arg;
        const char *name;
    } b = {
        .stacksize = DEFAULT_THREAD_STACKSIZE,
        .priority = 8,
        .flags = 0,
        .task_func = iwasm_main,
        .arg = NULL,
        .name = "simple_wamr"
    };
    /* clang-format on */

    b.stack = malloc(b.stacksize);
    kernel_pid_t tpid = thread_create(b.stack, b.stacksize, b.priority, b.flags,
                                      b.task_func, b.arg, b.name);

    return tpid != 0 ? true : false;
    ;
}

#define telltruth(X) ((X) ? "true" : "false")

int
main(void)
{
    printf("iwasm_initilised: %s\n", telltruth(iwasm_init()));
}
