/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wasm_c_api.h"

#define own

/* return a copy of the file stem of a file path */
static own char *
stem(const char *file_path)
{
    char *base_name = basename(file_path);
    char *s = strdup(base_name);
    char *dot = strchr(s, '.');
    assert(dot);
    *dot = '\0';
    return s;
}

static void
guest_i32_to_wasm_i32_array(int *args, unsigned argc, wasm_val_t *data,
                            unsigned datac)
{
    for (unsigned i = 0; i < argc && i < datac; i++) {
        memset(&data[i], 0, sizeof(wasm_val_t));
        data[i].kind = WASM_I32;
        data[i].of.i32 = args[i];
    }
}

int
load_run_wasm_file(wasm_engine_t *engine, const char *file_path, int *args,
                   unsigned argc)
{
    wasm_store_t *store = wasm_store_new(engine);
    // Load binary.
    printf("Loading binary...\n");
    FILE *file = fopen(file_path, "rb");
    assert(file);

    int ret = fseek(file, 0L, SEEK_END);
    assert(ret == 0);

    long file_size = ftell(file);
    assert(file_size != -1);

    ret = fseek(file, 0L, SEEK_SET);
    assert(ret == 0);

    wasm_byte_vec_t binary = { 0 };
    wasm_byte_vec_new_uninitialized(&binary, file_size);

    size_t nread = fread(binary.data, file_size, 1, file);
    fclose(file);

    // Compile.
    printf("Compiling module...\n");

    // Use its file name as the module name
    char *file_name = stem(file_path);
    assert(file_name);

    LoadArgs load_args = { 0 };
    load_args.name = file_name;
    own wasm_module_t *module = wasm_module_new_ex(store, &binary, &load_args);
    wasm_byte_vec_delete(&binary);
    assert(module);

    // Use export type to find the function index to call later
    wasm_exporttype_vec_t export_types = { 0 };
    wasm_module_exports(module, &export_types);
    int func_to_call = -1;
    for (unsigned i = 0; i < export_types.num_elems; i++) {
        const wasm_name_t *name = wasm_exporttype_name(export_types.data[i]);
        if (strncmp(name->data, "run", 3) == 0) {
            func_to_call = i;
            break;
        }
    }
    assert(func_to_call != -1);

    // Instantiate.
    printf("Instantiating module...\n");
    wasm_extern_vec_t imports = WASM_EMPTY_VEC;
    own wasm_instance_t *instance = wasm_instance_new_with_args(
        store, module, &imports, NULL, 16 * 1024 * 1024, 1 * 1024 * 1024);
    assert(instance);

    // Extract export.
    printf("Extracting export...\n");
    own wasm_extern_vec_t exports;
    wasm_instance_exports(instance, &exports);
    assert(exports.size);

    assert(wasm_extern_kind(exports.data[func_to_call]) == WASM_EXTERN_FUNC);
    const wasm_func_t *run_func =
        wasm_extern_as_func(exports.data[func_to_call]);
    assert(run_func);

    wasm_module_delete(module);
    wasm_instance_delete(instance);

    // Call.
    printf("Calling export...\n");
    wasm_val_t as[4] = { 0 };
    guest_i32_to_wasm_i32_array(args, argc, as, 4);

    wasm_val_vec_t params = WASM_ARRAY_VEC(as);
    wasm_val_t rs[1] = { WASM_I32_VAL(0) };
    wasm_val_vec_t results = WASM_ARRAY_VEC(rs);
    wasm_trap_t *trap = wasm_func_call(run_func, &params, &results);
    assert(!trap);

    wasm_extern_vec_delete(&exports);
    free(file_name);
    wasm_store_delete(store);

    {
        nread = nread;
        ret = ret;
        trap = trap;
    }
    return 0;
}

void *
load_run_fib_wasm(void *arg)
{
    wasm_engine_t *engine = (wasm_engine_t *)arg;
    int args[] = { 40 };
    load_run_wasm_file(engine, "./fib1.wasm", args, 1);
    return NULL;
}

void *
load_run_fib_aot(void *arg)
{
    wasm_engine_t *engine = (wasm_engine_t *)arg;
    int args[] = { 40 };
    load_run_wasm_file(engine, "./fib2.aot", args, 1);
    return NULL;
}

void *
load_run_ackermann_wasm(void *arg)
{
    wasm_engine_t *engine = (wasm_engine_t *)arg;
    int args[] = { 3, 12 };
    load_run_wasm_file(engine, "./ackermann1.wasm", args, 2);
    return NULL;
}

void *
load_run_ackermann_aot(void *arg)
{
    wasm_engine_t *engine = (wasm_engine_t *)arg;
    int args[] = { 3, 12 };
    load_run_wasm_file(engine, "./ackermann2.aot", args, 2);
    return NULL;
}

int
main(int argc, const char *argv[])
{
    // Initialize.
    printf("Initializing...\n");
    wasm_config_t *config = wasm_config_new();
    wasm_config_set_linux_perf_opt(config, true);
    wasm_engine_t *engine = wasm_engine_new_with_config(config);

    pthread_t tid[4] = { 0 };
    /* FIXME: uncomment when it is able to run two modules with llvm-jit */
    // pthread_create(&tid[0], NULL, load_run_fib_wasm, (void *)engine);
    // pthread_create(&tid[2], NULL, load_run_ackermann_wasm, (void *)engine);

    pthread_create(&tid[1], NULL, load_run_fib_aot, (void *)engine);
    pthread_create(&tid[3], NULL, load_run_ackermann_aot, (void *)engine);

    for (unsigned i = 0; i < sizeof(tid) / sizeof(tid[0]); i++)
        pthread_join(tid[i], NULL);

    // Shut down.
    printf("Shutting down...\n");
    wasm_engine_delete(engine);

    // All done.
    printf("Done.\n");
    return 0;
}
