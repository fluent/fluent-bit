/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wasm_c_api.h"

#define WORKER_NUMBER 10

/******************************* VM *******************************/
/* Use wasm_vm_t and vm_xxx to simulate a minimal Wasm VM in Envoy */

typedef struct _vm {
    wasm_engine_t *engine;
    wasm_store_t *store;
    wasm_module_t *module;
    wasm_shared_module_t *shared_module;
    wasm_instance_t *instance;
    wasm_func_t **function_list;
    wasm_memory_t *memory;
    wasm_table_t *table;
    wasm_extern_vec_t *exports;
} wasm_vm_t;

typedef enum _clone_level {
    not_cloneable = 0,
    compiled_bytecode,
    instantiated_module
} clone_level;

typedef struct _thread_arg_t {
    char name[32];
    bool *ready_go_flag;
    pthread_mutex_t *ready_go_lock;
    pthread_cond_t *ready_go_cond;
    const wasm_vm_t *base_vm;
} thread_arg_t;

wasm_vm_t *
vm_new()
{
    wasm_vm_t *vm = NULL;

    vm = malloc(sizeof(struct _vm));
    if (!vm)
        goto fail;

    memset(vm, 0, sizeof(wasm_vm_t));

    vm->engine = wasm_engine_new();
    if (!vm->engine)
        goto fail;

    vm->store = wasm_store_new(vm->engine);
    if (!vm->store)
        goto fail;

    return vm;

fail:
    if (vm) {
        if (vm->engine)
            wasm_engine_delete(vm->engine);

        free(vm);
    }
    return NULL;
}

wasm_vm_t *
vm_release(wasm_vm_t *vm)
{
    if (!vm)
        return NULL;

    if (vm->function_list) {
        free(vm->function_list);
        vm->function_list = NULL;
    }

    vm->memory = NULL;

    if (vm->exports) {
        wasm_extern_vec_delete(vm->exports);
        free(vm->exports);
        vm->exports = NULL;
    }

    wasm_instance_delete(vm->instance);
    vm->instance = NULL;

    wasm_shared_module_delete(vm->shared_module);
    vm->shared_module = NULL;

    wasm_module_delete(vm->module);
    vm->module = NULL;

    wasm_store_delete(vm->store);
    vm->store = NULL;

    wasm_engine_delete(vm->engine);
    vm->engine = NULL;

    free(vm);
    return NULL;
}

bool
vm_load(wasm_vm_t *vm, const wasm_byte_vec_t *binary)
{
    vm->module = wasm_module_new(vm->store, binary);
    vm->shared_module = wasm_module_share(vm->module);
    return vm->module != NULL;
}

bool
vm_link(wasm_vm_t *vm, wasm_extern_vec_t *imports)
{
    vm->instance = wasm_instance_new(vm->store, vm->module, imports, NULL);
    if (!vm->instance)
        goto fail;

    vm->exports = malloc(sizeof(wasm_extern_vec_t));
    if (!vm->exports)
        goto fail;

    memset(vm->exports, 0, sizeof(wasm_extern_vec_t));
    wasm_instance_exports(vm->instance, vm->exports);
    /* an exported memory, and two exported functions */
    assert(vm->exports->size == 3);

    /* bind memory */
    assert(wasm_extern_kind(vm->exports->data[0]) == WASM_EXTERN_MEMORY);
    vm->memory = wasm_extern_as_memory(vm->exports->data[0]);

    vm->function_list = malloc(2 * sizeof(wasm_func_t *));
    if (!vm->function_list)
        goto fail;

    memset(vm->function_list, 0, 2 * sizeof(wasm_func_t *));

    /* bind wasm_set_byte(...) */
    assert(wasm_extern_kind(vm->exports->data[1]) == WASM_EXTERN_FUNC);
    vm->function_list[0] = wasm_extern_as_func(vm->exports->data[1]);

    /* bind wasm_get_byte(...) */
    assert(wasm_extern_kind(vm->exports->data[2]) == WASM_EXTERN_FUNC);
    vm->function_list[1] = wasm_extern_as_func(vm->exports->data[2]);

    return true;
fail:
    return false;
}

wasm_vm_t *
vm_clone_from_module(const wasm_vm_t *base)
{
    printf("Initializing...\n");
    wasm_vm_t *secondary = NULL;

    secondary = vm_new();
    if (secondary) {
        printf("Reuse module and bypass vm_load()...");
        secondary->module =
            wasm_module_obtain(base->store, base->shared_module);
        if (!secondary->module)
            secondary = vm_release(secondary);
    }

    return secondary;
}

wasm_vm_t *
vm_clone_from_instance(const wasm_vm_t *base)
{
    /**
     * if do a clone of the level instantiated_module, need to malloc and
     * initialize
     *   - global. WASMGlobalInstance and global data
     *   - memory. WASMMemoryInstance, memory_data and heap
     *   - table. WASMTableInstance, table_data
     *   - exports. all global, memory and table
     *
     * it is almost everything in wasm_instantiate() except function.
     */
    (void)base;
    printf("Unsupported\n");
    return NULL;
}

wasm_vm_t *
vm_clone(const wasm_vm_t *base, clone_level level)
{
    if (level == not_cloneable)
        return NULL;

    if (level == compiled_bytecode)
        return vm_clone_from_module(base);
    else
        return vm_clone_from_instance(base);
}

bool
vm_memory_set_byte(const wasm_vm_t *vm, uint32_t offset, uint8_t byte)
{
    byte_t *data = wasm_memory_data(vm->memory);
    assert(data);
    *(data + offset) = byte;
    return true;
}

bool
vm_memory_get_byte(const wasm_vm_t *vm, uint32_t offset, uint8_t *byte)
{
    byte_t *data = wasm_memory_data(vm->memory);
    assert(data);
    *byte = *(data + offset);
    return true;
}

bool
vm_function_set_byte(const wasm_vm_t *vm, uint32_t offset, uint8_t byte)
{
    wasm_val_t a_v[2] = { WASM_I32_VAL(offset), WASM_I32_VAL(byte) };
    wasm_val_vec_t args = WASM_ARRAY_VEC(a_v);
    wasm_val_vec_t results = WASM_EMPTY_VEC;
    wasm_trap_t *trap = wasm_func_call(vm->function_list[0], &args, &results);
    if (trap) {
        printf("call wasm_set_byte failed");
        wasm_trap_delete(trap);
        return false;
    }

    return true;
}

bool
vm_function_get_byte(const wasm_vm_t *vm, uint32_t offset, uint8_t *byte)
{
    wasm_val_t a_v[1] = { WASM_I32_VAL(offset) };
    wasm_val_vec_t args = WASM_ARRAY_VEC(a_v);
    wasm_val_t r_v[1] = { WASM_INIT_VAL };
    wasm_val_vec_t results = WASM_ARRAY_VEC(r_v);
    wasm_trap_t *trap = wasm_func_call(vm->function_list[1], &args, &results);
    if (trap) {
        printf("call wasm_get_byte failed");
        wasm_trap_delete(trap);
        return false;
    }

    assert(results.data->kind == WASM_I32);
    *byte = results.data->of.i32;
    return true;
}

static bool
load_wasm_file_content(const char *file_name, wasm_byte_vec_t *out)
{
    bool ret = false;
#if WASM_ENABLE_AOT != 0 && WASM_ENABLE_INTERP == 0
    FILE *file = fopen(file_name, "rb");
#else
    FILE *file = fopen(file_name, "rb");
#endif
    if (!file) {
        printf("> Error loading .wasm!\n");
        goto quit;
    }

    int offset = fseek(file, 0L, SEEK_END);
    if (offset == -1) {
        printf("> Error loading .wasm!\n");
        goto close_file;
    }

    long file_size = ftell(file);
    if (file_size == -1) {
        printf("> Error loading .wasm!\n");
        goto close_file;
    }

    offset = fseek(file, 0L, SEEK_SET);
    if (offset == -1) {
        printf("> Error loading .wasm!\n");
        goto close_file;
    }

    wasm_byte_vec_new_uninitialized(out, file_size);
    if (fread(out->data, file_size, 1, file) != 1) {
        printf("> Error loading content!\n");
        goto close_file;
    }

    ret = true;
close_file:
    fclose(file);
quit:
    return ret;
}

static pthread_key_t name_key;

wasm_trap_t *
report_cb(const wasm_val_vec_t *args, wasm_val_vec_t *results)
{
    (void)results;

    assert(args->data[0].kind == WASM_I32);
    uint32_t chk_pnt_no = args->data[0].of.i32;

    char *name = pthread_getspecific(name_key);
    printf("[%s] Pass CHK POINT #%u\n", name, chk_pnt_no);

    return NULL;
}

bool
run_code_start(wasm_vm_t **out)
{
    bool ret = false;

    printf("Initializing...\n");
    wasm_vm_t *vm = vm_new();
    if (!vm)
        goto fail;

    printf("Loading binary...\n");
    wasm_byte_vec_t binary = { 0 };
#if WASM_ENABLE_AOT != 0 && WASM_ENABLE_INTERP == 0
    const char *file_name = "clone.aot";
#else
    const char *file_name = "clone.wasm";
#endif
    if (!load_wasm_file_content(file_name, &binary))
        goto release_vm;

    printf("Compiling module...\n");
    ret = vm_load(vm, &binary);
    wasm_byte_vec_delete(&binary);
    if (!ret)
        goto release_vm;

    printf("Creating callback...\n");
    wasm_functype_t *callback_type =
        wasm_functype_new_1_0(wasm_valtype_new_i32());
    if (!callback_type)
        goto release_vm;

    wasm_func_t *callback = wasm_func_new(vm->store, callback_type, report_cb);
    wasm_functype_delete(callback_type);
    if (!callback)
        goto release_vm;

    printf("Instantiating module...\n");
    wasm_extern_t *externs[] = { wasm_func_as_extern(callback) };
    wasm_extern_vec_t imports = WASM_ARRAY_VEC(externs);
    ret = vm_link(vm, &imports);
    wasm_func_delete(callback);
    if (!ret)
        goto release_vm;

    *out = vm;
    return true;

release_vm:
    vm_release(vm);
fail:
    return false;
}

bool
run_warm_start_w_compiled_bytecode(const wasm_vm_t *first, wasm_vm_t **out)
{
    bool ret;
    wasm_vm_t *secondary = vm_clone(first, compiled_bytecode);
    if (!secondary)
        goto fail;

    printf("Creating callback...\n");
    wasm_functype_t *callback_type =
        wasm_functype_new_1_0(wasm_valtype_new_i32());
    if (!callback_type)
        goto release_vm;

    wasm_func_t *callback =
        wasm_func_new(secondary->store, callback_type, report_cb);
    wasm_functype_delete(callback_type);
    if (!callback)
        goto release_vm;

    printf("Instantiating module...\n");
    wasm_extern_t *externs[] = { wasm_func_as_extern(callback) };
    wasm_extern_vec_t imports = WASM_ARRAY_VEC(externs);
    ret = vm_link(secondary, &imports);
    wasm_func_delete(callback);
    if (!ret)
        goto release_vm;

    *out = secondary;
    return true;

release_vm:
    vm_release(secondary);
fail:
    return false;
}

bool
run_warm_start_w_instantiated_module(const wasm_vm_t *first, wasm_vm_t **out)
{
    wasm_vm_t *secondary = vm_clone(first, instantiated_module);
    if (!secondary)
        return false;

    *out = secondary;
    return true;
}

void
run_test(const wasm_vm_t *vm)
{
    uint8_t byte = 0xFF;

    /* read initialization */
    vm_function_get_byte(vm, 10, &byte);
    assert(byte == 0x0);
    vm_memory_get_byte(vm, 10, &byte);
    assert(byte == 0x0);

    /* read after writing */
    vm_function_set_byte(vm, 16, 0xab);
    vm_function_get_byte(vm, 16, &byte);
    assert(byte == 0xab);

    vm_memory_set_byte(vm, 16, 0xcd);
    vm_memory_get_byte(vm, 16, &byte);
    assert(byte == 0xcd);

    /* reading and writing across */
    vm_function_set_byte(vm, 16, 0xef);
    vm_memory_get_byte(vm, 16, &byte);
    assert(byte == 0xef);

    vm_memory_set_byte(vm, 16, 0x67);
    vm_function_get_byte(vm, 16, &byte);
    assert(byte == 0x67);

    printf("All Passed ...\n");
}

static void *
thrd_func(void *arg)
{
    thread_arg_t *thrd_arg = (thread_arg_t *)arg;

    sleep(rand() % 5);
    printf("Running warm start at %s...\n", thrd_arg->name);

    pthread_setspecific(name_key, thrd_arg->name);

    wasm_vm_t *vm;
    if (!run_warm_start_w_compiled_bytecode(thrd_arg->base_vm, &vm))
        return NULL;

    pthread_mutex_trylock(thrd_arg->ready_go_lock);
    while (!(*thrd_arg->ready_go_flag)) {
        pthread_cond_wait(thrd_arg->ready_go_cond, thrd_arg->ready_go_lock);
    }
    pthread_mutex_unlock(thrd_arg->ready_go_lock);

    printf("Running test at %s...\n", thrd_arg->name);
    run_test(vm);

    vm_release(vm);
    pthread_exit(NULL);
    return NULL;
}

int
main()
{
    int ret = EXIT_FAILURE;
    bool ready_go_flag = false;
    pthread_mutex_t ready_go_lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t ready_go_cond = PTHREAD_COND_INITIALIZER;
    pthread_key_create(&name_key, NULL);
    pthread_setspecific(name_key, "Execution Thread");

    printf("Running cold start at the execution thread...\n");
    wasm_vm_t *base_vm;
    if (!run_code_start(&base_vm))
        goto quit;
    run_test(base_vm);

    printf("Running warm start at other threads...\n");

    pthread_t tids[WORKER_NUMBER] = { 0 };
    thread_arg_t thrd_args[WORKER_NUMBER] = { 0 };
    for (size_t i = 0; i < sizeof(tids) / sizeof(tids[0]); i++) {
        thread_arg_t *thrd_arg = thrd_args + i;

        snprintf(thrd_arg->name, 32, "Worker#%lu", i);
        thrd_arg->ready_go_cond = &ready_go_cond;
        thrd_arg->ready_go_lock = &ready_go_lock;
        thrd_arg->ready_go_flag = &ready_go_flag;
        thrd_arg->base_vm = base_vm;

        int ret = pthread_create(&tids[i], NULL, thrd_func, thrd_arg);
        if (ret != 0)
            break;
    }

    sleep(1);
    pthread_mutex_trylock(&ready_go_lock);
    ready_go_flag = true;
    pthread_mutex_unlock(&ready_go_lock);
    pthread_cond_broadcast(&ready_go_cond);

    sleep(3);
    for (size_t i = 0; i < sizeof(tids) / sizeof(tids[0]); i++) {
        if (tids[i] != 0)
            pthread_join(tids[i], NULL);
    }

    vm_release(base_vm);
    ret = EXIT_SUCCESS;
quit:
    return ret;
}
