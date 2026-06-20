/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "wasm_c_api.h"

#define own

static const byte_t *
get_memory_data(uint32_t offset, uint32_t length);

static bool
call_wasm_function(uint32_t export_id, const wasm_val_vec_t *args,
                   wasm_val_vec_t *results, const char *name);

/************************ IMPORTED FUNCTIONS **************************/

// (nil) -> i32
#define FUNCTION_TYPE_NIL_I32 wasm_functype_new_0_1(wasm_valtype_new_i32())
// (i32, i32) -> nil
#define FUNCTION_TYPE_I32X2_NIL \
    wasm_functype_new_2_0(wasm_valtype_new_i32(), wasm_valtype_new_i32())

/* IMPORT FUNCTION LIST */
#define IMPORT_FUNCTION_LIST(V)            \
    V(get_pairs, 0, FUNCTION_TYPE_NIL_I32) \
    V(log, 1, FUNCTION_TYPE_I32X2_NIL)

/* EXPORT FUNCTION LIST */
#define EXPORT_FUNCTION_LIST(V) \
    V(on_start)                 \
    V(on_stop)                  \
    V(malloc)                   \
    V(free)

enum EXPORT_ITEM_NAME {
#define DEFINE_ENUM(name) e_##name,
    EXPORT_FUNCTION_LIST(DEFINE_ENUM)
#undef DEFINE_ENUM
        e_MEMORY,
};

#define DEFINE_FUNCTION(name)                            \
    wasm_trap_t *STUB_##name(const wasm_val_vec_t *args, \
                             wasm_val_vec_t *results)

#define DEFINE_EMPTY_FUNCTION(name)                                 \
    DEFINE_FUNCTION(name)                                           \
    {                                                               \
        printf("[WASM -> NATIVE] calling back %s\n", __FUNCTION__); \
        return NULL;                                                \
    }
#undef DEFINE_EMPTY_FUNCTION

DEFINE_FUNCTION(get_pairs)
{
    wasm_val_vec_t as = { 0 };
    wasm_val_t data[1] = { WASM_I32_VAL(10) };
    wasm_val_vec_new(&as, 1, data);
    if (as.data == NULL) {
        printf("ERROR: create parameters failed\n");
        return NULL;
    }

    call_wasm_function(e_malloc, &as, results, "malloc");

    wasm_val_vec_delete(&as);
    return NULL;
}

DEFINE_FUNCTION(log)
{
    wasm_val_t offset = args->data[0];
    wasm_val_t length = args->data[1];
    const byte_t *data = NULL;

    printf("[WASM -> NATIVE] calling back %s\n", __FUNCTION__);

    if (offset.kind != WASM_I32 || length.kind != WASM_I32) {
        printf("> Error value type!\n");
    }

    if (!(data = get_memory_data(offset.of.i32, length.of.i32))) {
        return NULL;
    }

    if (data[length.of.i32 - 1]) {
        printf("> Error terminated character\n");
        return NULL;
    }

    printf("[WASM_LOG] %s\n", data);
    return NULL;
}

/**********************************************************************/
// all exportted wasm functions. check with "/opt/wabt/bin/wasm-objdump -x -j
// Export X.wasm" -1: memory 0-32: functions
static own wasm_extern_vec_t exports = { 0 };

static const byte_t *
get_memory_data(uint32_t offset, uint32_t length)
{
    wasm_memory_t *memory;

    if (!(memory = wasm_extern_as_memory(exports.data[e_MEMORY]))) {
        return NULL;
    }

    byte_t *base = wasm_memory_data(memory);
    size_t size = wasm_memory_data_size(memory);
    if (!base || offset + length > size) {
        return NULL;
    }

    printf("[NATIVE -> WASM] accessing the memory...\n");

    return base + offset;
}

static bool
call_wasm_function(uint32_t export_id, const wasm_val_vec_t *args,
                   wasm_val_vec_t *results, const char *name)
{
    const wasm_func_t *function;
    wasm_trap_t *trap;

    printf("[NATIVE -> WASM] calling func %s...\n", name);

    if (!(function = wasm_extern_as_func(exports.data[export_id]))) {
        printf("> Error get export function %u\n", export_id);
        return false;
    }

    if ((trap = wasm_func_call(function, args, results))) {
        own wasm_message_t message = { 0 };
        wasm_trap_message(trap, &message);

        if (message.data) {
            printf("> Error calling function %s\n", message.data);
        }
        else {
            printf("> Error calling function");
        }

        wasm_name_delete(&message);
        wasm_trap_delete(trap);
        return false;
    }
    return true;
}

int
main(int argc, const char *argv[])
{
    // Initialize.
    printf("Initializing...\n");
    wasm_engine_t *engine = wasm_engine_new();
    wasm_store_t *store = wasm_store_new(engine);

    // Load binary.
    printf("Loading binary...\n");
#if WASM_ENABLE_AOT != 0 && WASM_ENABLE_INTERP == 0
    FILE *file = fopen("callback_chain.aot", "rb");
#else
    FILE *file = fopen("callback_chain.wasm", "rb");
#endif
    if (!file) {
        printf("> Error loading module!\n");
        return 1;
    }

    int ret = fseek(file, 0L, SEEK_END);
    if (ret == -1) {
        printf("> Error loading module!\n");
        fclose(file);
        return 1;
    }

    long file_size = ftell(file);
    if (file_size == -1) {
        printf("> Error loading module!\n");
        fclose(file);
        return 1;
    }

    ret = fseek(file, 0L, SEEK_SET);
    if (ret == -1) {
        printf("> Error loading module!\n");
        fclose(file);
        return 1;
    }

    wasm_byte_vec_t binary;
    wasm_byte_vec_new_uninitialized(&binary, file_size);
    if (fread(binary.data, file_size, 1, file) != 1) {
        printf("> Error loading module!\n");
        fclose(file);
        return 1;
    }
    fclose(file);

    // Compile.
    printf("Compiling module...\n");
    own wasm_module_t *module = wasm_module_new(store, &binary);
    if (!module) {
        printf("> Error compiling module!\n");
        return 1;
    }

    wasm_byte_vec_delete(&binary);

    // Instantiate.
    printf("Instantiating module...\n");

    // Create external functions.
    printf("Creating callback...\n");
#define IMPORT_FUNCTION_VARIABLE_NAME(name, ...) \
    own wasm_func_t *function_##name = NULL;
    IMPORT_FUNCTION_LIST(IMPORT_FUNCTION_VARIABLE_NAME)
#undef IMPORT_FUNCTION_VARIABLE_NAME

#define CREATE_WASM_FUNCTION(name, index, CREATE_FUNC_TYPE)                 \
    {                                                                       \
        own wasm_functype_t *type = CREATE_FUNC_TYPE;                       \
        if (!(function_##name = wasm_func_new(store, type, STUB_##name))) { \
            printf("> Error creating new function\n");                      \
            return 1;                                                       \
        }                                                                   \
        wasm_functype_delete(type);                                         \
    }
    IMPORT_FUNCTION_LIST(CREATE_WASM_FUNCTION)
#undef CREATE_WASM_FUNCTION

    wasm_extern_t *fs[2] = { 0 };
#define ADD_TO_FUNCTION_LIST(name, index, ...) \
    fs[index] = wasm_func_as_extern(function_##name);
    IMPORT_FUNCTION_LIST(ADD_TO_FUNCTION_LIST)
#undef ADD_TO_FUNCTION_LIST

    wasm_extern_vec_t imports = WASM_ARRAY_VEC(fs);
    own wasm_instance_t *instance =
        wasm_instance_new(store, module, &imports, NULL);
    if (!instance) {
        printf("> Error instantiating module!\n");
        return 1;
    }

#define DESTROY_WASM_FUNCTION(name, index, ...) \
    wasm_func_delete(function_##name);
    IMPORT_FUNCTION_LIST(DESTROY_WASM_FUNCTION)
#undef DESTROY_WASM_FUNCTION

    // Extract export.
    printf("Extracting export...\n");
    wasm_instance_exports(instance, &exports);
    if (!exports.size) {
        printf("> Error accessing exports!\n");
        return 1;
    }

    wasm_module_delete(module);
    wasm_instance_delete(instance);

    // Call.
    printf("Calling export...\n");

    if (!call_wasm_function(e_on_start, NULL, NULL, "on_start")) {
        printf("> Error calling on_start\n");
        return 1;
    }

    if (!call_wasm_function(e_on_stop, NULL, NULL, "on_stop")) {
        printf("> Error calling on_stop\n");
        return 1;
    }

    wasm_extern_vec_delete(&exports);

    // Shut down.
    printf("Shutting down...\n");
    wasm_store_delete(store);
    wasm_engine_delete(engine);

    // All done.
    printf("Done.\n");
    return 0;
}
