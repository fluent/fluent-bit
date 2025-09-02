/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdlib.h>
#include <stdio.h>
#include "wasm_c_api.h"
#include "wasm_export.h"

static wasm_trap_t *
host_logs(const wasm_val_vec_t *args, wasm_val_vec_t *results)
{
    return NULL;
}

static bool
build_imports(wasm_store_t *store, const wasm_module_t *module,
              wasm_extern_vec_t *out)
{
    wasm_importtype_vec_t importtypes = { 0 };
    wasm_module_imports(module, &importtypes);

    wasm_extern_t *externs[32] = { 0 };

    for (unsigned i = 0; i < importtypes.num_elems; i++) {
        wasm_importtype_t *importtype = importtypes.data[i];

        /* use wasm_extern_new_empty() to create a placeholder */
        if (wasm_importtype_is_linked(importtype)) {
            externs[i] = wasm_extern_new_empty(
                store, wasm_externtype_kind(wasm_importtype_type(importtype)));
            continue;
        }

        const wasm_name_t *module_name =
            wasm_importtype_module(importtypes.data[i]);
        const wasm_name_t *field_name =
            wasm_importtype_name(importtypes.data[i]);

        if (strncmp(module_name->data, "env", strlen("env")) == 0
            && strncmp(field_name->data, "log", strlen("log")) == 0) {
            wasm_functype_t *log_type = wasm_functype_new_2_0(
                wasm_valtype_new_i64(), wasm_valtype_new_i32());
            wasm_func_t *log_func = wasm_func_new(store, log_type, host_logs);
            wasm_functype_delete(log_type);

            externs[i] = wasm_func_as_extern(log_func);
        }
    }

    wasm_extern_vec_new(out, importtypes.num_elems, externs);
    wasm_importtype_vec_delete(&importtypes);
    return true;
}

int
main()
{
    int main_ret = EXIT_FAILURE;

    // Initialize.
    printf("Initializing...\n");
    wasm_engine_t *engine = wasm_engine_new();
    if (!engine)
        goto quit;

    wasm_store_t *store = wasm_store_new(engine);
    if (!store)
        goto delete_engine;

    // Load binary.
    printf("Loading binary...\n");
#if WASM_ENABLE_AOT != 0 && WASM_ENABLE_INTERP == 0
    FILE *file = fopen("send_recv.aot", "rb");
    printf("> Load .aot\n");
#else
    FILE *file = fopen("send_recv.wasm", "rb");
    printf("> Load .wasm\n");
#endif
    if (!file) {
        printf("> Error loading module!\n");
        goto delete_store;
    }

    int ret = fseek(file, 0L, SEEK_END);
    if (ret == -1) {
        printf("> Error loading module!\n");
        goto close_file;
    }

    long file_size = ftell(file);
    if (file_size == -1) {
        printf("> Error loading module!\n");
        goto close_file;
    }

    ret = fseek(file, 0L, SEEK_SET);
    if (ret == -1) {
        printf("> Error loading module!\n");
        goto close_file;
    }

    wasm_byte_vec_t binary;
    wasm_byte_vec_new_uninitialized(&binary, file_size);

    if (fread(binary.data, file_size, 1, file) != 1) {
        printf("> Error loading module!\n");
        goto delete_binary;
    }

    // Compile.
    printf("Compiling module...\n");
    wasm_module_t *module = wasm_module_new(store, &binary);
    if (!module) {
        printf("> Error compiling module!\n");
        goto delete_binary;
    }

    // Set Wasi Context
    const char *addr_pool[1] = { "127.0.0.1" };
    wasm_runtime_set_wasi_addr_pool(*module, addr_pool, 1);

    // Instantiate.
    printf("Instantiating module...\n");
    wasm_extern_vec_t imports = { 0 };
    ret = build_imports(store, module, &imports);
    if (!ret) {
        printf("> Error building imports!\n");
        goto delete_module;
    }

    wasm_instance_t *instance =
        wasm_instance_new(store, module, &imports, NULL);
    if (!instance) {
        printf("> Error instantiating module!\n");
        goto delete_imports;
    }

    // Extract export.
    printf("Extracting export...\n");
    wasm_extern_vec_t exports;
    wasm_instance_exports(instance, &exports);
    if (exports.size == 0) {
        printf("> Error accessing exports!\n");
        goto delete_instance;
    }

    /**
     * should use information from wasm_module_exports to avoid hard coding "1"
     */
    const wasm_func_t *start_func = wasm_extern_as_func(exports.data[1]);
    if (start_func == NULL) {
        printf("> Error accessing export!\n");
        goto delete_exports;
    }

    // Call. "_start(nil) -> i32"
    printf("Calling _start ...\n");
    wasm_val_t rs[1] = { WASM_I32_VAL(0) };
    wasm_val_vec_t args = WASM_EMPTY_VEC;
    wasm_val_vec_t results = WASM_ARRAY_VEC(rs);
    wasm_trap_t *trap = wasm_func_call(start_func, &args, &results);
    if (trap) {
        wasm_name_t message = { 0 };
        wasm_trap_message(trap, &message);

        printf("> Error calling function! %s\n", message.data);

        wasm_name_delete(&message);
        wasm_trap_delete(trap);
        goto delete_exports;
    }

    // Print result.
    printf("Printing result...\n");
    printf("> %u\n", rs[0].of.i32);

    // Shut down.
    printf("Shutting down...\n");

    // All done.
    printf("Done.\n");
    main_ret = EXIT_SUCCESS;

delete_exports:
    wasm_extern_vec_delete(&exports);
delete_instance:
    wasm_instance_delete(instance);
delete_imports:
    wasm_extern_vec_delete(&imports);
delete_module:
    wasm_module_delete(module);
delete_binary:
    wasm_byte_vec_delete(&binary);
close_file:
    fclose(file);
delete_store:
    wasm_store_delete(store);
delete_engine:
    wasm_engine_delete(engine);
quit:
    return main_ret;
}