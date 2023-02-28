/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WASM_NATIVE_H
#define _WASM_NATIVE_H

#include "bh_common.h"
#include "../include/wasm_export.h"
#include "../interpreter/wasm.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NativeSymbolsNode {
    struct NativeSymbolsNode *next;
    const char *module_name;
    NativeSymbol *native_symbols;
    uint32 n_native_symbols;
    bool call_conv_raw;
} NativeSymbolsNode, *NativeSymbolsList;

/**
 * Lookup global variable of a given import global
 * from libc builtin globals
 *
 * @param module_name the module name of the import global
 * @param global_name the global name of the import global
 * @param global return the global data
 *
 * @param true if success, false otherwise
 */
bool
wasm_native_lookup_libc_builtin_global(const char *module_name,
                                       const char *global_name,
                                       WASMGlobalImport *global);

/**
 * Resolve native symbol in all libraries, including libc-builtin, libc-wasi,
 * base lib and extension lib, and user registered natives
 * function, which can be auto checked by vm before calling native function
 *
 * @param module_name the module name of the import function
 * @param func_name the function name of the import function
 * @param func_type the function prototype of the import function
 * @param p_signature output the signature if resolve success
 *
 * @return the native function pointer if success, NULL otherwise
 */
void *
wasm_native_resolve_symbol(const char *module_name, const char *field_name,
                           const WASMType *func_type, const char **p_signature,
                           void **p_attachment, bool *p_call_conv_raw);

bool
wasm_native_register_natives(const char *module_name,
                             NativeSymbol *native_symbols,
                             uint32 n_native_symbols);

bool
wasm_native_register_natives_raw(const char *module_name,
                                 NativeSymbol *native_symbols,
                                 uint32 n_native_symbols);

bool
wasm_native_init();

void
wasm_native_destroy();

#ifdef __cplusplus
}
#endif

#endif /* end of _WASM_NATIVE_H */
