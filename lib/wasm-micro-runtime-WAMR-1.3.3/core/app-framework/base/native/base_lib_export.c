/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib_export.h"
#include "req_resp_native_api.h"
#include "timer_native_api.h"

static NativeSymbol extended_native_symbol_defs[] = {
/* TODO: use macro EXPORT_WASM_API() or EXPORT_WASM_API2() to
   add functions to register. */
#include "base_lib.inl"
};

uint32
get_base_lib_export_apis(NativeSymbol **p_base_lib_apis)
{
    *p_base_lib_apis = extended_native_symbol_defs;
    return sizeof(extended_native_symbol_defs) / sizeof(NativeSymbol);
}
