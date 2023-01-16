/*
 * Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <librats/api.h>

#include "wasm_export.h"
#include "bh_common.h"

static uint32
librats_collect_wrapper(wasm_exec_env_t exec_env, const uint8_t *hash)
{
    char *json = NULL;
    char *str_ret;
    uint32 len;
    uint32 str_ret_offset = 0;
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    int code = librats_collect_evidence_to_json(hash, &json);
    if (code != 0) {
        return str_ret_offset;
    }
    if (json) {
        len = (uint32)strlen(json) + 1;

        str_ret_offset = module_malloc(len, (void **)&str_ret);
        if (str_ret_offset) {
            bh_memcpy_s(str_ret, len, json, len);
        }
    }
    return str_ret_offset;
}

static int
librats_verify_wrapper(wasm_exec_env_t exec_env, const char *evidence_json,
                       const uint8_t *hash)
{
    return librats_verify_evidence_from_json(evidence_json, hash);
}

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }
/* clang-format on */

static NativeSymbol native_symbols_lib_rats[] = {
    REG_NATIVE_FUNC(librats_collect, "($)i"),
    REG_NATIVE_FUNC(librats_verify, "($$)i")
};

uint32_t
get_lib_rats_export_apis(NativeSymbol **p_lib_rats_apis)
{
    *p_lib_rats_apis = native_symbols_lib_rats;
    return sizeof(native_symbols_lib_rats) / sizeof(NativeSymbol);
}