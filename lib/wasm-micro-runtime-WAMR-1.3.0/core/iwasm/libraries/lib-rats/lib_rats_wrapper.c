/*
 * Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <librats/api.h>
#include <string.h>
#include <openssl/sha.h>

#include "sgx_quote_3.h"
#include "wasm_export.h"
#include "bh_common.h"
#include "lib_rats_common.h"

static int
librats_collect_wrapper(wasm_exec_env_t exec_env, uint32_t *evidence_json,
                        const char *buffer, uint32_t buffer_size)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    wasm_module_t module = wasm_runtime_get_module(module_inst);
    char *wasm_module_hash = wasm_runtime_get_module_hash(module);

    char *json, *str_ret;
    uint32_t str_ret_offset;
    uint8_t final_hash[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, wasm_module_hash, SHA256_DIGEST_LENGTH);
    if (buffer != NULL)
        SHA256_Update(&sha256, buffer, buffer_size);
    SHA256_Final(final_hash, &sha256);

    int ret_code = librats_collect_evidence_to_json(final_hash, &json);
    if (ret_code != 0) {
        return ret_code;
    }

    uint32_t json_size = strlen(json) + 1;
    str_ret_offset = module_malloc(json_size, (void **)&str_ret);
    if (!str_ret_offset) {
        free(json);
        return (int)RATS_ATTESTER_ERR_NO_MEM;
    }
    bh_memcpy_s(str_ret, json_size, json, json_size);
    *evidence_json = str_ret_offset;
    free(json);

    return 0;
}

static int
librats_verify_wrapper(wasm_exec_env_t exec_env, const char *evidence_json,
                       uint32_t evidence_size, const uint8_t *hash,
                       uint32_t hash_size)
{
    return librats_verify_evidence_from_json(evidence_json, hash);
}

static int
librats_parse_evidence_wrapper(wasm_exec_env_t exec_env,
                               const char *evidence_json, uint32_t json_size,
                               rats_sgx_evidence_t *evidence,
                               uint32_t evidence_size)
{
    attestation_evidence_t att_ev;

    if (get_evidence_from_json(evidence_json, &att_ev) != 0) {
        return -1;
    }

    // Only supports parsing sgx evidence currently
    if (strcmp(att_ev.type, "sgx_ecdsa") != 0) {
        return -1;
    }

    sgx_quote3_t *quote_ptr = (sgx_quote3_t *)att_ev.ecdsa.quote;
    bh_memcpy_s(evidence->quote, att_ev.ecdsa.quote_len, att_ev.ecdsa.quote,
                att_ev.ecdsa.quote_len);
    evidence->quote_size = att_ev.ecdsa.quote_len;
    bh_memcpy_s(evidence->user_data, SGX_REPORT_DATA_SIZE,
                quote_ptr->report_body.report_data.d, SGX_REPORT_DATA_SIZE);
    bh_memcpy_s(evidence->mr_enclave, sizeof(sgx_measurement_t),
                quote_ptr->report_body.mr_enclave.m, sizeof(sgx_measurement_t));
    bh_memcpy_s(evidence->mr_signer, sizeof(sgx_measurement_t),
                quote_ptr->report_body.mr_signer.m, sizeof(sgx_measurement_t));
    evidence->product_id = quote_ptr->report_body.isv_prod_id;
    evidence->security_version = quote_ptr->report_body.isv_svn;
    evidence->att_flags = quote_ptr->report_body.attributes.flags;
    evidence->att_xfrm = quote_ptr->report_body.attributes.flags;

    return 0;
}

static void
librats_dispose_evidence_json_wrapper(wasm_exec_env_t exec_env,
                                      uint32_t evidence_json)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    module_free(evidence_json);
}

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }
/* clang-format on */

static NativeSymbol native_symbols_lib_rats[] = {
    REG_NATIVE_FUNC(librats_collect, "(**~)i"),
    REG_NATIVE_FUNC(librats_verify, "(*~*~)i"),
    REG_NATIVE_FUNC(librats_parse_evidence, "(*~*~)i"),
    REG_NATIVE_FUNC(librats_dispose_evidence_json, "(i)")
};

uint32_t
get_lib_rats_export_apis(NativeSymbol **p_lib_rats_apis)
{
    *p_lib_rats_apis = native_symbols_lib_rats;
    return sizeof(native_symbols_lib_rats) / sizeof(NativeSymbol);
}
