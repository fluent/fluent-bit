/*
 * Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include "lib_rats_wrapper.h"

#define __is_print(ch) ((unsigned int)((ch) - ' ') < 127u - ' ')

/**
 * hex_dump
 *
 * @brief dump data in hex format
 *
 * @param title: Title
 * @param buf: User buffer
 * @param size: Dump data size
 * @param number: The number of outputs per line
 *
 * @return void
 */
void
hex_dump(const char *title, const uint8_t *buf, uint32_t size, uint32_t number)
{
    int i, j;
    if (title) {
        printf("\n\t%s:\n\n", title);
    }

    for (i = 0; i < size; i += number) {
        printf("%08X: ", i);

        for (j = 0; j < number; j++) {
            if (j % 8 == 0) {
                printf(" ");
            }
            if (i + j < size)
                printf("%02X ", buf[i + j]);
            else
                printf("   ");
        }
        printf(" ");

        for (j = 0; j < number; j++) {
            if (i + j < size) {
                printf("%c", __is_print(buf[i + j]) ? buf[i + j] : '.');
            }
        }
        printf("\n");
    }
}

int
main(int argc, char **argv)
{
    int ret_code = -1;
    char *evidence_json = NULL;

    // Generate user_data by SHA256 buffer and the wasm module.
    // user_data = SHA256(sha256_wasm_module || buffer)
    const char *buffer = "This is a sample.";

    // If you want to declare the evidence of type rats_sgx_evidence_t on the
    // stack, you should modify the stack size of the CMAKE_EXE_LINKER_FLAGS in
    // CMakeLists.txt to 51200 at least.
    rats_sgx_evidence_t *evidence =
        (rats_sgx_evidence_t *)malloc(sizeof(rats_sgx_evidence_t));
    if (!evidence) {
        printf("ERROR: No memory to allocate.\n");
        goto err;
    }

    int rats_err = librats_collect(&evidence_json, buffer);
    if (rats_err != 0) {
        printf("ERROR: Collect evidence failed, error code: %#x\n", rats_err);
        goto err;
    }

    if (librats_parse_evidence(evidence_json, evidence) != 0) {
        printf("ERROR: Parse evidence failed.\n");
        goto err;
    }

    // You could use these parameters for further verification.
    hex_dump("Quote", evidence->quote, evidence->quote_size, 32);
    hex_dump("User Data", evidence->user_data, SGX_USER_DATA_SIZE, 32);
    hex_dump("MRENCLAVE", evidence->mr_enclave, SGX_MEASUREMENT_SIZE, 32);
    hex_dump("MRSIGNER", evidence->mr_signer, SGX_MEASUREMENT_SIZE, 32);
    printf("\n\tProduct ID:\t\t%u\n", evidence->product_id);
    printf("\tSecurity Version:\t%u\n", evidence->security_version);
    printf("\tAttributes.flags:\t%llu\n", evidence->att_flags);
    printf("\tAttribute.xfrm:\t\t%llu\n", evidence->att_xfrm);

    rats_err = librats_verify((const char *)evidence_json, evidence->user_data);
    if (rats_err != 0) {
        printf("ERROR: Evidence is not trusted, error code: %#x.\n", rats_err);
        goto err;
    }

    ret_code = 0;
    printf("Evidence is trusted.\n");

err:
    if (evidence_json) {
        librats_dispose_evidence_json(evidence_json);
    }

    if (evidence) {
        free(evidence);
    }

    return ret_code;
}
