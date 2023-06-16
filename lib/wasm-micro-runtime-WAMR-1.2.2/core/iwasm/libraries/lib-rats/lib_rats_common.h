/*
 * Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _RATS_WAMR_COMMON_H
#define _RATS_WAMR_COMMON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SGX_QUOTE_MAX_SIZE 8192
#define SGX_USER_DATA_SIZE 64
#define SGX_MEASUREMENT_SIZE 32

/* clang-format off */
typedef struct rats_sgx_evidence {
    uint8_t quote[SGX_QUOTE_MAX_SIZE];          /* The quote of the Enclave */
    uint32_t quote_size;                        /* The size of the quote */
    uint8_t user_data[SGX_USER_DATA_SIZE];      /* The custom data in the quote */
    uint32_t product_id;                        /* Product ID of the Enclave */
    uint8_t mr_enclave[SGX_MEASUREMENT_SIZE];   /* The MRENCLAVE of the Enclave */
    uint32_t security_version;                  /* Security Version of the Enclave */
    uint8_t mr_signer[SGX_MEASUREMENT_SIZE];    /* The MRSIGNER of the Enclave */
    uint64_t att_flags;                         /* Flags of the Enclave in attributes */
    uint64_t att_xfrm;                          /* XSAVE Feature Request Mask */
} rats_sgx_evidence_t;
/* clang-format on */

#ifdef __cplusplus
}
#endif

#endif
