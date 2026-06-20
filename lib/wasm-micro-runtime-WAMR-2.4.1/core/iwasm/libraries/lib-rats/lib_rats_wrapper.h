/*
 * Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _RATS_WAMR_API_H
#define _RATS_WAMR_API_H

#include <stdint.h>
#include <string.h>

#include "lib_rats_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int
librats_collect(char **evidence_json, const char *buffer, uint32_t buffer_size);

int
librats_verify(const char *evidence_json, uint32_t evidence_size,
               const uint8_t *hash, uint32_t hash_size);

int
librats_parse_evidence(const char *evidence_json, uint32_t json_size,
                       rats_sgx_evidence_t *evidence, uint32_t evidence_size);

#define librats_collect(evidence_json, buffer) \
    librats_collect(evidence_json, buffer, buffer ? strlen(buffer) + 1 : 0)

#define librats_verify(evidence_json, hash)                             \
    librats_verify(evidence_json,                                       \
                   evidence_json ? strlen(evidence_json) + 1 : 0, hash, \
                   hash ? strlen((const char *)hash) + 1 : 0)

#define librats_parse_evidence(evidence_json, evidence)                   \
    librats_parse_evidence(evidence_json,                                 \
                           evidence_json ? strlen(evidence_json) + 1 : 0, \
                           evidence, sizeof(rats_sgx_evidence_t))

void
librats_dispose_evidence_json(char *evidence_json);

#ifdef __cplusplus
}
#endif

#endif
