/*
 * Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _RATS_WAMR_API_H
#define _RATS_WAMR_API_H

#include <stdint.h>

char *
librats_collect(const uint8_t *hash);
int
librats_verify(const char *json_string, const uint8_t *hash);

#endif