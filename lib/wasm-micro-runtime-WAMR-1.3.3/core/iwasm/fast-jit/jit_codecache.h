/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_CODE_CACHE_H_
#define _JIT_CODE_CACHE_H_

#include "bh_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
jit_code_cache_init(uint32 code_cache_size);

void
jit_code_cache_destroy();

void *
jit_code_cache_alloc(uint32 size);

void
jit_code_cache_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* end of _JIT_CODE_CACHE_H_ */
