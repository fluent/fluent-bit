/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_UTILS_H_
#define _JIT_UTILS_H_

#include "bh_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void *
jit_malloc(unsigned int size)
{
    return wasm_runtime_malloc(size);
}

static inline void *
jit_calloc(unsigned int size)
{
    void *ret = wasm_runtime_malloc(size);
    if (ret) {
        memset(ret, 0, size);
    }
    return ret;
}

static inline void
jit_free(void *ptr)
{
    if (ptr)
        wasm_runtime_free(ptr);
}

#ifdef __cplusplus
}
#endif

#endif
