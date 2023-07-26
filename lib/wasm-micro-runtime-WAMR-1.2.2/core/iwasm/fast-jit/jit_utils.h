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

/**
 * A simple fixed size bitmap.
 */
typedef struct JitBitmap {
    /* The first valid bit index.  */
    uintptr_t begin_index;

    /* The last valid bit index plus one.  */
    uintptr_t end_index;

    /* The bitmap.  */
    uint8 map[1];
} JitBitmap;

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

/**
 * Create a new bitmap.
 *
 * @param begin_index the first valid bit index
 * @param bitnum maximal bit number of the bitmap.
 *
 * @return the new bitmap if succeeds, NULL otherwise.
 */
JitBitmap *
jit_bitmap_new(uintptr_t begin_index, unsigned bitnum);

/**
 * Delete a bitmap.
 *
 * @param bitmap the bitmap to be deleted
 */
static inline void
jit_bitmap_delete(JitBitmap *bitmap)
{
    jit_free(bitmap);
}

/**
 * Check whether the given index is in the range of the bitmap.
 *
 * @param bitmap the bitmap
 * @param n the bit index
 *
 * @return true if the index is in range, false otherwise
 */
static inline bool
jit_bitmap_is_in_range(JitBitmap *bitmap, unsigned n)
{
    return n >= bitmap->begin_index && n < bitmap->end_index;
}

/**
 * Get a bit in the bitmap
 *
 * @param bitmap the bitmap
 * @param n the n-th bit to be get
 *
 * @return value of the bit
 */
static inline int
jit_bitmap_get_bit(JitBitmap *bitmap, unsigned n)
{
    unsigned idx = n - bitmap->begin_index;
    bh_assert(n >= bitmap->begin_index && n < bitmap->end_index);
    return (bitmap->map[idx / 8] >> (idx % 8)) & 1;
}

/**
 * Set a bit in the bitmap.
 *
 * @param bitmap the bitmap
 * @param n the n-th bit to be set
 */
static inline void
jit_bitmap_set_bit(JitBitmap *bitmap, unsigned n)
{
    unsigned idx = n - bitmap->begin_index;
    bh_assert(n >= bitmap->begin_index && n < bitmap->end_index);
    bitmap->map[idx / 8] |= 1 << (idx % 8);
}

/**
 * Clear a bit in the bitmap.
 *
 * @param bitmap the bitmap
 * @param n the n-th bit to be cleared
 */
static inline void
jit_bitmap_clear_bit(JitBitmap *bitmap, unsigned n)
{
    unsigned idx = n - bitmap->begin_index;
    bh_assert(n >= bitmap->begin_index && n < bitmap->end_index);
    bitmap->map[idx / 8] &= ~(1 << (idx % 8));
}

#ifdef __cplusplus
}
#endif

#endif
