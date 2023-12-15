/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_utils.h"

JitBitmap *
jit_bitmap_new(uintptr_t begin_index, unsigned bitnum)
{
    JitBitmap *bitmap;

    if ((bitmap = jit_calloc(offsetof(JitBitmap, map) + (bitnum + 7) / 8))) {
        bitmap->begin_index = begin_index;
        bitmap->end_index = begin_index + bitnum;
    }

    return bitmap;
}
