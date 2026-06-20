/*
 * Copyright (C) 2023 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <assert.h>

#include "bh_platform.h"
#include "bh_atomic.h"

int
main(int argc, char **argv)
{
    bh_atomic_32_t v;
    uint32 o;

    v = 0x00ff00ff;
    o = BH_ATOMIC_32_LOAD(v);
    assert(o == 0x00ff00ff);

    v = 0x00ff00ff;
    o = BH_ATOMIC_32_FETCH_OR(v, 0xffff0000);
    assert(o == 0x00ff00ff);
    assert(v == 0xffff00ff);

    v = 0x00ff00ff;
    o = BH_ATOMIC_32_FETCH_AND(v, 0xffff0000);
    assert(o == 0x00ff00ff);
    assert(v == 0x00ff0000);

    v = 0x00ff00ff;
    o = BH_ATOMIC_32_FETCH_ADD(v, 0x10101);
    assert(o == 0x00ff00ff);
    assert(v == 0x00ff00ff + 0x10101);

    v = 0x00ff00ff;
    o = BH_ATOMIC_32_FETCH_SUB(v, 0x10101);
    assert(o == 0x00ff00ff);
    assert(v == 0x00ff00ff - 0x10101);

    return 0;
}
