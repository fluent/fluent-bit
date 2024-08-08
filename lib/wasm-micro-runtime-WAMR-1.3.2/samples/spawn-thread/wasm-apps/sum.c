/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

/*
 * have something in bss so that llvm synthesizes
 * wasm start function for this module.
 */
char *
return_bss()
{
    static char bss[4096];
    return bss;
}

int
sum(int start, int length)
{
    int sum = 0, i;

    for (i = start; i < start + length; i++) {
        sum += i;
    }

    return sum;
}
