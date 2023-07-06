/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

int
sum(int start, int length)
{
    int sum = 0, i;

    for (i = start; i < start + length; i++) {
        sum += i;
    }

    return sum;
}