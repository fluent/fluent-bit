/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>

int
python_func(int val);

int
add(int val1, int val2)
{
    return val1 + val2;
}

int
c_func(int val)
{
    printf("c: in c_func with input: %d\n", val);
    printf("c: calling python_func(%d)\n", val + 1);
    int res = python_func(val + 1);
    printf("c: result from python_func: %d\n", res);
    printf("c: returning %d\n", res + 1);
    return res + 1;
}

int
main()
{}
