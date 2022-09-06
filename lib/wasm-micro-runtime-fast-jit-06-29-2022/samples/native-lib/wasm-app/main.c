/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

int
test_add(int x, int y);

int
test_sqrt(int x, int y);

int
main(int argc, char **argv)
{
    int x = 10, y = 20, res;

    printf("Hello World!\n");

    res = test_add(x, y);
    printf("%d + %d = %d\n", x, y, res);

    res = test_sqrt(x, y);
    printf("sqrt(%d, %d) = %d\n", x, y, res);

    return 0;
}
