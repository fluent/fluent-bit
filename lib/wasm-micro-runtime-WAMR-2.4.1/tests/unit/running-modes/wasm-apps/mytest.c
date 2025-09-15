/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

int
recursive(int a)
{
    if (a > 0) {
        return recursive(a - 1) + 1;
    }
    else
        return 0;
}

int
testFunction(int *input, int length)
{
    int sum = 0;
    for (int i = 0; i < length; ++i) {
        sum += input[i];
    }
    return sum;
}

int
main(int argc, char **argv)
{

    int arr[5] = { 1, 2, 3, 4, 5 };
    testFunction(arr, recursive(5));

    char *buf;

    printf("Hello world!\n");

    buf = malloc(1024);
    if (!buf) {
        printf("malloc buf failed\n");
        return -1;
    }

    printf("buf ptr: %p\n", buf);

    snprintf(buf, 1024, "%s", "1234\n");
    printf("buf: %s", buf);

    free(buf);
    return 0;
}
