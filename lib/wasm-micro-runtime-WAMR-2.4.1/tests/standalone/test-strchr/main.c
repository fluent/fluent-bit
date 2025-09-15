/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
    char *str = malloc(32);
    printf("str ptr: %p\n", str);

    sprintf(str, "%s", "123456");
    printf("str: %s\n", str);

    char *str1 = strchr(str, '3');
    printf("str1 ptr: %p\n", str1);
    printf("str1: %s\n", str1);

    free(str);
    return 0;
}
