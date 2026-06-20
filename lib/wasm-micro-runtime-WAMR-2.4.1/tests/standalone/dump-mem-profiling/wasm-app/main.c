/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <malloc.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>

int
main(int argc, char **argv)
{
    printf("Hello World!\n");

    char *buf = "1234", *buf1 = "12345";

    printf("result is %f \n", 22.00);

    printf("Hello World!\n");

    buf = malloc(1024);

    printf("malloc func ptr: %p\n", malloc);

    printf("##buf: %p\n", buf);

    if (!buf) {
        printf("malloc buf failed\n");
        return -1;
    }

    printf("buf ptr: %p\n", buf);

    sprintf(buf, "%s", "1234\n");
    printf("buf: %s", buf);

    buf1 = strdup(buf);
    printf("buf1: %s\n", buf1);

    free(buf1);
    free(buf);

    printf("buf[65536]: %c\n", buf[65536 * 10]);

    return 0;
}
