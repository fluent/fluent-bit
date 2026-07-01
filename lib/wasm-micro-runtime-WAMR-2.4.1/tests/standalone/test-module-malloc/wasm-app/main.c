/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void *
test_module_malloc(unsigned buf_size);

void
test_module_free(void *buf);

int
main(int argc, char **argv)
{
    char *buf = NULL;

    printf("Hello World!\n");

    buf = test_module_malloc(1024);
    if (buf) {
        printf("module_malloc(1024) success, return %p\n", buf);
        snprintf(buf, 1024, "%s", "Hello world!\n");
    }
    else {
        printf("module_malloc(1024) failed!\n");
        return -1;
    }

    test_module_free(buf);

    buf = test_module_malloc(32 * 1024 * 1024);
    if (!buf) {
        printf("module_malloc(32MB) failed => expected, not an issue\n");
    }
    else {
        printf("module_malloc(32MB) success, unexpected!\n");
        return -1;
    }

    return 0;
}
