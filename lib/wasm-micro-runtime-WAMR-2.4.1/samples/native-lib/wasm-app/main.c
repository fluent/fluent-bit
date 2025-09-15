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
test_hello(const char *name, char *buf, size_t buflen);

int
test_hello2(const char *name, char *buf, size_t buflen);

int
main(int argc, char **argv)
{
    const char *name = __func__;
    char *buf;
    size_t buflen;
    int x = 10, y = 20, res;

    printf("Hello World!\n");

    res = test_add(x, y);
    printf("%d + %d = %d\n", x, y, res);

    res = test_sqrt(x, y);
    printf("sqrt(%d, %d) = %d\n", x, y, res);

    res = test_hello(name, NULL, 0);
    printf("test_hello(\"%s\", %p, %zu) = %d\n", name, NULL, (size_t)0, res);
    if (res == -1) {
        return -1;
    }
    buflen = res + 1;
    buf = malloc(buflen);
    printf("malloc(%zu) = %p\n", buflen, buf);
    res = test_hello(__func__, buf, buflen);
    if (res == -1) {
        return -1;
    }
    printf("test_hello(\"%s\", %p, %zu) = %d\n", name, buf, buflen, res);
    printf("Message from test_hello: %s", buf);
    free(buf);

    res = test_hello2(name, NULL, 0);
    printf("test_hello2(\"%s\", %p, %zu) = %d\n", name, NULL, (size_t)0, res);
    if (res == -1) {
        return -1;
    }
    buflen = res + 1;
    buf = malloc(buflen);
    printf("malloc(%zu) = %p\n", buflen, buf);
    res = test_hello2(__func__, buf, buflen);
    if (res == -1) {
        return -1;
    }
    printf("test_hello2(\"%s\", %p, %zu) = %d\n", name, buf, buflen, res);
    printf("Message from test_hello2: %s", buf);
    free(buf);

    return 0;
}
