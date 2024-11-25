/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>

unsigned
fib2(unsigned n)
{
    if (n < 2) {
        return 1;
    }
    return fib2(n - 2) + fib2(n - 1);
}

void
test1(int32_t i32, int64_t i64, float f32, double f64)
{
    printf("i32: %d, i64: %lld, f32: %f, f64: %f\n", i32, i64, f32, f64);
}

int64_t
test2(int64_t x, int64_t y)
{
    printf("%lld + %lld = %lld\n", x, y, x + y);
    return x + y;
}

double
test3(float x, double y)
{
    printf("%f * %f = %f\n", x, y, x * y);
    return x * y;
}

float
test4(double x, int32_t y)
{
    printf("%f / %d = %f\n", x, y, x / y);
    return x / y;
}

int
main(int argc, char **argv)
{
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
