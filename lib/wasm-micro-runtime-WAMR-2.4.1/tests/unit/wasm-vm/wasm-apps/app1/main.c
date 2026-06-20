/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

void
on_init()
{}

int
my_sqrt(int x, int y)
{
    return x * x + y * y;
}

void *
null_pointer()
{
    void *ptr = NULL;
    return ptr;
}

void *
my_malloc(int size)
{
    return malloc(size);
}

void *
my_calloc(int nmemb, int size)
{
    return calloc(nmemb, size);
}

void
my_free(void *ptr)
{
    return free(ptr);
}

void *
my_memcpy(void *dst, void *src, int size)
{
    return memcpy(dst, src, size);
}

char *
my_strdup(const char *s)
{
    return strdup(s);
}
