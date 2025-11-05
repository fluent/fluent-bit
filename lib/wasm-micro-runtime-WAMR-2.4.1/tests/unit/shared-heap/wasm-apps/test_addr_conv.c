/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>

extern void *
shared_heap_malloc(int size);
extern void
shared_heap_free(void *offset);
extern void *
test_addr_conv(void *ptr);

int
test()
{
    int *ptr = NULL;
    int *ptr2 = NULL;

    ptr = (int *)shared_heap_malloc(4);

    if (ptr == NULL) {
        return 0;
    }
    ptr2 = test_addr_conv(ptr);
    if (ptr2 != ptr) {
        return 0;
    }
    shared_heap_free(ptr);
    return 1;
}

int
test_preallocated(void *app_addr)
{
    int *ptr = (int *)app_addr;
    int *ptr2 = NULL;

    ptr2 = test_addr_conv(ptr);
    if (ptr2 != ptr) {
        return 0;
    }

    return 1;
}
