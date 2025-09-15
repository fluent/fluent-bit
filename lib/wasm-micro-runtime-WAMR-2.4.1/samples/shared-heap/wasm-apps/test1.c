/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern void *
shared_heap_malloc(uint32_t size);
extern void
shared_heap_free(void *ptr);

void *
my_shared_heap_malloc(uint32_t size, uint32_t index)
{
    char *buf1 = NULL, *buf2 = NULL, *buf;

    buf1 = shared_heap_malloc(128);
    if (!buf1)
        return NULL;

    buf1[0] = 'H';
    buf1[1] = 'e';
    buf1[2] = 'l';
    buf1[3] = 'l';
    buf1[4] = 'o';
    buf1[5] = ',';
    buf1[6] = ' ';

    buf2 = shared_heap_malloc(128);
    if (!buf2) {
        shared_heap_free(buf1);
        return NULL;
    }

    snprintf(buf2, 128, "this is buf %u allocated from shared heap", index);

    buf = shared_heap_malloc(size);
    if (!buf) {
        shared_heap_free(buf1);
        shared_heap_free(buf2);
        return NULL;
    }

    memset(buf, 0, size);
    memcpy(buf, buf1, strlen(buf1));
    memcpy(buf + strlen(buf1), buf2, strlen(buf2));

    shared_heap_free(buf1);
    shared_heap_free(buf2);
    return buf;
}

void
my_shared_heap_free(void *ptr)
{
    shared_heap_free(ptr);
}

void *
produce_str(char *addr, uint32_t index)
{
    char c;
    snprintf(addr, 512, "Data: %u stores to pre-allocated shared heap", index);
    /* Actually access it in wasm */
    c = addr[0];
    printf("In WASM: the first char is %c\n", c);
    return addr;
}
