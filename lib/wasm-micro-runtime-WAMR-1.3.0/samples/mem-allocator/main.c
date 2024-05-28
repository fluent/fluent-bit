/*
 * Copyright (C) 2023 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "mem_alloc.h"

char store[1000];

int
main(int argc, char **argv)
{
    mem_allocator_t a = mem_allocator_create(store, sizeof(store));
    uint8_t *p;
    uint8_t *p2;

    p = mem_allocator_malloc(a, 256);
    printf("%p\n", p);
    if (p == NULL) {
        exit(1);
    }
    p = mem_allocator_realloc(a, p, 256 + 12);
    printf("%p\n", p);
    if (p == NULL) {
        exit(1);
    }

    /*
     * write some values to confuse the ems allocator.
     *
     * hmu = p + 256
     * hmu_set_ut(hmu, HMU_FC)
     * hmu_set_size(hmu, 256)
     * hmu_set_free_size(hmu)
     */
    *(uint32_t *)(p + 256) = (1 << 30) | 0x20;
    *(uint32_t *)(p + 256 + 12 - 4) = 12;

    p2 = mem_allocator_malloc(a, 256);
    printf("%p\n", p2);
    if (p2 == NULL) {
        exit(1);
    }
    mem_allocator_free(a, p2);

    p2 = mem_allocator_malloc(a, 256);
    printf("%p\n", p2);
    if (p2 == NULL) {
        exit(1);
    }
    mem_allocator_free(a, p2);

    mem_allocator_free(a, p);
}
