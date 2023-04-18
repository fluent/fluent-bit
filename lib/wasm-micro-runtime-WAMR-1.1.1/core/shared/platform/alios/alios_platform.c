/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

int
os_thread_sys_init();

void
os_thread_sys_destroy();

int
bh_platform_init()
{
    return os_thread_sys_init();
}

void
bh_platform_destroy()
{
    os_thread_sys_destroy();
}

void *
os_malloc(unsigned size)
{
    return NULL;
}

void *
os_realloc(void *ptr, unsigned size)
{
    return NULL;
}

void
os_free(void *ptr)
{}

void *
os_mmap(void *hint, size_t size, int prot, int flags)
{
    if ((uint64)size >= UINT32_MAX)
        return NULL;
    return BH_MALLOC((uint32)size);
}

void
os_munmap(void *addr, size_t size)
{
    return BH_FREE(addr);
}

int
os_mprotect(void *addr, size_t size, int prot)
{
    return 0;
}

void
os_dcache_flush()
{}
