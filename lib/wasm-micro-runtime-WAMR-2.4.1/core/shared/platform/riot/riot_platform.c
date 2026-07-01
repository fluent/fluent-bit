/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * Copyright (C) 2020 TU Bergakademie Freiberg Karl Fessel
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

int
os_thread_sys_init(void);

void
os_thread_sys_destroy(void);

int
bh_platform_init(void)
{
    return os_thread_sys_init();
}

void
bh_platform_destroy(void)
{
    os_thread_sys_destroy();
}

void *
os_malloc(unsigned size)
{
    return malloc(size);
}

void *
os_realloc(void *ptr, unsigned size)
{
    return realloc(ptr, size);
}

void
os_free(void *ptr)
{
    free(ptr);
}

int
os_dumps_proc_mem_info(char *out, unsigned int size)
{
    return -1;
}

void *
os_mmap(void *hint, size_t size, int prot, int flags, os_file_handle file)
{
    void *addr;

    if (size >= UINT32_MAX)
        return NULL;

    if ((addr = BH_MALLOC((uint32)size)))
        memset(addr, 0, (uint32)size);

    return addr;
}

void *
os_mremap(void *old_addr, size_t old_size, size_t new_size)
{
    return os_mremap_slow(old_addr, old_size, new_size);
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
os_dcache_flush(void)
{
#if defined(CONFIG_CPU_CORTEX_M7) && defined(CONFIG_ARM_MPU)
    uint32 key;
    key = irq_lock();
    SCB_CleanDCache();
    irq_unlock(key);
#endif
}

void
os_icache_flush(void *start, size_t len)
{}

os_raw_file_handle
os_invalid_raw_handle(void)
{
    return -1;
}
