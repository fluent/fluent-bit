/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"
#include "sgx_rsrv_mem_mngr.h"

#define FIXED_BUFFER_SIZE (1 << 9)

static os_print_function_t print_function = NULL;

int
bh_platform_init()
{
    return 0;
}

void
bh_platform_destroy()
{}

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
putchar(int c)
{
    return 0;
}

int
puts(const char *s)
{
    return 0;
}

void
os_set_print_function(os_print_function_t pf)
{
    print_function = pf;
}

int
os_printf(const char *message, ...)
{
    if (print_function != NULL) {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        va_list ap;
        va_start(ap, message);
        vsnprintf(msg, FIXED_BUFFER_SIZE, message, ap);
        va_end(ap);
        print_function(msg);
    }

    return 0;
}

int
os_vprintf(const char *format, va_list arg)
{
    if (print_function != NULL) {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        vsnprintf(msg, FIXED_BUFFER_SIZE, format, arg);
        print_function(msg);
    }

    return 0;
}

char *
strcpy(char *dest, const char *src)
{
    const unsigned char *s = src;
    unsigned char *d = dest;

    while ((*d++ = *s++)) {
    }
    return dest;
}

void *
os_mmap(void *hint, size_t size, int prot, int flags)
{
    int mprot = 0;
    uint64 aligned_size, page_size;
    void *ret = NULL;
    sgx_status_t st = 0;

    page_size = getpagesize();
    aligned_size = (size + page_size - 1) & ~(page_size - 1);

    if (aligned_size >= UINT32_MAX)
        return NULL;

    ret = sgx_alloc_rsrv_mem(aligned_size);
    if (ret == NULL) {
        os_printf("os_mmap(size=%u, aligned size=%lu, prot=0x%x) failed.", size,
                  aligned_size, prot);
        return NULL;
    }

    if (prot & MMAP_PROT_READ)
        mprot |= SGX_PROT_READ;
    if (prot & MMAP_PROT_WRITE)
        mprot |= SGX_PROT_WRITE;
    if (prot & MMAP_PROT_EXEC)
        mprot |= SGX_PROT_EXEC;

    st = sgx_tprotect_rsrv_mem(ret, aligned_size, mprot);
    if (st != SGX_SUCCESS) {
        os_printf("os_mmap(size=%u, prot=0x%x) failed to set protect.", size,
                  prot);
        sgx_free_rsrv_mem(ret, aligned_size);
        return NULL;
    }

    return ret;
}

void
os_munmap(void *addr, size_t size)
{
    uint64 aligned_size, page_size;

    page_size = getpagesize();
    aligned_size = (size + page_size - 1) & ~(page_size - 1);
    sgx_free_rsrv_mem(addr, aligned_size);
}

int
os_mprotect(void *addr, size_t size, int prot)
{
    int mprot = 0;
    sgx_status_t st = 0;
    uint64 aligned_size, page_size;

    page_size = getpagesize();
    aligned_size = (size + page_size - 1) & ~(page_size - 1);

    if (prot & MMAP_PROT_READ)
        mprot |= SGX_PROT_READ;
    if (prot & MMAP_PROT_WRITE)
        mprot |= SGX_PROT_WRITE;
    if (prot & MMAP_PROT_EXEC)
        mprot |= SGX_PROT_EXEC;
    st = sgx_tprotect_rsrv_mem(addr, aligned_size, mprot);
    if (st != SGX_SUCCESS)
        os_printf("os_mprotect(addr=0x%" PRIx64 ", size=%u, prot=0x%x) failed.",
                  (uintptr_t)addr, size, prot);

    return (st == SGX_SUCCESS ? 0 : -1);
}

void
os_dcache_flush(void)
{}
