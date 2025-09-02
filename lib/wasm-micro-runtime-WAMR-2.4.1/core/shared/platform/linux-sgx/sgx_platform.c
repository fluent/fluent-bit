/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"
#include "sgx_rsrv_mem_mngr.h"

#if WASM_ENABLE_SGX_IPFS != 0
#include "sgx_ipfs.h"
#endif

static os_print_function_t print_function = NULL;

int
bh_platform_init()
{
    int ret = BHT_OK;

#if WASM_ENABLE_SGX_IPFS != 0
    ret = ipfs_init();
#endif

    return ret;
}

void
bh_platform_destroy()
{
#if WASM_ENABLE_SGX_IPFS != 0
    ipfs_destroy();
#endif
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

#define FIXED_BUFFER_SIZE 4096

int
os_printf(const char *message, ...)
{
    int bytes_written = 0;

    if (print_function != NULL) {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        va_list ap;
        va_start(ap, message);
        vsnprintf(msg, FIXED_BUFFER_SIZE, message, ap);
        va_end(ap);
        bytes_written += print_function(msg);
    }

    return bytes_written;
}

int
os_vprintf(const char *format, va_list arg)
{
    int bytes_written = 0;

    if (print_function != NULL) {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        vsnprintf(msg, FIXED_BUFFER_SIZE, format, arg);
        bytes_written += print_function(msg);
    }

    return bytes_written;
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

#if WASM_ENABLE_LIBC_WASI == 0
bool
os_is_handle_valid(os_file_handle *handle)
{
    assert(handle != NULL);

    return *handle > -1;
}
#else
/* implemented in posix_file.c */
#endif

void *
os_mmap(void *hint, size_t size, int prot, int flags, os_file_handle file)
{
    int mprot = 0;
    uint64 aligned_size, page_size;
    void *ret = NULL;
    sgx_status_t st = 0;

    if (os_is_handle_valid(&file)) {
        os_printf("os_mmap(size=%u, prot=0x%x, file=%x) failed: file is not "
                  "supported.\n",
                  size, prot, file);
        return NULL;
    }

    page_size = getpagesize();
    aligned_size = (size + page_size - 1) & ~(page_size - 1);

    if (aligned_size >= UINT32_MAX) {
        os_printf("mmap failed: request size overflow due to paging\n");
        return NULL;
    }

    ret = sgx_alloc_rsrv_mem(aligned_size);
    if (ret == NULL) {
        os_printf("os_mmap(size=%u, aligned size=%lu, prot=0x%x) failed.\n",
                  size, aligned_size, prot);
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
        os_printf("os_mmap(size=%u, prot=0x%x) failed to set protect.\n", size,
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
        os_printf("os_mprotect(addr=0x%" PRIx64
                  ", size=%u, prot=0x%x) failed.\n",
                  (uintptr_t)addr, size, prot);

    return (st == SGX_SUCCESS ? 0 : -1);
}

void
os_dcache_flush(void)
{}

void
os_icache_flush(void *start, size_t len)
{}
