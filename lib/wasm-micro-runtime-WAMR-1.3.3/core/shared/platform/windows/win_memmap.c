/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"

#define TRACE_MEMMAP 0

static DWORD
access_to_win32_flags(int prot)
{
    DWORD protect = PAGE_NOACCESS;

    if (prot & MMAP_PROT_EXEC) {
        if (prot & MMAP_PROT_WRITE)
            protect = PAGE_EXECUTE_READWRITE;
        else
            protect = PAGE_EXECUTE_READ;
    }
    else if (prot & MMAP_PROT_WRITE) {
        protect = PAGE_READWRITE;
    }
    else if (prot & MMAP_PROT_READ) {
        protect = PAGE_READONLY;
    }

    return protect;
}

void *
os_mmap(void *hint, size_t size, int prot, int flags, os_file_handle file)
{
    DWORD alloc_type = MEM_RESERVE;
    DWORD protect;
    size_t request_size, page_size;
    void *addr;

    page_size = os_getpagesize();
    request_size = (size + page_size - 1) & ~(page_size - 1);

    if (request_size < size)
        /* integer overflow */
        return NULL;

#if WASM_ENABLE_JIT != 0
    /**
     * Allocate memory at the highest possible address if the
     * request size is large, or LLVM JIT might report error:
     * IMAGE_REL_AMD64_ADDR32NB relocation requires an ordered
     * section layout.
     */
    if (request_size > 10 * BH_MB)
        alloc_type |= MEM_TOP_DOWN;
#endif

    protect = access_to_win32_flags(prot);
    if (protect != PAGE_NOACCESS) {
        alloc_type |= MEM_COMMIT;
    }

    addr = VirtualAlloc((LPVOID)hint, request_size, alloc_type, protect);

#if TRACE_MEMMAP != 0
    printf("Map memory, request_size: %zu, alloc_type: 0x%x, "
           "protect: 0x%x, ret: %p\n",
           request_size, alloc_type, protect, addr);
#endif
    return addr;
}

void
os_munmap(void *addr, size_t size)
{
    size_t page_size = os_getpagesize();
    size_t request_size = (size + page_size - 1) & ~(page_size - 1);

    if (addr) {
        if (!VirtualFree(addr, request_size, MEM_DECOMMIT)) {
            printf("warning: os_munmap decommit pages failed, "
                   "addr: %p, request_size: %zu, errno: %d\n",
                   addr, request_size, errno);
            return;
        }

        if (!VirtualFree(addr, 0, MEM_RELEASE)) {
            printf("warning: os_munmap release pages failed, "
                   "addr: %p, size: %zu, errno:%d\n",
                   addr, request_size, errno);
        }
    }
#if TRACE_MEMMAP != 0
    printf("Unmap memory, addr: %p, request_size: %zu\n", addr, request_size);
#endif
}

void *
os_mem_commit(void *addr, size_t size, int flags)
{
    DWORD protect = access_to_win32_flags(flags);
    size_t page_size = os_getpagesize();
    size_t request_size = (size + page_size - 1) & ~(page_size - 1);

    if (!addr)
        return NULL;

#if TRACE_MEMMAP != 0
    printf("Commit memory, addr: %p, request_size: %zu, protect: 0x%x\n", addr,
           request_size, protect);
#endif
    return VirtualAlloc((LPVOID)addr, request_size, MEM_COMMIT, protect);
}

void
os_mem_decommit(void *addr, size_t size)
{
    size_t page_size = os_getpagesize();
    size_t request_size = (size + page_size - 1) & ~(page_size - 1);

    if (!addr)
        return;

#if TRACE_MEMMAP != 0
    printf("Decommit memory, addr: %p, request_size: %zu\n", addr,
           request_size);
#endif
    VirtualFree((LPVOID)addr, request_size, MEM_DECOMMIT);
}

int
os_mprotect(void *addr, size_t size, int prot)
{
    DWORD protect;
    size_t page_size = os_getpagesize();
    size_t request_size = (size + page_size - 1) & ~(page_size - 1);

    if (!addr)
        return 0;

    protect = access_to_win32_flags(prot);
#if TRACE_MEMMAP != 0
    printf("Mprotect memory, addr: %p, request_size: %zu, protect: 0x%x\n",
           addr, request_size, protect);
#endif
    return VirtualProtect((LPVOID)addr, request_size, protect, NULL);
}
