/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_codecache.h"
#include "mem_alloc.h"
#include "jit_compiler.h"

static void *code_cache_pool = NULL;
static uint32 code_cache_pool_size = 0;
static mem_allocator_t code_cache_pool_allocator = NULL;

bool
jit_code_cache_init(uint32 code_cache_size)
{
    int map_prot = MMAP_PROT_READ | MMAP_PROT_WRITE | MMAP_PROT_EXEC;
    int map_flags = MMAP_MAP_NONE;

    if (!(code_cache_pool =
              os_mmap(NULL, code_cache_size, map_prot, map_flags))) {
        return false;
    }

    if (!(code_cache_pool_allocator =
              mem_allocator_create(code_cache_pool, code_cache_size))) {
        os_munmap(code_cache_pool, code_cache_size);
        code_cache_pool = NULL;
        return false;
    }

    code_cache_pool_size = code_cache_size;
    return true;
}

void
jit_code_cache_destroy()
{
    mem_allocator_destroy(code_cache_pool_allocator);
    os_munmap(code_cache_pool, code_cache_pool_size);
}

void *
jit_code_cache_alloc(uint32 size)
{
    return mem_allocator_malloc(code_cache_pool_allocator, size);
}

void
jit_code_cache_free(void *ptr)
{
    if (ptr)
        mem_allocator_free(code_cache_pool_allocator, ptr);
}

bool
jit_pass_register_jitted_code(JitCompContext *cc)
{
    uint32 jit_func_idx =
        cc->cur_wasm_func_idx - cc->cur_wasm_module->import_function_count;
    cc->cur_wasm_func->fast_jit_jitted_code = cc->jitted_addr_begin;
    cc->cur_wasm_module->fast_jit_func_ptrs[jit_func_idx] =
        cc->jitted_addr_begin;
    return true;
}
