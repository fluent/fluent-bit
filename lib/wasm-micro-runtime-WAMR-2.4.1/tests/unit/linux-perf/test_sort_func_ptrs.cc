/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_runtime.h"
#include <cstdint>
#include <gtest/gtest.h>
#include <dlfcn.h>

extern "C" {
// TODO: won't work, for non static function create_perf_map have goto statement jump to label ‘quit’
// #include "aot_perf_map.c"

// simply copy the function
struct func_info {
    uint32 idx;
    void *ptr;
};

static int
compare_func_ptrs(const void *f1, const void *f2)
{
    return (intptr_t)((struct func_info *)f1)->ptr
           - (intptr_t)((struct func_info *)f2)->ptr;
}

static struct func_info *
sort_func_ptrs(const AOTModule *module, char *error_buf, uint32 error_buf_size)
{
    uint64 content_len;
    struct func_info *sorted_func_ptrs;
    unsigned i;

    content_len = (uint64)sizeof(struct func_info) * module->func_count;
    sorted_func_ptrs = wasm_runtime_malloc(content_len);
    if (!sorted_func_ptrs) {
        snprintf(error_buf, error_buf_size,
                 "allocate memory failed when creating perf map");
        return NULL;
    }

    for (i = 0; i < module->func_count; i++) {
        sorted_func_ptrs[i].idx = i;
        sorted_func_ptrs[i].ptr = module->func_ptrs[i];
    }

    qsort(sorted_func_ptrs, module->func_count, sizeof(struct func_info),
          compare_func_ptrs);

    return sorted_func_ptrs;
}

void *
wasm_runtime_malloc(unsigned int size)
{
    return malloc(size);
}

void
wasm_runtime_free(void* ptr)
{
    return free(ptr);
}

int
b_memcpy_s(void *s1, unsigned int s1max, const void *s2, unsigned int n)
{
    return memcpy(s1, s2, n);
}
}

TEST(TestSortFuncPtrs, qsort)
{
    void *p = sort_func_ptrs;
    ASSERT_NE(p, nullptr);

    void *funcs[5] = {
        (void *)0x1024, (void *)0x10, (void *)0x24, (void *)0x102, (void *)0x4,
    };

    AOTModule module = { 0 };
    module.func_count = 5;
    module.func_ptrs = &funcs[0];

    char buf[64] = { 0 };

    struct func_info *sorted_funcs = sort_func_ptrs(&module, buf, 64);
    // sorted
    ASSERT_EQ((uintptr_t)(sorted_funcs[0].ptr), 0x4);
    ASSERT_EQ((uintptr_t)(sorted_funcs[1].ptr), 0x10);
    ASSERT_EQ((uintptr_t)(sorted_funcs[2].ptr), 0x24);
    ASSERT_EQ((uintptr_t)(sorted_funcs[3].ptr), 0x102);
    ASSERT_EQ((uintptr_t)(sorted_funcs[4].ptr), 0x1024);

    ASSERT_EQ(sorted_funcs[0].idx, 4);
    ASSERT_EQ(sorted_funcs[1].idx, 1);
    ASSERT_EQ(sorted_funcs[2].idx, 2);
    ASSERT_EQ(sorted_funcs[3].idx, 3);
    ASSERT_EQ(sorted_funcs[4].idx, 0);

    // don't change input
    ASSERT_EQ((uintptr_t)(funcs[0]), 0x1024);
    ASSERT_EQ((uintptr_t)(funcs[1]), 0x10);
    ASSERT_EQ((uintptr_t)(funcs[2]), 0x24);
    ASSERT_EQ((uintptr_t)(funcs[3]), 0x102);
    ASSERT_EQ((uintptr_t)(funcs[4]), 0x4);

    wasm_runtime_free(sorted_funcs);
}