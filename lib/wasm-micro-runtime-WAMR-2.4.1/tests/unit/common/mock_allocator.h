/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#pragma once

#include "wasm_export.h"
#include <functional>

template<int MaxAllocCount>
class MockAllocator
{
  private:
    RuntimeInitArgs init_args;

  public:
    MockAllocator()
    {
        memset(&init_args, 0, sizeof(RuntimeInitArgs));

        init_args.mem_alloc_type = Alloc_With_Allocator;
        init_args.mem_alloc_option.allocator.malloc_func = (void *)my_malloc;
        init_args.mem_alloc_option.allocator.realloc_func = (void *)realloc;
        init_args.mem_alloc_option.allocator.free_func = (void *)free;

        /* Set count to INT32_MIN so the initialization will not fail */
        alloc_count = INT32_MIN;

        wasm_runtime_full_init(&init_args);
        reset_count();
    }

    ~MockAllocator() { wasm_runtime_destroy(); }

    void reset_count() { alloc_count = 0; }

  protected:
    static int32_t alloc_count;
    static void *my_malloc(int32_t size)
    {
        if (alloc_count >= MaxAllocCount) {
            return nullptr;
        }

        alloc_count++;

        return malloc(size);
    }
};

template<int MaxAllocCount>
int32_t MockAllocator<MaxAllocCount>::alloc_count = 0;

class DumpAllocUsage : public MockAllocator<INT32_MAX>
{
  public:
    DumpAllocUsage()
      : MockAllocator<INT32_MAX>()
    {}

    ~DumpAllocUsage()
    {
        std::cout << "Alloc usage count: " << alloc_count << std::endl;
    }
};

template<int AllocRequired>
void
LIMIT_MALLOC_COUNT(std::function<void()> func)
{
    {
        MockAllocator<AllocRequired> allocator;
        func();
    }

    if (AllocRequired > 1)
        LIMIT_MALLOC_COUNT<AllocRequired - 1>(func);
}

template<>
void
LIMIT_MALLOC_COUNT<0>(std::function<void()> func)
{
    {
        MockAllocator<0> allocator;
        func();
    }
}
