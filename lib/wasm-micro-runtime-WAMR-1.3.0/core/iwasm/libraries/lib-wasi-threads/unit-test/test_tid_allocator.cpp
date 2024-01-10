/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <gtest/gtest.h>

#include "tid_allocator.h"

#include <stdint.h>

class TidAllocatorTest : public ::testing::Test
{
  protected:
    void SetUp() override { ASSERT_TRUE(tid_allocator_init(&_allocator)); }

    void TearDown() override { tid_allocator_deinit(&_allocator); }

    TidAllocator _allocator;
};

static bool
is_tid_valid(int32 tid)
{
    /* See: https://github.com/WebAssembly/wasi-threads#design-choice-thread-ids
     */
    return tid >= TID_MIN && tid <= TID_MAX;
}

TEST_F(TidAllocatorTest, BasicTest)
{
    int32 tid = tid_allocator_get_tid(&_allocator);

    ASSERT_TRUE(is_tid_valid(tid));
}

TEST_F(TidAllocatorTest, ShouldFailOnAllocatingMoreThanAllowedThreadIDs)
{
    int32 last_tid = 0;
    for (int32 i = 0; i < TID_MAX + 1; i++) {
        last_tid = tid_allocator_get_tid(&_allocator);
        if (last_tid < 0) {
            break;
        }
        ASSERT_TRUE(is_tid_valid(last_tid));
    }

    ASSERT_LT(last_tid, 0);
}

TEST_F(TidAllocatorTest, ShouldAllocateMoreThanAllowedTIDsIfOldTIDsAreReleased)
{
    int32 last_tid = 0;
    for (int32 i = 0; i < TID_MAX + 1; i++) {
        if (last_tid != 0) {
            tid_allocator_release_tid(&_allocator, last_tid);
        }

        last_tid = tid_allocator_get_tid(&_allocator);
        ASSERT_TRUE(is_tid_valid(last_tid));
    }
}
