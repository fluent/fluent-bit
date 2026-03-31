/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "test_helper.h"
#include "gtest/gtest.h"

#include "bh_assert.h"

class bh_assert_test_suite : public testing::Test
{
  protected:
    // You should make the members protected s.t. they can be
    // accessed from sub-classes.

    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    virtual void SetUp() {}

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    virtual void TearDown() {}
};

TEST_F(bh_assert_test_suite, bh_assert_internal)
{
    bh_assert_internal(6, "file_name_test", 6, "expr_string_test");

    // Test abnormal cases.
    EXPECT_DEATH(bh_assert_internal(0, "file_name_test", 1, "expr_string_test"),
                 "");
    EXPECT_DEATH(bh_assert_internal(0, nullptr, 2, "expr_string_test"), "");
    EXPECT_DEATH(bh_assert_internal(0, "file_name_test", 3, nullptr), "");
}
