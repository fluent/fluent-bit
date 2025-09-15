/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "test_helper.h"
#include "gtest/gtest.h"

#include "bh_common.h"

class bh_common_test_suite : public testing::Test
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

  public:
    WAMRRuntimeRAII<512 * 1024> runtime;
};

#define STR_TEST "test"

TEST_F(bh_common_test_suite, wa_strdup)
{
    EXPECT_EQ(nullptr, wa_strdup(nullptr));
    EXPECT_NE(nullptr, wa_strdup(STR_TEST));
}

TEST_F(bh_common_test_suite, b_strcpy_s)
{
    char dest[10] = { 0 };

    EXPECT_EQ(0, b_strcpy_s(dest, sizeof(dest), STR_TEST));

    // Test abnormal cases.
    EXPECT_EQ(-1, b_strcpy_s(nullptr, 0, nullptr));
    EXPECT_EQ(-1, b_strcpy_s(dest, sizeof(dest), nullptr));
    EXPECT_EQ(-1, b_strcpy_s(dest, 0, STR_TEST));
}

TEST_F(bh_common_test_suite, b_strcat_s)
{
    char dest[10] = { 0 };

    EXPECT_EQ(0, b_strcat_s(dest, sizeof(dest), STR_TEST));

    // Test abnormal cases.
    EXPECT_EQ(-1, b_strcat_s(nullptr, 0, nullptr));
    EXPECT_EQ(-1, b_strcat_s(dest, sizeof(dest), nullptr));
    EXPECT_EQ(-1, b_strcat_s(dest, 0, STR_TEST));
}

TEST_F(bh_common_test_suite, bh_strdup)
{
    EXPECT_NE(nullptr, bh_strdup(STR_TEST));
    EXPECT_EQ(nullptr, bh_strdup(nullptr));
}

TEST_F(bh_common_test_suite, b_memmove_s)
{
    char dest[10] = { 0 };

    EXPECT_EQ(0, b_memmove_s(dest, sizeof(dest), STR_TEST, sizeof(STR_TEST)));

    // Test abnormal cases.
    EXPECT_EQ(0, b_memmove_s(dest, sizeof(dest), STR_TEST, 0));
    EXPECT_EQ(0, b_memmove_s(nullptr, sizeof(dest), STR_TEST, 0));

    EXPECT_EQ(0, b_memmove_s(dest, sizeof(dest), nullptr, 0));
    EXPECT_EQ(-1, b_memmove_s(dest, sizeof(dest), STR_TEST, sizeof(dest) + 1));
}

TEST_F(bh_common_test_suite, b_memcpy_s)
{
    char dest[10] = { 0 };

    EXPECT_EQ(0, b_memcpy_s(dest, sizeof(dest), STR_TEST, sizeof(STR_TEST)));

    // Test abnormal cases.
    EXPECT_EQ(0, b_memcpy_s(dest, sizeof(dest), STR_TEST, 0));
    EXPECT_EQ(-1,
              b_memcpy_s(nullptr, sizeof(dest), STR_TEST, sizeof(STR_TEST)));
    EXPECT_EQ(-1, b_memcpy_s(dest, sizeof(dest), nullptr, sizeof(STR_TEST)));
    EXPECT_EQ(-1, b_memcpy_s(dest, sizeof(dest), STR_TEST, sizeof(dest) + 1));
}
