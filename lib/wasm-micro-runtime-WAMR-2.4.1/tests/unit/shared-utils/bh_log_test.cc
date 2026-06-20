/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "test_helper.h"
#include "gtest/gtest.h"

#include "bh_log.h"
#include "stdio.h"

class bh_log_test_suite : public testing::Test
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

#define TEST_STR "This is a test."

TEST_F(bh_log_test_suite, bh_log_set_verbose_level)
{
    bh_log_set_verbose_level(BH_LOG_LEVEL_DEBUG);
}

TEST_F(bh_log_test_suite, bh_print_time)
{
    std::string captured;

    bh_log_set_verbose_level(BH_LOG_LEVEL_WARNING);
    bh_print_time(TEST_STR);

    bh_log_set_verbose_level(BH_LOG_LEVEL_DEBUG);
    testing::internal::CaptureStdout();
    bh_print_time(TEST_STR);
    captured = testing::internal::GetCapturedStdout();
    EXPECT_EQ(0, strncmp(TEST_STR, captured.c_str(), strlen(TEST_STR)));

    testing::internal::CaptureStdout();
    bh_print_time(TEST_STR);
    captured = testing::internal::GetCapturedStdout();
    EXPECT_EQ(0, strncmp(TEST_STR, captured.c_str(), strlen(TEST_STR)));
}

TEST_F(bh_log_test_suite, bh_log)
{
    std::string captured;

    bh_log_set_verbose_level(BH_LOG_LEVEL_DEBUG);
    testing::internal::CaptureStdout();
    bh_log(BH_LOG_LEVEL_FATAL, __FILE__, __LINE__, TEST_STR);
    captured = testing::internal::GetCapturedStdout();
    EXPECT_PRED_FORMAT2(::testing::IsSubstring, TEST_STR, captured);

    testing::internal::CaptureStdout();
    bh_log(BH_LOG_LEVEL_ERROR, __FILE__, __LINE__, TEST_STR);
    captured = testing::internal::GetCapturedStdout();
    EXPECT_PRED_FORMAT2(::testing::IsSubstring, TEST_STR, captured);

    testing::internal::CaptureStdout();
    bh_log(BH_LOG_LEVEL_WARNING, __FILE__, __LINE__, TEST_STR);
    captured = testing::internal::GetCapturedStdout();
    EXPECT_PRED_FORMAT2(::testing::IsSubstring, TEST_STR, captured);

    testing::internal::CaptureStdout();
    bh_log(BH_LOG_LEVEL_DEBUG, __FILE__, __LINE__, TEST_STR);
    captured = testing::internal::GetCapturedStdout();
    EXPECT_PRED_FORMAT2(::testing::IsSubstring, TEST_STR, captured);

    // log_verbose_level == BH_LOG_LEVEL_DEBUG, so BH_LOG_LEVEL_VERBOSE is not
    // printed.
    testing::internal::CaptureStdout();
    bh_log(BH_LOG_LEVEL_VERBOSE, __FILE__, __LINE__, TEST_STR);
    captured = testing::internal::GetCapturedStdout();
    EXPECT_EQ(nullptr, strstr(captured.c_str(), TEST_STR));

    // After set log_verbose_level = BH_LOG_LEVEL_VERBOSE, BH_LOG_LEVEL_VERBOSE
    // can be printed.
    bh_log_set_verbose_level(BH_LOG_LEVEL_VERBOSE);
    testing::internal::CaptureStdout();
    bh_log(BH_LOG_LEVEL_VERBOSE, __FILE__, __LINE__, TEST_STR);
    captured = testing::internal::GetCapturedStdout();
    EXPECT_PRED_FORMAT2(::testing::IsSubstring, TEST_STR, captured);
}
