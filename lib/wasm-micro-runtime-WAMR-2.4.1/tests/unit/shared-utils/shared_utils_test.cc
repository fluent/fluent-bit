/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_platform.h"
#include "test_helper.h"
#include "gtest/gtest.h"

/* Test APIs under wamr/core/shared/utils */

class SharedUtilsTest : public testing::Test
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

TEST_F(SharedUtilsTest, bh_list) {}
