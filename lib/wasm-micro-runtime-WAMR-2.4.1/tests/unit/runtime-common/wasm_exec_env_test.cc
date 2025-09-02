/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "test_helper.h"
#include "gtest/gtest.h"

#include "wasm_exec_env.h"

class wasm_exec_env_test_suite : public testing::Test
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

TEST_F(wasm_exec_env_test_suite, wasm_exec_env_create)
{
    EXPECT_EQ(nullptr, wasm_exec_env_create(nullptr, 0));
}

TEST_F(wasm_exec_env_test_suite, wasm_exec_env_create_internal)
{
    EXPECT_EQ(nullptr, wasm_exec_env_create_internal(nullptr, UINT32_MAX));
}

TEST_F(wasm_exec_env_test_suite, wasm_exec_env_pop_jmpbuf)
{
    WASMExecEnv exec_env;

    exec_env.jmpbuf_stack_top = nullptr;
    EXPECT_EQ(nullptr, wasm_exec_env_pop_jmpbuf(&exec_env));
}
