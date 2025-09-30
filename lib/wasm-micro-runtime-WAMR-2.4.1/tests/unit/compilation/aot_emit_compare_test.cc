/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "gtest/gtest.h"
#include "aot_emit_compare.h"

class compilation_aot_emit_compare_test : public testing::Test
{
  protected:
    virtual void SetUp() {}
    virtual void TearDown() {}

  public:
};

TEST_F(compilation_aot_emit_compare_test, aot_compile_op_i32_compare)
{
    AOTCompContext comp_ctx = { 0 };
    AOTFuncContext func_ctx = { 0 };
    IntCond cond = INT_EQZ;
    IntCond cond1 = INT_EQZ;

    /* false cond = 0 */
    EXPECT_FALSE(aot_compile_op_i32_compare(&comp_ctx, &func_ctx, cond));

    /* false cond = -1 */
    EXPECT_FALSE(
        aot_compile_op_i32_compare(&comp_ctx, &func_ctx, (IntCond)(-1)));

    /* false cond = [1:10] || [11:100] */
    for (int i = 0; i < 0xFFFF; i++) {
        /* Generate random number range：[m,n] int a=m+rand()%(n-m+1); */
        cond = (IntCond)(1 + (rand() % (INT_GE_U - 1 + 1)));
        cond1 = (IntCond)((INT_GE_U + 1) + (rand() % (100 - 1 + 1)));
        EXPECT_FALSE(aot_compile_op_i32_compare(&comp_ctx, &func_ctx, cond));
        EXPECT_FALSE(aot_compile_op_i32_compare(&comp_ctx, &func_ctx, cond1));
    }
}

TEST_F(compilation_aot_emit_compare_test, aot_compile_op_i64_compare)
{
    AOTCompContext comp_ctx = { 0 };
    AOTFuncContext func_ctx = { 0 };
    IntCond cond = INT_EQZ;
    IntCond cond1 = INT_EQZ;

    /* false cond = 0 */
    // EXPECT_FALSE(aot_compile_op_i64_compare(&comp_ctx, &func_ctx, cond));

    /* false cond = -1 */
    EXPECT_FALSE(
        aot_compile_op_i64_compare(&comp_ctx, &func_ctx, (IntCond)(-1)));

    /* false cond = [1:10] || [11:100] */
    for (int i = 0; i < 0xFFFF; i++) {
        /* Generate random number range：[m,n] int a=m+rand()%(n-m+1); */
        cond = (IntCond)(1 + (rand() % (INT_GE_U - 1 + 1)));
        cond1 = (IntCond)((INT_GE_U + 1) + (rand() % (100 - 1 + 1)));
        EXPECT_FALSE(aot_compile_op_i64_compare(&comp_ctx, &func_ctx, cond));
        EXPECT_FALSE(aot_compile_op_i64_compare(&comp_ctx, &func_ctx, cond1));
    }
}

TEST_F(compilation_aot_emit_compare_test, aot_compile_op_f32_compare)
{
    AOTCompContext comp_ctx = { 0 };
    AOTFuncContext func_ctx = { 0 };
    FloatCond cond = FLOAT_EQ;
    FloatCond cond1 = FLOAT_EQ;

    /* false cond = 0 */
    EXPECT_FALSE(aot_compile_op_f32_compare(&comp_ctx, &func_ctx, cond));

    /* false cond = -1 */
    EXPECT_FALSE(
        aot_compile_op_f32_compare(&comp_ctx, &func_ctx, (FloatCond)(-1)));

    /* false cond = [1:10] || [7:100] */
    for (int i = 0; i < 0xFFFF; i++) {
        /* Generate random number range：[m,n] int a=m+rand()%(n-m+1); */
        cond = (FloatCond)(1 + (rand() % (FLOAT_UNO - 1 + 1)));
        cond1 = (FloatCond)((FLOAT_UNO + 1) + (rand() % (100 - 1 + 1)));
        EXPECT_FALSE(aot_compile_op_f32_compare(&comp_ctx, &func_ctx, cond));
        EXPECT_FALSE(aot_compile_op_f32_compare(&comp_ctx, &func_ctx, cond1));
    }
}

TEST_F(compilation_aot_emit_compare_test, aot_compile_op_f64_compare)
{
    AOTCompContext comp_ctx = { 0 };
    AOTFuncContext func_ctx = { 0 };
    FloatCond cond = FLOAT_EQ;
    FloatCond cond1 = FLOAT_EQ;

    /* false cond = 0 */
    EXPECT_FALSE(aot_compile_op_f64_compare(&comp_ctx, &func_ctx, cond));

    /* false cond = -1 */
    EXPECT_FALSE(
        aot_compile_op_f64_compare(&comp_ctx, &func_ctx, (FloatCond)(-1)));

    /* false cond = [1:10] || [7:100] */
    for (int i = 0; i < 0xFFFF; i++) {
        /* Generate random number range：[m,n] int a=m+rand()%(n-m+1); */
        cond = (FloatCond)(1 + (rand() % (FLOAT_UNO - 1 + 1)));
        cond1 = (FloatCond)((FLOAT_UNO + 1) + (rand() % (100 - 1 + 1)));
        EXPECT_FALSE(aot_compile_op_f64_compare(&comp_ctx, &func_ctx, cond));
        EXPECT_FALSE(aot_compile_op_f64_compare(&comp_ctx, &func_ctx, cond1));
    }
}
