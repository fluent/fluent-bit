/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <limits.h>
#include "gtest/gtest.h"
#include "wasm_export.h"
#include "bh_platform.h"
#include "aot_llvm.h"
#include "aot_intrinsic.h"
#include "aot.h"

#define G_INTRINSIC_COUNT (50u)
#define CONS(num) ("f##num##.const")

const char *llvm_intrinsic_tmp[G_INTRINSIC_COUNT] = {
    "llvm.experimental.constrained.fadd.f32",
    "llvm.experimental.constrained.fadd.f64",
    "llvm.experimental.constrained.fsub.f32",
    "llvm.experimental.constrained.fsub.f64",
    "llvm.experimental.constrained.fmul.f32",
    "llvm.experimental.constrained.fmul.f64",
    "llvm.experimental.constrained.fdiv.f32",
    "llvm.experimental.constrained.fdiv.f64",
    "llvm.fabs.f32",
    "llvm.fabs.f64",
    "llvm.ceil.f32",
    "llvm.ceil.f64",
    "llvm.floor.f32",
    "llvm.floor.f64",
    "llvm.trunc.f32",
    "llvm.trunc.f64",
    "llvm.rint.f32",
    "llvm.rint.f64",
    "llvm.sqrt.f32",
    "llvm.sqrt.f64",
    "llvm.copysign.f32",
    "llvm.copysign.f64",
    "llvm.minnum.f32",
    "llvm.minnum.f64",
    "llvm.maxnum.f32",
    "llvm.maxnum.f64",
    "llvm.ctlz.i32",
    "llvm.ctlz.i64",
    "llvm.cttz.i32",
    "llvm.cttz.i64",
    "llvm.ctpop.i32",
    "llvm.ctpop.i64",
    "f64_convert_i32_s",
    "f64_convert_i32_u",
    "f32_convert_i32_s",
    "f32_convert_i32_u",
    "f64_convert_i64_s",
    "f64_convert_i64_u",
    "f32_convert_i64_s",
    "f32_convert_i64_u",
    "i32_trunc_f32_u",
    "i32_trunc_f32_s",
    "i32_trunc_f64_u",
    "i32_trunc_f64_s",
    "f32_demote_f64",
    "f64_promote_f32",
    "f32_cmp",
    "f64_cmp",
    "f32.const",
    "f64.const",
};

uint64 g_intrinsic_flag[G_INTRINSIC_COUNT] = {
    AOT_INTRINSIC_FLAG_F32_FADD,     AOT_INTRINSIC_FLAG_F64_FADD,
    AOT_INTRINSIC_FLAG_F32_FSUB,     AOT_INTRINSIC_FLAG_F64_FSUB,
    AOT_INTRINSIC_FLAG_F32_FMUL,     AOT_INTRINSIC_FLAG_F64_FMUL,
    AOT_INTRINSIC_FLAG_F32_FDIV,     AOT_INTRINSIC_FLAG_F64_FDIV,
    AOT_INTRINSIC_FLAG_F32_FABS,     AOT_INTRINSIC_FLAG_F64_FABS,
    AOT_INTRINSIC_FLAG_F32_CEIL,     AOT_INTRINSIC_FLAG_F64_CEIL,
    AOT_INTRINSIC_FLAG_F32_FLOOR,    AOT_INTRINSIC_FLAG_F64_FLOOR,
    AOT_INTRINSIC_FLAG_F32_TRUNC,    AOT_INTRINSIC_FLAG_F64_TRUNC,
    AOT_INTRINSIC_FLAG_F32_RINT,     AOT_INTRINSIC_FLAG_F64_RINT,
    AOT_INTRINSIC_FLAG_F32_SQRT,     AOT_INTRINSIC_FLAG_F64_SQRT,
    AOT_INTRINSIC_FLAG_F32_COPYSIGN, AOT_INTRINSIC_FLAG_F64_COPYSIGN,
    AOT_INTRINSIC_FLAG_F32_MIN,      AOT_INTRINSIC_FLAG_F64_MIN,
    AOT_INTRINSIC_FLAG_F32_MAX,      AOT_INTRINSIC_FLAG_F64_MAX,
    AOT_INTRINSIC_FLAG_I32_CLZ,      AOT_INTRINSIC_FLAG_I64_CLZ,
    AOT_INTRINSIC_FLAG_I32_CTZ,      AOT_INTRINSIC_FLAG_I64_CTZ,
    AOT_INTRINSIC_FLAG_I32_POPCNT,   AOT_INTRINSIC_FLAG_I64_POPCNT,
    AOT_INTRINSIC_FLAG_I32_TO_F64,   AOT_INTRINSIC_FLAG_U32_TO_F64,
    AOT_INTRINSIC_FLAG_I32_TO_F32,   AOT_INTRINSIC_FLAG_U32_TO_F32,
    AOT_INTRINSIC_FLAG_I32_TO_F64,   AOT_INTRINSIC_FLAG_U64_TO_F64,
    AOT_INTRINSIC_FLAG_I64_TO_F32,   AOT_INTRINSIC_FLAG_U64_TO_F32,
    AOT_INTRINSIC_FLAG_F32_TO_U32,   AOT_INTRINSIC_FLAG_F32_TO_I32,
    AOT_INTRINSIC_FLAG_F64_TO_U32,   AOT_INTRINSIC_FLAG_F64_TO_I32,
    AOT_INTRINSIC_FLAG_F64_TO_F32,   AOT_INTRINSIC_FLAG_F32_TO_F64,
    AOT_INTRINSIC_FLAG_F32_CMP,      AOT_INTRINSIC_FLAG_F64_CMP,
    AOT_INTRINSIC_FLAG_F32_CONST,    AOT_INTRINSIC_FLAG_F64_CONST,
};

// To use a test fixture, derive a class from testing::Test.
class AOTTest : public testing::Test
{
  protected:
    // You should make the members protected s.t. they can be
    // accessed from sub-classes.

    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    virtual void SetUp()
    {
        memset(&init_args, 0, sizeof(RuntimeInitArgs));

        init_args.mem_alloc_type = Alloc_With_Pool;
        init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
        init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

        ASSERT_EQ(wasm_runtime_full_init(&init_args), true);
    }

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    virtual void TearDown() { wasm_runtime_destroy(); }

  public:
    char global_heap_buf[512 * 1024];
    RuntimeInitArgs init_args;
};

TEST_F(AOTTest, aot_value_stack_push_pop)
{
    AOTValueStack *stack;
    AOTValue *value1, *value2, *value3;
    AOTCompContext comp_ctx = { 0 };

    stack = (AOTValueStack *)wasm_runtime_malloc(sizeof(AOTValueStack));
    EXPECT_TRUE(stack != NULL);

    memset(stack, 0, sizeof(AOTValueStack));

    value1 = (AOTValue *)wasm_runtime_malloc(sizeof(AOTValue));
    EXPECT_TRUE(value1 != NULL);

    memset(value1, 0, sizeof(AOTValue));
    value1->type = VALUE_TYPE_I32;

    aot_value_stack_push(&comp_ctx, stack, value1);
    EXPECT_EQ(stack->value_list_head, value1);
    EXPECT_EQ(stack->value_list_end, value1);

    value2 = (AOTValue *)wasm_runtime_malloc(sizeof(AOTValue));
    EXPECT_TRUE(value2 != NULL);

    memset(value2, 0, sizeof(AOTValue));
    value2->type = VALUE_TYPE_I64;

    aot_value_stack_push(&comp_ctx, stack, value2);
    EXPECT_EQ(stack->value_list_head, value1);
    EXPECT_EQ(stack->value_list_end, value2);
    EXPECT_EQ(value2->prev, value1);

    value3 = aot_value_stack_pop(&comp_ctx, stack);
    EXPECT_EQ(value3, value2);
    EXPECT_EQ(stack->value_list_head, value1);
    EXPECT_EQ(stack->value_list_end, value1);
    EXPECT_TRUE(value3->prev == NULL);

    aot_value_stack_destroy(&comp_ctx, stack);
    wasm_runtime_free(value3);
    wasm_runtime_free(stack);
}

TEST_F(AOTTest, aot_block_stack_push_pop)
{
    AOTBlockStack *stack;
    AOTBlock *block1, *block2, *block3;
    AOTCompContext comp_ctx = { 0 };

    stack = (AOTBlockStack *)wasm_runtime_malloc(sizeof(AOTBlockStack));
    EXPECT_TRUE(stack != NULL);

    memset(stack, 0, sizeof(AOTBlockStack));

    block1 = (AOTBlock *)wasm_runtime_malloc(sizeof(AOTBlock));
    EXPECT_TRUE(block1 != NULL);

    memset(block1, 0, sizeof(AOTBlock));
    block1->label_type = LABEL_TYPE_LOOP;

    aot_block_stack_push(stack, block1);
    EXPECT_EQ(stack->block_list_head, block1);
    EXPECT_EQ(stack->block_list_end, block1);

    block2 = (AOTBlock *)wasm_runtime_malloc(sizeof(AOTBlock));
    EXPECT_TRUE(block2 != NULL);

    memset(block2, 0, sizeof(AOTBlock));
    block2->label_type = LABEL_TYPE_IF;

    aot_block_stack_push(stack, block2);
    EXPECT_EQ(stack->block_list_head, block1);
    EXPECT_EQ(stack->block_list_end, block2);
    EXPECT_EQ(block2->prev, block1);

    block3 = aot_block_stack_pop(stack);
    EXPECT_EQ(block3, block2);
    EXPECT_EQ(stack->block_list_head, block1);
    EXPECT_EQ(stack->block_list_end, block1);
    EXPECT_TRUE(block3->prev == NULL);

    aot_block_stack_destroy(&comp_ctx, stack);
    wasm_runtime_free(block3);
    wasm_runtime_free(stack);
}

TEST_F(AOTTest, aot_intrinsic_fadd_f32)
{
    float32 a = 1.0;
    float32 b = 1.0;
    EXPECT_EQ(aot_intrinsic_fadd_f32(a, b), (a + b));

    a = -1.0;
    b = -1.0;
    EXPECT_EQ(aot_intrinsic_fadd_f32(a, b), (a + b));
}

TEST_F(AOTTest, aot_intrinsic_fadd_f64)
{
    float64 a = 1.0;
    float64 b = 1.0;
    EXPECT_EQ(aot_intrinsic_fadd_f64(a, b), (a + b));

    a = -1.0;
    b = -1.0;
    EXPECT_EQ(aot_intrinsic_fadd_f64(a, b), (a + b));
}

TEST_F(AOTTest, aot_intrinsic_fsub_f32)
{
    float32 a = 1.0;
    float32 b = 1.0;
    EXPECT_EQ(aot_intrinsic_fsub_f32(a, b), (a - b));

    a = -1.0;
    b = -1.0;
    EXPECT_EQ(aot_intrinsic_fsub_f32(a, b), (a - b));
}

TEST_F(AOTTest, aot_intrinsic_fsub_f64)
{
    float64 a = 1.0;
    float64 b = 1.0;
    EXPECT_EQ(aot_intrinsic_fsub_f64(a, b), (a - b));

    a = -1.0;
    b = -1.0;
    EXPECT_EQ(aot_intrinsic_fsub_f64(a, b), (a - b));
}

TEST_F(AOTTest, aot_intrinsic_fmul_f32)
{
    float32 a = 1.0;
    float32 b = 1.0;
    EXPECT_EQ(aot_intrinsic_fmul_f32(a, b), (a * b));

    a = -1.0;
    b = -1.0;
    EXPECT_EQ(aot_intrinsic_fmul_f32(a, b), (a * b));
}

TEST_F(AOTTest, aot_intrinsic_fmul_f64)
{
    float64 a = 1.0;
    float64 b = 1.0;
    EXPECT_EQ(aot_intrinsic_fmul_f64(a, b), (a * b));

    a = -1.0;
    b = -1.0;
    EXPECT_EQ(aot_intrinsic_fmul_f64(a, b), (a * b));
}

TEST_F(AOTTest, aot_intrinsic_fdiv_f32)
{
    float32 a = 1.0;
    float32 b = 1.0;
    EXPECT_EQ(aot_intrinsic_fdiv_f32(a, b), (a / b));

    a = -1.0;
    b = -1.0;
    EXPECT_EQ(aot_intrinsic_fdiv_f32(a, b), (a / b));

    a = -1.0;
    b = 0.0;
    EXPECT_EQ(aot_intrinsic_fdiv_f32(a, b), (a / b));
}

TEST_F(AOTTest, aot_intrinsic_fdiv_f64)
{
    float64 a = 1.0;
    float64 b = 1.0;
    EXPECT_EQ(aot_intrinsic_fdiv_f64(a, b), (a / b));

    a = -1.0;
    b = -1.0;
    EXPECT_EQ(aot_intrinsic_fdiv_f64(a, b), (a / b));

    a = -1.0;
    b = 0.0;
    EXPECT_EQ(aot_intrinsic_fdiv_f64(a, b), (a / b));
}

TEST_F(AOTTest, aot_intrinsic_fabs_f32)
{
    float32 a = 1.0;
    EXPECT_EQ(aot_intrinsic_fabs_f32(a), fabs(a));

    a = -1.0;
    EXPECT_EQ(aot_intrinsic_fabs_f32(a), fabs(a));

    a = -1.5;
    EXPECT_EQ(aot_intrinsic_fabs_f32(a), fabs(a));
}

TEST_F(AOTTest, aot_intrinsic_fabs_f64)
{
    float64 a = 1.0;
    EXPECT_EQ(aot_intrinsic_fabs_f64(a), fabs(a));

    a = -1.0;
    EXPECT_EQ(aot_intrinsic_fabs_f64(a), fabs(a));

    a = -1.5;
    EXPECT_EQ(aot_intrinsic_fabs_f64(a), fabs(a));
}

TEST_F(AOTTest, aot_intrinsic_ceil_f32)
{
    float32 a = 1.0;
    EXPECT_EQ(aot_intrinsic_ceil_f32(a), ceilf(a));

    a = 1.1;
    EXPECT_EQ(aot_intrinsic_ceil_f32(a), 2);

    a = 1.9;
    EXPECT_EQ(aot_intrinsic_ceil_f32(a), 2);

    a = -1.9;
    EXPECT_EQ(aot_intrinsic_ceil_f32(a), -1);
}

TEST_F(AOTTest, aot_intrinsic_ceil_f64)
{
    float64 a = 1.0;
    EXPECT_EQ(aot_intrinsic_ceil_f64(a), ceil(a));

    a = 1.1;
    EXPECT_EQ(aot_intrinsic_ceil_f64(a), 2);

    a = 1.9;
    EXPECT_EQ(aot_intrinsic_ceil_f64(a), 2);

    a = -1.9;
    EXPECT_EQ(aot_intrinsic_ceil_f64(a), -1);
}

TEST_F(AOTTest, aot_intrinsic_floor_f32)
{
    float32 a = 1.0;
    EXPECT_EQ(aot_intrinsic_floor_f32(a), floorf(a));

    a = 1.1;
    EXPECT_EQ(aot_intrinsic_floor_f32(a), 1);

    a = 1.9;
    EXPECT_EQ(aot_intrinsic_floor_f32(a), 1);

    a = -1.9;
    EXPECT_EQ(aot_intrinsic_floor_f32(a), -2);
}

TEST_F(AOTTest, aot_intrinsic_floor_f64)
{
    float64 a = 1.0;
    EXPECT_EQ(aot_intrinsic_floor_f64(a), floor(a));

    a = 1.1;
    EXPECT_EQ(aot_intrinsic_floor_f64(a), 1);

    a = 1.9;
    EXPECT_EQ(aot_intrinsic_floor_f64(a), 1);

    a = -1.9;
    EXPECT_EQ(aot_intrinsic_floor_f64(a), -2);
}

TEST_F(AOTTest, aot_intrinsic_trunc_f32)
{
    float32 a = 1.0;
    EXPECT_EQ(aot_intrinsic_trunc_f32(a), trunc(a));

    a = 1.1;
    EXPECT_EQ(aot_intrinsic_trunc_f32(a), 1);

    a = 1.9;
    EXPECT_EQ(aot_intrinsic_trunc_f32(a), 1);

    a = -1.9;
    EXPECT_EQ(aot_intrinsic_trunc_f32(a), -1);
}

TEST_F(AOTTest, aot_intrinsic_trunc_f64)
{
    float64 a = 1.0;
    EXPECT_EQ(aot_intrinsic_trunc_f64(a), trunc(a));

    a = 1.1;
    EXPECT_EQ(aot_intrinsic_trunc_f64(a), 1);

    a = 1.9;
    EXPECT_EQ(aot_intrinsic_trunc_f64(a), 1);

    a = -1.9;
    EXPECT_EQ(aot_intrinsic_trunc_f64(a), -1);
}

TEST_F(AOTTest, aot_intrinsic_rint_f32)
{
    float32 a = 1.0;
    EXPECT_EQ(aot_intrinsic_rint_f32(a), rint(a));
    EXPECT_EQ(aot_intrinsic_rint_f32(a), 1);

    a = 1.1;
    EXPECT_EQ(aot_intrinsic_rint_f32(a), 1);

    a = 1.9;
    EXPECT_EQ(aot_intrinsic_rint_f32(a), 2);

    a = -1.9;
    EXPECT_EQ(aot_intrinsic_rint_f32(a), -2);
}

TEST_F(AOTTest, aot_intrinsic_rint_f64)
{
    float64 a = 1.0;
    EXPECT_EQ(aot_intrinsic_rint_f64(a), rint(a));
    EXPECT_EQ(aot_intrinsic_rint_f64(a), 1);

    a = 1.1;
    EXPECT_EQ(aot_intrinsic_rint_f64(a), 1);

    a = 1.9;
    EXPECT_EQ(aot_intrinsic_rint_f64(a), 2);

    a = -1.9;
    EXPECT_EQ(aot_intrinsic_rint_f64(a), -2);
}

TEST_F(AOTTest, aot_intrinsic_sqrt_f32)
{
    float32 a = 2.0;
    EXPECT_EQ(aot_intrinsic_sqrt_f32(a), sqrt(a));

    a = 2;
    EXPECT_EQ(aot_intrinsic_sqrt_f32(a), sqrt(a));
}

TEST_F(AOTTest, aot_intrinsic_sqrt_f64)
{
    float64 a = 2.0;
    EXPECT_EQ(aot_intrinsic_sqrt_f64(a), sqrt(a));

    a = 2;
    EXPECT_EQ(aot_intrinsic_sqrt_f64(a), sqrt(a));
}

TEST_F(AOTTest, aot_intrinsic_copysign_f32)
{
    float32 a = 20.0;
    float32 b = 2.0;

    EXPECT_EQ(aot_intrinsic_copysign_f32(a, b), fabs(a));

    b = 1.5;
    EXPECT_EQ(aot_intrinsic_copysign_f32(a, b), fabs(a));

    b = -2.0;
    EXPECT_EQ(aot_intrinsic_copysign_f32(a, b), -fabs(a));

    a = -20.0;
    b = -1.5;
    EXPECT_EQ(aot_intrinsic_copysign_f32(a, b), -fabs(a));
}

TEST_F(AOTTest, aot_intrinsic_copysign_f64)
{
    float64 a = 20.0;
    float64 b = 2.0;

    EXPECT_EQ(aot_intrinsic_copysign_f64(a, b), fabs(a));

    b = 1.5;
    EXPECT_EQ(aot_intrinsic_copysign_f64(a, b), fabs(a));

    b = -2.0;
    EXPECT_EQ(aot_intrinsic_copysign_f64(a, b), -fabs(a));

    a = -20.0;
    b = -1.5;
    EXPECT_EQ(aot_intrinsic_copysign_f64(a, b), -fabs(a));
}

TEST_F(AOTTest, aot_intrinsic_fmin_f32)
{
    float32 a = 1.2;
    float32 b = 2.5;

    EXPECT_EQ(aot_intrinsic_fmin_f32(a, b), a);

    a = -3;
    b = -1;
    EXPECT_EQ(aot_intrinsic_fmin_f32(a, b), a);

    b = 1;
    EXPECT_EQ(aot_intrinsic_fmin_f32('a', b), b);

    a = 3;
    EXPECT_EQ(aot_intrinsic_fmin_f32(a, 'b'), a);

    EXPECT_EQ(aot_intrinsic_fmin_f32('a', 'b'), 'a');

    EXPECT_EQ(aot_intrinsic_fmin_f32('b', 'c'), 'b');
    EXPECT_EQ(aot_intrinsic_fmin_f32('c', 'b'), 'b');

    EXPECT_EQ(aot_intrinsic_fmin_f32(true, 2.5), 1);
    EXPECT_EQ(aot_intrinsic_fmin_f32(1.0, false), 0);

    EXPECT_NE(aot_intrinsic_fmin_f32(sqrt(-1), 3), 3);
    EXPECT_NE(aot_intrinsic_fmin_f32(3, sqrt(-1)), 3);
}

TEST_F(AOTTest, aot_intrinsic_fmin_f64)
{
    float64 a = 1.00000000;
    float64 b = 3.00000000;

    EXPECT_EQ(aot_intrinsic_fmin_f64(a, b), a);

    EXPECT_EQ(aot_intrinsic_fmin_f64(-a, b), -a);

    EXPECT_EQ(aot_intrinsic_fmin_f64(-a, -b), -b);

    EXPECT_EQ(aot_intrinsic_fmin_f64(a, -b), -b);

    EXPECT_EQ(aot_intrinsic_fmin_f64(a, a), a);

    a = 0.0000;
    EXPECT_EQ(aot_intrinsic_fmin_f64(-a, -a), -a);
}

TEST_F(AOTTest, aot_intrinsic_fmax_f32)
{
    float32 a = 1.2;
    float32 b = 2.5;

    EXPECT_EQ(aot_intrinsic_fmax_f32(a, b), b);

    a = -3;
    b = -1;
    EXPECT_EQ(aot_intrinsic_fmax_f32(a, b), b);

    b = 1;
    EXPECT_EQ(aot_intrinsic_fmax_f32('a', b), 'a');

    a = 3;
    EXPECT_EQ(aot_intrinsic_fmax_f32(a, 'b'), 'b');

    EXPECT_EQ(aot_intrinsic_fmax_f32('a', 'b'), 'b');

    EXPECT_EQ(aot_intrinsic_fmax_f32(' ', 'b'), 'b');
    EXPECT_EQ(aot_intrinsic_fmax_f32('a', ' '), 'a');

    EXPECT_NE(aot_intrinsic_fmax_f32(sqrt(-1), 3), 3);
    EXPECT_NE(aot_intrinsic_fmax_f32(3, sqrt(-1)), 3);
}

TEST_F(AOTTest, aot_intrinsic_fmax_f64)
{
    float64 a = 1.00000000;
    float64 b = 3.00000000;

    EXPECT_EQ(aot_intrinsic_fmax_f64(a, b), b);

    EXPECT_EQ(aot_intrinsic_fmax_f64(-a, b), b);

    EXPECT_EQ(aot_intrinsic_fmax_f64(-a, -b), -a);

    EXPECT_EQ(aot_intrinsic_fmax_f64(a, -b), a);

    EXPECT_EQ(aot_intrinsic_fmax_f64(a, a), a);

    a = 0.0000;
    EXPECT_EQ(aot_intrinsic_fmax_f64(-a, -a), -a);

    EXPECT_EQ(aot_intrinsic_fmax_f64(-0, -0), -0);
}

TEST_F(AOTTest, aot_intrinsic_clz_i32)
{
    uint32 type = 0;
    uint32 data = 0;
    uint32 num = 0;

    EXPECT_EQ(aot_intrinsic_clz_i32(0), 32);

    for (uint32 i = 0; i < 0xFFFF; i++) {
        /* Generate random numbers [1,0xFFFFFFFF] */
        type = 1 + (rand() % (0xFFFFFFFF - 1 + 1));
        data = type;
        while (!(type & 0x80000000)) {
            num++;
            type <<= 1;
        }
        EXPECT_EQ(aot_intrinsic_clz_i32(data), num);
        num = 0;
    }

    EXPECT_EQ(aot_intrinsic_clz_i32(0xFFFFFFFF), 0);
}

TEST_F(AOTTest, aot_intrinsic_clz_i64)
{
    uint64 type = 0;
    uint64 data = 0;
    uint64 num = 0;

    EXPECT_EQ(aot_intrinsic_clz_i64(0), 64);

    for (uint32 i = 0; i < 0xFFFFF; i++) {
        /* Generate random numbers [1,0xFFFFFFFFFFFFFFFF] */
        type = 1 + (rand() % (0xFFFFFFFFFFFFFFFF - 1 + 1));
        data = type;
        while (!(type & 0x8000000000000000LL)) {
            num++;
            type <<= 1;
        }
        EXPECT_EQ(aot_intrinsic_clz_i64(data), num);
        num = 0;
    }

    EXPECT_EQ(aot_intrinsic_clz_i64(0xFFFFFFFFFFFFFFFF), 0);
}

TEST_F(AOTTest, ast_intrinsic_ctz_i32)
{
    uint32 type = 0;
    uint32 data = 0;
    uint32 num = 0;

    EXPECT_EQ(aot_intrinsic_ctz_i32(0), 32);

    for (uint32 i = 0; i < 0xFFFF; i++) {
        type = 1 + (rand() % (0xFFFFFFFF - 1 + 1));
        data = type;
        while (!(type & 1)) {
            num++;
            type >>= 1;
        }
        EXPECT_EQ(aot_intrinsic_ctz_i32(data), num);
        num = 0;
    }

    EXPECT_EQ(aot_intrinsic_ctz_i32(0xFFFFFFFF), 0);
}

TEST_F(AOTTest, ast_intrinsic_ctz_i64)
{
    uint64 type = 0;
    uint64 data = 0;
    uint64 num = 0;

    EXPECT_EQ(aot_intrinsic_ctz_i64(0), 64);

    for (uint32 i = 0; i < 0xFFFFF; i++) {
        type = 1 + (rand() % (0xFFFFFFFFFFFFFFFF - 1 + 1));
        data = type;
        while (!(type & 1)) {
            num++;
            type >>= 1;
        }
        EXPECT_EQ(aot_intrinsic_ctz_i64(data), num);
        num = 0;
    }

    EXPECT_EQ(aot_intrinsic_ctz_i64(0xFFFFFFFFFFFFFFFF), 0);
}

TEST_F(AOTTest, aot_intrinsic_popcnt_i32)
{
    uint32 data = 0;
    uint32 num = 0;
    uint32 temp = 0;

    EXPECT_EQ(aot_intrinsic_popcnt_i32(0), 0);

    for (uint32 i = 0; i < 0xFFFF; i++) {
        temp = 1 + (rand() % (0x100000000 - 1 + 1));
        data = temp;

        while (temp) {
            if (temp & 0x01)
                num++;
            temp >>= 1;
        }
        EXPECT_EQ(aot_intrinsic_popcnt_i32(data), num);
        num = 0;
    }

    EXPECT_EQ(aot_intrinsic_popcnt_i32(0xFFFFFFFF), 32);
}

TEST_F(AOTTest, aot_intrinsic_popcnt_i64)
{
    uint64 data = 0;
    uint64 num = 0;
    uint64 temp = 0;

    EXPECT_EQ(aot_intrinsic_popcnt_i64(0x00), 0);

    for (uint32 i = 0; i < 0xFFFFF; i++) {
        temp = 1 + (rand() % (0xFFFFFFFFFFFFFFFFLL - 1 + 1));
        data = temp;

        while (temp) {
            if (temp & 0x01)
                num++;
            temp >>= 1;
        }
        EXPECT_EQ(aot_intrinsic_popcnt_i64(data), num);
        num = 0;
    }

    EXPECT_EQ(aot_intrinsic_popcnt_i64(0xFFFFFFFFFFFFFFFF), 64);
}

TEST_F(AOTTest, aot_intrinsic_i32_to_f32)
{
    int32 idata = 0;

    EXPECT_EQ(aot_intrinsic_i32_to_f32(idata), (float32)idata);

    for (uint32 i = 0; i < 0xFFFF; i++) {
        idata = (int32)(1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        EXPECT_EQ(aot_intrinsic_i32_to_f32(idata), (float32)idata);
    }

    idata = 0xFFFFFFFF;
    EXPECT_EQ(aot_intrinsic_i32_to_f32(idata), (float32)idata);
}

TEST_F(AOTTest, aot_intrinsic_u32_to_f32)
{
    uint32 udata = 0;

    EXPECT_EQ(aot_intrinsic_u32_to_f32(udata), (float32)udata);

    for (uint32 i = 0; i < 0xFFFF; i++) {
        udata = (uint32)(1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        EXPECT_EQ(aot_intrinsic_u32_to_f32(udata), (float32)udata);
    }

    udata = 0xFFFFFFFF;
    EXPECT_EQ(aot_intrinsic_u32_to_f32(udata), (float32)udata);
}

TEST_F(AOTTest, aot_intrinsic_i32_to_f64)
{
    int32 idata = 0;

    EXPECT_EQ(aot_intrinsic_i32_to_f64(idata), (float64)idata);

    for (uint32 i = 0; i < 0xFFFF; i++) {
        idata = (int32)(1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        EXPECT_EQ(aot_intrinsic_i32_to_f64(idata), (float64)idata);
    }

    idata = 0xFFFFFFFF;
    EXPECT_EQ(aot_intrinsic_i32_to_f64(idata), (float64)idata);
}

TEST_F(AOTTest, aot_intrinsic_u32_to_f64)
{
    uint32 udata = 0;

    EXPECT_EQ(aot_intrinsic_u32_to_f64(udata), (float64)udata);

    for (uint32 i = 0; i < 0xFFFFF; i++) {
        udata = (uint32)(1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        EXPECT_EQ(aot_intrinsic_u32_to_f64(udata), (float64)udata);
    }

    udata = 0xFFFFFFFF;
    EXPECT_EQ(aot_intrinsic_u32_to_f64(udata), (float64)udata);
}

TEST_F(AOTTest, aot_intrinsic_i64_to_f32)
{
    int64 idata = 0LL;

    EXPECT_EQ(aot_intrinsic_i64_to_f32(idata), (float32)idata);

    for (uint32 i = 0; i < 0xFFFFF; i++) {
        idata = (int64)(1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        EXPECT_EQ(aot_intrinsic_i64_to_f32(idata), (float32)idata);
    }

    idata = 0xFFFFFFFFFFFFFFFFLL;
    EXPECT_EQ(aot_intrinsic_i64_to_f32(idata), (float32)idata);
}

TEST_F(AOTTest, aot_intrinsic_u64_to_f32)
{
    uint64 udata = 0LL;

    EXPECT_EQ(aot_intrinsic_u64_to_f32(udata), (float32)udata);

    for (uint32 i = 0; i < 0xFFFFF; i++) {
        udata = (uint64)(1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        EXPECT_EQ(aot_intrinsic_u64_to_f32(udata), (float32)udata);
    }

    udata = 0xFFFFFFFFFFFFFFFFLL;
    EXPECT_EQ(aot_intrinsic_u64_to_f32(udata), (float32)udata);
}

TEST_F(AOTTest, aot_intrinsic_i64_to_f64)
{
    int64 idata = 0LL;

    EXPECT_EQ(aot_intrinsic_i64_to_f64(idata), float64(idata));

    for (uint32_t i = 0; i < 0xFFFFF; i++) {
        idata = (int64)(1 + (rand() % (0xFFFFFFFFFFFFFFFLL - 1 + 1)));
        EXPECT_EQ(aot_intrinsic_i64_to_f64(idata), (float64)idata);
    }

    idata = 0xFFFFFFFFFFFFFFFFLL;
    EXPECT_EQ(aot_intrinsic_i64_to_f64(idata), (float64)idata);
}

TEST_F(AOTTest, aot_intrinsic_u64_to_f64)
{
    uint64 udata = 0LL;

    EXPECT_EQ(aot_intrinsic_u64_to_f64(udata), float64(udata));

    for (uint32_t i = 0; i < 0xFFFFF; i++) {
        udata = (uint64)(1 + (rand() % (0xFFFFFFFFFFFFFFFLL - 1 + 1)));
        EXPECT_EQ(aot_intrinsic_u64_to_f64(udata), (float64)udata);
    }

    udata = 0xFFFFFFFFFFFFFFFFLL;
    EXPECT_EQ(aot_intrinsic_u64_to_f64(udata), (float64)udata);
}

TEST_F(AOTTest, aot_intrinsic_f32_to_i32)
{
    float32 data = 0.0;

    EXPECT_EQ(aot_intrinsic_f32_to_i32(data), (int32)data);

    for (uint32 i = 0; i < 0xFFFF; i++) {
        data = (float32)((1 + (rand() % (100 - 1 + 1))) - 0.05);
        EXPECT_EQ(aot_intrinsic_f32_to_i32(data), (int32)data);
    }
}

TEST_F(AOTTest, aot_intrinsic_f32_to_u32)
{
    float32 data = 0.0;

    EXPECT_EQ(aot_intrinsic_f32_to_u32(data), (uint32)data);

    for (uint32 i = 0; i < 0xFFFF; i++) {
        data = (float32)((1 + (rand() % (0xFFFFFFFF - 1 + 1))) - 0.05);
        EXPECT_EQ(aot_intrinsic_f32_to_u32(data), (uint32)data);
    }
}

TEST_F(AOTTest, aot_intrinsic_f32_to_i64)
{
    float32 data = 0.0;

    EXPECT_EQ(aot_intrinsic_f32_to_i64(data), (int64)data);

    for (uint32 i = 0; i < 0xFFFF; i++) {
        data = (float32)((1 + (rand() % (0xFFFFFFFF - 1 + 1))) - 0.05);
        EXPECT_EQ(aot_intrinsic_f32_to_i64(data), (int64)data);
    }
}

TEST_F(AOTTest, aot_intrinsic_f32_to_u64)
{
    float32 data = 0.0;

    EXPECT_EQ(aot_intrinsic_f32_to_u64(data), (uint64)data);

    for (uint32 i = 0; i < 0xFFFF; i++) {
        data = (float32)((1 + (rand() % (0xFFFFFFFF - 1 + 1))) - 0.05);
        EXPECT_EQ(aot_intrinsic_f32_to_u64(data), (uint64)data);
    }
}

TEST_F(AOTTest, aot_intrinsic_f64_to_i32)
{
    float64 data = 0.0;

    EXPECT_EQ(aot_intrinsic_f64_to_i32(data), (int32)data);

    for (uint32 i = 0; i < 0xFFFFFF; i++) {
        data = (float64)((1 + (rand() % (0xFFFFFFFF - 1 + 1))) - 0.05);
        EXPECT_EQ(aot_intrinsic_f64_to_i32(data), (int32)data);
    }
}

TEST_F(AOTTest, aot_intrinsic_f64_to_u32)
{
    float64 data = 0.0;

    EXPECT_EQ(aot_intrinsic_f64_to_u32(data), (uint32)data);

    for (uint32 i = 0; i < 0xFFFFFF; i++) {
        data = (float64)((1 + (rand() % (0xFFFFFFFF - 1 + 1))) - 0.05);
        EXPECT_EQ(aot_intrinsic_f64_to_u32(data), (uint32)data);
    }
}

TEST_F(AOTTest, aot_intrinsic_f64_to_i64)
{
    float64 data = 0.0;

    EXPECT_EQ(aot_intrinsic_f64_to_i64(data), (int64)data);

    for (uint32 i = 0; i < 0xFFFFFF; i++) {
        data = (float64)((1 + (rand() % (0xFFFFFFFF - 1 + 1))) - 0.05);
        EXPECT_EQ(aot_intrinsic_f64_to_i64(data), (int64)data);
    }
}

TEST_F(AOTTest, aot_intrinsic_f64_to_u64)
{
    float64 data = 0.0;

    EXPECT_EQ(aot_intrinsic_f64_to_u64(data), (uint64)data);

    for (uint32 i = 0; i < 0xFFFFFF; i++) {
        data = (float64)((1 + (rand() % (0xFFFFFFFF - 1 + 1))) - 0.05);
        EXPECT_EQ(aot_intrinsic_f64_to_u64(data), (uint64)data);
    }
}

TEST_F(AOTTest, aot_intrinsic_f32_to_f64)
{
    float32 data = 0.0;

    EXPECT_EQ(aot_intrinsic_f32_to_f64(data), (float64)data);

    for (uint32 i = 0; i < 0xFFFF; i++) {
        data = (float32)((1 + (rand() % (0xFFFFFFFF - 1 + 1))) - 0.05);
        EXPECT_EQ(aot_intrinsic_f32_to_f64(data), (float64)data);
    }
}

TEST_F(AOTTest, aot_intrinsic_f64_to_f32)
{
    float64 data = 0.0;

    EXPECT_EQ(aot_intrinsic_f64_to_f32(data), (float32)data);

    for (uint32 i = 0; i < 0xFFFFFF; i++) {
        data = (float64)((1 + (rand() % (0xFFFFFFFF - 1 + 1))) - 0.06);
        EXPECT_EQ(aot_intrinsic_f32_to_f64(data), (float32)data);
    }
}

TEST_F(AOTTest, aot_intrinsic_f32_cmp)
{
    float32 lhs = 0.0;
    float32 rhs = 0.0;
    AOTFloatCond index = FLOAT_EQ;
    uint32 res = 0;

    for (uint32 i = 0; i < 0xFFFFFF; i++) {
        index = (AOTFloatCond)(1 + (rand() % (6 - 1 + 1)));
        lhs = (float32)((1 + (rand() % (0xFFFFFFFF - 1 + 1))) - 0.05);
        rhs = (float32)((1 + (rand() % (0xFFFFFFFF - 1 + 1))) - 0.05);

        /* cond : 0 */
        EXPECT_EQ(aot_intrinsic_f32_cmp(FLOAT_EQ, lhs, rhs),
                  lhs == rhs ? 1 : 0);

        /* cond : 1-6 */
        switch (index) {
            case FLOAT_LT: // 2
                res = (lhs < rhs ? 1 : 0);
                break;
            case FLOAT_GT: // 3
                res = (lhs > rhs ? 1 : 0);
                break;
            case FLOAT_LE: // 4
                res = (lhs <= rhs ? 1 : 0);
                break;
            case FLOAT_GE: // 5
                res = (lhs >= rhs ? 1 : 0);
                break;
            case FLOAT_NE: // 1
                res = (isnan(lhs) || isnan(rhs) || lhs != rhs) ? 1 : 0;
                break;
            case FLOAT_UNO: // 6
                res = (isnan(lhs) || isnan(rhs)) ? 1 : 0;
                break;

            default:
                break;
        }

        EXPECT_EQ(aot_intrinsic_f32_cmp(index, lhs, rhs), res);
        index = FLOAT_EQ;

        /* cond : > 6 */
        EXPECT_EQ(aot_intrinsic_f32_cmp((AOTFloatCond)(i + 7), lhs, rhs), 0);
    }

    EXPECT_EQ(aot_intrinsic_f32_cmp(FLOAT_NE, true, false), 1);
    EXPECT_EQ(aot_intrinsic_f32_cmp(FLOAT_NE, true, true), 0);

    EXPECT_EQ(aot_intrinsic_f32_cmp(FLOAT_UNO, true, false), 0);
    EXPECT_EQ(aot_intrinsic_f32_cmp(FLOAT_UNO, true, true), 0);

    EXPECT_EQ(aot_intrinsic_f32_cmp(FLOAT_UNO, 'a', 'b'), 0);
}

TEST_F(AOTTest, aot_intrinsic_f64_cmp)
{
    float64 lhs = 0.0;
    float64 rhs = 0.0;
    AOTFloatCond index = FLOAT_EQ;
    uint32 res = 0;

    for (uint32 i = 0; i < 0xFFFFFF; i++) {
        index = (AOTFloatCond)(1 + (rand() % (6 - 1 + 1)));
        lhs = (float32)((1 + (rand() % (0xFFFFFFFFFFFFFFFF - 1 + 1))) - 0.05);
        rhs = (float32)((1 + (rand() % (0xFFFFFFFFFFFFFFFF - 1 + 1))) - 0.05);

        /* cond : 0 */
        EXPECT_EQ(aot_intrinsic_f64_cmp(FLOAT_EQ, lhs, rhs),
                  lhs == rhs ? 1 : 0);

        /* cond : 1-6 */
        switch (index) {
            case FLOAT_LT: // 2
                res = (lhs < rhs ? 1 : 0);
                break;
            case FLOAT_GT: // 3
                res = (lhs > rhs ? 1 : 0);
                break;
            case FLOAT_LE: // 4
                res = (lhs <= rhs ? 1 : 0);
                break;
            case FLOAT_GE: // 5
                res = (lhs >= rhs ? 1 : 0);
                break;
            case FLOAT_NE: // 1
                res = (isnan(lhs) || isnan(rhs) || lhs != rhs) ? 1 : 0;
                break;
            case FLOAT_UNO: // 6
                res = (isnan(lhs) || isnan(rhs)) ? 1 : 0;
                break;

            default:
                break;
        }

        EXPECT_EQ(aot_intrinsic_f64_cmp(index, lhs, rhs), res);
        index = FLOAT_EQ;

        /* cond : > 6 */
        EXPECT_EQ(aot_intrinsic_f64_cmp((AOTFloatCond)(i + 7), lhs, rhs), 0);
    }

    EXPECT_EQ(aot_intrinsic_f64_cmp(FLOAT_NE, true, false), 1);
    EXPECT_EQ(aot_intrinsic_f64_cmp(FLOAT_NE, true, true), 0);

    EXPECT_EQ(aot_intrinsic_f64_cmp(FLOAT_UNO, true, false), 0);
    EXPECT_EQ(aot_intrinsic_f64_cmp(FLOAT_UNO, true, true), 0);

    EXPECT_EQ(aot_intrinsic_f64_cmp(FLOAT_UNO, 'a', 'b'), 0);
}

TEST_F(AOTTest, aot_intrinsic_get_symbol)
{
    const char *llvm_intrinsic_t = NULL;

    for (int i = 0; i < 2; i++) {
        if (i == 0)
            llvm_intrinsic_t = CONS(32);
        else
            llvm_intrinsic_t = CONS(64);

        EXPECT_EQ((const char *)aot_intrinsic_get_symbol(llvm_intrinsic_t),
                  (const char *)NULL);
    }

    for (int i = 0; i < G_INTRINSIC_COUNT - 2; i++) {
        EXPECT_NE((const char *)aot_intrinsic_get_symbol(llvm_intrinsic_tmp[i]),
                  (const char *)NULL);
    }
}

TEST_F(AOTTest, aot_intrinsic_check_capability)
{
    AOTCompContext *comp_ctx = NULL;
    AOTCompContext scomp_ctx = { 0 };
    const char *llvm_intrinsic_t = "f64_cmp";
    bool res = false;
    uint64 flag = 0;
    uint64 group = 0;

    comp_ctx = &scomp_ctx;
    memset(comp_ctx->flags, 0, sizeof(comp_ctx->flags));

    /*
        EXPECT_FALSE(aot_intrinsic_check_capability(comp_ctx, (const char
       *)NULL)); EXPECT_FALSE(aot_intrinsic_check_capability((const
       AOTCompContext *)NULL, llvm_intrinsic_t));
    */

    EXPECT_FALSE(aot_intrinsic_check_capability(comp_ctx, llvm_intrinsic_t));
    for (int i = 0; i < G_INTRINSIC_COUNT; i++) {
        EXPECT_FALSE(
            aot_intrinsic_check_capability(comp_ctx, llvm_intrinsic_tmp[i]));
    }

    memset(comp_ctx->flags, 1, sizeof(comp_ctx->flags));
    EXPECT_FALSE(aot_intrinsic_check_capability(comp_ctx, llvm_intrinsic_t));
    for (int i = 0; i < G_INTRINSIC_COUNT; i++) {
        flag = g_intrinsic_flag[i];
        group = AOT_INTRINSIC_GET_GROUP_FROM_FLAG(flag);
        flag &= AOT_INTRINSIC_FLAG_MASK;

        res = aot_intrinsic_check_capability(comp_ctx, llvm_intrinsic_tmp[i]);
        if ((flag & 0x01) || (flag & 0x100) || (flag & 0x10000)
            || (flag & 0x1000000))
            EXPECT_TRUE(res);
        else
            EXPECT_FALSE(res);
    }
}

TEST_F(AOTTest, aot_intrinsic_fill_capability_flags)
{
    // AOTCompContext *comp_ctx = NULL;
    AOTCompContext scomp_ctx = { 0 };

    // comp_ctx = &scomp_ctx;
    aot_intrinsic_fill_capability_flags(&scomp_ctx);

    AOTCompContext scomp_ctx_1{
        .target_cpu = (char *)"cortex-m7",
    };
    strncpy(scomp_ctx_1.target_arch, "thumb", strlen("thumb"));
    aot_intrinsic_fill_capability_flags(&scomp_ctx_1);

    AOTCompContext scomp_ctx_2{
        .target_cpu = (char *)"cortex-m4",
    };
    strncpy(scomp_ctx_2.target_arch, "thumb", strlen("thumb"));
    aot_intrinsic_fill_capability_flags(&scomp_ctx_2);

    AOTCompContext scomp_ctx_3{
        .target_cpu = (char *)"cortex-m4",
    };
    strncpy(scomp_ctx_3.target_arch, "riscv", strlen("riscv"));
    aot_intrinsic_fill_capability_flags(&scomp_ctx_3);

    AOTCompContext scomp_ctx_4{
        .target_cpu = (char *)"cortex-m4",
    };
    strncpy(scomp_ctx_4.target_arch, "intrinsic", strlen("intrinsic"));
    aot_intrinsic_fill_capability_flags(&scomp_ctx_4);
}
