/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "gtest/gtest.h"
#include "aot_emit_variable.h"

#define DEFAULT_CYCLE_TIMES 0xFFFF
#define DEFAULT_MAX_RAND_NUM 0xFFFFFFFF

class compilation_aot_emit_variable_test : public testing::Test
{
  protected:
    virtual void SetUp() {}
    virtual void TearDown() {}

  public:
    AOTCompContext comp_ctx = { 0 };
    AOTFuncContext func_ctx = { 0 };
};

TEST_F(compilation_aot_emit_variable_test, aot_compile_op_get_local)
{
    AOTCompContext *pcomp_ctx = &comp_ctx;
    AOTFuncContext *pfunc_ctx = &func_ctx;
    uint32 local_idx = 0;

    // aot_compile_op_get_local(NULL, pfunc_ctx, local_idx);

    // for (uint32_t i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
    //     local_idx = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
    //     aot_compile_op_get_local(pcomp_ctx, pfunc_ctx, local_idx);
    // }
}

TEST_F(compilation_aot_emit_variable_test, aot_compile_op_set_local)
{

    AOTCompContext *pcomp_ctx = &comp_ctx;
    AOTFuncContext *pfunc_ctx = &func_ctx;
    uint32 local_idx = 0;

    // aot_compile_op_set_local(pcomp_ctx, pfunc_ctx, local_idx);

    // for (uint32_t i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
    //     local_idx = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
    //     aot_compile_op_set_local(pcomp_ctx, pfunc_ctx, local_idx);
    // }
}

TEST_F(compilation_aot_emit_variable_test, aot_compile_op_tee_local)
{

    AOTCompContext *pcomp_ctx = &comp_ctx;
    AOTFuncContext *pfunc_ctx = &func_ctx;
    uint32 local_idx = 0;

    // aot_compile_op_tee_local(pcomp_ctx, pfunc_ctx, local_idx);

    // for (uint32_t i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
    //     local_idx = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
    //     aot_compile_op_tee_local(pcomp_ctx, pfunc_ctx, local_idx);
    // }
}

TEST_F(compilation_aot_emit_variable_test, aot_compile_op_get_global)
{
    AOTCompContext *pcomp_ctx = &comp_ctx;
    AOTFuncContext *pfunc_ctx = &func_ctx;
    uint32 global_idx = 0;

    // aot_compile_op_get_global(pcomp_ctx, pfunc_ctx, global_idx);

    // for (uint32_t i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
    //     local_idx = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
    //     aot_compile_op_get_global(pcomp_ctx, pfunc_ctx, global_idx);
    // }
}

TEST_F(compilation_aot_emit_variable_test, aot_compile_op_set_global)
{
    AOTCompContext *pcomp_ctx = &comp_ctx;
    AOTFuncContext *pfunc_ctx = &func_ctx;
    uint32 global_idx = 0;
    bool is_aux_stack = false;

    // aot_compile_op_set_global(pcomp_ctx, pfunc_ctx, global_idx,
    // is_aux_stack);

    // for (uint32_t i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
    //     is_aux_stack = is_aux_stack ? false : ture;
    //     local_idx = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
    //     aot_compile_op_set_global(pcomp_ctx, pfunc_ctx,
    //     global_idx,is_aux_stack);
    // }
}