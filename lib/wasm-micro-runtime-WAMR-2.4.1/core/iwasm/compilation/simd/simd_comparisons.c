/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "simd_comparisons.h"
#include "simd_common.h"
#include "../aot_emit_exception.h"
#include "../../aot/aot_runtime.h"

static bool
float_cond_2_predicate(FloatCond cond, LLVMRealPredicate *out)
{
    switch (cond) {
        case FLOAT_EQ:
            *out = LLVMRealOEQ;
            break;
        case FLOAT_NE:
            *out = LLVMRealUNE;
            break;
        case FLOAT_LT:
            *out = LLVMRealOLT;
            break;
        case FLOAT_GT:
            *out = LLVMRealOGT;
            break;
        case FLOAT_LE:
            *out = LLVMRealOLE;
            break;
        case FLOAT_GE:
            *out = LLVMRealOGE;
            break;
        default:
            bh_assert(0);
            goto fail;
    }

    return true;
fail:
    return false;
}

static bool
int_cond_2_predicate(IntCond cond, LLVMIntPredicate *out)
{
    switch (cond) {
        case INT_EQZ:
        case INT_EQ:
            *out = LLVMIntEQ;
            break;
        case INT_NE:
            *out = LLVMIntNE;
            break;
        case INT_LT_S:
            *out = LLVMIntSLT;
            break;
        case INT_LT_U:
            *out = LLVMIntULT;
            break;
        case INT_GT_S:
            *out = LLVMIntSGT;
            break;
        case INT_GT_U:
            *out = LLVMIntUGT;
            break;
        case INT_LE_S:
            *out = LLVMIntSLE;
            break;
        case INT_LE_U:
            *out = LLVMIntULE;
            break;
        case INT_GE_S:
            *out = LLVMIntSGE;
            break;
        case INT_GE_U:
            *out = LLVMIntUGE;
            break;
        default:
            bh_assert(0);
            goto fail;
    }

    return true;
fail:
    return false;
}

static bool
integer_vector_compare(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                       IntCond cond, LLVMTypeRef vector_type)
{
    LLVMValueRef vec1, vec2, result;
    LLVMIntPredicate int_pred;

    if (!(vec2 = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                           "vec2"))) {
        goto fail;
    }

    if (!(vec1 = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                           "vec1"))) {
        goto fail;
    }

    if (!int_cond_2_predicate(cond, &int_pred)) {
        HANDLE_FAILURE("int_cond_2_predicate");
        goto fail;
    }
    /* icmp <N x iX> %vec1, %vec2 */
    if (!(result =
              LLVMBuildICmp(comp_ctx->builder, int_pred, vec1, vec2, "cmp"))) {
        HANDLE_FAILURE("LLVMBuildICmp");
        goto fail;
    }

    /* sext <N x i1> %result to <N x iX> */
    if (!(result =
              LLVMBuildSExt(comp_ctx->builder, result, vector_type, "ext"))) {
        HANDLE_FAILURE("LLVMBuildSExt");
        goto fail;
    }

    /* bitcast <N x iX> %result to <2 x i64> */
    if (!(result = LLVMBuildBitCast(comp_ctx->builder, result, V128_i64x2_TYPE,
                                    "result"))) {
        HANDLE_FAILURE("LLVMBuildBitCast");
        goto fail;
    }

    PUSH_V128(result);

    return true;
fail:
    return false;
}

bool
aot_compile_simd_i8x16_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, IntCond cond)
{
    return integer_vector_compare(comp_ctx, func_ctx, cond, V128_i8x16_TYPE);
}

bool
aot_compile_simd_i16x8_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, IntCond cond)
{
    return integer_vector_compare(comp_ctx, func_ctx, cond, V128_i16x8_TYPE);
}

bool
aot_compile_simd_i32x4_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, IntCond cond)
{
    return integer_vector_compare(comp_ctx, func_ctx, cond, V128_i32x4_TYPE);
}

bool
aot_compile_simd_i64x2_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, IntCond cond)
{
    return integer_vector_compare(comp_ctx, func_ctx, cond, V128_i64x2_TYPE);
}

static bool
float_vector_compare(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                     FloatCond cond, LLVMTypeRef vector_type,
                     LLVMTypeRef result_type)
{
    LLVMValueRef vec1, vec2, result;
    LLVMRealPredicate real_pred;

    if (!(vec2 = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                           "vec2"))) {
        goto fail;
    }

    if (!(vec1 = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                           "vec1"))) {
        goto fail;
    }

    if (!float_cond_2_predicate(cond, &real_pred)) {
        HANDLE_FAILURE("float_cond_2_predicate");
        goto fail;
    }
    /* fcmp <N x iX> %vec1, %vec2 */
    if (!(result =
              LLVMBuildFCmp(comp_ctx->builder, real_pred, vec1, vec2, "cmp"))) {
        HANDLE_FAILURE("LLVMBuildFCmp");
        goto fail;
    }

    /* sext <N x i1> %result to <N x iX> */
    if (!(result =
              LLVMBuildSExt(comp_ctx->builder, result, result_type, "ext"))) {
        HANDLE_FAILURE("LLVMBuildSExt");
        goto fail;
    }

    /* bitcast <N x iX> %result to <2 x i64> */
    if (!(result = LLVMBuildBitCast(comp_ctx->builder, result, V128_i64x2_TYPE,
                                    "result"))) {
        HANDLE_FAILURE("LLVMBuildBitCast");
        goto fail;
    }

    PUSH_V128(result);

    return true;
fail:
    return false;
}

bool
aot_compile_simd_f32x4_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, FloatCond cond)
{
    return float_vector_compare(comp_ctx, func_ctx, cond, V128_f32x4_TYPE,
                                V128_i32x4_TYPE);
}

bool
aot_compile_simd_f64x2_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, FloatCond cond)
{
    return float_vector_compare(comp_ctx, func_ctx, cond, V128_f64x2_TYPE,
                                V128_i64x2_TYPE);
}
