/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "simd_floating_point.h"
#include "simd_common.h"
#include "../aot_emit_exception.h"
#include "../aot_emit_numberic.h"
#include "../../aot/aot_runtime.h"

static bool
simd_v128_float_arith(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                      FloatArithmetic arith_op, LLVMTypeRef vector_type)
{
    LLVMValueRef lhs, rhs, result = NULL;

    if (!(rhs =
              simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type, "rhs"))
        || !(lhs = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                             "lhs"))) {
        return false;
    }

    switch (arith_op) {
        case FLOAT_ADD:
            result = LLVMBuildFAdd(comp_ctx->builder, lhs, rhs, "sum");
            break;
        case FLOAT_SUB:
            result = LLVMBuildFSub(comp_ctx->builder, lhs, rhs, "difference");
            break;
        case FLOAT_MUL:
            result = LLVMBuildFMul(comp_ctx->builder, lhs, rhs, "product");
            break;
        case FLOAT_DIV:
            result = LLVMBuildFDiv(comp_ctx->builder, lhs, rhs, "quotient");
            break;
        default:
            return false;
    }

    if (!result) {
        HANDLE_FAILURE(
            "LLVMBuildFAdd/LLVMBuildFSub/LLVMBuildFMul/LLVMBuildFDiv");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_f32x4_arith(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             FloatArithmetic arith_op)
{
    return simd_v128_float_arith(comp_ctx, func_ctx, arith_op, V128_f32x4_TYPE);
}

bool
aot_compile_simd_f64x2_arith(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             FloatArithmetic arith_op)
{
    return simd_v128_float_arith(comp_ctx, func_ctx, arith_op, V128_f64x2_TYPE);
}

static bool
simd_v128_float_neg(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                    LLVMTypeRef vector_type)
{
    LLVMValueRef vector, result;

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                             "vector"))) {
        return false;
    }

    if (!(result = LLVMBuildFNeg(comp_ctx->builder, vector, "neg"))) {
        HANDLE_FAILURE("LLVMBuildFNeg");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_f32x4_neg(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_v128_float_neg(comp_ctx, func_ctx, V128_f32x4_TYPE);
}

bool
aot_compile_simd_f64x2_neg(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_v128_float_neg(comp_ctx, func_ctx, V128_f64x2_TYPE);
}

static bool
simd_float_intrinsic(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                     LLVMTypeRef vector_type, const char *intrinsic)
{
    LLVMValueRef vector, result;
    LLVMTypeRef param_types[1] = { vector_type };

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                             "vector"))) {
        return false;
    }

    if (!(result =
              aot_call_llvm_intrinsic(comp_ctx, func_ctx, intrinsic,
                                      vector_type, param_types, 1, vector))) {
        HANDLE_FAILURE("LLVMBuildCall");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_f32x4_abs(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f32x4_TYPE,
                                "llvm.fabs.v4f32");
}

bool
aot_compile_simd_f64x2_abs(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f64x2_TYPE,
                                "llvm.fabs.v2f64");
}

bool
aot_compile_simd_f32x4_sqrt(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f32x4_TYPE,
                                "llvm.sqrt.v4f32");
}

bool
aot_compile_simd_f64x2_sqrt(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f64x2_TYPE,
                                "llvm.sqrt.v2f64");
}

bool
aot_compile_simd_f32x4_ceil(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f32x4_TYPE,
                                "llvm.ceil.v4f32");
}

bool
aot_compile_simd_f64x2_ceil(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f64x2_TYPE,
                                "llvm.ceil.v2f64");
}

bool
aot_compile_simd_f32x4_floor(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f32x4_TYPE,
                                "llvm.floor.v4f32");
}

bool
aot_compile_simd_f64x2_floor(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f64x2_TYPE,
                                "llvm.floor.v2f64");
}

bool
aot_compile_simd_f32x4_trunc(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f32x4_TYPE,
                                "llvm.trunc.v4f32");
}

bool
aot_compile_simd_f64x2_trunc(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f64x2_TYPE,
                                "llvm.trunc.v2f64");
}

bool
aot_compile_simd_f32x4_nearest(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f32x4_TYPE,
                                "llvm.rint.v4f32");
}

bool
aot_compile_simd_f64x2_nearest(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx)
{
    return simd_float_intrinsic(comp_ctx, func_ctx, V128_f64x2_TYPE,
                                "llvm.rint.v2f64");
}

static bool
simd_float_cmp(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
               FloatArithmetic op, LLVMTypeRef vector_type)
{
    LLVMValueRef lhs, rhs, cmp, selected;

    if (!(rhs =
              simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type, "rhs"))
        || !(lhs = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                             "lhs"))) {
        return false;
    }

    if (!(cmp = LLVMBuildFCmp(comp_ctx->builder,
                              op == FLOAT_MIN ? LLVMRealOLT : LLVMRealOGT, rhs,
                              lhs, "cmp"))) {
        HANDLE_FAILURE("LLVMBuildFCmp");
        return false;
    }

    if (!(selected =
              LLVMBuildSelect(comp_ctx->builder, cmp, rhs, lhs, "selected"))) {
        HANDLE_FAILURE("LLVMBuildSelect");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, selected, "result");
}

static bool
simd_float_min(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
               LLVMTypeRef vector_type)
{
    LLVMValueRef lhs, rhs, lhs_nan, rhs_nan, olt_ret, ogt_ret, or_ret, ret1,
        ret2, ret3, ret4;

    if (!(rhs =
              simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type, "rhs"))
        || !(lhs = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                             "lhs"))) {
        return false;
    }

    if (!(lhs_nan = LLVMBuildFCmp(comp_ctx->builder, LLVMRealUNO, lhs, lhs,
                                  "lhs_nan"))) {
        HANDLE_FAILURE("LLVMBuildFCmp + LLVMRealUNO");
        return false;
    }

    if (!(rhs_nan = LLVMBuildFCmp(comp_ctx->builder, LLVMRealUNO, rhs, rhs,
                                  "rhs_nan"))) {
        HANDLE_FAILURE("LLVMBuildFCmp + LLVMRealUNO");
        return false;
    }

    if (!(olt_ret = LLVMBuildFCmp(comp_ctx->builder, LLVMRealOLT, lhs, rhs,
                                  "olt_ret"))) {
        HANDLE_FAILURE("LLVMBuildFCmp + LLVMRealOLT");
        return false;
    }

    if (!(ogt_ret = LLVMBuildFCmp(comp_ctx->builder, LLVMRealOGT, lhs, rhs,
                                  "ogt_ret"))) {
        HANDLE_FAILURE("LLVMBuildFCmp + LLVMRealOGT");
        return false;
    }

    /* lhs or rhs */
    {
        LLVMValueRef integer_l, integer_r, integer_or;

        if (!(integer_l = LLVMBuildBitCast(comp_ctx->builder, lhs,
                                           V128_i64x2_TYPE, "lhs_to_int"))) {
            HANDLE_FAILURE("LLVMBuildBitCas");
            return false;
        }

        if (!(integer_r = LLVMBuildBitCast(comp_ctx->builder, rhs,
                                           V128_i64x2_TYPE, "rhs_to_int"))) {
            HANDLE_FAILURE("LLVMBuildBitCas");
            return false;
        }

        if (!(integer_or =
                  LLVMBuildOr(comp_ctx->builder, integer_l, integer_r, "or"))) {
            HANDLE_FAILURE("LLVMBuildOr");
            return false;
        }

        if (!(or_ret = LLVMBuildBitCast(comp_ctx->builder, integer_or,
                                        vector_type, "holder"))) {
            HANDLE_FAILURE("LLVMBuildBitCast");
            return false;
        }
    }

    if (!(ret1 = LLVMBuildSelect(comp_ctx->builder, olt_ret, lhs, or_ret,
                                 "sel_olt"))) {
        HANDLE_FAILURE("LLVMBuildSelect");
        return false;
    }

    if (!(ret2 = LLVMBuildSelect(comp_ctx->builder, ogt_ret, rhs, ret1,
                                 "sel_ogt"))) {
        HANDLE_FAILURE("LLVMBuildSelect");
        return false;
    }

    if (!(ret3 = LLVMBuildSelect(comp_ctx->builder, lhs_nan, lhs, ret2,
                                 "sel_lhs_nan"))) {
        HANDLE_FAILURE("LLVMBuildSelect");
        return false;
    }

    if (!(ret4 = LLVMBuildSelect(comp_ctx->builder, rhs_nan, rhs, ret3,
                                 "sel_rhs_nan"))) {
        HANDLE_FAILURE("LLVMBuildSelect");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, ret4, "result");
}

static bool
simd_float_max(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
               LLVMTypeRef vector_type)
{
    LLVMValueRef lhs, rhs, lhs_nan, rhs_nan, olt_ret, ogt_ret, and_ret, ret1,
        ret2, ret3, ret4;

    if (!(rhs =
              simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type, "rhs"))
        || !(lhs = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                             "lhs"))) {
        return false;
    }

    if (!(lhs_nan = LLVMBuildFCmp(comp_ctx->builder, LLVMRealUNO, lhs, lhs,
                                  "lhs_nan"))) {
        HANDLE_FAILURE("LLVMBuildFCmp + LLVMRealUNO");
        return false;
    }

    if (!(rhs_nan = LLVMBuildFCmp(comp_ctx->builder, LLVMRealUNO, rhs, rhs,
                                  "rhs_nan"))) {
        HANDLE_FAILURE("LLVMBuildFCmp + LLVMRealUNO");
        return false;
    }

    if (!(olt_ret = LLVMBuildFCmp(comp_ctx->builder, LLVMRealOLT, lhs, rhs,
                                  "olt_ret"))) {
        HANDLE_FAILURE("LLVMBuildFCmp + LLVMRealOLT");
        return false;
    }

    if (!(ogt_ret = LLVMBuildFCmp(comp_ctx->builder, LLVMRealOGT, lhs, rhs,
                                  "ogt_ret"))) {
        HANDLE_FAILURE("LLVMBuildFCmp + LLVMRealOGT");
        return false;
    }

    /* lhs and rhs */
    {
        LLVMValueRef integer_l, integer_r, integer_and;

        if (!(integer_l = LLVMBuildBitCast(comp_ctx->builder, lhs,
                                           V128_i64x2_TYPE, "lhs_to_int"))) {
            HANDLE_FAILURE("LLVMBuildBitCas");
            return false;
        }

        if (!(integer_r = LLVMBuildBitCast(comp_ctx->builder, rhs,
                                           V128_i64x2_TYPE, "rhs_to_int"))) {
            HANDLE_FAILURE("LLVMBuildBitCas");
            return false;
        }

        if (!(integer_and = LLVMBuildAnd(comp_ctx->builder, integer_l,
                                         integer_r, "and"))) {
            HANDLE_FAILURE("LLVMBuildOr");
            return false;
        }

        if (!(and_ret = LLVMBuildBitCast(comp_ctx->builder, integer_and,
                                         vector_type, "holder"))) {
            HANDLE_FAILURE("LLVMBuildBitCast");
            return false;
        }
    }

    if (!(ret1 = LLVMBuildSelect(comp_ctx->builder, ogt_ret, lhs, and_ret,
                                 "sel_ogt"))) {
        HANDLE_FAILURE("LLVMBuildSelect");
        return false;
    }

    if (!(ret2 = LLVMBuildSelect(comp_ctx->builder, olt_ret, rhs, ret1,
                                 "sel_olt"))) {
        HANDLE_FAILURE("LLVMBuildSelect");
        return false;
    }

    if (!(ret3 = LLVMBuildSelect(comp_ctx->builder, lhs_nan, lhs, ret2,
                                 "sel_lhs_nan"))) {
        HANDLE_FAILURE("LLVMBuildSelect");
        return false;
    }

    if (!(ret4 = LLVMBuildSelect(comp_ctx->builder, rhs_nan, rhs, ret3,
                                 "sel_rhs_nan"))) {
        HANDLE_FAILURE("LLVMBuildSelect");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, ret4, "result");
}

bool
aot_compile_simd_f32x4_min_max(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, bool run_min)
{
    return run_min ? simd_float_min(comp_ctx, func_ctx, V128_f32x4_TYPE)
                   : simd_float_max(comp_ctx, func_ctx, V128_f32x4_TYPE);
}

bool
aot_compile_simd_f64x2_min_max(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, bool run_min)
{
    return run_min ? simd_float_min(comp_ctx, func_ctx, V128_f64x2_TYPE)
                   : simd_float_max(comp_ctx, func_ctx, V128_f64x2_TYPE);
}

bool
aot_compile_simd_f32x4_pmin_pmax(AOTCompContext *comp_ctx,
                                 AOTFuncContext *func_ctx, bool run_min)
{
    return simd_float_cmp(comp_ctx, func_ctx, run_min ? FLOAT_MIN : FLOAT_MAX,
                          V128_f32x4_TYPE);
}

bool
aot_compile_simd_f64x2_pmin_pmax(AOTCompContext *comp_ctx,
                                 AOTFuncContext *func_ctx, bool run_min)
{
    return simd_float_cmp(comp_ctx, func_ctx, run_min ? FLOAT_MIN : FLOAT_MAX,
                          V128_f64x2_TYPE);
}

bool
aot_compile_simd_f64x2_demote(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx)
{
    LLVMValueRef vector, elem_0, elem_1, result;

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                             V128_f64x2_TYPE, "vector"))) {
        return false;
    }

    if (!(elem_0 = LLVMBuildExtractElement(comp_ctx->builder, vector,
                                           LLVM_CONST(i32_zero), "elem_0"))
        || !(elem_1 = LLVMBuildExtractElement(comp_ctx->builder, vector,
                                              LLVM_CONST(i32_one), "elem_1"))) {
        HANDLE_FAILURE("LLVMBuildExtractElement");
        return false;
    }

    /* fptrunc <f64> elem to <f32> */
    if (!(elem_0 = LLVMBuildFPTrunc(comp_ctx->builder, elem_0, F32_TYPE,
                                    "elem_0_trunc"))
        || !(elem_1 = LLVMBuildFPTrunc(comp_ctx->builder, elem_1, F32_TYPE,
                                       "elem_1_trunc"))) {
        HANDLE_FAILURE("LLVMBuildFPTrunc");
        return false;
    }

    if (!(result = LLVMBuildInsertElement(comp_ctx->builder,
                                          LLVM_CONST(f32x4_vec_zero), elem_0,
                                          LLVM_CONST(i32_zero), "new_vector_0"))
        || !(result =
                 LLVMBuildInsertElement(comp_ctx->builder, result, elem_1,
                                        LLVM_CONST(i32_one), "new_vector_1"))) {
        HANDLE_FAILURE("LLVMBuildInsertElement");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_f32x4_promote(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx)
{
    LLVMValueRef vector, elem_0, elem_1, result;

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                             V128_f32x4_TYPE, "vector"))) {
        return false;
    }

    if (!(elem_0 = LLVMBuildExtractElement(comp_ctx->builder, vector,
                                           LLVM_CONST(i32_zero), "elem_0"))
        || !(elem_1 = LLVMBuildExtractElement(comp_ctx->builder, vector,
                                              LLVM_CONST(i32_one), "elem_1"))) {
        HANDLE_FAILURE("LLVMBuildExtractElement");
        return false;
    }

    /* fpext <f32> elem to <f64> */
    if (!(elem_0 =
              LLVMBuildFPExt(comp_ctx->builder, elem_0, F64_TYPE, "elem_0_ext"))
        || !(elem_1 = LLVMBuildFPExt(comp_ctx->builder, elem_1, F64_TYPE,
                                     "elem_1_ext"))) {
        HANDLE_FAILURE("LLVMBuildFPExt");
        return false;
    }

    if (!(result = LLVMBuildInsertElement(comp_ctx->builder,
                                          LLVM_CONST(f64x2_vec_zero), elem_0,
                                          LLVM_CONST(i32_zero), "new_vector_0"))
        || !(result =
                 LLVMBuildInsertElement(comp_ctx->builder, result, elem_1,
                                        LLVM_CONST(i32_one), "new_vector_1"))) {
        HANDLE_FAILURE("LLVMBuildInsertElement");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}
