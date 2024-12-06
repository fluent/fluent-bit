/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "simd_conversions.h"
#include "simd_common.h"
#include "../aot_emit_exception.h"
#include "../aot_emit_numberic.h"
#include "../../aot/aot_runtime.h"

static bool
simd_integer_narrow_x86(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        LLVMTypeRef in_vector_type, LLVMTypeRef out_vector_type,
                        const char *instrinsic)
{
    LLVMValueRef vector1, vector2, result;
    LLVMTypeRef param_types[2] = { in_vector_type, in_vector_type };

    if (!(vector2 = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                              in_vector_type, "vec2"))
        || !(vector1 = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                                 in_vector_type, "vec1"))) {
        return false;
    }

    if (!(result = aot_call_llvm_intrinsic(comp_ctx, func_ctx, instrinsic,
                                           out_vector_type, param_types, 2,
                                           vector1, vector2))) {
        HANDLE_FAILURE("LLVMBuildCall");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

enum integer_sat_type {
    e_sat_i16x8 = 0,
    e_sat_i32x4,
    e_sat_i64x2,
    e_sat_i32x8,
};

static LLVMValueRef
simd_saturate(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
              enum integer_sat_type itype, LLVMValueRef vector,
              LLVMValueRef min, LLVMValueRef max, bool is_signed)
{
    LLVMValueRef result;
    LLVMTypeRef vector_type;

    LLVMTypeRef param_types[][2] = {
        { V128_i16x8_TYPE, V128_i16x8_TYPE },
        { V128_i32x4_TYPE, V128_i32x4_TYPE },
        { V128_i64x2_TYPE, V128_i64x2_TYPE },
        { 0 },
    };

    const char *smin_intrinsic[] = {
        "llvm.smin.v8i16",
        "llvm.smin.v4i32",
        "llvm.smin.v2i64",
        "llvm.smin.v8i32",
    };

    const char *umin_intrinsic[] = {
        "llvm.umin.v8i16",
        "llvm.umin.v4i32",
        "llvm.umin.v2i64",
        "llvm.umin.v8i32",
    };

    const char *smax_intrinsic[] = {
        "llvm.smax.v8i16",
        "llvm.smax.v4i32",
        "llvm.smax.v2i64",
        "llvm.smax.v8i32",
    };

    const char *umax_intrinsic[] = {
        "llvm.umax.v8i16",
        "llvm.umax.v4i32",
        "llvm.umax.v2i64",
        "llvm.umax.v8i32",
    };

    if (e_sat_i32x8 == itype) {
        if (!(vector_type = LLVMVectorType(I32_TYPE, 8))) {
            HANDLE_FAILURE("LLVMVectorType");
            return NULL;
        }

        param_types[itype][0] = vector_type;
        param_types[itype][1] = vector_type;
    }

    if (!(result = aot_call_llvm_intrinsic(
              comp_ctx, func_ctx,
              is_signed ? smin_intrinsic[itype] : umin_intrinsic[itype],
              param_types[itype][0], param_types[itype], 2, vector, max))
        || !(result = aot_call_llvm_intrinsic(
                 comp_ctx, func_ctx,
                 is_signed ? smax_intrinsic[itype] : umax_intrinsic[itype],
                 param_types[itype][0], param_types[itype], 2, result, min))) {
        return NULL;
    }

    return result;
}

static bool
simd_integer_narrow_common(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           enum integer_sat_type itype, bool is_signed)
{
    LLVMValueRef vec1, vec2, min, max, mask, result;
    LLVMTypeRef in_vector_type[] = { V128_i16x8_TYPE, V128_i32x4_TYPE,
                                     V128_i64x2_TYPE };
    LLVMTypeRef min_max_type[] = { INT16_TYPE, I32_TYPE, I64_TYPE };
    LLVMTypeRef trunc_type[3] = { 0 };
    uint8 length[] = { 8, 4, 2 };

    int64 smin[] = { 0xff80, 0xffFF8000, 0xffFFffFF80000000 };
    int64 umin[] = { 0x0, 0x0, 0x0 };
    int64 smax[] = { 0x007f, 0x00007fff, 0x000000007fFFffFF };
    int64 umax[] = { 0x00ff, 0x0000ffff, 0x00000000ffFFffFF };

    LLVMValueRef mask_element[] = {
        LLVM_CONST(i32_zero),     LLVM_CONST(i32_one),
        LLVM_CONST(i32_two),      LLVM_CONST(i32_three),
        LLVM_CONST(i32_four),     LLVM_CONST(i32_five),
        LLVM_CONST(i32_six),      LLVM_CONST(i32_seven),
        LLVM_CONST(i32_eight),    LLVM_CONST(i32_nine),
        LLVM_CONST(i32_ten),      LLVM_CONST(i32_eleven),
        LLVM_CONST(i32_twelve),   LLVM_CONST(i32_thirteen),
        LLVM_CONST(i32_fourteen), LLVM_CONST(i32_fifteen),
    };

    if (!(trunc_type[0] = LLVMVectorType(INT8_TYPE, 8))
        || !(trunc_type[1] = LLVMVectorType(INT16_TYPE, 4))
        || !(trunc_type[2] = LLVMVectorType(I32_TYPE, 2))) {
        HANDLE_FAILURE("LLVMVectorType");
        return false;
    }

    if (!(vec2 = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                           in_vector_type[itype], "vec2"))
        || !(vec1 = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                              in_vector_type[itype], "vec1"))) {
        return false;
    }

    if (!(max = simd_build_splat_const_integer_vector(
              comp_ctx, min_max_type[itype],
              is_signed ? smax[itype] : umax[itype], length[itype]))
        || !(min = simd_build_splat_const_integer_vector(
                 comp_ctx, min_max_type[itype],
                 is_signed ? smin[itype] : umin[itype], length[itype]))) {
        return false;
    }

    /* Refer to:
     * https://github.com/WebAssembly/spec/blob/main/proposals/simd/SIMD.md#integer-to-integer-narrowing
     * Regardless of the whether the operation is signed or unsigned, the input
     * lanes are interpreted as signed integers.
     */
    if (!(vec1 = simd_saturate(comp_ctx, func_ctx, e_sat_i16x8, vec1, min, max,
                               true))
        || !(vec2 = simd_saturate(comp_ctx, func_ctx, e_sat_i16x8, vec2, min,
                                  max, true))) {
        return false;
    }

    /* trunc */
    if (!(vec1 = LLVMBuildTrunc(comp_ctx->builder, vec1, trunc_type[itype],
                                "vec1_trunc"))
        || !(vec2 = LLVMBuildTrunc(comp_ctx->builder, vec2, trunc_type[itype],
                                   "vec2_trunc"))) {
        HANDLE_FAILURE("LLVMBuildTrunc");
        return false;
    }

    /* combine */
    if (!(mask = LLVMConstVector(mask_element, (length[itype] << 1)))) {
        HANDLE_FAILURE("LLVMConstInt");
        return false;
    }

    if (!(result = LLVMBuildShuffleVector(comp_ctx->builder, vec1, vec2, mask,
                                          "vec_shuffle"))) {
        HANDLE_FAILURE("LLVMBuildShuffleVector");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_i8x16_narrow_i16x8(AOTCompContext *comp_ctx,
                                    AOTFuncContext *func_ctx, bool is_signed)
{
    if (is_target_x86(comp_ctx)) {
        return simd_integer_narrow_x86(
            comp_ctx, func_ctx, V128_i16x8_TYPE, V128_i8x16_TYPE,
            is_signed ? "llvm.x86.sse2.packsswb.128"
                      : "llvm.x86.sse2.packuswb.128");
    }
    else {
        return simd_integer_narrow_common(comp_ctx, func_ctx, e_sat_i16x8,
                                          is_signed);
    }
}

bool
aot_compile_simd_i16x8_narrow_i32x4(AOTCompContext *comp_ctx,
                                    AOTFuncContext *func_ctx, bool is_signed)
{
    if (is_target_x86(comp_ctx)) {
        return simd_integer_narrow_x86(comp_ctx, func_ctx, V128_i32x4_TYPE,
                                       V128_i16x8_TYPE,
                                       is_signed ? "llvm.x86.sse2.packssdw.128"
                                                 : "llvm.x86.sse41.packusdw");
    }
    else {
        return simd_integer_narrow_common(comp_ctx, func_ctx, e_sat_i32x4,
                                          is_signed);
    }
}

enum integer_extend_type {
    e_ext_i8x16,
    e_ext_i16x8,
    e_ext_i32x4,
};

static LLVMValueRef
simd_integer_extension(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                       enum integer_extend_type itype, LLVMValueRef vector,
                       bool lower_half, bool is_signed)
{
    LLVMValueRef mask, sub_vector, result;
    LLVMValueRef bits[] = {
        LLVM_CONST(i32_zero),     LLVM_CONST(i32_one),
        LLVM_CONST(i32_two),      LLVM_CONST(i32_three),
        LLVM_CONST(i32_four),     LLVM_CONST(i32_five),
        LLVM_CONST(i32_six),      LLVM_CONST(i32_seven),
        LLVM_CONST(i32_eight),    LLVM_CONST(i32_nine),
        LLVM_CONST(i32_ten),      LLVM_CONST(i32_eleven),
        LLVM_CONST(i32_twelve),   LLVM_CONST(i32_thirteen),
        LLVM_CONST(i32_fourteen), LLVM_CONST(i32_fifteen),
    };
    LLVMTypeRef out_vector_type[] = { V128_i16x8_TYPE, V128_i32x4_TYPE,
                                      V128_i64x2_TYPE };
    LLVMValueRef undef[] = { LLVM_CONST(i8x16_undef), LLVM_CONST(i16x8_undef),
                             LLVM_CONST(i32x4_undef) };
    uint32 sub_vector_length[] = { 8, 4, 2 };

    if (!(mask = lower_half ? LLVMConstVector(bits, sub_vector_length[itype])
                            : LLVMConstVector(bits + sub_vector_length[itype],
                                              sub_vector_length[itype]))) {
        HANDLE_FAILURE("LLVMConstVector");
        return false;
    }

    /* retrive the low or high half */
    if (!(sub_vector = LLVMBuildShuffleVector(comp_ctx->builder, vector,
                                              undef[itype], mask, "half"))) {
        HANDLE_FAILURE("LLVMBuildShuffleVector");
        return false;
    }

    if (is_signed) {
        if (!(result = LLVMBuildSExt(comp_ctx->builder, sub_vector,
                                     out_vector_type[itype], "sext"))) {
            HANDLE_FAILURE("LLVMBuildSExt");
            return false;
        }
    }
    else {
        if (!(result = LLVMBuildZExt(comp_ctx->builder, sub_vector,
                                     out_vector_type[itype], "zext"))) {
            HANDLE_FAILURE("LLVMBuildZExt");
            return false;
        }
    }

    return result;
}

static bool
simd_integer_extension_wrapper(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx,
                               enum integer_extend_type itype, bool lower_half,
                               bool is_signed)
{
    LLVMValueRef vector, result;

    LLVMTypeRef in_vector_type[] = { V128_i8x16_TYPE, V128_i16x8_TYPE,
                                     V128_i32x4_TYPE };

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                             in_vector_type[itype], "vec"))) {
        return false;
    }

    if (!(result = simd_integer_extension(comp_ctx, func_ctx, itype, vector,
                                          lower_half, is_signed))) {
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_i16x8_extend_i8x16(AOTCompContext *comp_ctx,
                                    AOTFuncContext *func_ctx, bool lower_half,
                                    bool is_signed)
{
    return simd_integer_extension_wrapper(comp_ctx, func_ctx, e_ext_i8x16,
                                          lower_half, is_signed);
}

bool
aot_compile_simd_i32x4_extend_i16x8(AOTCompContext *comp_ctx,
                                    AOTFuncContext *func_ctx, bool lower_half,
                                    bool is_signed)
{
    return simd_integer_extension_wrapper(comp_ctx, func_ctx, e_ext_i16x8,
                                          lower_half, is_signed);
}

bool
aot_compile_simd_i64x2_extend_i32x4(AOTCompContext *comp_ctx,
                                    AOTFuncContext *func_ctx, bool lower_half,
                                    bool is_signed)
{
    return simd_integer_extension_wrapper(comp_ctx, func_ctx, e_ext_i32x4,
                                          lower_half, is_signed);
}

static LLVMValueRef
simd_trunc_sat(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
               const char *intrinsics, LLVMTypeRef in_vector_type,
               LLVMTypeRef out_vector_type)
{
    LLVMValueRef vector, result;
    LLVMTypeRef param_types[] = { in_vector_type };

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, in_vector_type,
                                             "vector"))) {
        return false;
    }

    if (!(result = aot_call_llvm_intrinsic(comp_ctx, func_ctx, intrinsics,
                                           out_vector_type, param_types, 1,
                                           vector))) {
        return false;
    }

    return result;
}

bool
aot_compile_simd_i32x4_trunc_sat_f32x4(AOTCompContext *comp_ctx,
                                       AOTFuncContext *func_ctx, bool is_signed)
{
    LLVMValueRef result;
    if (!(result = simd_trunc_sat(comp_ctx, func_ctx,
                                  is_signed ? "llvm.fptosi.sat.v4i32.v4f32"
                                            : "llvm.fptoui.sat.v4i32.v4f32",
                                  V128_f32x4_TYPE, V128_i32x4_TYPE))) {
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_i32x4_trunc_sat_f64x2(AOTCompContext *comp_ctx,
                                       AOTFuncContext *func_ctx, bool is_signed)
{
    LLVMValueRef result, zero, mask;
    LLVMTypeRef out_vector_type;
    LLVMValueRef lanes[] = {
        LLVM_CONST(i32_zero),
        LLVM_CONST(i32_one),
        LLVM_CONST(i32_two),
        LLVM_CONST(i32_three),
    };

    if (!(out_vector_type = LLVMVectorType(I32_TYPE, 2))) {
        HANDLE_FAILURE("LLVMVectorType");
        return false;
    }

    if (!(result = simd_trunc_sat(comp_ctx, func_ctx,
                                  is_signed ? "llvm.fptosi.sat.v2i32.v2f64"
                                            : "llvm.fptoui.sat.v2i32.v2f64",
                                  V128_f64x2_TYPE, out_vector_type))) {
        return false;
    }

    if (!(zero = LLVMConstNull(out_vector_type))) {
        HANDLE_FAILURE("LLVMConstNull");
        return false;
    }

    /* v2i32 -> v4i32 */
    if (!(mask = LLVMConstVector(lanes, 4))) {
        HANDLE_FAILURE("LLVMConstVector");
        return false;
    }

    if (!(result = LLVMBuildShuffleVector(comp_ctx->builder, result, zero, mask,
                                          "extend"))) {
        HANDLE_FAILURE("LLVMBuildShuffleVector");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

static LLVMValueRef
simd_integer_convert(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                     bool is_signed, LLVMValueRef vector,
                     LLVMTypeRef out_vector_type)

{
    LLVMValueRef result;
    result = is_signed ? LLVMBuildSIToFP(comp_ctx->builder, vector,
                                         out_vector_type, "converted")
                       : LLVMBuildUIToFP(comp_ctx->builder, vector,
                                         out_vector_type, "converted");
    if (!result) {
        HANDLE_FAILURE("LLVMBuildSIToFP/LLVMBuildUIToFP");
    }

    return result;
}

bool
aot_compile_simd_f32x4_convert_i32x4(AOTCompContext *comp_ctx,
                                     AOTFuncContext *func_ctx, bool is_signed)
{
    LLVMValueRef vector, result;

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                             V128_i32x4_TYPE, "vec"))) {
        return false;
    }

    if (!(result = simd_integer_convert(comp_ctx, func_ctx, is_signed, vector,
                                        V128_f32x4_TYPE))) {
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_f64x2_convert_i32x4(AOTCompContext *comp_ctx,
                                     AOTFuncContext *func_ctx, bool is_signed)
{
    LLVMValueRef vector, mask, result;
    LLVMValueRef lanes[] = {
        LLVM_CONST(i32_zero),
        LLVM_CONST(i32_one),
    };
    LLVMTypeRef out_vector_type;

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                             V128_i32x4_TYPE, "vec"))) {
        return false;
    }

    if (!(out_vector_type = LLVMVectorType(F64_TYPE, 4))) {
        HANDLE_FAILURE("LLVMVectorType");
        return false;
    }

    if (!(result = simd_integer_convert(comp_ctx, func_ctx, is_signed, vector,
                                        out_vector_type))) {
        return false;
    }

    /* v4f64 -> v2f64 */
    if (!(mask = LLVMConstVector(lanes, 2))) {
        HANDLE_FAILURE("LLVMConstVector");
        return false;
    }

    if (!(result = LLVMBuildShuffleVector(comp_ctx->builder, result, result,
                                          mask, "trunc"))) {
        HANDLE_FAILURE("LLVMBuildShuffleVector");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

static bool
simd_extadd_pairwise(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                     LLVMTypeRef in_vector_type, LLVMTypeRef out_vector_type,
                     bool is_signed)
{
    LLVMValueRef vector, even_mask, odd_mask, sub_vector_even, sub_vector_odd,
        result;

    LLVMValueRef even_element[] = {
        LLVM_CONST(i32_zero),   LLVM_CONST(i32_two),      LLVM_CONST(i32_four),
        LLVM_CONST(i32_six),    LLVM_CONST(i32_eight),    LLVM_CONST(i32_ten),
        LLVM_CONST(i32_twelve), LLVM_CONST(i32_fourteen),
    };

    LLVMValueRef odd_element[] = {
        LLVM_CONST(i32_one),      LLVM_CONST(i32_three),
        LLVM_CONST(i32_five),     LLVM_CONST(i32_seven),
        LLVM_CONST(i32_nine),     LLVM_CONST(i32_eleven),
        LLVM_CONST(i32_thirteen), LLVM_CONST(i32_fifteen),
    };

    /* assumption about i16x8 from i8x16 and i32x4 from i16x8 */
    uint8 mask_length = V128_i16x8_TYPE == out_vector_type ? 8 : 4;

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, in_vector_type,
                                             "vector"))) {
        return false;
    }

    if (!(even_mask = LLVMConstVector(even_element, mask_length))
        || !(odd_mask = LLVMConstVector(odd_element, mask_length))) {
        HANDLE_FAILURE("LLVMConstVector");
        return false;
    }

    /* shuffle a <16xi8> vector to two <8xi8> vectors */
    if (!(sub_vector_even = LLVMBuildShuffleVector(
              comp_ctx->builder, vector, vector, even_mask, "pick_even"))
        || !(sub_vector_odd = LLVMBuildShuffleVector(
                 comp_ctx->builder, vector, vector, odd_mask, "pick_odd"))) {
        HANDLE_FAILURE("LLVMBuildShuffleVector");
        return false;
    }

    /* sext/zext <8xi8> to <8xi16> */
    if (is_signed) {
        if (!(sub_vector_even =
                  LLVMBuildSExt(comp_ctx->builder, sub_vector_even,
                                out_vector_type, "even_sext"))
            || !(sub_vector_odd =
                     LLVMBuildSExt(comp_ctx->builder, sub_vector_odd,
                                   out_vector_type, "odd_sext"))) {
            HANDLE_FAILURE("LLVMBuildSExt");
            return false;
        }
    }
    else {
        if (!(sub_vector_even =
                  LLVMBuildZExt(comp_ctx->builder, sub_vector_even,
                                out_vector_type, "even_zext"))
            || !(sub_vector_odd =
                     LLVMBuildZExt(comp_ctx->builder, sub_vector_odd,
                                   out_vector_type, "odd_zext"))) {
            HANDLE_FAILURE("LLVMBuildZExt");
            return false;
        }
    }

    if (!(result = LLVMBuildAdd(comp_ctx->builder, sub_vector_even,
                                sub_vector_odd, "sum"))) {
        HANDLE_FAILURE("LLVMBuildAdd");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_i16x8_extadd_pairwise_i8x16(AOTCompContext *comp_ctx,
                                             AOTFuncContext *func_ctx,
                                             bool is_signed)
{
    return simd_extadd_pairwise(comp_ctx, func_ctx, V128_i8x16_TYPE,
                                V128_i16x8_TYPE, is_signed);
}

bool
aot_compile_simd_i32x4_extadd_pairwise_i16x8(AOTCompContext *comp_ctx,
                                             AOTFuncContext *func_ctx,
                                             bool is_signed)
{
    return simd_extadd_pairwise(comp_ctx, func_ctx, V128_i16x8_TYPE,
                                V128_i32x4_TYPE, is_signed);
}

bool
aot_compile_simd_i16x8_q15mulr_sat(AOTCompContext *comp_ctx,
                                   AOTFuncContext *func_ctx)
{
    LLVMValueRef lhs, rhs, pad, offset, min, max, result;
    LLVMTypeRef vector_ext_type;

    if (!(rhs = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, V128_i16x8_TYPE,
                                          "rhs"))
        || !(lhs = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                             V128_i16x8_TYPE, "lhs"))) {
        return false;
    }

    if (!(vector_ext_type = LLVMVectorType(I32_TYPE, 8))) {
        HANDLE_FAILURE("LLVMVectorType");
        return false;
    }

    if (!(lhs = LLVMBuildSExt(comp_ctx->builder, lhs, vector_ext_type,
                              "lhs_v8i32"))
        || !(rhs = LLVMBuildSExt(comp_ctx->builder, rhs, vector_ext_type,
                                 "rhs_v8i32"))) {
        HANDLE_FAILURE("LLVMBuildSExt");
        return false;
    }

    /* 0x4000 and 15*/
    if (!(pad = simd_build_splat_const_integer_vector(comp_ctx, I32_TYPE,
                                                      0x4000, 8))
        || !(offset = simd_build_splat_const_integer_vector(comp_ctx, I32_TYPE,
                                                            15, 8))) {
        return false;
    }

    /* TODO: looking for x86 intrinsics about integer"fused multiply-and-add" */
    /* S.SignedSaturate((x * y + 0x4000) >> 15) */
    if (!(result = LLVMBuildMul(comp_ctx->builder, lhs, rhs, "mul"))) {
        HANDLE_FAILURE("LLVMBuildMul");
        return false;
    }

    if (!(result = LLVMBuildAdd(comp_ctx->builder, result, pad, "add"))) {
        HANDLE_FAILURE("LLVMBuildAdd");
        return false;
    }

    if (!(result = LLVMBuildAShr(comp_ctx->builder, result, offset, "ashr"))) {
        HANDLE_FAILURE("LLVMBuildAShr");
        return false;
    }

    if (!(min = simd_build_splat_const_integer_vector(comp_ctx, I32_TYPE,
                                                      0xffff8000, 8))
        || !(max = simd_build_splat_const_integer_vector(comp_ctx, I32_TYPE,
                                                         0x00007fff, 8))) {
        return false;
    }

    /* sat after trunc will let *sat* part be optimized */
    if (!(result = simd_saturate(comp_ctx, func_ctx, e_sat_i32x8, result, min,
                                 max, true))) {
        return false;
    }

    if (!(result = LLVMBuildTrunc(comp_ctx->builder, result, V128_i16x8_TYPE,
                                  "down_to_v8i16"))) {
        HANDLE_FAILURE("LLVMBuidlTrunc");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

enum integer_extmul_type {
    e_i16x8_extmul_i8x16,
    e_i32x4_extmul_i16x8,
    e_i64x2_extmul_i32x4,
};

static bool
simd_integer_extmul(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                    bool lower_half, bool is_signed,
                    enum integer_extmul_type itype)
{
    LLVMValueRef vec1, vec2, result;
    enum integer_extend_type ext_type[] = {
        e_ext_i8x16,
        e_ext_i16x8,
        e_ext_i32x4,
    };
    LLVMTypeRef in_vector_type[] = {
        V128_i8x16_TYPE,
        V128_i16x8_TYPE,
        V128_i32x4_TYPE,
    };

    if (!(vec1 = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                           in_vector_type[itype], "vec1"))
        || !(vec2 = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                              in_vector_type[itype], "vec2"))) {
        return false;
    }

    if (!(vec1 = simd_integer_extension(comp_ctx, func_ctx, ext_type[itype],
                                        vec1, lower_half, is_signed))
        || !(vec2 = simd_integer_extension(comp_ctx, func_ctx, ext_type[itype],
                                           vec2, lower_half, is_signed))) {
        return false;
    }

    if (!(result = LLVMBuildMul(comp_ctx->builder, vec1, vec2, "product"))) {
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_i16x8_extmul_i8x16(AOTCompContext *comp_ctx,
                                    AOTFuncContext *func_ctx, bool lower_half,
                                    bool is_signed)
{
    return simd_integer_extmul(comp_ctx, func_ctx, lower_half, is_signed,
                               e_i16x8_extmul_i8x16);
}

bool
aot_compile_simd_i32x4_extmul_i16x8(AOTCompContext *comp_ctx,
                                    AOTFuncContext *func_ctx, bool lower_half,
                                    bool is_signed)
{
    return simd_integer_extmul(comp_ctx, func_ctx, lower_half, is_signed,
                               e_i32x4_extmul_i16x8);
}

bool
aot_compile_simd_i64x2_extmul_i32x4(AOTCompContext *comp_ctx,
                                    AOTFuncContext *func_ctx, bool lower_half,
                                    bool is_signed)
{
    return simd_integer_extmul(comp_ctx, func_ctx, lower_half, is_signed,
                               e_i64x2_extmul_i32x4);
}
