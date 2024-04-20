/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "simd_bit_shifts.h"
#include "simd_common.h"
#include "../aot_emit_exception.h"
#include "../../aot/aot_runtime.h"

enum integer_shift {
    e_shift_i8x16,
    e_shift_i16x8,
    e_shift_i32x4,
    e_shift_i64x2,
};

static bool
simd_shift(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
           IntShift shift_op, enum integer_shift itype)
{
    LLVMValueRef vector, offset, result = NULL;
    LLVMTypeRef vector_type[] = { V128_i8x16_TYPE, V128_i16x8_TYPE,
                                  V128_i32x4_TYPE, V128_i64x2_TYPE };
    LLVMTypeRef element_type[] = { INT8_TYPE, INT16_TYPE, I32_TYPE, I64_TYPE };

    LLVMValueRef undef[] = { LLVM_CONST(i8x16_undef), LLVM_CONST(i16x8_undef),
                             LLVM_CONST(i32x4_undef), LLVM_CONST(i64x2_undef) };
    LLVMValueRef mask[] = { LLVM_CONST(i8x16_vec_zero),
                            LLVM_CONST(i16x8_vec_zero),
                            LLVM_CONST(i32x4_vec_zero),
                            LLVM_CONST(i64x2_vec_zero) };
    LLVMValueRef lane_shift_masks[] = {
        LLVMConstInt(I32_TYPE, 7, true),
        LLVMConstInt(I32_TYPE, 15, true),
        LLVMConstInt(I32_TYPE, 31, true),
        LLVMConstInt(I32_TYPE, 63, true),
    };

    POP_I32(offset);

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                             vector_type[itype], "vec"))) {
        return false;
    }

    /* offset = offset & shift_mask */
    if (!lane_shift_masks[itype]
        || !(offset = LLVMBuildAnd(comp_ctx->builder, offset,
                                   lane_shift_masks[itype], "offset_fix"))) {
        HANDLE_FAILURE("LLVMBuildAnd");
        return false;
    }

    /* change type */
    if (itype < e_shift_i32x4) {
        offset = LLVMBuildTrunc(comp_ctx->builder, offset, element_type[itype],
                                "offset_trunc");
    }
    else if (itype == e_shift_i64x2) {
        offset = LLVMBuildZExt(comp_ctx->builder, offset, element_type[itype],
                               "offset_ext");
    }

    if (!offset) {
        HANDLE_FAILURE("LLVMBuildZext/LLVMBuildTrunc");
        return false;
    }

    /* splat to a vector */
    if (!(offset =
              LLVMBuildInsertElement(comp_ctx->builder, undef[itype], offset,
                                     I32_ZERO, "offset_vector_base"))) {
        HANDLE_FAILURE("LLVMBuildInsertElement");
        return false;
    }

    if (!(offset =
              LLVMBuildShuffleVector(comp_ctx->builder, offset, undef[itype],
                                     mask[itype], "offset_vector"))) {
        HANDLE_FAILURE("LLVMBuildShuffleVector");
        return false;
    }

    switch (shift_op) {
        case INT_SHL:
        {
            result = LLVMBuildShl(comp_ctx->builder, vector, offset, "shl");
            break;
        }
        case INT_SHR_S:
        {
            result = LLVMBuildAShr(comp_ctx->builder, vector, offset, "ashr");
            break;
        }
        case INT_SHR_U:
        {
            result = LLVMBuildLShr(comp_ctx->builder, vector, offset, "lshr");
            break;
        }
        default:
        {
            break;
        }
    }

    if (!result) {
        HANDLE_FAILURE("LLVMBuildShl/LLVMBuildLShr/LLVMBuildAShr");
        goto fail;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");

fail:
    return false;
}

bool
aot_compile_simd_i8x16_shift(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             IntShift shift_op)
{
    return simd_shift(comp_ctx, func_ctx, shift_op, e_shift_i8x16);
}

bool
aot_compile_simd_i16x8_shift(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             IntShift shift_op)
{
    return simd_shift(comp_ctx, func_ctx, shift_op, e_shift_i16x8);
}

bool
aot_compile_simd_i32x4_shift(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             IntShift shift_op)
{
    return simd_shift(comp_ctx, func_ctx, shift_op, e_shift_i32x4);
}

bool
aot_compile_simd_i64x2_shift(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             IntShift shift_op)
{
    return simd_shift(comp_ctx, func_ctx, shift_op, e_shift_i64x2);
}
