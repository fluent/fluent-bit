/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "simd_bitmask_extracts.h"
#include "simd_common.h"
#include "../aot_emit_exception.h"
#include "../../aot/aot_runtime.h"

enum integer_bitmask_type {
    e_bitmask_i8x16,
    e_bitmask_i16x8,
    e_bitmask_i32x4,
    e_bitmask_i64x2,
};

/* TODO: should use a much clever intrinsic */
static bool
simd_build_bitmask(const AOTCompContext *comp_ctx,
                   const AOTFuncContext *func_ctx,
                   enum integer_bitmask_type itype)
{
    LLVMValueRef vector, mask, result;
    uint8 i;
    LLVMTypeRef vector_ext_type;

    uint32 lanes[] = { 16, 8, 4, 2 };
    uint32 lane_bits[] = { 8, 16, 32, 64 };
    LLVMTypeRef element_type[] = { INT8_TYPE, INT16_TYPE, I32_TYPE, I64_TYPE };
    LLVMTypeRef vector_type[] = { V128_i8x16_TYPE, V128_i16x8_TYPE,
                                  V128_i32x4_TYPE, V128_i64x2_TYPE };
    int32 mask_element[16] = { 0 };
    const char *intrinsic[] = {
        "llvm.vector.reduce.or.v16i64",
        "llvm.vector.reduce.or.v8i64",
        "llvm.vector.reduce.or.v4i64",
        "llvm.vector.reduce.or.v2i64",
    };

    LLVMValueRef ashr_distance;

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                             vector_type[itype], "vec"))) {
        goto fail;
    }

    /* fill every bit in a lange with its sign bit */
    if (!(ashr_distance = simd_build_splat_const_integer_vector(
              comp_ctx, element_type[itype], lane_bits[itype] - 1,
              lanes[itype]))) {
        goto fail;
    }

    if (!(vector = LLVMBuildAShr(comp_ctx->builder, vector, ashr_distance,
                                 "vec_ashr"))) {
        HANDLE_FAILURE("LLVMBuildAShr");
        goto fail;
    }

    if (!(vector_ext_type = LLVMVectorType(I64_TYPE, lanes[itype]))) {
        HANDLE_FAILURE("LLVMVectorType");
        goto fail;
    }

    if (e_bitmask_i64x2 != itype) {
        if (!(vector = LLVMBuildSExt(comp_ctx->builder, vector, vector_ext_type,
                                     "zext_to_i64"))) {
            goto fail;
        }
    }

    for (i = 0; i < 16; i++) {
        mask_element[i] = 0x1 << i;
    }

    if (!(mask = simd_build_const_integer_vector(comp_ctx, I64_TYPE,
                                                 mask_element, lanes[itype]))) {
        goto fail;
    }

    if (!(vector =
              LLVMBuildAnd(comp_ctx->builder, vector, mask, "mask_bits"))) {
        HANDLE_FAILURE("LLVMBuildAnd");
        goto fail;
    }

    if (!(result =
              aot_call_llvm_intrinsic(comp_ctx, func_ctx, intrinsic[itype],
                                      I64_TYPE, &vector_ext_type, 1, vector))) {
        goto fail;
    }

    if (!(result =
              LLVMBuildTrunc(comp_ctx->builder, result, I32_TYPE, "to_i32"))) {
        HANDLE_FAILURE("LLVMBuildTrunc");
        goto fail;
    }

    PUSH_I32(result);

    return true;
fail:
    return false;
}

bool
aot_compile_simd_i8x16_bitmask(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx)
{
    return simd_build_bitmask(comp_ctx, func_ctx, e_bitmask_i8x16);
}

bool
aot_compile_simd_i16x8_bitmask(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx)
{
    return simd_build_bitmask(comp_ctx, func_ctx, e_bitmask_i16x8);
}

bool
aot_compile_simd_i32x4_bitmask(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx)
{
    return simd_build_bitmask(comp_ctx, func_ctx, e_bitmask_i32x4);
}

bool
aot_compile_simd_i64x2_bitmask(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx)
{
    return simd_build_bitmask(comp_ctx, func_ctx, e_bitmask_i64x2);
}
