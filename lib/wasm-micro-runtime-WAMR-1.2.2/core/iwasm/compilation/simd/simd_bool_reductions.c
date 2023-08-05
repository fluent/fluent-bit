/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "simd_bool_reductions.h"
#include "simd_common.h"
#include "../aot_emit_exception.h"
#include "../../aot/aot_runtime.h"

enum integer_all_true {
    e_int_all_true_v16i8,
    e_int_all_true_v8i16,
    e_int_all_true_v4i32,
    e_int_all_true_v2i64,
};

static bool
simd_all_true(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
              enum integer_all_true itype)
{
    LLVMValueRef vector, result;
    LLVMTypeRef vector_i1_type;
    LLVMTypeRef vector_type[] = { V128_i8x16_TYPE, V128_i16x8_TYPE,
                                  V128_i32x4_TYPE, V128_i64x2_TYPE };
    uint32 lanes[] = { 16, 8, 4, 2 };
    const char *intrinsic[] = {
        "llvm.vector.reduce.and.v16i1",
        "llvm.vector.reduce.and.v8i1",
        "llvm.vector.reduce.and.v4i1",
        "llvm.vector.reduce.and.v2i1",
    };
    LLVMValueRef zero[] = {
        LLVM_CONST(i8x16_vec_zero),
        LLVM_CONST(i16x8_vec_zero),
        LLVM_CONST(i32x4_vec_zero),
        LLVM_CONST(i64x2_vec_zero),
    };

    if (!(vector_i1_type = LLVMVectorType(INT1_TYPE, lanes[itype]))) {
        HANDLE_FAILURE("LLVMVectorType");
        goto fail;
    }

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx,
                                             vector_type[itype], "vector"))) {
        goto fail;
    }

    /* compare with zero */
    if (!(result = LLVMBuildICmp(comp_ctx->builder, LLVMIntNE, vector,
                                 zero[itype], "ne_zero"))) {
        HANDLE_FAILURE("LLVMBuildICmp");
        goto fail;
    }

    /* check zero */
    if (!(result =
              aot_call_llvm_intrinsic(comp_ctx, func_ctx, intrinsic[itype],
                                      INT1_TYPE, &vector_i1_type, 1, result))) {
        goto fail;
    }

    if (!(result =
              LLVMBuildZExt(comp_ctx->builder, result, I32_TYPE, "to_i32"))) {
        HANDLE_FAILURE("LLVMBuildZExt");
        goto fail;
    }

    PUSH_I32(result);

    return true;
fail:
    return false;
}

bool
aot_compile_simd_i8x16_all_true(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx)
{
    return simd_all_true(comp_ctx, func_ctx, e_int_all_true_v16i8);
}

bool
aot_compile_simd_i16x8_all_true(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx)
{
    return simd_all_true(comp_ctx, func_ctx, e_int_all_true_v8i16);
}

bool
aot_compile_simd_i32x4_all_true(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx)
{
    return simd_all_true(comp_ctx, func_ctx, e_int_all_true_v4i32);
}

bool
aot_compile_simd_i64x2_all_true(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx)
{
    return simd_all_true(comp_ctx, func_ctx, e_int_all_true_v2i64);
}

bool
aot_compile_simd_v128_any_true(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx)
{
    LLVMTypeRef vector_type;
    LLVMValueRef vector, result;

    if (!(vector_type = LLVMVectorType(INT1_TYPE, 128))) {
        return false;
    }

    if (!(vector = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                             "vector"))) {
        goto fail;
    }

    if (!(result = aot_call_llvm_intrinsic(
              comp_ctx, func_ctx, "llvm.vector.reduce.or.v128i1", INT1_TYPE,
              &vector_type, 1, vector))) {
        goto fail;
    }

    if (!(result =
              LLVMBuildZExt(comp_ctx->builder, result, I32_TYPE, "to_i32"))) {
        HANDLE_FAILURE("LLVMBuildZExt");
        goto fail;
    }

    PUSH_I32(result);

    return true;
fail:
    return false;
}
