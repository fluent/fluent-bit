/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "simd_sat_int_arith.h"
#include "simd_common.h"
#include "../aot_emit_exception.h"
#include "../../aot/aot_runtime.h"

static bool
simd_sat_int_arith(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                   LLVMTypeRef vector_type, const char *intrinsics)
{
    LLVMValueRef lhs, rhs, result;
    LLVMTypeRef param_types[2];

    if (!(rhs =
              simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type, "rhs"))
        || !(lhs = simd_pop_v128_and_bitcast(comp_ctx, func_ctx, vector_type,
                                             "lhs"))) {
        return false;
    }

    param_types[0] = vector_type;
    param_types[1] = vector_type;

    if (!(result =
              aot_call_llvm_intrinsic(comp_ctx, func_ctx, intrinsics,
                                      vector_type, param_types, 2, lhs, rhs))) {
        HANDLE_FAILURE("LLVMBuildCall");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_i8x16_saturate(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx,
                                V128Arithmetic arith_op, bool is_signed)
{
    char *intrinsics[][2] = {
        { "llvm.sadd.sat.v16i8", "llvm.uadd.sat.v16i8" },
        { "llvm.ssub.sat.v16i8", "llvm.usub.sat.v16i8" },
    };

    return simd_sat_int_arith(comp_ctx, func_ctx, V128_i8x16_TYPE,
                              is_signed ? intrinsics[arith_op][0]
                                        : intrinsics[arith_op][1]);
}

bool
aot_compile_simd_i16x8_saturate(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx,
                                V128Arithmetic arith_op, bool is_signed)
{
    char *intrinsics[][2] = {
        { "llvm.sadd.sat.v8i16", "llvm.uadd.sat.v8i16" },
        { "llvm.ssub.sat.v8i16", "llvm.usub.sat.v8i16" },
    };

    return simd_sat_int_arith(comp_ctx, func_ctx, V128_i16x8_TYPE,
                              is_signed ? intrinsics[arith_op][0]
                                        : intrinsics[arith_op][1]);
}
