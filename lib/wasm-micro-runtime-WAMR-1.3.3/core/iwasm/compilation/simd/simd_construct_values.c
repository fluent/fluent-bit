/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "simd_common.h"
#include "simd_construct_values.h"
#include "../aot_emit_exception.h"
#include "../interpreter/wasm_opcode.h"
#include "../../aot/aot_runtime.h"

bool
aot_compile_simd_v128_const(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            const uint8 *imm_bytes)
{
    uint64 imm1, imm2;
    LLVMValueRef first_long, agg1, second_long, agg2;

    wasm_runtime_read_v128(imm_bytes, &imm1, &imm2);

    /* %agg1 = insertelement <2 x i64> undef, i16 0, i64 ${*imm} */
    if (!(first_long = I64_CONST(imm1))) {
        HANDLE_FAILURE("LLVMConstInt");
        goto fail;
    }

    if (!(agg1 =
              LLVMBuildInsertElement(comp_ctx->builder, LLVM_CONST(i64x2_undef),
                                     first_long, I32_ZERO, "agg1"))) {
        HANDLE_FAILURE("LLVMBuildInsertElement");
        goto fail;
    }

    /* %agg2 = insertelement <2 x i64> %agg1, i16 1, i64 ${*(imm + 1)} */
    if (!(second_long = I64_CONST(imm2))) {
        HANDLE_FAILURE("LLVMGetUndef");
        goto fail;
    }

    if (!(agg2 = LLVMBuildInsertElement(comp_ctx->builder, agg1, second_long,
                                        I32_ONE, "agg2"))) {
        HANDLE_FAILURE("LLVMBuildInsertElement");
        goto fail;
    }

    PUSH_V128(agg2);
    return true;
fail:
    return false;
}

bool
aot_compile_simd_splat(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                       uint8 opcode)
{
    uint32 opcode_index = opcode - SIMD_i8x16_splat;
    LLVMValueRef value = NULL, base, new_vector;
    LLVMValueRef undefs[] = {
        LLVM_CONST(i8x16_undef), LLVM_CONST(i16x8_undef),
        LLVM_CONST(i32x4_undef), LLVM_CONST(i64x2_undef),
        LLVM_CONST(f32x4_undef), LLVM_CONST(f64x2_undef),
    };
    LLVMValueRef masks[] = {
        LLVM_CONST(i32x16_zero), LLVM_CONST(i32x8_zero), LLVM_CONST(i32x4_zero),
        LLVM_CONST(i32x2_zero),  LLVM_CONST(i32x4_zero), LLVM_CONST(i32x2_zero),
    };

    switch (opcode) {
        case SIMD_i8x16_splat:
        {
            LLVMValueRef input;
            POP_I32(input);
            /* trunc i32 %input to i8 */
            value =
                LLVMBuildTrunc(comp_ctx->builder, input, INT8_TYPE, "trunc");
            break;
        }
        case SIMD_i16x8_splat:
        {
            LLVMValueRef input;
            POP_I32(input);
            /* trunc i32 %input to i16 */
            value =
                LLVMBuildTrunc(comp_ctx->builder, input, INT16_TYPE, "trunc");
            break;
        }
        case SIMD_i32x4_splat:
        {
            POP_I32(value);
            break;
        }
        case SIMD_i64x2_splat:
        {
            POP(value, VALUE_TYPE_I64);
            break;
        }
        case SIMD_f32x4_splat:
        {
            POP(value, VALUE_TYPE_F32);
            break;
        }
        case SIMD_f64x2_splat:
        {
            POP(value, VALUE_TYPE_F64);
            break;
        }
        default:
        {
            break;
        }
    }

    if (!value) {
        goto fail;
    }

    /* insertelement <n x ty> undef, ty %value, i32 0 */
    if (!(base = LLVMBuildInsertElement(comp_ctx->builder, undefs[opcode_index],
                                        value, I32_ZERO, "base"))) {
        HANDLE_FAILURE("LLVMBuildInsertElement");
        goto fail;
    }

    /* shufflevector <ty1> %base, <ty2> undef, <n x i32> zeroinitializer */
    if (!(new_vector = LLVMBuildShuffleVector(
              comp_ctx->builder, base, undefs[opcode_index],
              masks[opcode_index], "new_vector"))) {
        HANDLE_FAILURE("LLVMBuildShuffleVector");
        goto fail;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, new_vector, "result");
fail:
    return false;
}
