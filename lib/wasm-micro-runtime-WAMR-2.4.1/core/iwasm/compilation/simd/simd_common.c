/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "simd_common.h"

LLVMValueRef
simd_pop_v128_and_bitcast(const AOTCompContext *comp_ctx,
                          const AOTFuncContext *func_ctx, LLVMTypeRef vec_type,
                          const char *name)
{
    LLVMValueRef number;

    POP_V128(number);

    if (!(number =
              LLVMBuildBitCast(comp_ctx->builder, number, vec_type, name))) {
        HANDLE_FAILURE("LLVMBuildBitCast");
        goto fail;
    }

    return number;
fail:
    return NULL;
}

bool
simd_bitcast_and_push_v128(const AOTCompContext *comp_ctx,
                           const AOTFuncContext *func_ctx, LLVMValueRef vector,
                           const char *name)
{
    if (!(vector = LLVMBuildBitCast(comp_ctx->builder, vector, V128_i64x2_TYPE,
                                    name))) {
        HANDLE_FAILURE("LLVMBuildBitCast");
        goto fail;
    }

    /* push result into the stack */
    PUSH_V128(vector);

    return true;
fail:
    return false;
}

LLVMValueRef
simd_lane_id_to_llvm_value(AOTCompContext *comp_ctx, uint8 lane_id)
{
    LLVMValueRef lane_indexes[] = {
        LLVM_CONST(i32_zero),     LLVM_CONST(i32_one),
        LLVM_CONST(i32_two),      LLVM_CONST(i32_three),
        LLVM_CONST(i32_four),     LLVM_CONST(i32_five),
        LLVM_CONST(i32_six),      LLVM_CONST(i32_seven),
        LLVM_CONST(i32_eight),    LLVM_CONST(i32_nine),
        LLVM_CONST(i32_ten),      LLVM_CONST(i32_eleven),
        LLVM_CONST(i32_twelve),   LLVM_CONST(i32_thirteen),
        LLVM_CONST(i32_fourteen), LLVM_CONST(i32_fifteen),
    };

    return lane_id < 16 ? lane_indexes[lane_id] : NULL;
}

LLVMValueRef
simd_build_const_integer_vector(const AOTCompContext *comp_ctx,
                                const LLVMTypeRef element_type,
                                const int *element_value, uint32 length)
{
    LLVMValueRef vector = NULL;
    LLVMValueRef *elements;
    unsigned i;

    if (!(elements = wasm_runtime_malloc(sizeof(LLVMValueRef) * length))) {
        return NULL;
    }

    for (i = 0; i < length; i++) {
        if (!(elements[i] =
                  LLVMConstInt(element_type, element_value[i], true))) {
            HANDLE_FAILURE("LLVMConstInst");
            goto fail;
        }
    }

    if (!(vector = LLVMConstVector(elements, length))) {
        HANDLE_FAILURE("LLVMConstVector");
        goto fail;
    }

fail:
    wasm_runtime_free(elements);
    return vector;
}

LLVMValueRef
simd_build_splat_const_integer_vector(const AOTCompContext *comp_ctx,
                                      const LLVMTypeRef element_type,
                                      const int64 element_value, uint32 length)
{
    LLVMValueRef vector = NULL, element;
    LLVMValueRef *elements;
    unsigned i;

    if (!(elements = wasm_runtime_malloc(sizeof(LLVMValueRef) * length))) {
        return NULL;
    }

    if (!(element = LLVMConstInt(element_type, element_value, true))) {
        HANDLE_FAILURE("LLVMConstInt");
        goto fail;
    }

    for (i = 0; i < length; i++) {
        elements[i] = element;
    }

    if (!(vector = LLVMConstVector(elements, length))) {
        HANDLE_FAILURE("LLVMConstVector");
        goto fail;
    }

fail:
    wasm_runtime_free(elements);
    return vector;
}

LLVMValueRef
simd_build_splat_const_float_vector(const AOTCompContext *comp_ctx,
                                    const LLVMTypeRef element_type,
                                    const float element_value, uint32 length)
{
    LLVMValueRef vector = NULL, element;
    LLVMValueRef *elements;
    unsigned i;

    if (!(elements = wasm_runtime_malloc(sizeof(LLVMValueRef) * length))) {
        return NULL;
    }

    if (!(element = LLVMConstReal(element_type, element_value))) {
        HANDLE_FAILURE("LLVMConstReal");
        goto fail;
    }

    for (i = 0; i < length; i++) {
        elements[i] = element;
    }

    if (!(vector = LLVMConstVector(elements, length))) {
        HANDLE_FAILURE("LLVMConstVector");
        goto fail;
    }

fail:
    wasm_runtime_free(elements);
    return vector;
}
