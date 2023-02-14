/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "simd_bitwise_ops.h"
#include "../aot_emit_exception.h"
#include "../../aot/aot_runtime.h"

static bool
v128_bitwise_two_component(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           V128Bitwise bitwise_op)
{
    LLVMValueRef vector1, vector2, result;

    POP_V128(vector2);
    POP_V128(vector1);

    switch (bitwise_op) {
        case V128_AND:
            if (!(result = LLVMBuildAnd(comp_ctx->builder, vector1, vector2,
                                        "and"))) {
                HANDLE_FAILURE("LLVMBuildAnd");
                goto fail;
            }
            break;
        case V128_OR:
            if (!(result =
                      LLVMBuildOr(comp_ctx->builder, vector1, vector2, "or"))) {
                HANDLE_FAILURE("LLVMBuildAnd");
                goto fail;
            }
            break;
        case V128_XOR:
            if (!(result = LLVMBuildXor(comp_ctx->builder, vector1, vector2,
                                        "xor"))) {
                HANDLE_FAILURE("LLVMBuildAnd");
                goto fail;
            }
            break;
        case V128_ANDNOT:
        {
            /* v128.and(a, v128.not(b)) */
            if (!(vector2 = LLVMBuildNot(comp_ctx->builder, vector2, "not"))) {
                HANDLE_FAILURE("LLVMBuildNot");
                goto fail;
            }

            if (!(result = LLVMBuildAnd(comp_ctx->builder, vector1, vector2,
                                        "and"))) {
                HANDLE_FAILURE("LLVMBuildAnd");
                goto fail;
            }

            break;
        }
        default:
            bh_assert(0);
            goto fail;
    }

    PUSH_V128(result);
    return true;
fail:
    return false;
}

static bool
v128_bitwise_not(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef vector, result;

    POP_V128(vector);

    if (!(result = LLVMBuildNot(comp_ctx->builder, vector, "not"))) {
        HANDLE_FAILURE("LLVMBuildNot");
        goto fail;
    }

    PUSH_V128(result);
    return true;
fail:
    return false;
}

/* v128.or(v128.and(v1, c), v128.and(v2, v128.not(c))) */
static bool
v128_bitwise_bitselect(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef vector1, vector2, vector3, result;

    POP_V128(vector3);
    POP_V128(vector2);
    POP_V128(vector1);

    if (!(vector1 =
              LLVMBuildAnd(comp_ctx->builder, vector1, vector3, "a_and_c"))) {
        HANDLE_FAILURE("LLVMBuildAdd");
        goto fail;
    }

    if (!(vector3 = LLVMBuildNot(comp_ctx->builder, vector3, "not_c"))) {
        HANDLE_FAILURE("LLVMBuildNot");
        goto fail;
    }

    if (!(vector2 =
              LLVMBuildAnd(comp_ctx->builder, vector2, vector3, "b_and_c"))) {
        HANDLE_FAILURE("LLVMBuildAdd");
        goto fail;
    }

    if (!(result =
              LLVMBuildOr(comp_ctx->builder, vector1, vector2, "a_or_b"))) {
        HANDLE_FAILURE("LLVMBuildOr");
        goto fail;
    }

    PUSH_V128(result);

    return true;
fail:
    return false;
}

bool
aot_compile_simd_v128_bitwise(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, V128Bitwise bitwise_op)
{
    switch (bitwise_op) {
        case V128_AND:
        case V128_OR:
        case V128_XOR:
        case V128_ANDNOT:
            return v128_bitwise_two_component(comp_ctx, func_ctx, bitwise_op);
        case V128_NOT:
            return v128_bitwise_not(comp_ctx, func_ctx);
        case V128_BITSELECT:
            return v128_bitwise_bitselect(comp_ctx, func_ctx);
        default:
            bh_assert(0);
            return false;
    }
}
