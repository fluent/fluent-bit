/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_emit_compare.h"
#include "../aot/aot_intrinsic.h"

static bool
int_cond_to_llvm_op(IntCond cond, LLVMIntPredicate *op)
{
    if (cond < INT_EQZ || cond > INT_GE_U)
        return false;

    switch (cond) {
        case INT_EQZ:
        case INT_EQ:
            *op = LLVMIntEQ;
            break;
        case INT_NE:
            *op = LLVMIntNE;
            break;
        case INT_LT_S:
            *op = LLVMIntSLT;
            break;
        case INT_LT_U:
            *op = LLVMIntULT;
            break;
        case INT_GT_S:
            *op = LLVMIntSGT;
            break;
        case INT_GT_U:
            *op = LLVMIntUGT;
            break;
        case INT_LE_S:
            *op = LLVMIntSLE;
            break;
        case INT_LE_U:
            *op = LLVMIntULE;
            break;
        case INT_GE_S:
            *op = LLVMIntSGE;
            break;
        case INT_GE_U:
            *op = LLVMIntUGE;
            break;
        default:
            return false;
    }

    return true;
}

static bool
float_cond_to_llvm_op(FloatCond cond, LLVMRealPredicate *op)
{
    if (cond < FLOAT_EQ || cond > FLOAT_GE)
        return false;

    switch (cond) {
        case FLOAT_EQ:
            *op = LLVMRealOEQ;
            break;
        case FLOAT_NE:
            *op = LLVMRealUNE;
            break;
        case FLOAT_LT:
            *op = LLVMRealOLT;
            break;
        case FLOAT_GT:
            *op = LLVMRealOGT;
            break;
        case FLOAT_LE:
            *op = LLVMRealOLE;
            break;
        case FLOAT_GE:
            *op = LLVMRealOGE;
            break;
        default:
            return false;
    }

    return true;
}

bool
aot_compile_op_i32_compare(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           IntCond cond)
{
    LLVMIntPredicate op;
    LLVMValueRef lhs, rhs, res;

    if (!int_cond_to_llvm_op(cond, &op)) {
        aot_set_last_error("invalid WASM condition opcode");
        return false;
    }

    if (cond == INT_EQZ)
        rhs = I32_ZERO;
    else
        POP_I32(rhs);

    POP_I32(lhs);

    if (!(res = LLVMBuildICmp(comp_ctx->builder, op, lhs, rhs, "i32_cmp"))) {
        aot_set_last_error("llvm build compare failed.");
        return false;
    }

    PUSH_COND(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_i64_compare(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           IntCond cond)
{
    LLVMIntPredicate op;
    LLVMValueRef lhs, rhs, res;

    if (!int_cond_to_llvm_op(cond, &op)) {
        aot_set_last_error("invalid WASM condition opcode");
        return false;
    }

    if (cond == INT_EQZ)
        rhs = I64_CONST(0);
    else
        POP_I64(rhs);

    POP_I64(lhs);

    if (!(res = LLVMBuildICmp(comp_ctx->builder, op, lhs, rhs, "i64_cmp"))) {
        aot_set_last_error("llvm build compare failed.");
        return false;
    }

    PUSH_COND(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_f32_compare(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           FloatCond cond)
{
    LLVMRealPredicate op;
    LLVMValueRef lhs, rhs, res;

    if (!float_cond_to_llvm_op(cond, &op)) {
        aot_set_last_error("invalid WASM condition opcode");
        return false;
    }

    POP_F32(rhs);
    POP_F32(lhs);

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(comp_ctx, "f32_cmp")) {
        LLVMTypeRef param_types[3];
        LLVMValueRef opcond = LLVMConstInt(I32_TYPE, cond, true);
        param_types[0] = I32_TYPE;
        param_types[1] = F32_TYPE;
        param_types[2] = F32_TYPE;
        res = aot_call_llvm_intrinsic(comp_ctx, func_ctx, "f32_cmp", I32_TYPE,
                                      param_types, 3, opcond, lhs, rhs);
        if (!res) {
            goto fail;
        }
        res = LLVMBuildIntCast(comp_ctx->builder, res, INT1_TYPE, "bit_cast");
    }
    else {
        res = LLVMBuildFCmp(comp_ctx->builder, op, lhs, rhs, "f32_cmp");
    }

    if (!res) {
        aot_set_last_error("llvm build compare failed.");
        return false;
    }

    PUSH_COND(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_f64_compare(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           FloatCond cond)
{
    LLVMRealPredicate op;
    LLVMValueRef lhs, rhs, res;

    if (!float_cond_to_llvm_op(cond, &op)) {
        aot_set_last_error("invalid WASM condition opcode");
        return false;
    }

    POP_F64(rhs);
    POP_F64(lhs);

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(comp_ctx, "f64_cmp")) {
        LLVMTypeRef param_types[3];
        LLVMValueRef opcond = LLVMConstInt(I32_TYPE, cond, true);
        param_types[0] = I32_TYPE;
        param_types[1] = F64_TYPE;
        param_types[2] = F64_TYPE;
        res = aot_call_llvm_intrinsic(comp_ctx, func_ctx, "f64_cmp", I32_TYPE,
                                      param_types, 3, opcond, lhs, rhs);
        if (!res) {
            goto fail;
        }
        res = LLVMBuildIntCast(comp_ctx->builder, res, INT1_TYPE, "bit_cast");
    }
    else {
        res = LLVMBuildFCmp(comp_ctx->builder, op, lhs, rhs, "f64_cmp");
    }

    if (!res) {
        aot_set_last_error("llvm build compare failed.");
        return false;
    }

    PUSH_COND(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_ref_eq(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef gc_obj1 = NULL, gc_obj2 = NULL, res;

    POP_GC_REF(gc_obj1);
    POP_GC_REF(gc_obj2);

    /* LLVM pointer values pointers are compared using LLVMBuildICmp */
    res = LLVMBuildICmp(comp_ctx->builder, LLVMIntEQ, gc_obj1, gc_obj2,
                        "cmp_gc_obj_eq");

    if (!res) {
        aot_set_last_error("llvm build compare failed.");
        return false;
    }

    PUSH_COND(res);

    return true;
fail:
    return false;
}
