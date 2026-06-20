/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_emit_conversion.h"
#include "aot_emit_exception.h"
#include "aot_emit_numberic.h"
#include "../aot/aot_intrinsic.h"
#include "../aot/aot_runtime.h"

static LLVMValueRef
call_fcmp_intrinsic(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                    enum AOTFloatCond cond, LLVMRealPredicate op,
                    LLVMValueRef lhs, LLVMValueRef rhs, LLVMTypeRef src_type,
                    const char *name)
{
    LLVMValueRef res = NULL;
    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(
            comp_ctx, src_type == F32_TYPE ? "f32_cmp" : "f64_cmp")) {
        LLVMTypeRef param_types[3];
        LLVMValueRef opcond = LLVMConstInt(I32_TYPE, cond, true);
        param_types[0] = I32_TYPE;
        param_types[1] = src_type;
        param_types[2] = src_type;
        res = aot_call_llvm_intrinsic(
            comp_ctx, func_ctx, src_type == F32_TYPE ? "f32_cmp" : "f64_cmp",
            I32_TYPE, param_types, 3, opcond, lhs, rhs);
        if (!res) {
            goto fail;
        }
        res = LLVMBuildIntCast(comp_ctx->builder, res, INT1_TYPE, "bit_cast");
    }
    else {
        res = LLVMBuildFCmp(comp_ctx->builder, op, lhs, rhs, name);
    }
fail:
    return res;
}

static bool
trunc_float_to_int(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                   LLVMValueRef operand, LLVMTypeRef src_type,
                   LLVMTypeRef dest_type, LLVMValueRef min_value,
                   LLVMValueRef max_value, char *name, bool sign)
{
    LLVMBasicBlockRef check_nan_succ, check_overflow_succ;
    LLVMValueRef is_less, is_greater, res;

    res = call_fcmp_intrinsic(comp_ctx, func_ctx, FLOAT_UNO, LLVMRealUNO,
                              operand, operand, src_type, "fcmp_is_nan");

    if (!res) {
        aot_set_last_error("llvm build fcmp failed.");
        goto fail;
    }

    if (!(check_nan_succ = LLVMAppendBasicBlockInContext(
              comp_ctx->context, func_ctx->func, "check_nan_succ"))) {
        aot_set_last_error("llvm add basic block failed.");
        goto fail;
    }

    LLVMMoveBasicBlockAfter(check_nan_succ,
                            LLVMGetInsertBlock(comp_ctx->builder));

    if (!(aot_emit_exception(comp_ctx, func_ctx,
                             EXCE_INVALID_CONVERSION_TO_INTEGER, true, res,
                             check_nan_succ)))
        goto fail;

    is_less =
        call_fcmp_intrinsic(comp_ctx, func_ctx, FLOAT_LE, LLVMRealOLE, operand,
                            min_value, src_type, "fcmp_min_value");

    if (!is_less) {
        aot_set_last_error("llvm build fcmp failed.");
        goto fail;
    }

    is_greater =
        call_fcmp_intrinsic(comp_ctx, func_ctx, FLOAT_GE, LLVMRealOGE, operand,
                            max_value, src_type, "fcmp_min_value");

    if (!is_greater) {
        aot_set_last_error("llvm build fcmp failed.");
        goto fail;
    }

    if (!(res = LLVMBuildOr(comp_ctx->builder, is_less, is_greater,
                            "is_overflow"))) {
        aot_set_last_error("llvm build logic and failed.");
        goto fail;
    }

    /* Check if float value out of range */
    if (!(check_overflow_succ = LLVMAppendBasicBlockInContext(
              comp_ctx->context, func_ctx->func, "check_overflow_succ"))) {
        aot_set_last_error("llvm add basic block failed.");
        goto fail;
    }

    LLVMMoveBasicBlockAfter(check_overflow_succ,
                            LLVMGetInsertBlock(comp_ctx->builder));

    if (!(aot_emit_exception(comp_ctx, func_ctx, EXCE_INTEGER_OVERFLOW, true,
                             res, check_overflow_succ)))
        goto fail;

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(comp_ctx, name)) {
        LLVMTypeRef param_types[1];
        param_types[0] = src_type;
        res = aot_call_llvm_intrinsic(comp_ctx, func_ctx, name, dest_type,
                                      param_types, 1, operand);
    }
    else {
        if (sign)
            res = LLVMBuildFPToSI(comp_ctx->builder, operand, dest_type, name);
        else
            res = LLVMBuildFPToUI(comp_ctx->builder, operand, dest_type, name);
    }

    if (!res) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    if (dest_type == I32_TYPE)
        PUSH_I32(res);
    else if (dest_type == I64_TYPE)
        PUSH_I64(res);
    return true;
fail:
    return false;
}

#define ADD_BASIC_BLOCK(block, name)                                           \
    do {                                                                       \
        if (!(block = LLVMAppendBasicBlockInContext(comp_ctx->context,         \
                                                    func_ctx->func, name))) {  \
            aot_set_last_error("llvm add basic block failed.");                \
            goto fail;                                                         \
        }                                                                      \
                                                                               \
        LLVMMoveBasicBlockAfter(block, LLVMGetInsertBlock(comp_ctx->builder)); \
    } while (0)

static bool
trunc_sat_float_to_int(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                       LLVMValueRef operand, LLVMTypeRef src_type,
                       LLVMTypeRef dest_type, LLVMValueRef min_value,
                       LLVMValueRef max_value, char *name, bool sign)
{
    LLVMBasicBlockRef check_nan_succ, check_less_succ, check_greater_succ;
    LLVMBasicBlockRef is_nan_block, is_less_block, is_greater_block, res_block;
    LLVMValueRef is_less, is_greater, res, phi;
    LLVMValueRef zero = (dest_type == I32_TYPE) ? I32_ZERO : I64_ZERO;
    LLVMValueRef vmin, vmax;

    if (!(res =
              call_fcmp_intrinsic(comp_ctx, func_ctx, FLOAT_UNO, LLVMRealUNO,
                                  operand, operand, src_type, "fcmp_is_nan"))) {
        aot_set_last_error("llvm build fcmp failed.");
        goto fail;
    }

    ADD_BASIC_BLOCK(check_nan_succ, "check_nan_succ");
    ADD_BASIC_BLOCK(is_nan_block, "is_nan_block");
    ADD_BASIC_BLOCK(check_less_succ, "check_less_succ");
    ADD_BASIC_BLOCK(is_less_block, "is_less_block");
    ADD_BASIC_BLOCK(check_greater_succ, "check_greater_succ");
    ADD_BASIC_BLOCK(is_greater_block, "is_greater_block");
    ADD_BASIC_BLOCK(res_block, "res_block");

    if (!LLVMBuildCondBr(comp_ctx->builder, res, is_nan_block,
                         check_nan_succ)) {
        aot_set_last_error("llvm build cond br failed.");
        goto fail;
    }

    /* Start to translate is_nan block */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, is_nan_block);
    if (!LLVMBuildBr(comp_ctx->builder, res_block)) {
        aot_set_last_error("llvm build br failed.");
        goto fail;
    }

    /* Start to translate check_nan_succ block */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, check_nan_succ);
    if (!(is_less = call_fcmp_intrinsic(comp_ctx, func_ctx, FLOAT_LE,
                                        LLVMRealOLE, operand, min_value,
                                        src_type, "fcmp_min_value"))) {
        aot_set_last_error("llvm build fcmp failed.");
        goto fail;
    }
    if (!LLVMBuildCondBr(comp_ctx->builder, is_less, is_less_block,
                         check_less_succ)) {
        aot_set_last_error("llvm build cond br failed.");
        goto fail;
    }

    /* Start to translate is_less block */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, is_less_block);
    if (!LLVMBuildBr(comp_ctx->builder, res_block)) {
        aot_set_last_error("llvm build br failed.");
        goto fail;
    }

    /* Start to translate check_less_succ block */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, check_less_succ);
    if (!(is_greater = call_fcmp_intrinsic(comp_ctx, func_ctx, FLOAT_GE,
                                           LLVMRealOGE, operand, max_value,
                                           src_type, "fcmp_max_value"))) {
        aot_set_last_error("llvm build fcmp failed.");
        goto fail;
    }
    if (!LLVMBuildCondBr(comp_ctx->builder, is_greater, is_greater_block,
                         check_greater_succ)) {
        aot_set_last_error("llvm build cond br failed.");
        goto fail;
    }

    /* Start to translate is_greater block */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, is_greater_block);
    if (!LLVMBuildBr(comp_ctx->builder, res_block)) {
        aot_set_last_error("llvm build br failed.");
        goto fail;
    }

    /* Start to translate check_greater_succ block */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, check_greater_succ);

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(comp_ctx, name)) {
        LLVMTypeRef param_types[1];
        param_types[0] = src_type;
        res = aot_call_llvm_intrinsic(comp_ctx, func_ctx, name, dest_type,
                                      param_types, 1, operand);
    }
    else {
        char intrinsic[128];

        /* Integer width is always 32 or 64 here. */

        snprintf(intrinsic, sizeof(intrinsic), "i%d_trunc_f%d_%c",
                 LLVMGetIntTypeWidth(dest_type),
                 LLVMGetTypeKind(src_type) == LLVMFloatTypeKind ? 32 : 64,
                 sign ? 's' : 'u');

        if (comp_ctx->disable_llvm_intrinsics
            && aot_intrinsic_check_capability(comp_ctx, intrinsic)) {
            res = aot_call_llvm_intrinsic(comp_ctx, func_ctx, intrinsic,
                                          dest_type, &src_type, 1, operand);
        }
        else {
            if (sign) {
                res = LLVMBuildFPToSI(comp_ctx->builder, operand, dest_type,
                                      name);
            }
            else {
                res = LLVMBuildFPToUI(comp_ctx->builder, operand, dest_type,
                                      name);
            }
        }
    }

    if (!res) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }
    if (!LLVMBuildBr(comp_ctx->builder, res_block)) {
        aot_set_last_error("llvm build br failed.");
        goto fail;
    }

    /* Start to translate res_block */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, res_block);
    /* Create result phi */
    if (!(phi = LLVMBuildPhi(comp_ctx->builder, dest_type,
                             "trunc_sat_result_phi"))) {
        aot_set_last_error("llvm build phi failed.");
        return false;
    }

    /* Add phi incoming values */
    if (dest_type == I32_TYPE) {
        if (sign) {
            vmin = I32_CONST(INT32_MIN);
            vmax = I32_CONST(INT32_MAX);
        }
        else {
            vmin = I32_CONST(0);
            vmax = I32_CONST(UINT32_MAX);
        }
    }
    else if (dest_type == I64_TYPE) {
        if (sign) {
            vmin = I64_CONST(INT64_MIN);
            vmax = I64_CONST(INT64_MAX);
        }
        else {
            vmin = I64_CONST(0);
            vmax = I64_CONST(UINT64_MAX);
        }
    }
    LLVMAddIncoming(phi, &zero, &is_nan_block, 1);
    LLVMAddIncoming(phi, &vmin, &is_less_block, 1);
    LLVMAddIncoming(phi, &vmax, &is_greater_block, 1);
    LLVMAddIncoming(phi, &res, &check_greater_succ, 1);

    if (dest_type == I32_TYPE)
        PUSH_I32(phi);
    else if (dest_type == I64_TYPE)
        PUSH_I64(phi);
    return true;
fail:
    return false;
}

bool
aot_compile_op_i32_wrap_i64(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef value, res;

    POP_I64(value);

    if (!(res = LLVMBuildTrunc(comp_ctx->builder, value, I32_TYPE,
                               "i32_wrap_i64"))) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    PUSH_I32(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_i32_trunc_f32(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             bool sign, bool saturating)
{
    LLVMValueRef value;
    LLVMValueRef min_value, max_value;

    POP_F32(value);

    if (comp_ctx->is_indirect_mode
        && aot_intrinsic_check_capability(comp_ctx, "f32.const")) {
        WASMValue wasm_value;
        if (sign) {
            wasm_value.f32 = -2147483904.0f;
            min_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F32);
            wasm_value.f32 = 2147483648.0f;
            max_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F32);
        }
        else {
            wasm_value.f32 = -1.0f;
            min_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F32);
            wasm_value.f32 = 4294967296.0f;
            max_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F32);
        }
    }
    else {
        if (sign) {
            min_value = F32_CONST(-2147483904.0f);
            max_value = F32_CONST(2147483648.0f);
        }
        else {
            min_value = F32_CONST(-1.0f);
            max_value = F32_CONST(4294967296.0f);
        }
    }
    CHECK_LLVM_CONST(min_value);
    CHECK_LLVM_CONST(max_value);

    if (!saturating)
        return trunc_float_to_int(
            comp_ctx, func_ctx, value, F32_TYPE, I32_TYPE, min_value, max_value,
            sign ? "i32_trunc_f32_s" : "i32_trunc_f32_u", sign);
    else
        return trunc_sat_float_to_int(
            comp_ctx, func_ctx, value, F32_TYPE, I32_TYPE, min_value, max_value,
            sign ? "i32_trunc_sat_f32_s" : "i32_trunc_sat_f32_u", sign);
fail:
    return false;
}

bool
aot_compile_op_i32_trunc_f64(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             bool sign, bool saturating)
{
    LLVMValueRef value;
    LLVMValueRef min_value, max_value;

    POP_F64(value);

    if (comp_ctx->is_indirect_mode
        && aot_intrinsic_check_capability(comp_ctx, "f64.const")) {
        WASMValue wasm_value;
        if (sign) {
            wasm_value.f64 = -2147483649.0;
            min_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F64);
            wasm_value.f64 = 2147483648.0;
            max_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F64);
        }
        else {
            wasm_value.f64 = -1.0;
            min_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F64);
            wasm_value.f64 = 4294967296.0;
            max_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F64);
        }
    }
    else {
        if (sign) {
            min_value = F64_CONST(-2147483649.0);
            max_value = F64_CONST(2147483648.0);
        }
        else {
            min_value = F64_CONST(-1.0);
            max_value = F64_CONST(4294967296.0);
        }
    }
    CHECK_LLVM_CONST(min_value);
    CHECK_LLVM_CONST(max_value);

    if (!saturating)
        return trunc_float_to_int(
            comp_ctx, func_ctx, value, F64_TYPE, I32_TYPE, min_value, max_value,
            sign ? "i32_trunc_f64_s" : "i32_trunc_f64_u", sign);
    else
        return trunc_sat_float_to_int(
            comp_ctx, func_ctx, value, F64_TYPE, I32_TYPE, min_value, max_value,
            sign ? "i32_trunc_sat_f64_s" : "i32_trunc_sat_f64_u", sign);
fail:
    return false;
}

bool
aot_compile_op_i64_extend_i32(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, bool sign)
{
    LLVMValueRef value, res;

    POP_I32(value);

    if (sign)
        res = LLVMBuildSExt(comp_ctx->builder, value, I64_TYPE,
                            "i64_extend_i32_s");
    else
        res = LLVMBuildZExt(comp_ctx->builder, value, I64_TYPE,
                            "i64_extend_i32_u");
    if (!res) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    PUSH_I64(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_i64_extend_i64(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, int8 bitwidth)
{
    LLVMValueRef value, res, cast_value = NULL;

    POP_I64(value);

    if (bitwidth == 8) {
        cast_value = LLVMBuildIntCast2(comp_ctx->builder, value, INT8_TYPE,
                                       true, "i8_intcast_i64");
    }
    else if (bitwidth == 16) {
        cast_value = LLVMBuildIntCast2(comp_ctx->builder, value, INT16_TYPE,
                                       true, "i16_intcast_i64");
    }
    else if (bitwidth == 32) {
        cast_value = LLVMBuildIntCast2(comp_ctx->builder, value, I32_TYPE, true,
                                       "i32_intcast_i64");
    }

    if (!cast_value) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    res = LLVMBuildSExt(comp_ctx->builder, cast_value, I64_TYPE,
                        "i64_extend_i64_s");

    if (!res) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    PUSH_I64(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_i32_extend_i32(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, int8 bitwidth)
{
    LLVMValueRef value, res, cast_value = NULL;

    POP_I32(value);

    if (bitwidth == 8) {
        cast_value = LLVMBuildIntCast2(comp_ctx->builder, value, INT8_TYPE,
                                       true, "i8_intcast_i32");
    }
    else if (bitwidth == 16) {
        cast_value = LLVMBuildIntCast2(comp_ctx->builder, value, INT16_TYPE,
                                       true, "i16_intcast_i32");
    }

    if (!cast_value) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    res = LLVMBuildSExt(comp_ctx->builder, cast_value, I32_TYPE,
                        "i32_extend_i32_s");

    if (!res) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    PUSH_I32(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_i64_trunc_f32(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             bool sign, bool saturating)
{
    LLVMValueRef value;
    LLVMValueRef min_value, max_value;

    POP_F32(value);

    if (comp_ctx->is_indirect_mode
        && aot_intrinsic_check_capability(comp_ctx, "f32.const")) {
        WASMValue wasm_value;
        if (sign) {
            wasm_value.f32 = -9223373136366403584.0f;
            min_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F32);
            wasm_value.f32 = 9223372036854775808.0f;
            max_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F32);
        }
        else {
            wasm_value.f32 = -1.0f;
            min_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F32);
            wasm_value.f32 = 18446744073709551616.0f;
            max_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F32);
        }
    }
    else {
        if (sign) {
            min_value = F32_CONST(-9223373136366403584.0f);
            max_value = F32_CONST(9223372036854775808.0f);
        }
        else {
            min_value = F32_CONST(-1.0f);
            max_value = F32_CONST(18446744073709551616.0f);
        }
    }
    CHECK_LLVM_CONST(min_value);
    CHECK_LLVM_CONST(max_value);

    if (!saturating)
        return trunc_float_to_int(
            comp_ctx, func_ctx, value, F32_TYPE, I64_TYPE, min_value, max_value,
            sign ? "i64_trunc_f32_s" : "i64_trunc_f32_u", sign);
    else
        return trunc_sat_float_to_int(
            comp_ctx, func_ctx, value, F32_TYPE, I64_TYPE, min_value, max_value,
            sign ? "i64_trunc_sat_f32_s" : "i64_trunc_sat_f32_u", sign);
fail:
    return false;
}

bool
aot_compile_op_i64_trunc_f64(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             bool sign, bool saturating)
{
    LLVMValueRef value;
    LLVMValueRef min_value, max_value;

    POP_F64(value);

    if (comp_ctx->is_indirect_mode
        && aot_intrinsic_check_capability(comp_ctx, "f64.const")) {
        WASMValue wasm_value;
        if (sign) {
            wasm_value.f64 = -9223372036854777856.0;
            min_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F64);
            wasm_value.f64 = 9223372036854775808.0;
            max_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F64);
        }
        else {
            wasm_value.f64 = -1.0;
            min_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F64);
            wasm_value.f64 = 18446744073709551616.0;
            max_value = aot_load_const_from_table(
                comp_ctx, func_ctx->native_symbol, &wasm_value, VALUE_TYPE_F64);
        }
    }
    else {
        if (sign) {
            min_value = F64_CONST(-9223372036854777856.0);
            max_value = F64_CONST(9223372036854775808.0);
        }
        else {
            min_value = F64_CONST(-1.0);
            max_value = F64_CONST(18446744073709551616.0);
        }
    }
    CHECK_LLVM_CONST(min_value);
    CHECK_LLVM_CONST(max_value);

    if (!saturating)
        return trunc_float_to_int(
            comp_ctx, func_ctx, value, F64_TYPE, I64_TYPE, min_value, max_value,
            sign ? "i64_trunc_f64_s" : "i64_trunc_f64_u", sign);
    else
        return trunc_sat_float_to_int(
            comp_ctx, func_ctx, value, F64_TYPE, I64_TYPE, min_value, max_value,
            sign ? "i64_trunc_sat_f64_s" : "i64_trunc_sat_f64_u", sign);

fail:
    return false;
}

bool
aot_compile_op_f32_convert_i32(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, bool sign)
{
    LLVMValueRef value, res;

    POP_I32(value);

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(
            comp_ctx, sign ? "f32_convert_i32_s" : "f32_convert_i32_u")) {
        LLVMTypeRef param_types[1];
        param_types[0] = I32_TYPE;
        res = aot_call_llvm_intrinsic(comp_ctx, func_ctx,
                                      sign ? "f32_convert_i32_s"
                                           : "f32_convert_i32_u",
                                      F32_TYPE, param_types, 1, value);
    }
    else {
        if (sign)
            res = LLVMBuildSIToFP(comp_ctx->builder, value, F32_TYPE,
                                  "f32_convert_i32_s");
        else
            res = LLVMBuildUIToFP(comp_ctx->builder, value, F32_TYPE,
                                  "f32_convert_i32_u");
    }
    if (!res) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    PUSH_F32(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_f32_convert_i64(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, bool sign)
{
    LLVMValueRef value, res;

    POP_I64(value);

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(
            comp_ctx, sign ? "f32_convert_i64_s" : "f32_convert_i64_u")) {
        LLVMTypeRef param_types[1];
        param_types[0] = I64_TYPE;
        res = aot_call_llvm_intrinsic(comp_ctx, func_ctx,
                                      sign ? "f32_convert_i64_s"
                                           : "f32_convert_i64_u",
                                      F32_TYPE, param_types, 1, value);
    }
    else {
        if (sign)
            res = LLVMBuildSIToFP(comp_ctx->builder, value, F32_TYPE,
                                  "f32_convert_i64_s");
        else
            res = LLVMBuildUIToFP(comp_ctx->builder, value, F32_TYPE,
                                  "f32_convert_i64_u");
    }

    if (!res) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    PUSH_F32(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_f32_demote_f64(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx)
{
    LLVMValueRef value, res;

    POP_F64(value);

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(comp_ctx, "f32_demote_f64")) {
        LLVMTypeRef param_types[1];
        param_types[0] = F64_TYPE;
        res = aot_call_llvm_intrinsic(comp_ctx, func_ctx, "f32_demote_f64",
                                      F32_TYPE, param_types, 1, value);
    }
    else {
        res = LLVMBuildFPTrunc(comp_ctx->builder, value, F32_TYPE,
                               "f32_demote_f64");
    }

    if (!res) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    PUSH_F32(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_f64_convert_i32(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, bool sign)
{
    LLVMValueRef value, res;

    POP_I32(value);

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(
            comp_ctx, sign ? "f64_convert_i32_s" : "f64_convert_i32_u")) {
        LLVMTypeRef param_types[1];
        param_types[0] = I32_TYPE;

        res = aot_call_llvm_intrinsic(comp_ctx, func_ctx,
                                      sign ? "f64_convert_i32_s"
                                           : "f64_convert_i32_u",
                                      F64_TYPE, param_types, 1, value);
    }
    else {
        if (sign)
            res = LLVMBuildSIToFP(comp_ctx->builder, value, F64_TYPE,
                                  "f64_convert_i32_s");
        else
            res = LLVMBuildUIToFP(comp_ctx->builder, value, F64_TYPE,
                                  "f64_convert_i32_u");
    }

    if (!res) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    PUSH_F64(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_f64_convert_i64(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, bool sign)
{
    LLVMValueRef value, res;

    POP_I64(value);

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(
            comp_ctx, sign ? "f64_convert_i64_s" : "f64_convert_i64_u")) {
        LLVMTypeRef param_types[1];
        param_types[0] = I64_TYPE;

        res = aot_call_llvm_intrinsic(comp_ctx, func_ctx,
                                      sign ? "f64_convert_i64_s"
                                           : "f64_convert_i64_u",
                                      F64_TYPE, param_types, 1, value);
    }
    else {
        if (sign)
            res = LLVMBuildSIToFP(comp_ctx->builder, value, F64_TYPE,
                                  "f64_convert_i64_s");
        else
            res = LLVMBuildUIToFP(comp_ctx->builder, value, F64_TYPE,
                                  "f64_convert_i64_u");
    }

    if (!res) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    PUSH_F64(res);
    return true;
fail:
    return false;
}

bool
aot_compile_op_f64_promote_f32(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx)
{
    LLVMValueRef value, res;

    POP_F32(value);

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(comp_ctx, "f64_promote_f32")) {
        LLVMTypeRef param_types[1];
        param_types[0] = F32_TYPE;
        res = aot_call_llvm_intrinsic(comp_ctx, func_ctx, "f64_promote_f32",
                                      F64_TYPE, param_types, 1, value);
    }
    else {
        res = LLVMBuildFPExt(comp_ctx->builder, value, F64_TYPE,
                             "f64_promote_f32");
    }

    if (!res) {
        aot_set_last_error("llvm build conversion failed.");
        return false;
    }

    PUSH_F64(res);

    /* Avoid the promote being optimized away */
    PUSH_F64(F64_CONST(1.0));
    return aot_compile_op_f64_arithmetic(comp_ctx, func_ctx, FLOAT_MUL);
fail:
    return false;
}

bool
aot_compile_op_i64_reinterpret_f64(AOTCompContext *comp_ctx,
                                   AOTFuncContext *func_ctx)
{
    LLVMValueRef value;
    POP_F64(value);
    if (!(value =
              LLVMBuildBitCast(comp_ctx->builder, value, I64_TYPE, "i64"))) {
        aot_set_last_error("llvm build fp to si failed.");
        return false;
    }
    PUSH_I64(value);
    return true;
fail:
    return false;
}

bool
aot_compile_op_i32_reinterpret_f32(AOTCompContext *comp_ctx,
                                   AOTFuncContext *func_ctx)
{
    LLVMValueRef value;
    POP_F32(value);
    if (!(value =
              LLVMBuildBitCast(comp_ctx->builder, value, I32_TYPE, "i32"))) {
        aot_set_last_error("llvm build fp to si failed.");
        return false;
    }
    PUSH_I32(value);
    return true;
fail:
    return false;
}

bool
aot_compile_op_f64_reinterpret_i64(AOTCompContext *comp_ctx,
                                   AOTFuncContext *func_ctx)
{
    LLVMValueRef value;
    POP_I64(value);
    if (!(value =
              LLVMBuildBitCast(comp_ctx->builder, value, F64_TYPE, "f64"))) {
        aot_set_last_error("llvm build si to fp failed.");
        return false;
    }
    PUSH_F64(value);
    return true;
fail:
    return false;
}

bool
aot_compile_op_f32_reinterpret_i32(AOTCompContext *comp_ctx,
                                   AOTFuncContext *func_ctx)
{
    LLVMValueRef value;
    POP_I32(value);
    if (!(value =
              LLVMBuildBitCast(comp_ctx->builder, value, F32_TYPE, "f32"))) {
        aot_set_last_error("llvm build si to fp failed.");
        return false;
    }
    PUSH_F32(value);
    return true;
fail:
    return false;
}
