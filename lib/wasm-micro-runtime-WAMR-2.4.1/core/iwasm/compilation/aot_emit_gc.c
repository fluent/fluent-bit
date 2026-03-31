/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_emit_gc.h"
#include "aot_compiler.h"
#include "aot_emit_exception.h"

#if WASM_ENABLE_GC != 0

#define BUILD_ISNULL(ptr, res, name)                                  \
    do {                                                              \
        if (!(res = LLVMBuildIsNull(comp_ctx->builder, ptr, name))) { \
            aot_set_last_error("llvm build isnull failed.");          \
            goto fail;                                                \
        }                                                             \
    } while (0)

#define BUILD_ISNOTNULL(ptr, res, name)                                  \
    do {                                                                 \
        if (!(res = LLVMBuildIsNotNull(comp_ctx->builder, ptr, name))) { \
            aot_set_last_error("llvm build isnotnull failed.");          \
            goto fail;                                                   \
        }                                                                \
    } while (0)

#define ADD_BASIC_BLOCK(block, name)                                          \
    do {                                                                      \
        if (!(block = LLVMAppendBasicBlockInContext(comp_ctx->context,        \
                                                    func_ctx->func, name))) { \
            aot_set_last_error("llvm add basic block failed.");               \
            goto fail;                                                        \
        }                                                                     \
    } while (0)

#define CURR_BLOCK() LLVMGetInsertBlock(comp_ctx->builder)

#define MOVE_BLOCK_AFTER(llvm_block, llvm_block_after) \
    LLVMMoveBasicBlockAfter(llvm_block, llvm_block_after)

#define MOVE_BLOCK_AFTER_CURR(llvm_block) \
    LLVMMoveBasicBlockAfter(llvm_block, CURR_BLOCK())

#define MOVE_BLOCK_BEFORE(llvm_block, llvm_block_before) \
    LLVMMoveBasicBlockBefore(llvm_block, llvm_block_before)

#define BUILD_COND_BR(value_if, block_then, block_else)               \
    do {                                                              \
        if (!LLVMBuildCondBr(comp_ctx->builder, value_if, block_then, \
                             block_else)) {                           \
            aot_set_last_error("llvm build cond br failed.");         \
            goto fail;                                                \
        }                                                             \
    } while (0)

#define SET_BUILDER_POS(llvm_block) \
    LLVMPositionBuilderAtEnd(comp_ctx->builder, llvm_block)

#define BUILD_BR(llvm_block)                               \
    do {                                                   \
        if (!LLVMBuildBr(comp_ctx->builder, llvm_block)) { \
            aot_set_last_error("llvm build br failed.");   \
            goto fail;                                     \
        }                                                  \
    } while (0)

#define BUILD_ICMP(op, left, right, res, name)                                \
    do {                                                                      \
        if (!(res =                                                           \
                  LLVMBuildICmp(comp_ctx->builder, op, left, right, name))) { \
            aot_set_last_error("llvm build icmp failed.");                    \
            goto fail;                                                        \
        }                                                                     \
    } while (0)

static bool
is_target_x86(AOTCompContext *comp_ctx)
{
    return !strncmp(comp_ctx->target_arch, "x86_64", 6)
           || !strncmp(comp_ctx->target_arch, "i386", 4);
}

bool
aot_call_aot_create_func_obj(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef func_idx, LLVMValueRef *p_gc_obj)
{
    LLVMValueRef gc_obj, cmp_gc_obj, param_values[5], func, value;
    LLVMTypeRef param_types[5], ret_type, func_type, func_ptr_type;
    AOTFuncType *aot_func_type = func_ctx->aot_func->func_type;
    LLVMBasicBlockRef block_curr = LLVMGetInsertBlock(comp_ctx->builder);
    LLVMBasicBlockRef init_gc_obj_fail, init_gc_obj_succ;

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = INT8_TYPE;
    param_types[3] = INT8_PTR_TYPE;
    param_types[4] = I32_TYPE;
    ret_type = GC_REF_TYPE;

    if (comp_ctx->is_jit_mode)
        GET_AOT_FUNCTION(llvm_jit_create_func_obj, 5);
    else
        GET_AOT_FUNCTION(aot_create_func_obj, 5);

    /* Call function llvm_jit/aot_create_func_obj()  */
    param_values[0] = func_ctx->aot_inst;
    param_values[1] = func_idx;
    param_values[2] = I8_CONST(1);
    param_values[3] = I8_PTR_NULL;
    param_values[4] = I32_ZERO;
    if (!(gc_obj = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                  param_values, 5, "call"))) {
        aot_set_last_error("llvm build call failed.");
        return false;
    }

    BUILD_ISNOTNULL(gc_obj, cmp_gc_obj, "gc_obj_not_null");

    ADD_BASIC_BLOCK(init_gc_obj_fail, "init_gc_obj_fail");
    ADD_BASIC_BLOCK(init_gc_obj_succ, "init_gc_obj_success");

    LLVMMoveBasicBlockAfter(init_gc_obj_fail, block_curr);
    LLVMMoveBasicBlockAfter(init_gc_obj_succ, block_curr);

    if (!LLVMBuildCondBr(comp_ctx->builder, cmp_gc_obj, init_gc_obj_succ,
                         init_gc_obj_fail)) {
        aot_set_last_error("llvm build cond br failed.");
        goto fail;
    }

    /* If init gc_obj failed, return this function
       so the runtime can catch the exception */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, init_gc_obj_fail);
    if (!aot_build_zero_function_ret(comp_ctx, func_ctx, aot_func_type)) {
        goto fail;
    }

    LLVMPositionBuilderAtEnd(comp_ctx->builder, init_gc_obj_succ);
    *p_gc_obj = gc_obj;

    return true;
fail:
    return false;
}

bool
aot_call_aot_obj_is_instance_of(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx, LLVMValueRef gc_obj,
                                LLVMValueRef heap_type, LLVMValueRef *castable)
{
    LLVMValueRef param_values[3], func, value, res;
    LLVMTypeRef param_types[3], ret_type, func_type, func_ptr_type;

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = GC_REF_TYPE;
    param_types[2] = I32_TYPE;
    ret_type = INT8_TYPE;

    if (comp_ctx->is_jit_mode)
        GET_AOT_FUNCTION(llvm_jit_obj_is_instance_of, 3);
    else
        GET_AOT_FUNCTION(aot_obj_is_instance_of, 3);

    /* Call function aot_obj_is_instance_of() or llvm_jit_obj_is_instance_of()
     */
    param_values[0] = func_ctx->aot_inst;
    param_values[1] = gc_obj;
    param_values[2] = heap_type;

    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               3, "call"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    *castable = res;

    return true;
fail:
    return false;
}

bool
aot_call_wasm_obj_is_type_of(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef gc_obj, LLVMValueRef heap_type,
                             LLVMValueRef *castable)
{
    LLVMValueRef param_values[2], func, value, res;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;

    param_types[0] = GC_REF_TYPE;
    param_types[1] = I32_TYPE;
    ret_type = INT8_TYPE;

    GET_AOT_FUNCTION(wasm_obj_is_type_of, 2);

    /* Call function wasm_obj_is_type_of() */
    param_values[0] = gc_obj;
    param_values[1] = heap_type;
    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               2, "call"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    *castable = res;

    return true;
fail:
    return false;
}

bool
aot_call_aot_rtt_type_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          LLVMValueRef type_index, LLVMValueRef *rtt_type)
{
    LLVMValueRef param_values[2], func, value, res;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    ret_type = GC_REF_TYPE;

    if (comp_ctx->is_jit_mode)
        GET_AOT_FUNCTION(llvm_jit_rtt_type_new, 2);
    else
        GET_AOT_FUNCTION(aot_rtt_type_new, 2);

    /* Call function llvm_jit/aot_rtt_type_new() */
    param_values[0] = func_ctx->aot_inst;
    param_values[1] = type_index;
    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               2, "call"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    *rtt_type = res;
    return true;
fail:
    return false;
}

bool
aot_compile_op_ref_as_non_null(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx)
{
    LLVMValueRef gc_obj, cmp_gc_obj;
    LLVMBasicBlockRef check_gc_obj_succ;

    GET_GC_REF_FROM_STACK(gc_obj);

    /* Check if gc object is NULL */
    BUILD_ISNULL(gc_obj, cmp_gc_obj, "cmp_gc_obj");

    ADD_BASIC_BLOCK(check_gc_obj_succ, "check_gc_obj_succ");
    MOVE_BLOCK_AFTER_CURR(check_gc_obj_succ);

    /*  Throw exception if it is NULL */
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_NULL_REFERENCE, true,
                            cmp_gc_obj, check_gc_obj_succ))
        goto fail;

    return true;
fail:
    return false;
}

static bool
aot_call_wasm_struct_obj_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef rtt_type, LLVMValueRef *struct_obj)
{
    LLVMValueRef param_values[2], func, value, res;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = INT8_PTR_TYPE;
    ret_type = GC_REF_TYPE;

    GET_AOT_FUNCTION(wasm_struct_obj_new, 2);

    /* Call function wasm_struct_obj_new() */
    param_values[0] = func_ctx->exec_env;
    param_values[1] = rtt_type;
    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               2, "call"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    *struct_obj = res;
    return true;
fail:
    return false;
}

static void
get_struct_field_data_types(const AOTCompContext *comp_ctx, uint8 field_type,
                            LLVMTypeRef *p_field_data_type,
                            LLVMTypeRef *p_field_data_ptr_type,
                            bool *p_trunc_or_extend)
{
    LLVMTypeRef field_data_type = NULL, field_data_ptr_type = NULL;
    bool trunc_or_extend = false;

    if (wasm_is_type_reftype(field_type)) {
        field_data_type = GC_REF_TYPE;
        field_data_ptr_type = GC_REF_PTR_TYPE;
    }
    else {
        switch (field_type) {
            case VALUE_TYPE_I32:
                field_data_type = I32_TYPE;
                field_data_ptr_type = INT32_PTR_TYPE;
                break;
            case VALUE_TYPE_I64:
                field_data_type = I64_TYPE;
                field_data_ptr_type = INT64_PTR_TYPE;
                break;
            case VALUE_TYPE_F32:
                field_data_type = F32_TYPE;
                field_data_ptr_type = F32_PTR_TYPE;
                break;
            case VALUE_TYPE_F64:
                field_data_type = F64_TYPE;
                field_data_ptr_type = F64_PTR_TYPE;
                break;
            case PACKED_TYPE_I8:
                field_data_type = INT8_TYPE;
                field_data_ptr_type = INT8_PTR_TYPE;
                trunc_or_extend = true;
                break;
            case PACKED_TYPE_I16:
                field_data_type = INT16_TYPE;
                field_data_ptr_type = INT16_PTR_TYPE;
                trunc_or_extend = true;
                break;
            default:
                bh_assert(0);
                break;
        }
    }

    *p_field_data_type = field_data_type;
    *p_field_data_ptr_type = field_data_ptr_type;
    *p_trunc_or_extend = trunc_or_extend;
}

static bool
aot_struct_obj_set_field(AOTCompContext *comp_ctx, LLVMValueRef struct_obj,
                         LLVMValueRef field_offset, LLVMValueRef field_value,
                         uint8 field_type)
{
    bool trunc = false;
    LLVMValueRef field_data_ptr, res;
    LLVMTypeRef field_data_type = NULL, field_data_ptr_type = NULL;

    get_struct_field_data_types(comp_ctx, field_type, &field_data_type,
                                &field_data_ptr_type, &trunc);

    /* Truncate field_value if necessary */
    if (trunc) {
        if (!(field_value =
                  LLVMBuildTrunc(comp_ctx->builder, field_value,
                                 field_data_type, "field_value_trunc"))) {
            aot_set_last_error("llvm build trunc failed.");
            goto fail;
        }
    }

    if (!(struct_obj = LLVMBuildBitCast(comp_ctx->builder, struct_obj,
                                        INT8_PTR_TYPE, "struct_obj_i8p"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    /* Build field data ptr and store the value */
    if (!(field_data_ptr =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, struct_obj,
                                    &field_offset, 1, "field_data_i8p"))) {
        aot_set_last_error("llvm build gep failed.");
        goto fail;
    }

    /* Cast to the field data type ptr */
    if (!(field_data_ptr =
              LLVMBuildBitCast(comp_ctx->builder, field_data_ptr,
                               field_data_ptr_type, "field_value_ptr"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    if (!(res =
              LLVMBuildStore(comp_ctx->builder, field_value, field_data_ptr))) {
        aot_set_last_error("llvm build store failed.");
        goto fail;
    }

    if (!is_target_x86(comp_ctx)
        && (field_data_type == I64_TYPE || field_data_type == F64_TYPE
            || field_data_type == GC_REF_TYPE)) {
        LLVMSetAlignment(res, 4);
    }

    return true;
fail:
    return false;
}

static bool
aot_struct_obj_get_field(AOTCompContext *comp_ctx, LLVMValueRef struct_obj,
                         LLVMValueRef field_offset, LLVMValueRef *p_field_value,
                         uint8 field_type, bool sign_extend)
{
    bool extend = false;
    LLVMValueRef field_value, field_data_ptr;
    LLVMTypeRef field_data_type = NULL, field_data_ptr_type = NULL;

    get_struct_field_data_types(comp_ctx, field_type, &field_data_type,
                                &field_data_ptr_type, &extend);

    if (!(struct_obj = LLVMBuildBitCast(comp_ctx->builder, struct_obj,
                                        INT8_PTR_TYPE, "struct_obj_i8p"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    if (!(field_data_ptr =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, struct_obj,
                                    &field_offset, 1, "field_data_i8p"))) {
        aot_set_last_error("llvm build gep failed.");
        goto fail;
    }

    if (!(field_data_ptr =
              LLVMBuildBitCast(comp_ctx->builder, field_data_ptr,
                               field_data_ptr_type, "field_value_ptr"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    if (!(field_value = LLVMBuildLoad2(comp_ctx->builder, field_data_type,
                                       field_data_ptr, "field_value"))) {
        aot_set_last_error("llvm build load failed.");
        goto fail;
    }

    if (!is_target_x86(comp_ctx)
        && (field_data_type == I64_TYPE || field_data_type == F64_TYPE
            || field_data_type == GC_REF_TYPE)) {
        LLVMSetAlignment(field_value, 4);
    }

    if (extend) {
        if (sign_extend) {
            if (!(field_value = LLVMBuildSExt(comp_ctx->builder, field_value,
                                              I32_TYPE, "field_value_sext"))) {
                aot_set_last_error("llvm build signed ext failed.");
                goto fail;
            }
        }
        else {
            if (!(field_value = LLVMBuildZExt(comp_ctx->builder, field_value,
                                              I32_TYPE, "field_value_zext"))) {
                aot_set_last_error("llvm build unsigned ext failed.");
                goto fail;
            }
        }
    }

    *p_field_value = field_value;
    return true;
fail:
    return false;
}

static bool
struct_new_canon_init_fields(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             uint32 type_index, LLVMValueRef struct_obj)
{
    LLVMValueRef field_value = NULL;
    /* Used in compile time, to distinguish what type of AOTValue POP,
     * field_data offset, size  */
    WASMStructType *compile_time_struct_type =
        (WASMStructType *)comp_ctx->comp_data->types[type_index];
    WASMStructFieldType *fields = compile_time_struct_type->fields;
    int32 field_count = (int32)compile_time_struct_type->field_count;
    int32 field_idx;
    uint32 field_offset;
    uint8 field_type;

    for (field_idx = field_count - 1; field_idx >= 0; field_idx--) {
        field_type = fields[field_idx].field_type;
        field_offset = comp_ctx->pointer_size == sizeof(uint64)
                           ? fields[field_idx].field_offset_64bit
                           : fields[field_idx].field_offset_32bit;

        if (wasm_is_type_reftype(field_type)) {
            POP_GC_REF(field_value);
        }
        else if (field_type == VALUE_TYPE_I32 || field_type == PACKED_TYPE_I8
                 || field_type == PACKED_TYPE_I16) {
            POP_I32(field_value);
        }
        else if (field_type == VALUE_TYPE_I64) {
            POP_I64(field_value);
        }
        else if (field_type == VALUE_TYPE_F32) {
            POP_F32(field_value);
        }
        else if (field_type == VALUE_TYPE_F64) {
            POP_F64(field_value);
        }
        else {
            bh_assert(0);
        }

        if (!aot_struct_obj_set_field(comp_ctx, struct_obj,
                                      I32_CONST(field_offset), field_value,
                                      field_type))
            goto fail;
    }

    return true;
fail:
    return false;
}

bool
aot_compile_op_struct_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 type_index, bool init_with_default)
{
    LLVMValueRef rtt_type, struct_obj, cmp;
    LLVMBasicBlockRef check_rtt_type_succ, check_struct_obj_succ;

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    /* Generate call wasm_rtt_type_new and check for exception */
    if (!aot_call_aot_rtt_type_new(comp_ctx, func_ctx, I32_CONST(type_index),
                                   &rtt_type))
        goto fail;

    ADD_BASIC_BLOCK(check_rtt_type_succ, "check rtt type succ");
    MOVE_BLOCK_AFTER_CURR(check_rtt_type_succ);

    BUILD_ISNULL(rtt_type, cmp, "cmp_rtt_type");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_FAILED_TO_CREATE_RTT_TYPE,
                            true, cmp, check_rtt_type_succ))
        goto fail;

    /* Generate call wasm_struct_obj_new and check for exception */
    if (!aot_call_wasm_struct_obj_new(comp_ctx, func_ctx, rtt_type,
                                      &struct_obj))
        goto fail;

    ADD_BASIC_BLOCK(check_struct_obj_succ, "check struct obj succ");
    MOVE_BLOCK_AFTER(check_struct_obj_succ, check_rtt_type_succ);

    BUILD_ISNULL(struct_obj, cmp, "cmp_struct_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx,
                            EXCE_FAILED_TO_CREATE_STRUCT_OBJ, true, cmp,
                            check_struct_obj_succ))
        goto fail;

    SET_BUILDER_POS(check_struct_obj_succ);

    /* For WASM_OP_STRUCT_NEW, init field with poped value */
    if (!init_with_default
        && !struct_new_canon_init_fields(comp_ctx, func_ctx, type_index,
                                         struct_obj)) {
        goto fail;
    }

    PUSH_GC_REF(struct_obj);

    return true;
fail:
    return false;
}

bool
aot_compile_op_struct_get(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 type_index, uint32 field_idx, bool sign)
{
    LLVMValueRef struct_obj, cmp, field_value;
    LLVMBasicBlockRef check_struct_obj_succ;

    /* Used in compile time, to distinguish what type of AOTValue PUSH,
     * field_data offset, size  */
    WASMStructType *compile_time_struct_type =
        (WASMStructType *)comp_ctx->comp_data->types[type_index];
    WASMStructFieldType *field;
    uint32 field_offset;
    uint8 field_type;

    field = compile_time_struct_type->fields + field_idx;
    field_type = field->field_type;
    field_offset = comp_ctx->pointer_size == sizeof(uint64)
                       ? field->field_offset_64bit
                       : field->field_offset_32bit;

    if (field_idx >= compile_time_struct_type->field_count) {
        aot_set_last_error("struct field index out of bounds");
        goto fail;
    }

    POP_GC_REF(struct_obj);

    ADD_BASIC_BLOCK(check_struct_obj_succ, "check struct obj succ");
    MOVE_BLOCK_AFTER_CURR(check_struct_obj_succ);

    BUILD_ISNULL(struct_obj, cmp, "cmp_struct_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_NULL_STRUCT_OBJ, true, cmp,
                            check_struct_obj_succ))
        goto fail;

    if (!aot_struct_obj_get_field(comp_ctx, struct_obj, I32_CONST(field_offset),
                                  &field_value, field_type, sign))
        goto fail;

    if (wasm_is_type_reftype(field_type)) {
        PUSH_GC_REF(field_value);
    }
    else if (field_type == VALUE_TYPE_I32 || field_type == PACKED_TYPE_I8
             || field_type == PACKED_TYPE_I16) {
        PUSH_I32(field_value);
    }
    else if (field_type == VALUE_TYPE_I64) {
        PUSH_I64(field_value);
    }
    else if (field_type == VALUE_TYPE_F32) {
        PUSH_F32(field_value);
    }
    else if (field_type == VALUE_TYPE_F64) {
        PUSH_F64(field_value);
    }
    else {
        bh_assert(0);
    }

    return true;
fail:
    return false;
}

bool
aot_compile_op_struct_set(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 type_index, uint32 field_idx)
{
    LLVMValueRef struct_obj, cmp, field_value = NULL;
    LLVMBasicBlockRef check_struct_obj_succ;
    /* Used in compile time, to distinguish what type of AOTValue POP,
     * field_data offset, size  */
    WASMStructType *compile_time_struct_type =
        (WASMStructType *)comp_ctx->comp_data->types[type_index];
    WASMStructFieldType *field;
    uint32 field_offset;
    uint8 field_type;

    field = compile_time_struct_type->fields + field_idx;
    field_type = field->field_type;
    field_offset = comp_ctx->pointer_size == sizeof(uint64)
                       ? field->field_offset_64bit
                       : field->field_offset_32bit;

    if (field_idx >= compile_time_struct_type->field_count) {
        aot_set_last_error("struct field index out of bounds");
        goto fail;
    }

    if (wasm_is_type_reftype(field_type)) {
        POP_GC_REF(field_value);
    }
    else if (field_type == VALUE_TYPE_I32 || field_type == PACKED_TYPE_I8
             || field_type == PACKED_TYPE_I16) {
        POP_I32(field_value);
    }
    else if (field_type == VALUE_TYPE_I64) {
        POP_I64(field_value);
    }
    else if (field_type == VALUE_TYPE_F32) {
        POP_F32(field_value);
    }
    else if (field_type == VALUE_TYPE_F64) {
        POP_F64(field_value);
    }
    else {
        bh_assert(0);
    }

    POP_GC_REF(struct_obj);

    ADD_BASIC_BLOCK(check_struct_obj_succ, "check struct obj succ");
    MOVE_BLOCK_AFTER_CURR(check_struct_obj_succ);

    BUILD_ISNULL(struct_obj, cmp, "cmp_struct_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_NULL_STRUCT_OBJ, true, cmp,
                            check_struct_obj_succ))
        goto fail;

    if (!aot_struct_obj_set_field(comp_ctx, struct_obj, I32_CONST(field_offset),
                                  field_value, field_type))
        goto fail;

    return true;
fail:
    return false;
}

static bool
aot_call_wasm_array_obj_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            LLVMValueRef rtt_type, LLVMValueRef array_len,
                            LLVMValueRef array_elem, LLVMValueRef *array_obj)
{
    LLVMValueRef param_values[4], func, value, res, array_elem_ptr;
    LLVMTypeRef param_types[4], ret_type, func_type, func_ptr_type;

    if (!(array_elem_ptr = LLVMBuildAlloca(
              comp_ctx->builder, LLVMTypeOf(array_elem), "array_elem_ptr"))) {
        aot_set_last_error("llvm build alloca failed.");
        goto fail;
    }
    if (!LLVMBuildStore(comp_ctx->builder, array_elem, array_elem_ptr)) {
        aot_set_last_error("llvm build store failed.");
        goto fail;
    }
    if (!(array_elem_ptr = LLVMBuildBitCast(comp_ctx->builder, array_elem_ptr,
                                            INT8_PTR_TYPE, "array_elem_ptr"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = INT8_PTR_TYPE;
    param_types[2] = I32_TYPE;
    param_types[3] = INT8_PTR_TYPE;
    ret_type = GC_REF_TYPE;

    GET_AOT_FUNCTION(wasm_array_obj_new, 4);

    /* Call function wasm_array_obj_new() */
    param_values[0] = func_ctx->exec_env;
    param_values[1] = rtt_type;
    param_values[2] = array_len;
    param_values[3] = array_elem_ptr;
    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               4, "call"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    *array_obj = res;
    return true;
fail:
    return false;
}

static uint32
aot_array_obj_elem_size_log(AOTCompContext *comp_ctx, uint8 array_elem_type)
{
    uint32 elem_size_log = 0;

    if (wasm_is_type_reftype(array_elem_type)) {
        elem_size_log = comp_ctx->pointer_size == sizeof(uint32) ? 2 : 3;
    }
    else if (array_elem_type == PACKED_TYPE_I8) {
        elem_size_log = 0;
    }
    else if (array_elem_type == PACKED_TYPE_I16) {
        elem_size_log = 1;
    }
    else if (array_elem_type == VALUE_TYPE_I32
             || array_elem_type == VALUE_TYPE_F32) {
        elem_size_log = 2;
    }
    else if (array_elem_type == VALUE_TYPE_I64
             || array_elem_type == VALUE_TYPE_F64) {
        elem_size_log = 3;
    }
    else {
        bh_assert(0);
    }

    return elem_size_log;
}

/* array_obj->elem_data + (elem_idx << elem_size_log) */
bool
aot_array_obj_elem_addr(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        LLVMValueRef array_obj, LLVMValueRef elem_idx,
                        LLVMValueRef *p_elem_data, uint8 array_elem_type)
{
    uint32 elem_size_log = 0;
    LLVMValueRef start_offset, elem_offset, elem_data;

    elem_size_log = aot_array_obj_elem_size_log(comp_ctx, array_elem_type);

    /* Get the elem data start offset of the WASMArrayObject, the offset may be
     * different in 32-bit runtime and 64-bit runtime since WASMObjectHeader
     * is uintptr_t. Use comp_ctx->pointer_size + 4(uint32 for length) as the
     * offsetof(WASMArrayObject, length)*/
    if (!(start_offset = I32_CONST(comp_ctx->pointer_size + sizeof(uint32)))) {
        aot_set_last_error("llvm build const failed.");
        goto fail;
    }

    if (!(elem_offset =
              LLVMBuildShl(comp_ctx->builder, elem_idx,
                           I32_CONST(elem_size_log), "elem_offset"))) {
        aot_set_last_error("llvm build shl failed.");
        goto fail;
    }

    if (!(elem_offset = LLVMBuildAdd(comp_ctx->builder, start_offset,
                                     elem_offset, "total_offset"))) {
        aot_set_last_error("llvm build add failed.");
        goto fail;
    }

    if (!(elem_data = LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE,
                                            array_obj, &elem_offset, 1,
                                            "array_obj_elem_data_i8p"))) {
        aot_set_last_error("llvm build gep failed.");
        goto fail;
    }

    *p_elem_data = elem_data;
    return true;
fail:
    return false;
}

static bool
aot_array_obj_set_elem(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                       LLVMValueRef array_obj, LLVMValueRef elem_idx,
                       LLVMValueRef array_elem, uint8 array_elem_type)
{
    bool trunc = false;
    LLVMValueRef elem_data_ptr, res;
    LLVMTypeRef elem_data_type = NULL, elem_data_ptr_type = NULL;

    if (!aot_array_obj_elem_addr(comp_ctx, func_ctx, array_obj, elem_idx,
                                 &elem_data_ptr, array_elem_type))
        goto fail;

    if (wasm_is_type_reftype(array_elem_type)) {
        elem_data_type = GC_REF_TYPE;
        elem_data_ptr_type = GC_REF_PTR_TYPE;
    }
    else
        switch (array_elem_type) {
            case PACKED_TYPE_I8:
                elem_data_type = INT8_TYPE;
                elem_data_ptr_type = INT8_PTR_TYPE;
                trunc = true;
                break;
            case PACKED_TYPE_I16:
                elem_data_type = INT16_TYPE;
                elem_data_ptr_type = INT16_PTR_TYPE;
                trunc = true;
                break;
            case VALUE_TYPE_I32:
                elem_data_type = I32_TYPE;
                elem_data_ptr_type = INT32_PTR_TYPE;
                break;
            case VALUE_TYPE_I64:
                elem_data_type = I64_TYPE;
                elem_data_ptr_type = INT64_PTR_TYPE;
                break;
            case VALUE_TYPE_F32:
                elem_data_type = F32_TYPE;
                elem_data_ptr_type = F32_PTR_TYPE;
                break;
            case VALUE_TYPE_F64:
                elem_data_type = F64_TYPE;
                elem_data_ptr_type = F64_PTR_TYPE;
                break;
            default:
                bh_assert(0);
                break;
        }

    /* Based on elem_size, trunc array_elem if necessary */
    if (trunc) {
        if (!(array_elem =
                  LLVMBuildTrunc(comp_ctx->builder, array_elem, elem_data_type,
                                 "array_elem_trunc"))) {
            aot_set_last_error("llvm build trunc failed.");
            goto fail;
        }
    }

    /* Cast to the field data type ptr */
    if (!(elem_data_ptr =
              LLVMBuildBitCast(comp_ctx->builder, elem_data_ptr,
                               elem_data_ptr_type, "elem_data_ptr"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    if (!(res = LLVMBuildStore(comp_ctx->builder, array_elem, elem_data_ptr))) {
        aot_set_last_error("llvm build store failed.");
        goto fail;
    }

    if (!is_target_x86(comp_ctx)
        && (elem_data_type == I64_TYPE || elem_data_type == F64_TYPE
            || elem_data_type == GC_REF_TYPE)) {
        LLVMSetAlignment(res, 4);
    }

    return true;
fail:
    return false;
}

static bool
aot_call_aot_array_init_with_data(
    AOTCompContext *comp_ctx, AOTFuncContext *func_ctx, LLVMValueRef seg_index,
    LLVMValueRef data_seg_offset, LLVMValueRef array_obj,
    LLVMValueRef elem_size, LLVMValueRef array_len)
{
    LLVMValueRef param_values[6], func, value, res, cmp;
    LLVMTypeRef param_types[6], ret_type, func_type, func_ptr_type;
    LLVMBasicBlockRef init_success;

    ADD_BASIC_BLOCK(init_success, "init success");
    MOVE_BLOCK_AFTER_CURR(init_success);

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = I32_TYPE;
    param_types[3] = INT8_PTR_TYPE;
    param_types[4] = I32_TYPE;
    param_types[5] = I32_TYPE;
    ret_type = INT8_TYPE;

    if (comp_ctx->is_jit_mode)
        GET_AOT_FUNCTION(llvm_array_init_with_data, 6);
    else
        GET_AOT_FUNCTION(aot_array_init_with_data, 6);

    /* Call function aot_array_init_with_data() */
    param_values[0] = func_ctx->aot_inst;
    param_values[1] = seg_index;
    param_values[2] = data_seg_offset;
    param_values[3] = array_obj;
    param_values[4] = elem_size;
    param_values[5] = array_len;
    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               6, "call"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    BUILD_ICMP(LLVMIntEQ, res, I8_ZERO, cmp, "array_init_ret");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_ARRAY_IDX_OOB, true, cmp,
                            init_success))
        goto fail;

    return true;
fail:
    return false;
}

static bool
aot_call_wasm_array_get_elem(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef array_obj, LLVMValueRef elem_idx,
                             LLVMValueRef *p_array_elem, uint8 array_elem_type,
                             bool sign)
{
    bool extend = false;
    LLVMValueRef elem_data_ptr, array_elem;
    LLVMTypeRef elem_data_type = NULL, elem_data_ptr_type = NULL;

    if (!aot_array_obj_elem_addr(comp_ctx, func_ctx, array_obj, elem_idx,
                                 &elem_data_ptr, array_elem_type))
        goto fail;

    if (wasm_is_type_reftype(array_elem_type)) {
        elem_data_type = GC_REF_TYPE;
        elem_data_ptr_type = GC_REF_PTR_TYPE;
    }
    else
        switch (array_elem_type) {
            case PACKED_TYPE_I8:
                elem_data_type = INT8_TYPE;
                elem_data_ptr_type = INT8_PTR_TYPE;
                extend = true;
                break;
            case PACKED_TYPE_I16:
                elem_data_type = INT16_TYPE;
                elem_data_ptr_type = INT16_PTR_TYPE;
                extend = true;
                break;
            case VALUE_TYPE_I32:
                elem_data_type = I32_TYPE;
                elem_data_ptr_type = INT32_PTR_TYPE;
                break;
            case VALUE_TYPE_I64:
                elem_data_type = I64_TYPE;
                elem_data_ptr_type = INT64_PTR_TYPE;
                break;
            case VALUE_TYPE_F32:
                elem_data_type = F32_TYPE;
                elem_data_ptr_type = F32_PTR_TYPE;
                break;
            case VALUE_TYPE_F64:
                elem_data_type = F64_TYPE;
                elem_data_ptr_type = F64_PTR_TYPE;
                break;
            default:
                bh_assert(0);
                break;
        }

    /* Based on elem_size, trunc array_elem if necessary */
    if (!(elem_data_ptr =
              LLVMBuildBitCast(comp_ctx->builder, elem_data_ptr,
                               elem_data_ptr_type, "elem_data_ptr"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    if (!(array_elem = LLVMBuildLoad2(comp_ctx->builder, elem_data_type,
                                      elem_data_ptr, "array_elem"))) {
        aot_set_last_error("llvm build load failed.");
        goto fail;
    }

    if (!is_target_x86(comp_ctx)
        && (elem_data_type == I64_TYPE || elem_data_type == F64_TYPE
            || elem_data_type == GC_REF_TYPE)) {
        LLVMSetAlignment(array_elem, 4);
    }

    if (extend) {
        if (sign) {
            if (!(array_elem = LLVMBuildSExt(comp_ctx->builder, array_elem,
                                             I32_TYPE, "array_elem_sext"))) {
                aot_set_last_error("llvm build signed ext failed.");
                goto fail;
            }
        }
        else {
            if (!(array_elem = LLVMBuildZExt(comp_ctx->builder, array_elem,
                                             I32_TYPE, "array_elem_zext"))) {
                aot_set_last_error("llvm build unsigned ext failed.");
                goto fail;
            }
        }
    }

    *p_array_elem = array_elem;
    return true;
fail:
    return false;
}

/* array_obj->length >> WASM_ARRAY_LENGTH_SHIFT */
bool
aot_array_obj_length(AOTCompContext *comp_ctx, LLVMValueRef array_obj,
                     LLVMValueRef *p_array_len)
{
    LLVMValueRef offset, array_len;

    /* Get the length of the WASMArrayObject, the offset may be
     * different in 32-bit runtime and 64-bit runtime since WASMObjectHeader
     * is uintptr_t. Use comp_ctx->pointer_size as the
     * offsetof(WASMArrayObject, length)*/
    if (!(offset = I32_CONST(comp_ctx->pointer_size))) {
        aot_set_last_error("llvm build const failed.");
        goto fail;
    }

    if (!(array_len =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, array_obj,
                                    &offset, 1, "array_obj_length_i8p"))) {
        aot_set_last_error("llvm build gep failed.");
        goto fail;
    }

    if (!(array_len =
              LLVMBuildBitCast(comp_ctx->builder, array_len, INT32_PTR_TYPE,
                               "array_obj_length_i32ptr"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    if (!(array_len = LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, array_len,
                                     "array_obj_length"))) {
        aot_set_last_error("llvm build load failed.");
        goto fail;
    }

    if (!(array_len = LLVMBuildLShr(comp_ctx->builder, array_len,
                                    I32_CONST(WASM_ARRAY_LENGTH_SHIFT),
                                    "array_obj_length_shr"))) {
        aot_set_last_error("llvm build lshr failed.");
        goto fail;
    }

    *p_array_len = array_len;
    return true;
fail:
    return false;
}

bool
aot_compile_op_array_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 type_index, bool init_with_default,
                         bool fixed_size, uint32 array_len)
{
    LLVMValueRef array_length, array_elem = NULL, array_obj;
    LLVMValueRef rtt_type, cmp, elem_idx;
    LLVMBasicBlockRef check_rtt_type_succ, check_array_obj_succ;
    /* Use for distinguish what type of AOTValue POP */
    WASMArrayType *compile_time_array_type =
        (WASMArrayType *)comp_ctx->comp_data->types[type_index];
    uint8 array_elem_type = compile_time_array_type->elem_type;
    uint32 i;

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    /* Generate call aot_rtt_type_new and check for exception */
    if (!aot_call_aot_rtt_type_new(comp_ctx, func_ctx, I32_CONST(type_index),
                                   &rtt_type))
        goto fail;

    ADD_BASIC_BLOCK(check_rtt_type_succ, "check rtt type succ");
    MOVE_BLOCK_AFTER_CURR(check_rtt_type_succ);

    BUILD_ISNULL(rtt_type, cmp, "cmp_rtt_type");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_FAILED_TO_CREATE_RTT_TYPE,
                            true, cmp, check_rtt_type_succ))
        goto fail;

    if (!fixed_size)
        POP_I32(array_length);
    else
        array_length = I32_CONST(array_len);

    /* For WASM_OP_ARRAY_NEW */
    if (!fixed_size && !init_with_default) {
        if (wasm_is_type_reftype(array_elem_type)) {
            POP_GC_REF(array_elem);
        }
        else if (array_elem_type == VALUE_TYPE_I32
                 || array_elem_type == PACKED_TYPE_I8
                 || array_elem_type == PACKED_TYPE_I16) {
            POP_I32(array_elem);
        }
        else if (array_elem_type == VALUE_TYPE_I64) {
            POP_I64(array_elem);
        }
        else if (array_elem_type == VALUE_TYPE_F32) {
            POP_F32(array_elem);
        }
        else if (array_elem_type == VALUE_TYPE_F64) {
            POP_F64(array_elem);
        }
        else {
            bh_assert(0);
        }
    }
    else {
        /* I64 will alloca large enough space for all union access includes
         * array_elem.gc_ob, i32, i64 to be interpreted as 0*/
        array_elem = I64_ZERO;
    }

    /* Generate call wasm_array_obj_new and check for exception */
    if (!aot_call_wasm_array_obj_new(comp_ctx, func_ctx, rtt_type, array_length,
                                     array_elem, &array_obj))
        goto fail;

    ADD_BASIC_BLOCK(check_array_obj_succ, "check array obj succ");
    MOVE_BLOCK_AFTER(check_array_obj_succ, check_rtt_type_succ);

    BUILD_ISNULL(array_obj, cmp, "cmp_array_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_FAILED_TO_CREATE_ARRAY_OBJ,
                            true, cmp, check_array_obj_succ))
        goto fail;

    if (fixed_size) {
        for (i = 0; i < array_len; i++) {
            if (wasm_is_type_reftype(array_elem_type)) {
                POP_GC_REF(array_elem);
            }
            else if (array_elem_type == VALUE_TYPE_I32
                     || array_elem_type == PACKED_TYPE_I8
                     || array_elem_type == PACKED_TYPE_I16) {
                POP_I32(array_elem);
            }
            else if (array_elem_type == VALUE_TYPE_I64) {
                POP_I64(array_elem);
            }
            else if (array_elem_type == VALUE_TYPE_F32) {
                POP_F32(array_elem);
            }
            else if (array_elem_type == VALUE_TYPE_F64) {
                POP_F64(array_elem);
            }
            else {
                bh_assert(0);
            }

            /* array_len - 1 - i */
            if (!(elem_idx = LLVMBuildSub(comp_ctx->builder, array_length,
                                          I32_CONST(i + 1), "elem_idx"))) {
                aot_set_last_error("llvm build sub failed.");
                goto fail;
            }

            if (!aot_array_obj_set_elem(comp_ctx, func_ctx, array_obj, elem_idx,
                                        array_elem, array_elem_type))
                goto fail;
        }
    }

    PUSH_GC_REF(array_obj);

    return true;
fail:
    return false;
}

bool
aot_compile_op_array_new_data(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, uint32 type_index,
                              uint32 data_seg_index)
{
    LLVMValueRef array_length, data_seg_offset, rtt_type,
        elem_size = NULL, array_elem, array_obj, cmp;
    LLVMBasicBlockRef check_rtt_type_succ, check_array_obj_succ;
    /* Use for distinguish what type of element in array */
    WASMArrayType *compile_time_array_type =
        (WASMArrayType *)comp_ctx->comp_data->types[type_index];
    uint8 array_elem_type = compile_time_array_type->elem_type;

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    /* Generate call aot_rtt_type_new and check for exception */
    if (!aot_call_aot_rtt_type_new(comp_ctx, func_ctx, I32_CONST(type_index),
                                   &rtt_type))
        goto fail;

    ADD_BASIC_BLOCK(check_rtt_type_succ, "check rtt type succ");
    MOVE_BLOCK_AFTER_CURR(check_rtt_type_succ);

    BUILD_ISNULL(rtt_type, cmp, "cmp_rtt_type");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_FAILED_TO_CREATE_RTT_TYPE,
                            true, cmp, check_rtt_type_succ))
        goto fail;

    POP_I32(array_length);
    POP_I32(data_seg_offset);

    switch (array_elem_type) {
        case PACKED_TYPE_I8:
            elem_size = I32_ONE;
            break;
        case PACKED_TYPE_I16:
            elem_size = I32_TWO;
            break;
        case VALUE_TYPE_I32:
        case VALUE_TYPE_F32:
            elem_size = I32_FOUR;
            break;
        case VALUE_TYPE_I64:
        case VALUE_TYPE_F64:
            elem_size = I32_EIGHT;
            break;
        default:
            bh_assert(0);
    }

    if (elem_size == I32_EIGHT)
        array_elem = I64_ZERO;
    else
        array_elem = I32_ZERO;

    /* Generate call wasm_array_obj_new and check for exception */
    if (!aot_call_wasm_array_obj_new(comp_ctx, func_ctx, rtt_type, array_length,
                                     array_elem, &array_obj))
        goto fail;

    ADD_BASIC_BLOCK(check_array_obj_succ, "check array obj succ");
    MOVE_BLOCK_AFTER(check_array_obj_succ, check_rtt_type_succ);

    BUILD_ISNULL(array_obj, cmp, "cmp_array_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_FAILED_TO_CREATE_ARRAY_OBJ,
                            true, cmp, check_array_obj_succ))
        goto fail;

    if (!aot_call_aot_array_init_with_data(
            comp_ctx, func_ctx, I32_CONST(data_seg_index), data_seg_offset,
            array_obj, elem_size, array_length))
        goto fail;

    PUSH_GC_REF(array_obj);

    return true;
fail:
    return false;
}

bool
aot_compile_op_array_get(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 type_index, bool sign)
{
    LLVMValueRef elem_idx, array_obj, cmp, array_len, array_elem;
    LLVMBasicBlockRef check_array_obj_succ, check_boundary_succ;
    /* Use for distinguish what type of AOTValue PUSH */
    WASMArrayType *compile_time_array_type =
        (WASMArrayType *)comp_ctx->comp_data->types[type_index];
    uint8 array_elem_type = compile_time_array_type->elem_type;

    POP_I32(elem_idx);
    POP_GC_REF(array_obj);

    ADD_BASIC_BLOCK(check_array_obj_succ, "check array obj succ");
    MOVE_BLOCK_AFTER_CURR(check_array_obj_succ);

    BUILD_ISNULL(array_obj, cmp, "cmp_array_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_NULL_ARRAY_OBJ, true, cmp,
                            check_array_obj_succ))
        goto fail;

    SET_BUILDER_POS(check_array_obj_succ);
    if (!aot_array_obj_length(comp_ctx, array_obj, &array_len))
        goto fail;

    ADD_BASIC_BLOCK(check_boundary_succ, "check boundary succ");
    MOVE_BLOCK_AFTER(check_boundary_succ, check_array_obj_succ);

    BUILD_ICMP(LLVMIntUGE, elem_idx, array_len, cmp, "cmp_array_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_ARRAY_IDX_OOB, true, cmp,
                            check_boundary_succ))
        goto fail;

    SET_BUILDER_POS(check_boundary_succ);
    if (!aot_call_wasm_array_get_elem(comp_ctx, func_ctx, array_obj, elem_idx,
                                      &array_elem, array_elem_type, sign))
        goto fail;

    if (wasm_is_type_reftype(array_elem_type)) {
        PUSH_GC_REF(array_elem);
    }
    else if (array_elem_type == VALUE_TYPE_I32
             || array_elem_type == PACKED_TYPE_I8
             || array_elem_type == PACKED_TYPE_I16) {
        PUSH_I32(array_elem);
    }
    else if (array_elem_type == VALUE_TYPE_I64) {
        PUSH_I64(array_elem);
    }
    else if (array_elem_type == VALUE_TYPE_F32) {
        PUSH_F32(array_elem);
    }
    else if (array_elem_type == VALUE_TYPE_F64) {
        PUSH_F64(array_elem);
    }
    else {
        bh_assert(0);
    }

    return true;
fail:
    return false;
}

bool
aot_compile_op_array_set(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 type_index)
{
    LLVMValueRef elem_idx, array_obj, cmp, array_len, array_elem = NULL;
    LLVMBasicBlockRef check_array_obj_succ, check_boundary_succ;
    /* Use for distinguish what type of AOTValue POP */
    WASMArrayType *compile_time_array_type =
        (WASMArrayType *)comp_ctx->comp_data->types[type_index];
    uint8 array_elem_type = compile_time_array_type->elem_type;

    /* Get LLVM type based on array_elem_type */
    if (wasm_is_type_reftype(array_elem_type)) {
        POP_GC_REF(array_elem);
    }
    else if (array_elem_type == VALUE_TYPE_I32
             || array_elem_type == PACKED_TYPE_I8
             || array_elem_type == PACKED_TYPE_I16) {
        POP_I32(array_elem);
    }
    else if (array_elem_type == VALUE_TYPE_I64) {
        POP_I64(array_elem);
    }
    else if (array_elem_type == VALUE_TYPE_F32) {
        POP_F32(array_elem);
    }
    else if (array_elem_type == VALUE_TYPE_F64) {
        POP_F64(array_elem);
    }
    else {
        bh_assert(0);
    }

    POP_I32(elem_idx);
    POP_GC_REF(array_obj);

    ADD_BASIC_BLOCK(check_array_obj_succ, "check array obj succ");
    MOVE_BLOCK_AFTER_CURR(check_array_obj_succ);

    BUILD_ISNULL(array_obj, cmp, "cmp_array_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_NULL_ARRAY_OBJ, true, cmp,
                            check_array_obj_succ))
        goto fail;

    SET_BUILDER_POS(check_array_obj_succ);
    if (!aot_array_obj_length(comp_ctx, array_obj, &array_len))
        goto fail;

    ADD_BASIC_BLOCK(check_boundary_succ, "check boundary succ");
    MOVE_BLOCK_AFTER(check_boundary_succ, check_array_obj_succ);

    BUILD_ICMP(LLVMIntUGE, elem_idx, array_len, cmp, "cmp_array_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_ARRAY_IDX_OOB, true, cmp,
                            check_boundary_succ))
        goto fail;

    SET_BUILDER_POS(check_boundary_succ);
    if (!aot_array_obj_set_elem(comp_ctx, func_ctx, array_obj, elem_idx,
                                array_elem, array_elem_type)) {
        aot_set_last_error("llvm build alloca failed.");
        goto fail;
    }

    return true;
fail:
    return false;
}

bool
aot_compile_op_array_fill(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 type_index)
{
    LLVMValueRef len, array_obj, fill_value = NULL, offset, array_len, cmp[2],
                                 boundary, loop_counter_addr, loop_counter_val;
    LLVMBasicBlockRef check_obj_succ, len_gt_zero, len_le_zero, inner_else;
    LLVMBasicBlockRef fill_loop_header, fill_loop_body;
    WASMArrayType *compile_time_array_type =
        (WASMArrayType *)comp_ctx->comp_data->types[type_index];
    uint8 array_elem_type = compile_time_array_type->elem_type;

    POP_I32(len);
    /* Get LLVM type based on array_elem_type */
    if (wasm_is_type_reftype(array_elem_type)) {
        POP_GC_REF(fill_value);
    }
    else if (array_elem_type == VALUE_TYPE_I32
             || array_elem_type == PACKED_TYPE_I8
             || array_elem_type == PACKED_TYPE_I16) {
        POP_I32(fill_value);
    }
    else if (array_elem_type == VALUE_TYPE_I64) {
        POP_I64(fill_value);
    }
    else if (array_elem_type == VALUE_TYPE_F32) {
        POP_F32(fill_value);
    }
    else if (array_elem_type == VALUE_TYPE_F64) {
        POP_F64(fill_value);
    }
    else {
        bh_assert(0);
    }

    POP_I32(offset);
    POP_GC_REF(array_obj);

    ADD_BASIC_BLOCK(check_obj_succ, "check array objs succ");
    MOVE_BLOCK_AFTER_CURR(check_obj_succ);

    BUILD_ISNULL(array_obj, cmp[0], "cmp_obj");

    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_NULL_ARRAY_OBJ, true,
                            cmp[0], check_obj_succ))
        goto fail;

    /* Create if block */
    ADD_BASIC_BLOCK(len_gt_zero, "len_gt_zero");
    MOVE_BLOCK_AFTER_CURR(len_gt_zero);

    /* Create inner else block */
    ADD_BASIC_BLOCK(inner_else, "inner_else");
    MOVE_BLOCK_AFTER(inner_else, len_gt_zero);

    /* Create fill_loop_header block */
    ADD_BASIC_BLOCK(fill_loop_header, "fill_loop_header");
    MOVE_BLOCK_AFTER(fill_loop_header, len_gt_zero);

    /* Create fill_loop_body block */
    ADD_BASIC_BLOCK(fill_loop_body, "fill_loop_body");
    MOVE_BLOCK_AFTER(fill_loop_body, len_gt_zero);

    /* Create else(end) block */
    ADD_BASIC_BLOCK(len_le_zero, "len_le_zero");
    MOVE_BLOCK_AFTER(len_le_zero, len_gt_zero);

    BUILD_ICMP(LLVMIntSGT, len, I32_ZERO, cmp[0], "cmp_len");
    BUILD_COND_BR(cmp[0], len_gt_zero, len_le_zero);

    /* Move builder to len > 0 block */
    SET_BUILDER_POS(len_gt_zero);
    /* dst_offset > UINT32_MAX - len */
    if (!(boundary = LLVMBuildAdd(comp_ctx->builder, offset, len, ""))) {
        aot_set_last_error("llvm build failed.");
        goto fail;
    }
    BUILD_ICMP(LLVMIntUGT, boundary, I32_CONST(UINT32_MAX), cmp[0],
               "boundary_check1");
    /* dst_offset + len > wasm_array_obj_length(dst_obj) */
    if (!aot_array_obj_length(comp_ctx, array_obj, &array_len))
        goto fail;
    BUILD_ICMP(LLVMIntUGT, boundary, array_len, cmp[1], "boundary_check2");

    if (!(cmp[0] = LLVMBuildOr(comp_ctx->builder, cmp[0], cmp[1], ""))) {
        aot_set_last_error("llvm build failed.");
        goto fail;
    }

    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_ARRAY_IDX_OOB, true,
                            cmp[0], inner_else))
        goto fail;

    if (!(loop_counter_addr = LLVMBuildAlloca(comp_ctx->builder, I32_TYPE,
                                              "fill_loop_counter"))) {
        aot_set_last_error("llvm build alloc failed.");
        goto fail;
    }

    if (!is_target_x86(comp_ctx)) {
        LLVMSetAlignment(loop_counter_addr, 4);
    }

    if (!LLVMBuildStore(comp_ctx->builder, offset, loop_counter_addr)) {
        aot_set_last_error("llvm build store failed.");
        goto fail;
    }

    BUILD_BR(fill_loop_header);
    SET_BUILDER_POS(fill_loop_header);

    if (!(loop_counter_val =
              LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, loop_counter_addr,
                             "fill_loop_counter"))) {
        aot_set_last_error("llvm build load failed.");
        goto fail;
    }

    BUILD_ICMP(LLVMIntULT, loop_counter_val, boundary, cmp[0],
               "cmp_loop_counter");
    BUILD_COND_BR(cmp[0], fill_loop_body, len_le_zero);

    SET_BUILDER_POS(fill_loop_body);

    if (!aot_array_obj_set_elem(comp_ctx, func_ctx, array_obj, loop_counter_val,
                                fill_value, array_elem_type))
        goto fail;

    if (!(loop_counter_val = LLVMBuildAdd(comp_ctx->builder, loop_counter_val,
                                          I32_ONE, "fill_loop_counter"))) {
        aot_set_last_error("llvm build add failed.");
        goto fail;
    }

    if (!LLVMBuildStore(comp_ctx->builder, loop_counter_val,
                        loop_counter_addr)) {
        aot_set_last_error("llvm build store failed.");
        goto fail;
    }

    BUILD_BR(fill_loop_header);

    SET_BUILDER_POS(len_le_zero);

    return true;
fail:
    return false;
}

static bool
aot_call_wasm_array_obj_copy(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef dst_obj, LLVMValueRef dst_offset,
                             LLVMValueRef src_obj, LLVMValueRef src_offset,
                             LLVMValueRef len)
{
    LLVMValueRef param_values[5], func, value;
    LLVMTypeRef param_types[5], ret_type, func_type, func_ptr_type;

    param_types[0] = GC_REF_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = GC_REF_TYPE;
    param_types[3] = I32_TYPE;
    param_types[4] = I32_TYPE;
    ret_type = VOID_TYPE;

    GET_AOT_FUNCTION(wasm_array_obj_copy, 5);

    /* Call function wasm_array_obj_copy() */
    param_values[0] = dst_obj;
    param_values[1] = dst_offset;
    param_values[2] = src_obj;
    param_values[3] = src_offset;
    param_values[4] = len;
    if (!LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values, 5,
                        "")) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    return true;
fail:
    return false;
}

bool
aot_compile_op_array_copy(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 type_index, uint32 src_type_index)
{
    LLVMValueRef len, src_offset, src_obj, dst_offset, dst_obj, array_len,
        cmp[4], boundary;
    LLVMBasicBlockRef check_objs_succ, len_gt_zero, len_le_zero, inner_else;
    int i;

    POP_I32(len);
    POP_I32(src_offset);
    POP_GC_REF(src_obj);
    POP_I32(dst_offset);
    POP_GC_REF(dst_obj);

    ADD_BASIC_BLOCK(check_objs_succ, "check array objs succ");
    MOVE_BLOCK_AFTER_CURR(check_objs_succ);

    BUILD_ISNULL(src_obj, cmp[0], "cmp_src_obj");
    BUILD_ISNULL(dst_obj, cmp[1], "cmp_dst_obj");

    /* src_obj is null or dst_obj is null, throw exception */
    if (!(cmp[0] = LLVMBuildOr(comp_ctx->builder, cmp[0], cmp[1], ""))) {
        aot_set_last_error("llvm build or failed.");
        goto fail;
    }

    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_NULL_ARRAY_OBJ, true,
                            cmp[0], check_objs_succ))
        goto fail;

    /* Create if block */
    ADD_BASIC_BLOCK(len_gt_zero, "len_gt_zero");
    MOVE_BLOCK_AFTER_CURR(len_gt_zero);

    /* Create else(end) block */
    ADD_BASIC_BLOCK(len_le_zero, "len_le_zero");
    MOVE_BLOCK_AFTER(len_le_zero, len_gt_zero);

    /* Create inner else block */
    ADD_BASIC_BLOCK(inner_else, "inner_else");
    MOVE_BLOCK_AFTER(inner_else, len_gt_zero);

    BUILD_ICMP(LLVMIntSGT, len, I32_ZERO, cmp[0], "cmp_len");
    BUILD_COND_BR(cmp[0], len_gt_zero, len_le_zero);

    /* Move builder to len > 0 block */
    SET_BUILDER_POS(len_gt_zero);
    /* dst_offset > UINT32_MAX - len */
    if (!(boundary = LLVMBuildAdd(comp_ctx->builder, dst_offset, len, ""))) {
        aot_set_last_error("llvm build failed.");
        goto fail;
    }
    BUILD_ICMP(LLVMIntUGT, boundary, I32_CONST(UINT32_MAX), cmp[0],
               "boundary_check1");
    /* dst_offset + len > wasm_array_obj_length(dst_obj) */
    if (!aot_array_obj_length(comp_ctx, dst_obj, &array_len))
        goto fail;
    BUILD_ICMP(LLVMIntUGT, boundary, array_len, cmp[1], "boundary_check2");
    /* src_offset > UINT32_MAX - len */
    if (!(boundary = LLVMBuildAdd(comp_ctx->builder, src_offset, len, ""))) {
        aot_set_last_error("llvm build failed.");
        goto fail;
    }
    BUILD_ICMP(LLVMIntUGT, boundary, I32_CONST(UINT32_MAX), cmp[2],
               "boundary_check3");
    /* src_offset + len > wasm_array_obj_length(src_obj) */
    if (!aot_array_obj_length(comp_ctx, src_obj, &array_len))
        goto fail;
    BUILD_ICMP(LLVMIntUGT, boundary, array_len, cmp[3], "boundary_check4");

    /* logical or above 4 boundary checks */
    for (i = 1; i < 4; ++i) {
        if (!(cmp[0] = LLVMBuildOr(comp_ctx->builder, cmp[0], cmp[i], ""))) {
            aot_set_last_error("llvm build failed.");
            goto fail;
        }
    }

    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_ARRAY_IDX_OOB, true,
                            cmp[0], inner_else))
        goto fail;

    if (!aot_call_wasm_array_obj_copy(comp_ctx, func_ctx, dst_obj, dst_offset,
                                      src_obj, src_offset, len))
        goto fail;

    BUILD_BR(len_le_zero);
    SET_BUILDER_POS(len_le_zero);

    return true;
fail:
    return false;
}

bool
aot_compile_op_array_len(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef array_obj, cmp, array_len;
    LLVMBasicBlockRef check_array_obj_succ;

    POP_GC_REF(array_obj);

    ADD_BASIC_BLOCK(check_array_obj_succ, "check array obj succ");
    MOVE_BLOCK_AFTER_CURR(check_array_obj_succ);

    BUILD_ISNULL(array_obj, cmp, "cmp_array_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_NULL_ARRAY_OBJ, true, cmp,
                            check_array_obj_succ))
        goto fail;

    if (!aot_array_obj_length(comp_ctx, array_obj, &array_len))
        goto fail;

    PUSH_I32(array_len);

    return true;
fail:
    return false;
}

bool
aot_compile_op_i31_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef i31_val, i31_obj;

    POP_I32(i31_val);

    /* i31_val <<= 1 */
    if (!(i31_val = LLVMBuildShl(comp_ctx->builder, i31_val, I32_ONE,
                                 "i31_val_shl"))) {
        aot_set_last_error("llvm build shl failed.");
        goto fail;
    }

    /* i31_val |= 1 */
    if (!(i31_val =
              LLVMBuildOr(comp_ctx->builder, i31_val, I32_ONE, "i31_val_or"))) {
        aot_set_last_error("llvm build or failed.");
        goto fail;
    }

    if (!(i31_obj = LLVMBuildIntToPtr(comp_ctx->builder, i31_val, GC_REF_TYPE,
                                      "i31_obj"))) {
        aot_set_last_error("llvm build bit cast failed.");
        goto fail;
    }

    PUSH_GC_REF(i31_obj);

    return true;
fail:
    return false;
}

bool
aot_compile_op_i31_get(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                       bool sign)
{
    LLVMValueRef i31_obj, i31_val, cmp_i31_obj;
    LLVMBasicBlockRef check_i31_obj_succ;

    POP_GC_REF(i31_obj);

    ADD_BASIC_BLOCK(check_i31_obj_succ, "check_i31_obj_succ");
    MOVE_BLOCK_AFTER_CURR(check_i31_obj_succ);

    /* Check if i31 object is NULL, throw exception if it is */
    BUILD_ISNULL(i31_obj, cmp_i31_obj, "cmp_i31_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_NULL_I31_OBJ, true,
                            cmp_i31_obj, check_i31_obj_succ)) {
        goto fail;
    }

    if (!(i31_val = LLVMBuildPtrToInt(comp_ctx->builder, i31_obj, I32_TYPE,
                                      "i31_val"))) {
        aot_set_last_error("llvm build ptr to init failed.");
        goto fail;
    }

    if (!sign) {
        if (!(i31_val = LLVMBuildLShr(comp_ctx->builder, i31_val, I32_ONE,
                                      "i31_value"))) {
            aot_set_last_error("llvm build lshr failed.");
            goto fail;
        }
    }
    else {
        if (!(i31_val = LLVMBuildAShr(comp_ctx->builder, i31_val, I32_ONE,
                                      "i31_value"))) {
            aot_set_last_error("llvm build ashr failed.");
            goto fail;
        }
    }

    PUSH_I32(i31_val);

    return true;
fail:
    return false;
}

bool
aot_compile_op_ref_test(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        int32 heap_type, bool nullable)
{
    LLVMValueRef gc_obj, ref_test_phi, cmp, castable;
    LLVMBasicBlockRef block_curr, block_obj_non_null, block_end;

    POP_GC_REF(gc_obj);

    block_curr = CURR_BLOCK();

    /* Create non-null object block */
    ADD_BASIC_BLOCK(block_obj_non_null, "non_null_obj");
    MOVE_BLOCK_AFTER_CURR(block_obj_non_null);

    /* Create end block */
    ADD_BASIC_BLOCK(block_end, "ref_test_end");
    MOVE_BLOCK_AFTER(block_end, block_obj_non_null);

    /* Create ref test result phi */
    SET_BUILDER_POS(block_end);
    if (!(ref_test_phi =
              LLVMBuildPhi(comp_ctx->builder, INT1_TYPE, "ref_test_res"))) {
        aot_set_last_error("llvm build phi failed");
        return false;
    }

    /* Check if gc object is NULL */
    SET_BUILDER_POS(block_curr);
    BUILD_ISNULL(gc_obj, cmp, "cmp_gc_obj");
    BUILD_COND_BR(cmp, block_end, block_obj_non_null);

    if (nullable)
        LLVMAddIncoming(ref_test_phi, &I1_ONE, &block_curr, 1);
    else
        LLVMAddIncoming(ref_test_phi, &I1_ZERO, &block_curr, 1);

    /* Move builder to non-null object block */
    SET_BUILDER_POS(block_obj_non_null);

    if (heap_type >= 0) {
        if (!aot_call_aot_obj_is_instance_of(comp_ctx, func_ctx, gc_obj,
                                             I32_CONST(heap_type), &castable))
            return false;
    }
    else {
        if (!aot_call_wasm_obj_is_type_of(comp_ctx, func_ctx, gc_obj,
                                          I32_CONST(heap_type), &castable))
            return false;
    }

    if (!(castable = LLVMBuildICmp(comp_ctx->builder, LLVMIntNE, castable,
                                   I8_ZERO, "castable"))) {
        aot_set_last_error("llvm build icmp failed.");
        return false;
    }

    BUILD_BR(block_end);
    LLVMAddIncoming(ref_test_phi, &castable, &block_obj_non_null, 1);

    SET_BUILDER_POS(block_end);
    PUSH_COND(ref_test_phi);

    return true;
fail:
    return false;
}

bool
aot_compile_op_ref_cast(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        int32 heap_type, bool nullable)
{
    LLVMValueRef gc_obj, cmp, castable;
    LLVMBasicBlockRef block_obj_non_null, block_end;

    GET_GC_REF_FROM_STACK(gc_obj);

    /* Create non null block */
    ADD_BASIC_BLOCK(block_obj_non_null, "non_null_obj");
    MOVE_BLOCK_AFTER_CURR(block_obj_non_null);

    /* Create end block */
    ADD_BASIC_BLOCK(block_end, "ref_cast_end");
    MOVE_BLOCK_AFTER(block_end, block_obj_non_null);

    BUILD_ISNULL(gc_obj, cmp, "obj_is_null");
    if (nullable) {
        BUILD_COND_BR(cmp, block_end, block_obj_non_null);
    }
    else {
        if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_CAST_FAILURE, true,
                                cmp, block_obj_non_null)) {
            return false;
        }
    }

    SET_BUILDER_POS(block_obj_non_null);

    if (heap_type >= 0) {
        if (!aot_call_aot_obj_is_instance_of(comp_ctx, func_ctx, gc_obj,
                                             I32_CONST(heap_type), &castable))
            return false;
    }
    else {
        if (!aot_call_wasm_obj_is_type_of(comp_ctx, func_ctx, gc_obj,
                                          I32_CONST(heap_type), &castable))
            return false;
    }

    if (!(cmp = LLVMBuildICmp(comp_ctx->builder, LLVMIntEQ, castable, I8_ZERO,
                              "is_uncastable"))) {
        aot_set_last_error("llvm build not failed");
        return false;
    }

    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_CAST_FAILURE, true, cmp,
                            block_end)) {
        return false;
    }

    SET_BUILDER_POS(block_end);

    return true;
fail:
    return false;
}

static bool
aot_call_wasm_externref_obj_to_internal_obj(AOTCompContext *comp_ctx,
                                            AOTFuncContext *func_ctx,
                                            LLVMValueRef externref_obj,
                                            LLVMValueRef *gc_obj)
{
    LLVMValueRef param_values[1], func, value, res;
    LLVMTypeRef param_types[1], ret_type, func_type, func_ptr_type;

    param_types[0] = GC_REF_TYPE;
    ret_type = GC_REF_TYPE;

    GET_AOT_FUNCTION(wasm_externref_obj_to_internal_obj, 1);

    /* Call function wasm_externref_obj_to_internal_obj */
    param_values[0] = externref_obj;
    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               1, "call"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    *gc_obj = res;

    return true;
fail:
    return false;
}

bool
aot_compile_op_extern_internalize(AOTCompContext *comp_ctx,
                                  AOTFuncContext *func_ctx)
{
    LLVMValueRef externref_obj, gc_obj, cmp, internal_obj_phi;
    LLVMBasicBlockRef block_curr, block_obj_non_null, block_end;

    POP_GC_REF(externref_obj);

    block_curr = CURR_BLOCK();

    /* Create non-null object block */
    ADD_BASIC_BLOCK(block_obj_non_null, "non_null_obj");
    MOVE_BLOCK_AFTER_CURR(block_obj_non_null);

    /* Create end block */
    ADD_BASIC_BLOCK(block_end, "internalize_end");
    MOVE_BLOCK_AFTER(block_end, block_obj_non_null);

    /* Create internalized object phi */
    SET_BUILDER_POS(block_end);
    if (!(internal_obj_phi =
              LLVMBuildPhi(comp_ctx->builder, GC_REF_TYPE, "internal_obj"))) {
        aot_set_last_error("llvm build phi failed");
        return false;
    }

    /* Check if externref object is NULL */
    SET_BUILDER_POS(block_curr);
    BUILD_ISNULL(externref_obj, cmp, "cmp_externref_obj");
    BUILD_COND_BR(cmp, block_end, block_obj_non_null);
    LLVMAddIncoming(internal_obj_phi, &GC_REF_NULL, &block_curr, 1);

    /* Move builder to non-null object block */
    SET_BUILDER_POS(block_obj_non_null);
    if (!aot_call_wasm_externref_obj_to_internal_obj(comp_ctx, func_ctx,
                                                     externref_obj, &gc_obj)) {
        return false;
    }
    BUILD_BR(block_end);
    LLVMAddIncoming(internal_obj_phi, &gc_obj, &block_obj_non_null, 1);

    /* Move builder to end block */
    SET_BUILDER_POS(block_end);
    PUSH_GC_REF(internal_obj_phi);

    return true;
fail:
    return false;
}

static bool
aot_call_wasm_internal_obj_to_external_obj(AOTCompContext *comp_ctx,
                                           AOTFuncContext *func_ctx,
                                           LLVMValueRef gc_obj,
                                           LLVMValueRef *externref_obj)
{
    LLVMValueRef param_values[2], func, value, res;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = GC_REF_TYPE;
    ret_type = GC_REF_TYPE;

    GET_AOT_FUNCTION(wasm_internal_obj_to_externref_obj, 2);

    /* Call function wasm_internal_obj_to_externref_obj() */
    param_values[0] = func_ctx->exec_env;
    param_values[1] = gc_obj;
    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               2, "call"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    *externref_obj = res;

    return true;
fail:
    return false;
}

bool
aot_compile_op_extern_externalize(AOTCompContext *comp_ctx,
                                  AOTFuncContext *func_ctx)
{
    LLVMValueRef gc_obj, cmp, external_obj_phi, externref_obj;
    LLVMBasicBlockRef block_curr, block_obj_non_null, block_end;

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    POP_GC_REF(gc_obj);

    block_curr = CURR_BLOCK();

    /* Create non-null object block */
    ADD_BASIC_BLOCK(block_obj_non_null, "non_null_obj");
    MOVE_BLOCK_AFTER_CURR(block_obj_non_null);

    /* Create end block */
    ADD_BASIC_BLOCK(block_end, "externalize_end");
    MOVE_BLOCK_AFTER(block_end, block_obj_non_null);

    /* Create externalized object phi */
    SET_BUILDER_POS(block_end);
    if (!(external_obj_phi =
              LLVMBuildPhi(comp_ctx->builder, GC_REF_TYPE, "external_obj"))) {
        aot_set_last_error("llvm build phi failed");
        return false;
    }

    /* Check if gc object is NULL */
    SET_BUILDER_POS(block_curr);
    BUILD_ISNULL(gc_obj, cmp, "cmp_gc_obj");
    BUILD_COND_BR(cmp, block_end, block_obj_non_null);
    LLVMAddIncoming(external_obj_phi, &GC_REF_NULL, &block_curr, 1);

    /* Move builder to non-null object block */
    SET_BUILDER_POS(block_obj_non_null);

    if (!aot_call_wasm_internal_obj_to_external_obj(comp_ctx, func_ctx, gc_obj,
                                                    &externref_obj)) {
        return false;
    }

    /* Check whether failed to externalize */
    BUILD_ISNULL(externref_obj, cmp, "cmp_externref_obj");
    if (!aot_emit_exception(comp_ctx, func_ctx,
                            EXCE_FAILED_TO_CREATE_EXTERNREF_OBJ, true, cmp,
                            block_end)) {
        return false;
    }

    LLVMAddIncoming(external_obj_phi, &externref_obj, &block_obj_non_null, 1);

    /* Move builder to end block */
    SET_BUILDER_POS(block_end);
    PUSH_GC_REF(external_obj_phi);

    return true;
fail:
    return false;
}

#endif /* end of WASM_ENABLE_GC != 0 */
