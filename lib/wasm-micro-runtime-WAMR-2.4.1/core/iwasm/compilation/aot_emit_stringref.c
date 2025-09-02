/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#if WASM_ENABLE_STRINGREF != 0

#include "aot_emit_stringref.h"
#include "aot_emit_exception.h"
#include "aot_emit_memory.h"
#include "aot_emit_gc.h"
#include "aot.h"
#include "aot_compiler.h"
#include "aot_emit_memory.h"
#include "gc_object.h"
#include "string_object.h"

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

#define DEFINE_STRINGREF_CHECK_VAR()                                   \
    LLVMBasicBlockRef check_string_obj_succ, check_stringref_obj_succ; \
    LLVMValueRef cmp

#define CHECK_STRING_OBJ(str_obj)                                        \
    do {                                                                 \
        ADD_BASIC_BLOCK(check_string_obj_succ, "check string obj succ"); \
        MOVE_BLOCK_AFTER_CURR(check_string_obj_succ);                    \
                                                                         \
        BUILD_ISNULL(str_obj, cmp, "cmp_string_obj");                    \
        if (!aot_emit_exception(comp_ctx, func_ctx,                      \
                                EXCE_FAILED_TO_CREATE_STRING, true, cmp, \
                                check_string_obj_succ))                  \
            goto fail;                                                   \
    } while (0)

#define CHECK_STRINGREF_INTERNAL(stringref_obj, exce_id, name)                \
    do {                                                                      \
        ADD_BASIC_BLOCK(check_stringref_obj_succ, "check " name " obj succ"); \
        MOVE_BLOCK_AFTER(check_stringref_obj_succ, check_string_obj_succ);    \
                                                                              \
        BUILD_ISNULL(stringref_obj, cmp, "cmp_" name "_obj");                 \
        if (!aot_emit_exception(comp_ctx, func_ctx, exce_id, true, cmp,       \
                                check_stringref_obj_succ))                    \
            goto fail;                                                        \
    } while (0)

#define CHECK_STRINGREF_OBJ(stringref_obj)                                   \
    CHECK_STRINGREF_INTERNAL(stringref_obj, EXCE_FAILED_TO_CREATE_STRINGREF, \
                             "stringref")

#define CHECK_STRINGVIEW_OBJ(stringview_obj)                                   \
    CHECK_STRINGREF_INTERNAL(stringview_obj, EXCE_FAILED_TO_CREATE_STRINGVIEW, \
                             "stringview")

#define CHECK_STRING_ENCODE(value)                                             \
    do {                                                                       \
        ADD_BASIC_BLOCK(check_string_encode_succ, "check string encode succ"); \
        MOVE_BLOCK_AFTER_CURR(check_string_encode_succ);                       \
                                                                               \
        if (!(cmp = LLVMBuildICmp(comp_ctx->builder, LLVMIntSLT, value,        \
                                  I32_ZERO, "cmp_string_encode"))) {           \
            aot_set_last_error("llvm build icmp failed.");                     \
            goto fail;                                                         \
        }                                                                      \
                                                                               \
        if (!aot_emit_exception(comp_ctx, func_ctx,                            \
                                EXCE_FAILED_TO_ENCODE_STRING, true, cmp,       \
                                check_string_encode_succ))                     \
            goto fail;                                                         \
    } while (0)

static bool
aot_call_wasm_stringref_obj_new(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx, LLVMValueRef str_obj,
                                uint32 stringref_type, uint32 pos,
                                LLVMValueRef *stringref_obj)
{
    LLVMValueRef param_values[3], func, value, res;
    LLVMTypeRef param_types[3], ret_type, func_type, func_ptr_type;
    uint32 argc = 2;

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = INT8_PTR_TYPE;
    param_types[2] = I32_TYPE;
    ret_type = INT8_PTR_TYPE;

    if (stringref_type == WASM_TYPE_STRINGREF) {
        GET_AOT_FUNCTION(wasm_stringref_obj_new, argc);
    }
    else if (stringref_type == WASM_TYPE_STRINGVIEWWTF8) {
        GET_AOT_FUNCTION(wasm_stringview_wtf8_obj_new, argc);
    }
    else if (stringref_type == WASM_TYPE_STRINGVIEWWTF16) {
        GET_AOT_FUNCTION(wasm_stringview_wtf16_obj_new, argc);
    }
    else {
        argc = 3;
        GET_AOT_FUNCTION(wasm_stringview_iter_obj_new, argc);
    }

    param_values[0] = func_ctx->exec_env;
    param_values[1] = str_obj;
    if (stringref_type == WASM_TYPE_STRINGVIEWITER) {
        param_values[2] = I32_CONST(pos);
    }

    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               argc, "create_stringref"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    *stringref_obj = res;

    return true;
fail:
    return false;
}

static LLVMValueRef
aot_stringref_obj_get_value(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            LLVMValueRef stringref_obj)
{
    LLVMValueRef str_obj_ptr, str_obj, host_ptr_offset;

    /* header */
    host_ptr_offset = I32_CONST(comp_ctx->pointer_size);

    if (!(stringref_obj =
              LLVMBuildBitCast(comp_ctx->builder, stringref_obj, INT8_PTR_TYPE,
                               "stringref_obj_i8p"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    if (!(str_obj_ptr =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, stringref_obj,
                                    &host_ptr_offset, 1, "str_obj_i8p"))) {
        aot_set_last_error("llvm build gep failed.");
        goto fail;
    }

    if (!(str_obj_ptr = LLVMBuildBitCast(comp_ctx->builder, str_obj_ptr,
                                         GC_REF_PTR_TYPE, "str_obj_gcref_p"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    if (!(str_obj = LLVMBuildLoad2(comp_ctx->builder, GC_REF_TYPE, str_obj_ptr,
                                   "str_obj"))) {
        aot_set_last_error("llvm build load failed.");
        goto fail;
    }

    LLVMSetAlignment(str_obj, 4);

    return str_obj;

fail:
    return NULL;
}

static LLVMValueRef
get_stringview_iter_pos_addr(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef stringview_iter_obj)
{
    LLVMValueRef iter_pos_ptr, host_ptr_offset;

    /* header + str_obj */
    host_ptr_offset = I32_CONST(comp_ctx->pointer_size * 2);

    if (!(stringview_iter_obj =
              LLVMBuildBitCast(comp_ctx->builder, stringview_iter_obj,
                               INT8_PTR_TYPE, "stringview_iter_obj_i8p"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    if (!(iter_pos_ptr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, INT8_TYPE, stringview_iter_obj,
              &host_ptr_offset, 1, "iter_pos_i8p"))) {
        aot_set_last_error("llvm build gep failed.");
        goto fail;
    }

    if (!(iter_pos_ptr = LLVMBuildBitCast(comp_ctx->builder, iter_pos_ptr,
                                          INT32_PTR_TYPE, "iter_pos_i32p"))) {
        aot_set_last_error("llvm build bitcast failed.");
        goto fail;
    }

    return iter_pos_ptr;

fail:
    return NULL;
}

static LLVMValueRef
aot_call_wasm_string_measure(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef stringref_obj, uint32 encoding)
{
    LLVMValueRef param_values[3], func, value, str_obj;
    LLVMTypeRef param_types[3], ret_type, func_type, func_ptr_type;

    if (!(str_obj =
              aot_stringref_obj_get_value(comp_ctx, func_ctx, stringref_obj))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    ret_type = I32_TYPE;

    GET_AOT_FUNCTION(wasm_string_measure, 2);

    /* Call function wasm_string_measure() */
    param_values[0] = str_obj;
    param_values[1] = I32_CONST(encoding);

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 2, "string_measure"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    return value;
fail:
    return NULL;
}

static LLVMValueRef
aot_call_wasm_string_create_view(AOTCompContext *comp_ctx,
                                 AOTFuncContext *func_ctx,
                                 LLVMValueRef stringref_obj, uint32 encoding)
{
    LLVMValueRef param_values[3], func, value, str_obj;
    LLVMTypeRef param_types[3], ret_type, func_type, func_ptr_type;

    if (!(str_obj =
              aot_stringref_obj_get_value(comp_ctx, func_ctx, stringref_obj))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    ret_type = INT8_PTR_TYPE;

    GET_AOT_FUNCTION(wasm_string_create_view, 2);

    /* Call function wasm_string_create_view() */
    param_values[0] = str_obj;
    param_values[1] = I32_CONST(encoding);

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 2, "string_create_view"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    return value;
fail:
    return NULL;
}

static LLVMValueRef
aot_call_wasm_string_advance(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef stringref_obj, LLVMValueRef bytes,
                             LLVMValueRef pos)
{
    LLVMValueRef param_values[4], func, value, str_obj;
    LLVMTypeRef param_types[4], ret_type, func_type, func_ptr_type;

    if (!(str_obj =
              aot_stringref_obj_get_value(comp_ctx, func_ctx, stringref_obj))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = I32_TYPE;
    param_types[3] = INT32_PTR_TYPE;
    ret_type = INT8_PTR_TYPE;

    GET_AOT_FUNCTION(wasm_string_advance, 4);

    /* Call function wasm_string_advance() */
    param_values[0] = str_obj;
    param_values[1] = pos;
    param_values[2] = bytes;
    param_values[3] = I8_PTR_NULL;

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 4, "string_advance"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    return value;
fail:
    return NULL;
}

static LLVMValueRef
aot_call_wasm_string_slice(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           LLVMValueRef stringref_obj, LLVMValueRef start,
                           LLVMValueRef end, StringViewType stringview_type)
{
    LLVMValueRef param_values[4], func, value, str_obj;
    LLVMTypeRef param_types[4], ret_type, func_type, func_ptr_type;

    if (!(str_obj =
              aot_stringref_obj_get_value(comp_ctx, func_ctx, stringref_obj))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = I32_TYPE;
    param_types[3] = I32_TYPE;
    ret_type = INT8_PTR_TYPE;

    GET_AOT_FUNCTION(wasm_string_slice, 4);

    /* Call function wasm_string_slice() */
    param_values[0] = str_obj;
    param_values[1] = start;
    param_values[2] = end;
    param_values[3] = I32_CONST(stringview_type);

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 4, "string_slice"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    return value;
fail:
    return NULL;
}

bool
aot_compile_op_string_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 encoding)
{
    LLVMValueRef maddr, byte_length, offset, str_obj, stringref_obj;
    LLVMValueRef param_values[5], func, value;
    LLVMTypeRef param_types[5], ret_type, func_type, func_ptr_type;
    DEFINE_STRINGREF_CHECK_VAR();

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    POP_I32(byte_length);
    POP_I32(offset);

    if (!(maddr = check_bulk_memory_overflow(comp_ctx, func_ctx, offset,
                                             byte_length)))
        goto fail;

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = I32_TYPE;
    ret_type = INT8_PTR_TYPE;

    GET_AOT_FUNCTION(wasm_string_new_with_encoding, 3);

    /* Call function wasm_struct_obj_new() */
    param_values[0] = maddr;
    param_values[1] = byte_length;
    param_values[2] = I32_CONST(encoding);

    if (!(str_obj = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                   param_values, 3, "wasm_string_new"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }
    CHECK_STRING_OBJ(str_obj);

    if (!aot_call_wasm_stringref_obj_new(comp_ctx, func_ctx, str_obj,
                                         WASM_TYPE_STRINGREF, 0,
                                         &stringref_obj)) {
        goto fail;
    }
    CHECK_STRINGREF_OBJ(stringref_obj);

    PUSH_GC_REF(stringref_obj);

    return true;
fail:
    return false;
}

bool
aot_compile_op_string_const(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            uint32 contents)
{
    LLVMValueRef param_values[2], func, value, str_obj, stringref_obj;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;
    DEFINE_STRINGREF_CHECK_VAR();

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    ret_type = INT8_PTR_TYPE;

    GET_AOT_FUNCTION(wasm_string_new_const, 2);

    bh_assert(contents < comp_ctx->comp_data->string_literal_count);
    param_values[0] = LLVMConstIntToPtr(
        I64_CONST((unsigned long long)(uintptr_t)
                      comp_ctx->comp_data->string_literal_ptrs_wp[contents]),
        INT8_PTR_TYPE);
    param_values[1] =
        I32_CONST(comp_ctx->comp_data->string_literal_lengths_wp[contents]);

    if (!(str_obj = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                   param_values, 2, "create_stringref"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }
    CHECK_STRING_OBJ(str_obj);

    if (!aot_call_wasm_stringref_obj_new(comp_ctx, func_ctx, str_obj,
                                         WASM_TYPE_STRINGREF, 0,
                                         &stringref_obj)) {
        goto fail;
    }
    CHECK_STRINGREF_OBJ(stringref_obj);

    PUSH_GC_REF(stringref_obj);

    return true;
fail:
    return false;
}

bool
aot_compile_op_string_measure(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, uint32 encoding)
{
    LLVMValueRef stringref_obj, value;

    POP_GC_REF(stringref_obj);

    if (!(value = aot_call_wasm_string_measure(comp_ctx, func_ctx,
                                               stringref_obj, encoding))) {
        goto fail;
    }

    PUSH_I32(value);

    return true;
fail:
    return false;
}

bool
aot_compile_op_string_encode(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             uint32 mem_idx, uint32 encoding)
{
    LLVMValueRef param_values[6], func, value, offset, length, maddr, str_obj,
        stringref_obj;
    LLVMTypeRef param_types[6], ret_type, func_type, func_ptr_type;
    LLVMBasicBlockRef check_string_encode_succ;
    LLVMValueRef cmp;

    POP_I32(offset);
    POP_GC_REF(stringref_obj);

    if (!(str_obj =
              aot_stringref_obj_get_value(comp_ctx, func_ctx, stringref_obj))) {
        goto fail;
    }

    if (!(length = aot_call_wasm_string_measure(comp_ctx, func_ctx,
                                                stringref_obj, encoding))) {
        goto fail;
    }

    if (!(maddr =
              check_bulk_memory_overflow(comp_ctx, func_ctx, offset, length)))
        goto fail;

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = I32_TYPE;
    param_types[3] = INT8_PTR_TYPE;
    param_types[4] = INT8_PTR_TYPE;
    param_types[5] = I32_TYPE;
    ret_type = I32_TYPE;

    GET_AOT_FUNCTION(wasm_string_encode, 6);

    /* Call function wasm_string_measure() */
    param_values[0] = str_obj;
    param_values[1] = I32_ZERO;
    param_values[2] = length;
    param_values[3] = maddr;
    param_values[4] = I8_PTR_NULL;
    param_values[5] = I32_CONST(encoding);

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 6, "string_encode"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    CHECK_STRING_ENCODE(value);

    PUSH_I32(value);

    return true;
fail:
    return false;
}

bool
aot_compile_op_string_concat(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef param_values[2], func, value, str_obj_lhs, str_obj_rhs,
        stringref_obj_lhs, stringref_obj_rhs, stringref_obj_new;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;
    DEFINE_STRINGREF_CHECK_VAR();

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    POP_GC_REF(stringref_obj_rhs);
    POP_GC_REF(stringref_obj_lhs);

    if (!(str_obj_lhs = aot_stringref_obj_get_value(comp_ctx, func_ctx,
                                                    stringref_obj_lhs))) {
        goto fail;
    }

    if (!(str_obj_rhs = aot_stringref_obj_get_value(comp_ctx, func_ctx,
                                                    stringref_obj_rhs))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = INT8_PTR_TYPE;
    ret_type = INT8_PTR_TYPE;

    GET_AOT_FUNCTION(wasm_string_concat, 2);

    /* Call function wasm_string_concat() */
    param_values[0] = str_obj_lhs;
    param_values[1] = str_obj_rhs;

    if (!(str_obj_lhs = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                       param_values, 2, "string_concat"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }
    CHECK_STRING_OBJ(str_obj_lhs);

    if (!aot_call_wasm_stringref_obj_new(comp_ctx, func_ctx, str_obj_lhs,
                                         WASM_TYPE_STRINGREF, 0,
                                         &stringref_obj_new)) {
        goto fail;
    }
    CHECK_STRINGREF_OBJ(stringref_obj_new);

    PUSH_GC_REF(stringref_obj_new);

    return true;
fail:
    return false;
}

bool
aot_compile_op_string_eq(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef param_values[2], func, value, str_obj_lhs, str_obj_rhs,
        stringref_obj_lhs, stringref_obj_rhs;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;

    POP_GC_REF(stringref_obj_lhs);
    POP_GC_REF(stringref_obj_rhs);

    if (!(str_obj_lhs = aot_stringref_obj_get_value(comp_ctx, func_ctx,
                                                    stringref_obj_lhs))) {
        goto fail;
    }

    if (!(str_obj_rhs = aot_stringref_obj_get_value(comp_ctx, func_ctx,
                                                    stringref_obj_rhs))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = INT8_PTR_TYPE;
    ret_type = I32_TYPE;

    GET_AOT_FUNCTION(wasm_string_eq, 2);

    /* Call function wasm_string_eq() */
    param_values[0] = str_obj_lhs;
    param_values[1] = str_obj_rhs;

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 2, "string_eq"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    PUSH_I32(value);

    return true;
fail:
    return false;
}

bool
aot_compile_op_string_is_usv_sequence(AOTCompContext *comp_ctx,
                                      AOTFuncContext *func_ctx)
{
    LLVMValueRef param_values[1], func, value, str_obj, stringref_obj;
    LLVMTypeRef param_types[1], ret_type, func_type, func_ptr_type;

    POP_GC_REF(stringref_obj);

    if (!(str_obj =
              aot_stringref_obj_get_value(comp_ctx, func_ctx, stringref_obj))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    ret_type = I32_TYPE;

    GET_AOT_FUNCTION(wasm_string_is_usv_sequence, 1);

    /* Call function wasm_string_is_usv_sequence() */
    param_values[0] = str_obj;

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 1, "string_is_usv_sequence"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    PUSH_I32(value);

    return true;
fail:
    return false;
}

bool
aot_compile_op_string_as_wtf8(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx)
{
    LLVMValueRef str_obj, stringref_obj, stringview_wtf8_obj;
    DEFINE_STRINGREF_CHECK_VAR();

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    POP_GC_REF(stringref_obj);

    if (!(str_obj = aot_call_wasm_string_create_view(
              comp_ctx, func_ctx, stringref_obj, STRING_VIEW_WTF8))) {
        goto fail;
    }
    CHECK_STRING_OBJ(str_obj);

    if (!aot_call_wasm_stringref_obj_new(comp_ctx, func_ctx, str_obj,
                                         WASM_TYPE_STRINGVIEWWTF8, 0,
                                         &stringview_wtf8_obj)) {
        goto fail;
    }
    CHECK_STRINGVIEW_OBJ(stringref_obj);

    PUSH_GC_REF(stringview_wtf8_obj);

    return true;
fail:
    return false;
}

bool
aot_compile_op_stringview_wtf8_advance(AOTCompContext *comp_ctx,
                                       AOTFuncContext *func_ctx)
{
    LLVMValueRef stringref_obj, bytes, pos, value;

    POP_I32(bytes);
    POP_I32(pos);
    POP_GC_REF(stringref_obj);

    if (!(value = aot_call_wasm_string_advance(comp_ctx, func_ctx,
                                               stringref_obj, bytes, pos))) {
        goto fail;
    }

    PUSH_I32(value);

    return true;
fail:
    return false;
}

bool
aot_compile_op_stringview_wtf8_encode(AOTCompContext *comp_ctx,
                                      AOTFuncContext *func_ctx, uint32 mem_idx,
                                      uint32 encoding)
{
    LLVMValueRef param_values[6], func, value, offset, maddr, str_obj,
        stringref_obj;
    LLVMValueRef bytes, pos, next_pos;
    LLVMTypeRef param_types[6], ret_type, func_type, func_ptr_type;
    LLVMBasicBlockRef check_string_encode_succ;
    LLVMValueRef cmp;

    POP_I32(bytes);
    POP_I32(pos);
    POP_I32(offset);

    next_pos = LLVMBuildAlloca(comp_ctx->builder, I32_TYPE, "next_pos");
    if (!next_pos) {
        aot_set_last_error("failed to build alloca");
        goto fail;
    }

    if (!(maddr =
              check_bulk_memory_overflow(comp_ctx, func_ctx, offset, bytes)))
        goto fail;

    POP_GC_REF(stringref_obj);

    if (!(str_obj =
              aot_stringref_obj_get_value(comp_ctx, func_ctx, stringref_obj))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = I32_TYPE;
    param_types[3] = INT8_PTR_TYPE;
    param_types[4] = INT8_PTR_TYPE;
    param_types[5] = I32_TYPE;
    ret_type = I32_TYPE;

    GET_AOT_FUNCTION(wasm_string_encode, 6);

    /* Call function wasm_string_measure() */
    param_values[0] = str_obj;
    param_values[1] = pos;
    param_values[2] = bytes;
    param_values[3] = maddr;
    param_values[4] = next_pos;
    param_values[5] = I32_CONST(encoding);

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 6, "string_encode"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    CHECK_STRING_ENCODE(value);

    next_pos =
        LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, next_pos, "next_pos");
    if (!next_pos) {
        aot_set_last_error("llvm build load failed.");
        goto fail;
    }

    LLVMSetAlignment(next_pos, 4);

    PUSH_I32(next_pos);
    PUSH_I32(value);

    return true;
fail:
    return false;
}

bool
aot_compile_op_stringview_wtf8_slice(AOTCompContext *comp_ctx,
                                     AOTFuncContext *func_ctx)
{
    LLVMValueRef stringref_obj, start, end, stringref_obj_new, value;
    DEFINE_STRINGREF_CHECK_VAR();

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    POP_I32(start);
    POP_I32(end);
    POP_GC_REF(stringref_obj);

    if (!(value = aot_call_wasm_string_slice(comp_ctx, func_ctx, stringref_obj,
                                             start, end, STRING_VIEW_WTF8))) {
        goto fail;
    }
    CHECK_STRING_OBJ(value);

    if (!aot_call_wasm_stringref_obj_new(comp_ctx, func_ctx, value,
                                         WASM_TYPE_STRINGREF, 0,
                                         &stringref_obj_new)) {
        goto fail;
    }
    CHECK_STRINGREF_OBJ(stringref_obj_new);

    PUSH_GC_REF(stringref_obj_new);

    return true;
fail:
    return false;
}

bool
aot_compile_op_string_as_wtf16(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx)
{
    LLVMValueRef str_obj, stringref_obj, stringview_wtf16_obj;
    DEFINE_STRINGREF_CHECK_VAR();

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    POP_GC_REF(stringref_obj);

    if (!(str_obj = aot_call_wasm_string_create_view(
              comp_ctx, func_ctx, stringref_obj, STRING_VIEW_WTF16))) {
        goto fail;
    }
    CHECK_STRING_OBJ(str_obj);

    if (!aot_call_wasm_stringref_obj_new(comp_ctx, func_ctx, str_obj,
                                         WASM_TYPE_STRINGVIEWWTF16, 0,
                                         &stringview_wtf16_obj)) {
        goto fail;
    }
    CHECK_STRINGVIEW_OBJ(stringview_wtf16_obj);

    PUSH_GC_REF(stringview_wtf16_obj);

    return true;
fail:
    return false;
}

bool
aot_compile_op_stringview_wtf16_length(AOTCompContext *comp_ctx,
                                       AOTFuncContext *func_ctx)
{
    LLVMValueRef param_values[2], func, value, str_obj, stringview_wtf16_obj;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;

    POP_GC_REF(stringview_wtf16_obj);

    if (!(str_obj = aot_stringref_obj_get_value(comp_ctx, func_ctx,
                                                stringview_wtf16_obj))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    ret_type = I32_TYPE;

    GET_AOT_FUNCTION(wasm_string_wtf16_get_length, 6);

    /* Call function wasm_string_wtf16_get_length() */
    param_values[0] = str_obj;

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 1, "stringview_wtf16_length"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    PUSH_I32(value);

    return true;
fail:
    return false;
}

bool
aot_compile_op_stringview_wtf16_get_codeunit(AOTCompContext *comp_ctx,
                                             AOTFuncContext *func_ctx)
{
    LLVMValueRef param_values[2], func, value, str_obj, stringview_wtf16_obj,
        pos;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;

    POP_I32(pos);
    POP_GC_REF(stringview_wtf16_obj);

    if (!(str_obj = aot_stringref_obj_get_value(comp_ctx, func_ctx,
                                                stringview_wtf16_obj))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    ret_type = I32_TYPE;

    GET_AOT_FUNCTION(wasm_string_get_wtf16_codeunit, 2);

    /* Call function wasm_string_get_wtf16_codeunit() */
    param_values[0] = str_obj;
    param_values[1] = pos;

    if (!(value =
              LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                             2, "stringview_wtf16_get_codeunit"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    PUSH_I32(value);

    return true;
fail:
    return false;
}

bool
aot_compile_op_stringview_wtf16_encode(AOTCompContext *comp_ctx,
                                       AOTFuncContext *func_ctx, uint32 mem_idx)
{
    LLVMValueRef param_values[6], func, value, offset, maddr, str_obj,
        stringref_obj;
    LLVMValueRef len, pos;
    LLVMTypeRef param_types[6], ret_type, func_type, func_ptr_type;
    LLVMBasicBlockRef check_string_encode_succ;
    LLVMValueRef cmp;

    POP_I32(len);
    POP_I32(pos);
    POP_I32(offset);

    if (!(maddr = check_bulk_memory_overflow(
              comp_ctx, func_ctx, offset,
              LLVMBuildMul(comp_ctx->builder, len, I32_CONST(2), "wtf16_len"))))
        goto fail;

    POP_GC_REF(stringref_obj);

    if (!check_memory_alignment(comp_ctx, func_ctx, maddr, 2)) {
        goto fail;
    }

    if (!(str_obj =
              aot_stringref_obj_get_value(comp_ctx, func_ctx, stringref_obj))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = I32_TYPE;
    param_types[3] = INT8_PTR_TYPE;
    param_types[4] = INT8_PTR_TYPE;
    param_types[5] = I32_TYPE;
    ret_type = I32_TYPE;

    GET_AOT_FUNCTION(wasm_string_encode, 6);

    /* Call function wasm_string_measure() */
    param_values[0] = str_obj;
    param_values[1] = pos;
    param_values[2] = len;
    param_values[3] = maddr;
    param_values[4] = I8_PTR_NULL;
    param_values[5] = I32_CONST(WTF16);

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 6, "string_encode"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    CHECK_STRING_ENCODE(value);

    PUSH_I32(value);

    return true;
fail:
    return false;
}

bool
aot_compile_op_stringview_wtf16_slice(AOTCompContext *comp_ctx,
                                      AOTFuncContext *func_ctx)
{
    LLVMValueRef stringref_obj, start, end, stringref_obj_new, value;
    DEFINE_STRINGREF_CHECK_VAR();

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    POP_I32(end);
    POP_I32(start);
    POP_GC_REF(stringref_obj);

    if (!(value = aot_call_wasm_string_slice(comp_ctx, func_ctx, stringref_obj,
                                             start, end, STRING_VIEW_WTF16))) {
        goto fail;
    }
    CHECK_STRING_OBJ(value);

    if (!aot_call_wasm_stringref_obj_new(comp_ctx, func_ctx, value,
                                         WASM_TYPE_STRINGREF, 0,
                                         &stringref_obj_new)) {
        goto fail;
    }
    CHECK_STRINGREF_OBJ(stringref_obj_new);

    PUSH_GC_REF(stringref_obj_new);

    return true;
fail:
    return false;
}

bool
aot_compile_op_string_as_iter(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx)
{
    LLVMValueRef stringref_obj, stringview_iter_obj, str_obj;
    DEFINE_STRINGREF_CHECK_VAR();

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    POP_GC_REF(stringref_obj);

    if (!(str_obj = aot_call_wasm_string_create_view(
              comp_ctx, func_ctx, stringref_obj, STRING_VIEW_WTF8))) {
        goto fail;
    }
    CHECK_STRING_OBJ(str_obj);

    if (!aot_call_wasm_stringref_obj_new(comp_ctx, func_ctx, stringref_obj,
                                         WASM_TYPE_STRINGVIEWITER, 0,
                                         &stringview_iter_obj)) {
        goto fail;
    }
    CHECK_STRINGVIEW_OBJ(stringview_iter_obj);

    PUSH_GC_REF(stringview_iter_obj);

    return true;
fail:
    return false;
}

bool
aot_compile_op_stringview_iter_next(AOTCompContext *comp_ctx,
                                    AOTFuncContext *func_ctx)
{
    LLVMValueRef param_values[2], func, value, stringview_iter_obj, str_obj,
        iter_pos_addr, pos;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;

    POP_GC_REF(stringview_iter_obj);

    if (!(str_obj = aot_stringref_obj_get_value(comp_ctx, func_ctx,
                                                stringview_iter_obj))) {
        goto fail;
    }

    if (!(iter_pos_addr = get_stringview_iter_pos_addr(comp_ctx, func_ctx,
                                                       stringview_iter_obj))) {
        goto fail;
    }

    pos = LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, iter_pos_addr,
                         "get_iter_pos");
    LLVMSetAlignment(pos, 4);

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    ret_type = I32_TYPE;

    GET_AOT_FUNCTION(wasm_string_next_codepoint, 2);

    /* Call function wasm_string_measure() */
    param_values[0] = str_obj;
    param_values[1] = pos;

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 2, "stringview_iter_next"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    PUSH_I32(value);

    return true;
fail:
    return false;
}

static bool
stringview_iter_advance_or_rewind(AOTCompContext *comp_ctx,
                                  AOTFuncContext *func_ctx, bool is_rewind)
{
    LLVMValueRef param_values[4], func, value, stringview_iter_obj, str_obj,
        code_points_consumed, iter_pos_addr, pos, code_points_count, res;
    LLVMTypeRef param_types[4], ret_type, func_type, func_ptr_type;

    POP_I32(code_points_count);
    POP_GC_REF(stringview_iter_obj);

    if (!(str_obj = aot_stringref_obj_get_value(comp_ctx, func_ctx,
                                                stringview_iter_obj))) {
        goto fail;
    }

    if (!(iter_pos_addr = get_stringview_iter_pos_addr(comp_ctx, func_ctx,
                                                       stringview_iter_obj))) {
        goto fail;
    }

    if (!(pos = LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, iter_pos_addr,
                               "get_iter_pos"))) {
        goto fail;
    }
    LLVMSetAlignment(pos, 4);

    if (!(code_points_consumed = LLVMBuildAlloca(comp_ctx->builder, I32_TYPE,
                                                 "code_points_consumed"))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = I32_TYPE;
    param_types[3] = INT32_PTR_TYPE;
    ret_type = I32_TYPE;

    if (is_rewind) {
        GET_AOT_FUNCTION(wasm_string_rewind, 4);
    }
    else {
        GET_AOT_FUNCTION(wasm_string_advance, 4);
    }

    /* Call function wasm_string_advance() */
    param_values[0] = str_obj;
    param_values[1] = pos;
    param_values[2] = code_points_count;
    param_values[3] = code_points_consumed;

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 4, "string_advance"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    if (!(code_points_consumed =
              LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, code_points_consumed,
                             "get_code_points_consumed"))) {
        aot_set_last_error("llvm build load failed.");
        goto fail;
    }
    LLVMSetAlignment(code_points_consumed, 4);

    if (!(res = LLVMBuildStore(comp_ctx->builder, code_points_consumed,
                               iter_pos_addr))) {
        aot_set_last_error("llvm build store failed.");
        goto fail;
    }
    LLVMSetAlignment(res, 4);

    PUSH_I32(code_points_consumed);
fail:
    return false;
}

bool
aot_compile_op_stringview_iter_advance(AOTCompContext *comp_ctx,
                                       AOTFuncContext *func_ctx)
{
    return stringview_iter_advance_or_rewind(comp_ctx, func_ctx, false);
}

bool
aot_compile_op_stringview_iter_rewind(AOTCompContext *comp_ctx,
                                      AOTFuncContext *func_ctx)
{
    return stringview_iter_advance_or_rewind(comp_ctx, func_ctx, true);
}

bool
aot_compile_op_stringview_iter_slice(AOTCompContext *comp_ctx,
                                     AOTFuncContext *func_ctx)
{
    LLVMValueRef stringview_iter_obj, start, end, stringref_obj_new, value,
        iter_pos_addr, code_points_count;
    DEFINE_STRINGREF_CHECK_VAR();

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    POP_I32(code_points_count);
    POP_GC_REF(stringview_iter_obj);

    if (!(iter_pos_addr = get_stringview_iter_pos_addr(comp_ctx, func_ctx,
                                                       stringview_iter_obj))) {
        goto fail;
    }

    if (!(start = LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, iter_pos_addr,
                                 "get_iter_pos"))) {
        goto fail;
    }
    LLVMSetAlignment(start, 4);

    if (!(end = LLVMBuildAdd(comp_ctx->builder, start, code_points_count,
                             "calc_slice_end"))) {
        goto fail;
    }

    if (!(value = aot_call_wasm_string_slice(comp_ctx, func_ctx,
                                             stringview_iter_obj, start, end,
                                             STRING_VIEW_ITER))) {
        goto fail;
    }
    CHECK_STRING_OBJ(value);

    if (!aot_call_wasm_stringref_obj_new(comp_ctx, func_ctx, value,
                                         WASM_TYPE_STRINGREF, 0,
                                         &stringref_obj_new)) {
        goto fail;
    }
    CHECK_STRINGREF_OBJ(stringref_obj_new);

    PUSH_GC_REF(stringref_obj_new);

    return true;
fail:
    return false;
}

bool
aot_compile_op_string_new_array(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx, uint32 encoding)
{
    LLVMValueRef start, end, count, str_obj, stringref_obj, array_obj,
        elem_data_ptr;
    LLVMValueRef param_values[5], func, value;
    LLVMTypeRef param_types[5], ret_type, func_type, func_ptr_type;
    DEFINE_STRINGREF_CHECK_VAR();

    if (!aot_gen_commit_values(comp_ctx->aot_frame))
        return false;

    if (!aot_gen_commit_sp_ip(comp_ctx->aot_frame, true, true))
        return false;

    POP_I32(end);
    POP_I32(start);
    POP_GC_REF(array_obj);

    if (!aot_array_obj_elem_addr(
            comp_ctx, func_ctx, array_obj, start, &elem_data_ptr,
            encoding == WTF16 ? PACKED_TYPE_I16 : PACKED_TYPE_I8)) {
        goto fail;
    }

    if (!(count = LLVMBuildSub(comp_ctx->builder, end, start, "calc_count"))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = I32_TYPE;
    ret_type = INT8_PTR_TYPE;

    GET_AOT_FUNCTION(wasm_string_new_with_encoding, 3);

    /* Call function wasm_struct_obj_new() */
    param_values[0] = elem_data_ptr;
    param_values[1] = count;
    param_values[2] = I32_CONST(encoding);

    if (!(str_obj = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                   param_values, 3, "wasm_string_new"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }
    CHECK_STRING_OBJ(str_obj);

    if (!aot_call_wasm_stringref_obj_new(comp_ctx, func_ctx, str_obj,
                                         WASM_TYPE_STRINGREF, 0,
                                         &stringref_obj)) {
        goto fail;
    }
    CHECK_STRINGREF_OBJ(stringref_obj);

    PUSH_GC_REF(stringref_obj);

    return true;
fail:
    return false;
}

bool
aot_compile_op_string_encode_array(AOTCompContext *comp_ctx,
                                   AOTFuncContext *func_ctx, uint32 encoding)
{
    LLVMValueRef param_values[6], func, value, count, start, str_obj,
        stringref_obj, array_obj, elem_data_ptr, array_len;
    LLVMTypeRef param_types[6], ret_type, func_type, func_ptr_type;
    LLVMBasicBlockRef check_string_encode_succ, check_array_index_succ;
    LLVMValueRef cmp;

    POP_I32(start);
    POP_GC_REF(array_obj);
    POP_GC_REF(stringref_obj);

    if (!(str_obj =
              aot_stringref_obj_get_value(comp_ctx, func_ctx, stringref_obj))) {
        goto fail;
    }

    if (!aot_array_obj_length(comp_ctx, array_obj, &array_len))
        goto fail;

    if (!(cmp = LLVMBuildICmp(comp_ctx->builder, LLVMIntUGE, start, array_len,
                              "check_array_index"))) {
        aot_set_last_error("llvm build icmp failed.");
        goto fail;
    }

    ADD_BASIC_BLOCK(check_array_index_succ, "check array index succ");
    MOVE_BLOCK_AFTER_CURR(check_array_index_succ);

    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_ARRAY_IDX_OOB, true, cmp,
                            check_array_index_succ)) {
        goto fail;
    }

    if (!aot_array_obj_elem_addr(
            comp_ctx, func_ctx, stringref_obj, start, &elem_data_ptr,
            encoding == WTF16 ? PACKED_TYPE_I16 : PACKED_TYPE_I8)) {
        goto fail;
    }

    if (!(count = aot_call_wasm_string_measure(comp_ctx, func_ctx,
                                               stringref_obj, encoding))) {
        goto fail;
    }

    param_types[0] = INT8_PTR_TYPE;
    param_types[1] = I32_TYPE;
    param_types[2] = I32_TYPE;
    param_types[3] = INT8_PTR_TYPE;
    param_types[4] = INT8_PTR_TYPE;
    param_types[5] = I32_TYPE;
    ret_type = I32_TYPE;

    GET_AOT_FUNCTION(wasm_string_encode, 6);

    /* Call function wasm_string_measure() */
    param_values[0] = str_obj;
    param_values[1] = start;
    param_values[2] = count;
    param_values[3] = elem_data_ptr;
    param_values[4] = I8_PTR_NULL;
    param_values[5] = I32_CONST(encoding);

    if (!(value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                 param_values, 6, "string_encode"))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    CHECK_STRING_ENCODE(value);

    PUSH_I32(value);

    return true;
fail:
    return false;
}

#endif /* WASM_ENABLE_STRINGREF != 0 */
