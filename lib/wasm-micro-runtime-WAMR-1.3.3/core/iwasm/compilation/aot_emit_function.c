/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_emit_function.h"
#include "aot_emit_exception.h"
#include "aot_emit_control.h"
#include "aot_emit_table.h"
#include "../aot/aot_runtime.h"

#define ADD_BASIC_BLOCK(block, name)                                          \
    do {                                                                      \
        if (!(block = LLVMAppendBasicBlockInContext(comp_ctx->context,        \
                                                    func_ctx->func, name))) { \
            aot_set_last_error("llvm add basic block failed.");               \
            goto fail;                                                        \
        }                                                                     \
    } while (0)

static bool
is_win_platform(AOTCompContext *comp_ctx)
{
    char *triple = LLVMGetTargetMachineTriple(comp_ctx->target_machine);
    bool ret;

    bh_assert(triple);
    ret = (strstr(triple, "win32") || strstr(triple, "win")) ? true : false;

    LLVMDisposeMessage(triple);

    return ret;
}

static bool
create_func_return_block(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMBasicBlockRef block_curr = LLVMGetInsertBlock(comp_ctx->builder);
    AOTFuncType *aot_func_type = func_ctx->aot_func->func_type;

    /* Create function return block if it isn't created */
    if (!func_ctx->func_return_block) {
        if (!(func_ctx->func_return_block = LLVMAppendBasicBlockInContext(
                  comp_ctx->context, func_ctx->func, "func_ret"))) {
            aot_set_last_error("llvm add basic block failed.");
            return false;
        }

        /* Create return IR */
        LLVMPositionBuilderAtEnd(comp_ctx->builder,
                                 func_ctx->func_return_block);
        if (!comp_ctx->enable_bound_check) {
            if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_ALREADY_THROWN,
                                    false, NULL, NULL)) {
                return false;
            }
        }
        else if (!aot_build_zero_function_ret(comp_ctx, func_ctx,
                                              aot_func_type)) {
            return false;
        }
    }

    LLVMPositionBuilderAtEnd(comp_ctx->builder, block_curr);
    return true;
}

/* Check whether there was exception thrown, if yes, return directly */
static bool
check_exception_thrown(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMBasicBlockRef block_curr, check_exce_succ;
    LLVMValueRef value, cmp;

    /* Create function return block if it isn't created */
    if (!create_func_return_block(comp_ctx, func_ctx))
        return false;

    /* Load the first byte of aot_module_inst->cur_exception, and check
       whether it is '\0'. If yes, no exception was thrown. */
    if (!(value = LLVMBuildLoad2(comp_ctx->builder, INT8_TYPE,
                                 func_ctx->cur_exception, "exce_value"))
        || !(cmp = LLVMBuildICmp(comp_ctx->builder, LLVMIntEQ, value, I8_ZERO,
                                 "cmp"))) {
        aot_set_last_error("llvm build icmp failed.");
        return false;
    }

    /* Add check exection success block */
    if (!(check_exce_succ = LLVMAppendBasicBlockInContext(
              comp_ctx->context, func_ctx->func, "check_exce_succ"))) {
        aot_set_last_error("llvm add basic block failed.");
        return false;
    }

    block_curr = LLVMGetInsertBlock(comp_ctx->builder);
    LLVMMoveBasicBlockAfter(check_exce_succ, block_curr);

    LLVMPositionBuilderAtEnd(comp_ctx->builder, block_curr);
    /* Create condition br */
    if (!LLVMBuildCondBr(comp_ctx->builder, cmp, check_exce_succ,
                         func_ctx->func_return_block)) {
        aot_set_last_error("llvm build cond br failed.");
        return false;
    }

    LLVMPositionBuilderAtEnd(comp_ctx->builder, check_exce_succ);
    return true;
}

/* Check whether there was exception thrown, if yes, return directly */
static bool
check_call_return(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                  LLVMValueRef res)
{
    LLVMBasicBlockRef block_curr, check_call_succ;
    LLVMValueRef cmp;

    /* Create function return block if it isn't created */
    if (!create_func_return_block(comp_ctx, func_ctx))
        return false;

    if (!(cmp = LLVMBuildICmp(comp_ctx->builder, LLVMIntNE, res, I8_ZERO,
                              "cmp"))) {
        aot_set_last_error("llvm build icmp failed.");
        return false;
    }

    /* Add check exection success block */
    if (!(check_call_succ = LLVMAppendBasicBlockInContext(
              comp_ctx->context, func_ctx->func, "check_call_succ"))) {
        aot_set_last_error("llvm add basic block failed.");
        return false;
    }

    block_curr = LLVMGetInsertBlock(comp_ctx->builder);
    LLVMMoveBasicBlockAfter(check_call_succ, block_curr);

    LLVMPositionBuilderAtEnd(comp_ctx->builder, block_curr);
    /* Create condition br */
    if (!LLVMBuildCondBr(comp_ctx->builder, cmp, check_call_succ,
                         func_ctx->func_return_block)) {
        aot_set_last_error("llvm build cond br failed.");
        return false;
    }

    LLVMPositionBuilderAtEnd(comp_ctx->builder, check_call_succ);
    return true;
}

static bool
call_aot_invoke_native_func(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            LLVMValueRef func_idx, AOTFuncType *aot_func_type,
                            LLVMTypeRef *param_types,
                            LLVMValueRef *param_values, uint32 param_count,
                            uint32 param_cell_num, LLVMTypeRef ret_type,
                            uint8 wasm_ret_type, LLVMValueRef *p_value_ret,
                            LLVMValueRef *p_res)
{
    LLVMTypeRef func_type, func_ptr_type, func_param_types[4];
    LLVMTypeRef ret_ptr_type, elem_ptr_type;
    LLVMValueRef func, elem_idx, elem_ptr;
    LLVMValueRef func_param_values[4], value_ret = NULL, res;
    char buf[32], *func_name = "aot_invoke_native";
    uint32 i, cell_num = 0;

    /* prepare function type of aot_invoke_native */
    func_param_types[0] = comp_ctx->exec_env_type; /* exec_env */
    func_param_types[1] = I32_TYPE;                /* func_idx */
    func_param_types[2] = I32_TYPE;                /* argc */
    func_param_types[3] = INT32_PTR_TYPE;          /* argv */
    if (!(func_type =
              LLVMFunctionType(INT8_TYPE, func_param_types, 4, false))) {
        aot_set_last_error("llvm add function type failed.");
        return false;
    }

    /* prepare function pointer */
    if (comp_ctx->is_jit_mode) {
        if (!(func_ptr_type = LLVMPointerType(func_type, 0))) {
            aot_set_last_error("create LLVM function type failed.");
            return false;
        }

        /* JIT mode, call the function directly */
        if (!(func = I64_CONST((uint64)(uintptr_t)llvm_jit_invoke_native))
            || !(func = LLVMConstIntToPtr(func, func_ptr_type))) {
            aot_set_last_error("create LLVM value failed.");
            return false;
        }
    }
    else if (comp_ctx->is_indirect_mode) {
        int32 func_index;
        if (!(func_ptr_type = LLVMPointerType(func_type, 0))) {
            aot_set_last_error("create LLVM function type failed.");
            return false;
        }
        func_index = aot_get_native_symbol_index(comp_ctx, func_name);
        if (func_index < 0) {
            return false;
        }
        if (!(func = aot_get_func_from_table(comp_ctx, func_ctx->native_symbol,
                                             func_ptr_type, func_index))) {
            return false;
        }
    }
    else {
        if (!(func = LLVMGetNamedFunction(func_ctx->module, func_name))
            && !(func =
                     LLVMAddFunction(func_ctx->module, func_name, func_type))) {
            aot_set_last_error("add LLVM function failed.");
            return false;
        }
    }

    if (param_cell_num > 64) {
        aot_set_last_error("prepare native arguments failed: "
                           "maximum 64 parameter cell number supported.");
        return false;
    }

    /* prepare frame_lp */
    for (i = 0; i < param_count; i++) {
        if (!(elem_idx = I32_CONST(cell_num))
            || !(elem_ptr_type = LLVMPointerType(param_types[i], 0))) {
            aot_set_last_error("llvm add const or pointer type failed.");
            return false;
        }

        snprintf(buf, sizeof(buf), "%s%d", "elem", i);
        if (!(elem_ptr =
                  LLVMBuildInBoundsGEP2(comp_ctx->builder, I32_TYPE,
                                        func_ctx->argv_buf, &elem_idx, 1, buf))
            || !(elem_ptr = LLVMBuildBitCast(comp_ctx->builder, elem_ptr,
                                             elem_ptr_type, buf))) {
            aot_set_last_error("llvm build bit cast failed.");
            return false;
        }

        if (!(res = LLVMBuildStore(comp_ctx->builder, param_values[i],
                                   elem_ptr))) {
            aot_set_last_error("llvm build store failed.");
            return false;
        }
        LLVMSetAlignment(res, 1);

        cell_num += wasm_value_type_cell_num(aot_func_type->types[i]);
    }

    func_param_values[0] = func_ctx->exec_env;
    func_param_values[1] = func_idx;
    func_param_values[2] = I32_CONST(param_cell_num);
    func_param_values[3] = func_ctx->argv_buf;

    if (!func_param_values[2]) {
        aot_set_last_error("llvm create const failed.");
        return false;
    }

    /* call aot_invoke_native() function */
    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                               func_param_values, 4, "res"))) {
        aot_set_last_error("llvm build call failed.");
        return false;
    }

    /* get function return value */
    if (wasm_ret_type != VALUE_TYPE_VOID) {
        if (!(ret_ptr_type = LLVMPointerType(ret_type, 0))) {
            aot_set_last_error("llvm add pointer type failed.");
            return false;
        }

        if (!(value_ret =
                  LLVMBuildBitCast(comp_ctx->builder, func_ctx->argv_buf,
                                   ret_ptr_type, "argv_ret"))) {
            aot_set_last_error("llvm build bit cast failed.");
            return false;
        }
        if (!(*p_value_ret = LLVMBuildLoad2(comp_ctx->builder, ret_type,
                                            value_ret, "value_ret"))) {
            aot_set_last_error("llvm build load failed.");
            return false;
        }
    }

    *p_res = res;
    return true;
}

static bool
call_aot_invoke_c_api_native(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             uint32 import_func_idx, AOTFuncType *aot_func_type,
                             LLVMValueRef *params)
{
    LLVMTypeRef int8_ptr_type, param_types[6], ret_type;
    LLVMTypeRef value_ptr_type = NULL, value_type = NULL;
    LLVMTypeRef func_type, func_ptr_type;
    LLVMValueRef param_values[6], res, func, value = NULL, offset;
    LLVMValueRef c_api_func_imports, c_api_func_import;
    LLVMValueRef c_api_params, c_api_results, value_ret;
    LLVMValueRef c_api_param_kind, c_api_param_value;
    LLVMValueRef c_api_result_value;
    uint32 offset_c_api_func_imports, i;
    uint32 offset_param_kind, offset_param_value;
    char buf[16];

    /* `int8 **` type */
    int8_ptr_type = LLVMPointerType(INT8_PTR_TYPE, 0);
    if (!int8_ptr_type) {
        aot_set_last_error("create llvm pointer type failed");
        return false;
    }

    param_types[0] = INT8_PTR_TYPE; /* module_inst */
    param_types[1] = INT8_PTR_TYPE; /* CApiFuncImport *c_api_import */
    param_types[2] = INT8_PTR_TYPE; /* wasm_val_t *params */
    param_types[3] = I32_TYPE;      /* uint32 param_count */
    param_types[4] = INT8_PTR_TYPE; /* wasm_val_t *results */
    param_types[5] = I32_TYPE;      /* uint32 result_count */

    ret_type = INT8_TYPE;

    GET_AOT_FUNCTION(wasm_runtime_quick_invoke_c_api_native, 6);

    param_values[0] = func_ctx->aot_inst;

    /* Get module_inst->e->common.c_api_func_imports */
    offset_c_api_func_imports =
        get_module_inst_extra_offset(comp_ctx)
        + (comp_ctx->is_jit_mode
               ? offsetof(WASMModuleInstanceExtra, common.c_api_func_imports)
               /* offsetof(AOTModuleInstanceExtra, common.c_api_func_imports) */
               : sizeof(uint64));
    offset = I32_CONST(offset_c_api_func_imports);
    CHECK_LLVM_CONST(offset);
    c_api_func_imports =
        LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst,
                              &offset, 1, "c_api_func_imports_addr");
    c_api_func_imports =
        LLVMBuildBitCast(comp_ctx->builder, c_api_func_imports, int8_ptr_type,
                         "c_api_func_imports_ptr");
    c_api_func_imports =
        LLVMBuildLoad2(comp_ctx->builder, INT8_PTR_TYPE, c_api_func_imports,
                       "c_api_func_imports");

    /* Get &c_api_func_imports[func_idx], note size of CApiFuncImport
       is pointer_size * 3 */
    offset = I32_CONST((comp_ctx->pointer_size * 3) * import_func_idx);
    CHECK_LLVM_CONST(offset);
    c_api_func_import =
        LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, c_api_func_imports,
                              &offset, 1, "c_api_func_import");

    param_values[1] = c_api_func_import;
    param_values[2] = c_api_params = func_ctx->argv_buf;
    param_values[3] = I32_CONST(aot_func_type->param_count);
    CHECK_LLVM_CONST(param_values[3]);

    /* Ensure sizeof(wasm_val_t) is 16 bytes */
    offset = I32_CONST(sizeof(wasm_val_t) * aot_func_type->param_count);
    c_api_results =
        LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, func_ctx->argv_buf,
                              &offset, 1, "results");
    param_values[4] = c_api_results;

    param_values[5] = I32_CONST(aot_func_type->result_count);
    CHECK_LLVM_CONST(param_values[5]);

    /* Set each c api param */
    for (i = 0; i < aot_func_type->param_count; i++) {
        /* Ensure sizeof(wasm_val_t) is 16 bytes */
        offset_param_kind = sizeof(wasm_val_t) * i;
        offset = I32_CONST(offset_param_kind);
        CHECK_LLVM_CONST(offset);
        c_api_param_kind =
            LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, c_api_params,
                                  &offset, 1, "c_api_param_kind_addr");
        c_api_param_kind =
            LLVMBuildBitCast(comp_ctx->builder, c_api_param_kind, INT8_PTR_TYPE,
                             "c_api_param_kind_ptr");

        switch (aot_func_type->types[i]) {
            case VALUE_TYPE_I32:
                value = I8_CONST(WASM_I32);
                break;
            case VALUE_TYPE_F32:
                value = I8_CONST(WASM_F32);
                break;
            case VALUE_TYPE_I64:
                value = I8_CONST(WASM_I64);
                break;
            case VALUE_TYPE_F64:
                value = I8_CONST(WASM_F64);
                break;
            default:
                bh_assert(0);
                break;
        }
        CHECK_LLVM_CONST(value);

        LLVMBuildStore(comp_ctx->builder, value, c_api_param_kind);

        /* Ensure offsetof(wasm_val_t, of) is 8 bytes */
        offset_param_value = offset_param_kind + offsetof(wasm_val_t, of);
        offset = I32_CONST(offset_param_value);
        CHECK_LLVM_CONST(offset);
        c_api_param_value =
            LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, c_api_params,
                                  &offset, 1, "c_api_param_value_addr");

        switch (aot_func_type->types[i]) {
            case VALUE_TYPE_I32:
                value_ptr_type = INT32_PTR_TYPE;
                break;
            case VALUE_TYPE_F32:
                value_ptr_type = F32_PTR_TYPE;
                break;
            case VALUE_TYPE_I64:
                value_ptr_type = INT64_PTR_TYPE;
                break;
            case VALUE_TYPE_F64:
                value_ptr_type = F64_PTR_TYPE;
                break;
            default:
                bh_assert(0);
                break;
        }

        c_api_param_value =
            LLVMBuildBitCast(comp_ctx->builder, c_api_param_value,
                             value_ptr_type, "c_api_param_value_ptr");
        LLVMBuildStore(comp_ctx->builder, params[i], c_api_param_value);
    }

    /* Call the function */
    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               6, "call"))) {
        aot_set_last_error("LLVM build call failed.");
        goto fail;
    }

    /* Check whether exception was thrown when executing the function */
    if (comp_ctx->enable_bound_check
        && !check_call_return(comp_ctx, func_ctx, res)) {
        goto fail;
    }

    for (i = 0; i < aot_func_type->result_count; i++) {
        /* Ensure sizeof(wasm_val_t) is 16 bytes and
           offsetof(wasm_val_t, of) is 8 bytes */
        uint32 offset_result_value =
            sizeof(wasm_val_t) * i + offsetof(wasm_val_t, of);

        offset = I32_CONST(offset_result_value);
        CHECK_LLVM_CONST(offset);
        c_api_result_value =
            LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, c_api_results,
                                  &offset, 1, "c_api_result_value_addr");

        switch (aot_func_type->types[aot_func_type->param_count + i]) {
            case VALUE_TYPE_I32:
                value_type = I32_TYPE;
                value_ptr_type = INT32_PTR_TYPE;
                break;
            case VALUE_TYPE_F32:
                value_type = F32_TYPE;
                value_ptr_type = F32_PTR_TYPE;
                break;
            case VALUE_TYPE_I64:
                value_type = I64_TYPE;
                value_ptr_type = INT64_PTR_TYPE;
                break;
            case VALUE_TYPE_F64:
                value_type = F64_TYPE;
                value_ptr_type = F64_PTR_TYPE;
                break;
            default:
                bh_assert(0);
                break;
        }

        c_api_result_value =
            LLVMBuildBitCast(comp_ctx->builder, c_api_result_value,
                             value_ptr_type, "c_api_result_value_ptr");
        snprintf(buf, sizeof(buf), "%s%u", "ret", i);
        value_ret = LLVMBuildLoad2(comp_ctx->builder, value_type,
                                   c_api_result_value, buf);

        PUSH(value_ret, aot_func_type->types[aot_func_type->param_count + i]);
    }

    return true;
fail:
    return false;
}

#if (WASM_ENABLE_DUMP_CALL_STACK != 0) || (WASM_ENABLE_PERF_PROFILING != 0)
static bool
call_aot_alloc_frame_func(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          LLVMValueRef func_idx)
{
    LLVMValueRef param_values[2], ret_value, value, func;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;
    LLVMBasicBlockRef block_curr = LLVMGetInsertBlock(comp_ctx->builder);
    LLVMBasicBlockRef frame_alloc_fail, frame_alloc_success;
    AOTFuncType *aot_func_type = func_ctx->aot_func->func_type;

    param_types[0] = comp_ctx->exec_env_type;
    param_types[1] = I32_TYPE;
    ret_type = INT8_TYPE;

    if (comp_ctx->is_jit_mode)
        GET_AOT_FUNCTION(llvm_jit_alloc_frame, 2);
    else
        GET_AOT_FUNCTION(aot_alloc_frame, 2);

    param_values[0] = func_ctx->exec_env;
    param_values[1] = func_idx;

    if (!(ret_value =
              LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                             2, "call_aot_alloc_frame"))) {
        aot_set_last_error("llvm build call failed.");
        return false;
    }

    if (!(ret_value = LLVMBuildICmp(comp_ctx->builder, LLVMIntUGT, ret_value,
                                    I8_ZERO, "frame_alloc_ret"))) {
        aot_set_last_error("llvm build icmp failed.");
        return false;
    }

    ADD_BASIC_BLOCK(frame_alloc_fail, "frame_alloc_fail");
    ADD_BASIC_BLOCK(frame_alloc_success, "frame_alloc_success");

    LLVMMoveBasicBlockAfter(frame_alloc_fail, block_curr);
    LLVMMoveBasicBlockAfter(frame_alloc_success, block_curr);

    if (!LLVMBuildCondBr(comp_ctx->builder, ret_value, frame_alloc_success,
                         frame_alloc_fail)) {
        aot_set_last_error("llvm build cond br failed.");
        return false;
    }

    /* If frame alloc failed, return this function
        so the runtime can catch the exception */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, frame_alloc_fail);
    if (!aot_build_zero_function_ret(comp_ctx, func_ctx, aot_func_type)) {
        return false;
    }

    LLVMPositionBuilderAtEnd(comp_ctx->builder, frame_alloc_success);

    return true;

fail:
    return false;
}

static bool
call_aot_free_frame_func(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef param_values[1], ret_value, value, func;
    LLVMTypeRef param_types[1], ret_type, func_type, func_ptr_type;

    param_types[0] = comp_ctx->exec_env_type;
    ret_type = INT8_TYPE;

    if (comp_ctx->is_jit_mode)
        GET_AOT_FUNCTION(llvm_jit_free_frame, 1);
    else
        GET_AOT_FUNCTION(aot_free_frame, 1);

    param_values[0] = func_ctx->exec_env;

    if (!(ret_value = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                                     param_values, 1, "call_aot_free_frame"))) {
        aot_set_last_error("llvm build call failed.");
        return false;
    }

    return true;
fail:
    return false;
}
#endif /* end of (WASM_ENABLE_DUMP_CALL_STACK != 0) \
                 || (WASM_ENABLE_PERF_PROFILING != 0) */

/**
 * Check whether the app address and its buffer are inside the linear memory,
 * if no, throw exception
 */
static bool
check_app_addr_and_convert(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           bool is_str_arg, LLVMValueRef app_addr,
                           LLVMValueRef buf_size,
                           LLVMValueRef *p_native_addr_converted)
{
    LLVMTypeRef func_type, func_ptr_type, func_param_types[5];
    LLVMValueRef func, func_param_values[5], res, native_addr_ptr;
    char *func_name = "aot_check_app_addr_and_convert";

    /* prepare function type of aot_check_app_addr_and_convert */
    func_param_types[0] = comp_ctx->aot_inst_type; /* module_inst */
    func_param_types[1] = INT8_TYPE;               /* is_str_arg */
    func_param_types[2] = I32_TYPE;                /* app_offset */
    func_param_types[3] = I32_TYPE;                /* buf_size */
    func_param_types[4] =
        comp_ctx->basic_types.int8_pptr_type; /* p_native_addr */
    if (!(func_type =
              LLVMFunctionType(INT8_TYPE, func_param_types, 5, false))) {
        aot_set_last_error("llvm add function type failed.");
        return false;
    }

    /* prepare function pointer */
    if (comp_ctx->is_jit_mode) {
        if (!(func_ptr_type = LLVMPointerType(func_type, 0))) {
            aot_set_last_error("create LLVM function type failed.");
            return false;
        }

        /* JIT mode, call the function directly */
        if (!(func =
                  I64_CONST((uint64)(uintptr_t)jit_check_app_addr_and_convert))
            || !(func = LLVMConstIntToPtr(func, func_ptr_type))) {
            aot_set_last_error("create LLVM value failed.");
            return false;
        }
    }
    else if (comp_ctx->is_indirect_mode) {
        int32 func_index;
        if (!(func_ptr_type = LLVMPointerType(func_type, 0))) {
            aot_set_last_error("create LLVM function type failed.");
            return false;
        }
        func_index = aot_get_native_symbol_index(comp_ctx, func_name);
        if (func_index < 0) {
            return false;
        }
        if (!(func = aot_get_func_from_table(comp_ctx, func_ctx->native_symbol,
                                             func_ptr_type, func_index))) {
            return false;
        }
    }
    else {
        if (!(func = LLVMGetNamedFunction(func_ctx->module, func_name))
            && !(func =
                     LLVMAddFunction(func_ctx->module, func_name, func_type))) {
            aot_set_last_error("add LLVM function failed.");
            return false;
        }
    }

    if (!(native_addr_ptr = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->argv_buf,
              comp_ctx->basic_types.int8_pptr_type, "p_native_addr"))) {
        aot_set_last_error("llvm build bit cast failed.");
        return false;
    }

    func_param_values[0] = func_ctx->aot_inst;
    func_param_values[1] = I8_CONST(is_str_arg);
    func_param_values[2] = app_addr;
    func_param_values[3] = buf_size;
    func_param_values[4] = native_addr_ptr;

    if (!func_param_values[1]) {
        aot_set_last_error("llvm create const failed.");
        return false;
    }

    /* call aot_check_app_addr_and_convert() function */
    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                               func_param_values, 5, "res"))) {
        aot_set_last_error("llvm build call failed.");
        return false;
    }

    /* Check whether exception was thrown when executing the function */
    if ((comp_ctx->enable_bound_check || is_win_platform(comp_ctx))
        && !check_call_return(comp_ctx, func_ctx, res)) {
        return false;
    }

    if (!(*p_native_addr_converted =
              LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE, native_addr_ptr,
                             "native_addr"))) {
        aot_set_last_error("llvm build load failed.");
        return false;
    }

    return true;
}

static void
aot_estimate_and_record_stack_usage_for_function_call(
    const AOTCompContext *comp_ctx, AOTFuncContext *caller_func_ctx,
    const AOTFuncType *callee_func_type)
{
    unsigned int size;

    if (!(comp_ctx->enable_stack_bound_check
          || comp_ctx->enable_stack_estimation)) {
        return;
    }

    size =
        aot_estimate_stack_usage_for_function_call(comp_ctx, callee_func_type);
    /*
     * only record the max value, assuming that LLVM emits machine code
     * which rewinds the stack before making the next call in the
     * function.
     */
    if (caller_func_ctx->stack_consumption_for_func_call < size) {
        caller_func_ctx->stack_consumption_for_func_call = size;
    }
}

bool
aot_compile_op_call(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                    uint32 func_idx, bool tail_call)
{
    uint32 import_func_count = comp_ctx->comp_data->import_func_count;
    AOTImportFunc *import_funcs = comp_ctx->comp_data->import_funcs;
    uint32 func_count = comp_ctx->func_ctx_count, param_cell_num = 0;
    uint32 ext_ret_cell_num = 0, cell_num = 0;
    AOTFuncContext **func_ctxes = comp_ctx->func_ctxes;
    AOTFuncType *func_type;
    LLVMTypeRef *param_types = NULL, ret_type;
    LLVMTypeRef ext_ret_ptr_type;
    LLVMValueRef *param_values = NULL, value_ret = NULL, func;
    LLVMValueRef import_func_idx, res;
    LLVMValueRef ext_ret, ext_ret_ptr, ext_ret_idx;
    int32 i, j = 0, param_count, result_count, ext_ret_count;
    uint64 total_size;
    uint8 wasm_ret_type;
    uint8 *ext_ret_types = NULL;
    const char *signature = NULL;
    bool ret = false;
    char buf[32];
    bool quick_invoke_c_api_import = false;

#if WASM_ENABLE_THREAD_MGR != 0
    /* Insert suspend check point */
    if (comp_ctx->enable_thread_mgr) {
        if (!check_suspend_flags(comp_ctx, func_ctx))
            return false;
    }
#endif

    /* Check function index */
    if (func_idx >= import_func_count + func_count) {
        aot_set_last_error("Function index out of range.");
        return false;
    }

    /* Get function type */
    if (func_idx < import_func_count) {
        func_type = import_funcs[func_idx].func_type;
        signature = import_funcs[func_idx].signature;
    }
    else {
        func_type =
            func_ctxes[func_idx - import_func_count]->aot_func->func_type;
    }
    aot_estimate_and_record_stack_usage_for_function_call(comp_ctx, func_ctx,
                                                          func_type);

    /* Get param cell number */
    param_cell_num = func_type->param_cell_num;

#if (WASM_ENABLE_DUMP_CALL_STACK != 0) || (WASM_ENABLE_PERF_PROFILING != 0)
    if (comp_ctx->enable_aux_stack_frame) {
        LLVMValueRef func_idx_const;

        if (!(func_idx_const = I32_CONST(func_idx))) {
            aot_set_last_error("llvm build const failed.");
            return false;
        }
        if (!call_aot_alloc_frame_func(comp_ctx, func_ctx, func_idx_const))
            return false;
    }
#endif

    /* Allocate memory for parameters.
     * Parameters layout:
     *   - exec env
     *   - wasm function's parameters
     *   - extra results'(except the first one) addresses
     */
    param_count = (int32)func_type->param_count;
    result_count = (int32)func_type->result_count;
    ext_ret_count = result_count > 1 ? result_count - 1 : 0;
    total_size =
        sizeof(LLVMValueRef) * (uint64)(param_count + 1 + ext_ret_count);
    if (total_size >= UINT32_MAX
        || !(param_values = wasm_runtime_malloc((uint32)total_size))) {
        aot_set_last_error("allocate memory failed.");
        return false;
    }

    /* First parameter is exec env */
    param_values[j++] = func_ctx->exec_env;

    /* Pop parameters from stack */
    for (i = param_count - 1; i >= 0; i--)
        POP(param_values[i + j], func_type->types[i]);

    /* Set parameters for multiple return values, the first return value
       is returned by function return value, and the other return values
       are returned by function parameters with pointer types */
    if (ext_ret_count > 0) {
        ext_ret_types = func_type->types + param_count + 1;
        ext_ret_cell_num = wasm_get_cell_num(ext_ret_types, ext_ret_count);
        if (ext_ret_cell_num > 64) {
            aot_set_last_error("prepare extra results's return "
                               "address arguments failed: "
                               "maximum 64 parameter cell number supported.");
            goto fail;
        }

        for (i = 0; i < ext_ret_count; i++) {
            if (!(ext_ret_idx = I32_CONST(cell_num))
                || !(ext_ret_ptr_type =
                         LLVMPointerType(TO_LLVM_TYPE(ext_ret_types[i]), 0))) {
                aot_set_last_error("llvm add const or pointer type failed.");
                goto fail;
            }

            snprintf(buf, sizeof(buf), "ext_ret%d_ptr", i);
            if (!(ext_ret_ptr = LLVMBuildInBoundsGEP2(
                      comp_ctx->builder, I32_TYPE, func_ctx->argv_buf,
                      &ext_ret_idx, 1, buf))) {
                aot_set_last_error("llvm build GEP failed.");
                goto fail;
            }
            snprintf(buf, sizeof(buf), "ext_ret%d_ptr_cast", i);
            if (!(ext_ret_ptr = LLVMBuildBitCast(comp_ctx->builder, ext_ret_ptr,
                                                 ext_ret_ptr_type, buf))) {
                aot_set_last_error("llvm build bit cast failed.");
                goto fail;
            }
            param_values[param_count + 1 + i] = ext_ret_ptr;
            cell_num += wasm_value_type_cell_num(ext_ret_types[i]);
        }
    }

    if (func_idx < import_func_count) {
        if (!(import_func_idx = I32_CONST(func_idx))) {
            aot_set_last_error("llvm build inbounds gep failed.");
            goto fail;
        }

        /* Initialize parameter types of the LLVM function */
        total_size = sizeof(LLVMTypeRef) * (uint64)(param_count + 1);
        if (total_size >= UINT32_MAX
            || !(param_types = wasm_runtime_malloc((uint32)total_size))) {
            aot_set_last_error("allocate memory failed.");
            goto fail;
        }

        j = 0;
        param_types[j++] = comp_ctx->exec_env_type;

        for (i = 0; i < param_count; i++, j++) {
            param_types[j] = TO_LLVM_TYPE(func_type->types[i]);

            /* If the signature can be gotten, e.g. the signature of the builtin
               native libraries, just check the app offset and buf size, and
               then convert app offset to native addr and call the native func
               directly, no need to call aot_invoke_native to call it */
            if (signature) {
                LLVMValueRef native_addr, native_addr_size;
                if (signature[i + 1] == '*' || signature[i + 1] == '$') {
                    param_types[j] = INT8_PTR_TYPE;
                }
                if (signature[i + 1] == '*') {
                    if (signature[i + 2] == '~')
                        native_addr_size = param_values[i + 2];
                    else
                        native_addr_size = I32_ONE;
                    if (!check_app_addr_and_convert(
                            comp_ctx, func_ctx, false, param_values[j],
                            native_addr_size, &native_addr)) {
                        goto fail;
                    }
                    param_values[j] = native_addr;
                }
                else if (signature[i + 1] == '$') {
                    native_addr_size = I32_ZERO;
                    if (!check_app_addr_and_convert(
                            comp_ctx, func_ctx, true, param_values[j],
                            native_addr_size, &native_addr)) {
                        goto fail;
                    }
                    param_values[j] = native_addr;
                }
            }
        }

        if (func_type->result_count) {
            wasm_ret_type = func_type->types[func_type->param_count];
            ret_type = TO_LLVM_TYPE(wasm_ret_type);
        }
        else {
            wasm_ret_type = VALUE_TYPE_VOID;
            ret_type = VOID_TYPE;
        }

        if (!signature) {
            if (comp_ctx->quick_invoke_c_api_import) {
                uint32 buf_size_needed =
                    sizeof(wasm_val_t) * (param_count + result_count);

                /* length of exec_env->argv_buf is 64 */
                if (buf_size_needed < sizeof(uint32) * 64) {
                    for (i = 0; i < param_count + result_count; i++) {
                        /* Only support i32/i64/f32/f64 now */
                        if (!(func_type->types[i] == VALUE_TYPE_I32
                              || func_type->types[i] == VALUE_TYPE_I64
                              || func_type->types[i] == VALUE_TYPE_F32
                              || func_type->types[i] == VALUE_TYPE_F64))
                            break;
                    }
                    if (i == param_count + result_count)
                        quick_invoke_c_api_import = true;
                }
            }
            if (quick_invoke_c_api_import) {
                if (!call_aot_invoke_c_api_native(comp_ctx, func_ctx, func_idx,
                                                  func_type, param_values + 1))
                    goto fail;
            }
            else {
                /* call aot_invoke_native() */
                if (!call_aot_invoke_native_func(
                        comp_ctx, func_ctx, import_func_idx, func_type,
                        param_types + 1, param_values + 1, param_count,
                        param_cell_num, ret_type, wasm_ret_type, &value_ret,
                        &res))
                    goto fail;
                /* Check whether there was exception thrown when executing
                   the function */
                if ((comp_ctx->enable_bound_check || is_win_platform(comp_ctx))
                    && !check_call_return(comp_ctx, func_ctx, res))
                    goto fail;
            }
        }
        else { /* call native func directly */
            LLVMTypeRef native_func_type, func_ptr_type;
            LLVMValueRef func_ptr;

            if (!(native_func_type = LLVMFunctionType(
                      ret_type, param_types, param_count + 1, false))) {
                aot_set_last_error("llvm add function type failed.");
                goto fail;
            }

            if (!(func_ptr_type = LLVMPointerType(native_func_type, 0))) {
                aot_set_last_error("create LLVM function type failed.");
                goto fail;
            }

            /* Load function pointer */
            if (!(func_ptr = LLVMBuildInBoundsGEP2(
                      comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->func_ptrs,
                      &import_func_idx, 1, "native_func_ptr_tmp"))) {
                aot_set_last_error("llvm build inbounds gep failed.");
                goto fail;
            }

            if (!(func_ptr = LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                                            func_ptr, "native_func_ptr"))) {
                aot_set_last_error("llvm build load failed.");
                goto fail;
            }

            if (!(func = LLVMBuildBitCast(comp_ctx->builder, func_ptr,
                                          func_ptr_type, "native_func"))) {
                aot_set_last_error("llvm bit cast failed.");
                goto fail;
            }

            /* Call the function */
            if (!(value_ret = LLVMBuildCall2(
                      comp_ctx->builder, native_func_type, func, param_values,
                      (uint32)param_count + 1 + ext_ret_count,
                      (func_type->result_count > 0 ? "call" : "")))) {
                aot_set_last_error("LLVM build call failed.");
                goto fail;
            }

            /* Check whether there was exception thrown when executing
               the function */
            if (!check_exception_thrown(comp_ctx, func_ctx)) {
                goto fail;
            }
        }
    }
    else {
#if LLVM_VERSION_MAJOR >= 14
        LLVMTypeRef llvm_func_type;
#endif
        if (comp_ctx->is_indirect_mode) {
            LLVMTypeRef func_ptr_type;

            if (!(func_ptr_type = LLVMPointerType(
                      func_ctxes[func_idx - import_func_count]->func_type,
                      0))) {
                aot_set_last_error("construct func ptr type failed.");
                goto fail;
            }
            if (!(func = aot_get_func_from_table(comp_ctx, func_ctx->func_ptrs,
                                                 func_ptr_type, func_idx))) {
                goto fail;
            }
        }
        else {
            if (func_ctxes[func_idx - import_func_count] == func_ctx) {
                /* recursive call */
                func = func_ctx->precheck_func;
            }
            else {
                if (!comp_ctx->is_jit_mode) {
                    func =
                        func_ctxes[func_idx - import_func_count]->precheck_func;
                }
                else {
#if !(WASM_ENABLE_FAST_JIT != 0 && WASM_ENABLE_LAZY_JIT != 0)
                    func =
                        func_ctxes[func_idx - import_func_count]->precheck_func;
#else
                    /* JIT tier-up, load func ptr from func_ptrs[func_idx] */
                    LLVMValueRef func_ptr, func_idx_const;
                    LLVMTypeRef func_ptr_type;

                    if (!(func_idx_const = I32_CONST(func_idx))) {
                        aot_set_last_error("llvm build const failed.");
                        goto fail;
                    }

                    if (!(func_ptr = LLVMBuildInBoundsGEP2(
                              comp_ctx->builder, OPQ_PTR_TYPE,
                              func_ctx->func_ptrs, &func_idx_const, 1,
                              "func_ptr_tmp"))) {
                        aot_set_last_error("llvm build inbounds gep failed.");
                        goto fail;
                    }

                    if (!(func_ptr =
                              LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                                             func_ptr, "func_ptr"))) {
                        aot_set_last_error("llvm build load failed.");
                        goto fail;
                    }

                    if (!(func_ptr_type = LLVMPointerType(
                              func_ctxes[func_idx - import_func_count]
                                  ->func_type,
                              0))) {
                        aot_set_last_error("construct func ptr type failed.");
                        goto fail;
                    }

                    if (!(func = LLVMBuildBitCast(comp_ctx->builder, func_ptr,
                                                  func_ptr_type,
                                                  "indirect_func"))) {
                        aot_set_last_error("llvm build bit cast failed.");
                        goto fail;
                    }
#endif /* end of !(WASM_ENABLE_FAST_JIT != 0 && WASM_ENABLE_LAZY_JIT != 0) */
                }
            }
        }

#if LLVM_VERSION_MAJOR >= 14
        llvm_func_type = func_ctxes[func_idx - import_func_count]->func_type;
#endif

        /* Call the function */
        if (!(value_ret = LLVMBuildCall2(
                  comp_ctx->builder, llvm_func_type, func, param_values,
                  (uint32)param_count + 1 + ext_ret_count,
                  (func_type->result_count > 0 ? "call" : "")))) {
            aot_set_last_error("LLVM build call failed.");
            goto fail;
        }

        if (tail_call)
            LLVMSetTailCall(value_ret, true);

        /* Check whether there was exception thrown when executing
           the function */
        if (!tail_call
            && (comp_ctx->enable_bound_check || is_win_platform(comp_ctx))
            && !check_exception_thrown(comp_ctx, func_ctx))
            goto fail;
    }

    if (func_type->result_count > 0 && !quick_invoke_c_api_import) {
        /* Push the first result to stack */
        PUSH(value_ret, func_type->types[func_type->param_count]);
        /* Load extra result from its address and push to stack */
        for (i = 0; i < ext_ret_count; i++) {
            snprintf(buf, sizeof(buf), "func%d_ext_ret%d", func_idx, i);
            if (!(ext_ret = LLVMBuildLoad2(
                      comp_ctx->builder, TO_LLVM_TYPE(ext_ret_types[i]),
                      param_values[1 + param_count + i], buf))) {
                aot_set_last_error("llvm build load failed.");
                goto fail;
            }
            PUSH(ext_ret, ext_ret_types[i]);
        }
    }

#if (WASM_ENABLE_DUMP_CALL_STACK != 0) || (WASM_ENABLE_PERF_PROFILING != 0)
    if (comp_ctx->enable_aux_stack_frame) {
        if (!call_aot_free_frame_func(comp_ctx, func_ctx))
            goto fail;
    }
#endif

#if WASM_ENABLE_THREAD_MGR != 0
    /* Insert suspend check point */
    if (comp_ctx->enable_thread_mgr) {
        if (!check_suspend_flags(comp_ctx, func_ctx))
            goto fail;
    }
#endif

    ret = true;
fail:
    if (param_types)
        wasm_runtime_free(param_types);
    if (param_values)
        wasm_runtime_free(param_values);
    return ret;
}

static bool
call_aot_call_indirect_func(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            AOTFuncType *aot_func_type,
                            LLVMValueRef func_type_idx, LLVMValueRef table_idx,
                            LLVMValueRef table_elem_idx,
                            LLVMTypeRef *param_types,
                            LLVMValueRef *param_values, uint32 param_count,
                            uint32 param_cell_num, uint32 result_count,
                            uint8 *wasm_ret_types, LLVMValueRef *value_rets,
                            LLVMValueRef *p_res)
{
    LLVMTypeRef func_type, func_ptr_type, func_param_types[6];
    LLVMTypeRef ret_type, ret_ptr_type, elem_ptr_type;
    LLVMValueRef func, ret_idx, ret_ptr, elem_idx, elem_ptr;
    LLVMValueRef func_param_values[6], res = NULL;
    char buf[32], *func_name = "aot_call_indirect";
    uint32 i, cell_num = 0, ret_cell_num, argv_cell_num;

    /* prepare function type of aot_call_indirect */
    func_param_types[0] = comp_ctx->exec_env_type; /* exec_env */
    func_param_types[1] = I32_TYPE;                /* table_idx */
    func_param_types[2] = I32_TYPE;                /* table_elem_idx */
    func_param_types[3] = I32_TYPE;                /* argc */
    func_param_types[4] = INT32_PTR_TYPE;          /* argv */
    if (!(func_type =
              LLVMFunctionType(INT8_TYPE, func_param_types, 5, false))) {
        aot_set_last_error("llvm add function type failed.");
        return false;
    }

    /* prepare function pointer */
    if (comp_ctx->is_jit_mode) {
        if (!(func_ptr_type = LLVMPointerType(func_type, 0))) {
            aot_set_last_error("create LLVM function type failed.");
            return false;
        }

        /* JIT mode, call the function directly */
        if (!(func = I64_CONST((uint64)(uintptr_t)llvm_jit_call_indirect))
            || !(func = LLVMConstIntToPtr(func, func_ptr_type))) {
            aot_set_last_error("create LLVM value failed.");
            return false;
        }
    }
    else if (comp_ctx->is_indirect_mode) {
        int32 func_index;
        if (!(func_ptr_type = LLVMPointerType(func_type, 0))) {
            aot_set_last_error("create LLVM function type failed.");
            return false;
        }
        func_index = aot_get_native_symbol_index(comp_ctx, func_name);
        if (func_index < 0) {
            return false;
        }
        if (!(func = aot_get_func_from_table(comp_ctx, func_ctx->native_symbol,
                                             func_ptr_type, func_index))) {
            return false;
        }
    }
    else {
        if (!(func = LLVMGetNamedFunction(func_ctx->module, func_name))
            && !(func =
                     LLVMAddFunction(func_ctx->module, func_name, func_type))) {
            aot_set_last_error("add LLVM function failed.");
            return false;
        }
    }

    ret_cell_num = wasm_get_cell_num(wasm_ret_types, result_count);
    argv_cell_num =
        param_cell_num > ret_cell_num ? param_cell_num : ret_cell_num;
    if (argv_cell_num > 64) {
        aot_set_last_error("prepare native arguments failed: "
                           "maximum 64 parameter cell number supported.");
        return false;
    }

    /* prepare frame_lp */
    for (i = 0; i < param_count; i++) {
        if (!(elem_idx = I32_CONST(cell_num))
            || !(elem_ptr_type = LLVMPointerType(param_types[i], 0))) {
            aot_set_last_error("llvm add const or pointer type failed.");
            return false;
        }

        snprintf(buf, sizeof(buf), "%s%d", "elem", i);
        if (!(elem_ptr =
                  LLVMBuildInBoundsGEP2(comp_ctx->builder, I32_TYPE,
                                        func_ctx->argv_buf, &elem_idx, 1, buf))
            || !(elem_ptr = LLVMBuildBitCast(comp_ctx->builder, elem_ptr,
                                             elem_ptr_type, buf))) {
            aot_set_last_error("llvm build bit cast failed.");
            return false;
        }

        if (!(res = LLVMBuildStore(comp_ctx->builder, param_values[i],
                                   elem_ptr))) {
            aot_set_last_error("llvm build store failed.");
            return false;
        }
        LLVMSetAlignment(res, 1);

        cell_num += wasm_value_type_cell_num(aot_func_type->types[i]);
    }

    func_param_values[0] = func_ctx->exec_env;
    func_param_values[1] = table_idx;
    func_param_values[2] = table_elem_idx;
    func_param_values[3] = I32_CONST(param_cell_num);
    func_param_values[4] = func_ctx->argv_buf;

    if (!func_param_values[3]) {
        aot_set_last_error("llvm create const failed.");
        return false;
    }

    /* call aot_call_indirect() function */
    if (!(res = LLVMBuildCall2(comp_ctx->builder, func_type, func,
                               func_param_values, 5, "res"))) {
        aot_set_last_error("llvm build call failed.");
        return false;
    }

    /* get function result values */
    cell_num = 0;
    for (i = 0; i < result_count; i++) {
        ret_type = TO_LLVM_TYPE(wasm_ret_types[i]);
        if (!(ret_idx = I32_CONST(cell_num))
            || !(ret_ptr_type = LLVMPointerType(ret_type, 0))) {
            aot_set_last_error("llvm add const or pointer type failed.");
            return false;
        }

        snprintf(buf, sizeof(buf), "argv_ret%d", i);
        if (!(ret_ptr =
                  LLVMBuildInBoundsGEP2(comp_ctx->builder, I32_TYPE,
                                        func_ctx->argv_buf, &ret_idx, 1, buf))
            || !(ret_ptr = LLVMBuildBitCast(comp_ctx->builder, ret_ptr,
                                            ret_ptr_type, buf))) {
            aot_set_last_error("llvm build GEP or bit cast failed.");
            return false;
        }

        snprintf(buf, sizeof(buf), "ret%d", i);
        if (!(value_rets[i] =
                  LLVMBuildLoad2(comp_ctx->builder, ret_type, ret_ptr, buf))) {
            aot_set_last_error("llvm build load failed.");
            return false;
        }
        cell_num += wasm_value_type_cell_num(wasm_ret_types[i]);
    }

    *p_res = res;
    return true;
}

bool
aot_compile_op_call_indirect(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             uint32 type_idx, uint32 tbl_idx)
{
    AOTFuncType *func_type;
    LLVMValueRef tbl_idx_value, elem_idx, table_elem, func_idx;
    LLVMValueRef ftype_idx_ptr, ftype_idx, ftype_idx_const;
    LLVMValueRef cmp_elem_idx, cmp_func_idx, cmp_ftype_idx;
    LLVMValueRef func, func_ptr, table_size_const;
    LLVMValueRef ext_ret_offset, ext_ret_ptr, ext_ret, res;
    LLVMValueRef *param_values = NULL, *value_rets = NULL;
    LLVMValueRef *result_phis = NULL, value_ret, import_func_count;
    LLVMTypeRef *param_types = NULL, ret_type;
    LLVMTypeRef llvm_func_type, llvm_func_ptr_type;
    LLVMTypeRef ext_ret_ptr_type;
    LLVMBasicBlockRef check_elem_idx_succ, check_ftype_idx_succ;
    LLVMBasicBlockRef check_func_idx_succ, block_return, block_curr;
    LLVMBasicBlockRef block_call_import, block_call_non_import;
    LLVMValueRef offset;
    uint32 total_param_count, func_param_count, func_result_count;
    uint32 ext_cell_num, param_cell_num, i, j;
    uint8 wasm_ret_type, *wasm_ret_types;
    uint64 total_size;
    char buf[32];
    bool ret = false;

    /* Check function type index */
    if (type_idx >= comp_ctx->comp_data->func_type_count) {
        aot_set_last_error("function type index out of range");
        return false;
    }

    /* Find the equivalent function type whose type index is the smallest:
       the callee function's type index is also converted to the smallest
       one in wasm loader, so we can just check whether the two type indexes
       are equal (the type index of call_indirect opcode and callee func),
       we don't need to check whether the whole function types are equal,
       including param types and result types. */
    type_idx = wasm_get_smallest_type_idx(comp_ctx->comp_data->func_types,
                                          comp_ctx->comp_data->func_type_count,
                                          type_idx);
    ftype_idx_const = I32_CONST(type_idx);
    CHECK_LLVM_CONST(ftype_idx_const);

    func_type = comp_ctx->comp_data->func_types[type_idx];
    aot_estimate_and_record_stack_usage_for_function_call(comp_ctx, func_ctx,
                                                          func_type);
    func_param_count = func_type->param_count;
    func_result_count = func_type->result_count;

    POP_I32(elem_idx);

    /* get the cur size of the table instance */
    if (!(offset = I32_CONST(get_tbl_inst_offset(comp_ctx, func_ctx, tbl_idx)
                             + offsetof(AOTTableInstance, cur_size)))) {
        HANDLE_FAILURE("LLVMConstInt");
        goto fail;
    }

    if (!(table_size_const = LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE,
                                                   func_ctx->aot_inst, &offset,
                                                   1, "cur_size_i8p"))) {
        HANDLE_FAILURE("LLVMBuildGEP");
        goto fail;
    }

    if (!(table_size_const =
              LLVMBuildBitCast(comp_ctx->builder, table_size_const,
                               INT32_PTR_TYPE, "cur_siuze_i32p"))) {
        HANDLE_FAILURE("LLVMBuildBitCast");
        goto fail;
    }

    if (!(table_size_const = LLVMBuildLoad2(comp_ctx->builder, I32_TYPE,
                                            table_size_const, "cur_size"))) {
        HANDLE_FAILURE("LLVMBuildLoad");
        goto fail;
    }

    /* Check if (uint32)elem index >= table size */
    if (!(cmp_elem_idx = LLVMBuildICmp(comp_ctx->builder, LLVMIntUGE, elem_idx,
                                       table_size_const, "cmp_elem_idx"))) {
        aot_set_last_error("llvm build icmp failed.");
        goto fail;
    }

    /* Throw exception if elem index >= table size */
    if (!(check_elem_idx_succ = LLVMAppendBasicBlockInContext(
              comp_ctx->context, func_ctx->func, "check_elem_idx_succ"))) {
        aot_set_last_error("llvm add basic block failed.");
        goto fail;
    }

    LLVMMoveBasicBlockAfter(check_elem_idx_succ,
                            LLVMGetInsertBlock(comp_ctx->builder));

    if (!(aot_emit_exception(comp_ctx, func_ctx, EXCE_UNDEFINED_ELEMENT, true,
                             cmp_elem_idx, check_elem_idx_succ)))
        goto fail;

    /* load data as i32* */
    if (!(offset = I32_CONST(get_tbl_inst_offset(comp_ctx, func_ctx, tbl_idx)
                             + offsetof(AOTTableInstance, elems)))) {
        HANDLE_FAILURE("LLVMConstInt");
        goto fail;
    }

    if (!(table_elem = LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE,
                                             func_ctx->aot_inst, &offset, 1,
                                             "table_elem_i8p"))) {
        aot_set_last_error("llvm build add failed.");
        goto fail;
    }

    if (!(table_elem = LLVMBuildBitCast(comp_ctx->builder, table_elem,
                                        INT32_PTR_TYPE, "table_elem_i32p"))) {
        HANDLE_FAILURE("LLVMBuildBitCast");
        goto fail;
    }

    /* Load function index */
    if (!(table_elem =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, I32_TYPE, table_elem,
                                    &elem_idx, 1, "table_elem"))) {
        HANDLE_FAILURE("LLVMBuildNUWAdd");
        goto fail;
    }

    if (!(func_idx = LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, table_elem,
                                    "func_idx"))) {
        aot_set_last_error("llvm build load failed.");
        goto fail;
    }

    /* Check if func_idx == -1 */
    if (!(cmp_func_idx = LLVMBuildICmp(comp_ctx->builder, LLVMIntEQ, func_idx,
                                       I32_NEG_ONE, "cmp_func_idx"))) {
        aot_set_last_error("llvm build icmp failed.");
        goto fail;
    }

    /* Throw exception if func_idx == -1 */
    if (!(check_func_idx_succ = LLVMAppendBasicBlockInContext(
              comp_ctx->context, func_ctx->func, "check_func_idx_succ"))) {
        aot_set_last_error("llvm add basic block failed.");
        goto fail;
    }

    LLVMMoveBasicBlockAfter(check_func_idx_succ,
                            LLVMGetInsertBlock(comp_ctx->builder));

    if (!(aot_emit_exception(comp_ctx, func_ctx, EXCE_UNINITIALIZED_ELEMENT,
                             true, cmp_func_idx, check_func_idx_succ)))
        goto fail;

    /* Load function type index */
    if (!(ftype_idx_ptr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, I32_TYPE, func_ctx->func_type_indexes,
              &func_idx, 1, "ftype_idx_ptr"))) {
        aot_set_last_error("llvm build inbounds gep failed.");
        goto fail;
    }

    if (!(ftype_idx = LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, ftype_idx_ptr,
                                     "ftype_idx"))) {
        aot_set_last_error("llvm build load failed.");
        goto fail;
    }

    /* Check if function type index not equal */
    if (!(cmp_ftype_idx = LLVMBuildICmp(comp_ctx->builder, LLVMIntNE, ftype_idx,
                                        ftype_idx_const, "cmp_ftype_idx"))) {
        aot_set_last_error("llvm build icmp failed.");
        goto fail;
    }

    /* Throw exception if ftype_idx != ftype_idx_const */
    if (!(check_ftype_idx_succ = LLVMAppendBasicBlockInContext(
              comp_ctx->context, func_ctx->func, "check_ftype_idx_succ"))) {
        aot_set_last_error("llvm add basic block failed.");
        goto fail;
    }

    LLVMMoveBasicBlockAfter(check_ftype_idx_succ,
                            LLVMGetInsertBlock(comp_ctx->builder));

    if (!(aot_emit_exception(comp_ctx, func_ctx,
                             EXCE_INVALID_FUNCTION_TYPE_INDEX, true,
                             cmp_ftype_idx, check_ftype_idx_succ)))
        goto fail;

    /* Initialize parameter types of the LLVM function */
    total_param_count = 1 + func_param_count;

    /* Extra function results' addresses (except the first one) are
       appended to aot function parameters. */
    if (func_result_count > 1)
        total_param_count += func_result_count - 1;

    total_size = sizeof(LLVMTypeRef) * (uint64)total_param_count;
    if (total_size >= UINT32_MAX
        || !(param_types = wasm_runtime_malloc((uint32)total_size))) {
        aot_set_last_error("allocate memory failed.");
        goto fail;
    }

    /* Prepare param types */
    j = 0;
    param_types[j++] = comp_ctx->exec_env_type;
    for (i = 0; i < func_param_count; i++)
        param_types[j++] = TO_LLVM_TYPE(func_type->types[i]);

    for (i = 1; i < func_result_count; i++, j++) {
        param_types[j] = TO_LLVM_TYPE(func_type->types[func_param_count + i]);
        if (!(param_types[j] = LLVMPointerType(param_types[j], 0))) {
            aot_set_last_error("llvm get pointer type failed.");
            goto fail;
        }
    }

    /* Resolve return type of the LLVM function */
    if (func_result_count) {
        wasm_ret_type = func_type->types[func_param_count];
        ret_type = TO_LLVM_TYPE(wasm_ret_type);
    }
    else {
        wasm_ret_type = VALUE_TYPE_VOID;
        ret_type = VOID_TYPE;
    }

    /* Allocate memory for parameters */
    total_size = sizeof(LLVMValueRef) * (uint64)total_param_count;
    if (total_size >= UINT32_MAX
        || !(param_values = wasm_runtime_malloc((uint32)total_size))) {
        aot_set_last_error("allocate memory failed.");
        goto fail;
    }

    /* First parameter is exec env */
    j = 0;
    param_values[j++] = func_ctx->exec_env;

    /* Pop parameters from stack */
    for (i = func_param_count - 1; (int32)i >= 0; i--)
        POP(param_values[i + j], func_type->types[i]);

    /* Prepare extra parameters */
    ext_cell_num = 0;
    for (i = 1; i < func_result_count; i++) {
        ext_ret_offset = I32_CONST(ext_cell_num);
        CHECK_LLVM_CONST(ext_ret_offset);

        snprintf(buf, sizeof(buf), "ext_ret%d_ptr", i - 1);
        if (!(ext_ret_ptr = LLVMBuildInBoundsGEP2(comp_ctx->builder, I32_TYPE,
                                                  func_ctx->argv_buf,
                                                  &ext_ret_offset, 1, buf))) {
            aot_set_last_error("llvm build GEP failed.");
            goto fail;
        }

        ext_ret_ptr_type = param_types[func_param_count + i];
        snprintf(buf, sizeof(buf), "ext_ret%d_ptr_cast", i - 1);
        if (!(ext_ret_ptr = LLVMBuildBitCast(comp_ctx->builder, ext_ret_ptr,
                                             ext_ret_ptr_type, buf))) {
            aot_set_last_error("llvm build bit cast failed.");
            goto fail;
        }

        param_values[func_param_count + i] = ext_ret_ptr;
        ext_cell_num +=
            wasm_value_type_cell_num(func_type->types[func_param_count + i]);
    }

    if (ext_cell_num > 64) {
        aot_set_last_error("prepare call-indirect arguments failed: "
                           "maximum 64 extra cell number supported.");
        goto fail;
    }

#if WASM_ENABLE_THREAD_MGR != 0
    /* Insert suspend check point */
    if (comp_ctx->enable_thread_mgr) {
        if (!check_suspend_flags(comp_ctx, func_ctx))
            goto fail;
    }
#endif

#if (WASM_ENABLE_DUMP_CALL_STACK != 0) || (WASM_ENABLE_PERF_PROFILING != 0)
    if (comp_ctx->enable_aux_stack_frame) {
        if (!call_aot_alloc_frame_func(comp_ctx, func_ctx, func_idx))
            goto fail;
    }
#endif

    /* Add basic blocks */
    block_call_import = LLVMAppendBasicBlockInContext(
        comp_ctx->context, func_ctx->func, "call_import");
    block_call_non_import = LLVMAppendBasicBlockInContext(
        comp_ctx->context, func_ctx->func, "call_non_import");
    block_return = LLVMAppendBasicBlockInContext(comp_ctx->context,
                                                 func_ctx->func, "func_return");
    if (!block_call_import || !block_call_non_import || !block_return) {
        aot_set_last_error("llvm add basic block failed.");
        goto fail;
    }

    LLVMMoveBasicBlockAfter(block_call_import,
                            LLVMGetInsertBlock(comp_ctx->builder));
    LLVMMoveBasicBlockAfter(block_call_non_import, block_call_import);
    LLVMMoveBasicBlockAfter(block_return, block_call_non_import);

    import_func_count = I32_CONST(comp_ctx->comp_data->import_func_count);
    CHECK_LLVM_CONST(import_func_count);

    /* Check if func_idx < import_func_count */
    if (!(cmp_func_idx = LLVMBuildICmp(comp_ctx->builder, LLVMIntULT, func_idx,
                                       import_func_count, "cmp_func_idx"))) {
        aot_set_last_error("llvm build icmp failed.");
        goto fail;
    }

    /* If func_idx < import_func_count, jump to call import block,
       else jump to call non-import block */
    if (!LLVMBuildCondBr(comp_ctx->builder, cmp_func_idx, block_call_import,
                         block_call_non_import)) {
        aot_set_last_error("llvm build cond br failed.");
        goto fail;
    }

    /* Add result phis for return block */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, block_return);

    if (func_result_count > 0) {
        total_size = sizeof(LLVMValueRef) * (uint64)func_result_count;
        if (total_size >= UINT32_MAX
            || !(result_phis = wasm_runtime_malloc((uint32)total_size))) {
            aot_set_last_error("allocate memory failed.");
            goto fail;
        }
        memset(result_phis, 0, (uint32)total_size);
        for (i = 0; i < func_result_count; i++) {
            LLVMTypeRef tmp_type =
                TO_LLVM_TYPE(func_type->types[func_param_count + i]);
            if (!(result_phis[i] =
                      LLVMBuildPhi(comp_ctx->builder, tmp_type, "phi"))) {
                aot_set_last_error("llvm build phi failed.");
                goto fail;
            }
        }
    }

    /* Translate call import block */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, block_call_import);

    /* Allocate memory for result values */
    if (func_result_count > 0) {
        total_size = sizeof(LLVMValueRef) * (uint64)func_result_count;
        if (total_size >= UINT32_MAX
            || !(value_rets = wasm_runtime_malloc((uint32)total_size))) {
            aot_set_last_error("allocate memory failed.");
            goto fail;
        }
        memset(value_rets, 0, (uint32)total_size);
    }

    param_cell_num = func_type->param_cell_num;
    wasm_ret_types = func_type->types + func_type->param_count;

    tbl_idx_value = I32_CONST(tbl_idx);
    if (!tbl_idx_value) {
        aot_set_last_error("llvm create const failed.");
        goto fail;
    }

    if (!call_aot_call_indirect_func(
            comp_ctx, func_ctx, func_type, ftype_idx, tbl_idx_value, elem_idx,
            param_types + 1, param_values + 1, func_param_count, param_cell_num,
            func_result_count, wasm_ret_types, value_rets, &res))
        goto fail;

    /* Check whether exception was thrown when executing the function */
    if ((comp_ctx->enable_bound_check || is_win_platform(comp_ctx))
        && !check_call_return(comp_ctx, func_ctx, res))
        goto fail;

    block_curr = LLVMGetInsertBlock(comp_ctx->builder);
    for (i = 0; i < func_result_count; i++) {
        LLVMAddIncoming(result_phis[i], &value_rets[i], &block_curr, 1);
    }

    if (!LLVMBuildBr(comp_ctx->builder, block_return)) {
        aot_set_last_error("llvm build br failed.");
        goto fail;
    }

    /* Translate call non-import block */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, block_call_non_import);

    /* Load function pointer */
    if (!(func_ptr = LLVMBuildInBoundsGEP2(comp_ctx->builder, OPQ_PTR_TYPE,
                                           func_ctx->func_ptrs, &func_idx, 1,
                                           "func_ptr_tmp"))) {
        aot_set_last_error("llvm build inbounds gep failed.");
        goto fail;
    }

    if (!(func_ptr = LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE, func_ptr,
                                    "func_ptr"))) {
        aot_set_last_error("llvm build load failed.");
        goto fail;
    }

    if (!(llvm_func_type =
              LLVMFunctionType(ret_type, param_types, total_param_count, false))
        || !(llvm_func_ptr_type = LLVMPointerType(llvm_func_type, 0))) {
        aot_set_last_error("llvm add function type failed.");
        goto fail;
    }

    if (!(func = LLVMBuildBitCast(comp_ctx->builder, func_ptr,
                                  llvm_func_ptr_type, "indirect_func"))) {
        aot_set_last_error("llvm build bit cast failed.");
        goto fail;
    }

    if (!(value_ret = LLVMBuildCall2(comp_ctx->builder, llvm_func_type, func,
                                     param_values, total_param_count,
                                     func_result_count > 0 ? "ret" : ""))) {
        aot_set_last_error("llvm build call failed.");
        goto fail;
    }

    /* Check whether exception was thrown when executing the function */
    if ((comp_ctx->enable_bound_check || is_win_platform(comp_ctx))
        && !check_exception_thrown(comp_ctx, func_ctx))
        goto fail;

    if (func_result_count > 0) {
        block_curr = LLVMGetInsertBlock(comp_ctx->builder);

        /* Push the first result to stack */
        LLVMAddIncoming(result_phis[0], &value_ret, &block_curr, 1);

        /* Load extra result from its address and push to stack */
        for (i = 1; i < func_result_count; i++) {
            ret_type = TO_LLVM_TYPE(func_type->types[func_param_count + i]);
            snprintf(buf, sizeof(buf), "ext_ret%d", i - 1);
            if (!(ext_ret = LLVMBuildLoad2(comp_ctx->builder, ret_type,
                                           param_values[func_param_count + i],
                                           buf))) {
                aot_set_last_error("llvm build load failed.");
                goto fail;
            }
            LLVMAddIncoming(result_phis[i], &ext_ret, &block_curr, 1);
        }
    }

    if (!LLVMBuildBr(comp_ctx->builder, block_return)) {
        aot_set_last_error("llvm build br failed.");
        goto fail;
    }

    /* Translate function return block */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, block_return);

    for (i = 0; i < func_result_count; i++) {
        PUSH(result_phis[i], func_type->types[func_param_count + i]);
    }

#if (WASM_ENABLE_DUMP_CALL_STACK != 0) || (WASM_ENABLE_PERF_PROFILING != 0)
    if (comp_ctx->enable_aux_stack_frame) {
        if (!call_aot_free_frame_func(comp_ctx, func_ctx))
            goto fail;
    }
#endif

#if WASM_ENABLE_THREAD_MGR != 0
    /* Insert suspend check point */
    if (comp_ctx->enable_thread_mgr) {
        if (!check_suspend_flags(comp_ctx, func_ctx))
            goto fail;
    }
#endif

    ret = true;

fail:
    if (param_values)
        wasm_runtime_free(param_values);
    if (param_types)
        wasm_runtime_free(param_types);
    if (value_rets)
        wasm_runtime_free(value_rets);
    if (result_phis)
        wasm_runtime_free(result_phis);
    return ret;
}

bool
aot_compile_op_ref_null(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    PUSH_I32(REF_NULL);

    return true;
fail:
    return false;
}

bool
aot_compile_op_ref_is_null(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef lhs, res;

    POP_I32(lhs);

    if (!(res = LLVMBuildICmp(comp_ctx->builder, LLVMIntEQ, lhs, REF_NULL,
                              "cmp_w_null"))) {
        HANDLE_FAILURE("LLVMBuildICmp");
        goto fail;
    }

    if (!(res = LLVMBuildZExt(comp_ctx->builder, res, I32_TYPE, "r_i"))) {
        HANDLE_FAILURE("LLVMBuildZExt");
        goto fail;
    }

    PUSH_I32(res);

    return true;
fail:
    return false;
}

bool
aot_compile_op_ref_func(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        uint32 func_idx)
{
    LLVMValueRef ref_idx;

    if (!(ref_idx = I32_CONST(func_idx))) {
        HANDLE_FAILURE("LLVMConstInt");
        goto fail;
    }

    PUSH_I32(ref_idx);

    return true;
fail:
    return false;
}
