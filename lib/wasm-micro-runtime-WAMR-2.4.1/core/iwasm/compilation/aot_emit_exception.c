/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_emit_exception.h"
#include "aot_compiler.h"
#include "../interpreter/wasm_runtime.h"
#include "../aot/aot_runtime.h"

bool
aot_emit_exception(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                   int32 exception_id, bool is_cond_br, LLVMValueRef cond_br_if,
                   LLVMBasicBlockRef cond_br_else_block)
{
    LLVMBasicBlockRef block_curr = LLVMGetInsertBlock(comp_ctx->builder);
    LLVMValueRef exce_id = I32_CONST((uint32)exception_id), func_const, func;
    LLVMTypeRef param_types[2], ret_type, func_type, func_ptr_type;
    LLVMValueRef param_values[2];
    bool is_64bit = (comp_ctx->pointer_size == sizeof(uint64)) ? true : false;

    bh_assert(exception_id >= 0 && exception_id < EXCE_NUM);

    CHECK_LLVM_CONST(exce_id);

    /* Create got_exception block if needed */
    if (!func_ctx->got_exception_block) {
        if (!(func_ctx->got_exception_block = LLVMAppendBasicBlockInContext(
                  comp_ctx->context, func_ctx->func, "got_exception"))) {
            aot_set_last_error("add LLVM basic block failed.");
            return false;
        }

        LLVMPositionBuilderAtEnd(comp_ctx->builder,
                                 func_ctx->got_exception_block);

        /* Create exception id phi */
        if (!(func_ctx->exception_id_phi = LLVMBuildPhi(
                  comp_ctx->builder, I32_TYPE, "exception_id_phi"))) {
            aot_set_last_error("llvm build phi failed.");
            return false;
        }

        if (comp_ctx->aot_frame && comp_ctx->call_stack_features.trap_ip) {
            /* Create exception ip phi */
            if (!(func_ctx->exception_ip_phi = LLVMBuildPhi(
                      comp_ctx->builder, is_64bit ? I64_TYPE : I32_TYPE,
                      "exception_ip_phi"))) {
                aot_set_last_error("llvm build phi failed.");
                return false;
            }

            /* Commit ip to current frame */
            if (!aot_gen_commit_ip(comp_ctx, func_ctx,
                                   func_ctx->exception_ip_phi, is_64bit)) {
                return false;
            }
        }

        /* Call aot_set_exception_with_id() to throw exception */
        param_types[0] = INT8_PTR_TYPE;
        param_types[1] = I32_TYPE;
        ret_type = VOID_TYPE;

        /* Create function type */
        if (!(func_type = LLVMFunctionType(ret_type, param_types, 2, false))) {
            aot_set_last_error("create LLVM function type failed.");
            return false;
        }

        if (comp_ctx->is_jit_mode) {
            /* Create function type */
            if (!(func_ptr_type = LLVMPointerType(func_type, 0))) {
                aot_set_last_error("create LLVM function type failed.");
                return false;
            }
            /* Create LLVM function with const function pointer */
            if (!(func_const =
                      I64_CONST((uint64)(uintptr_t)jit_set_exception_with_id))
                || !(func = LLVMConstIntToPtr(func_const, func_ptr_type))) {
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

            func_index = aot_get_native_symbol_index(
                comp_ctx, "aot_set_exception_with_id");
            if (func_index < 0) {
                return false;
            }
            if (!(func =
                      aot_get_func_from_table(comp_ctx, func_ctx->native_symbol,
                                              func_ptr_type, func_index))) {
                return false;
            }
        }
        else {
            /* Create LLVM function with external function pointer */
            if (!(func = LLVMGetNamedFunction(func_ctx->module,
                                              "aot_set_exception_with_id"))
                && !(func = LLVMAddFunction(func_ctx->module,
                                            "aot_set_exception_with_id",
                                            func_type))) {
                aot_set_last_error("add LLVM function failed.");
                return false;
            }
        }

        /* Call the aot_set_exception_with_id() function */
        param_values[0] = func_ctx->aot_inst;
        param_values[1] = func_ctx->exception_id_phi;
        if (!LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values, 2,
                            "")) {
            aot_set_last_error("llvm build call failed.");
            return false;
        }

        /* Create return IR */
        AOTFuncType *aot_func_type = func_ctx->aot_func->func_type;
        if (!aot_build_zero_function_ret(comp_ctx, func_ctx, aot_func_type)) {
            return false;
        }

        /* Resume the builder position */
        LLVMPositionBuilderAtEnd(comp_ctx->builder, block_curr);
    }

    /* Add phi incoming value to got_exception block */
    LLVMAddIncoming(func_ctx->exception_id_phi, &exce_id, &block_curr, 1);

    if (comp_ctx->aot_frame && comp_ctx->call_stack_features.trap_ip) {
        const uint8 *ip = comp_ctx->aot_frame->frame_ip;
        LLVMValueRef exce_ip = NULL;

        if (!comp_ctx->is_jit_mode) {
            WASMModule *module = comp_ctx->comp_data->wasm_module;
            if (is_64bit)
                exce_ip =
                    I64_CONST((uint64)(uintptr_t)(ip - module->load_addr));
            else
                exce_ip =
                    I32_CONST((uint32)(uintptr_t)(ip - module->load_addr));
        }
        else {
            if (is_64bit)
                exce_ip = I64_CONST((uint64)(uintptr_t)ip);
            else
                exce_ip = I32_CONST((uint32)(uintptr_t)ip);
        }

        if (!exce_ip) {
            aot_set_last_error("llvm build const failed");
            return false;
        }

        /* Add phi incoming value to got_exception block */
        LLVMAddIncoming(func_ctx->exception_ip_phi, &exce_ip, &block_curr, 1);
    }

    if (!is_cond_br) {
        /* not condition br, create br IR */
        if (!LLVMBuildBr(comp_ctx->builder, func_ctx->got_exception_block)) {
            aot_set_last_error("llvm build br failed.");
            return false;
        }
    }
    else {
        /* Create condition br */
        if (!LLVMBuildCondBr(comp_ctx->builder, cond_br_if,
                             func_ctx->got_exception_block,
                             cond_br_else_block)) {
            aot_set_last_error("llvm build cond br failed.");
            return false;
        }
        /* Start to translate the else block */
        LLVMPositionBuilderAtEnd(comp_ctx->builder, cond_br_else_block);
    }

    return true;
fail:
    return false;
}
