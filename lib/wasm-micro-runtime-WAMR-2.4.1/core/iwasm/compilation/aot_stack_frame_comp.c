/*
 * Copyright (C) 2024 Amazon Inc.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include "aot_stack_frame_comp.h"
#include "aot_emit_exception.h"

#define ADD_IN_BOUNDS_GEP(variable, type, pointer, indices, num_indices)     \
    do {                                                                     \
        if (!(variable =                                                     \
                  LLVMBuildInBoundsGEP2(comp_ctx->builder, type, pointer,    \
                                        indices, num_indices, #variable))) { \
            aot_set_last_error("llvm build in bounds gep failed");           \
            return false;                                                    \
        }                                                                    \
    } while (0)

#define ADD_STORE(value, pointer)                                 \
    do {                                                          \
        if (!LLVMBuildStore(comp_ctx->builder, value, pointer)) { \
            aot_set_last_error("llvm build store failed");        \
            return false;                                         \
        }                                                         \
    } while (0)

#define ADD_LOAD(value, type, pointer)                                         \
    do {                                                                       \
        if (!(value =                                                          \
                  LLVMBuildLoad2(comp_ctx->builder, type, pointer, #value))) { \
            aot_set_last_error("llvm build load failed");                      \
            return false;                                                      \
        }                                                                      \
    } while (0)

static bool
aot_alloc_tiny_frame_for_aot_func(AOTCompContext *comp_ctx,
                                  AOTFuncContext *func_ctx,
                                  LLVMValueRef func_index)
{
    LLVMValueRef wasm_stack_top_ptr = func_ctx->wasm_stack_top_ptr,
                 wasm_stack_top_bound = func_ctx->wasm_stack_top_bound,
                 wasm_stack_top, cmp;
    LLVMBasicBlockRef check_wasm_stack_succ;
    LLVMValueRef offset;

    ADD_LOAD(wasm_stack_top, INT8_PTR_TYPE, wasm_stack_top_ptr);

    if (comp_ctx->call_stack_features.bounds_checks) {
        if (!(check_wasm_stack_succ = LLVMAppendBasicBlockInContext(
                  comp_ctx->context, func_ctx->func,
                  "check_wasm_stack_succ"))) {
            aot_set_last_error("llvm add basic block failed.");
            return false;
        }

        LLVMMoveBasicBlockAfter(check_wasm_stack_succ,
                                LLVMGetInsertBlock(comp_ctx->builder));

        if (!(cmp = LLVMBuildICmp(comp_ctx->builder, LLVMIntUGE, wasm_stack_top,
                                  wasm_stack_top_bound, "cmp"))) {
            aot_set_last_error("llvm build icmp failed");
            return false;
        }

        if (!(aot_emit_exception(comp_ctx, func_ctx,
                                 EXCE_OPERAND_STACK_OVERFLOW, true, cmp,
                                 check_wasm_stack_succ))) {
            return false;
        }
    }

    /* Save the func_idx on the top of the stack */
    if (comp_ctx->call_stack_features.func_idx) {
        ADD_STORE(func_index, wasm_stack_top);
    }

    /* increment the stack pointer */
    INT_CONST(offset, sizeof(AOTTinyFrame), I32_TYPE, true);
    ADD_IN_BOUNDS_GEP(wasm_stack_top, INT8_TYPE, wasm_stack_top, &offset, 1);
    ADD_STORE(wasm_stack_top, wasm_stack_top_ptr);

    return true;
}

static bool
aot_free_tiny_frame_for_aot_func(AOTCompContext *comp_ctx,
                                 AOTFuncContext *func_ctx)
{
    LLVMValueRef wasm_stack_top_ptr = func_ctx->wasm_stack_top_ptr,
                 wasm_stack_top;
    LLVMValueRef offset;

    ADD_LOAD(wasm_stack_top, INT8_PTR_TYPE, wasm_stack_top_ptr);

    INT_CONST(offset, -sizeof(AOTTinyFrame),
              comp_ctx->pointer_size == 8 ? I64_TYPE : I32_TYPE, true);
    ADD_IN_BOUNDS_GEP(wasm_stack_top, INT8_TYPE, wasm_stack_top, &offset, 1);
    ADD_STORE(wasm_stack_top, wasm_stack_top_ptr);

    return true;
}

bool
aot_tiny_frame_gen_commit_ip(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef ip_value)
{
    LLVMValueRef wasm_stack_top_ptr = func_ctx->wasm_stack_top_ptr,
                 wasm_stack_top;
    LLVMValueRef offset, ip_addr;

    bh_assert(ip_value);

    ADD_LOAD(wasm_stack_top, INT8_PTR_TYPE, wasm_stack_top_ptr);

    INT_CONST(offset, -4, comp_ctx->pointer_size == 8 ? I64_TYPE : I32_TYPE,
              true);
    ADD_IN_BOUNDS_GEP(ip_addr, INT8_TYPE, wasm_stack_top, &offset, 1);

    ADD_STORE(ip_value, ip_addr);

    return true;
}

bool
aot_alloc_frame_per_function_frame_for_aot_func(AOTCompContext *comp_ctx,
                                                AOTFuncContext *func_ctx,
                                                LLVMValueRef func_index)
{
    switch (comp_ctx->aux_stack_frame_type) {
        case AOT_STACK_FRAME_TYPE_TINY:
            return aot_alloc_tiny_frame_for_aot_func(comp_ctx, func_ctx,
                                                     func_index);
        default:
            aot_set_last_error("unsupported mode");
            return false;
    }
}

bool
aot_free_frame_per_function_frame_for_aot_func(AOTCompContext *comp_ctx,
                                               AOTFuncContext *func_ctx)
{
    switch (comp_ctx->aux_stack_frame_type) {
        case AOT_STACK_FRAME_TYPE_TINY:
            return aot_free_tiny_frame_for_aot_func(comp_ctx, func_ctx);
        default:
            aot_set_last_error("unsupported mode");
            return false;
    }
}
