/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_emit_parametric.h"

static bool
pop_value_from_wasm_stack(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          LLVMValueRef *p_value, bool is_32, uint8 *p_type)
{
    AOTValue *aot_value;
    uint8 type;

    if (!func_ctx->block_stack.block_list_end) {
        aot_set_last_error("WASM block stack underflow.");
        return false;
    }
    if (!func_ctx->block_stack.block_list_end->value_stack.value_list_end) {
        aot_set_last_error("WASM data stack underflow.");
        return false;
    }

    aot_value = aot_value_stack_pop(
        comp_ctx, &func_ctx->block_stack.block_list_end->value_stack);
    type = aot_value->type;

    if (aot_value->type == VALUE_TYPE_I1) {
        if (!(aot_value->value =
                  LLVMBuildZExt(comp_ctx->builder, aot_value->value, I32_TYPE,
                                "val_s_ext"))) {
            aot_set_last_error("llvm build sign ext failed.");
            return false;
        }
        type = aot_value->type = VALUE_TYPE_I32;
    }

    if (p_type != NULL) {
        *p_type = aot_value->type;
    }
    if (p_value != NULL) {
        *p_value = aot_value->value;
    }

    wasm_runtime_free(aot_value);

    if (is_32) {
        /* is_32: i32, f32, ref.func, ref.extern, v128,
                  or GC ref types */
        if (!(type == VALUE_TYPE_I32 || type == VALUE_TYPE_F32
              || type == VALUE_TYPE_V128
              || (comp_ctx->enable_ref_types
                  && (type == VALUE_TYPE_FUNCREF
                      || type == VALUE_TYPE_EXTERNREF))
#if WASM_ENABLE_GC != 0
              || (comp_ctx->enable_gc && type == VALUE_TYPE_GC_REF)
#endif
                  )) {
            aot_set_last_error("invalid WASM stack data type.");
            return false;
        }
    }
    else {
        /* !is_32: i64, f64, or GC ref types */
        if (!(type == VALUE_TYPE_I64 || type == VALUE_TYPE_F64
#if WASM_ENABLE_GC != 0
              || (comp_ctx->enable_gc && type == VALUE_TYPE_GC_REF)
              /* may be i32 which denotes funcref/externref */
              || (!comp_ctx->enable_gc && type == VALUE_TYPE_I32)
#endif
                  )) {
            aot_set_last_error("invalid WASM stack data type.");
            return false;
        }
    }

    return true;
}

bool
aot_compile_op_drop(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                    bool is_drop_32)
{
    if (!pop_value_from_wasm_stack(comp_ctx, func_ctx, NULL, is_drop_32, NULL))
        return false;

    return true;
}

bool
aot_compile_op_select(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                      bool is_select_32)
{
    LLVMValueRef val1, val2, cond, selected;
    uint8 val1_type, val2_type;

    POP_COND(cond);

    if (!pop_value_from_wasm_stack(comp_ctx, func_ctx, &val2, is_select_32,
                                   &val2_type)
        || !pop_value_from_wasm_stack(comp_ctx, func_ctx, &val1, is_select_32,
                                      &val1_type))
        return false;

    if (val1_type != val2_type) {
        aot_set_last_error("invalid stack values with different type");
        return false;
    }

    if (!(selected =
              LLVMBuildSelect(comp_ctx->builder, cond, val1, val2, "select"))) {
        aot_set_last_error("llvm build select failed.");
        return false;
    }

    PUSH(selected, val1_type);

    return true;

fail:
    return false;
}
