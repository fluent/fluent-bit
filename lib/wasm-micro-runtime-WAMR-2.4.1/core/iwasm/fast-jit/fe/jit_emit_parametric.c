/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_emit_parametric.h"
#include "../jit_frontend.h"

static bool
pop_value_from_wasm_stack(JitCompContext *cc, bool is_32bit, JitReg *p_value,
                          uint8 *p_type)
{
    JitValue *jit_value;
    JitReg value;
    uint8 type;

    if (!jit_block_stack_top(&cc->block_stack)) {
        jit_set_last_error(cc, "WASM block stack underflow.");
        return false;
    }
    if (!jit_block_stack_top(&cc->block_stack)->value_stack.value_list_end) {
        jit_set_last_error(cc, "WASM data stack underflow.");
        return false;
    }

    jit_value = jit_value_stack_pop(
        &jit_block_stack_top(&cc->block_stack)->value_stack);
    type = jit_value->type;

    if (p_type != NULL) {
        *p_type = jit_value->type;
    }

    wasm_runtime_free(jit_value);

    /* is_32: i32, f32, ref.func, ref.extern, v128 */
    if (is_32bit
        && !(type == VALUE_TYPE_I32 || type == VALUE_TYPE_F32
#if WASM_ENABLE_REF_TYPES != 0
             || type == VALUE_TYPE_FUNCREF || type == VALUE_TYPE_EXTERNREF
#endif
             || type == VALUE_TYPE_V128)) {
        jit_set_last_error(cc, "invalid WASM stack data type.");
        return false;
    }
    /* !is_32: i64, f64 */
    if (!is_32bit && !(type == VALUE_TYPE_I64 || type == VALUE_TYPE_F64)) {
        jit_set_last_error(cc, "invalid WASM stack data type.");
        return false;
    }

    switch (type) {
        case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
        case VALUE_TYPE_FUNCREF:
        case VALUE_TYPE_EXTERNREF:
#endif
            value = pop_i32(cc->jit_frame);
            break;
        case VALUE_TYPE_I64:
            value = pop_i64(cc->jit_frame);
            break;
        case VALUE_TYPE_F32:
            value = pop_f32(cc->jit_frame);
            break;
        case VALUE_TYPE_F64:
            value = pop_f64(cc->jit_frame);
            break;
        default:
            bh_assert(0);
            return false;
    }

    if (p_value != NULL) {
        *p_value = value;
    }
    return true;
}

bool
jit_compile_op_drop(JitCompContext *cc, bool is_drop_32)
{
    if (!pop_value_from_wasm_stack(cc, is_drop_32, NULL, NULL))
        return false;
    return true;
}

bool
jit_compile_op_select(JitCompContext *cc, bool is_select_32)
{
    JitReg val1, val2, cond, selected;
    uint8 val1_type, val2_type;

    POP_I32(cond);

    if (!pop_value_from_wasm_stack(cc, is_select_32, &val2, &val2_type)
        || !pop_value_from_wasm_stack(cc, is_select_32, &val1, &val1_type)) {
        return false;
    }

    if (val1_type != val2_type) {
        jit_set_last_error(cc, "invalid stack values with different type");
        return false;
    }

    switch (val1_type) {
        case VALUE_TYPE_I32:
            selected = jit_cc_new_reg_I32(cc);
            break;
        case VALUE_TYPE_I64:
            selected = jit_cc_new_reg_I64(cc);
            break;
        case VALUE_TYPE_F32:
            selected = jit_cc_new_reg_F32(cc);
            break;
        case VALUE_TYPE_F64:
            selected = jit_cc_new_reg_F64(cc);
            break;
        default:
            bh_assert(0);
            return false;
    }

    GEN_INSN(CMP, cc->cmp_reg, cond, NEW_CONST(I32, 0));
    GEN_INSN(SELECTNE, selected, cc->cmp_reg, val1, val2);
    PUSH(selected, val1_type);
    return true;
fail:
    return false;
}
