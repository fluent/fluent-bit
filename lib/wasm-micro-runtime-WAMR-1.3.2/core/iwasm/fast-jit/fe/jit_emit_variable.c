/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_emit_variable.h"
#include "jit_emit_exception.h"
#include "../jit_frontend.h"

#define CHECK_LOCAL(idx)                                                     \
    do {                                                                     \
        if (idx                                                              \
            >= wasm_func->func_type->param_count + wasm_func->local_count) { \
            jit_set_last_error(cc, "local index out of range");              \
            goto fail;                                                       \
        }                                                                    \
    } while (0)

static uint8
get_local_type(const WASMFunction *wasm_func, uint32 local_idx)
{
    uint32 param_count = wasm_func->func_type->param_count;
    return local_idx < param_count
               ? wasm_func->func_type->types[local_idx]
               : wasm_func->local_types[local_idx - param_count];
}

bool
jit_compile_op_get_local(JitCompContext *cc, uint32 local_idx)
{
    WASMFunction *wasm_func = cc->cur_wasm_func;
    uint16 *local_offsets = wasm_func->local_offsets;
    uint16 local_offset;
    uint8 local_type;
    JitReg value = 0;

    CHECK_LOCAL(local_idx);

    local_offset = local_offsets[local_idx];
    local_type = get_local_type(wasm_func, local_idx);

    switch (local_type) {
        case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
        case VALUE_TYPE_EXTERNREF:
        case VALUE_TYPE_FUNCREF:
#endif
            value = local_i32(cc->jit_frame, local_offset);

            break;
        case VALUE_TYPE_I64:
            value = local_i64(cc->jit_frame, local_offset);
            break;
        case VALUE_TYPE_F32:
            value = local_f32(cc->jit_frame, local_offset);
            break;
        case VALUE_TYPE_F64:
            value = local_f64(cc->jit_frame, local_offset);
            break;
        default:
            bh_assert(0);
            break;
    }

    PUSH(value, local_type);
    return true;
fail:
    return false;
}

bool
jit_compile_op_set_local(JitCompContext *cc, uint32 local_idx)
{
    WASMFunction *wasm_func = cc->cur_wasm_func;
    uint16 *local_offsets = wasm_func->local_offsets;
    uint16 local_offset;
    uint8 local_type;
    JitReg value;

    CHECK_LOCAL(local_idx);

    local_offset = local_offsets[local_idx];
    local_type = get_local_type(wasm_func, local_idx);

    switch (local_type) {
        case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
        case VALUE_TYPE_EXTERNREF:
        case VALUE_TYPE_FUNCREF:
#endif
            POP_I32(value);
            set_local_i32(cc->jit_frame, local_offset, value);
            break;
        case VALUE_TYPE_I64:
            POP_I64(value);
            set_local_i64(cc->jit_frame, local_offset, value);
            break;
        case VALUE_TYPE_F32:
            POP_F32(value);
            set_local_f32(cc->jit_frame, local_offset, value);
            break;
        case VALUE_TYPE_F64:
            POP_F64(value);
            set_local_f64(cc->jit_frame, local_offset, value);
            break;
        default:
            bh_assert(0);
            break;
    }

    return true;
fail:
    return false;
}

bool
jit_compile_op_tee_local(JitCompContext *cc, uint32 local_idx)
{
    WASMFunction *wasm_func = cc->cur_wasm_func;
    uint16 *local_offsets = wasm_func->local_offsets;
    uint16 local_offset;
    uint8 local_type;
    JitReg value = 0;

    CHECK_LOCAL(local_idx);

    local_offset = local_offsets[local_idx];
    local_type = get_local_type(wasm_func, local_idx);

    switch (local_type) {
        case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
        case VALUE_TYPE_EXTERNREF:
        case VALUE_TYPE_FUNCREF:
#endif
            POP_I32(value);
            set_local_i32(cc->jit_frame, local_offset, value);
            PUSH_I32(value);
            break;
        case VALUE_TYPE_I64:
            POP_I64(value);
            set_local_i64(cc->jit_frame, local_offset, value);
            PUSH_I64(value);
            break;
        case VALUE_TYPE_F32:
            POP_F32(value);
            set_local_f32(cc->jit_frame, local_offset, value);
            PUSH_F32(value);
            break;
        case VALUE_TYPE_F64:
            POP_F64(value);
            set_local_f64(cc->jit_frame, local_offset, value);
            PUSH_F64(value);
            break;
        default:
            bh_assert(0);
            goto fail;
    }

    return true;
fail:
    return false;
}

static uint8
get_global_type(const WASMModule *module, uint32 global_idx)
{
    if (global_idx < module->import_global_count) {
        const WASMGlobalImport *import_global =
            &((module->import_globals + global_idx)->u.global);
        return import_global->type;
    }
    else {
        const WASMGlobal *global =
            module->globals + (global_idx - module->import_global_count);
        return global->type;
    }
}

bool
jit_compile_op_get_global(JitCompContext *cc, uint32 global_idx)
{
    uint32 data_offset;
    uint8 global_type = 0;
    JitReg value = 0;

    bh_assert(global_idx < cc->cur_wasm_module->import_global_count
                               + cc->cur_wasm_module->global_count);

    data_offset =
        jit_frontend_get_global_data_offset(cc->cur_wasm_module, global_idx);
    global_type = get_global_type(cc->cur_wasm_module, global_idx);

    switch (global_type) {
        case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
        case VALUE_TYPE_EXTERNREF:
        case VALUE_TYPE_FUNCREF:
#endif
        {
            value = jit_cc_new_reg_I32(cc);
            GEN_INSN(LDI32, value, get_module_inst_reg(cc->jit_frame),
                     NEW_CONST(I32, data_offset));
            break;
        }
        case VALUE_TYPE_I64:
        {
            value = jit_cc_new_reg_I64(cc);
            GEN_INSN(LDI64, value, get_module_inst_reg(cc->jit_frame),
                     NEW_CONST(I32, data_offset));
            break;
        }
        case VALUE_TYPE_F32:
        {
            value = jit_cc_new_reg_F32(cc);
            GEN_INSN(LDF32, value, get_module_inst_reg(cc->jit_frame),
                     NEW_CONST(I32, data_offset));
            break;
        }
        case VALUE_TYPE_F64:
        {
            value = jit_cc_new_reg_F64(cc);
            GEN_INSN(LDF64, value, get_module_inst_reg(cc->jit_frame),
                     NEW_CONST(I32, data_offset));
            break;
        }
        default:
        {
            jit_set_last_error(cc, "unexpected global type");
            goto fail;
        }
    }

    PUSH(value, global_type);

    return true;
fail:
    return false;
}

bool
jit_compile_op_set_global(JitCompContext *cc, uint32 global_idx,
                          bool is_aux_stack)
{
    uint32 data_offset;
    uint8 global_type = 0;
    JitReg value = 0;

    bh_assert(global_idx < cc->cur_wasm_module->import_global_count
                               + cc->cur_wasm_module->global_count);

    data_offset =
        jit_frontend_get_global_data_offset(cc->cur_wasm_module, global_idx);
    global_type = get_global_type(cc->cur_wasm_module, global_idx);

    switch (global_type) {
        case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
        case VALUE_TYPE_EXTERNREF:
        case VALUE_TYPE_FUNCREF:
#endif
        {
            POP_I32(value);
            if (is_aux_stack) {
                JitReg aux_stack_bound = get_aux_stack_bound_reg(cc->jit_frame);
                JitReg aux_stack_bottom =
                    get_aux_stack_bottom_reg(cc->jit_frame);
                GEN_INSN(CMP, cc->cmp_reg, value, aux_stack_bound);
                if (!(jit_emit_exception(cc, EXCE_AUX_STACK_OVERFLOW,
                                         JIT_OP_BLEU, cc->cmp_reg, NULL)))
                    goto fail;
                GEN_INSN(CMP, cc->cmp_reg, value, aux_stack_bottom);
                if (!(jit_emit_exception(cc, EXCE_AUX_STACK_UNDERFLOW,
                                         JIT_OP_BGTU, cc->cmp_reg, NULL)))
                    goto fail;
            }
            GEN_INSN(STI32, value, get_module_inst_reg(cc->jit_frame),
                     NEW_CONST(I32, data_offset));
            break;
        }
        case VALUE_TYPE_I64:
        {
            POP_I64(value);
            GEN_INSN(STI64, value, get_module_inst_reg(cc->jit_frame),
                     NEW_CONST(I32, data_offset));
            break;
        }
        case VALUE_TYPE_F32:
        {
            POP_F32(value);
            GEN_INSN(STF32, value, get_module_inst_reg(cc->jit_frame),
                     NEW_CONST(I32, data_offset));
            break;
        }
        case VALUE_TYPE_F64:
        {
            POP_F64(value);
            GEN_INSN(STF64, value, get_module_inst_reg(cc->jit_frame),
                     NEW_CONST(I32, data_offset));
            break;
        }
        default:
        {
            jit_set_last_error(cc, "unexpected global type");
            goto fail;
        }
    }

    return true;
fail:
    return false;
}
