/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_emit_function.h"
#include "jit_emit_exception.h"
#include "../jit_frontend.h"
#include "../jit_codegen.h"
#include "../../interpreter/wasm_runtime.h"

extern bool
jit_invoke_native(WASMExecEnv *exec_env, uint32 func_idx,
                  WASMInterpFrame *prev_frame);

/* Prepare parameters for the function to call */
static bool
pre_call(JitCompContext *cc, const WASMType *func_type)
{
    JitReg value;
    uint32 i, outs_off;
    /* Prepare parameters for the function to call */
    outs_off =
        cc->total_frame_size + offsetof(WASMInterpFrame, lp)
        + wasm_get_cell_num(func_type->types, func_type->param_count) * 4;

    for (i = 0; i < func_type->param_count; i++) {
        switch (func_type->types[func_type->param_count - 1 - i]) {
            case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_EXTERNREF:
            case VALUE_TYPE_FUNCREF:
#endif
                POP_I32(value);
                outs_off -= 4;
                GEN_INSN(STI32, value, cc->fp_reg, NEW_CONST(I32, outs_off));
                break;
            case VALUE_TYPE_I64:
                POP_I64(value);
                outs_off -= 8;
                GEN_INSN(STI64, value, cc->fp_reg, NEW_CONST(I32, outs_off));
                break;
            case VALUE_TYPE_F32:
                POP_F32(value);
                outs_off -= 4;
                GEN_INSN(STF32, value, cc->fp_reg, NEW_CONST(I32, outs_off));
                break;
            case VALUE_TYPE_F64:
                POP_F64(value);
                outs_off -= 8;
                GEN_INSN(STF64, value, cc->fp_reg, NEW_CONST(I32, outs_off));
                break;
            default:
                bh_assert(0);
                goto fail;
        }
    }

    /* Commit sp as the callee may use it to store the results */
    gen_commit_sp_ip(cc->jit_frame);

    return true;
fail:
    return false;
}

/* Push results */
static bool
post_return(JitCompContext *cc, const WASMType *func_type, JitReg first_res)
{
    uint32 i, n;
    JitReg value;

    n = cc->jit_frame->sp - cc->jit_frame->lp;
    for (i = 0; i < func_type->result_count; i++) {
        switch (func_type->types[func_type->param_count + i]) {
            case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_EXTERNREF:
            case VALUE_TYPE_FUNCREF:
#endif
                if (i == 0 && first_res) {
                    bh_assert(jit_reg_kind(first_res) == JIT_REG_KIND_I32);
                    value = first_res;
                }
                else {
                    value = jit_cc_new_reg_I32(cc);
                    GEN_INSN(LDI32, value, cc->fp_reg,
                             NEW_CONST(I32, offset_of_local(n)));
                }
                PUSH_I32(value);
                n++;
                break;
            case VALUE_TYPE_I64:
                if (i == 0 && first_res) {
                    bh_assert(jit_reg_kind(first_res) == JIT_REG_KIND_I64);
                    value = first_res;
                }
                else {
                    value = jit_cc_new_reg_I64(cc);
                    GEN_INSN(LDI64, value, cc->fp_reg,
                             NEW_CONST(I32, offset_of_local(n)));
                }
                PUSH_I64(value);
                n += 2;
                break;
            case VALUE_TYPE_F32:
                if (i == 0 && first_res) {
                    bh_assert(jit_reg_kind(first_res) == JIT_REG_KIND_F32);
                    value = first_res;
                }
                else {
                    value = jit_cc_new_reg_F32(cc);
                    GEN_INSN(LDF32, value, cc->fp_reg,
                             NEW_CONST(I32, offset_of_local(n)));
                }
                PUSH_F32(value);
                n++;
                break;
            case VALUE_TYPE_F64:
                if (i == 0 && first_res) {
                    bh_assert(jit_reg_kind(first_res) == JIT_REG_KIND_F64);
                    value = first_res;
                }
                else {
                    value = jit_cc_new_reg_F64(cc);
                    GEN_INSN(LDF64, value, cc->fp_reg,
                             NEW_CONST(I32, offset_of_local(n)));
                }
                PUSH_F64(value);
                n += 2;
                break;
            default:
                bh_assert(0);
                goto fail;
        }
    }

    /* Update the committed_sp as the callee has updated the frame sp */
    cc->jit_frame->committed_sp = cc->jit_frame->sp;

    return true;
fail:
    return false;
}

bool
jit_compile_op_call(JitCompContext *cc, uint32 func_idx, bool tail_call)
{
    WASMModule *wasm_module = cc->cur_wasm_module;
    WASMFunctionImport *func_import;
    WASMFunction *func;
    WASMType *func_type;
    JitFrame *jit_frame = cc->jit_frame;
    JitReg native_ret;
    JitReg fast_jit_func_ptrs, jitted_code = 0;
    uint32 jitted_func_idx;

    if (func_idx >= wasm_module->import_function_count) {
        fast_jit_func_ptrs = get_fast_jit_func_ptrs_reg(jit_frame);
        jitted_code = jit_cc_new_reg_ptr(cc);
        /* jitted_code = func_ptrs[func_idx - import_function_count] */
        jitted_func_idx = func_idx - wasm_module->import_function_count;
        GEN_INSN(LDPTR, jitted_code, fast_jit_func_ptrs,
                 NEW_CONST(I32, (uint32)sizeof(void *) * jitted_func_idx));
    }

    if (func_idx < wasm_module->import_function_count) {
        func_import = &wasm_module->import_functions[func_idx].u.function;
        func_type = func_import->func_type;
    }
    else {
        func = wasm_module
                   ->functions[func_idx - wasm_module->import_function_count];
        func_type = func->func_type;
    }

    if (!pre_call(cc, func_type)) {
        goto fail;
    }

    if (func_idx < wasm_module->import_function_count) {
        JitReg arg_regs[3];

        native_ret = jit_cc_new_reg_I32(cc);
        arg_regs[0] = cc->exec_env_reg;
        arg_regs[1] = NEW_CONST(I32, func_idx);
        arg_regs[2] = cc->fp_reg;

        if (!jit_emit_callnative(cc, jit_invoke_native, native_ret, arg_regs,
                                 3)) {
            return false;
        }
        /* Convert bool to uint32 */
        GEN_INSN(AND, native_ret, native_ret, NEW_CONST(I32, 0xFF));

        /* Check whether there is exception thrown */
        GEN_INSN(CMP, cc->cmp_reg, native_ret, NEW_CONST(I32, 0));
        if (!jit_emit_exception(cc, JIT_EXCE_ALREADY_THROWN, JIT_OP_BEQ,
                                cc->cmp_reg, NULL)) {
            return false;
        }

        if (!post_return(cc, func_type, 0)) {
            goto fail;
        }
    }
    else {
        JitReg res = 0;

        if (func_type->result_count > 0) {
            switch (func_type->types[func_type->param_count]) {
                case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
                case VALUE_TYPE_EXTERNREF:
                case VALUE_TYPE_FUNCREF:
#endif
                    res = jit_cc_new_reg_I32(cc);
                    break;
                case VALUE_TYPE_I64:
                    res = jit_cc_new_reg_I64(cc);
                    break;
                case VALUE_TYPE_F32:
                    res = jit_cc_new_reg_F32(cc);
                    break;
                case VALUE_TYPE_F64:
                    res = jit_cc_new_reg_F64(cc);
                    break;
                default:
                    bh_assert(0);
                    goto fail;
            }
        }

        GEN_INSN(CALLBC, res, 0, jitted_code);

        if (!post_return(cc, func_type, res)) {
            goto fail;
        }
    }

    /* Clear part of memory regs and table regs as their values
       may be changed in the function call */
    if (cc->cur_wasm_module->possible_memory_grow)
        clear_memory_regs(jit_frame);
    clear_table_regs(jit_frame);

    /* Ignore tail call currently */
    (void)tail_call;
    return true;
fail:
    return false;
}

static JitReg
pack_argv(JitCompContext *cc)
{
    /* reuse the stack of the next frame */
    uint32 stack_base;
    JitReg argv;

    stack_base = cc->total_frame_size + offsetof(WASMInterpFrame, lp);
    argv = jit_cc_new_reg_ptr(cc);
    GEN_INSN(ADD, argv, cc->fp_reg, NEW_CONST(PTR, stack_base));
    if (jit_get_last_error(cc)) {
        return (JitReg)0;
    }
    return argv;
}

static bool
unpack_argv(JitCompContext *cc, const WASMType *func_type, JitReg argv)
{
    uint32 i, offset_by_cell = 0;
    JitReg value;

    /* push results in argv to stack */
    for (i = 0; i < func_type->result_count; i++) {
        switch (func_type->types[func_type->param_count + i]) {
            case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_EXTERNREF:
            case VALUE_TYPE_FUNCREF:
#endif
            {
                value = jit_cc_new_reg_I32(cc);
                GEN_INSN(LDI32, value, argv, NEW_CONST(I32, offset_by_cell));
                PUSH_I32(value);
                offset_by_cell += 4;
                break;
            }
            case VALUE_TYPE_I64:
            {
                value = jit_cc_new_reg_I64(cc);
                GEN_INSN(LDI64, value, argv, NEW_CONST(I32, offset_by_cell));
                PUSH_I64(value);
                offset_by_cell += 8;
                break;
            }
            case VALUE_TYPE_F32:
            {
                value = jit_cc_new_reg_F32(cc);
                GEN_INSN(LDF32, value, argv, NEW_CONST(I32, offset_by_cell));
                PUSH_F32(value);
                offset_by_cell += 4;
                break;
            }
            case VALUE_TYPE_F64:
            {
                value = jit_cc_new_reg_F64(cc);
                GEN_INSN(LDF64, value, argv, NEW_CONST(I32, offset_by_cell));
                PUSH_F64(value);
                offset_by_cell += 8;
                break;
            }
            default:
            {
                bh_assert(0);
                goto fail;
            }
        }
    }

    /* Update the committed_sp as the callee has updated the frame sp */
    cc->jit_frame->committed_sp = cc->jit_frame->sp;

    return true;
fail:
    return false;
}

bool
jit_compile_op_call_indirect(JitCompContext *cc, uint32 type_idx,
                             uint32 tbl_idx)
{
    JitReg elem_idx, native_ret, argv, arg_regs[6];
    WASMType *func_type;

    POP_I32(elem_idx);

    func_type = cc->cur_wasm_module->types[type_idx];
    if (!pre_call(cc, func_type)) {
        goto fail;
    }

    argv = pack_argv(cc);
    if (!argv) {
        goto fail;
    }
    native_ret = jit_cc_new_reg_I32(cc);
    arg_regs[0] = cc->exec_env_reg;
    arg_regs[1] = NEW_CONST(I32, tbl_idx);
    arg_regs[2] = elem_idx;
    arg_regs[3] = NEW_CONST(I32, type_idx);
    arg_regs[4] = NEW_CONST(I32, func_type->param_cell_num);
    arg_regs[5] = argv;

    if (!jit_emit_callnative(cc, jit_call_indirect, native_ret, arg_regs, 6)) {
        return false;
    }
    /* Convert bool to uint32 */
    GEN_INSN(AND, native_ret, native_ret, NEW_CONST(I32, 0xFF));

    /* Check whether there is exception thrown */
    GEN_INSN(CMP, cc->cmp_reg, native_ret, NEW_CONST(I32, 0));
    if (!jit_emit_exception(cc, JIT_EXCE_ALREADY_THROWN, JIT_OP_BEQ,
                            cc->cmp_reg, NULL)) {
        return false;
    }

    if (!unpack_argv(cc, func_type, argv)) {
        goto fail;
    }

    /* Clear part of memory regs and table regs as their values
       may be changed in the function call */
    if (cc->cur_wasm_module->possible_memory_grow)
        clear_memory_regs(cc->jit_frame);
    clear_table_regs(cc->jit_frame);
    return true;
fail:
    return false;
}

#if WASM_ENABLE_REF_TYPES != 0
bool
jit_compile_op_ref_null(JitCompContext *cc, uint32 ref_type)
{
    PUSH_I32(NEW_CONST(I32, NULL_REF));
    (void)ref_type;
    return true;
fail:
    return false;
}

bool
jit_compile_op_ref_is_null(JitCompContext *cc)
{
    JitReg ref, res;

    POP_I32(ref);

    GEN_INSN(CMP, cc->cmp_reg, ref, NEW_CONST(I32, NULL_REF));
    res = jit_cc_new_reg_I32(cc);
    GEN_INSN(SELECTEQ, res, cc->cmp_reg, NEW_CONST(I32, 1), NEW_CONST(I32, 0));
    PUSH_I32(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_ref_func(JitCompContext *cc, uint32 func_idx)
{
    PUSH_I32(NEW_CONST(I32, func_idx));
    return true;
fail:
    return false;
}
#endif

#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64)
bool
jit_emit_callnative(JitCompContext *cc, void *native_func, JitReg res,
                    JitReg *params, uint32 param_count)
{
    JitInsn *insn;
    char *i64_arg_names[] = { "rdi", "rsi", "rdx", "rcx", "r8", "r9" };
    char *f32_arg_names[] = { "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5" };
    char *f64_arg_names[] = { "xmm0_f64", "xmm1_f64", "xmm2_f64",
                              "xmm3_f64", "xmm4_f64", "xmm5_f64" };
    JitReg i64_arg_regs[6], f32_arg_regs[6], f64_arg_regs[6], res_hreg = 0;
    JitReg eax_hreg = jit_codegen_get_hreg_by_name("eax");
    JitReg rax_hreg = jit_codegen_get_hreg_by_name("rax");
    JitReg xmm0_hreg = jit_codegen_get_hreg_by_name("xmm0");
    JitReg xmm0_f64_hreg = jit_codegen_get_hreg_by_name("xmm0_f64");
    uint32 i, i64_reg_idx, float_reg_idx;

    bh_assert(param_count <= 6);

    for (i = 0; i < 6; i++) {
        i64_arg_regs[i] = jit_codegen_get_hreg_by_name(i64_arg_names[i]);
        f32_arg_regs[i] = jit_codegen_get_hreg_by_name(f32_arg_names[i]);
        f64_arg_regs[i] = jit_codegen_get_hreg_by_name(f64_arg_names[i]);
    }

    i64_reg_idx = float_reg_idx = 0;
    for (i = 0; i < param_count; i++) {
        switch (jit_reg_kind(params[i])) {
            case JIT_REG_KIND_I32:
                GEN_INSN(I32TOI64, i64_arg_regs[i64_reg_idx++], params[i]);
                break;
            case JIT_REG_KIND_I64:
                GEN_INSN(MOV, i64_arg_regs[i64_reg_idx++], params[i]);
                break;
            case JIT_REG_KIND_F32:
                GEN_INSN(MOV, f32_arg_regs[float_reg_idx++], params[i]);
                break;
            case JIT_REG_KIND_F64:
                GEN_INSN(MOV, f64_arg_regs[float_reg_idx++], params[i]);
                break;
            default:
                bh_assert(0);
                return false;
        }
    }

    if (res) {
        switch (jit_reg_kind(res)) {
            case JIT_REG_KIND_I32:
                res_hreg = eax_hreg;
                break;
            case JIT_REG_KIND_I64:
                res_hreg = rax_hreg;
                break;
            case JIT_REG_KIND_F32:
                res_hreg = xmm0_hreg;
                break;
            case JIT_REG_KIND_F64:
                res_hreg = xmm0_f64_hreg;
                break;
            default:
                bh_assert(0);
                return false;
        }
    }

    insn = GEN_INSN(CALLNATIVE, res_hreg,
                    NEW_CONST(PTR, (uintptr_t)native_func), param_count);
    if (!insn) {
        return false;
    }

    i64_reg_idx = float_reg_idx = 0;
    for (i = 0; i < param_count; i++) {
        switch (jit_reg_kind(params[i])) {
            case JIT_REG_KIND_I32:
            case JIT_REG_KIND_I64:
                *(jit_insn_opndv(insn, i + 2)) = i64_arg_regs[i64_reg_idx++];
                break;
            case JIT_REG_KIND_F32:
                *(jit_insn_opndv(insn, i + 2)) = f32_arg_regs[float_reg_idx++];
                break;
            case JIT_REG_KIND_F64:
                *(jit_insn_opndv(insn, i + 2)) = f64_arg_regs[float_reg_idx++];
                break;
            default:
                bh_assert(0);
                return false;
        }
    }

    if (res) {
        GEN_INSN(MOV, res, res_hreg);
    }

    return true;
}
#else
bool
jit_emit_callnative(JitCompContext *cc, void *native_func, JitReg res,
                    JitReg *params, uint32 param_count)
{
    JitInsn *insn;
    uint32 i;

    bh_assert(param_count <= 6);

    insn = GEN_INSN(CALLNATIVE, res, NEW_CONST(PTR, (uintptr_t)native_func),
                    param_count);
    if (!insn)
        return false;

    for (i = 0; i < param_count; i++) {
        *(jit_insn_opndv(insn, i + 2)) = params[i];
    }
    return true;
}
#endif
