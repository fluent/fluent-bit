/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_emit_table.h"
#include "jit_emit_exception.h"
#include "jit_emit_function.h"
#include "../../interpreter/wasm_runtime.h"
#include "../jit_frontend.h"

#if WASM_ENABLE_REF_TYPES != 0
static void
wasm_elem_drop(WASMModuleInstance *inst, uint32 tbl_seg_idx)
{
    bh_bitmap_set_bit(inst->e->common.elem_dropped, tbl_seg_idx);
}

bool
jit_compile_op_elem_drop(JitCompContext *cc, uint32 tbl_seg_idx)
{
    JitReg args[2] = { 0 };

    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = NEW_CONST(I32, tbl_seg_idx);

    return jit_emit_callnative(cc, wasm_elem_drop, 0, args,
                               sizeof(args) / sizeof(args[0]));
}

bool
jit_compile_op_table_get(JitCompContext *cc, uint32 tbl_idx)
{
    JitReg elem_idx, tbl_sz, tbl_elems, elem_idx_long, offset, res;

    POP_I32(elem_idx);

    /* if (elem_idx >= tbl_sz) goto exception; */
    tbl_sz = get_table_cur_size_reg(cc->jit_frame, tbl_idx);
    GEN_INSN(CMP, cc->cmp_reg, elem_idx, tbl_sz);
    if (!jit_emit_exception(cc, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS, JIT_OP_BGEU,
                            cc->cmp_reg, NULL))
        goto fail;

    elem_idx_long = jit_cc_new_reg_I64(cc);
    GEN_INSN(I32TOI64, elem_idx_long, elem_idx);

    offset = jit_cc_new_reg_I64(cc);
    GEN_INSN(MUL, offset, elem_idx_long, NEW_CONST(I64, sizeof(uint32)));

    res = jit_cc_new_reg_I32(cc);
    tbl_elems = get_table_elems_reg(cc->jit_frame, tbl_idx);
    GEN_INSN(LDI32, res, tbl_elems, offset);
    PUSH_I32(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_table_set(JitCompContext *cc, uint32 tbl_idx)
{
    JitReg elem_idx, elem_val, tbl_sz, tbl_elems, elem_idx_long, offset;

    POP_I32(elem_val);
    POP_I32(elem_idx);

    /* if (elem_idx >= tbl_sz) goto exception; */
    tbl_sz = get_table_cur_size_reg(cc->jit_frame, tbl_idx);
    GEN_INSN(CMP, cc->cmp_reg, elem_idx, tbl_sz);
    if (!jit_emit_exception(cc, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS, JIT_OP_BGEU,
                            cc->cmp_reg, NULL))
        goto fail;

    elem_idx_long = jit_cc_new_reg_I64(cc);
    GEN_INSN(I32TOI64, elem_idx_long, elem_idx);

    offset = jit_cc_new_reg_I64(cc);
    GEN_INSN(MUL, offset, elem_idx_long, NEW_CONST(I64, sizeof(uint32)));

    tbl_elems = get_table_elems_reg(cc->jit_frame, tbl_idx);
    GEN_INSN(STI32, elem_val, tbl_elems, offset);

    return true;
fail:
    return false;
}

static int
wasm_init_table(WASMModuleInstance *inst, uint32 tbl_idx, uint32 seg_idx,
                uint32 dst_offset, uint32 len, uint32 src_offset)
{
    WASMTableInstance *tbl;
    uint32 tbl_sz;
    WASMTableSeg *tbl_seg = inst->module->table_segments + seg_idx;
    uint32 *tbl_seg_elems = NULL, tbl_seg_len = 0;

    if (!bh_bitmap_get_bit(inst->e->common.elem_dropped, seg_idx)) {
        /* table segment isn't dropped */
        tbl_seg_elems = tbl_seg->func_indexes;
        tbl_seg_len = tbl_seg->function_count;
    }

    if (offset_len_out_of_bounds(src_offset, len, tbl_seg_len))
        goto out_of_bounds;

    tbl = inst->tables[tbl_idx];
    tbl_sz = tbl->cur_size;
    if (offset_len_out_of_bounds(dst_offset, len, tbl_sz))
        goto out_of_bounds;

    if (!len)
        return 0;

    bh_memcpy_s((uint8 *)tbl + offsetof(WASMTableInstance, elems)
                    + dst_offset * sizeof(uint32),
                (uint32)((tbl_sz - dst_offset) * sizeof(uint32)),
                tbl_seg_elems + src_offset, (uint32)(len * sizeof(uint32)));

    return 0;
out_of_bounds:
    wasm_set_exception(inst, "out of bounds table access");
    return -1;
}

bool
jit_compile_op_table_init(JitCompContext *cc, uint32 tbl_idx,
                          uint32 tbl_seg_idx)
{
    JitReg len, src, dst, res;
    JitReg args[6] = { 0 };

    POP_I32(len);
    POP_I32(src);
    POP_I32(dst);

    res = jit_cc_new_reg_I32(cc);
    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = NEW_CONST(I32, tbl_idx);
    args[2] = NEW_CONST(I32, tbl_seg_idx);
    args[3] = dst;
    args[4] = len;
    args[5] = src;

    if (!jit_emit_callnative(cc, wasm_init_table, res, args,
                             sizeof(args) / sizeof(args[0])))
        goto fail;

    GEN_INSN(CMP, cc->cmp_reg, res, NEW_CONST(I32, 0));
    if (!jit_emit_exception(cc, EXCE_ALREADY_THROWN, JIT_OP_BLTS, cc->cmp_reg,
                            NULL))
        goto fail;

    return true;
fail:
    return false;
}

static int
wasm_copy_table(WASMModuleInstance *inst, uint32 src_tbl_idx,
                uint32 dst_tbl_idx, uint32 dst_offset, uint32 len,
                uint32 src_offset)
{
    WASMTableInstance *src_tbl, *dst_tbl;
    uint32 src_tbl_sz, dst_tbl_sz;

    dst_tbl = inst->tables[dst_tbl_idx];
    dst_tbl_sz = dst_tbl->cur_size;
    if (offset_len_out_of_bounds(dst_offset, len, dst_tbl_sz))
        goto out_of_bounds;

    src_tbl = inst->tables[src_tbl_idx];
    src_tbl_sz = src_tbl->cur_size;
    if (offset_len_out_of_bounds(src_offset, len, src_tbl_sz))
        goto out_of_bounds;

    bh_memmove_s((uint8 *)dst_tbl + offsetof(WASMTableInstance, elems)
                     + dst_offset * sizeof(uint32),
                 (uint32)((dst_tbl_sz - dst_offset) * sizeof(uint32)),
                 (uint8 *)src_tbl + offsetof(WASMTableInstance, elems)
                     + src_offset * sizeof(uint32),
                 (uint32)(len * sizeof(uint32)));

    return 0;
out_of_bounds:
    wasm_set_exception(inst, "out of bounds table access");
    return -1;
}

bool
jit_compile_op_table_copy(JitCompContext *cc, uint32 src_tbl_idx,
                          uint32 dst_tbl_idx)
{
    JitReg len, src, dst, res;
    JitReg args[6] = { 0 };

    POP_I32(len);
    POP_I32(src);
    POP_I32(dst);

    res = jit_cc_new_reg_I32(cc);
    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = NEW_CONST(I32, src_tbl_idx);
    args[2] = NEW_CONST(I32, dst_tbl_idx);
    args[3] = dst;
    args[4] = len;
    args[5] = src;

    if (!jit_emit_callnative(cc, wasm_copy_table, res, args,
                             sizeof(args) / sizeof(args[0])))
        goto fail;

    GEN_INSN(CMP, cc->cmp_reg, res, NEW_CONST(I32, 0));
    if (!jit_emit_exception(cc, EXCE_ALREADY_THROWN, JIT_OP_BLTS, cc->cmp_reg,
                            NULL))
        goto fail;

    return true;
fail:
    return false;
}

bool
jit_compile_op_table_size(JitCompContext *cc, uint32 tbl_idx)
{
    JitReg res;

    res = get_table_cur_size_reg(cc->jit_frame, tbl_idx);
    PUSH_I32(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_table_grow(JitCompContext *cc, uint32 tbl_idx)
{
    JitReg tbl_sz, n, val, enlarge_ret, res;
    JitReg args[4] = { 0 };

    POP_I32(n);
    POP_I32(val);

    tbl_sz = get_table_cur_size_reg(cc->jit_frame, tbl_idx);

    enlarge_ret = jit_cc_new_reg_I32(cc);
    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = NEW_CONST(I32, tbl_idx);
    args[2] = n;
    args[3] = val;

    if (!jit_emit_callnative(cc, wasm_enlarge_table, enlarge_ret, args,
                             sizeof(args) / sizeof(args[0])))
        goto fail;

    /* Convert bool to uint32 */
    GEN_INSN(AND, enlarge_ret, enlarge_ret, NEW_CONST(I32, 0xFF));

    res = jit_cc_new_reg_I32(cc);
    GEN_INSN(CMP, cc->cmp_reg, enlarge_ret, NEW_CONST(I32, 1));
    GEN_INSN(SELECTEQ, res, cc->cmp_reg, tbl_sz, NEW_CONST(I32, -1));
    PUSH_I32(res);

    /* Ensure a refresh in next get memory related registers */
    clear_table_regs(cc->jit_frame);
    return true;
fail:
    return false;
}

static int
wasm_fill_table(WASMModuleInstance *inst, uint32 tbl_idx, uint32 dst_offset,
                uint32 val, uint32 len)
{
    WASMTableInstance *tbl;
    uint32 tbl_sz;

    tbl = inst->tables[tbl_idx];
    tbl_sz = tbl->cur_size;

    if (offset_len_out_of_bounds(dst_offset, len, tbl_sz))
        goto out_of_bounds;

    for (; len != 0; dst_offset++, len--) {
        tbl->elems[dst_offset] = val;
    }

    return 0;
out_of_bounds:
    wasm_set_exception(inst, "out of bounds table access");
    return -1;
}

bool
jit_compile_op_table_fill(JitCompContext *cc, uint32 tbl_idx)
{
    JitReg len, val, dst, res;
    JitReg args[5] = { 0 };

    POP_I32(len);
    POP_I32(val);
    POP_I32(dst);

    res = jit_cc_new_reg_I32(cc);
    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = NEW_CONST(I32, tbl_idx);
    args[2] = dst;
    args[3] = val;
    args[4] = len;

    if (!jit_emit_callnative(cc, wasm_fill_table, res, args,
                             sizeof(args) / sizeof(args[0])))
        goto fail;

    GEN_INSN(CMP, cc->cmp_reg, res, NEW_CONST(I32, 0));
    if (!jit_emit_exception(cc, EXCE_ALREADY_THROWN, JIT_OP_BLTS, cc->cmp_reg,
                            NULL))
        goto fail;

    return true;
fail:
    return false;
}
#endif
