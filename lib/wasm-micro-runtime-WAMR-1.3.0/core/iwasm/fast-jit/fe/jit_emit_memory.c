/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_emit_memory.h"
#include "jit_emit_exception.h"
#include "jit_emit_function.h"
#include "../jit_frontend.h"
#include "../jit_codegen.h"
#include "../../interpreter/wasm_runtime.h"
#include "jit_emit_control.h"

#ifndef OS_ENABLE_HW_BOUND_CHECK
static JitReg
get_memory_boundary(JitCompContext *cc, uint32 mem_idx, uint32 bytes)
{
    JitReg memory_boundary;

    switch (bytes) {
        case 1:
        {
            memory_boundary =
                get_mem_bound_check_1byte_reg(cc->jit_frame, mem_idx);
            break;
        }
        case 2:
        {
            memory_boundary =
                get_mem_bound_check_2bytes_reg(cc->jit_frame, mem_idx);
            break;
        }
        case 4:
        {
            memory_boundary =
                get_mem_bound_check_4bytes_reg(cc->jit_frame, mem_idx);
            break;
        }
        case 8:
        {
            memory_boundary =
                get_mem_bound_check_8bytes_reg(cc->jit_frame, mem_idx);
            break;
        }
        case 16:
        {
            memory_boundary =
                get_mem_bound_check_16bytes_reg(cc->jit_frame, mem_idx);
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

    return memory_boundary;
fail:
    return 0;
}
#endif

#if WASM_ENABLE_SHARED_MEMORY != 0
static void
set_load_or_store_atomic(JitInsn *load_or_store_inst)
{
    load_or_store_inst->flags_u8 |= 0x1;
}
#endif

#if UINTPTR_MAX == UINT64_MAX
static JitReg
check_and_seek_on_64bit_platform(JitCompContext *cc, JitReg addr, JitReg offset,
                                 JitReg memory_boundary)
{
    JitReg long_addr, offset1;

    /* long_addr = (int64_t)addr */
    long_addr = jit_cc_new_reg_I64(cc);
    GEN_INSN(U32TOI64, long_addr, addr);

    /* offset1 = offset + long_addr */
    offset1 = jit_cc_new_reg_I64(cc);
    GEN_INSN(ADD, offset1, offset, long_addr);

#ifndef OS_ENABLE_HW_BOUND_CHECK
    /* if (offset1 > memory_boundary) goto EXCEPTION */
    GEN_INSN(CMP, cc->cmp_reg, offset1, memory_boundary);
    if (!jit_emit_exception(cc, EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS, JIT_OP_BGTU,
                            cc->cmp_reg, NULL)) {
        goto fail;
    }
#endif

    return offset1;
#ifndef OS_ENABLE_HW_BOUND_CHECK
fail:
    return 0;
#endif
}
#else
static JitReg
check_and_seek_on_32bit_platform(JitCompContext *cc, JitReg addr, JitReg offset,
                                 JitReg memory_boundary)
{
    JitReg offset1;

    /* offset1 = offset + addr */
    offset1 = jit_cc_new_reg_I32(cc);
    GEN_INSN(ADD, offset1, offset, addr);

    /* if (offset1 < addr) goto EXCEPTION */
    GEN_INSN(CMP, cc->cmp_reg, offset1, addr);
    if (!jit_emit_exception(cc, EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS, JIT_OP_BLTU,
                            cc->cmp_reg, NULL)) {
        goto fail;
    }

#ifndef OS_ENABLE_HW_BOUND_CHECK
    /* if (offset1 > memory_boundary) goto EXCEPTION */
    GEN_INSN(CMP, cc->cmp_reg, offset1, memory_boundary);
    if (!jit_emit_exception(cc, EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS, JIT_OP_BGTU,
                            cc->cmp_reg, NULL)) {
        goto fail;
    }
#endif

    return offset1;
fail:
    return 0;
}
#endif

static JitReg
check_and_seek(JitCompContext *cc, JitReg addr, uint32 offset, uint32 bytes)
{
    JitReg memory_boundary = 0, offset1;
#ifndef OS_ENABLE_HW_BOUND_CHECK
    JitReg cur_page_count;
    /* the default memory */
    uint32 mem_idx = 0;
#endif

#ifndef OS_ENABLE_HW_BOUND_CHECK
    /* ---------- check ---------- */
    /* 1. shortcut if the memory size is 0 */
    if (cc->cur_wasm_module->memories != NULL
        && 0 == cc->cur_wasm_module->memories[mem_idx].init_page_count) {

        cur_page_count = get_cur_page_count_reg(cc->jit_frame, mem_idx);

        /* if (cur_mem_page_count == 0) goto EXCEPTION */
        GEN_INSN(CMP, cc->cmp_reg, cur_page_count, NEW_CONST(I32, 0));
        if (!jit_emit_exception(cc, EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS,
                                JIT_OP_BEQ, cc->cmp_reg, NULL)) {
            goto fail;
        }
    }

    /* 2. a complete boundary check */
    memory_boundary = get_memory_boundary(cc, mem_idx, bytes);
    if (!memory_boundary)
        goto fail;
#endif

#if UINTPTR_MAX == UINT64_MAX
    offset1 = check_and_seek_on_64bit_platform(cc, addr, NEW_CONST(I64, offset),
                                               memory_boundary);
    if (!offset1)
        goto fail;
#else
    offset1 = check_and_seek_on_32bit_platform(cc, addr, NEW_CONST(I32, offset),
                                               memory_boundary);
    if (!offset1)
        goto fail;
#endif

    return offset1;
fail:
    return 0;
}

#if UINTPTR_MAX == UINT64_MAX
#define CHECK_ALIGNMENT(offset1)                                       \
    do {                                                               \
        JitReg align_mask = NEW_CONST(I64, ((uint64)1 << align) - 1);  \
        JitReg AND_res = jit_cc_new_reg_I64(cc);                       \
        GEN_INSN(AND, AND_res, offset1, align_mask);                   \
        GEN_INSN(CMP, cc->cmp_reg, AND_res, NEW_CONST(I64, 0));        \
        if (!jit_emit_exception(cc, EXCE_UNALIGNED_ATOMIC, JIT_OP_BNE, \
                                cc->cmp_reg, NULL))                    \
            goto fail;                                                 \
    } while (0)
#else
#define CHECK_ALIGNMENT(offset1)                                       \
    do {                                                               \
        JitReg align_mask = NEW_CONST(I32, (1 << align) - 1);          \
        JitReg AND_res = jit_cc_new_reg_I32(cc);                       \
        GEN_INSN(AND, AND_res, offset1, align_mask);                   \
        GEN_INSN(CMP, cc->cmp_reg, AND_res, NEW_CONST(I32, 0));        \
        if (!jit_emit_exception(cc, EXCE_UNALIGNED_ATOMIC, JIT_OP_BNE, \
                                cc->cmp_reg, NULL))                    \
            goto fail;                                                 \
    } while (0)
#endif

bool
jit_compile_op_i32_load(JitCompContext *cc, uint32 align, uint32 offset,
                        uint32 bytes, bool sign, bool atomic)
{
    JitReg addr, offset1, value, memory_data;
    JitInsn *load_insn = NULL;

    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1) {
        goto fail;
    }
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic) {
        CHECK_ALIGNMENT(offset1);
    }
#endif

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    value = jit_cc_new_reg_I32(cc);
    switch (bytes) {
        case 1:
        {
            if (sign) {
                load_insn = GEN_INSN(LDI8, value, memory_data, offset1);
            }
            else {
                load_insn = GEN_INSN(LDU8, value, memory_data, offset1);
            }
            break;
        }
        case 2:
        {
            if (sign) {
                load_insn = GEN_INSN(LDI16, value, memory_data, offset1);
            }
            else {
                load_insn = GEN_INSN(LDU16, value, memory_data, offset1);
            }
            break;
        }
        case 4:
        {
            if (sign) {
                load_insn = GEN_INSN(LDI32, value, memory_data, offset1);
            }
            else {
                load_insn = GEN_INSN(LDU32, value, memory_data, offset1);
            }
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic && load_insn)
        set_load_or_store_atomic(load_insn);
#else
    (void)load_insn;
#endif

    PUSH_I32(value);
    return true;
fail:
    return false;
}

bool
jit_compile_op_i64_load(JitCompContext *cc, uint32 align, uint32 offset,
                        uint32 bytes, bool sign, bool atomic)
{
    JitReg addr, offset1, value, memory_data;
    JitInsn *load_insn = NULL;

    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1) {
        goto fail;
    }
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic) {
        CHECK_ALIGNMENT(offset1);
    }
#endif

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    value = jit_cc_new_reg_I64(cc);
    switch (bytes) {
        case 1:
        {
            if (sign) {
                load_insn = GEN_INSN(LDI8, value, memory_data, offset1);
            }
            else {
                load_insn = GEN_INSN(LDU8, value, memory_data, offset1);
            }
            break;
        }
        case 2:
        {
            if (sign) {
                load_insn = GEN_INSN(LDI16, value, memory_data, offset1);
            }
            else {
                load_insn = GEN_INSN(LDU16, value, memory_data, offset1);
            }
            break;
        }
        case 4:
        {
            if (sign) {
                load_insn = GEN_INSN(LDI32, value, memory_data, offset1);
            }
            else {
                load_insn = GEN_INSN(LDU32, value, memory_data, offset1);
            }
            break;
        }
        case 8:
        {
            if (sign) {
                load_insn = GEN_INSN(LDI64, value, memory_data, offset1);
            }
            else {
                load_insn = GEN_INSN(LDU64, value, memory_data, offset1);
            }
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic && load_insn)
        set_load_or_store_atomic(load_insn);
#else
    (void)load_insn;
#endif

    PUSH_I64(value);
    return true;
fail:
    return false;
}

bool
jit_compile_op_f32_load(JitCompContext *cc, uint32 align, uint32 offset)
{
    JitReg addr, offset1, value, memory_data;

    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, 4);
    if (!offset1) {
        goto fail;
    }

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    value = jit_cc_new_reg_F32(cc);
    GEN_INSN(LDF32, value, memory_data, offset1);

    PUSH_F32(value);
    return true;
fail:
    return false;
}

bool
jit_compile_op_f64_load(JitCompContext *cc, uint32 align, uint32 offset)
{
    JitReg addr, offset1, value, memory_data;

    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, 8);
    if (!offset1) {
        goto fail;
    }

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    value = jit_cc_new_reg_F64(cc);
    GEN_INSN(LDF64, value, memory_data, offset1);

    PUSH_F64(value);
    return true;
fail:
    return false;
}

bool
jit_compile_op_i32_store(JitCompContext *cc, uint32 align, uint32 offset,
                         uint32 bytes, bool atomic)
{
    JitReg value, addr, offset1, memory_data;
    JitInsn *store_insn = NULL;

    POP_I32(value);
    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1) {
        goto fail;
    }
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic) {
        CHECK_ALIGNMENT(offset1);
    }
#endif

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    switch (bytes) {
        case 1:
        {
            store_insn = GEN_INSN(STI8, value, memory_data, offset1);
            break;
        }
        case 2:
        {
            store_insn = GEN_INSN(STI16, value, memory_data, offset1);
            break;
        }
        case 4:
        {
            store_insn = GEN_INSN(STI32, value, memory_data, offset1);
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic && store_insn)
        set_load_or_store_atomic(store_insn);
#else
    (void)store_insn;
#endif

    return true;
fail:
    return false;
}

bool
jit_compile_op_i64_store(JitCompContext *cc, uint32 align, uint32 offset,
                         uint32 bytes, bool atomic)
{
    JitReg value, addr, offset1, memory_data;
    JitInsn *store_insn = NULL;

    POP_I64(value);
    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1) {
        goto fail;
    }
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic) {
        CHECK_ALIGNMENT(offset1);
    }
#endif

    if (jit_reg_is_const(value) && bytes < 8) {
        value = NEW_CONST(I32, (int32)jit_cc_get_const_I64(cc, value));
    }

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    switch (bytes) {
        case 1:
        {
            store_insn = GEN_INSN(STI8, value, memory_data, offset1);
            break;
        }
        case 2:
        {
            store_insn = GEN_INSN(STI16, value, memory_data, offset1);
            break;
        }
        case 4:
        {
            store_insn = GEN_INSN(STI32, value, memory_data, offset1);
            break;
        }
        case 8:
        {
            store_insn = GEN_INSN(STI64, value, memory_data, offset1);
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic && store_insn)
        set_load_or_store_atomic(store_insn);
#else
    (void)store_insn;
#endif

    return true;
fail:
    return false;
}

bool
jit_compile_op_f32_store(JitCompContext *cc, uint32 align, uint32 offset)
{
    JitReg value, addr, offset1, memory_data;

    POP_F32(value);
    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, 4);
    if (!offset1) {
        goto fail;
    }

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    GEN_INSN(STF32, value, memory_data, offset1);

    return true;
fail:
    return false;
}

bool
jit_compile_op_f64_store(JitCompContext *cc, uint32 align, uint32 offset)
{
    JitReg value, addr, offset1, memory_data;

    POP_F64(value);
    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, 8);
    if (!offset1) {
        goto fail;
    }

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    GEN_INSN(STF64, value, memory_data, offset1);

    return true;
fail:
    return false;
}

bool
jit_compile_op_memory_size(JitCompContext *cc, uint32 mem_idx)
{
    JitReg cur_page_count;

    cur_page_count = get_cur_page_count_reg(cc->jit_frame, mem_idx);

    PUSH_I32(cur_page_count);

    return true;
fail:
    return false;
}

bool
jit_compile_op_memory_grow(JitCompContext *cc, uint32 mem_idx)
{
    JitReg grow_res, res;
    JitReg prev_page_count, inc_page_count, args[2];

    /* Get current page count as prev_page_count */
    prev_page_count = get_cur_page_count_reg(cc->jit_frame, mem_idx);

    /* Call wasm_enlarge_memory */
    POP_I32(inc_page_count);

    grow_res = jit_cc_new_reg_I32(cc);
    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = inc_page_count;

    if (!jit_emit_callnative(cc, wasm_enlarge_memory, grow_res, args, 2)) {
        goto fail;
    }
    /* Convert bool to uint32 */
    GEN_INSN(AND, grow_res, grow_res, NEW_CONST(I32, 0xFF));

    /* return different values according to memory.grow result */
    res = jit_cc_new_reg_I32(cc);
    GEN_INSN(CMP, cc->cmp_reg, grow_res, NEW_CONST(I32, 0));
    GEN_INSN(SELECTNE, res, cc->cmp_reg, prev_page_count,
             NEW_CONST(I32, (int32)-1));
    PUSH_I32(res);

    /* Ensure a refresh in next get memory related registers */
    clear_memory_regs(cc->jit_frame);

    return true;
fail:
    return false;
}

#if WASM_ENABLE_BULK_MEMORY != 0
static int
wasm_init_memory(WASMModuleInstance *inst, uint32 mem_idx, uint32 seg_idx,
                 uint32 len, uint32 mem_offset, uint32 data_offset)
{
    WASMMemoryInstance *mem_inst;
    WASMDataSeg *data_segment;
    uint32 mem_size;
    uint8 *mem_addr, *data_addr;
    uint32 seg_len;

    /* if d + n > the length of mem.data */
    mem_inst = inst->memories[mem_idx];
    mem_size = mem_inst->cur_page_count * mem_inst->num_bytes_per_page;
    if (mem_size < mem_offset || mem_size - mem_offset < len)
        goto out_of_bounds;

    /* if s + n > the length of data.data */
    bh_assert(seg_idx < inst->module->data_seg_count);
    if (bh_bitmap_get_bit(inst->e->common.data_dropped, seg_idx)) {
        seg_len = 0;
        data_addr = NULL;
    }
    else {
        data_segment = inst->module->data_segments[seg_idx];
        seg_len = data_segment->data_length;
        data_addr = data_segment->data + data_offset;
    }
    if (seg_len < data_offset || seg_len - data_offset < len)
        goto out_of_bounds;

    mem_addr = mem_inst->memory_data + mem_offset;
    bh_memcpy_s(mem_addr, mem_size - mem_offset, data_addr, len);

    return 0;
out_of_bounds:
    wasm_set_exception(inst, "out of bounds memory access");
    return -1;
}

bool
jit_compile_op_memory_init(JitCompContext *cc, uint32 mem_idx, uint32 seg_idx)
{
    JitReg len, mem_offset, data_offset, res;
    JitReg args[6] = { 0 };

    POP_I32(len);
    POP_I32(data_offset);
    POP_I32(mem_offset);

    res = jit_cc_new_reg_I32(cc);
    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = NEW_CONST(I32, mem_idx);
    args[2] = NEW_CONST(I32, seg_idx);
    args[3] = len;
    args[4] = mem_offset;
    args[5] = data_offset;

    if (!jit_emit_callnative(cc, wasm_init_memory, res, args,
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

static void
wasm_data_drop(WASMModuleInstance *inst, uint32 seg_idx)
{
    bh_bitmap_set_bit(inst->e->common.data_dropped, seg_idx);
}

bool
jit_compile_op_data_drop(JitCompContext *cc, uint32 seg_idx)
{
    JitReg args[2] = { 0 };

    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = NEW_CONST(I32, seg_idx);

    return jit_emit_callnative(cc, wasm_data_drop, 0, args,
                               sizeof(args) / sizeof(args[0]));
}

static int
wasm_copy_memory(WASMModuleInstance *inst, uint32 src_mem_idx,
                 uint32 dst_mem_idx, uint32 len, uint32 src_offset,
                 uint32 dst_offset)
{
    WASMMemoryInstance *src_mem, *dst_mem;
    uint32 src_mem_size, dst_mem_size;
    uint8 *src_addr, *dst_addr;

    src_mem = inst->memories[src_mem_idx];
    dst_mem = inst->memories[dst_mem_idx];
    src_mem_size = src_mem->cur_page_count * src_mem->num_bytes_per_page;
    dst_mem_size = dst_mem->cur_page_count * dst_mem->num_bytes_per_page;

    /* if s + n > the length of mem.data */
    if (src_mem_size < src_offset || src_mem_size - src_offset < len)
        goto out_of_bounds;

    /* if d + n > the length of mem.data */
    if (dst_mem_size < dst_offset || dst_mem_size - dst_offset < len)
        goto out_of_bounds;

    src_addr = src_mem->memory_data + src_offset;
    dst_addr = dst_mem->memory_data + dst_offset;
    /* allowing the destination and source to overlap */
    bh_memmove_s(dst_addr, dst_mem_size - dst_offset, src_addr, len);

    return 0;
out_of_bounds:
    wasm_set_exception(inst, "out of bounds memory access");
    return -1;
}

bool
jit_compile_op_memory_copy(JitCompContext *cc, uint32 src_mem_idx,
                           uint32 dst_mem_idx)
{
    JitReg len, src, dst, res;
    JitReg args[6] = { 0 };

    POP_I32(len);
    POP_I32(src);
    POP_I32(dst);

    res = jit_cc_new_reg_I32(cc);
    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = NEW_CONST(I32, src_mem_idx);
    args[2] = NEW_CONST(I32, dst_mem_idx);
    args[3] = len;
    args[4] = src;
    args[5] = dst;

    if (!jit_emit_callnative(cc, wasm_copy_memory, res, args,
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
wasm_fill_memory(WASMModuleInstance *inst, uint32 mem_idx, uint32 len,
                 uint32 val, uint32 dst)
{
    WASMMemoryInstance *mem_inst;
    uint32 mem_size;
    uint8 *dst_addr;

    mem_inst = inst->memories[mem_idx];
    mem_size = mem_inst->cur_page_count * mem_inst->num_bytes_per_page;

    if (mem_size < dst || mem_size - dst < len)
        goto out_of_bounds;

    dst_addr = mem_inst->memory_data + dst;
    memset(dst_addr, val, len);

    return 0;
out_of_bounds:
    wasm_set_exception(inst, "out of bounds memory access");
    return -1;
}

bool
jit_compile_op_memory_fill(JitCompContext *cc, uint32 mem_idx)
{
    JitReg res, len, val, dst;
    JitReg args[5] = { 0 };

    POP_I32(len);
    POP_I32(val);
    POP_I32(dst);

    res = jit_cc_new_reg_I32(cc);
    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = NEW_CONST(I32, mem_idx);
    args[2] = len;
    args[3] = val;
    args[4] = dst;

    if (!jit_emit_callnative(cc, wasm_fill_memory, res, args,
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

#if WASM_ENABLE_SHARED_MEMORY != 0
#define GEN_AT_RMW_INSN(op, op_type, bytes, result, value, memory_data,       \
                        offset1)                                              \
    do {                                                                      \
        switch (bytes) {                                                      \
            case 1:                                                           \
            {                                                                 \
                insn = GEN_INSN(AT_##op##U8, result, value, memory_data,      \
                                offset1);                                     \
                break;                                                        \
            }                                                                 \
            case 2:                                                           \
            {                                                                 \
                insn = GEN_INSN(AT_##op##U16, result, value, memory_data,     \
                                offset1);                                     \
                break;                                                        \
            }                                                                 \
            case 4:                                                           \
            {                                                                 \
                if (op_type == VALUE_TYPE_I32)                                \
                    insn = GEN_INSN(AT_##op##I32, result, value, memory_data, \
                                    offset1);                                 \
                else                                                          \
                    insn = GEN_INSN(AT_##op##U32, result, value, memory_data, \
                                    offset1);                                 \
                break;                                                        \
            }                                                                 \
            case 8:                                                           \
            {                                                                 \
                insn = GEN_INSN(AT_##op##I64, result, value, memory_data,     \
                                offset1);                                     \
                break;                                                        \
            }                                                                 \
            default:                                                          \
            {                                                                 \
                bh_assert(0);                                                 \
                goto fail;                                                    \
            }                                                                 \
        }                                                                     \
    } while (0)

bool
jit_compile_op_atomic_rmw(JitCompContext *cc, uint8 atomic_op, uint8 op_type,
                          uint32 align, uint32 offset, uint32 bytes)
{
    JitReg addr, offset1, memory_data, value, result, eax_hreg, rax_hreg,
        ebx_hreg, rbx_hreg;
    JitInsn *insn = NULL;
    bool is_i32 = op_type == VALUE_TYPE_I32;
    bool is_logical_op = atomic_op == AtomicRMWBinOpAnd
                         || atomic_op == AtomicRMWBinOpOr
                         || atomic_op == AtomicRMWBinOpXor;

    /* currently we only implement atomic rmw on x86-64 target */
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64)

    /* For atomic logical binary ops, it implicitly uses rax in cmpxchg
     * instruction and implicitly uses rbx for storing temp value in the
     * generated loop */
    eax_hreg = jit_codegen_get_hreg_by_name("eax");
    rax_hreg = jit_codegen_get_hreg_by_name("rax");
    ebx_hreg = jit_codegen_get_hreg_by_name("ebx");
    rbx_hreg = jit_codegen_get_hreg_by_name("rbx");

    bh_assert(op_type == VALUE_TYPE_I32 || op_type == VALUE_TYPE_I64);
    if (op_type == VALUE_TYPE_I32) {
        POP_I32(value);
    }
    else {
        POP_I64(value);
    }
    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1) {
        goto fail;
    }
    CHECK_ALIGNMENT(offset1);

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    if (op_type == VALUE_TYPE_I32)
        result = jit_cc_new_reg_I32(cc);
    else
        result = jit_cc_new_reg_I64(cc);

    switch (atomic_op) {
        case AtomicRMWBinOpAdd:
        {
            GEN_AT_RMW_INSN(ADD, op_type, bytes, result, value, memory_data,
                            offset1);
            break;
        }
        case AtomicRMWBinOpSub:
        {
            GEN_AT_RMW_INSN(SUB, op_type, bytes, result, value, memory_data,
                            offset1);
            break;
        }
        case AtomicRMWBinOpAnd:
        {
            GEN_AT_RMW_INSN(AND, op_type, bytes, result, value, memory_data,
                            offset1);
            break;
        }
        case AtomicRMWBinOpOr:
        {
            GEN_AT_RMW_INSN(OR, op_type, bytes, result, value, memory_data,
                            offset1);
            break;
        }
        case AtomicRMWBinOpXor:
        {
            GEN_AT_RMW_INSN(XOR, op_type, bytes, result, value, memory_data,
                            offset1);
            break;
        }
        case AtomicRMWBinOpXchg:
        {
            GEN_AT_RMW_INSN(XCHG, op_type, bytes, result, value, memory_data,
                            offset1);
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

    if (is_logical_op
        && (!insn
            || !jit_lock_reg_in_insn(cc, insn, is_i32 ? eax_hreg : rax_hreg)
            || !jit_lock_reg_in_insn(cc, insn, is_i32 ? ebx_hreg : rbx_hreg))) {
        jit_set_last_error(
            cc, "generate atomic logical insn or lock ra&rb hreg failed");
        goto fail;
    }

    if (op_type == VALUE_TYPE_I32)
        PUSH_I32(result);
    else
        PUSH_I64(result);

    return true;
#endif /* defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64) */

fail:
    return false;
}

bool
jit_compile_op_atomic_cmpxchg(JitCompContext *cc, uint8 op_type, uint32 align,
                              uint32 offset, uint32 bytes)
{
    JitReg addr, offset1, memory_data, value, expect, result;
    bool is_i32 = op_type == VALUE_TYPE_I32;
    /* currently we only implement atomic cmpxchg on x86-64 target */
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64)
    /* cmpxchg will use register al/ax/eax/rax to store parameter expected
     * value, and the read result will also be stored to al/ax/eax/rax */
    JitReg eax_hreg = jit_codegen_get_hreg_by_name("eax");
    JitReg rax_hreg = jit_codegen_get_hreg_by_name("rax");
    JitInsn *insn = NULL;

    bh_assert(op_type == VALUE_TYPE_I32 || op_type == VALUE_TYPE_I64);
    if (is_i32) {
        POP_I32(value);
        POP_I32(expect);
        result = jit_cc_new_reg_I32(cc);
    }
    else {
        POP_I64(value);
        POP_I64(expect);
        result = jit_cc_new_reg_I64(cc);
    }
    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1) {
        goto fail;
    }
    CHECK_ALIGNMENT(offset1);

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    GEN_INSN(MOV, is_i32 ? eax_hreg : rax_hreg, expect);
    switch (bytes) {
        case 1:
        {
            insn = GEN_INSN(AT_CMPXCHGU8, value, is_i32 ? eax_hreg : rax_hreg,
                            memory_data, offset1);
            break;
        }
        case 2:
        {
            insn = GEN_INSN(AT_CMPXCHGU16, value, is_i32 ? eax_hreg : rax_hreg,
                            memory_data, offset1);
            break;
        }
        case 4:
        {
            if (op_type == VALUE_TYPE_I32)
                insn =
                    GEN_INSN(AT_CMPXCHGI32, value, is_i32 ? eax_hreg : rax_hreg,
                             memory_data, offset1);
            else
                insn =
                    GEN_INSN(AT_CMPXCHGU32, value, is_i32 ? eax_hreg : rax_hreg,
                             memory_data, offset1);
            break;
        }
        case 8:
        {
            insn = GEN_INSN(AT_CMPXCHGI64, value, is_i32 ? eax_hreg : rax_hreg,
                            memory_data, offset1);
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

    if (!insn
        || !jit_lock_reg_in_insn(cc, insn, is_i32 ? eax_hreg : rax_hreg)) {
        jit_set_last_error(cc, "generate cmpxchg insn or lock ra hreg failed");
        goto fail;
    }

    GEN_INSN(MOV, result, is_i32 ? eax_hreg : rax_hreg);

    if (is_i32)
        PUSH_I32(result);
    else
        PUSH_I64(result);

    return true;
#endif /* defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64) */

fail:
    return false;
}

bool
jit_compile_op_atomic_wait(JitCompContext *cc, uint8 op_type, uint32 align,
                           uint32 offset, uint32 bytes)
{
    bh_assert(op_type == VALUE_TYPE_I32 || op_type == VALUE_TYPE_I64);

    // Pop atomic.wait arguments
    JitReg timeout, expect, expect_64, addr;
    POP_I64(timeout);
    if (op_type == VALUE_TYPE_I32) {
        POP_I32(expect);
        expect_64 = jit_cc_new_reg_I64(cc);
        GEN_INSN(I32TOI64, expect_64, expect);
    }
    else {
        POP_I64(expect_64);
    }
    POP_I32(addr);

    // Get referenced address and store it in `maddr`
    JitReg memory_data = get_memory_data_reg(cc->jit_frame, 0);
    JitReg offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1)
        goto fail;
    CHECK_ALIGNMENT(offset1);

    JitReg maddr = jit_cc_new_reg_ptr(cc);
    GEN_INSN(ADD, maddr, memory_data, offset1);

    // Prepare `wasm_runtime_atomic_wait` arguments
    JitReg res = jit_cc_new_reg_I32(cc);
    JitReg args[5] = { 0 };
    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = maddr;
    args[2] = expect_64;
    args[3] = timeout;
    args[4] = NEW_CONST(I32, false);

    if (!jit_emit_callnative(cc, wasm_runtime_atomic_wait, res, args,
                             sizeof(args) / sizeof(args[0])))
        goto fail;

    // Handle return code
    GEN_INSN(CMP, cc->cmp_reg, res, NEW_CONST(I32, -1));
    if (!jit_emit_exception(cc, EXCE_ALREADY_THROWN, JIT_OP_BEQ, cc->cmp_reg,
                            NULL))
        goto fail;

    PUSH_I32(res);

#if WASM_ENABLE_THREAD_MGR != 0
    /* Insert suspend check point */
    if (!jit_check_suspend_flags(cc))
        goto fail;
#endif
    return true;
fail:
    return false;
}

bool
jit_compiler_op_atomic_notify(JitCompContext *cc, uint32 align, uint32 offset,
                              uint32 bytes)
{
    // Pop atomic.notify arguments
    JitReg notify_count, addr;
    POP_I32(notify_count);
    POP_I32(addr);

    // Get referenced address and store it in `maddr`
    JitReg memory_data = get_memory_data_reg(cc->jit_frame, 0);
    JitReg offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1)
        goto fail;
    CHECK_ALIGNMENT(offset1);

    JitReg maddr = jit_cc_new_reg_ptr(cc);
    GEN_INSN(ADD, maddr, memory_data, offset1);

    // Prepare `wasm_runtime_atomic_notify` arguments
    JitReg res = jit_cc_new_reg_I32(cc);
    JitReg args[3] = { 0 };
    args[0] = get_module_inst_reg(cc->jit_frame);
    args[1] = maddr;
    args[2] = notify_count;

    if (!jit_emit_callnative(cc, wasm_runtime_atomic_notify, res, args,
                             sizeof(args) / sizeof(args[0])))
        goto fail;

    // Handle return code
    GEN_INSN(CMP, cc->cmp_reg, res, NEW_CONST(I32, 0));
    if (!jit_emit_exception(cc, EXCE_ALREADY_THROWN, JIT_OP_BLTS, cc->cmp_reg,
                            NULL))
        goto fail;

    PUSH_I32(res);
    return true;
fail:
    return false;
}

bool
jit_compiler_op_atomic_fence(JitCompContext *cc)
{
    GEN_INSN(FENCE);
    return true;
}
#endif
