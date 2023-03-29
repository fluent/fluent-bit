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
    if (!jit_emit_exception(cc, JIT_EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS,
                            JIT_OP_BGTU, cc->cmp_reg, NULL)) {
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
    if (!jit_emit_exception(cc, JIT_EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS,
                            JIT_OP_BLTU, cc->cmp_reg, NULL)) {
        goto fail;
    }

#ifndef OS_ENABLE_HW_BOUND_CHECK
    /* if (offset1 > memory_boundary) goto EXCEPTION */
    GEN_INSN(CMP, cc->cmp_reg, offset1, memory_boundary);
    if (!jit_emit_exception(cc, JIT_EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS,
                            JIT_OP_BGTU, cc->cmp_reg, NULL)) {
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
    /* the default memory */
    uint32 mem_idx = 0;
#endif

#ifndef OS_ENABLE_HW_BOUND_CHECK
    /* ---------- check ---------- */
    /* 1. shortcut if the memory size is 0 */
    if (0 == cc->cur_wasm_module->memories[mem_idx].init_page_count) {
        JitReg memory_inst, cur_mem_page_count;

        /* if (cur_mem_page_count == 0) goto EXCEPTION */
        memory_inst = get_memory_inst_reg(cc->jit_frame, mem_idx);
        cur_mem_page_count = jit_cc_new_reg_I32(cc);
        GEN_INSN(LDI32, cur_mem_page_count, memory_inst,
                 NEW_CONST(I32, offsetof(WASMMemoryInstance, cur_page_count)));
        GEN_INSN(CMP, cc->cmp_reg, cur_mem_page_count, NEW_CONST(I32, 0));
        if (!jit_emit_exception(cc, JIT_EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS,
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

bool
jit_compile_op_i32_load(JitCompContext *cc, uint32 align, uint32 offset,
                        uint32 bytes, bool sign, bool atomic)
{
    JitReg addr, offset1, value, memory_data;

    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1) {
        goto fail;
    }

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    value = jit_cc_new_reg_I32(cc);
    switch (bytes) {
        case 1:
        {
            if (sign) {
                GEN_INSN(LDI8, value, memory_data, offset1);
            }
            else {
                GEN_INSN(LDU8, value, memory_data, offset1);
            }
            break;
        }
        case 2:
        {
            if (sign) {
                GEN_INSN(LDI16, value, memory_data, offset1);
            }
            else {
                GEN_INSN(LDU16, value, memory_data, offset1);
            }
            break;
        }
        case 4:
        {
            if (sign) {
                GEN_INSN(LDI32, value, memory_data, offset1);
            }
            else {
                GEN_INSN(LDU32, value, memory_data, offset1);
            }
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

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

    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1) {
        goto fail;
    }

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    value = jit_cc_new_reg_I64(cc);
    switch (bytes) {
        case 1:
        {
            if (sign) {
                GEN_INSN(LDI8, value, memory_data, offset1);
            }
            else {
                GEN_INSN(LDU8, value, memory_data, offset1);
            }
            break;
        }
        case 2:
        {
            if (sign) {
                GEN_INSN(LDI16, value, memory_data, offset1);
            }
            else {
                GEN_INSN(LDU16, value, memory_data, offset1);
            }
            break;
        }
        case 4:
        {
            if (sign) {
                GEN_INSN(LDI32, value, memory_data, offset1);
            }
            else {
                GEN_INSN(LDU32, value, memory_data, offset1);
            }
            break;
        }
        case 8:
        {
            if (sign) {
                GEN_INSN(LDI64, value, memory_data, offset1);
            }
            else {
                GEN_INSN(LDU64, value, memory_data, offset1);
            }
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

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

    POP_I32(value);
    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1) {
        goto fail;
    }

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    switch (bytes) {
        case 1:
        {
            GEN_INSN(STI8, value, memory_data, offset1);
            break;
        }
        case 2:
        {
            GEN_INSN(STI16, value, memory_data, offset1);
            break;
        }
        case 4:
        {
            GEN_INSN(STI32, value, memory_data, offset1);
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

    return true;
fail:
    return false;
}

bool
jit_compile_op_i64_store(JitCompContext *cc, uint32 align, uint32 offset,
                         uint32 bytes, bool atomic)
{
    JitReg value, addr, offset1, memory_data;

    POP_I64(value);
    POP_I32(addr);

    offset1 = check_and_seek(cc, addr, offset, bytes);
    if (!offset1) {
        goto fail;
    }

    if (jit_reg_is_const(value) && bytes < 8) {
        value = NEW_CONST(I32, (int32)jit_cc_get_const_I64(cc, value));
    }

    memory_data = get_memory_data_reg(cc->jit_frame, 0);

    switch (bytes) {
        case 1:
        {
            GEN_INSN(STI8, value, memory_data, offset1);
            break;
        }
        case 2:
        {
            GEN_INSN(STI16, value, memory_data, offset1);
            break;
        }
        case 4:
        {
            GEN_INSN(STI32, value, memory_data, offset1);
            break;
        }
        case 8:
        {
            GEN_INSN(STI64, value, memory_data, offset1);
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

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
    JitReg mem_inst, res;

    mem_inst = get_memory_inst_reg(cc->jit_frame, mem_idx);

    res = jit_cc_new_reg_I32(cc);
    GEN_INSN(LDI32, res, mem_inst,
             NEW_CONST(I32, offsetof(WASMMemoryInstance, cur_page_count)));

    PUSH_I32(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_memory_grow(JitCompContext *cc, uint32 mem_idx)
{
    JitReg memory_inst, grow_res, res;
    JitReg prev_page_count, inc_page_count, args[2];

    /* Get current page count */
    memory_inst = get_memory_inst_reg(cc->jit_frame, mem_idx);
    prev_page_count = jit_cc_new_reg_I32(cc);
    GEN_INSN(LDI32, prev_page_count, memory_inst,
             NEW_CONST(I32, offsetof(WASMMemoryInstance, cur_page_count)));

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

    /* if d + n > the length of mem.data */
    mem_inst = inst->memories[mem_idx];
    mem_size = mem_inst->cur_page_count * mem_inst->num_bytes_per_page;
    if (mem_size < mem_offset || mem_size - mem_offset < len)
        goto out_of_bounds;

    /* if s + n > the length of data.data */
    bh_assert(seg_idx < inst->module->data_seg_count);
    data_segment = inst->module->data_segments[seg_idx];
    if (data_segment->data_length < data_offset
        || data_segment->data_length - data_offset < len)
        goto out_of_bounds;

    mem_addr = mem_inst->memory_data + mem_offset;
    data_addr = data_segment->data + data_offset;
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
    if (!jit_emit_exception(cc, JIT_EXCE_ALREADY_THROWN, JIT_OP_BLTS,
                            cc->cmp_reg, NULL))
        goto fail;

    return true;
fail:
    return false;
}

bool
jit_compile_op_data_drop(JitCompContext *cc, uint32 seg_idx)
{
    JitReg module = get_module_reg(cc->jit_frame);
    JitReg data_segments = jit_cc_new_reg_ptr(cc);
    JitReg data_segment = jit_cc_new_reg_ptr(cc);

    GEN_INSN(LDPTR, data_segments, module,
             NEW_CONST(I32, offsetof(WASMModule, data_segments)));
    GEN_INSN(LDPTR, data_segment, data_segments,
             NEW_CONST(I32, seg_idx * sizeof(WASMDataSeg *)));
    GEN_INSN(STI32, NEW_CONST(I32, 0), data_segment,
             NEW_CONST(I32, offsetof(WASMDataSeg, data_length)));

    return true;
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
    if (!jit_emit_exception(cc, JIT_EXCE_ALREADY_THROWN, JIT_OP_BLTS,
                            cc->cmp_reg, NULL))
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
    if (!jit_emit_exception(cc, JIT_EXCE_ALREADY_THROWN, JIT_OP_BLTS,
                            cc->cmp_reg, NULL))
        goto fail;

    return true;
fail:
    return false;
}
#endif

#if WASM_ENABLE_SHARED_MEMORY != 0
bool
jit_compile_op_atomic_rmw(JitCompContext *cc, uint8 atomic_op, uint8 op_type,
                          uint32 align, uint32 offset, uint32 bytes)
{
    return false;
}

bool
jit_compile_op_atomic_cmpxchg(JitCompContext *cc, uint8 op_type, uint32 align,
                              uint32 offset, uint32 bytes)
{
    return false;
}

bool
jit_compile_op_atomic_wait(JitCompContext *cc, uint8 op_type, uint32 align,
                           uint32 offset, uint32 bytes)
{
    return false;
}

bool
jit_compiler_op_atomic_notify(JitCompContext *cc, uint32 align, uint32 offset,
                              uint32 bytes)
{
    return false;
}
#endif
