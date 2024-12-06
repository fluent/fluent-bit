/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_compiler.h"
#include "jit_frontend.h"
#include "fe/jit_emit_compare.h"
#include "fe/jit_emit_const.h"
#include "fe/jit_emit_control.h"
#include "fe/jit_emit_conversion.h"
#include "fe/jit_emit_exception.h"
#include "fe/jit_emit_function.h"
#include "fe/jit_emit_memory.h"
#include "fe/jit_emit_numberic.h"
#include "fe/jit_emit_parametric.h"
#include "fe/jit_emit_table.h"
#include "fe/jit_emit_variable.h"
#include "../interpreter/wasm_interp.h"
#include "../interpreter/wasm_opcode.h"
#include "../interpreter/wasm_runtime.h"
#include "../common/wasm_exec_env.h"

static uint32
get_global_base_offset(const WASMModule *module)
{
    uint32 module_inst_struct_size =
        (uint32)offsetof(WASMModuleInstance, global_table_data.bytes);
    uint32 mem_inst_size =
        (uint32)sizeof(WASMMemoryInstance)
        * (module->import_memory_count + module->memory_count);

#if WASM_ENABLE_JIT != 0
    /* If the module dosen't have memory, reserve one mem_info space
       with empty content to align with llvm jit compiler */
    if (mem_inst_size == 0)
        mem_inst_size = (uint32)sizeof(WASMMemoryInstance);
#endif

    /* Size of module inst and memory instances */
    return module_inst_struct_size + mem_inst_size;
}

static uint32
get_first_table_inst_offset(const WASMModule *module)
{
    return get_global_base_offset(module) + module->global_data_size;
}

uint32
jit_frontend_get_global_data_offset(const WASMModule *module, uint32 global_idx)
{
    uint32 global_base_offset = get_global_base_offset(module);

    if (global_idx < module->import_global_count) {
        const WASMGlobalImport *import_global =
            &((module->import_globals + global_idx)->u.global);
        return global_base_offset + import_global->data_offset;
    }
    else {
        const WASMGlobal *global =
            module->globals + (global_idx - module->import_global_count);
        return global_base_offset + global->data_offset;
    }
}

uint32
jit_frontend_get_table_inst_offset(const WASMModule *module, uint32 tbl_idx)
{
    uint32 offset, i = 0;

    offset = get_first_table_inst_offset(module);

    while (i < tbl_idx && i < module->import_table_count) {
        WASMTableImport *import_table = &module->import_tables[i].u.table;

        offset += (uint32)offsetof(WASMTableInstance, elems);
#if WASM_ENABLE_MULTI_MODULE != 0
        offset += (uint32)sizeof(uint32) * import_table->max_size;
#else
        offset += (uint32)sizeof(uint32)
                  * (import_table->possible_grow ? import_table->max_size
                                                 : import_table->init_size);
#endif

        i++;
    }

    if (i == tbl_idx) {
        return offset;
    }

    tbl_idx -= module->import_table_count;
    i -= module->import_table_count;
    while (i < tbl_idx && i < module->table_count) {
        WASMTable *table = module->tables + i;

        offset += (uint32)offsetof(WASMTableInstance, elems);
#if WASM_ENABLE_MULTI_MODULE != 0
        offset += (uint32)sizeof(uint32) * table->max_size;
#else
        offset += (uint32)sizeof(uint32)
                  * (table->possible_grow ? table->max_size : table->init_size);
#endif

        i++;
    }

    return offset;
}

uint32
jit_frontend_get_module_inst_extra_offset(const WASMModule *module)
{
    uint32 offset = jit_frontend_get_table_inst_offset(
        module, module->import_table_count + module->table_count);

    return align_uint(offset, 8);
}

JitReg
get_module_inst_reg(JitFrame *frame)
{
    JitCompContext *cc = frame->cc;

    if (!frame->module_inst_reg) {
        frame->module_inst_reg = cc->module_inst_reg;
        GEN_INSN(LDPTR, frame->module_inst_reg, cc->exec_env_reg,
                 NEW_CONST(I32, offsetof(WASMExecEnv, module_inst)));
    }
    return frame->module_inst_reg;
}

JitReg
get_module_reg(JitFrame *frame)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg = get_module_inst_reg(frame);

    if (!frame->module_reg) {
        frame->module_reg = cc->module_reg;
        GEN_INSN(LDPTR, frame->module_reg, module_inst_reg,
                 NEW_CONST(I32, offsetof(WASMModuleInstance, module)));
    }
    return frame->module_reg;
}

JitReg
get_import_func_ptrs_reg(JitFrame *frame)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg = get_module_inst_reg(frame);

    if (!frame->import_func_ptrs_reg) {
        frame->import_func_ptrs_reg = cc->import_func_ptrs_reg;
        GEN_INSN(
            LDPTR, frame->import_func_ptrs_reg, module_inst_reg,
            NEW_CONST(I32, offsetof(WASMModuleInstance, import_func_ptrs)));
    }
    return frame->import_func_ptrs_reg;
}

JitReg
get_fast_jit_func_ptrs_reg(JitFrame *frame)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg = get_module_inst_reg(frame);

    if (!frame->fast_jit_func_ptrs_reg) {
        frame->fast_jit_func_ptrs_reg = cc->fast_jit_func_ptrs_reg;
        GEN_INSN(
            LDPTR, frame->fast_jit_func_ptrs_reg, module_inst_reg,
            NEW_CONST(I32, offsetof(WASMModuleInstance, fast_jit_func_ptrs)));
    }
    return frame->fast_jit_func_ptrs_reg;
}

JitReg
get_func_type_indexes_reg(JitFrame *frame)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg = get_module_inst_reg(frame);

    if (!frame->func_type_indexes_reg) {
        frame->func_type_indexes_reg = cc->func_type_indexes_reg;
        GEN_INSN(
            LDPTR, frame->func_type_indexes_reg, module_inst_reg,
            NEW_CONST(I32, offsetof(WASMModuleInstance, func_type_indexes)));
    }
    return frame->func_type_indexes_reg;
}

JitReg
get_aux_stack_bound_reg(JitFrame *frame)
{
    JitCompContext *cc = frame->cc;

    if (!frame->aux_stack_bound_reg) {
        frame->aux_stack_bound_reg = cc->aux_stack_bound_reg;
        GEN_INSN(
            LDI32, frame->aux_stack_bound_reg, cc->exec_env_reg,
            NEW_CONST(I32, offsetof(WASMExecEnv, aux_stack_boundary.boundary)));
    }
    return frame->aux_stack_bound_reg;
}

JitReg
get_aux_stack_bottom_reg(JitFrame *frame)
{
    JitCompContext *cc = frame->cc;

    if (!frame->aux_stack_bottom_reg) {
        frame->aux_stack_bottom_reg = cc->aux_stack_bottom_reg;
        GEN_INSN(
            LDI32, frame->aux_stack_bottom_reg, cc->exec_env_reg,
            NEW_CONST(I32, offsetof(WASMExecEnv, aux_stack_bottom.bottom)));
    }
    return frame->aux_stack_bottom_reg;
}

#if WASM_ENABLE_SHARED_MEMORY != 0
static bool
is_shared_memory(WASMModule *module, uint32 mem_idx)
{
    WASMMemory *memory;
    WASMMemoryImport *memory_import;
    bool is_shared;

    if (mem_idx < module->import_memory_count) {
        memory_import = &(module->import_memories[mem_idx].u.memory);
        is_shared = memory_import->flags & 0x02 ? true : false;
    }
    else {
        memory = &module->memories[mem_idx - module->import_memory_count];
        is_shared = memory->flags & 0x02 ? true : false;
    }
    return is_shared;
}
#endif

JitReg
get_memory_inst_reg(JitFrame *frame, uint32 mem_idx)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg = get_module_inst_reg(frame);
    uint32 memory_inst_offset;
#if WASM_ENABLE_SHARED_MEMORY != 0
    JitReg memories_addr;
    uint32 memories_offset;
    bool is_shared;
#endif

    if (frame->memory_regs[mem_idx].memory_inst)
        return frame->memory_regs[mem_idx].memory_inst;

    frame->memory_regs[mem_idx].memory_inst =
        cc->memory_regs[mem_idx].memory_inst;

    bh_assert(mem_idx == 0);
#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared = is_shared_memory(cc->cur_wasm_module, mem_idx);
    if (is_shared) {
        memories_addr = jit_cc_new_reg_ptr(cc);
        memories_offset = (uint32)offsetof(WASMModuleInstance, memories);
        /* module_inst->memories */
        GEN_INSN(LDPTR, memories_addr, module_inst_reg,
                 NEW_CONST(I32, memories_offset));
        /* module_inst->memories[mem_idx], mem_idx can only be 0 now */
        GEN_INSN(LDPTR, frame->memory_regs[mem_idx].memory_inst, memories_addr,
                 NEW_CONST(I32, mem_idx));
    }
    else
#endif
    {
        memory_inst_offset =
            (uint32)offsetof(WASMModuleInstance, global_table_data.bytes);
        GEN_INSN(LDPTR, frame->memory_regs[mem_idx].memory_inst,
                 module_inst_reg, NEW_CONST(I32, memory_inst_offset));
    }

    return frame->memory_regs[mem_idx].memory_inst;
}

JitReg
get_cur_page_count_reg(JitFrame *frame, uint32 mem_idx)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg;
    uint32 cur_page_count_offset;
#if WASM_ENABLE_SHARED_MEMORY != 0
    JitReg memory_inst_reg;
    bool is_shared;
#endif

    if (frame->memory_regs[mem_idx].cur_page_count)
        return frame->memory_regs[mem_idx].cur_page_count;

    frame->memory_regs[mem_idx].cur_page_count =
        cc->memory_regs[mem_idx].cur_page_count;

    /* Get current page count */
    bh_assert(mem_idx == 0);
#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared = is_shared_memory(cc->cur_wasm_module, mem_idx);
    if (is_shared) {
        memory_inst_reg = get_memory_inst_reg(frame, mem_idx);
        cur_page_count_offset =
            (uint32)offsetof(WASMMemoryInstance, cur_page_count);
        /* memories[mem_idx]->cur_page_count_offset */
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].cur_page_count,
                 memory_inst_reg, NEW_CONST(I32, cur_page_count_offset));
    }
    else
#endif
    {
        module_inst_reg = get_module_inst_reg(frame);
        cur_page_count_offset =
            (uint32)offsetof(WASMModuleInstance, global_table_data.bytes)
            + (uint32)offsetof(WASMMemoryInstance, cur_page_count);
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].cur_page_count,
                 module_inst_reg, NEW_CONST(I32, cur_page_count_offset));
    }

    return frame->memory_regs[mem_idx].cur_page_count;
}

JitReg
get_memory_data_reg(JitFrame *frame, uint32 mem_idx)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg;
    uint32 memory_data_offset;
#if WASM_ENABLE_SHARED_MEMORY != 0
    JitReg memory_inst_reg;
    bool is_shared;
#endif

    if (frame->memory_regs[mem_idx].memory_data)
        return frame->memory_regs[mem_idx].memory_data;

    frame->memory_regs[mem_idx].memory_data =
        cc->memory_regs[mem_idx].memory_data;

    bh_assert(mem_idx == 0);
#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared = is_shared_memory(cc->cur_wasm_module, mem_idx);
    if (is_shared) {
        memory_inst_reg = get_memory_inst_reg(frame, mem_idx);
        memory_data_offset = (uint32)offsetof(WASMMemoryInstance, memory_data);
        /* memories[mem_idx]->memory_data */
        GEN_INSN(LDPTR, frame->memory_regs[mem_idx].memory_data,
                 memory_inst_reg, NEW_CONST(I32, memory_data_offset));
    }
    else
#endif
    {
        module_inst_reg = get_module_inst_reg(frame);
        memory_data_offset =
            (uint32)offsetof(WASMModuleInstance, global_table_data.bytes)
            + (uint32)offsetof(WASMMemoryInstance, memory_data);
        GEN_INSN(LDPTR, frame->memory_regs[mem_idx].memory_data,
                 module_inst_reg, NEW_CONST(I32, memory_data_offset));
    }
    return frame->memory_regs[mem_idx].memory_data;
}

JitReg
get_memory_data_end_reg(JitFrame *frame, uint32 mem_idx)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg;
    uint32 memory_data_end_offset;
#if WASM_ENABLE_SHARED_MEMORY != 0
    JitReg memory_inst_reg;
    bool is_shared;
#endif

    if (frame->memory_regs[mem_idx].memory_data_end)
        return frame->memory_regs[mem_idx].memory_data_end;

    frame->memory_regs[mem_idx].memory_data_end =
        cc->memory_regs[mem_idx].memory_data_end;

    bh_assert(mem_idx == 0);
#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared = is_shared_memory(cc->cur_wasm_module, mem_idx);
    if (is_shared) {
        memory_inst_reg = get_memory_inst_reg(frame, mem_idx);
        memory_data_end_offset =
            (uint32)offsetof(WASMMemoryInstance, memory_data_end);
        /* memories[mem_idx]->memory_data_end */
        GEN_INSN(LDPTR, frame->memory_regs[mem_idx].memory_data_end,
                 memory_inst_reg, NEW_CONST(I32, memory_data_end_offset));
    }
    else
#endif
    {
        module_inst_reg = get_module_inst_reg(frame);
        memory_data_end_offset =
            (uint32)offsetof(WASMModuleInstance, global_table_data.bytes)
            + (uint32)offsetof(WASMMemoryInstance, memory_data_end);
        GEN_INSN(LDPTR, frame->memory_regs[mem_idx].memory_data_end,
                 module_inst_reg, NEW_CONST(I32, memory_data_end_offset));
    }
    return frame->memory_regs[mem_idx].memory_data_end;
}

JitReg
get_mem_bound_check_1byte_reg(JitFrame *frame, uint32 mem_idx)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg;
    uint32 mem_bound_check_1byte_offset;
#if WASM_ENABLE_SHARED_MEMORY != 0
    JitReg memory_inst_reg;
    bool is_shared;
#endif

    if (frame->memory_regs[mem_idx].mem_bound_check_1byte)
        return frame->memory_regs[mem_idx].mem_bound_check_1byte;

    frame->memory_regs[mem_idx].mem_bound_check_1byte =
        cc->memory_regs[mem_idx].mem_bound_check_1byte;

    bh_assert(mem_idx == 0);

#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared = is_shared_memory(cc->cur_wasm_module, mem_idx);
    if (is_shared) {
        memory_inst_reg = get_memory_inst_reg(frame, mem_idx);
        mem_bound_check_1byte_offset =
            (uint32)offsetof(WASMMemoryInstance, mem_bound_check_1byte);
        /* memories[mem_idx]->mem_bound_check_1byte */
#if UINTPTR_MAX == UINT64_MAX
        GEN_INSN(LDI64, frame->memory_regs[mem_idx].mem_bound_check_1byte,
                 memory_inst_reg, NEW_CONST(I32, mem_bound_check_1byte_offset));
#else
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].mem_bound_check_1byte,
                 memory_inst_reg, NEW_CONST(I32, mem_bound_check_1byte_offset));
#endif
    }
    else
#endif
    {
        module_inst_reg = get_module_inst_reg(frame);
        mem_bound_check_1byte_offset =
            (uint32)offsetof(WASMModuleInstance, global_table_data.bytes)
            + (uint32)offsetof(WASMMemoryInstance, mem_bound_check_1byte);
#if UINTPTR_MAX == UINT64_MAX
        GEN_INSN(LDI64, frame->memory_regs[mem_idx].mem_bound_check_1byte,
                 module_inst_reg, NEW_CONST(I32, mem_bound_check_1byte_offset));
#else
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].mem_bound_check_1byte,
                 module_inst_reg, NEW_CONST(I32, mem_bound_check_1byte_offset));
#endif
    }
    return frame->memory_regs[mem_idx].mem_bound_check_1byte;
}

JitReg
get_mem_bound_check_2bytes_reg(JitFrame *frame, uint32 mem_idx)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg;
    uint32 mem_bound_check_2bytes_offset;
#if WASM_ENABLE_SHARED_MEMORY != 0
    JitReg memory_inst_reg;
    bool is_shared;
#endif

    if (frame->memory_regs[mem_idx].mem_bound_check_2bytes)
        return frame->memory_regs[mem_idx].mem_bound_check_2bytes;

    frame->memory_regs[mem_idx].mem_bound_check_2bytes =
        cc->memory_regs[mem_idx].mem_bound_check_2bytes;

    bh_assert(mem_idx == 0);

#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared = is_shared_memory(cc->cur_wasm_module, mem_idx);
    if (is_shared) {
        memory_inst_reg = get_memory_inst_reg(frame, mem_idx);
        mem_bound_check_2bytes_offset =
            (uint32)offsetof(WASMMemoryInstance, mem_bound_check_2bytes);
        /* memories[mem_idx]->mem_bound_check_2bytes */
#if UINTPTR_MAX == UINT64_MAX
        GEN_INSN(LDI64, frame->memory_regs[mem_idx].mem_bound_check_2bytes,
                 memory_inst_reg,
                 NEW_CONST(I32, mem_bound_check_2bytes_offset));
#else
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].mem_bound_check_2bytes,
                 memory_inst_reg,
                 NEW_CONST(I32, mem_bound_check_2bytes_offset));
#endif
    }
    else
#endif
    {
        module_inst_reg = get_module_inst_reg(frame);
        mem_bound_check_2bytes_offset =
            (uint32)offsetof(WASMModuleInstance, global_table_data.bytes)
            + (uint32)offsetof(WASMMemoryInstance, mem_bound_check_2bytes);
#if UINTPTR_MAX == UINT64_MAX
        GEN_INSN(LDI64, frame->memory_regs[mem_idx].mem_bound_check_2bytes,
                 module_inst_reg,
                 NEW_CONST(I32, mem_bound_check_2bytes_offset));
#else
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].mem_bound_check_2bytes,
                 module_inst_reg,
                 NEW_CONST(I32, mem_bound_check_2bytes_offset));
#endif
    }
    return frame->memory_regs[mem_idx].mem_bound_check_2bytes;
}

JitReg
get_mem_bound_check_4bytes_reg(JitFrame *frame, uint32 mem_idx)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg;
    uint32 mem_bound_check_4bytes_offset;
#if WASM_ENABLE_SHARED_MEMORY != 0
    JitReg memory_inst_reg;
    bool is_shared;
#endif

    if (frame->memory_regs[mem_idx].mem_bound_check_4bytes)
        return frame->memory_regs[mem_idx].mem_bound_check_4bytes;

    frame->memory_regs[mem_idx].mem_bound_check_4bytes =
        cc->memory_regs[mem_idx].mem_bound_check_4bytes;

    bh_assert(mem_idx == 0);

#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared = is_shared_memory(cc->cur_wasm_module, mem_idx);
    if (is_shared) {
        memory_inst_reg = get_memory_inst_reg(frame, mem_idx);
        mem_bound_check_4bytes_offset =
            (uint32)offsetof(WASMMemoryInstance, mem_bound_check_4bytes);
        /* memories[mem_idx]->mem_bound_check_4bytes */
#if UINTPTR_MAX == UINT64_MAX
        GEN_INSN(LDI64, frame->memory_regs[mem_idx].mem_bound_check_4bytes,
                 memory_inst_reg,
                 NEW_CONST(I32, mem_bound_check_4bytes_offset));
#else
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].mem_bound_check_4bytes,
                 memory_inst_reg,
                 NEW_CONST(I32, mem_bound_check_4bytes_offset));
#endif
    }
    else
#endif
    {
        module_inst_reg = get_module_inst_reg(frame);
        mem_bound_check_4bytes_offset =
            (uint32)offsetof(WASMModuleInstance, global_table_data.bytes)
            + (uint32)offsetof(WASMMemoryInstance, mem_bound_check_4bytes);
#if UINTPTR_MAX == UINT64_MAX
        GEN_INSN(LDI64, frame->memory_regs[mem_idx].mem_bound_check_4bytes,
                 module_inst_reg,
                 NEW_CONST(I32, mem_bound_check_4bytes_offset));
#else
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].mem_bound_check_4bytes,
                 module_inst_reg,
                 NEW_CONST(I32, mem_bound_check_4bytes_offset));
#endif
    }
    return frame->memory_regs[mem_idx].mem_bound_check_4bytes;
}

JitReg
get_mem_bound_check_8bytes_reg(JitFrame *frame, uint32 mem_idx)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg;
    uint32 mem_bound_check_8bytes_offset;
#if WASM_ENABLE_SHARED_MEMORY != 0
    JitReg memory_inst_reg;
    bool is_shared;
#endif

    if (frame->memory_regs[mem_idx].mem_bound_check_8bytes)
        return frame->memory_regs[mem_idx].mem_bound_check_8bytes;

    frame->memory_regs[mem_idx].mem_bound_check_8bytes =
        cc->memory_regs[mem_idx].mem_bound_check_8bytes;

    bh_assert(mem_idx == 0);

#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared = is_shared_memory(cc->cur_wasm_module, mem_idx);
    if (is_shared) {
        memory_inst_reg = get_memory_inst_reg(frame, mem_idx);
        mem_bound_check_8bytes_offset =
            (uint32)offsetof(WASMMemoryInstance, mem_bound_check_8bytes);
        /* memories[mem_idx]->mem_bound_check_8bytes */
#if UINTPTR_MAX == UINT64_MAX
        GEN_INSN(LDI64, frame->memory_regs[mem_idx].mem_bound_check_8bytes,
                 memory_inst_reg,
                 NEW_CONST(I32, mem_bound_check_8bytes_offset));
#else
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].mem_bound_check_8bytes,
                 memory_inst_reg,
                 NEW_CONST(I32, mem_bound_check_8bytes_offset));
#endif
    }
    else
#endif
    {
        module_inst_reg = get_module_inst_reg(frame);
        mem_bound_check_8bytes_offset =
            (uint32)offsetof(WASMModuleInstance, global_table_data.bytes)
            + (uint32)offsetof(WASMMemoryInstance, mem_bound_check_8bytes);
#if UINTPTR_MAX == UINT64_MAX
        GEN_INSN(LDI64, frame->memory_regs[mem_idx].mem_bound_check_8bytes,
                 module_inst_reg,
                 NEW_CONST(I32, mem_bound_check_8bytes_offset));
#else
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].mem_bound_check_8bytes,
                 module_inst_reg,
                 NEW_CONST(I32, mem_bound_check_8bytes_offset));
#endif
    }
    return frame->memory_regs[mem_idx].mem_bound_check_8bytes;
}

JitReg
get_mem_bound_check_16bytes_reg(JitFrame *frame, uint32 mem_idx)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst_reg;
    uint32 mem_bound_check_16bytes_offset;
#if WASM_ENABLE_SHARED_MEMORY != 0
    JitReg memory_inst_reg;
    bool is_shared;
#endif

    if (frame->memory_regs[mem_idx].mem_bound_check_16bytes)
        return frame->memory_regs[mem_idx].mem_bound_check_16bytes;

    frame->memory_regs[mem_idx].mem_bound_check_16bytes =
        cc->memory_regs[mem_idx].mem_bound_check_16bytes;

    bh_assert(mem_idx == 0);

#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared = is_shared_memory(cc->cur_wasm_module, mem_idx);
    if (is_shared) {
        memory_inst_reg = get_memory_inst_reg(frame, mem_idx);
        mem_bound_check_16bytes_offset =
            (uint32)offsetof(WASMMemoryInstance, mem_bound_check_16bytes);
        /* memories[mem_idx]->mem_bound_check_16bytes */
#if UINTPTR_MAX == UINT64_MAX
        GEN_INSN(LDI64, frame->memory_regs[mem_idx].mem_bound_check_16bytes,
                 memory_inst_reg,
                 NEW_CONST(I32, mem_bound_check_16bytes_offset));
#else
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].mem_bound_check_16bytes,
                 memory_inst_reg,
                 NEW_CONST(I32, mem_bound_check_16bytes_offset));
#endif
    }
    else
#endif
    {
        module_inst_reg = get_module_inst_reg(frame);
        mem_bound_check_16bytes_offset =
            (uint32)offsetof(WASMModuleInstance, global_table_data.bytes)
            + (uint32)offsetof(WASMMemoryInstance, mem_bound_check_16bytes);
#if UINTPTR_MAX == UINT64_MAX
        GEN_INSN(LDI64, frame->memory_regs[mem_idx].mem_bound_check_16bytes,
                 module_inst_reg,
                 NEW_CONST(I32, mem_bound_check_16bytes_offset));
#else
        GEN_INSN(LDI32, frame->memory_regs[mem_idx].mem_bound_check_16bytes,
                 module_inst_reg,
                 NEW_CONST(I32, mem_bound_check_16bytes_offset));
#endif
    }
    return frame->memory_regs[mem_idx].mem_bound_check_16bytes;
}

JitReg
get_table_elems_reg(JitFrame *frame, uint32 tbl_idx)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst = get_module_inst_reg(frame);
    uint32 offset =
        jit_frontend_get_table_inst_offset(cc->cur_wasm_module, tbl_idx)
        + (uint32)offsetof(WASMTableInstance, elems);

    if (!frame->table_regs[tbl_idx].table_elems) {
        frame->table_regs[tbl_idx].table_elems =
            cc->table_regs[tbl_idx].table_elems;
        GEN_INSN(ADD, frame->table_regs[tbl_idx].table_elems, module_inst,
                 NEW_CONST(PTR, offset));
    }
    return frame->table_regs[tbl_idx].table_elems;
}

JitReg
get_table_cur_size_reg(JitFrame *frame, uint32 tbl_idx)
{
    JitCompContext *cc = frame->cc;
    JitReg module_inst = get_module_inst_reg(frame);
    uint32 offset =
        jit_frontend_get_table_inst_offset(cc->cur_wasm_module, tbl_idx)
        + (uint32)offsetof(WASMTableInstance, cur_size);

    if (!frame->table_regs[tbl_idx].table_cur_size) {
        frame->table_regs[tbl_idx].table_cur_size =
            cc->table_regs[tbl_idx].table_cur_size;
        GEN_INSN(LDI32, frame->table_regs[tbl_idx].table_cur_size, module_inst,
                 NEW_CONST(I32, offset));
    }
    return frame->table_regs[tbl_idx].table_cur_size;
}

void
clear_fixed_virtual_regs(JitFrame *frame)
{
    WASMModule *module = frame->cc->cur_wasm_module;
    uint32 count, i;

    frame->module_inst_reg = 0;
    frame->module_reg = 0;
    frame->import_func_ptrs_reg = 0;
    frame->fast_jit_func_ptrs_reg = 0;
    frame->func_type_indexes_reg = 0;
    frame->aux_stack_bound_reg = 0;
    frame->aux_stack_bottom_reg = 0;

    count = module->import_memory_count + module->memory_count;
    for (i = 0; i < count; i++) {
        frame->memory_regs[i].memory_inst = 0;
        frame->memory_regs[i].cur_page_count = 0;
        frame->memory_regs[i].memory_data = 0;
        frame->memory_regs[i].memory_data_end = 0;
        frame->memory_regs[i].mem_bound_check_1byte = 0;
        frame->memory_regs[i].mem_bound_check_2bytes = 0;
        frame->memory_regs[i].mem_bound_check_4bytes = 0;
        frame->memory_regs[i].mem_bound_check_8bytes = 0;
        frame->memory_regs[i].mem_bound_check_16bytes = 0;
    }

    count = module->import_table_count + module->table_count;
    for (i = 0; i < count; i++) {
        frame->table_regs[i].table_elems = 0;
        frame->table_regs[i].table_cur_size = 0;
    }
}

void
clear_memory_regs(JitFrame *frame)
{
    WASMModule *module = frame->cc->cur_wasm_module;
    uint32 count, i;

    count = module->import_memory_count + module->memory_count;
    for (i = 0; i < count; i++) {
        frame->memory_regs[i].cur_page_count = 0;
        frame->memory_regs[i].memory_data = 0;
        frame->memory_regs[i].memory_data_end = 0;
        frame->memory_regs[i].mem_bound_check_1byte = 0;
        frame->memory_regs[i].mem_bound_check_2bytes = 0;
        frame->memory_regs[i].mem_bound_check_4bytes = 0;
        frame->memory_regs[i].mem_bound_check_8bytes = 0;
        frame->memory_regs[i].mem_bound_check_16bytes = 0;
    }
}

void
clear_table_regs(JitFrame *frame)
{
    WASMModule *module = frame->cc->cur_wasm_module;
    uint32 count, i;

    count = module->import_table_count + module->table_count;
    for (i = 0; i < count; i++) {
        frame->table_regs[i].table_cur_size = 0;
    }
}

JitReg
gen_load_i32(JitFrame *frame, unsigned n)
{
    if (!frame->lp[n].reg) {
        JitCompContext *cc = frame->cc;
        frame->lp[n].reg = jit_cc_new_reg_I32(cc);
        GEN_INSN(LDI32, frame->lp[n].reg, cc->fp_reg,
                 NEW_CONST(I32, offset_of_local(n)));
    }

    return frame->lp[n].reg;
}

JitReg
gen_load_i64(JitFrame *frame, unsigned n)
{
    if (!frame->lp[n].reg) {
        JitCompContext *cc = frame->cc;
        frame->lp[n].reg = frame->lp[n + 1].reg = jit_cc_new_reg_I64(cc);
        GEN_INSN(LDI64, frame->lp[n].reg, cc->fp_reg,
                 NEW_CONST(I32, offset_of_local(n)));
    }

    return frame->lp[n].reg;
}

JitReg
gen_load_f32(JitFrame *frame, unsigned n)
{
    if (!frame->lp[n].reg) {
        JitCompContext *cc = frame->cc;
        frame->lp[n].reg = jit_cc_new_reg_F32(cc);
        GEN_INSN(LDF32, frame->lp[n].reg, cc->fp_reg,
                 NEW_CONST(I32, offset_of_local(n)));
    }

    return frame->lp[n].reg;
}

JitReg
gen_load_f64(JitFrame *frame, unsigned n)
{
    if (!frame->lp[n].reg) {
        JitCompContext *cc = frame->cc;
        frame->lp[n].reg = frame->lp[n + 1].reg = jit_cc_new_reg_F64(cc);
        GEN_INSN(LDF64, frame->lp[n].reg, cc->fp_reg,
                 NEW_CONST(I32, offset_of_local(n)));
    }

    return frame->lp[n].reg;
}

void
gen_commit_values(JitFrame *frame, JitValueSlot *begin, JitValueSlot *end)
{
    JitCompContext *cc = frame->cc;
    JitValueSlot *p;
    int n;

    for (p = begin; p < end; p++) {
        if (!p->dirty)
            continue;

        p->dirty = 0;
        n = p - frame->lp;

        switch (jit_reg_kind(p->reg)) {
            case JIT_REG_KIND_I32:
                GEN_INSN(STI32, p->reg, cc->fp_reg,
                         NEW_CONST(I32, offset_of_local(n)));
                break;

            case JIT_REG_KIND_I64:
                GEN_INSN(STI64, p->reg, cc->fp_reg,
                         NEW_CONST(I32, offset_of_local(n)));
                (++p)->dirty = 0;
                break;

            case JIT_REG_KIND_F32:
                GEN_INSN(STF32, p->reg, cc->fp_reg,
                         NEW_CONST(I32, offset_of_local(n)));
                break;

            case JIT_REG_KIND_F64:
                GEN_INSN(STF64, p->reg, cc->fp_reg,
                         NEW_CONST(I32, offset_of_local(n)));
                (++p)->dirty = 0;
                break;
        }
    }
}

/**
 * Generate instructions to commit SP and IP pointers to the frame.
 *
 * @param frame the frame information
 */
void
gen_commit_sp_ip(JitFrame *frame)
{
    JitCompContext *cc = frame->cc;
    JitReg sp;

    if (frame->sp != frame->committed_sp) {
        sp = jit_cc_new_reg_ptr(cc);
        GEN_INSN(ADD, sp, cc->fp_reg,
                 NEW_CONST(PTR, offset_of_local(frame->sp - frame->lp)));
        GEN_INSN(STPTR, sp, cc->fp_reg,
                 NEW_CONST(I32, offsetof(WASMInterpFrame, sp)));
        frame->committed_sp = frame->sp;
    }

#if 0 /* Disable committing ip currently */
    if (frame->ip != frame->committed_ip) {
        GEN_INSN(STPTR, NEW_CONST(PTR, (uintptr_t)frame->ip), cc->fp_reg,
                 NEW_CONST(I32, offsetof(WASMInterpFrame, ip)));
        frame->committed_ip = frame->ip;
    }
#endif
}

static bool
create_fixed_virtual_regs(JitCompContext *cc)
{
    WASMModule *module = cc->cur_wasm_module;
    uint64 total_size;
    uint32 i, count;

    cc->module_inst_reg = jit_cc_new_reg_ptr(cc);
    cc->module_reg = jit_cc_new_reg_ptr(cc);
    cc->import_func_ptrs_reg = jit_cc_new_reg_ptr(cc);
    cc->fast_jit_func_ptrs_reg = jit_cc_new_reg_ptr(cc);
    cc->func_type_indexes_reg = jit_cc_new_reg_ptr(cc);
    cc->aux_stack_bound_reg = jit_cc_new_reg_I32(cc);
    cc->aux_stack_bottom_reg = jit_cc_new_reg_I32(cc);

    count = module->import_memory_count + module->memory_count;
    if (count > 0) {
        total_size = (uint64)sizeof(JitMemRegs) * count;
        if (total_size > UINT32_MAX
            || !(cc->memory_regs = jit_calloc((uint32)total_size))) {
            jit_set_last_error(cc, "allocate memory failed");
            return false;
        }

        for (i = 0; i < count; i++) {
            cc->memory_regs[i].memory_inst = jit_cc_new_reg_ptr(cc);
            cc->memory_regs[i].cur_page_count = jit_cc_new_reg_I32(cc);
            cc->memory_regs[i].memory_data = jit_cc_new_reg_ptr(cc);
            cc->memory_regs[i].memory_data_end = jit_cc_new_reg_ptr(cc);
            cc->memory_regs[i].mem_bound_check_1byte = jit_cc_new_reg_ptr(cc);
            cc->memory_regs[i].mem_bound_check_2bytes = jit_cc_new_reg_ptr(cc);
            cc->memory_regs[i].mem_bound_check_4bytes = jit_cc_new_reg_ptr(cc);
            cc->memory_regs[i].mem_bound_check_8bytes = jit_cc_new_reg_ptr(cc);
            cc->memory_regs[i].mem_bound_check_16bytes = jit_cc_new_reg_ptr(cc);
        }
    }

    count = module->import_table_count + module->table_count;
    if (count > 0) {
        total_size = (uint64)sizeof(JitTableRegs) * count;
        if (total_size > UINT32_MAX
            || !(cc->table_regs = jit_calloc((uint32)total_size))) {
            jit_set_last_error(cc, "allocate memory failed");
            return false;
        }

        for (i = 0; i < count; i++) {
            cc->table_regs[i].table_elems = jit_cc_new_reg_ptr(cc);
            cc->table_regs[i].table_cur_size = jit_cc_new_reg_I32(cc);
        }
    }

    return true;
}

static bool
form_and_translate_func(JitCompContext *cc)
{
    JitBasicBlock *func_entry_basic_block;
    JitReg func_entry_label;
    JitInsn *insn;
    JitIncomingInsn *incoming_insn, *incoming_insn_next;
    uint32 i;

    if (!create_fixed_virtual_regs(cc))
        return false;

    if (!(func_entry_basic_block = jit_frontend_translate_func(cc)))
        return false;

    jit_cc_reset_insn_hash(cc);

    /* The label of the func entry basic block. */
    func_entry_label = jit_basic_block_label(func_entry_basic_block);

    /* Create a JMP instruction jumping to the func entry. */
    if (!(insn = jit_cc_new_insn(cc, JMP, func_entry_label)))
        return false;

    /* Insert the instruction into the cc entry block. */
    jit_basic_block_append_insn(jit_cc_entry_basic_block(cc), insn);

    /* Patch INSNs jumping to exception basic blocks. */
    for (i = 0; i < EXCE_NUM; i++) {
        incoming_insn = cc->incoming_insns_for_exec_bbs[i];
        if (incoming_insn) {
            if (!(cc->exce_basic_blocks[i] = jit_cc_new_basic_block(cc, 0))) {
                jit_set_last_error(cc, "create basic block failed");
                return false;
            }
            while (incoming_insn) {
                incoming_insn_next = incoming_insn->next;
                insn = incoming_insn->insn;
                if (insn->opcode == JIT_OP_JMP) {
                    *(jit_insn_opnd(insn, 0)) =
                        jit_basic_block_label(cc->exce_basic_blocks[i]);
                }
                else if (insn->opcode >= JIT_OP_BEQ
                         && insn->opcode <= JIT_OP_BLEU) {
                    *(jit_insn_opnd(insn, 1)) =
                        jit_basic_block_label(cc->exce_basic_blocks[i]);
                }
                incoming_insn = incoming_insn_next;
            }
            cc->cur_basic_block = cc->exce_basic_blocks[i];
            if (i != EXCE_ALREADY_THROWN) {
                JitReg module_inst_reg = jit_cc_new_reg_ptr(cc);
                GEN_INSN(LDPTR, module_inst_reg, cc->exec_env_reg,
                         NEW_CONST(I32, offsetof(WASMExecEnv, module_inst)));
                insn = GEN_INSN(
                    CALLNATIVE, 0,
                    NEW_CONST(PTR, (uintptr_t)jit_set_exception_with_id), 2);
                if (insn) {
                    *(jit_insn_opndv(insn, 2)) = module_inst_reg;
                    *(jit_insn_opndv(insn, 3)) = NEW_CONST(I32, i);
                }
            }
            GEN_INSN(RETURN, NEW_CONST(I32, JIT_INTERP_ACTION_THROWN));

            *(jit_annl_begin_bcip(cc,
                                  jit_basic_block_label(cc->cur_basic_block))) =
                *(jit_annl_end_bcip(
                    cc, jit_basic_block_label(cc->cur_basic_block))) =
                    cc->cur_wasm_module->load_addr;
        }
    }

    *(jit_annl_begin_bcip(cc, cc->entry_label)) =
        *(jit_annl_end_bcip(cc, cc->entry_label)) =
            *(jit_annl_begin_bcip(cc, cc->exit_label)) =
                *(jit_annl_end_bcip(cc, cc->exit_label)) =
                    cc->cur_wasm_module->load_addr;

    if (jit_get_last_error(cc)) {
        return false;
    }
    return true;
}

bool
jit_pass_frontend(JitCompContext *cc)
{
    /* Enable necessary annotations required at the current stage. */
    if (!jit_annl_enable_begin_bcip(cc) || !jit_annl_enable_end_bcip(cc)
        || !jit_annl_enable_end_sp(cc) || !jit_annr_enable_def_insn(cc)
        || !jit_cc_enable_insn_hash(cc, 127))
        return false;

    if (!(form_and_translate_func(cc)))
        return false;

    /* Release the annotations after local CSE and translation. */
    jit_cc_disable_insn_hash(cc);
    jit_annl_disable_end_sp(cc);

    return true;
}

static JitFrame *
init_func_translation(JitCompContext *cc)
{
    JitFrame *jit_frame;
    JitReg top, top_boundary, new_top, frame_boundary, frame_sp;
    WASMModule *cur_wasm_module = cc->cur_wasm_module;
    WASMFunction *cur_wasm_func = cc->cur_wasm_func;
    uint32 cur_wasm_func_idx = cc->cur_wasm_func_idx;
    uint32 max_locals =
        cur_wasm_func->param_cell_num + cur_wasm_func->local_cell_num;
    uint32 max_stacks = cur_wasm_func->max_stack_cell_num;
    uint64 total_cell_num =
        (uint64)cur_wasm_func->param_cell_num
        + (uint64)cur_wasm_func->local_cell_num
        + (uint64)cur_wasm_func->max_stack_cell_num
        + ((uint64)cur_wasm_func->max_block_num) * sizeof(WASMBranchBlock) / 4;
    uint32 frame_size, outs_size, local_size, count;
    uint32 i, local_off;
    uint64 total_size;
#if WASM_ENABLE_DUMP_CALL_STACK != 0 || WASM_ENABLE_PERF_PROFILING != 0
    JitReg module_inst, func_inst;
    uint32 func_insts_offset;
#if WASM_ENABLE_PERF_PROFILING != 0
    JitReg time_started;
#endif
#endif

    if ((uint64)max_locals + (uint64)max_stacks >= UINT32_MAX
        || total_cell_num >= UINT32_MAX
        || !(jit_frame = jit_calloc(offsetof(JitFrame, lp)
                                    + sizeof(*jit_frame->lp)
                                          * (max_locals + max_stacks)))) {
        os_printf("allocate jit frame failed\n");
        return NULL;
    }

    count =
        cur_wasm_module->import_memory_count + cur_wasm_module->memory_count;
    if (count > 0) {
        total_size = (uint64)sizeof(JitMemRegs) * count;
        if (total_size > UINT32_MAX
            || !(jit_frame->memory_regs = jit_calloc((uint32)total_size))) {
            jit_set_last_error(cc, "allocate memory failed");
            jit_free(jit_frame);
            return NULL;
        }
    }

    count = cur_wasm_module->import_table_count + cur_wasm_module->table_count;
    if (count > 0) {
        total_size = (uint64)sizeof(JitTableRegs) * count;
        if (total_size > UINT32_MAX
            || !(jit_frame->table_regs = jit_calloc((uint32)total_size))) {
            jit_set_last_error(cc, "allocate memory failed");
            if (jit_frame->memory_regs)
                jit_free(jit_frame->memory_regs);
            jit_free(jit_frame);
            return NULL;
        }
    }

    jit_frame->cur_wasm_module = cur_wasm_module;
    jit_frame->cur_wasm_func = cur_wasm_func;
    jit_frame->cur_wasm_func_idx = cur_wasm_func_idx;
    jit_frame->cc = cc;
    jit_frame->max_locals = max_locals;
    jit_frame->max_stacks = max_stacks;
    jit_frame->sp = jit_frame->lp + max_locals;
    jit_frame->ip = cur_wasm_func->code;

    cc->jit_frame = jit_frame;
    cc->cur_basic_block = jit_cc_entry_basic_block(cc);
    cc->spill_cache_offset = wasm_interp_interp_frame_size(total_cell_num);
    /* Set spill cache size according to max local cell num, max stack cell
       num and virtual fixed register num */
    cc->spill_cache_size = (max_locals + max_stacks) * 4 + sizeof(void *) * 16;
    cc->total_frame_size = cc->spill_cache_offset + cc->spill_cache_size;
    cc->jitted_return_address_offset =
        offsetof(WASMInterpFrame, jitted_return_addr);
    cc->cur_basic_block = jit_cc_entry_basic_block(cc);

    frame_size = outs_size = cc->total_frame_size;
    local_size =
        (cur_wasm_func->param_cell_num + cur_wasm_func->local_cell_num) * 4;

    top = jit_cc_new_reg_ptr(cc);
    top_boundary = jit_cc_new_reg_ptr(cc);
    new_top = jit_cc_new_reg_ptr(cc);
    frame_boundary = jit_cc_new_reg_ptr(cc);
    frame_sp = jit_cc_new_reg_ptr(cc);

#if WASM_ENABLE_DUMP_CALL_STACK != 0 || WASM_ENABLE_PERF_PROFILING != 0
    module_inst = jit_cc_new_reg_ptr(cc);
    func_inst = jit_cc_new_reg_ptr(cc);
#if WASM_ENABLE_PERF_PROFILING != 0
    time_started = jit_cc_new_reg_I64(cc);
    /* Call os_time_get_boot_us() to get time_started firstly
       as there is stack frame switching below, calling native in them
       may cause register spilling work inproperly */
    if (!jit_emit_callnative(cc, os_time_get_boot_us, time_started, NULL, 0)) {
        return NULL;
    }
#endif
#endif

    /* top = exec_env->wasm_stack.s.top */
    GEN_INSN(LDPTR, top, cc->exec_env_reg,
             NEW_CONST(I32, offsetof(WASMExecEnv, wasm_stack.s.top)));
    /* top_boundary = exec_env->wasm_stack.s.top_boundary */
    GEN_INSN(LDPTR, top_boundary, cc->exec_env_reg,
             NEW_CONST(I32, offsetof(WASMExecEnv, wasm_stack.s.top_boundary)));
    /* frame_boundary = top + frame_size + outs_size */
    GEN_INSN(ADD, frame_boundary, top, NEW_CONST(PTR, frame_size + outs_size));
    /* if frame_boundary > top_boundary, throw stack overflow exception */
    GEN_INSN(CMP, cc->cmp_reg, frame_boundary, top_boundary);
    if (!jit_emit_exception(cc, EXCE_OPERAND_STACK_OVERFLOW, JIT_OP_BGTU,
                            cc->cmp_reg, NULL)) {
        return NULL;
    }

    /* Add first and then sub to reduce one used register */
    /* new_top = frame_boundary - outs_size = top + frame_size */
    GEN_INSN(SUB, new_top, frame_boundary, NEW_CONST(PTR, outs_size));
    /* exec_env->wasm_stack.s.top = new_top */
    GEN_INSN(STPTR, new_top, cc->exec_env_reg,
             NEW_CONST(I32, offsetof(WASMExecEnv, wasm_stack.s.top)));
    /* frame_sp = frame->lp + local_size */
    GEN_INSN(ADD, frame_sp, top,
             NEW_CONST(PTR, offsetof(WASMInterpFrame, lp) + local_size));
    /* frame->sp = frame_sp */
    GEN_INSN(STPTR, frame_sp, top,
             NEW_CONST(I32, offsetof(WASMInterpFrame, sp)));
    /* frame->prev_frame = fp_reg */
    GEN_INSN(STPTR, cc->fp_reg, top,
             NEW_CONST(I32, offsetof(WASMInterpFrame, prev_frame)));
#if WASM_ENABLE_DUMP_CALL_STACK != 0 || WASM_ENABLE_PERF_PROFILING != 0
    /* module_inst = exec_env->module_inst */
    GEN_INSN(LDPTR, module_inst, cc->exec_env_reg,
             NEW_CONST(I32, offsetof(WASMExecEnv, module_inst)));
    func_insts_offset =
        jit_frontend_get_module_inst_extra_offset(cur_wasm_module)
        + (uint32)offsetof(WASMModuleInstanceExtra, functions);
    /* func_inst = module_inst->e->functions */
    GEN_INSN(LDPTR, func_inst, module_inst, NEW_CONST(I32, func_insts_offset));
    /* func_inst = func_inst + cur_wasm_func_idx */
    GEN_INSN(ADD, func_inst, func_inst,
             NEW_CONST(PTR, (uint32)sizeof(WASMFunctionInstance)
                                * cur_wasm_func_idx));
    /* frame->function = func_inst */
    GEN_INSN(STPTR, func_inst, top,
             NEW_CONST(I32, offsetof(WASMInterpFrame, function)));
#if WASM_ENABLE_PERF_PROFILING != 0
    /* frame->time_started = time_started */
    GEN_INSN(STI64, time_started, top,
             NEW_CONST(I32, offsetof(WASMInterpFrame, time_started)));
#endif
#endif
    /* exec_env->cur_frame = top */
    GEN_INSN(STPTR, top, cc->exec_env_reg,
             NEW_CONST(I32, offsetof(WASMExecEnv, cur_frame)));
    /* fp_reg = top */
    GEN_INSN(MOV, cc->fp_reg, top);

    /* Initialize local variables, set them to 0 */
    local_off = (uint32)offsetof(WASMInterpFrame, lp)
                + cur_wasm_func->param_cell_num * 4;
    for (i = 0; i < cur_wasm_func->local_cell_num / 2; i++, local_off += 8) {
        GEN_INSN(STI64, NEW_CONST(I64, 0), cc->fp_reg,
                 NEW_CONST(I32, local_off));
    }
    if (cur_wasm_func->local_cell_num & 1) {
        GEN_INSN(STI32, NEW_CONST(I32, 0), cc->fp_reg,
                 NEW_CONST(I32, local_off));
    }

    return jit_frame;
}

static void
free_block_memory(JitBlock *block)
{
    if (block->param_types)
        jit_free(block->param_types);
    if (block->result_types)
        jit_free(block->result_types);
    jit_free(block);
}

static JitBasicBlock *
create_func_block(JitCompContext *cc)
{
    JitBlock *jit_block;
    WASMFunction *cur_func = cc->cur_wasm_func;
    WASMType *func_type = cur_func->func_type;
    uint32 param_count = func_type->param_count;
    uint32 result_count = func_type->result_count;

    if (!(jit_block = jit_calloc(sizeof(JitBlock)))) {
        return NULL;
    }

    if (param_count && !(jit_block->param_types = jit_calloc(param_count))) {
        goto fail;
    }
    if (result_count && !(jit_block->result_types = jit_calloc(result_count))) {
        goto fail;
    }

    /* Set block data */
    jit_block->label_type = LABEL_TYPE_FUNCTION;
    jit_block->param_count = param_count;
    if (param_count) {
        bh_memcpy_s(jit_block->param_types, param_count, func_type->types,
                    param_count);
    }
    jit_block->result_count = result_count;
    if (result_count) {
        bh_memcpy_s(jit_block->result_types, result_count,
                    func_type->types + param_count, result_count);
    }
    jit_block->wasm_code_end = cur_func->code + cur_func->code_size;
    jit_block->frame_sp_begin = cc->jit_frame->sp;

    /* Add function entry block */
    if (!(jit_block->basic_block_entry = jit_cc_new_basic_block(cc, 0))) {
        goto fail;
    }
    *(jit_annl_begin_bcip(
        cc, jit_basic_block_label(jit_block->basic_block_entry))) =
        cur_func->code;
    jit_block_stack_push(&cc->block_stack, jit_block);
    cc->cur_basic_block = jit_block->basic_block_entry;

    return jit_block->basic_block_entry;

fail:
    free_block_memory(jit_block);
    return NULL;
}

#define CHECK_BUF(buf, buf_end, length)                                 \
    do {                                                                \
        if (buf + length > buf_end) {                                   \
            jit_set_last_error(cc, "read leb failed: unexpected end."); \
            return false;                                               \
        }                                                               \
    } while (0)

static bool
read_leb(JitCompContext *cc, const uint8 *buf, const uint8 *buf_end,
         uint32 *p_offset, uint32 maxbits, bool sign, uint64 *p_result)
{
    uint64 result = 0;
    uint32 shift = 0;
    uint32 bcnt = 0;
    uint64 byte;

    while (true) {
        CHECK_BUF(buf, buf_end, 1);
        byte = buf[*p_offset];
        *p_offset += 1;
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            break;
        }
        bcnt += 1;
    }
    if (bcnt > (maxbits + 6) / 7) {
        jit_set_last_error(cc, "read leb failed: "
                               "integer representation too long");
        return false;
    }
    if (sign && (shift < maxbits) && (byte & 0x40)) {
        /* Sign extend */
        result |= (~((uint64)0)) << shift;
    }
    *p_result = result;
    return true;
}

#define read_leb_uint32(p, p_end, res)                        \
    do {                                                      \
        uint32 off = 0;                                       \
        uint64 res64;                                         \
        if (!read_leb(cc, p, p_end, &off, 32, false, &res64)) \
            return false;                                     \
        p += off;                                             \
        res = (uint32)res64;                                  \
    } while (0)

#define read_leb_int32(p, p_end, res)                        \
    do {                                                     \
        uint32 off = 0;                                      \
        uint64 res64;                                        \
        if (!read_leb(cc, p, p_end, &off, 32, true, &res64)) \
            return false;                                    \
        p += off;                                            \
        res = (int32)res64;                                  \
    } while (0)

#define read_leb_int64(p, p_end, res)                        \
    do {                                                     \
        uint32 off = 0;                                      \
        uint64 res64;                                        \
        if (!read_leb(cc, p, p_end, &off, 64, true, &res64)) \
            return false;                                    \
        p += off;                                            \
        res = (int64)res64;                                  \
    } while (0)

#if WASM_ENABLE_SHARED_MEMORY != 0
#define COMPILE_ATOMIC_RMW(OP, NAME)                  \
    case WASM_OP_ATOMIC_RMW_I32_##NAME:               \
        bytes = 4;                                    \
        op_type = VALUE_TYPE_I32;                     \
        goto OP_ATOMIC_##OP;                          \
    case WASM_OP_ATOMIC_RMW_I64_##NAME:               \
        bytes = 8;                                    \
        op_type = VALUE_TYPE_I64;                     \
        goto OP_ATOMIC_##OP;                          \
    case WASM_OP_ATOMIC_RMW_I32_##NAME##8_U:          \
        bytes = 1;                                    \
        op_type = VALUE_TYPE_I32;                     \
        goto OP_ATOMIC_##OP;                          \
    case WASM_OP_ATOMIC_RMW_I32_##NAME##16_U:         \
        bytes = 2;                                    \
        op_type = VALUE_TYPE_I32;                     \
        goto OP_ATOMIC_##OP;                          \
    case WASM_OP_ATOMIC_RMW_I64_##NAME##8_U:          \
        bytes = 1;                                    \
        op_type = VALUE_TYPE_I64;                     \
        goto OP_ATOMIC_##OP;                          \
    case WASM_OP_ATOMIC_RMW_I64_##NAME##16_U:         \
        bytes = 2;                                    \
        op_type = VALUE_TYPE_I64;                     \
        goto OP_ATOMIC_##OP;                          \
    case WASM_OP_ATOMIC_RMW_I64_##NAME##32_U:         \
        bytes = 4;                                    \
        op_type = VALUE_TYPE_I64;                     \
        OP_ATOMIC_##OP : bin_op = AtomicRMWBinOp##OP; \
        goto build_atomic_rmw;
#endif

static bool
jit_compile_func(JitCompContext *cc)
{
    WASMFunction *cur_func = cc->cur_wasm_func;
    WASMType *func_type = NULL;
    uint8 *frame_ip = cur_func->code, opcode, *p_f32, *p_f64;
    uint8 *frame_ip_end = frame_ip + cur_func->code_size;
    uint8 *param_types = NULL, *result_types = NULL, value_type;
    uint16 param_count, result_count;
    uint32 br_depth, *br_depths, br_count;
    uint32 func_idx, type_idx, mem_idx, local_idx, global_idx, i;
    uint32 bytes = 4, align, offset;
    bool merge_cmp_and_if = false, merge_cmp_and_br_if = false;
    bool sign = true;
    int32 i32_const;
    int64 i64_const;
    float32 f32_const;
    float64 f64_const;

    while (frame_ip < frame_ip_end) {
        cc->jit_frame->ip = frame_ip;
        opcode = *frame_ip++;

#if 0 /* TODO */
#if WASM_ENABLE_THREAD_MGR != 0
    /* Insert suspend check point */
    if (cc->enable_thread_mgr) {
        if (!check_suspend_flags(cc, func_ctx))
            return false;
    }
#endif
#endif

        switch (opcode) {
            case WASM_OP_UNREACHABLE:
                if (!jit_compile_op_unreachable(cc, &frame_ip))
                    return false;
                break;

            case WASM_OP_NOP:
                break;

            case WASM_OP_BLOCK:
            case WASM_OP_LOOP:
            case WASM_OP_IF:
            {
                value_type = *frame_ip++;
                if (value_type == VALUE_TYPE_I32 || value_type == VALUE_TYPE_I64
                    || value_type == VALUE_TYPE_F32
                    || value_type == VALUE_TYPE_F64
                    || value_type == VALUE_TYPE_V128
                    || value_type == VALUE_TYPE_VOID
                    || value_type == VALUE_TYPE_FUNCREF
                    || value_type == VALUE_TYPE_EXTERNREF) {
                    param_count = 0;
                    param_types = NULL;
                    if (value_type == VALUE_TYPE_VOID) {
                        result_count = 0;
                        result_types = NULL;
                    }
                    else {
                        result_count = 1;
                        result_types = &value_type;
                    }
                }
                else {
                    jit_set_last_error(cc, "unsupported value type");
                    return false;
                }
                if (!jit_compile_op_block(
                        cc, &frame_ip, frame_ip_end,
                        (uint32)(LABEL_TYPE_BLOCK + opcode - WASM_OP_BLOCK),
                        param_count, param_types, result_count, result_types,
                        merge_cmp_and_if))
                    return false;
                /* Clear flag */
                merge_cmp_and_if = false;
                break;
            }
            case EXT_OP_BLOCK:
            case EXT_OP_LOOP:
            case EXT_OP_IF:
            {
                read_leb_uint32(frame_ip, frame_ip_end, type_idx);
                func_type = cc->cur_wasm_module->types[type_idx];
                param_count = func_type->param_count;
                param_types = func_type->types;
                result_count = func_type->result_count;
                result_types = func_type->types + param_count;
                if (!jit_compile_op_block(
                        cc, &frame_ip, frame_ip_end,
                        (uint32)(LABEL_TYPE_BLOCK + opcode - EXT_OP_BLOCK),
                        param_count, param_types, result_count, result_types,
                        merge_cmp_and_if))
                    return false;
                /* Clear flag */
                merge_cmp_and_if = false;
                break;
            }

            case WASM_OP_ELSE:
                if (!jit_compile_op_else(cc, &frame_ip))
                    return false;
                break;

            case WASM_OP_END:
                if (!jit_compile_op_end(cc, &frame_ip))
                    return false;
                break;

            case WASM_OP_BR:
                read_leb_uint32(frame_ip, frame_ip_end, br_depth);
                if (!jit_compile_op_br(cc, br_depth, &frame_ip))
                    return false;
                break;

            case WASM_OP_BR_IF:
                read_leb_uint32(frame_ip, frame_ip_end, br_depth);
                if (!jit_compile_op_br_if(cc, br_depth, merge_cmp_and_br_if,
                                          &frame_ip))
                    return false;
                /* Clear flag */
                merge_cmp_and_br_if = false;
                break;

            case WASM_OP_BR_TABLE:
                read_leb_uint32(frame_ip, frame_ip_end, br_count);
                if (!(br_depths = jit_calloc((uint32)sizeof(uint32)
                                             * (br_count + 1)))) {
                    jit_set_last_error(cc, "allocate memory failed.");
                    goto fail;
                }
#if WASM_ENABLE_FAST_INTERP != 0
                for (i = 0; i <= br_count; i++)
                    read_leb_uint32(frame_ip, frame_ip_end, br_depths[i]);
#else
                for (i = 0; i <= br_count; i++)
                    br_depths[i] = *frame_ip++;
#endif

                if (!jit_compile_op_br_table(cc, br_depths, br_count,
                                             &frame_ip)) {
                    jit_free(br_depths);
                    return false;
                }

                jit_free(br_depths);
                break;

#if WASM_ENABLE_FAST_INTERP == 0
            case EXT_OP_BR_TABLE_CACHE:
            {
                BrTableCache *node = bh_list_first_elem(
                    cc->cur_wasm_module->br_table_cache_list);
                BrTableCache *node_next;
                uint8 *p_opcode = frame_ip - 1;

                read_leb_uint32(frame_ip, frame_ip_end, br_count);

                while (node) {
                    node_next = bh_list_elem_next(node);
                    if (node->br_table_op_addr == p_opcode) {
                        br_depths = node->br_depths;
                        if (!jit_compile_op_br_table(cc, br_depths, br_count,
                                                     &frame_ip)) {
                            return false;
                        }
                        break;
                    }
                    node = node_next;
                }
                bh_assert(node);

                break;
            }
#endif

            case WASM_OP_RETURN:
                if (!jit_compile_op_return(cc, &frame_ip))
                    return false;
                break;

            case WASM_OP_CALL:
                read_leb_uint32(frame_ip, frame_ip_end, func_idx);
                if (!jit_compile_op_call(cc, func_idx, false))
                    return false;
                break;

            case WASM_OP_CALL_INDIRECT:
            {
                uint32 tbl_idx;

                read_leb_uint32(frame_ip, frame_ip_end, type_idx);

#if WASM_ENABLE_REF_TYPES != 0
                read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
#else
                frame_ip++;
                tbl_idx = 0;
#endif

                if (!jit_compile_op_call_indirect(cc, type_idx, tbl_idx))
                    return false;
                break;
            }

#if WASM_ENABLE_TAIL_CALL != 0
            case WASM_OP_RETURN_CALL:
                read_leb_uint32(frame_ip, frame_ip_end, func_idx);

                if (!jit_compile_op_call(cc, func_idx, true))
                    return false;
                if (!jit_compile_op_return(cc, &frame_ip))
                    return false;
                break;

            case WASM_OP_RETURN_CALL_INDIRECT:
            {
                uint32 tbl_idx;

                read_leb_uint32(frame_ip, frame_ip_end, type_idx);
#if WASM_ENABLE_REF_TYPES != 0
                read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
#else
                frame_ip++;
                tbl_idx = 0;
#endif

                if (!jit_compile_op_call_indirect(cc, type_idx, tbl_idx))
                    return false;
                if (!jit_compile_op_return(cc, &frame_ip))
                    return false;
                break;
            }
#endif /* end of WASM_ENABLE_TAIL_CALL */

            case WASM_OP_DROP:
                if (!jit_compile_op_drop(cc, true))
                    return false;
                break;

            case WASM_OP_DROP_64:
                if (!jit_compile_op_drop(cc, false))
                    return false;
                break;

            case WASM_OP_SELECT:
                if (!jit_compile_op_select(cc, true))
                    return false;
                break;

            case WASM_OP_SELECT_64:
                if (!jit_compile_op_select(cc, false))
                    return false;
                break;

#if WASM_ENABLE_REF_TYPES != 0
            case WASM_OP_SELECT_T:
            {
                uint32 vec_len;

                read_leb_uint32(frame_ip, frame_ip_end, vec_len);
                bh_assert(vec_len == 1);
                (void)vec_len;

                type_idx = *frame_ip++;
                if (!jit_compile_op_select(cc,
                                           (type_idx != VALUE_TYPE_I64)
                                               && (type_idx != VALUE_TYPE_F64)))
                    return false;
                break;
            }
            case WASM_OP_TABLE_GET:
            {
                uint32 tbl_idx;

                read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                if (!jit_compile_op_table_get(cc, tbl_idx))
                    return false;
                break;
            }
            case WASM_OP_TABLE_SET:
            {
                uint32 tbl_idx;

                read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                if (!jit_compile_op_table_set(cc, tbl_idx))
                    return false;
                break;
            }
            case WASM_OP_REF_NULL:
            {
                uint32 ref_type;
                read_leb_uint32(frame_ip, frame_ip_end, ref_type);
                if (!jit_compile_op_ref_null(cc, ref_type))
                    return false;
                break;
            }
            case WASM_OP_REF_IS_NULL:
            {
                if (!jit_compile_op_ref_is_null(cc))
                    return false;
                break;
            }
            case WASM_OP_REF_FUNC:
            {
                read_leb_uint32(frame_ip, frame_ip_end, func_idx);
                if (!jit_compile_op_ref_func(cc, func_idx))
                    return false;
                break;
            }
#endif

            case WASM_OP_GET_LOCAL:
                read_leb_uint32(frame_ip, frame_ip_end, local_idx);
                if (!jit_compile_op_get_local(cc, local_idx))
                    return false;
                break;

            case WASM_OP_SET_LOCAL:
                read_leb_uint32(frame_ip, frame_ip_end, local_idx);
                if (!jit_compile_op_set_local(cc, local_idx))
                    return false;
                break;

            case WASM_OP_TEE_LOCAL:
                read_leb_uint32(frame_ip, frame_ip_end, local_idx);
                if (!jit_compile_op_tee_local(cc, local_idx))
                    return false;
                break;

            case WASM_OP_GET_GLOBAL:
            case WASM_OP_GET_GLOBAL_64:
                read_leb_uint32(frame_ip, frame_ip_end, global_idx);
                if (!jit_compile_op_get_global(cc, global_idx))
                    return false;
                break;

            case WASM_OP_SET_GLOBAL:
            case WASM_OP_SET_GLOBAL_64:
            case WASM_OP_SET_GLOBAL_AUX_STACK:
                read_leb_uint32(frame_ip, frame_ip_end, global_idx);
                if (!jit_compile_op_set_global(
                        cc, global_idx,
                        opcode == WASM_OP_SET_GLOBAL_AUX_STACK ? true : false))
                    return false;
                break;

            case WASM_OP_I32_LOAD:
                bytes = 4;
                sign = true;
                goto op_i32_load;
            case WASM_OP_I32_LOAD8_S:
            case WASM_OP_I32_LOAD8_U:
                bytes = 1;
                sign = (opcode == WASM_OP_I32_LOAD8_S) ? true : false;
                goto op_i32_load;
            case WASM_OP_I32_LOAD16_S:
            case WASM_OP_I32_LOAD16_U:
                bytes = 2;
                sign = (opcode == WASM_OP_I32_LOAD16_S) ? true : false;
            op_i32_load:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                if (!jit_compile_op_i32_load(cc, align, offset, bytes, sign,
                                             false))
                    return false;
                break;

            case WASM_OP_I64_LOAD:
                bytes = 8;
                sign = true;
                goto op_i64_load;
            case WASM_OP_I64_LOAD8_S:
            case WASM_OP_I64_LOAD8_U:
                bytes = 1;
                sign = (opcode == WASM_OP_I64_LOAD8_S) ? true : false;
                goto op_i64_load;
            case WASM_OP_I64_LOAD16_S:
            case WASM_OP_I64_LOAD16_U:
                bytes = 2;
                sign = (opcode == WASM_OP_I64_LOAD16_S) ? true : false;
                goto op_i64_load;
            case WASM_OP_I64_LOAD32_S:
            case WASM_OP_I64_LOAD32_U:
                bytes = 4;
                sign = (opcode == WASM_OP_I64_LOAD32_S) ? true : false;
            op_i64_load:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                if (!jit_compile_op_i64_load(cc, align, offset, bytes, sign,
                                             false))
                    return false;
                break;

            case WASM_OP_F32_LOAD:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                if (!jit_compile_op_f32_load(cc, align, offset))
                    return false;
                break;

            case WASM_OP_F64_LOAD:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                if (!jit_compile_op_f64_load(cc, align, offset))
                    return false;
                break;

            case WASM_OP_I32_STORE:
                bytes = 4;
                goto op_i32_store;
            case WASM_OP_I32_STORE8:
                bytes = 1;
                goto op_i32_store;
            case WASM_OP_I32_STORE16:
                bytes = 2;
            op_i32_store:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                if (!jit_compile_op_i32_store(cc, align, offset, bytes, false))
                    return false;
                break;

            case WASM_OP_I64_STORE:
                bytes = 8;
                goto op_i64_store;
            case WASM_OP_I64_STORE8:
                bytes = 1;
                goto op_i64_store;
            case WASM_OP_I64_STORE16:
                bytes = 2;
                goto op_i64_store;
            case WASM_OP_I64_STORE32:
                bytes = 4;
            op_i64_store:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                if (!jit_compile_op_i64_store(cc, align, offset, bytes, false))
                    return false;
                break;

            case WASM_OP_F32_STORE:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                if (!jit_compile_op_f32_store(cc, align, offset))
                    return false;
                break;

            case WASM_OP_F64_STORE:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                if (!jit_compile_op_f64_store(cc, align, offset))
                    return false;
                break;

            case WASM_OP_MEMORY_SIZE:
                read_leb_uint32(frame_ip, frame_ip_end, mem_idx);
                if (!jit_compile_op_memory_size(cc, mem_idx))
                    return false;
                break;

            case WASM_OP_MEMORY_GROW:
                read_leb_uint32(frame_ip, frame_ip_end, mem_idx);
                if (!jit_compile_op_memory_grow(cc, mem_idx))
                    return false;
                break;

            case WASM_OP_I32_CONST:
                read_leb_int32(frame_ip, frame_ip_end, i32_const);
                if (!jit_compile_op_i32_const(cc, i32_const))
                    return false;
                break;

            case WASM_OP_I64_CONST:
                read_leb_int64(frame_ip, frame_ip_end, i64_const);
                if (!jit_compile_op_i64_const(cc, i64_const))
                    return false;
                break;

            case WASM_OP_F32_CONST:
                p_f32 = (uint8 *)&f32_const;
                for (i = 0; i < sizeof(float32); i++)
                    *p_f32++ = *frame_ip++;
                if (!jit_compile_op_f32_const(cc, f32_const))
                    return false;
                break;

            case WASM_OP_F64_CONST:
                p_f64 = (uint8 *)&f64_const;
                for (i = 0; i < sizeof(float64); i++)
                    *p_f64++ = *frame_ip++;
                if (!jit_compile_op_f64_const(cc, f64_const))
                    return false;
                break;

            case WASM_OP_I32_EQZ:
            case WASM_OP_I32_EQ:
            case WASM_OP_I32_NE:
            case WASM_OP_I32_LT_S:
            case WASM_OP_I32_LT_U:
            case WASM_OP_I32_GT_S:
            case WASM_OP_I32_GT_U:
            case WASM_OP_I32_LE_S:
            case WASM_OP_I32_LE_U:
            case WASM_OP_I32_GE_S:
            case WASM_OP_I32_GE_U:
                if (!jit_compile_op_i32_compare(cc, INT_EQZ + opcode
                                                        - WASM_OP_I32_EQZ))
                    return false;
                if (frame_ip < frame_ip_end) {
                    /* Merge `CMP, SELECTcc, CMP, BNE` insns into `CMP, Bcc` */
                    if (*frame_ip == WASM_OP_IF || *frame_ip == EXT_OP_IF)
                        merge_cmp_and_if = true;
                    if (*frame_ip == WASM_OP_BR_IF)
                        merge_cmp_and_br_if = true;
                }
                break;

            case WASM_OP_I64_EQZ:
            case WASM_OP_I64_EQ:
            case WASM_OP_I64_NE:
            case WASM_OP_I64_LT_S:
            case WASM_OP_I64_LT_U:
            case WASM_OP_I64_GT_S:
            case WASM_OP_I64_GT_U:
            case WASM_OP_I64_LE_S:
            case WASM_OP_I64_LE_U:
            case WASM_OP_I64_GE_S:
            case WASM_OP_I64_GE_U:
                if (!jit_compile_op_i64_compare(cc, INT_EQZ + opcode
                                                        - WASM_OP_I64_EQZ))
                    return false;
                if (frame_ip < frame_ip_end) {
                    /* Merge `CMP, SELECTcc, CMP, BNE` insns into `CMP, Bcc` */
                    if (*frame_ip == WASM_OP_IF || *frame_ip == EXT_OP_IF)
                        merge_cmp_and_if = true;
                    if (*frame_ip == WASM_OP_BR_IF)
                        merge_cmp_and_br_if = true;
                }
                break;

            case WASM_OP_F32_EQ:
            case WASM_OP_F32_NE:
            case WASM_OP_F32_LT:
            case WASM_OP_F32_GT:
            case WASM_OP_F32_LE:
            case WASM_OP_F32_GE:
                if (!jit_compile_op_f32_compare(cc, FLOAT_EQ + opcode
                                                        - WASM_OP_F32_EQ))
                    return false;
                if (frame_ip < frame_ip_end) {
                    /* Merge `CMP, SELECTcc, CMP, BNE` insns into `CMP, Bcc` */
                    if (*frame_ip == WASM_OP_IF || *frame_ip == EXT_OP_IF)
                        merge_cmp_and_if = true;
                    if (*frame_ip == WASM_OP_BR_IF)
                        merge_cmp_and_br_if = true;
                }
                break;

            case WASM_OP_F64_EQ:
            case WASM_OP_F64_NE:
            case WASM_OP_F64_LT:
            case WASM_OP_F64_GT:
            case WASM_OP_F64_LE:
            case WASM_OP_F64_GE:
                if (!jit_compile_op_f64_compare(cc, FLOAT_EQ + opcode
                                                        - WASM_OP_F64_EQ))
                    return false;
                if (frame_ip < frame_ip_end) {
                    /* Merge `CMP, SELECTcc, CMP, BNE` insns into `CMP, Bcc` */
                    if (*frame_ip == WASM_OP_IF || *frame_ip == EXT_OP_IF)
                        merge_cmp_and_if = true;
                    if (*frame_ip == WASM_OP_BR_IF)
                        merge_cmp_and_br_if = true;
                }
                break;

            case WASM_OP_I32_CLZ:
                if (!jit_compile_op_i32_clz(cc))
                    return false;
                break;

            case WASM_OP_I32_CTZ:
                if (!jit_compile_op_i32_ctz(cc))
                    return false;
                break;

            case WASM_OP_I32_POPCNT:
                if (!jit_compile_op_i32_popcnt(cc))
                    return false;
                break;

            case WASM_OP_I32_ADD:
            case WASM_OP_I32_SUB:
            case WASM_OP_I32_MUL:
            case WASM_OP_I32_DIV_S:
            case WASM_OP_I32_DIV_U:
            case WASM_OP_I32_REM_S:
            case WASM_OP_I32_REM_U:
                if (!jit_compile_op_i32_arithmetic(
                        cc, INT_ADD + opcode - WASM_OP_I32_ADD, &frame_ip))
                    return false;
                break;

            case WASM_OP_I32_AND:
            case WASM_OP_I32_OR:
            case WASM_OP_I32_XOR:
                if (!jit_compile_op_i32_bitwise(cc, INT_SHL + opcode
                                                        - WASM_OP_I32_AND))
                    return false;
                break;

            case WASM_OP_I32_SHL:
            case WASM_OP_I32_SHR_S:
            case WASM_OP_I32_SHR_U:
            case WASM_OP_I32_ROTL:
            case WASM_OP_I32_ROTR:
                if (!jit_compile_op_i32_shift(cc, INT_SHL + opcode
                                                      - WASM_OP_I32_SHL))
                    return false;
                break;

            case WASM_OP_I64_CLZ:
                if (!jit_compile_op_i64_clz(cc))
                    return false;
                break;

            case WASM_OP_I64_CTZ:
                if (!jit_compile_op_i64_ctz(cc))
                    return false;
                break;

            case WASM_OP_I64_POPCNT:
                if (!jit_compile_op_i64_popcnt(cc))
                    return false;
                break;

            case WASM_OP_I64_ADD:
            case WASM_OP_I64_SUB:
            case WASM_OP_I64_MUL:
            case WASM_OP_I64_DIV_S:
            case WASM_OP_I64_DIV_U:
            case WASM_OP_I64_REM_S:
            case WASM_OP_I64_REM_U:
                if (!jit_compile_op_i64_arithmetic(
                        cc, INT_ADD + opcode - WASM_OP_I64_ADD, &frame_ip))
                    return false;
                break;

            case WASM_OP_I64_AND:
            case WASM_OP_I64_OR:
            case WASM_OP_I64_XOR:
                if (!jit_compile_op_i64_bitwise(cc, INT_SHL + opcode
                                                        - WASM_OP_I64_AND))
                    return false;
                break;

            case WASM_OP_I64_SHL:
            case WASM_OP_I64_SHR_S:
            case WASM_OP_I64_SHR_U:
            case WASM_OP_I64_ROTL:
            case WASM_OP_I64_ROTR:
                if (!jit_compile_op_i64_shift(cc, INT_SHL + opcode
                                                      - WASM_OP_I64_SHL))
                    return false;
                break;

            case WASM_OP_F32_ABS:
            case WASM_OP_F32_NEG:
            case WASM_OP_F32_CEIL:
            case WASM_OP_F32_FLOOR:
            case WASM_OP_F32_TRUNC:
            case WASM_OP_F32_NEAREST:
            case WASM_OP_F32_SQRT:
                if (!jit_compile_op_f32_math(cc, FLOAT_ABS + opcode
                                                     - WASM_OP_F32_ABS))
                    return false;
                break;

            case WASM_OP_F32_ADD:
            case WASM_OP_F32_SUB:
            case WASM_OP_F32_MUL:
            case WASM_OP_F32_DIV:
            case WASM_OP_F32_MIN:
            case WASM_OP_F32_MAX:
                if (!jit_compile_op_f32_arithmetic(cc, FLOAT_ADD + opcode
                                                           - WASM_OP_F32_ADD))
                    return false;
                break;

            case WASM_OP_F32_COPYSIGN:
                if (!jit_compile_op_f32_copysign(cc))
                    return false;
                break;

            case WASM_OP_F64_ABS:
            case WASM_OP_F64_NEG:
            case WASM_OP_F64_CEIL:
            case WASM_OP_F64_FLOOR:
            case WASM_OP_F64_TRUNC:
            case WASM_OP_F64_NEAREST:
            case WASM_OP_F64_SQRT:
                if (!jit_compile_op_f64_math(cc, FLOAT_ABS + opcode
                                                     - WASM_OP_F64_ABS))
                    return false;
                break;

            case WASM_OP_F64_ADD:
            case WASM_OP_F64_SUB:
            case WASM_OP_F64_MUL:
            case WASM_OP_F64_DIV:
            case WASM_OP_F64_MIN:
            case WASM_OP_F64_MAX:
                if (!jit_compile_op_f64_arithmetic(cc, FLOAT_ADD + opcode
                                                           - WASM_OP_F64_ADD))
                    return false;
                break;

            case WASM_OP_F64_COPYSIGN:
                if (!jit_compile_op_f64_copysign(cc))
                    return false;
                break;

            case WASM_OP_I32_WRAP_I64:
                if (!jit_compile_op_i32_wrap_i64(cc))
                    return false;
                break;

            case WASM_OP_I32_TRUNC_S_F32:
            case WASM_OP_I32_TRUNC_U_F32:
                sign = (opcode == WASM_OP_I32_TRUNC_S_F32) ? true : false;
                if (!jit_compile_op_i32_trunc_f32(cc, sign, false))
                    return false;
                break;

            case WASM_OP_I32_TRUNC_S_F64:
            case WASM_OP_I32_TRUNC_U_F64:
                sign = (opcode == WASM_OP_I32_TRUNC_S_F64) ? true : false;
                if (!jit_compile_op_i32_trunc_f64(cc, sign, false))
                    return false;
                break;

            case WASM_OP_I64_EXTEND_S_I32:
            case WASM_OP_I64_EXTEND_U_I32:
                sign = (opcode == WASM_OP_I64_EXTEND_S_I32) ? true : false;
                if (!jit_compile_op_i64_extend_i32(cc, sign))
                    return false;
                break;

            case WASM_OP_I64_TRUNC_S_F32:
            case WASM_OP_I64_TRUNC_U_F32:
                sign = (opcode == WASM_OP_I64_TRUNC_S_F32) ? true : false;
                if (!jit_compile_op_i64_trunc_f32(cc, sign, false))
                    return false;
                break;

            case WASM_OP_I64_TRUNC_S_F64:
            case WASM_OP_I64_TRUNC_U_F64:
                sign = (opcode == WASM_OP_I64_TRUNC_S_F64) ? true : false;
                if (!jit_compile_op_i64_trunc_f64(cc, sign, false))
                    return false;
                break;

            case WASM_OP_F32_CONVERT_S_I32:
            case WASM_OP_F32_CONVERT_U_I32:
                sign = (opcode == WASM_OP_F32_CONVERT_S_I32) ? true : false;
                if (!jit_compile_op_f32_convert_i32(cc, sign))
                    return false;
                break;

            case WASM_OP_F32_CONVERT_S_I64:
            case WASM_OP_F32_CONVERT_U_I64:
                sign = (opcode == WASM_OP_F32_CONVERT_S_I64) ? true : false;
                if (!jit_compile_op_f32_convert_i64(cc, sign))
                    return false;
                break;

            case WASM_OP_F32_DEMOTE_F64:
                if (!jit_compile_op_f32_demote_f64(cc))
                    return false;
                break;

            case WASM_OP_F64_CONVERT_S_I32:
            case WASM_OP_F64_CONVERT_U_I32:
                sign = (opcode == WASM_OP_F64_CONVERT_S_I32) ? true : false;
                if (!jit_compile_op_f64_convert_i32(cc, sign))
                    return false;
                break;

            case WASM_OP_F64_CONVERT_S_I64:
            case WASM_OP_F64_CONVERT_U_I64:
                sign = (opcode == WASM_OP_F64_CONVERT_S_I64) ? true : false;
                if (!jit_compile_op_f64_convert_i64(cc, sign))
                    return false;
                break;

            case WASM_OP_F64_PROMOTE_F32:
                if (!jit_compile_op_f64_promote_f32(cc))
                    return false;
                break;

            case WASM_OP_I32_REINTERPRET_F32:
                if (!jit_compile_op_i32_reinterpret_f32(cc))
                    return false;
                break;

            case WASM_OP_I64_REINTERPRET_F64:
                if (!jit_compile_op_i64_reinterpret_f64(cc))
                    return false;
                break;

            case WASM_OP_F32_REINTERPRET_I32:
                if (!jit_compile_op_f32_reinterpret_i32(cc))
                    return false;
                break;

            case WASM_OP_F64_REINTERPRET_I64:
                if (!jit_compile_op_f64_reinterpret_i64(cc))
                    return false;
                break;

            case WASM_OP_I32_EXTEND8_S:
                if (!jit_compile_op_i32_extend_i32(cc, 8))
                    return false;
                break;

            case WASM_OP_I32_EXTEND16_S:
                if (!jit_compile_op_i32_extend_i32(cc, 16))
                    return false;
                break;

            case WASM_OP_I64_EXTEND8_S:
                if (!jit_compile_op_i64_extend_i64(cc, 8))
                    return false;
                break;

            case WASM_OP_I64_EXTEND16_S:
                if (!jit_compile_op_i64_extend_i64(cc, 16))
                    return false;
                break;

            case WASM_OP_I64_EXTEND32_S:
                if (!jit_compile_op_i64_extend_i64(cc, 32))
                    return false;
                break;

            case WASM_OP_MISC_PREFIX:
            {
                uint32 opcode1;

                read_leb_uint32(frame_ip, frame_ip_end, opcode1);
                /* opcode1 was checked in loader and is no larger than
                   UINT8_MAX */
                opcode = (uint8)opcode1;

                switch (opcode) {
                    case WASM_OP_I32_TRUNC_SAT_S_F32:
                    case WASM_OP_I32_TRUNC_SAT_U_F32:
                        sign = (opcode == WASM_OP_I32_TRUNC_SAT_S_F32) ? true
                                                                       : false;
                        if (!jit_compile_op_i32_trunc_f32(cc, sign, true))
                            return false;
                        break;
                    case WASM_OP_I32_TRUNC_SAT_S_F64:
                    case WASM_OP_I32_TRUNC_SAT_U_F64:
                        sign = (opcode == WASM_OP_I32_TRUNC_SAT_S_F64) ? true
                                                                       : false;
                        if (!jit_compile_op_i32_trunc_f64(cc, sign, true))
                            return false;
                        break;
                    case WASM_OP_I64_TRUNC_SAT_S_F32:
                    case WASM_OP_I64_TRUNC_SAT_U_F32:
                        sign = (opcode == WASM_OP_I64_TRUNC_SAT_S_F32) ? true
                                                                       : false;
                        if (!jit_compile_op_i64_trunc_f32(cc, sign, true))
                            return false;
                        break;
                    case WASM_OP_I64_TRUNC_SAT_S_F64:
                    case WASM_OP_I64_TRUNC_SAT_U_F64:
                        sign = (opcode == WASM_OP_I64_TRUNC_SAT_S_F64) ? true
                                                                       : false;
                        if (!jit_compile_op_i64_trunc_f64(cc, sign, true))
                            return false;
                        break;
#if WASM_ENABLE_BULK_MEMORY != 0
                    case WASM_OP_MEMORY_INIT:
                    {
                        uint32 seg_idx = 0;
                        read_leb_uint32(frame_ip, frame_ip_end, seg_idx);
                        read_leb_uint32(frame_ip, frame_ip_end, mem_idx);
                        if (!jit_compile_op_memory_init(cc, mem_idx, seg_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_DATA_DROP:
                    {
                        uint32 seg_idx;
                        read_leb_uint32(frame_ip, frame_ip_end, seg_idx);
                        if (!jit_compile_op_data_drop(cc, seg_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_MEMORY_COPY:
                    {
                        uint32 src_mem_idx, dst_mem_idx;
                        read_leb_uint32(frame_ip, frame_ip_end, src_mem_idx);
                        read_leb_uint32(frame_ip, frame_ip_end, dst_mem_idx);
                        if (!jit_compile_op_memory_copy(cc, src_mem_idx,
                                                        dst_mem_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_MEMORY_FILL:
                    {
                        read_leb_uint32(frame_ip, frame_ip_end, mem_idx);
                        if (!jit_compile_op_memory_fill(cc, mem_idx))
                            return false;
                        break;
                    }
#endif /* WASM_ENABLE_BULK_MEMORY */
#if WASM_ENABLE_REF_TYPES != 0
                    case WASM_OP_TABLE_INIT:
                    {
                        uint32 tbl_idx, tbl_seg_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_seg_idx);
                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        if (!jit_compile_op_table_init(cc, tbl_idx,
                                                       tbl_seg_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_ELEM_DROP:
                    {
                        uint32 tbl_seg_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_seg_idx);
                        if (!jit_compile_op_elem_drop(cc, tbl_seg_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_TABLE_COPY:
                    {
                        uint32 src_tbl_idx, dst_tbl_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, dst_tbl_idx);
                        read_leb_uint32(frame_ip, frame_ip_end, src_tbl_idx);
                        if (!jit_compile_op_table_copy(cc, src_tbl_idx,
                                                       dst_tbl_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_TABLE_GROW:
                    {
                        uint32 tbl_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        if (!jit_compile_op_table_grow(cc, tbl_idx))
                            return false;
                        break;
                    }

                    case WASM_OP_TABLE_SIZE:
                    {
                        uint32 tbl_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        if (!jit_compile_op_table_size(cc, tbl_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_TABLE_FILL:
                    {
                        uint32 tbl_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        if (!jit_compile_op_table_fill(cc, tbl_idx))
                            return false;
                        break;
                    }
#endif /* WASM_ENABLE_REF_TYPES */
                    default:
                        jit_set_last_error(cc, "unsupported opcode");
                        return false;
                }
                break;
            }

#if WASM_ENABLE_SHARED_MEMORY != 0
            case WASM_OP_ATOMIC_PREFIX:
            {
                uint8 bin_op, op_type;
                uint32 opcode1;

                read_leb_uint32(frame_ip, frame_ip_end, opcode1);
                /* opcode1 was checked in loader and is no larger than
                   UINT8_MAX */
                opcode = (uint8)opcode1;

                if (opcode != WASM_OP_ATOMIC_FENCE) {
                    read_leb_uint32(frame_ip, frame_ip_end, align);
                    read_leb_uint32(frame_ip, frame_ip_end, offset);
                }
                switch (opcode) {
                    case WASM_OP_ATOMIC_WAIT32:
                        if (!jit_compile_op_atomic_wait(cc, VALUE_TYPE_I32,
                                                        align, offset, 4))
                            return false;
                        break;
                    case WASM_OP_ATOMIC_WAIT64:
                        if (!jit_compile_op_atomic_wait(cc, VALUE_TYPE_I64,
                                                        align, offset, 8))
                            return false;
                        break;
                    case WASM_OP_ATOMIC_NOTIFY:
                        if (!jit_compiler_op_atomic_notify(cc, align, offset,
                                                           bytes))
                            return false;
                        break;
                    case WASM_OP_ATOMIC_FENCE:
                        /* Skip memory index */
                        frame_ip++;
                        if (!jit_compiler_op_atomic_fence(cc))
                            return false;
                        break;
                    case WASM_OP_ATOMIC_I32_LOAD:
                        bytes = 4;
                        goto op_atomic_i32_load;
                    case WASM_OP_ATOMIC_I32_LOAD8_U:
                        bytes = 1;
                        goto op_atomic_i32_load;
                    case WASM_OP_ATOMIC_I32_LOAD16_U:
                        bytes = 2;
                    op_atomic_i32_load:
                        if (!jit_compile_op_i32_load(cc, align, offset, bytes,
                                                     sign, true))
                            return false;
                        break;

                    case WASM_OP_ATOMIC_I64_LOAD:
                        bytes = 8;
                        goto op_atomic_i64_load;
                    case WASM_OP_ATOMIC_I64_LOAD8_U:
                        bytes = 1;
                        goto op_atomic_i64_load;
                    case WASM_OP_ATOMIC_I64_LOAD16_U:
                        bytes = 2;
                        goto op_atomic_i64_load;
                    case WASM_OP_ATOMIC_I64_LOAD32_U:
                        bytes = 4;
                    op_atomic_i64_load:
                        if (!jit_compile_op_i64_load(cc, align, offset, bytes,
                                                     sign, true))
                            return false;
                        break;

                    case WASM_OP_ATOMIC_I32_STORE:
                        bytes = 4;
                        goto op_atomic_i32_store;
                    case WASM_OP_ATOMIC_I32_STORE8:
                        bytes = 1;
                        goto op_atomic_i32_store;
                    case WASM_OP_ATOMIC_I32_STORE16:
                        bytes = 2;
                    op_atomic_i32_store:
                        if (!jit_compile_op_i32_store(cc, align, offset, bytes,
                                                      true))
                            return false;
                        break;

                    case WASM_OP_ATOMIC_I64_STORE:
                        bytes = 8;
                        goto op_atomic_i64_store;
                    case WASM_OP_ATOMIC_I64_STORE8:
                        bytes = 1;
                        goto op_atomic_i64_store;
                    case WASM_OP_ATOMIC_I64_STORE16:
                        bytes = 2;
                        goto op_atomic_i64_store;
                    case WASM_OP_ATOMIC_I64_STORE32:
                        bytes = 4;
                    op_atomic_i64_store:
                        if (!jit_compile_op_i64_store(cc, align, offset, bytes,
                                                      true))
                            return false;
                        break;

                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG:
                        bytes = 4;
                        op_type = VALUE_TYPE_I32;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG:
                        bytes = 8;
                        op_type = VALUE_TYPE_I64;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG8_U:
                        bytes = 1;
                        op_type = VALUE_TYPE_I32;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG16_U:
                        bytes = 2;
                        op_type = VALUE_TYPE_I32;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG8_U:
                        bytes = 1;
                        op_type = VALUE_TYPE_I64;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG16_U:
                        bytes = 2;
                        op_type = VALUE_TYPE_I64;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG32_U:
                        bytes = 4;
                        op_type = VALUE_TYPE_I64;
                    op_atomic_cmpxchg:
                        if (!jit_compile_op_atomic_cmpxchg(cc, op_type, align,
                                                           offset, bytes))
                            return false;
                        break;

                        COMPILE_ATOMIC_RMW(Add, ADD);
                        COMPILE_ATOMIC_RMW(Sub, SUB);
                        COMPILE_ATOMIC_RMW(And, AND);
                        COMPILE_ATOMIC_RMW(Or, OR);
                        COMPILE_ATOMIC_RMW(Xor, XOR);
                        COMPILE_ATOMIC_RMW(Xchg, XCHG);

                    build_atomic_rmw:
                        if (!jit_compile_op_atomic_rmw(cc, bin_op, op_type,
                                                       align, offset, bytes))
                            return false;
                        break;

                    default:
                        jit_set_last_error(cc, "unsupported opcode");
                        return false;
                }
                break;
            }
#endif /* end of WASM_ENABLE_SHARED_MEMORY */

            default:
                jit_set_last_error(cc, "unsupported opcode");
                return false;
        }
        /* Error may occur when creating registers, basic blocks, insns,
           consts and labels, in which the return value may be unchecked,
           here we check again */
        if (jit_get_last_error(cc)) {
            return false;
        }
    }

    (void)func_idx;
    return true;
fail:
    return false;
}

JitBasicBlock *
jit_frontend_translate_func(JitCompContext *cc)
{
    JitFrame *jit_frame;
    JitBasicBlock *basic_block_entry;

    if (!(jit_frame = init_func_translation(cc))) {
        return NULL;
    }

    if (!(basic_block_entry = create_func_block(cc))) {
        return NULL;
    }

    if (!jit_compile_func(cc)) {
        return NULL;
    }

    return basic_block_entry;
}

uint32
jit_frontend_get_jitted_return_addr_offset()
{
    return (uint32)offsetof(WASMInterpFrame, jitted_return_addr);
}
