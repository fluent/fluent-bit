/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_llvm.h"
#include "aot_compiler.h"
#include "aot_emit_exception.h"
#include "../aot/aot_runtime.h"
#include "../aot/aot_intrinsic.h"

#if WASM_ENABLE_DEBUG_AOT != 0
#include "debug/dwarf_extractor.h"
#endif

LLVMTypeRef
wasm_type_to_llvm_type(AOTLLVMTypes *llvm_types, uint8 wasm_type)
{
    switch (wasm_type) {
        case VALUE_TYPE_I32:
        case VALUE_TYPE_FUNCREF:
        case VALUE_TYPE_EXTERNREF:
            return llvm_types->int32_type;
        case VALUE_TYPE_I64:
            return llvm_types->int64_type;
        case VALUE_TYPE_F32:
            return llvm_types->float32_type;
        case VALUE_TYPE_F64:
            return llvm_types->float64_type;
        case VALUE_TYPE_V128:
            return llvm_types->i64x2_vec_type;
        case VALUE_TYPE_VOID:
            return llvm_types->void_type;
        default:
            break;
    }
    return NULL;
}

/**
 * Add LLVM function
 */
static LLVMValueRef
aot_add_llvm_func(AOTCompContext *comp_ctx, LLVMModuleRef module,
                  AOTFuncType *aot_func_type, uint32 func_index,
                  LLVMTypeRef *p_func_type)
{
    LLVMValueRef func = NULL;
    LLVMTypeRef *param_types, ret_type, func_type;
    LLVMValueRef local_value;
    char func_name[32];
    uint64 size;
    uint32 i, j = 0, param_count = (uint64)aot_func_type->param_count;

    /* exec env as first parameter */
    param_count++;

    /* Extra wasm function results(except the first one)'s address are
     * appended to aot function parameters. */
    if (aot_func_type->result_count > 1)
        param_count += aot_func_type->result_count - 1;

    /* Initialize parameter types of the LLVM function */
    size = sizeof(LLVMTypeRef) * ((uint64)param_count);
    if (size >= UINT32_MAX
        || !(param_types = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    /* exec env as first parameter */
    param_types[j++] = comp_ctx->exec_env_type;
    for (i = 0; i < aot_func_type->param_count; i++)
        param_types[j++] = TO_LLVM_TYPE(aot_func_type->types[i]);
    /* Extra results' address */
    for (i = 1; i < aot_func_type->result_count; i++, j++) {
        param_types[j] =
            TO_LLVM_TYPE(aot_func_type->types[aot_func_type->param_count + i]);
        if (!(param_types[j] = LLVMPointerType(param_types[j], 0))) {
            aot_set_last_error("llvm get pointer type failed.");
            goto fail;
        }
    }

    /* Resolve return type of the LLVM function */
    if (aot_func_type->result_count)
        ret_type =
            TO_LLVM_TYPE(aot_func_type->types[aot_func_type->param_count]);
    else
        ret_type = VOID_TYPE;

    /* Resolve function prototype */
    if (!(func_type =
              LLVMFunctionType(ret_type, param_types, param_count, false))) {
        aot_set_last_error("create LLVM function type failed.");
        goto fail;
    }

    /* Add LLVM function */
    snprintf(func_name, sizeof(func_name), "%s%d", AOT_FUNC_PREFIX, func_index);
    if (!(func = LLVMAddFunction(module, func_name, func_type))) {
        aot_set_last_error("add LLVM function failed.");
        goto fail;
    }

    j = 0;
    local_value = LLVMGetParam(func, j++);
    LLVMSetValueName(local_value, "exec_env");

    /* Set parameter names */
    for (i = 0; i < aot_func_type->param_count; i++) {
        local_value = LLVMGetParam(func, j++);
        LLVMSetValueName(local_value, "");
    }

    if (p_func_type)
        *p_func_type = func_type;

fail:
    wasm_runtime_free(param_types);
    return func;
}

static void
free_block_memory(AOTBlock *block)
{
    if (block->param_types)
        wasm_runtime_free(block->param_types);
    if (block->result_types)
        wasm_runtime_free(block->result_types);
    wasm_runtime_free(block);
}

/**
 * Create first AOTBlock, or function block for the function
 */
static AOTBlock *
aot_create_func_block(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                      AOTFunc *func, AOTFuncType *aot_func_type)
{
    AOTBlock *aot_block;
    uint32 param_count = aot_func_type->param_count,
           result_count = aot_func_type->result_count;

    /* Allocate memory */
    if (!(aot_block = wasm_runtime_malloc(sizeof(AOTBlock)))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }
    memset(aot_block, 0, sizeof(AOTBlock));
    if (param_count
        && !(aot_block->param_types = wasm_runtime_malloc(param_count))) {
        aot_set_last_error("allocate memory failed.");
        goto fail;
    }
    if (result_count) {
        if (!(aot_block->result_types = wasm_runtime_malloc(result_count))) {
            aot_set_last_error("allocate memory failed.");
            goto fail;
        }
    }

    /* Set block data */
    aot_block->label_type = LABEL_TYPE_FUNCTION;
    aot_block->param_count = param_count;
    if (param_count) {
        bh_memcpy_s(aot_block->param_types, param_count, aot_func_type->types,
                    param_count);
    }
    aot_block->result_count = result_count;
    if (result_count) {
        bh_memcpy_s(aot_block->result_types, result_count,
                    aot_func_type->types + param_count, result_count);
    }
    aot_block->wasm_code_end = func->code + func->code_size;

    /* Add function entry block */
    if (!(aot_block->llvm_entry_block = LLVMAppendBasicBlockInContext(
              comp_ctx->context, func_ctx->func, "func_begin"))) {
        aot_set_last_error("add LLVM basic block failed.");
        goto fail;
    }

    return aot_block;

fail:
    free_block_memory(aot_block);
    return NULL;
}

static bool
create_memory_info(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                   LLVMTypeRef int8_ptr_type, uint32 func_index)
{
    LLVMValueRef offset, mem_info_base;
    uint32 memory_count;
    WASMModule *module = comp_ctx->comp_data->wasm_module;
    WASMFunction *func = module->functions[func_index];
    LLVMTypeRef bound_check_type;
    bool mem_space_unchanged =
        (!func->has_op_memory_grow && !func->has_op_func_call)
        || (!module->possible_memory_grow);
#if WASM_ENABLE_SHARED_MEMORY != 0
    bool is_shared_memory;
#endif

    func_ctx->mem_space_unchanged = mem_space_unchanged;

    memory_count = module->memory_count + module->import_memory_count;
    /* If the module dosen't have memory, reserve
        one mem_info space with empty content */
    if (memory_count == 0)
        memory_count = 1;

    if (!(func_ctx->mem_info =
              wasm_runtime_malloc(sizeof(AOTMemInfo) * memory_count))) {
        return false;
    }
    memset(func_ctx->mem_info, 0, sizeof(AOTMemInfo));

    /* Currently we only create memory info for memory 0 */
    /* Load memory base address */
#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared_memory =
        comp_ctx->comp_data->memories[0].memory_flags & 0x02 ? true : false;
    if (is_shared_memory) {
        LLVMValueRef shared_mem_addr;
        offset = I32_CONST(offsetof(AOTModuleInstance, memories));
        if (!offset) {
            aot_set_last_error("create llvm const failed.");
            return false;
        }

        /* aot_inst->memories */
        if (!(shared_mem_addr = LLVMBuildInBoundsGEP2(
                  comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst, &offset, 1,
                  "shared_mem_addr_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
        if (!(shared_mem_addr =
                  LLVMBuildBitCast(comp_ctx->builder, shared_mem_addr,
                                   int8_ptr_type, "shared_mem_addr_ptr"))) {
            aot_set_last_error("llvm build bit cast failed");
            return false;
        }
        /* aot_inst->memories[0] */
        if (!(shared_mem_addr =
                  LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                                 shared_mem_addr, "shared_mem_addr"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
        if (!(shared_mem_addr =
                  LLVMBuildBitCast(comp_ctx->builder, shared_mem_addr,
                                   int8_ptr_type, "shared_mem_addr_ptr"))) {
            aot_set_last_error("llvm build bit cast failed");
            return false;
        }
        if (!(shared_mem_addr =
                  LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                                 shared_mem_addr, "shared_mem_addr"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
        /* memories[0]->memory_data */
        offset = I32_CONST(offsetof(AOTMemoryInstance, memory_data.ptr));
        if (!(func_ctx->mem_info[0].mem_base_addr = LLVMBuildInBoundsGEP2(
                  comp_ctx->builder, INT8_TYPE, shared_mem_addr, &offset, 1,
                  "mem_base_addr_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
        /* memories[0]->cur_page_count */
        offset = I32_CONST(offsetof(AOTMemoryInstance, cur_page_count));
        if (!(func_ctx->mem_info[0].mem_cur_page_count_addr =
                  LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE,
                                        shared_mem_addr, &offset, 1,
                                        "mem_cur_page_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
        /* memories[0]->memory_data_size */
        offset = I32_CONST(offsetof(AOTMemoryInstance, memory_data_size));
        if (!(func_ctx->mem_info[0].mem_data_size_addr = LLVMBuildInBoundsGEP2(
                  comp_ctx->builder, INT8_TYPE, shared_mem_addr, &offset, 1,
                  "mem_data_size_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
    }
    else
#endif
    {
        offset = I32_CONST(offsetof(AOTModuleInstance, global_table_data)
                           + offsetof(AOTMemoryInstance, memory_data.ptr));
        if (!(func_ctx->mem_info[0].mem_base_addr = LLVMBuildInBoundsGEP2(
                  comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst, &offset, 1,
                  "mem_base_addr_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
        offset = I32_CONST(offsetof(AOTModuleInstance, global_table_data)
                           + offsetof(AOTMemoryInstance, cur_page_count));
        if (!(func_ctx->mem_info[0].mem_cur_page_count_addr =
                  LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE,
                                        func_ctx->aot_inst, &offset, 1,
                                        "mem_cur_page_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
        offset = I32_CONST(offsetof(AOTModuleInstance, global_table_data)
                           + offsetof(AOTMemoryInstance, memory_data_size));
        if (!(func_ctx->mem_info[0].mem_data_size_addr = LLVMBuildInBoundsGEP2(
                  comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst, &offset, 1,
                  "mem_data_size_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
    }
    /* Store mem info base address before cast */
    mem_info_base = func_ctx->mem_info[0].mem_base_addr;

    if (!(func_ctx->mem_info[0].mem_base_addr = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_base_addr,
              int8_ptr_type, "mem_base_addr_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_cur_page_count_addr = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_cur_page_count_addr,
              INT32_PTR_TYPE, "mem_cur_page_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_data_size_addr = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_data_size_addr,
              INT32_PTR_TYPE, "mem_data_size_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_base_addr = LLVMBuildLoad2(
                  comp_ctx->builder, OPQ_PTR_TYPE,
                  func_ctx->mem_info[0].mem_base_addr, "mem_base_addr"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
        if (!(func_ctx->mem_info[0].mem_cur_page_count_addr =
                  LLVMBuildLoad2(comp_ctx->builder, I32_TYPE,
                                 func_ctx->mem_info[0].mem_cur_page_count_addr,
                                 "mem_cur_page_count"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
        if (!(func_ctx->mem_info[0].mem_data_size_addr = LLVMBuildLoad2(
                  comp_ctx->builder, I32_TYPE,
                  func_ctx->mem_info[0].mem_data_size_addr, "mem_data_size"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }
#if WASM_ENABLE_SHARED_MEMORY != 0
    else if (is_shared_memory) {
        /* The base address for shared memory will never changed,
            we can load the value here */
        if (!(func_ctx->mem_info[0].mem_base_addr = LLVMBuildLoad2(
                  comp_ctx->builder, OPQ_PTR_TYPE,
                  func_ctx->mem_info[0].mem_base_addr, "mem_base_addr"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }
#endif

    bound_check_type = (comp_ctx->pointer_size == sizeof(uint64))
                           ? INT64_PTR_TYPE
                           : INT32_PTR_TYPE;

    /* Load memory bound check constants */
    offset = I32_CONST(offsetof(AOTMemoryInstance, mem_bound_check_1byte)
                       - offsetof(AOTMemoryInstance, memory_data.ptr));
    if (!(func_ctx->mem_info[0].mem_bound_check_1byte =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, mem_info_base,
                                    &offset, 1, "bound_check_1byte_offset"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_bound_check_1byte = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_bound_check_1byte,
              bound_check_type, "bound_check_1byte_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_bound_check_1byte = LLVMBuildLoad2(
                  comp_ctx->builder,
                  (comp_ctx->pointer_size == sizeof(uint64)) ? I64_TYPE
                                                             : I32_TYPE,
                  func_ctx->mem_info[0].mem_bound_check_1byte,
                  "bound_check_1byte"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }

    offset = I32_CONST(offsetof(AOTMemoryInstance, mem_bound_check_2bytes)
                       - offsetof(AOTMemoryInstance, memory_data.ptr));
    if (!(func_ctx->mem_info[0].mem_bound_check_2bytes =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, mem_info_base,
                                    &offset, 1, "bound_check_2bytes_offset"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_bound_check_2bytes = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_bound_check_2bytes,
              bound_check_type, "bound_check_2bytes_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_bound_check_2bytes = LLVMBuildLoad2(
                  comp_ctx->builder,
                  (comp_ctx->pointer_size == sizeof(uint64)) ? I64_TYPE
                                                             : I32_TYPE,
                  func_ctx->mem_info[0].mem_bound_check_2bytes,
                  "bound_check_2bytes"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }

    offset = I32_CONST(offsetof(AOTMemoryInstance, mem_bound_check_4bytes)
                       - offsetof(AOTMemoryInstance, memory_data.ptr));
    if (!(func_ctx->mem_info[0].mem_bound_check_4bytes =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, mem_info_base,
                                    &offset, 1, "bound_check_4bytes_offset"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_bound_check_4bytes = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_bound_check_4bytes,
              bound_check_type, "bound_check_4bytes_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_bound_check_4bytes = LLVMBuildLoad2(
                  comp_ctx->builder,
                  (comp_ctx->pointer_size == sizeof(uint64)) ? I64_TYPE
                                                             : I32_TYPE,
                  func_ctx->mem_info[0].mem_bound_check_4bytes,
                  "bound_check_4bytes"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }

    offset = I32_CONST(offsetof(AOTMemoryInstance, mem_bound_check_8bytes)
                       - offsetof(AOTMemoryInstance, memory_data.ptr));
    if (!(func_ctx->mem_info[0].mem_bound_check_8bytes =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, mem_info_base,
                                    &offset, 1, "bound_check_8bytes_offset"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_bound_check_8bytes = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_bound_check_8bytes,
              bound_check_type, "bound_check_8bytes_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_bound_check_8bytes = LLVMBuildLoad2(
                  comp_ctx->builder,
                  (comp_ctx->pointer_size == sizeof(uint64)) ? I64_TYPE
                                                             : I32_TYPE,
                  func_ctx->mem_info[0].mem_bound_check_8bytes,
                  "bound_check_8bytes"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }

    offset = I32_CONST(offsetof(AOTMemoryInstance, mem_bound_check_16bytes)
                       - offsetof(AOTMemoryInstance, memory_data.ptr));
    if (!(func_ctx->mem_info[0].mem_bound_check_16bytes = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, INT8_TYPE, mem_info_base, &offset, 1,
              "bound_check_16bytes_offset"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_bound_check_16bytes = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_bound_check_16bytes,
              bound_check_type, "bound_check_16bytes_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_bound_check_16bytes = LLVMBuildLoad2(
                  comp_ctx->builder,
                  (comp_ctx->pointer_size == sizeof(uint64)) ? I64_TYPE
                                                             : I32_TYPE,
                  func_ctx->mem_info[0].mem_bound_check_16bytes,
                  "bound_check_16bytes"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }

    return true;
}

static bool
create_cur_exception(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef offset;

    offset = I32_CONST(offsetof(AOTModuleInstance, cur_exception));
    func_ctx->cur_exception =
        LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst,
                              &offset, 1, "cur_exception");
    if (!func_ctx->cur_exception) {
        aot_set_last_error("llvm build in bounds gep failed.");
        return false;
    }
    return true;
}

static bool
create_func_type_indexes(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef offset, func_type_indexes_ptr;
    LLVMTypeRef int32_ptr_type;

    offset = I32_CONST(offsetof(AOTModuleInstance, func_type_indexes.ptr));
    func_type_indexes_ptr =
        LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst,
                              &offset, 1, "func_type_indexes_ptr");
    if (!func_type_indexes_ptr) {
        aot_set_last_error("llvm build add failed.");
        return false;
    }

    if (!(int32_ptr_type = LLVMPointerType(INT32_PTR_TYPE, 0))) {
        aot_set_last_error("llvm get pointer type failed.");
        return false;
    }

    func_ctx->func_type_indexes =
        LLVMBuildBitCast(comp_ctx->builder, func_type_indexes_ptr,
                         int32_ptr_type, "func_type_indexes_tmp");
    if (!func_ctx->func_type_indexes) {
        aot_set_last_error("llvm build bit cast failed.");
        return false;
    }

    func_ctx->func_type_indexes =
        LLVMBuildLoad2(comp_ctx->builder, INT32_PTR_TYPE,
                       func_ctx->func_type_indexes, "func_type_indexes");
    if (!func_ctx->func_type_indexes) {
        aot_set_last_error("llvm build load failed.");
        return false;
    }
    return true;
}

static bool
create_func_ptrs(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef offset;

    offset = I32_CONST(offsetof(AOTModuleInstance, func_ptrs));
    func_ctx->func_ptrs =
        LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst,
                              &offset, 1, "func_ptrs_offset");
    if (!func_ctx->func_ptrs) {
        aot_set_last_error("llvm build in bounds gep failed.");
        return false;
    }
    func_ctx->func_ptrs =
        LLVMBuildBitCast(comp_ctx->builder, func_ctx->func_ptrs,
                         comp_ctx->exec_env_type, "func_ptrs_tmp");
    if (!func_ctx->func_ptrs) {
        aot_set_last_error("llvm build bit cast failed.");
        return false;
    }

    func_ctx->func_ptrs = LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                                         func_ctx->func_ptrs, "func_ptrs_ptr");
    if (!func_ctx->func_ptrs) {
        aot_set_last_error("llvm build load failed.");
        return false;
    }

    func_ctx->func_ptrs =
        LLVMBuildBitCast(comp_ctx->builder, func_ctx->func_ptrs,
                         comp_ctx->exec_env_type, "func_ptrs");
    if (!func_ctx->func_ptrs) {
        aot_set_last_error("llvm build bit cast failed.");
        return false;
    }

    return true;
}

/**
 * Create function compiler context
 */
static AOTFuncContext *
aot_create_func_context(AOTCompData *comp_data, AOTCompContext *comp_ctx,
                        AOTFunc *func, uint32 func_index)
{
    AOTFuncContext *func_ctx;
    AOTFuncType *aot_func_type = comp_data->func_types[func->func_type_index];
    AOTBlock *aot_block;
    LLVMTypeRef int8_ptr_type, int32_ptr_type;
    LLVMValueRef aot_inst_offset = I32_TWO, aot_inst_addr;
    LLVMValueRef argv_buf_offset = I32_THREE, argv_buf_addr;
    LLVMValueRef stack_bound_offset = I32_FOUR, stack_bound_addr;
    LLVMValueRef aux_stack_bound_offset = I32_SIX, aux_stack_bound_addr;
    LLVMValueRef aux_stack_bottom_offset = I32_SEVEN, aux_stack_bottom_addr;
    LLVMValueRef native_symbol_offset = I32_EIGHT, native_symbol_addr;
    char local_name[32];
    uint64 size;
    uint32 i, j = 0;

    /* Allocate memory for the function context */
    size = offsetof(AOTFuncContext, locals)
           + sizeof(LLVMValueRef)
                 * ((uint64)aot_func_type->param_count + func->local_count);
    if (size >= UINT32_MAX || !(func_ctx = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    memset(func_ctx, 0, (uint32)size);
    func_ctx->aot_func = func;

#if WASM_ENABLE_LAZY_JIT == 0
    func_ctx->module = comp_ctx->module;
#else
    func_ctx->module = comp_ctx->modules[func_index];
#endif

    /* Add LLVM function */
    if (!(func_ctx->func =
              aot_add_llvm_func(comp_ctx, func_ctx->module, aot_func_type,
                                func_index, &func_ctx->func_type)))
        goto fail;

    /* Create function's first AOTBlock */
    if (!(aot_block =
              aot_create_func_block(comp_ctx, func_ctx, func, aot_func_type)))
        goto fail;

#if WASM_ENABLE_DEBUG_AOT != 0
    func_ctx->debug_func = dwarf_gen_func_info(comp_ctx, func_ctx);
#endif

    aot_block_stack_push(&func_ctx->block_stack, aot_block);

    /* Add local variables */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, aot_block->llvm_entry_block);

    /* Save the pameters for fast access */
    func_ctx->exec_env = LLVMGetParam(func_ctx->func, j++);

    /* Get aot inst address, the layout of exec_env is:
       exec_env->next, exec_env->prev, exec_env->module_inst, and argv_buf */
    if (!(aot_inst_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &aot_inst_offset, 1, "aot_inst_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        goto fail;
    }

    /* Load aot inst */
    if (!(func_ctx->aot_inst = LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                                              aot_inst_addr, "aot_inst"))) {
        aot_set_last_error("llvm build load failed");
        goto fail;
    }

    /* Get argv buffer address */
    if (!(argv_buf_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &argv_buf_offset, 1, "argv_buf_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        goto fail;
    }

    if (!(int32_ptr_type = LLVMPointerType(INT32_PTR_TYPE, 0))) {
        aot_set_last_error("llvm add pointer type failed");
        goto fail;
    }

    /* Convert to int32 pointer type */
    if (!(argv_buf_addr = LLVMBuildBitCast(comp_ctx->builder, argv_buf_addr,
                                           int32_ptr_type, "argv_buf_ptr"))) {
        aot_set_last_error("llvm build load failed");
        goto fail;
    }

    if (!(func_ctx->argv_buf = LLVMBuildLoad2(comp_ctx->builder, INT32_PTR_TYPE,
                                              argv_buf_addr, "argv_buf"))) {
        aot_set_last_error("llvm build load failed");
        goto fail;
    }

    /* Get native stack boundary address */
    if (!(stack_bound_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &stack_bound_offset, 1, "stack_bound_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        goto fail;
    }

    if (!(func_ctx->native_stack_bound =
              LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE, stack_bound_addr,
                             "native_stack_bound"))) {
        aot_set_last_error("llvm build load failed");
        goto fail;
    }

    /* Get aux stack boundary address */
    if (!(aux_stack_bound_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &aux_stack_bound_offset, 1, "aux_stack_bound_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        goto fail;
    }

    if (!(aux_stack_bound_addr =
              LLVMBuildBitCast(comp_ctx->builder, aux_stack_bound_addr,
                               INT32_PTR_TYPE, "aux_stack_bound_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        goto fail;
    }

    if (!(func_ctx->aux_stack_bound =
              LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, aux_stack_bound_addr,
                             "aux_stack_bound"))) {
        aot_set_last_error("llvm build load failed");
        goto fail;
    }

    /* Get aux stack bottom address */
    if (!(aux_stack_bottom_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &aux_stack_bottom_offset, 1, "aux_stack_bottom_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        goto fail;
    }

    if (!(aux_stack_bottom_addr =
              LLVMBuildBitCast(comp_ctx->builder, aux_stack_bottom_addr,
                               INT32_PTR_TYPE, "aux_stack_bottom_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        goto fail;
    }
    if (!(func_ctx->aux_stack_bottom =
              LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, aux_stack_bottom_addr,
                             "aux_stack_bottom"))) {
        aot_set_last_error("llvm build load failed");
        goto fail;
    }

    if (!(native_symbol_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &native_symbol_offset, 1, "native_symbol_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        goto fail;
    }

    if (!(func_ctx->native_symbol =
              LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                             native_symbol_addr, "native_symbol_tmp"))) {
        aot_set_last_error("llvm build bit cast failed");
        goto fail;
    }

    if (!(func_ctx->native_symbol =
              LLVMBuildBitCast(comp_ctx->builder, func_ctx->native_symbol,
                               comp_ctx->exec_env_type, "native_symbol"))) {
        aot_set_last_error("llvm build bit cast failed");
        goto fail;
    }

    for (i = 0; i < aot_func_type->param_count; i++, j++) {
        snprintf(local_name, sizeof(local_name), "l%d", i);
        func_ctx->locals[i] =
            LLVMBuildAlloca(comp_ctx->builder,
                            TO_LLVM_TYPE(aot_func_type->types[i]), local_name);
        if (!func_ctx->locals[i]) {
            aot_set_last_error("llvm build alloca failed.");
            goto fail;
        }
        if (!LLVMBuildStore(comp_ctx->builder, LLVMGetParam(func_ctx->func, j),
                            func_ctx->locals[i])) {
            aot_set_last_error("llvm build store failed.");
            goto fail;
        }
    }

    for (i = 0; i < func->local_count; i++) {
        LLVMTypeRef local_type;
        LLVMValueRef local_value = NULL;
        snprintf(local_name, sizeof(local_name), "l%d",
                 aot_func_type->param_count + i);
        local_type = TO_LLVM_TYPE(func->local_types[i]);
        func_ctx->locals[aot_func_type->param_count + i] =
            LLVMBuildAlloca(comp_ctx->builder, local_type, local_name);
        if (!func_ctx->locals[aot_func_type->param_count + i]) {
            aot_set_last_error("llvm build alloca failed.");
            goto fail;
        }
        switch (func->local_types[i]) {
            case VALUE_TYPE_I32:
                local_value = I32_ZERO;
                break;
            case VALUE_TYPE_I64:
                local_value = I64_ZERO;
                break;
            case VALUE_TYPE_F32:
                local_value = F32_ZERO;
                break;
            case VALUE_TYPE_F64:
                local_value = F64_ZERO;
                break;
            case VALUE_TYPE_V128:
                local_value = V128_i64x2_ZERO;
                break;
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
                local_value = REF_NULL;
                break;
            default:
                bh_assert(0);
                break;
        }
        if (!LLVMBuildStore(comp_ctx->builder, local_value,
                            func_ctx->locals[aot_func_type->param_count + i])) {
            aot_set_last_error("llvm build store failed.");
            goto fail;
        }
    }

    if (aot_func_type->param_count + func->local_count > 0) {
        func_ctx->last_alloca =
            func_ctx
                ->locals[aot_func_type->param_count + func->local_count - 1];
        if (!(func_ctx->last_alloca =
                  LLVMBuildBitCast(comp_ctx->builder, func_ctx->last_alloca,
                                   INT8_PTR_TYPE, "stack_ptr"))) {
            aot_set_last_error("llvm build bit cast failed.");
            goto fail;
        }
    }
    else {
        if (!(func_ctx->last_alloca =
                  LLVMBuildAlloca(comp_ctx->builder, INT8_TYPE, "stack_ptr"))) {
            aot_set_last_error("llvm build alloca failed.");
            goto fail;
        }
    }

    if (!(int8_ptr_type = LLVMPointerType(INT8_PTR_TYPE, 0))) {
        aot_set_last_error("llvm add pointer type failed.");
        goto fail;
    }

    /* Create base addr, end addr, data size of mem, heap */
    if (!create_memory_info(comp_ctx, func_ctx, int8_ptr_type, func_index))
        goto fail;

    /* Load current exception */
    if (!create_cur_exception(comp_ctx, func_ctx))
        goto fail;

    /* Load function type indexes */
    if (!create_func_type_indexes(comp_ctx, func_ctx))
        goto fail;

    /* Load function pointers */
    if (!create_func_ptrs(comp_ctx, func_ctx))
        goto fail;

    return func_ctx;

fail:
    if (func_ctx->mem_info)
        wasm_runtime_free(func_ctx->mem_info);
    aot_block_stack_destroy(&func_ctx->block_stack);
    wasm_runtime_free(func_ctx);
    return NULL;
}

static void
aot_destroy_func_contexts(AOTFuncContext **func_ctxes, uint32 count)
{
    uint32 i;

    for (i = 0; i < count; i++)
        if (func_ctxes[i]) {
            if (func_ctxes[i]->mem_info)
                wasm_runtime_free(func_ctxes[i]->mem_info);
            aot_block_stack_destroy(&func_ctxes[i]->block_stack);
            aot_checked_addr_list_destroy(func_ctxes[i]);
            wasm_runtime_free(func_ctxes[i]);
        }
    wasm_runtime_free(func_ctxes);
}

/**
 * Create function compiler contexts
 */
static AOTFuncContext **
aot_create_func_contexts(AOTCompData *comp_data, AOTCompContext *comp_ctx)
{
    AOTFuncContext **func_ctxes;
    uint64 size;
    uint32 i;

    /* Allocate memory */
    size = sizeof(AOTFuncContext *) * (uint64)comp_data->func_count;
    if (size >= UINT32_MAX
        || !(func_ctxes = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    memset(func_ctxes, 0, size);

    /* Create each function context */
    for (i = 0; i < comp_data->func_count; i++) {
        AOTFunc *func = comp_data->funcs[i];
        if (!(func_ctxes[i] =
                  aot_create_func_context(comp_data, comp_ctx, func, i))) {
            aot_destroy_func_contexts(func_ctxes, comp_data->func_count);
            return NULL;
        }
    }

    return func_ctxes;
}

static bool
aot_set_llvm_basic_types(AOTLLVMTypes *basic_types, LLVMContextRef context)
{
    basic_types->int1_type = LLVMInt1TypeInContext(context);
    basic_types->int8_type = LLVMInt8TypeInContext(context);
    basic_types->int16_type = LLVMInt16TypeInContext(context);
    basic_types->int32_type = LLVMInt32TypeInContext(context);
    basic_types->int64_type = LLVMInt64TypeInContext(context);
    basic_types->float32_type = LLVMFloatTypeInContext(context);
    basic_types->float64_type = LLVMDoubleTypeInContext(context);
    basic_types->void_type = LLVMVoidTypeInContext(context);

    basic_types->meta_data_type = LLVMMetadataTypeInContext(context);

    basic_types->int8_ptr_type = LLVMPointerType(basic_types->int8_type, 0);

    if (basic_types->int8_ptr_type) {
        basic_types->int8_pptr_type =
            LLVMPointerType(basic_types->int8_ptr_type, 0);
    }

    basic_types->int16_ptr_type = LLVMPointerType(basic_types->int16_type, 0);
    basic_types->int32_ptr_type = LLVMPointerType(basic_types->int32_type, 0);
    basic_types->int64_ptr_type = LLVMPointerType(basic_types->int64_type, 0);
    basic_types->float32_ptr_type =
        LLVMPointerType(basic_types->float32_type, 0);
    basic_types->float64_ptr_type =
        LLVMPointerType(basic_types->float64_type, 0);

    basic_types->i8x16_vec_type = LLVMVectorType(basic_types->int8_type, 16);
    basic_types->i16x8_vec_type = LLVMVectorType(basic_types->int16_type, 8);
    basic_types->i32x4_vec_type = LLVMVectorType(basic_types->int32_type, 4);
    basic_types->i64x2_vec_type = LLVMVectorType(basic_types->int64_type, 2);
    basic_types->f32x4_vec_type = LLVMVectorType(basic_types->float32_type, 4);
    basic_types->f64x2_vec_type = LLVMVectorType(basic_types->float64_type, 2);

    basic_types->v128_type = basic_types->i64x2_vec_type;
    basic_types->v128_ptr_type = LLVMPointerType(basic_types->v128_type, 0);

    basic_types->i1x2_vec_type = LLVMVectorType(basic_types->int1_type, 2);

    basic_types->funcref_type = LLVMInt32TypeInContext(context);
    basic_types->externref_type = LLVMInt32TypeInContext(context);

    return (basic_types->int8_ptr_type && basic_types->int8_pptr_type
            && basic_types->int16_ptr_type && basic_types->int32_ptr_type
            && basic_types->int64_ptr_type && basic_types->float32_ptr_type
            && basic_types->float64_ptr_type && basic_types->i8x16_vec_type
            && basic_types->i16x8_vec_type && basic_types->i32x4_vec_type
            && basic_types->i64x2_vec_type && basic_types->f32x4_vec_type
            && basic_types->f64x2_vec_type && basic_types->i1x2_vec_type
            && basic_types->meta_data_type && basic_types->funcref_type
            && basic_types->externref_type)
               ? true
               : false;
}

static bool
aot_create_llvm_consts(AOTLLVMConsts *consts, AOTCompContext *comp_ctx)
{
#define CREATE_I1_CONST(name, value)                                       \
    if (!(consts->i1_##name =                                              \
              LLVMConstInt(comp_ctx->basic_types.int1_type, value, true))) \
        return false;

    CREATE_I1_CONST(zero, 0)
    CREATE_I1_CONST(one, 1)
#undef CREATE_I1_CONST

    if (!(consts->i8_zero = I8_CONST(0)))
        return false;

    if (!(consts->f32_zero = F32_CONST(0)))
        return false;

    if (!(consts->f64_zero = F64_CONST(0)))
        return false;

#define CREATE_I32_CONST(name, value)                                \
    if (!(consts->i32_##name = LLVMConstInt(I32_TYPE, value, true))) \
        return false;

    CREATE_I32_CONST(min, (uint32)INT32_MIN)
    CREATE_I32_CONST(neg_one, (uint32)-1)
    CREATE_I32_CONST(zero, 0)
    CREATE_I32_CONST(one, 1)
    CREATE_I32_CONST(two, 2)
    CREATE_I32_CONST(three, 3)
    CREATE_I32_CONST(four, 4)
    CREATE_I32_CONST(five, 5)
    CREATE_I32_CONST(six, 6)
    CREATE_I32_CONST(seven, 7)
    CREATE_I32_CONST(eight, 8)
    CREATE_I32_CONST(nine, 9)
    CREATE_I32_CONST(ten, 10)
    CREATE_I32_CONST(eleven, 11)
    CREATE_I32_CONST(twelve, 12)
    CREATE_I32_CONST(thirteen, 13)
    CREATE_I32_CONST(fourteen, 14)
    CREATE_I32_CONST(fifteen, 15)
    CREATE_I32_CONST(31, 31)
    CREATE_I32_CONST(32, 32)
#undef CREATE_I32_CONST

#define CREATE_I64_CONST(name, value)                                \
    if (!(consts->i64_##name = LLVMConstInt(I64_TYPE, value, true))) \
        return false;

    CREATE_I64_CONST(min, (uint64)INT64_MIN)
    CREATE_I64_CONST(neg_one, (uint64)-1)
    CREATE_I64_CONST(zero, 0)
    CREATE_I64_CONST(63, 63)
    CREATE_I64_CONST(64, 64)
#undef CREATE_I64_CONST

#define CREATE_V128_CONST(name, type)                     \
    if (!(consts->name##_vec_zero = LLVMConstNull(type))) \
        return false;                                     \
    if (!(consts->name##_undef = LLVMGetUndef(type)))     \
        return false;

    CREATE_V128_CONST(i8x16, V128_i8x16_TYPE)
    CREATE_V128_CONST(i16x8, V128_i16x8_TYPE)
    CREATE_V128_CONST(i32x4, V128_i32x4_TYPE)
    CREATE_V128_CONST(i64x2, V128_i64x2_TYPE)
    CREATE_V128_CONST(f32x4, V128_f32x4_TYPE)
    CREATE_V128_CONST(f64x2, V128_f64x2_TYPE)
#undef CREATE_V128_CONST

#define CREATE_VEC_ZERO_MASK(slot)                                       \
    {                                                                    \
        LLVMTypeRef type = LLVMVectorType(I32_TYPE, slot);               \
        if (!type || !(consts->i32x##slot##_zero = LLVMConstNull(type))) \
            return false;                                                \
    }

    CREATE_VEC_ZERO_MASK(16)
    CREATE_VEC_ZERO_MASK(8)
    CREATE_VEC_ZERO_MASK(4)
    CREATE_VEC_ZERO_MASK(2)
#undef CREATE_VEC_ZERO_MASK

    return true;
}

typedef struct ArchItem {
    char *arch;
    bool support_eb;
} ArchItem;

/* clang-format off */
static ArchItem valid_archs[] = {
    { "x86_64", false },
    { "i386", false },
    { "xtensa", false },
    { "mips", true },
    { "mipsel", false },
    { "aarch64v8", false },
    { "aarch64v8.1", false },
    { "aarch64v8.2", false },
    { "aarch64v8.3", false },
    { "aarch64v8.4", false },
    { "aarch64v8.5", false },
    { "aarch64_bev8", false }, /* big endian */
    { "aarch64_bev8.1", false },
    { "aarch64_bev8.2", false },
    { "aarch64_bev8.3", false },
    { "aarch64_bev8.4", false },
    { "aarch64_bev8.5", false },
    { "armv4", true },
    { "armv4t", true },
    { "armv5t", true },
    { "armv5te", true },
    { "armv5tej", true },
    { "armv6", true },
    { "armv6kz", true },
    { "armv6t2", true },
    { "armv6k", true },
    { "armv7", true },
    { "armv6m", true },
    { "armv6sm", true },
    { "armv7em", true },
    { "armv8a", true },
    { "armv8r", true },
    { "armv8m.base", true },
    { "armv8m.main", true },
    { "armv8.1m.main", true },
    { "thumbv4", true },
    { "thumbv4t", true },
    { "thumbv5t", true },
    { "thumbv5te", true },
    { "thumbv5tej", true },
    { "thumbv6", true },
    { "thumbv6kz", true },
    { "thumbv6t2", true },
    { "thumbv6k", true },
    { "thumbv7", true },
    { "thumbv6m", true },
    { "thumbv6sm", true },
    { "thumbv7em", true },
    { "thumbv8a", true },
    { "thumbv8r", true },
    { "thumbv8m.base", true },
    { "thumbv8m.main", true },
    { "thumbv8.1m.main", true },
    { "riscv32", true },
    { "riscv64", true },
    { "arc", true }
};

static const char *valid_abis[] = {
    "gnu",
    "eabi",
    "gnueabihf",
    "msvc",
    "ilp32",
    "ilp32f",
    "ilp32d",
    "lp64",
    "lp64f",
    "lp64d"
};
/* clang-format on */

static void
print_supported_targets()
{
    uint32 i;
    os_printf("Supported targets:\n");
    for (i = 0; i < sizeof(valid_archs) / sizeof(ArchItem); i++) {
        os_printf("%s ", valid_archs[i].arch);
        if (valid_archs[i].support_eb)
            os_printf("%seb ", valid_archs[i].arch);
    }
    os_printf("\n");
}

static void
print_supported_abis()
{
    uint32 i;
    os_printf("Supported ABI: ");
    for (i = 0; i < sizeof(valid_abis) / sizeof(const char *); i++)
        os_printf("%s ", valid_abis[i]);
    os_printf("\n");
}

static bool
check_target_arch(const char *target_arch)
{
    uint32 i;
    char *arch;
    bool support_eb;

    for (i = 0; i < sizeof(valid_archs) / sizeof(ArchItem); i++) {
        arch = valid_archs[i].arch;
        support_eb = valid_archs[i].support_eb;

        if (!strncmp(target_arch, arch, strlen(arch))
            && ((support_eb
                 && (!strcmp(target_arch + strlen(arch), "eb")
                     || !strcmp(target_arch + strlen(arch), "")))
                || (!support_eb && !strcmp(target_arch + strlen(arch), "")))) {
            return true;
        }
    }
    return false;
}

static bool
check_target_abi(const char *target_abi)
{
    uint32 i;
    for (i = 0; i < sizeof(valid_abis) / sizeof(char *); i++) {
        if (!strcmp(target_abi, valid_abis[i]))
            return true;
    }
    return false;
}

static void
get_target_arch_from_triple(const char *triple, char *arch_buf, uint32 buf_size)
{
    uint32 i = 0;
    while (*triple != '-' && *triple != '\0' && i < buf_size - 1)
        arch_buf[i++] = *triple++;
    /* Make sure buffer is long enough */
    bh_assert(*triple == '-' || *triple == '\0');
}

LLVMBool
WAMRCreateMCJITCompilerForModule(LLVMExecutionEngineRef *OutJIT,
                                 LLVMModuleRef M,
                                 struct LLVMMCJITCompilerOptions *Options,
                                 size_t SizeOfOptions, char **OutError);

void
LLVMAddPromoteMemoryToRegisterPass(LLVMPassManagerRef PM);

#if WASM_ENABLE_LAZY_JIT != 0
void
aot_handle_llvm_errmsg(const char *string, LLVMErrorRef err)
{
    char *err_msg = LLVMGetErrorMessage(err);
    aot_set_last_error_v("%s: %s", string, err_msg);
    LLVMDisposeErrorMessage(err_msg);
}

static bool
orc_lazyjit_create(AOTCompContext *comp_ctx, uint32 func_count)
{
    uint32 i;
    char *err_msg = NULL;
    char *cpu = NULL;
    char *features = NULL;
    char *llvm_triple = NULL;
    char func_name[32] = { 0 };
    LLVMErrorRef err;
    LLVMTargetRef llvm_targetref = NULL;
    LLVMTargetMachineRef target_machine_for_orcjit = NULL;
    LLVMOrcLLJITRef orc_lazyjit = NULL;
    LLVMOrcJITTargetMachineBuilderRef target_machine_builder = NULL;
    LLVMOrcLLJITBuilderRef orc_lazyjit_builder = NULL;
    LLVMOrcMaterializationUnitRef orc_material_unit = NULL;
    LLVMOrcExecutionSessionRef orc_execution_session = NULL;
    LLVMOrcLazyCallThroughManagerRef orc_call_through_mgr = NULL;
    LLVMOrcIndirectStubsManagerRef orc_indirect_stub_mgr = NULL;
    LLVMOrcCSymbolAliasMapPair *orc_symbol_map_pairs = NULL;

    llvm_triple = LLVMGetDefaultTargetTriple();
    if (llvm_triple == NULL) {
        aot_set_last_error("failed to get default target triple.");
        goto fail;
    }

    if (LLVMGetTargetFromTriple(llvm_triple, &llvm_targetref, &err_msg) != 0) {
        aot_set_last_error_v("failed to get llvm target from triple %s.",
                             err_msg);
        LLVMDisposeMessage(err_msg);
        goto fail;
    }

    if (!LLVMTargetHasJIT(llvm_targetref)) {
        aot_set_last_error("unspported JIT on this platform.");
        goto fail;
    }

    cpu = LLVMGetHostCPUName();
    if (cpu == NULL) {
        aot_set_last_error("failed to get host cpu information.");
        goto fail;
    }

    features = LLVMGetHostCPUFeatures();
    if (features == NULL) {
        aot_set_last_error("failed to get host cpu features.");
        goto fail;
    }

    LOG_VERBOSE("LLVM ORCJIT detected CPU \"%s\", with features \"%s\"\n", cpu,
                features);

    comp_ctx->target_machine = LLVMCreateTargetMachine(
        llvm_targetref, llvm_triple, cpu, features, LLVMCodeGenLevelDefault,
        LLVMRelocDefault, LLVMCodeModelJITDefault);
    if (!comp_ctx->target_machine) {
        aot_set_last_error("failed to create target machine.");
        goto fail;
    }

    target_machine_for_orcjit = LLVMCreateTargetMachine(
        llvm_targetref, llvm_triple, cpu, features, LLVMCodeGenLevelDefault,
        LLVMRelocDefault, LLVMCodeModelJITDefault);
    if (!target_machine_for_orcjit) {
        aot_set_last_error("failed to create target machine.");
        goto fail;
    }

    target_machine_builder =
        LLVMOrcJITTargetMachineBuilderCreateFromTargetMachine(
            target_machine_for_orcjit);
    if (!target_machine_builder) {
        aot_set_last_error("failed to create target machine builder.");
        goto fail;
    }
    /* The target_machine_for_orcjit has been disposed before
       LLVMOrcJITTargetMachineBuilderCreateFromTargetMachine() returns */
    target_machine_for_orcjit = NULL;

    orc_lazyjit_builder = LLVMOrcCreateLLJITBuilder();
    if (!orc_lazyjit_builder) {
        aot_set_last_error("failed to create lazy jit builder.");
        goto fail;
    }
    LLVMOrcLLJITBuilderSetNumCompileThreads(orc_lazyjit_builder,
                                            WASM_LAZY_JIT_COMPILE_THREAD_NUM);
    LLVMOrcLLJITBuilderSetJITTargetMachineBuilder(orc_lazyjit_builder,
                                                  target_machine_builder);
    /* Should not dispose of the JITTargetMachineBuilder after calling
       LLVMOrcLLJITBuilderSetJITTargetMachineBuilder() */
    target_machine_builder = NULL;

    err = LLVMOrcCreateLLJIT(&orc_lazyjit, orc_lazyjit_builder);
    if (err) {
        aot_handle_llvm_errmsg("failed to create llvm lazy orcjit instance",
                               err);
        goto fail;
    }
    /* The orc_lazyjit_builder is managed by orc_lazyjit after calling
       LLVMOrcCreateLLJIT(), here we should not dispose it again */
    orc_lazyjit_builder = NULL;

    if (func_count > 0) {
        orc_execution_session = LLVMOrcLLJITGetExecutionSession(orc_lazyjit);
        if (!orc_execution_session) {
            aot_set_last_error("failed to get orc execution session");
            goto fail;
        }

        err = LLVMOrcCreateLocalLazyCallThroughManager(
            llvm_triple, orc_execution_session, 0, &orc_call_through_mgr);
        if (err) {
            aot_handle_llvm_errmsg("failed to create orc call through manager",
                                   err);
            goto fail;
        }

        orc_indirect_stub_mgr =
            LLVMOrcCreateLocalIndirectStubsManager(llvm_triple);
        if (!orc_indirect_stub_mgr) {
            aot_set_last_error("failed to create orc indirect stub manager");
            goto fail;
        }

        if (!(orc_symbol_map_pairs = wasm_runtime_malloc(
                  sizeof(LLVMOrcCSymbolAliasMapPair) * func_count))) {
            aot_set_last_error("failed to allocate memory");
            goto fail;
        }
        memset(orc_symbol_map_pairs, 0,
               sizeof(LLVMOrcCSymbolAliasMapPair) * func_count);

        for (i = 0; i < func_count; i++) {
            snprintf(func_name, sizeof(func_name), "orcjit_%s%d",
                     AOT_FUNC_PREFIX, i);
            orc_symbol_map_pairs[i].Name =
                LLVMOrcExecutionSessionIntern(orc_execution_session, func_name);
            snprintf(func_name, sizeof(func_name), "%s%d", AOT_FUNC_PREFIX, i);
            orc_symbol_map_pairs[i].Entry.Name =
                LLVMOrcExecutionSessionIntern(orc_execution_session, func_name);
            orc_symbol_map_pairs[i].Entry.Flags.GenericFlags =
                LLVMJITSymbolGenericFlagsExported
                | LLVMJITSymbolGenericFlagsCallable;
            orc_symbol_map_pairs[i].Entry.Flags.TargetFlags =
                LLVMJITSymbolGenericFlagsExported
                | LLVMJITSymbolGenericFlagsCallable;

            if (!orc_symbol_map_pairs[i].Name
                || !orc_symbol_map_pairs[i].Entry.Name) {
                aot_set_last_error("failed to allocate memory");
                goto fail;
            }
        }

        orc_material_unit =
            LLVMOrcLazyReexports(orc_call_through_mgr, orc_indirect_stub_mgr,
                                 LLVMOrcLLJITGetMainJITDylib(orc_lazyjit),
                                 orc_symbol_map_pairs, func_count);
        if (!orc_material_unit) {
            aot_set_last_error("failed to orc re-exports");
            goto fail;
        }
    }

    comp_ctx->orc_lazyjit = orc_lazyjit;
    comp_ctx->orc_material_unit = orc_material_unit;
    comp_ctx->orc_symbol_map_pairs = orc_symbol_map_pairs;
    comp_ctx->orc_call_through_mgr = orc_call_through_mgr;
    comp_ctx->orc_indirect_stub_mgr = orc_indirect_stub_mgr;

    LLVMDisposeMessage(llvm_triple);
    LLVMDisposeMessage(cpu);
    LLVMDisposeMessage(features);
    return true;

fail:
    if (orc_symbol_map_pairs)
        wasm_runtime_free(orc_symbol_map_pairs);
    if (orc_call_through_mgr)
        LLVMOrcDisposeLazyCallThroughManager(orc_call_through_mgr);
    if (orc_indirect_stub_mgr)
        LLVMOrcDisposeIndirectStubsManager(orc_indirect_stub_mgr);
    if (orc_lazyjit)
        LLVMOrcDisposeLLJIT(orc_lazyjit);
    if (target_machine_builder)
        LLVMOrcDisposeJITTargetMachineBuilder(target_machine_builder);
    if (orc_lazyjit_builder)
        LLVMOrcDisposeLLJITBuilder(orc_lazyjit_builder);
    if (target_machine_for_orcjit)
        LLVMDisposeTargetMachine(target_machine_for_orcjit);
    if (features)
        LLVMDisposeMessage(features);
    if (cpu)
        LLVMDisposeMessage(cpu);
    if (llvm_triple)
        LLVMDisposeMessage(llvm_triple);
    return false;
}
#endif /* WASM_ENABLE_LAZY_JIT != 0 */

AOTCompContext *
aot_create_comp_context(AOTCompData *comp_data, aot_comp_option_t option)
{
    AOTCompContext *comp_ctx, *ret = NULL;
#if WASM_ENABLE_LAZY_JIT == 0
    struct LLVMMCJITCompilerOptions jit_options;
#endif
    LLVMTargetRef target;
    char *triple = NULL, *triple_norm, *arch, *abi;
    char *cpu = NULL, *features, buf[128];
    char *triple_norm_new = NULL, *cpu_new = NULL;
    char *err = NULL, *fp_round = "round.tonearest",
         *fp_exce = "fpexcept.strict";
    char triple_buf[32] = { 0 }, features_buf[128] = { 0 };
    uint32 opt_level, size_level, i;
    LLVMCodeModel code_model;
    LLVMTargetDataRef target_data_ref;

    /* Initialize LLVM environment */
#if WASM_ENABLE_LAZY_JIT != 0
    LLVMInitializeCore(LLVMGetGlobalPassRegistry());
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    LLVMInitializeNativeAsmParser();
#else
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargets();
    LLVMInitializeAllTargetMCs();
    LLVMInitializeAllAsmPrinters();
    LLVMLinkInMCJIT();
#endif

    /* Allocate memory */
    if (!(comp_ctx = wasm_runtime_malloc(sizeof(AOTCompContext)))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    memset(comp_ctx, 0, sizeof(AOTCompContext));
    comp_ctx->comp_data = comp_data;

    /* Create LLVM context, module and builder */
#if WASM_ENABLE_LAZY_JIT != 0
    comp_ctx->orc_thread_safe_context = LLVMOrcCreateNewThreadSafeContext();
    if (!comp_ctx->orc_thread_safe_context) {
        aot_set_last_error("create LLVM ThreadSafeContext failed.");
        goto fail;
    }

    /* Get a reference to the underlying LLVMContext, note:
         different from non LAZY JIT mode, no need to dispose this context,
         if will be disposed when the thread safe context is disposed */
    if (!(comp_ctx->context = LLVMOrcThreadSafeContextGetContext(
              comp_ctx->orc_thread_safe_context))) {
        aot_set_last_error("get context from LLVM ThreadSafeContext failed.");
        goto fail;
    }
#else
    if (!(comp_ctx->context = LLVMContextCreate())) {
        aot_set_last_error("create LLVM context failed.");
        goto fail;
    }
#endif

    if (!(comp_ctx->builder = LLVMCreateBuilderInContext(comp_ctx->context))) {
        aot_set_last_error("create LLVM builder failed.");
        goto fail;
    }

#if WASM_ENABLE_LAZY_JIT == 0
    if (!(comp_ctx->module = LLVMModuleCreateWithNameInContext(
              "WASM Module", comp_ctx->context))) {
        aot_set_last_error("create LLVM module failed.");
        goto fail;
    }
#else
    if (comp_data->func_count > 0) {
        if (!(comp_ctx->modules = wasm_runtime_malloc(
                  sizeof(LLVMModuleRef) * comp_data->func_count))) {
            aot_set_last_error("allocate memory failed.");
            goto fail;
        }
        memset(comp_ctx->modules, 0,
               sizeof(LLVMModuleRef) * comp_data->func_count);
        for (i = 0; i < comp_data->func_count; i++) {
            char module_name[32];
            snprintf(module_name, sizeof(module_name), "WASM Module %d", i);
            /* Create individual modules for each aot function, note:
               different from non LAZY JIT mode, no need to dispose them,
               they will be disposed when the thread safe context is disposed */
            if (!(comp_ctx->modules[i] = LLVMModuleCreateWithNameInContext(
                      module_name, comp_ctx->context))) {
                aot_set_last_error("create LLVM module failed.");
                goto fail;
            }
        }
    }
#endif

    if (BH_LIST_ERROR == bh_list_init(&comp_ctx->native_symbols)) {
        goto fail;
    }

#if WASM_ENABLE_DEBUG_AOT != 0 && WASM_ENABLE_LAZY_JIT == 0
    if (!(comp_ctx->debug_builder = LLVMCreateDIBuilder(comp_ctx->module))) {
        aot_set_last_error("create LLVM Debug Infor builder failed.");
        goto fail;
    }

    LLVMAddModuleFlag(
        comp_ctx->module, LLVMModuleFlagBehaviorWarning, "Debug Info Version",
        strlen("Debug Info Version"),
        LLVMValueAsMetadata(LLVMConstInt(LLVMInt32Type(), 3, false)));

    comp_ctx->debug_file = dwarf_gen_file_info(comp_ctx);
    if (!comp_ctx->debug_file) {
        aot_set_last_error("dwarf generate file info failed");
        goto fail;
    }
    comp_ctx->debug_comp_unit = dwarf_gen_comp_unit_info(comp_ctx);
    if (!comp_ctx->debug_comp_unit) {
        aot_set_last_error("dwarf generate compile unit info failed");
        goto fail;
    }
#endif

    if (option->enable_bulk_memory)
        comp_ctx->enable_bulk_memory = true;

    if (option->enable_thread_mgr)
        comp_ctx->enable_thread_mgr = true;

    if (option->enable_tail_call)
        comp_ctx->enable_tail_call = true;

    if (option->enable_ref_types)
        comp_ctx->enable_ref_types = true;

    if (option->enable_aux_stack_frame)
        comp_ctx->enable_aux_stack_frame = true;

    if (option->enable_aux_stack_check)
        comp_ctx->enable_aux_stack_check = true;

    if (option->is_indirect_mode)
        comp_ctx->is_indirect_mode = true;

    if (option->disable_llvm_intrinsics)
        comp_ctx->disable_llvm_intrinsics = true;

    if (option->disable_llvm_lto)
        comp_ctx->disable_llvm_lto = true;

    comp_ctx->opt_level = option->opt_level;
    comp_ctx->size_level = option->size_level;

    comp_ctx->custom_sections_wp = option->custom_sections;
    comp_ctx->custom_sections_count = option->custom_sections_count;

    if (option->is_jit_mode) {
        char *triple_jit = NULL;

        comp_ctx->is_jit_mode = true;

#if WASM_ENABLE_LAZY_JIT != 0
        /* Create LLJIT Instance */
        if (!orc_lazyjit_create(comp_ctx, comp_data->func_count)) {
            goto fail;
        }

#else
        /* Create LLVM execution engine */
        LLVMInitializeMCJITCompilerOptions(&jit_options, sizeof(jit_options));
        jit_options.OptLevel = LLVMCodeGenLevelAggressive;
        jit_options.EnableFastISel = true;
        /*jit_options.CodeModel = LLVMCodeModelSmall;*/
        if (WAMRCreateMCJITCompilerForModule(&comp_ctx->exec_engine,
                                             comp_ctx->module, &jit_options,
                                             sizeof(jit_options), &err)
            != 0) {
            if (err) {
                LLVMDisposeMessage(err);
                err = NULL;
            }
            aot_set_last_error("create LLVM JIT compiler failed.");
            goto fail;
        }
        comp_ctx->target_machine =
            LLVMGetExecutionEngineTargetMachine(comp_ctx->exec_engine);
#endif

#ifndef OS_ENABLE_HW_BOUND_CHECK
        comp_ctx->enable_bound_check = true;
#else
        comp_ctx->enable_bound_check = false;
#endif

#if WASM_ENABLE_LAZY_JIT != 0
        if (!(triple_jit =
                  (char *)LLVMOrcLLJITGetTripleString(comp_ctx->orc_lazyjit))) {
            aot_set_last_error("can not get triple from the target machine");
            goto fail;
        }

        /* Save target arch */
        get_target_arch_from_triple(triple_jit, comp_ctx->target_arch,
                                    sizeof(comp_ctx->target_arch));
#else
        if (!(triple_jit =
                  LLVMGetTargetMachineTriple(comp_ctx->target_machine))) {
            aot_set_last_error("can not get triple from the target machine");
            goto fail;
        }

        /* Save target arch */
        get_target_arch_from_triple(triple_jit, comp_ctx->target_arch,
                                    sizeof(comp_ctx->target_arch));
        LLVMDisposeMessage(triple_jit);
#endif
    }
    else {
        /* Create LLVM target machine */
        arch = option->target_arch;
        abi = option->target_abi;
        cpu = option->target_cpu;
        features = option->cpu_features;
        opt_level = option->opt_level;
        size_level = option->size_level;

        /* verify external llc compiler */
        comp_ctx->external_llc_compiler = getenv("WAMRC_LLC_COMPILER");
        if (comp_ctx->external_llc_compiler) {
#if defined(_WIN32) || defined(_WIN32_)
            comp_ctx->external_llc_compiler = NULL;
            LOG_WARNING("External LLC compiler not supported on Windows.");
#else
            if (access(comp_ctx->external_llc_compiler, X_OK) != 0) {
                LOG_WARNING("WAMRC_LLC_COMPILER [%s] not found, fallback to "
                            "default pipeline",
                            comp_ctx->external_llc_compiler);
                comp_ctx->external_llc_compiler = NULL;
            }
            else {
                comp_ctx->llc_compiler_flags = getenv("WAMRC_LLC_FLAGS");
                LOG_VERBOSE("Using external LLC compiler [%s]",
                            comp_ctx->external_llc_compiler);
            }
#endif
        }

        /* verify external asm compiler */
        if (!comp_ctx->external_llc_compiler) {
            comp_ctx->external_asm_compiler = getenv("WAMRC_ASM_COMPILER");
            if (comp_ctx->external_asm_compiler) {
#if defined(_WIN32) || defined(_WIN32_)
                comp_ctx->external_asm_compiler = NULL;
                LOG_WARNING("External ASM compiler not supported on Windows.");
#else
                if (access(comp_ctx->external_asm_compiler, X_OK) != 0) {
                    LOG_WARNING(
                        "WAMRC_ASM_COMPILER [%s] not found, fallback to "
                        "default pipeline",
                        comp_ctx->external_asm_compiler);
                    comp_ctx->external_asm_compiler = NULL;
                }
                else {
                    comp_ctx->asm_compiler_flags = getenv("WAMRC_ASM_FLAGS");
                    LOG_VERBOSE("Using external ASM compiler [%s]",
                                comp_ctx->external_asm_compiler);
                }
#endif
            }
        }

        if (arch) {
            /* Add default sub-arch if not specified */
            if (!strcmp(arch, "arm"))
                arch = "armv4";
            else if (!strcmp(arch, "armeb"))
                arch = "armv4eb";
            else if (!strcmp(arch, "thumb"))
                arch = "thumbv4t";
            else if (!strcmp(arch, "thumbeb"))
                arch = "thumbv4teb";
            else if (!strcmp(arch, "aarch64"))
                arch = "aarch64v8";
            else if (!strcmp(arch, "aarch64_be"))
                arch = "aarch64_bev8";
        }

        /* Check target arch */
        if (arch && !check_target_arch(arch)) {
            if (!strcmp(arch, "help"))
                print_supported_targets();
            else
                aot_set_last_error(
                    "Invalid target. "
                    "Use --target=help to list all supported targets");
            goto fail;
        }

        /* Check target ABI */
        if (abi && !check_target_abi(abi)) {
            if (!strcmp(abi, "help"))
                print_supported_abis();
            else
                aot_set_last_error(
                    "Invalid target ABI. "
                    "Use --target-abi=help to list all supported ABI");
            goto fail;
        }

        /* Set default abi for riscv target */
        if (arch && !strncmp(arch, "riscv", 5) && !abi) {
            if (!strcmp(arch, "riscv64"))
                abi = "lp64d";
            else
                abi = "ilp32d";
        }

#if defined(__APPLE__) || defined(__MACH__)
        if (!abi) {
            /* On MacOS platform, set abi to "gnu" to avoid generating
               object file of Mach-O binary format which is unsupported */
            abi = "gnu";
            if (!arch && !cpu && !features) {
                /* Get CPU name of the host machine to avoid checking
                   SIMD capability failed */
                if (!(cpu = cpu_new = LLVMGetHostCPUName())) {
                    aot_set_last_error("llvm get host cpu name failed.");
                    goto fail;
                }
            }
        }
#endif

        if (abi) {
            /* Construct target triple: <arch>-<vendor>-<sys>-<abi> */
            const char *vendor_sys;
            char *arch1 = arch, default_arch[32] = { 0 };

            if (!arch1) {
                char *default_triple = LLVMGetDefaultTargetTriple();

                if (!default_triple) {
                    aot_set_last_error(
                        "llvm get default target triple failed.");
                    goto fail;
                }

                vendor_sys = strstr(default_triple, "-");
                bh_assert(vendor_sys);
                bh_memcpy_s(default_arch, sizeof(default_arch), default_triple,
                            (uint32)(vendor_sys - default_triple));
                arch1 = default_arch;

                LLVMDisposeMessage(default_triple);
            }

            /**
             * Set <vendor>-<sys> according to abi to generate the object file
             * with the correct file format which might be different from the
             * default object file format of the host, e.g., generating AOT file
             * for Windows/MacOS under Linux host, or generating AOT file for
             * Linux/MacOS under Windows host.
             */
            if (!strcmp(abi, "msvc")) {
                if (!strcmp(arch1, "i386"))
                    vendor_sys = "-pc-win32-";
                else
                    vendor_sys = "-pc-windows-";
            }
            else {
                vendor_sys = "-pc-linux-";
            }

            bh_assert(strlen(arch1) + strlen(vendor_sys) + strlen(abi)
                      < sizeof(triple_buf));
            bh_memcpy_s(triple_buf, (uint32)sizeof(triple_buf), arch1,
                        (uint32)strlen(arch1));
            bh_memcpy_s(triple_buf + strlen(arch1),
                        (uint32)(sizeof(triple_buf) - strlen(arch1)),
                        vendor_sys, (uint32)strlen(vendor_sys));
            bh_memcpy_s(triple_buf + strlen(arch1) + strlen(vendor_sys),
                        (uint32)(sizeof(triple_buf) - strlen(arch1)
                                 - strlen(vendor_sys)),
                        abi, (uint32)strlen(abi));
            triple = triple_buf;
        }
        else if (arch) {
            /* Construct target triple: <arch>-<vendor>-<sys>-<abi> */
            const char *vendor_sys;
            char *default_triple = LLVMGetDefaultTargetTriple();

            if (!default_triple) {
                aot_set_last_error("llvm get default target triple failed.");
                goto fail;
            }

            if (strstr(default_triple, "windows")) {
                vendor_sys = "-pc-windows-";
                if (!abi)
                    abi = "msvc";
            }
            else if (strstr(default_triple, "win32")) {
                vendor_sys = "-pc-win32-";
                if (!abi)
                    abi = "msvc";
            }
            else {
                vendor_sys = "-pc-linux-";
                if (!abi)
                    abi = "gnu";
            }

            LLVMDisposeMessage(default_triple);

            bh_assert(strlen(arch) + strlen(vendor_sys) + strlen(abi)
                      < sizeof(triple_buf));
            bh_memcpy_s(triple_buf, (uint32)sizeof(triple_buf), arch,
                        (uint32)strlen(arch));
            bh_memcpy_s(triple_buf + strlen(arch),
                        (uint32)(sizeof(triple_buf) - strlen(arch)), vendor_sys,
                        (uint32)strlen(vendor_sys));
            bh_memcpy_s(triple_buf + strlen(arch) + strlen(vendor_sys),
                        (uint32)(sizeof(triple_buf) - strlen(arch)
                                 - strlen(vendor_sys)),
                        abi, (uint32)strlen(abi));
            triple = triple_buf;
        }

        if (!cpu && features) {
            aot_set_last_error("cpu isn't specified for cpu features.");
            goto fail;
        }

        if (!triple && !cpu) {
            /* Get a triple for the host machine */
            if (!(triple_norm = triple_norm_new =
                      LLVMGetDefaultTargetTriple())) {
                aot_set_last_error("llvm get default target triple failed.");
                goto fail;
            }
            /* Get CPU name of the host machine */
            if (!(cpu = cpu_new = LLVMGetHostCPUName())) {
                aot_set_last_error("llvm get host cpu name failed.");
                goto fail;
            }
        }
        else if (triple) {
            /* Normalize a target triple */
            if (!(triple_norm = triple_norm_new =
                      LLVMNormalizeTargetTriple(triple))) {
                snprintf(buf, sizeof(buf),
                         "llvm normlalize target triple (%s) failed.", triple);
                aot_set_last_error(buf);
                goto fail;
            }
            if (!cpu)
                cpu = "";
        }
        else {
            /* triple is NULL, cpu isn't NULL */
            snprintf(buf, sizeof(buf), "target isn't specified for cpu %s.",
                     cpu);
            aot_set_last_error(buf);
            goto fail;
        }

        /* Add module flag and cpu feature for riscv target */
        if (arch && !strncmp(arch, "riscv", 5)) {
            LLVMMetadataRef meta_target_abi;

            if (!(meta_target_abi = LLVMMDStringInContext2(comp_ctx->context,
                                                           abi, strlen(abi)))) {
                aot_set_last_error("create metadata string failed.");
                goto fail;
            }
#if WASM_ENABLE_LAZY_JIT == 0
            LLVMAddModuleFlag(comp_ctx->module, LLVMModuleFlagBehaviorError,
                              "target-abi", strlen("target-abi"),
                              meta_target_abi);
#else
            for (i = 0; i < comp_data->func_count; i++) {
                LLVMAddModuleFlag(comp_ctx->modules[i],
                                  LLVMModuleFlagBehaviorError, "target-abi",
                                  strlen("target-abi"), meta_target_abi);
            }
#endif

            if (!strcmp(abi, "lp64d") || !strcmp(abi, "ilp32d")) {
                if (features) {
                    snprintf(features_buf, sizeof(features_buf), "%s%s",
                             features, ",+d");
                    features = features_buf;
                }
                else
                    features = "+d";
            }
        }

        if (!features)
            features = "";

        /* Get target with triple, note that LLVMGetTargetFromTriple()
           return 0 when success, but not true. */
        if (LLVMGetTargetFromTriple(triple_norm, &target, &err) != 0) {
            if (err) {
                LLVMDisposeMessage(err);
                err = NULL;
            }
            snprintf(buf, sizeof(buf),
                     "llvm get target from triple (%s) failed", triple_norm);
            aot_set_last_error(buf);
            goto fail;
        }

        /* Save target arch */
        get_target_arch_from_triple(triple_norm, comp_ctx->target_arch,
                                    sizeof(comp_ctx->target_arch));

        if (option->bounds_checks == 1 || option->bounds_checks == 0) {
            /* Set by user */
            comp_ctx->enable_bound_check =
                (option->bounds_checks == 1) ? true : false;
        }
        else {
            /* Unset by user, use default value */
            if (strstr(comp_ctx->target_arch, "64")
                && !option->is_sgx_platform) {
                comp_ctx->enable_bound_check = false;
            }
            else {
                comp_ctx->enable_bound_check = true;
            }
        }

        os_printf("Create AoT compiler with:\n");
        os_printf("  target:        %s\n", comp_ctx->target_arch);
        os_printf("  target cpu:    %s\n", cpu);
        os_printf("  cpu features:  %s\n", features);
        os_printf("  opt level:     %d\n", opt_level);
        os_printf("  size level:    %d\n", size_level);
        switch (option->output_format) {
            case AOT_LLVMIR_UNOPT_FILE:
                os_printf("  output format: unoptimized LLVM IR\n");
                break;
            case AOT_LLVMIR_OPT_FILE:
                os_printf("  output format: optimized LLVM IR\n");
                break;
            case AOT_FORMAT_FILE:
                os_printf("  output format: AoT file\n");
                break;
            case AOT_OBJECT_FILE:
                os_printf("  output format: native object file\n");
                break;
        }

        if (!LLVMTargetHasTargetMachine(target)) {
            snprintf(buf, sizeof(buf),
                     "no target machine for this target (%s).", triple_norm);
            aot_set_last_error(buf);
            goto fail;
        }

        /* Report error if target isn't arc and hasn't asm backend.
           For arc target, as it cannot emit to memory buffer of elf file
           currently, we let it emit to assembly file instead, and then call
           arc-gcc to compile
           asm file to elf file, and read elf file to memory buffer. */
        if (strncmp(comp_ctx->target_arch, "arc", 3)
            && !LLVMTargetHasAsmBackend(target)) {
            snprintf(buf, sizeof(buf), "no asm backend for this target (%s).",
                     LLVMGetTargetName(target));
            aot_set_last_error(buf);
            goto fail;
        }

        /* Set code model */
        if (size_level == 0)
            code_model = LLVMCodeModelLarge;
        else if (size_level == 1)
            code_model = LLVMCodeModelMedium;
        else if (size_level == 2)
            code_model = LLVMCodeModelKernel;
        else
            code_model = LLVMCodeModelSmall;

        /* Create the target machine */
        if (!(comp_ctx->target_machine = LLVMCreateTargetMachine(
                  target, triple_norm, cpu, features, opt_level,
                  LLVMRelocStatic, code_model))) {
            aot_set_last_error("create LLVM target machine failed.");
            goto fail;
        }

#if WASM_ENABLE_LAZY_JIT == 0
        LLVMSetTarget(comp_ctx->module, triple_norm);
#endif
    }

    if (option->enable_simd && strcmp(comp_ctx->target_arch, "x86_64") != 0
        && strncmp(comp_ctx->target_arch, "aarch64", 7) != 0) {
        /* Disable simd if it isn't supported by target arch */
        option->enable_simd = false;
    }

    if (option->enable_simd) {
        char *tmp;
        bool check_simd_ret;

        comp_ctx->enable_simd = true;

        if (!(tmp = LLVMGetTargetMachineCPU(comp_ctx->target_machine))) {
            aot_set_last_error("get CPU from Target Machine fail");
            goto fail;
        }

        check_simd_ret =
            aot_check_simd_compatibility(comp_ctx->target_arch, tmp);
        LLVMDisposeMessage(tmp);
        if (!check_simd_ret) {
            aot_set_last_error("SIMD compatibility check failed, "
                               "try adding --cpu=<cpu> to specify a cpu "
                               "or adding --disable-simd to disable SIMD");
            goto fail;
        }
    }

    if (!(target_data_ref =
              LLVMCreateTargetDataLayout(comp_ctx->target_machine))) {
        aot_set_last_error("create LLVM target data layout failed.");
        goto fail;
    }
    comp_ctx->pointer_size = LLVMPointerSize(target_data_ref);
    LLVMDisposeTargetData(target_data_ref);

    comp_ctx->optimize = true;
    if (option->output_format == AOT_LLVMIR_UNOPT_FILE)
        comp_ctx->optimize = false;

    /* Create metadata for llvm float experimental constrained intrinsics */
    if (!(comp_ctx->fp_rounding_mode = LLVMMDStringInContext(
              comp_ctx->context, fp_round, (uint32)strlen(fp_round)))
        || !(comp_ctx->fp_exception_behavior = LLVMMDStringInContext(
                 comp_ctx->context, fp_exce, (uint32)strlen(fp_exce)))) {
        aot_set_last_error("create float llvm metadata failed.");
        goto fail;
    }

    if (!aot_set_llvm_basic_types(&comp_ctx->basic_types, comp_ctx->context)) {
        aot_set_last_error("create LLVM basic types failed.");
        goto fail;
    }

    if (!aot_create_llvm_consts(&comp_ctx->llvm_consts, comp_ctx)) {
        aot_set_last_error("create LLVM const values failed.");
        goto fail;
    }

    /* set exec_env data type to int8** */
    comp_ctx->exec_env_type = comp_ctx->basic_types.int8_pptr_type;

    /* set aot_inst data type to int8* */
    comp_ctx->aot_inst_type = INT8_PTR_TYPE;

    /* Create function context for each function */
    comp_ctx->func_ctx_count = comp_data->func_count;
    if (comp_data->func_count > 0
        && !(comp_ctx->func_ctxes =
                 aot_create_func_contexts(comp_data, comp_ctx)))
        goto fail;

    if (cpu) {
        uint32 len = (uint32)strlen(cpu) + 1;
        if (!(comp_ctx->target_cpu = wasm_runtime_malloc(len))) {
            aot_set_last_error("allocate memory failed");
            goto fail;
        }
        bh_memcpy_s(comp_ctx->target_cpu, len, cpu, len);
    }

    if (comp_ctx->disable_llvm_intrinsics)
        aot_intrinsic_fill_capability_flags(comp_ctx);

    ret = comp_ctx;

fail:
    if (triple_norm_new)
        LLVMDisposeMessage(triple_norm_new);

    if (cpu_new)
        LLVMDisposeMessage(cpu_new);

    if (!ret)
        aot_destroy_comp_context(comp_ctx);

    (void)i;
    return ret;
}

void
aot_destroy_comp_context(AOTCompContext *comp_ctx)
{
    if (!comp_ctx)
        return;

#if WASM_ENABLE_LAZY_JIT != 0
    if (comp_ctx->orc_symbol_map_pairs)
        wasm_runtime_free(comp_ctx->orc_symbol_map_pairs);

    if (comp_ctx->orc_call_through_mgr)
        LLVMOrcDisposeLazyCallThroughManager(comp_ctx->orc_call_through_mgr);

    if (comp_ctx->orc_indirect_stub_mgr)
        LLVMOrcDisposeIndirectStubsManager(comp_ctx->orc_indirect_stub_mgr);

    if (comp_ctx->orc_material_unit)
        LLVMOrcDisposeMaterializationUnit(comp_ctx->orc_material_unit);

    if (comp_ctx->target_machine)
        LLVMDisposeTargetMachine(comp_ctx->target_machine);

    if (comp_ctx->builder)
        LLVMDisposeBuilder(comp_ctx->builder);

    if (comp_ctx->orc_lazyjit)
        LLVMOrcDisposeLLJIT(comp_ctx->orc_lazyjit);

    if (comp_ctx->orc_thread_safe_context)
        LLVMOrcDisposeThreadSafeContext(comp_ctx->orc_thread_safe_context);

    if (comp_ctx->modules)
        wasm_runtime_free(comp_ctx->modules);

    /* Note: don't dispose comp_ctx->context and comp_ctx->modules[i] as
       they are disposed when disposing the thread safe context */

    LLVMShutdown();
#else
    if (comp_ctx->target_machine && !comp_ctx->is_jit_mode)
        LLVMDisposeTargetMachine(comp_ctx->target_machine);

    if (comp_ctx->builder)
        LLVMDisposeBuilder(comp_ctx->builder);

    if (comp_ctx->exec_engine) {
        LLVMDisposeExecutionEngine(comp_ctx->exec_engine);
        /* The LLVM module is freed when disposing execution engine,
           no need to dispose it again. */
    }
    else if (comp_ctx->module)
        LLVMDisposeModule(comp_ctx->module);

    if (comp_ctx->context)
        LLVMContextDispose(comp_ctx->context);
#endif

    if (comp_ctx->func_ctxes)
        aot_destroy_func_contexts(comp_ctx->func_ctxes,
                                  comp_ctx->func_ctx_count);

    if (bh_list_length(&comp_ctx->native_symbols) > 0) {
        AOTNativeSymbol *sym = bh_list_first_elem(&comp_ctx->native_symbols);
        while (sym) {
            AOTNativeSymbol *t = bh_list_elem_next(sym);
            bh_list_remove(&comp_ctx->native_symbols, sym);
            wasm_runtime_free(sym);
            sym = t;
        }
    }

    if (comp_ctx->target_cpu) {
        wasm_runtime_free(comp_ctx->target_cpu);
    }

    wasm_runtime_free(comp_ctx);
}

static bool
insert_native_symbol(AOTCompContext *comp_ctx, const char *symbol, int32 idx)
{
    AOTNativeSymbol *sym = wasm_runtime_malloc(sizeof(AOTNativeSymbol));

    if (!sym) {
        aot_set_last_error("alloc native symbol failed.");
        return false;
    }

    memset(sym, 0, sizeof(AOTNativeSymbol));
    bh_assert(strlen(symbol) <= sizeof(sym->symbol));
    snprintf(sym->symbol, sizeof(sym->symbol), "%s", symbol);
    sym->index = idx;

    if (BH_LIST_ERROR == bh_list_insert(&comp_ctx->native_symbols, sym)) {
        wasm_runtime_free(sym);
        aot_set_last_error("insert native symbol to list failed.");
        return false;
    }

    return true;
}

int32
aot_get_native_symbol_index(AOTCompContext *comp_ctx, const char *symbol)
{
    int32 idx = -1;
    AOTNativeSymbol *sym = NULL;

    sym = bh_list_first_elem(&comp_ctx->native_symbols);

    /* Lookup an existing symobl record */

    while (sym) {
        if (strcmp(sym->symbol, symbol) == 0) {
            idx = sym->index;
            break;
        }
        sym = bh_list_elem_next(sym);
    }

    /* Given symbol is not exist in list, then we alloc a new index for it */

    if (idx < 0) {
        if (comp_ctx->pointer_size == sizeof(uint32)
            && !strncmp(symbol, "f64#", 4)) {
            idx = bh_list_length(&comp_ctx->native_symbols);
            /* Add 4 bytes padding on 32-bit target to make sure that
               the f64 const is stored on 8-byte aligned address */
            if ((idx & 1) && !strncmp(comp_ctx->target_arch, "i386", 4)) {
                if (!insert_native_symbol(comp_ctx, "__ignore", idx)) {
                    return -1;
                }
            }
        }

        idx = bh_list_length(&comp_ctx->native_symbols);
        if (!insert_native_symbol(comp_ctx, symbol, idx)) {
            return -1;
        }

        if (comp_ctx->pointer_size == sizeof(uint32)
            && !strncmp(symbol, "f64#", 4)) {
            /* f64 const occupies 2 pointer slots on 32-bit target */
            if (!insert_native_symbol(comp_ctx, "__ignore", idx + 1)) {
                return -1;
            }
        }
    }

    return idx;
}

void
aot_value_stack_push(AOTValueStack *stack, AOTValue *value)
{
    if (!stack->value_list_head)
        stack->value_list_head = stack->value_list_end = value;
    else {
        stack->value_list_end->next = value;
        value->prev = stack->value_list_end;
        stack->value_list_end = value;
    }
}

AOTValue *
aot_value_stack_pop(AOTValueStack *stack)
{
    AOTValue *value = stack->value_list_end;

    bh_assert(stack->value_list_end);

    if (stack->value_list_head == stack->value_list_end)
        stack->value_list_head = stack->value_list_end = NULL;
    else {
        stack->value_list_end = stack->value_list_end->prev;
        stack->value_list_end->next = NULL;
        value->prev = NULL;
    }

    return value;
}

void
aot_value_stack_destroy(AOTValueStack *stack)
{
    AOTValue *value = stack->value_list_head, *p;

    while (value) {
        p = value->next;
        wasm_runtime_free(value);
        value = p;
    }

    stack->value_list_head = NULL;
    stack->value_list_end = NULL;
}

void
aot_block_stack_push(AOTBlockStack *stack, AOTBlock *block)
{
    if (!stack->block_list_head)
        stack->block_list_head = stack->block_list_end = block;
    else {
        stack->block_list_end->next = block;
        block->prev = stack->block_list_end;
        stack->block_list_end = block;
    }
}

AOTBlock *
aot_block_stack_pop(AOTBlockStack *stack)
{
    AOTBlock *block = stack->block_list_end;

    bh_assert(stack->block_list_end);

    if (stack->block_list_head == stack->block_list_end)
        stack->block_list_head = stack->block_list_end = NULL;
    else {
        stack->block_list_end = stack->block_list_end->prev;
        stack->block_list_end->next = NULL;
        block->prev = NULL;
    }

    return block;
}

void
aot_block_stack_destroy(AOTBlockStack *stack)
{
    AOTBlock *block = stack->block_list_head, *p;

    while (block) {
        p = block->next;
        aot_value_stack_destroy(&block->value_stack);
        aot_block_destroy(block);
        block = p;
    }

    stack->block_list_head = NULL;
    stack->block_list_end = NULL;
}

void
aot_block_destroy(AOTBlock *block)
{
    aot_value_stack_destroy(&block->value_stack);
    if (block->param_types)
        wasm_runtime_free(block->param_types);
    if (block->param_phis)
        wasm_runtime_free(block->param_phis);
    if (block->else_param_phis)
        wasm_runtime_free(block->else_param_phis);
    if (block->result_types)
        wasm_runtime_free(block->result_types);
    if (block->result_phis)
        wasm_runtime_free(block->result_phis);
    wasm_runtime_free(block);
}

bool
aot_checked_addr_list_add(AOTFuncContext *func_ctx, uint32 local_idx,
                          uint32 offset, uint32 bytes)
{
    AOTCheckedAddr *node = func_ctx->checked_addr_list;

    if (!(node = wasm_runtime_malloc(sizeof(AOTCheckedAddr)))) {
        aot_set_last_error("allocate memory failed.");
        return false;
    }

    node->local_idx = local_idx;
    node->offset = offset;
    node->bytes = bytes;

    node->next = func_ctx->checked_addr_list;
    func_ctx->checked_addr_list = node;
    return true;
}

void
aot_checked_addr_list_del(AOTFuncContext *func_ctx, uint32 local_idx)
{
    AOTCheckedAddr *node = func_ctx->checked_addr_list;
    AOTCheckedAddr *node_prev = NULL, *node_next;

    while (node) {
        node_next = node->next;

        if (node->local_idx == local_idx) {
            if (!node_prev)
                func_ctx->checked_addr_list = node_next;
            else
                node_prev->next = node_next;
            wasm_runtime_free(node);
        }
        else {
            node_prev = node;
        }

        node = node_next;
    }
}

bool
aot_checked_addr_list_find(AOTFuncContext *func_ctx, uint32 local_idx,
                           uint32 offset, uint32 bytes)
{
    AOTCheckedAddr *node = func_ctx->checked_addr_list;

    while (node) {
        if (node->local_idx == local_idx && node->offset == offset
            && node->bytes >= bytes) {
            return true;
        }
        node = node->next;
    }

    return false;
}

void
aot_checked_addr_list_destroy(AOTFuncContext *func_ctx)
{
    AOTCheckedAddr *node = func_ctx->checked_addr_list, *node_next;

    while (node) {
        node_next = node->next;
        wasm_runtime_free(node);
        node = node_next;
    }

    func_ctx->checked_addr_list = NULL;
}

bool
aot_build_zero_function_ret(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            AOTFuncType *func_type)
{
    LLVMValueRef ret = NULL;

    if (func_type->result_count) {
        switch (func_type->types[func_type->param_count]) {
            case VALUE_TYPE_I32:
                ret = LLVMBuildRet(comp_ctx->builder, I32_ZERO);
                break;
            case VALUE_TYPE_I64:
                ret = LLVMBuildRet(comp_ctx->builder, I64_ZERO);
                break;
            case VALUE_TYPE_F32:
                ret = LLVMBuildRet(comp_ctx->builder, F32_ZERO);
                break;
            case VALUE_TYPE_F64:
                ret = LLVMBuildRet(comp_ctx->builder, F64_ZERO);
                break;
            case VALUE_TYPE_V128:
                ret =
                    LLVMBuildRet(comp_ctx->builder, LLVM_CONST(i64x2_vec_zero));
                break;
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
                ret = LLVMBuildRet(comp_ctx->builder, REF_NULL);
                break;
            default:
                bh_assert(0);
        }
    }
    else {
        ret = LLVMBuildRetVoid(comp_ctx->builder);
    }

    if (!ret) {
        aot_set_last_error("llvm build ret failed.");
        return false;
    }
#if WASM_ENABLE_DEBUG_AOT != 0
    LLVMMetadataRef return_location =
        dwarf_gen_func_ret_location(comp_ctx, func_ctx);
    LLVMInstructionSetDebugLoc(ret, return_location);
#endif
    return true;
}

static LLVMValueRef
__call_llvm_intrinsic(const AOTCompContext *comp_ctx,
                      const AOTFuncContext *func_ctx, const char *name,
                      LLVMTypeRef ret_type, LLVMTypeRef *param_types,
                      int param_count, LLVMValueRef *param_values)
{
    LLVMValueRef func, ret;
    LLVMTypeRef func_type;
    const char *symname;
    int32 func_idx;

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(comp_ctx, name)) {
        if (func_ctx == NULL) {
            aot_set_last_error_v("invalid func_ctx for intrinsic: %s", name);
            return NULL;
        }

        if (!(func_type = LLVMFunctionType(ret_type, param_types,
                                           (uint32)param_count, false))) {
            aot_set_last_error("create LLVM intrinsic function type failed.");
            return NULL;
        }
        if (!(func_type = LLVMPointerType(func_type, 0))) {
            aot_set_last_error(
                "create LLVM intrinsic function pointer type failed.");
            return NULL;
        }

        if (!(symname = aot_intrinsic_get_symbol(name))) {
            aot_set_last_error_v("runtime intrinsic not implemented: %s\n",
                                 name);
            return NULL;
        }

        func_idx =
            aot_get_native_symbol_index((AOTCompContext *)comp_ctx, symname);
        if (func_idx < 0) {
            aot_set_last_error_v("get runtime intrinsc index failed: %s\n",
                                 name);
            return NULL;
        }

        if (!(func = aot_get_func_from_table(comp_ctx, func_ctx->native_symbol,
                                             func_type, func_idx))) {
            aot_set_last_error_v("get runtime intrinsc failed: %s\n", name);
            return NULL;
        }
    }
    else {
        /* Declare llvm intrinsic function if necessary */
        if (!(func = LLVMGetNamedFunction(func_ctx->module, name))) {
            if (!(func_type = LLVMFunctionType(ret_type, param_types,
                                               (uint32)param_count, false))) {
                aot_set_last_error(
                    "create LLVM intrinsic function type failed.");
                return NULL;
            }

            if (!(func = LLVMAddFunction(func_ctx->module, name, func_type))) {
                aot_set_last_error("add LLVM intrinsic function failed.");
                return NULL;
            }
        }
    }

#if LLVM_VERSION_MAJOR >= 14
    func_type =
        LLVMFunctionType(ret_type, param_types, (uint32)param_count, false);
#endif

    /* Call the LLVM intrinsic function */
    if (!(ret = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               (uint32)param_count, "call"))) {
        aot_set_last_error("llvm build intrinsic call failed.");
        return NULL;
    }

    return ret;
}

LLVMValueRef
aot_call_llvm_intrinsic(const AOTCompContext *comp_ctx,
                        const AOTFuncContext *func_ctx, const char *intrinsic,
                        LLVMTypeRef ret_type, LLVMTypeRef *param_types,
                        int param_count, ...)
{
    LLVMValueRef *param_values, ret;
    va_list argptr;
    uint64 total_size;
    int i = 0;

    /* Create param values */
    total_size = sizeof(LLVMValueRef) * (uint64)param_count;
    if (total_size >= UINT32_MAX
        || !(param_values = wasm_runtime_malloc((uint32)total_size))) {
        aot_set_last_error("allocate memory for param values failed.");
        return false;
    }

    /* Load each param value */
    va_start(argptr, param_count);
    while (i < param_count)
        param_values[i++] = va_arg(argptr, LLVMValueRef);
    va_end(argptr);

    ret = __call_llvm_intrinsic(comp_ctx, func_ctx, intrinsic, ret_type,
                                param_types, param_count, param_values);

    wasm_runtime_free(param_values);

    return ret;
}

LLVMValueRef
aot_call_llvm_intrinsic_v(const AOTCompContext *comp_ctx,
                          const AOTFuncContext *func_ctx, const char *intrinsic,
                          LLVMTypeRef ret_type, LLVMTypeRef *param_types,
                          int param_count, va_list param_value_list)
{
    LLVMValueRef *param_values, ret;
    uint64 total_size;
    int i = 0;

    /* Create param values */
    total_size = sizeof(LLVMValueRef) * (uint64)param_count;
    if (total_size >= UINT32_MAX
        || !(param_values = wasm_runtime_malloc((uint32)total_size))) {
        aot_set_last_error("allocate memory for param values failed.");
        return false;
    }

    /* Load each param value */
    while (i < param_count)
        param_values[i++] = va_arg(param_value_list, LLVMValueRef);

    ret = __call_llvm_intrinsic(comp_ctx, func_ctx, intrinsic, ret_type,
                                param_types, param_count, param_values);

    wasm_runtime_free(param_values);

    return ret;
}

LLVMValueRef
aot_get_func_from_table(const AOTCompContext *comp_ctx, LLVMValueRef base,
                        LLVMTypeRef func_type, int32 index)
{
    LLVMValueRef func;
    LLVMValueRef func_addr;

    if (!(func_addr = I32_CONST(index))) {
        aot_set_last_error("construct function index failed.");
        goto fail;
    }

    if (!(func_addr =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, OPQ_PTR_TYPE, base,
                                    &func_addr, 1, "func_addr"))) {
        aot_set_last_error("get function addr by index failed.");
        goto fail;
    }

    func =
        LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE, func_addr, "func_tmp");

    if (func == NULL) {
        aot_set_last_error("get function pointer failed.");
        goto fail;
    }

    if (!(func =
              LLVMBuildBitCast(comp_ctx->builder, func, func_type, "func"))) {
        aot_set_last_error("cast function fialed.");
        goto fail;
    }

    return func;
fail:
    return NULL;
}

LLVMValueRef
aot_load_const_from_table(AOTCompContext *comp_ctx, LLVMValueRef base,
                          const WASMValue *value, uint8 value_type)
{
    LLVMValueRef const_index, const_addr, const_value;
    LLVMTypeRef const_ptr_type, const_type;
    char buf[128] = { 0 };
    int32 index;

    switch (value_type) {
        case VALUE_TYPE_I32:
            /* Store the raw int bits of i32 const as a hex string */
            snprintf(buf, sizeof(buf), "i32#%08" PRIX32, value->i32);
            const_ptr_type = INT32_PTR_TYPE;
            const_type = I32_TYPE;
            break;
        case VALUE_TYPE_I64:
            /* Store the raw int bits of i64 const as a hex string */
            snprintf(buf, sizeof(buf), "i64#%016" PRIX64, value->i64);
            const_ptr_type = INT64_PTR_TYPE;
            const_type = I64_TYPE;
            break;
        case VALUE_TYPE_F32:
            /* Store the raw int bits of f32 const as a hex string */
            snprintf(buf, sizeof(buf), "f32#%08" PRIX32, value->i32);
            const_ptr_type = F32_PTR_TYPE;
            const_type = F32_TYPE;
            break;
        case VALUE_TYPE_F64:
            /* Store the raw int bits of f64 const as a hex string */
            snprintf(buf, sizeof(buf), "f64#%016" PRIX64, value->i64);
            const_ptr_type = F64_PTR_TYPE;
            const_type = F64_TYPE;
            break;
        default:
            bh_assert(0);
            return NULL;
    }

    /* Load f32/f64 const from exec_env->native_symbol[index] */

    index = aot_get_native_symbol_index(comp_ctx, buf);
    if (index < 0) {
        return NULL;
    }

    if (!(const_index = I32_CONST(index))) {
        aot_set_last_error("construct const index failed.");
        return NULL;
    }

    if (!(const_addr =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, OPQ_PTR_TYPE, base,
                                    &const_index, 1, "const_addr_tmp"))) {
        aot_set_last_error("get const addr by index failed.");
        return NULL;
    }

    if (!(const_addr = LLVMBuildBitCast(comp_ctx->builder, const_addr,
                                        const_ptr_type, "const_addr"))) {
        aot_set_last_error("cast const fialed.");
        return NULL;
    }

    if (!(const_value = LLVMBuildLoad2(comp_ctx->builder, const_type,
                                       const_addr, "const_value"))) {
        aot_set_last_error("load const failed.");
        return NULL;
    }

    (void)const_type;
    return const_value;
}
