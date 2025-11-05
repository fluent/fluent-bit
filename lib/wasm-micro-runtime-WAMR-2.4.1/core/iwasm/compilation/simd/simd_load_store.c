/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "simd_common.h"
#include "simd_load_store.h"
#include "../aot_emit_exception.h"
#include "../aot_emit_memory.h"
#include "../../aot/aot_runtime.h"
#include "../../interpreter/wasm_opcode.h"

/* data_length in bytes */
static LLVMValueRef
simd_load(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx, uint32 align,
          mem_offset_t offset, uint32 data_length, LLVMTypeRef ptr_type,
          LLVMTypeRef data_type, bool enable_segue)
{
    LLVMValueRef maddr, data;

    if (!(maddr = aot_check_memory_overflow(comp_ctx, func_ctx, offset,
                                            data_length, enable_segue, NULL))) {
        HANDLE_FAILURE("aot_check_memory_overflow");
        return NULL;
    }

    if (!(maddr = LLVMBuildBitCast(comp_ctx->builder, maddr, ptr_type,
                                   "data_ptr"))) {
        HANDLE_FAILURE("LLVMBuildBitCast");
        return NULL;
    }

    if (!(data = LLVMBuildLoad2(comp_ctx->builder, data_type, maddr, "data"))) {
        HANDLE_FAILURE("LLVMBuildLoad");
        return NULL;
    }

    LLVMSetAlignment(data, 1);

    return data;
}

bool
aot_compile_simd_v128_load(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           uint32 align, mem_offset_t offset)
{
    bool enable_segue = comp_ctx->enable_segue_v128_load;
    LLVMTypeRef v128_ptr_type = enable_segue ? V128_PTR_TYPE_GS : V128_PTR_TYPE;
    LLVMValueRef result;

    if (!(result = simd_load(comp_ctx, func_ctx, align, offset, 16,
                             v128_ptr_type, V128_TYPE, enable_segue))) {
        return false;
    }

    PUSH_V128(result);

    return true;
fail:
    return false;
}

bool
aot_compile_simd_load_extend(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             uint8 opcode, uint32 align, mem_offset_t offset)
{
    LLVMValueRef sub_vector, result;
    uint32 opcode_index = opcode - SIMD_v128_load8x8_s;
    bool signeds[] = { true, false, true, false, true, false };
    LLVMTypeRef vector_types[] = {
        V128_i16x8_TYPE, V128_i16x8_TYPE, V128_i32x4_TYPE,
        V128_i32x4_TYPE, V128_i64x2_TYPE, V128_i64x2_TYPE,
    };
    LLVMTypeRef sub_vector_types[] = {
        LLVMVectorType(INT8_TYPE, 8),  LLVMVectorType(INT8_TYPE, 8),
        LLVMVectorType(INT16_TYPE, 4), LLVMVectorType(INT16_TYPE, 4),
        LLVMVectorType(I32_TYPE, 2),   LLVMVectorType(I32_TYPE, 2),
    };
    LLVMTypeRef sub_vector_type, sub_vector_ptr_type;
    bool enable_segue = comp_ctx->enable_segue_v128_load;

    bh_assert(opcode_index < 6);

    sub_vector_type = sub_vector_types[opcode_index];

    /* to vector ptr type */
    if (!sub_vector_type
        || !(sub_vector_ptr_type =
                 LLVMPointerType(sub_vector_type, enable_segue ? 256 : 0))) {
        HANDLE_FAILURE("LLVMPointerType");
        return false;
    }

    if (!(sub_vector =
              simd_load(comp_ctx, func_ctx, align, offset, 8,
                        sub_vector_ptr_type, sub_vector_type, enable_segue))) {
        return false;
    }

    if (signeds[opcode_index]) {
        if (!(result = LLVMBuildSExt(comp_ctx->builder, sub_vector,
                                     vector_types[opcode_index], "vector"))) {
            HANDLE_FAILURE("LLVMBuildSExt");
            return false;
        }
    }
    else {
        if (!(result = LLVMBuildZExt(comp_ctx->builder, sub_vector,
                                     vector_types[opcode_index], "vector"))) {
            HANDLE_FAILURE("LLVMBuildZExt");
            return false;
        }
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_load_splat(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            uint8 opcode, uint32 align, mem_offset_t offset)
{
    uint32 opcode_index = opcode - SIMD_v128_load8_splat;
    LLVMValueRef element, result;
    LLVMTypeRef element_ptr_types[] = { INT8_PTR_TYPE, INT16_PTR_TYPE,
                                        INT32_PTR_TYPE, INT64_PTR_TYPE };
    LLVMTypeRef element_ptr_types_gs[] = { INT8_PTR_TYPE_GS, INT16_PTR_TYPE_GS,
                                           INT32_PTR_TYPE_GS,
                                           INT64_PTR_TYPE_GS };
    LLVMTypeRef element_data_types[] = { INT8_TYPE, INT16_TYPE, I32_TYPE,
                                         I64_TYPE };
    uint32 data_lengths[] = { 1, 2, 4, 8 };
    LLVMValueRef undefs[] = {
        LLVM_CONST(i8x16_undef),
        LLVM_CONST(i16x8_undef),
        LLVM_CONST(i32x4_undef),
        LLVM_CONST(i64x2_undef),
    };
    LLVMValueRef masks[] = {
        LLVM_CONST(i32x16_zero),
        LLVM_CONST(i32x8_zero),
        LLVM_CONST(i32x4_zero),
        LLVM_CONST(i32x2_zero),
    };
    bool enable_segue = comp_ctx->enable_segue_v128_load;

    bh_assert(opcode_index < 4);

    if (!(element = simd_load(
              comp_ctx, func_ctx, align, offset, data_lengths[opcode_index],
              comp_ctx->enable_segue_v128_load
                  ? element_ptr_types_gs[opcode_index]
                  : element_ptr_types[opcode_index],
              element_data_types[opcode_index], enable_segue))) {
        return false;
    }

    if (!(result =
              LLVMBuildInsertElement(comp_ctx->builder, undefs[opcode_index],
                                     element, I32_ZERO, "base"))) {
        HANDLE_FAILURE("LLVMBuildInsertElement");
        return false;
    }

    if (!(result = LLVMBuildShuffleVector(comp_ctx->builder, result,
                                          undefs[opcode_index],
                                          masks[opcode_index], "vector"))) {
        HANDLE_FAILURE("LLVMBuildShuffleVector");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

bool
aot_compile_simd_load_lane(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           uint8 opcode, uint32 align, mem_offset_t offset,
                           uint8 lane_id)
{
    LLVMValueRef element, vector;
    uint32 opcode_index = opcode - SIMD_v128_load8_lane;
    uint32 data_lengths[] = { 1, 2, 4, 8 };
    LLVMTypeRef element_ptr_types[] = { INT8_PTR_TYPE, INT16_PTR_TYPE,
                                        INT32_PTR_TYPE, INT64_PTR_TYPE };
    LLVMTypeRef element_ptr_types_gs[] = { INT8_PTR_TYPE_GS, INT16_PTR_TYPE_GS,
                                           INT32_PTR_TYPE_GS,
                                           INT64_PTR_TYPE_GS };
    LLVMTypeRef element_data_types[] = { INT8_TYPE, INT16_TYPE, I32_TYPE,
                                         I64_TYPE };
    LLVMTypeRef vector_types[] = { V128_i8x16_TYPE, V128_i16x8_TYPE,
                                   V128_i32x4_TYPE, V128_i64x2_TYPE };
    LLVMValueRef lane = simd_lane_id_to_llvm_value(comp_ctx, lane_id);
    bool enable_segue = comp_ctx->enable_segue_v128_load;

    bh_assert(opcode_index < 4);

    if (!(vector = simd_pop_v128_and_bitcast(
              comp_ctx, func_ctx, vector_types[opcode_index], "src"))) {
        return false;
    }

    if (!(element = simd_load(
              comp_ctx, func_ctx, align, offset, data_lengths[opcode_index],
              comp_ctx->enable_segue_v128_load
                  ? element_ptr_types_gs[opcode_index]
                  : element_ptr_types[opcode_index],
              element_data_types[opcode_index], enable_segue))) {
        return false;
    }

    if (!(vector = LLVMBuildInsertElement(comp_ctx->builder, vector, element,
                                          lane, "dst"))) {
        HANDLE_FAILURE("LLVMBuildInsertElement");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, vector, "result");
}

bool
aot_compile_simd_load_zero(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           uint8 opcode, uint32 align, mem_offset_t offset)
{
    LLVMValueRef element, result, mask;
    uint32 opcode_index = opcode - SIMD_v128_load32_zero;
    uint32 data_lengths[] = { 4, 8 };
    LLVMTypeRef element_ptr_types[] = { INT32_PTR_TYPE, INT64_PTR_TYPE };
    LLVMTypeRef element_ptr_types_gs[] = { INT32_PTR_TYPE_GS,
                                           INT64_PTR_TYPE_GS };
    LLVMTypeRef element_data_types[] = { I32_TYPE, I64_TYPE };
    LLVMValueRef zero[] = {
        LLVM_CONST(i32x4_vec_zero),
        LLVM_CONST(i64x2_vec_zero),
    };
    LLVMValueRef undef[] = {
        LLVM_CONST(i32x4_undef),
        LLVM_CONST(i64x2_undef),
    };
    uint32 mask_length[] = { 4, 2 };
    LLVMValueRef mask_element[][4] = {
        { LLVM_CONST(i32_zero), LLVM_CONST(i32_four), LLVM_CONST(i32_five),
          LLVM_CONST(i32_six) },
        { LLVM_CONST(i32_zero), LLVM_CONST(i32_two) },
    };
    bool enable_segue = comp_ctx->enable_segue_v128_load;

    bh_assert(opcode_index < 2);

    if (!(element = simd_load(
              comp_ctx, func_ctx, align, offset, data_lengths[opcode_index],
              comp_ctx->enable_segue_v128_load
                  ? element_ptr_types_gs[opcode_index]
                  : element_ptr_types[opcode_index],
              element_data_types[opcode_index], enable_segue))) {
        return false;
    }

    if (!(result =
              LLVMBuildInsertElement(comp_ctx->builder, undef[opcode_index],
                                     element, I32_ZERO, "vector"))) {
        HANDLE_FAILURE("LLVMBuildInsertElement");
        return false;
    }

    /* fill in other lanes with zero */
    if (!(mask = LLVMConstVector(mask_element[opcode_index],
                                 mask_length[opcode_index]))) {
        HANDLE_FAILURE("LLConstVector");
        return false;
    }

    if (!(result = LLVMBuildShuffleVector(comp_ctx->builder, result,
                                          zero[opcode_index], mask,
                                          "fill_in_zero"))) {
        HANDLE_FAILURE("LLVMBuildShuffleVector");
        return false;
    }

    return simd_bitcast_and_push_v128(comp_ctx, func_ctx, result, "result");
}

/* data_length in bytes */
static bool
simd_store(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx, uint32 align,
           mem_offset_t offset, uint32 data_length, LLVMValueRef value,
           LLVMTypeRef value_ptr_type, bool enable_segue)
{
    LLVMValueRef maddr, result;

    if (!(maddr = aot_check_memory_overflow(comp_ctx, func_ctx, offset,
                                            data_length, enable_segue, NULL)))
        return false;

    if (!(maddr = LLVMBuildBitCast(comp_ctx->builder, maddr, value_ptr_type,
                                   "data_ptr"))) {
        HANDLE_FAILURE("LLVMBuildBitCast");
        return false;
    }

    if (!(result = LLVMBuildStore(comp_ctx->builder, value, maddr))) {
        HANDLE_FAILURE("LLVMBuildStore");
        return false;
    }

    LLVMSetAlignment(result, 1);

    return true;
}

bool
aot_compile_simd_v128_store(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            uint32 align, mem_offset_t offset)
{
    bool enable_segue = comp_ctx->enable_segue_v128_store;
    LLVMTypeRef v128_ptr_type = enable_segue ? V128_PTR_TYPE_GS : V128_PTR_TYPE;
    LLVMValueRef value;

    POP_V128(value);

    return simd_store(comp_ctx, func_ctx, align, offset, 16, value,
                      v128_ptr_type, enable_segue);
fail:
    return false;
}

bool
aot_compile_simd_store_lane(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            uint8 opcode, uint32 align, mem_offset_t offset,
                            uint8 lane_id)
{
    LLVMValueRef element, vector;
    uint32 data_lengths[] = { 1, 2, 4, 8 };
    LLVMTypeRef element_ptr_types[] = { INT8_PTR_TYPE, INT16_PTR_TYPE,
                                        INT32_PTR_TYPE, INT64_PTR_TYPE };
    LLVMTypeRef element_ptr_types_gs[] = { INT8_PTR_TYPE_GS, INT16_PTR_TYPE_GS,
                                           INT32_PTR_TYPE_GS,
                                           INT64_PTR_TYPE_GS };
    uint32 opcode_index = opcode - SIMD_v128_store8_lane;
    LLVMTypeRef vector_types[] = { V128_i8x16_TYPE, V128_i16x8_TYPE,
                                   V128_i32x4_TYPE, V128_i64x2_TYPE };
    LLVMValueRef lane = simd_lane_id_to_llvm_value(comp_ctx, lane_id);
    bool enable_segue = comp_ctx->enable_segue_v128_store;

    bh_assert(opcode_index < 4);

    if (!(vector = simd_pop_v128_and_bitcast(
              comp_ctx, func_ctx, vector_types[opcode_index], "src"))) {
        return false;
    }

    if (!(element = LLVMBuildExtractElement(comp_ctx->builder, vector, lane,
                                            "element"))) {
        HANDLE_FAILURE("LLVMBuildExtractElement");
        return false;
    }

    return simd_store(comp_ctx, func_ctx, align, offset,
                      data_lengths[opcode_index], element,
                      enable_segue ? element_ptr_types_gs[opcode_index]
                                   : element_ptr_types[opcode_index],
                      enable_segue);
}
