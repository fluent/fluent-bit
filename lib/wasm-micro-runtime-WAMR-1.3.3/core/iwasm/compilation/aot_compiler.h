/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_COMPILER_H_
#define _AOT_COMPILER_H_

#include "aot.h"
#include "aot_llvm.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef AOTIntCond IntCond;
typedef AOTFloatCond FloatCond;

typedef enum IntArithmetic {
    INT_ADD = 0,
    INT_SUB,
    INT_MUL,
    INT_DIV_S,
    INT_DIV_U,
    INT_REM_S,
    INT_REM_U
} IntArithmetic;

typedef enum V128Arithmetic {
    V128_ADD = 0,
    V128_SUB,
    V128_MUL,
    V128_DIV,
    V128_NEG,
    V128_MIN,
    V128_MAX,
} V128Arithmetic;

typedef enum IntBitwise {
    INT_AND = 0,
    INT_OR,
    INT_XOR,
} IntBitwise;

typedef enum V128Bitwise {
    V128_NOT,
    V128_AND,
    V128_ANDNOT,
    V128_OR,
    V128_XOR,
    V128_BITSELECT,
} V128Bitwise;

typedef enum IntShift {
    INT_SHL = 0,
    INT_SHR_S,
    INT_SHR_U,
    INT_ROTL,
    INT_ROTR
} IntShift;

typedef enum FloatMath {
    FLOAT_ABS = 0,
    FLOAT_NEG,
    FLOAT_CEIL,
    FLOAT_FLOOR,
    FLOAT_TRUNC,
    FLOAT_NEAREST,
    FLOAT_SQRT
} FloatMath;

typedef enum FloatArithmetic {
    FLOAT_ADD = 0,
    FLOAT_SUB,
    FLOAT_MUL,
    FLOAT_DIV,
    FLOAT_MIN,
    FLOAT_MAX,
} FloatArithmetic;

static inline bool
check_type_compatible(uint8 src_type, uint8 dst_type)
{
    if (src_type == dst_type) {
        return true;
    }

    /* ext i1 to i32 */
    if (src_type == VALUE_TYPE_I1 && dst_type == VALUE_TYPE_I32) {
        return true;
    }

    /* i32 <==> func.ref, i32 <==> extern.ref */
    if (src_type == VALUE_TYPE_I32
        && (dst_type == VALUE_TYPE_EXTERNREF
            || dst_type == VALUE_TYPE_FUNCREF)) {
        return true;
    }

    if (dst_type == VALUE_TYPE_I32
        && (src_type == VALUE_TYPE_FUNCREF
            || src_type == VALUE_TYPE_EXTERNREF)) {
        return true;
    }

    return false;
}

#define CHECK_STACK()                                          \
    do {                                                       \
        if (!func_ctx->block_stack.block_list_end) {           \
            aot_set_last_error("WASM block stack underflow."); \
            goto fail;                                         \
        }                                                      \
        if (!func_ctx->block_stack.block_list_end->value_stack \
                 .value_list_end) {                            \
            aot_set_last_error("WASM data stack underflow.");  \
            goto fail;                                         \
        }                                                      \
    } while (0)

#define POP(llvm_value, value_type)                                          \
    do {                                                                     \
        AOTValue *aot_value;                                                 \
        CHECK_STACK();                                                       \
        aot_value = aot_value_stack_pop(                                     \
            &func_ctx->block_stack.block_list_end->value_stack);             \
        if (!check_type_compatible(aot_value->type, value_type)) {           \
            aot_set_last_error("invalid WASM stack data type.");             \
            wasm_runtime_free(aot_value);                                    \
            goto fail;                                                       \
        }                                                                    \
        if (aot_value->type == value_type)                                   \
            llvm_value = aot_value->value;                                   \
        else {                                                               \
            if (aot_value->type == VALUE_TYPE_I1) {                          \
                if (!(llvm_value =                                           \
                          LLVMBuildZExt(comp_ctx->builder, aot_value->value, \
                                        I32_TYPE, "i1toi32"))) {             \
                    aot_set_last_error("invalid WASM stack "                 \
                                       "data type.");                        \
                    wasm_runtime_free(aot_value);                            \
                    goto fail;                                               \
                }                                                            \
            }                                                                \
            else {                                                           \
                bh_assert(aot_value->type == VALUE_TYPE_I32                  \
                          || aot_value->type == VALUE_TYPE_FUNCREF           \
                          || aot_value->type == VALUE_TYPE_EXTERNREF);       \
                bh_assert(value_type == VALUE_TYPE_I32                       \
                          || value_type == VALUE_TYPE_FUNCREF                \
                          || value_type == VALUE_TYPE_EXTERNREF);            \
                llvm_value = aot_value->value;                               \
            }                                                                \
        }                                                                    \
        wasm_runtime_free(aot_value);                                        \
    } while (0)

#define POP_I32(v) POP(v, VALUE_TYPE_I32)
#define POP_I64(v) POP(v, VALUE_TYPE_I64)
#define POP_F32(v) POP(v, VALUE_TYPE_F32)
#define POP_F64(v) POP(v, VALUE_TYPE_F64)
#define POP_V128(v) POP(v, VALUE_TYPE_V128)
#define POP_FUNCREF(v) POP(v, VALUE_TYPE_FUNCREF)
#define POP_EXTERNREF(v) POP(v, VALUE_TYPE_EXTERNREF)

#define POP_COND(llvm_value)                                                   \
    do {                                                                       \
        AOTValue *aot_value;                                                   \
        CHECK_STACK();                                                         \
        aot_value = aot_value_stack_pop(                                       \
            &func_ctx->block_stack.block_list_end->value_stack);               \
        if (aot_value->type != VALUE_TYPE_I1                                   \
            && aot_value->type != VALUE_TYPE_I32) {                            \
            aot_set_last_error("invalid WASM stack data type.");               \
            wasm_runtime_free(aot_value);                                      \
            goto fail;                                                         \
        }                                                                      \
        if (aot_value->type == VALUE_TYPE_I1)                                  \
            llvm_value = aot_value->value;                                     \
        else {                                                                 \
            if (!(llvm_value =                                                 \
                      LLVMBuildICmp(comp_ctx->builder, LLVMIntNE,              \
                                    aot_value->value, I32_ZERO, "i1_cond"))) { \
                aot_set_last_error("llvm build trunc failed.");                \
                wasm_runtime_free(aot_value);                                  \
                goto fail;                                                     \
            }                                                                  \
        }                                                                      \
        wasm_runtime_free(aot_value);                                          \
    } while (0)

#define PUSH(llvm_value, value_type)                                        \
    do {                                                                    \
        AOTValue *aot_value;                                                \
        if (!func_ctx->block_stack.block_list_end) {                        \
            aot_set_last_error("WASM block stack underflow.");              \
            goto fail;                                                      \
        }                                                                   \
        aot_value = wasm_runtime_malloc(sizeof(AOTValue));                  \
        if (!aot_value) {                                                   \
            aot_set_last_error("allocate memory failed.");                  \
            goto fail;                                                      \
        }                                                                   \
        memset(aot_value, 0, sizeof(AOTValue));                             \
        if (comp_ctx->enable_ref_types                                      \
            && (value_type == VALUE_TYPE_FUNCREF                            \
                || value_type == VALUE_TYPE_EXTERNREF))                     \
            aot_value->type = VALUE_TYPE_I32;                               \
        else                                                                \
            aot_value->type = value_type;                                   \
        aot_value->value = llvm_value;                                      \
        aot_value_stack_push(                                               \
            &func_ctx->block_stack.block_list_end->value_stack, aot_value); \
    } while (0)

#define PUSH_I32(v) PUSH(v, VALUE_TYPE_I32)
#define PUSH_I64(v) PUSH(v, VALUE_TYPE_I64)
#define PUSH_F32(v) PUSH(v, VALUE_TYPE_F32)
#define PUSH_F64(v) PUSH(v, VALUE_TYPE_F64)
#define PUSH_V128(v) PUSH(v, VALUE_TYPE_V128)
#define PUSH_COND(v) PUSH(v, VALUE_TYPE_I1)
#define PUSH_FUNCREF(v) PUSH(v, VALUE_TYPE_FUNCREF)
#define PUSH_EXTERNREF(v) PUSH(v, VALUE_TYPE_EXTERNREF)

#define TO_LLVM_TYPE(wasm_type) \
    wasm_type_to_llvm_type(&comp_ctx->basic_types, wasm_type)

#define I32_TYPE comp_ctx->basic_types.int32_type
#define I64_TYPE comp_ctx->basic_types.int64_type
#define F32_TYPE comp_ctx->basic_types.float32_type
#define F64_TYPE comp_ctx->basic_types.float64_type
#define VOID_TYPE comp_ctx->basic_types.void_type
#define INT1_TYPE comp_ctx->basic_types.int1_type
#define INT8_TYPE comp_ctx->basic_types.int8_type
#define INT16_TYPE comp_ctx->basic_types.int16_type
#define MD_TYPE comp_ctx->basic_types.meta_data_type
#define INT8_PTR_TYPE comp_ctx->basic_types.int8_ptr_type
#define INT16_PTR_TYPE comp_ctx->basic_types.int16_ptr_type
#define INT32_PTR_TYPE comp_ctx->basic_types.int32_ptr_type
#define INT64_PTR_TYPE comp_ctx->basic_types.int64_ptr_type
#define F32_PTR_TYPE comp_ctx->basic_types.float32_ptr_type
#define F64_PTR_TYPE comp_ctx->basic_types.float64_ptr_type
#define FUNC_REF_TYPE comp_ctx->basic_types.funcref_type
#define EXTERN_REF_TYPE comp_ctx->basic_types.externref_type

#define INT8_PTR_TYPE_GS comp_ctx->basic_types.int8_ptr_type_gs
#define INT16_PTR_TYPE_GS comp_ctx->basic_types.int16_ptr_type_gs
#define INT32_PTR_TYPE_GS comp_ctx->basic_types.int32_ptr_type_gs
#define INT64_PTR_TYPE_GS comp_ctx->basic_types.int64_ptr_type_gs
#define F32_PTR_TYPE_GS comp_ctx->basic_types.float32_ptr_type_gs
#define F64_PTR_TYPE_GS comp_ctx->basic_types.float64_ptr_type_gs

#define I32_CONST(v) LLVMConstInt(I32_TYPE, v, true)
#define I64_CONST(v) LLVMConstInt(I64_TYPE, v, true)
#define F32_CONST(v) LLVMConstReal(F32_TYPE, v)
#define F64_CONST(v) LLVMConstReal(F64_TYPE, v)
#define I8_CONST(v) LLVMConstInt(INT8_TYPE, v, true)

#define LLVM_CONST(name) (comp_ctx->llvm_consts.name)
#define I8_ZERO LLVM_CONST(i8_zero)
#define I32_ZERO LLVM_CONST(i32_zero)
#define I64_ZERO LLVM_CONST(i64_zero)
#define F32_ZERO LLVM_CONST(f32_zero)
#define F64_ZERO LLVM_CONST(f64_zero)
#define I32_ONE LLVM_CONST(i32_one)
#define I32_TWO LLVM_CONST(i32_two)
#define I32_THREE LLVM_CONST(i32_three)
#define I32_FOUR LLVM_CONST(i32_four)
#define I32_FIVE LLVM_CONST(i32_five)
#define I32_SIX LLVM_CONST(i32_six)
#define I32_SEVEN LLVM_CONST(i32_seven)
#define I32_EIGHT LLVM_CONST(i32_eight)
#define I32_NINE LLVM_CONST(i32_nine)
#define I32_NEG_ONE LLVM_CONST(i32_neg_one)
#define I64_NEG_ONE LLVM_CONST(i64_neg_one)
#define I32_MIN LLVM_CONST(i32_min)
#define I64_MIN LLVM_CONST(i64_min)
#define I32_31 LLVM_CONST(i32_31)
#define I32_32 LLVM_CONST(i32_32)
#define I64_63 LLVM_CONST(i64_63)
#define I64_64 LLVM_CONST(i64_64)
#define REF_NULL I32_NEG_ONE

#define V128_TYPE comp_ctx->basic_types.v128_type
#define V128_PTR_TYPE comp_ctx->basic_types.v128_ptr_type
#define V128_PTR_TYPE_GS comp_ctx->basic_types.v128_ptr_type_gs
#define V128_i8x16_TYPE comp_ctx->basic_types.i8x16_vec_type
#define V128_i16x8_TYPE comp_ctx->basic_types.i16x8_vec_type
#define V128_i32x4_TYPE comp_ctx->basic_types.i32x4_vec_type
#define V128_i64x2_TYPE comp_ctx->basic_types.i64x2_vec_type
#define V128_f32x4_TYPE comp_ctx->basic_types.f32x4_vec_type
#define V128_f64x2_TYPE comp_ctx->basic_types.f64x2_vec_type

#define V128_i8x16_ZERO LLVM_CONST(i8x16_vec_zero)
#define V128_i16x8_ZERO LLVM_CONST(i16x8_vec_zero)
#define V128_i32x4_ZERO LLVM_CONST(i32x4_vec_zero)
#define V128_i64x2_ZERO LLVM_CONST(i64x2_vec_zero)
#define V128_f32x4_ZERO LLVM_CONST(f32x4_vec_zero)
#define V128_f64x2_ZERO LLVM_CONST(f64x2_vec_zero)

#define TO_V128_i8x16(v) \
    LLVMBuildBitCast(comp_ctx->builder, v, V128_i8x16_TYPE, "i8x16_val")
#define TO_V128_i16x8(v) \
    LLVMBuildBitCast(comp_ctx->builder, v, V128_i16x8_TYPE, "i16x8_val")
#define TO_V128_i32x4(v) \
    LLVMBuildBitCast(comp_ctx->builder, v, V128_i32x4_TYPE, "i32x4_val")
#define TO_V128_i64x2(v) \
    LLVMBuildBitCast(comp_ctx->builder, v, V128_i64x2_TYPE, "i64x2_val")
#define TO_V128_f32x4(v) \
    LLVMBuildBitCast(comp_ctx->builder, v, V128_f32x4_TYPE, "f32x4_val")
#define TO_V128_f64x2(v) \
    LLVMBuildBitCast(comp_ctx->builder, v, V128_f64x2_TYPE, "f64x2_val")

#define CHECK_LLVM_CONST(v)                                  \
    do {                                                     \
        if (!v) {                                            \
            aot_set_last_error("create llvm const failed."); \
            goto fail;                                       \
        }                                                    \
    } while (0)

#define GET_AOT_FUNCTION(name, argc)                                        \
    do {                                                                    \
        if (!(func_type =                                                   \
                  LLVMFunctionType(ret_type, param_types, argc, false))) {  \
            aot_set_last_error("llvm add function type failed.");           \
            goto fail;                                                      \
        }                                                                   \
        if (comp_ctx->is_jit_mode) {                                        \
            /* JIT mode, call the function directly */                      \
            if (!(func_ptr_type = LLVMPointerType(func_type, 0))) {         \
                aot_set_last_error("llvm add pointer type failed.");        \
                goto fail;                                                  \
            }                                                               \
            if (!(value = I64_CONST((uint64)(uintptr_t)name))               \
                || !(func = LLVMConstIntToPtr(value, func_ptr_type))) {     \
                aot_set_last_error("create LLVM value failed.");            \
                goto fail;                                                  \
            }                                                               \
        }                                                                   \
        else if (comp_ctx->is_indirect_mode) {                              \
            int32 func_index;                                               \
            if (!(func_ptr_type = LLVMPointerType(func_type, 0))) {         \
                aot_set_last_error("create LLVM function type failed.");    \
                goto fail;                                                  \
            }                                                               \
                                                                            \
            func_index = aot_get_native_symbol_index(comp_ctx, #name);      \
            if (func_index < 0) {                                           \
                goto fail;                                                  \
            }                                                               \
            if (!(func = aot_get_func_from_table(                           \
                      comp_ctx, func_ctx->native_symbol, func_ptr_type,     \
                      func_index))) {                                       \
                goto fail;                                                  \
            }                                                               \
        }                                                                   \
        else {                                                              \
            char *func_name = #name;                                        \
            /* AOT mode, delcare the function */                            \
            if (!(func = LLVMGetNamedFunction(func_ctx->module, func_name)) \
                && !(func = LLVMAddFunction(func_ctx->module, func_name,    \
                                            func_type))) {                  \
                aot_set_last_error("llvm add function failed.");            \
                goto fail;                                                  \
            }                                                               \
        }                                                                   \
    } while (0)

/* if val is a constant integer and its value is not undef or poison */
static inline bool
LLVMIsEfficientConstInt(LLVMValueRef val)
{
    return LLVMIsConstant(val)
           && LLVMGetValueKind(val) == LLVMConstantIntValueKind
           && !LLVMIsUndef(val)
#if LLVM_VERSION_NUMBER >= 12
           && !LLVMIsPoison(addr)
#endif
        ;
}

bool
aot_compile_wasm(AOTCompContext *comp_ctx);

bool
aot_emit_llvm_file(AOTCompContext *comp_ctx, const char *file_name);

bool
aot_emit_aot_file(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                  const char *file_name);

uint8 *
aot_emit_aot_file_buf(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                      uint32 *p_aot_file_size);

bool
aot_emit_object_file(AOTCompContext *comp_ctx, char *file_name);

char *
aot_generate_tempfile_name(const char *prefix, const char *extension,
                           char *buffer, uint32 len);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_COMPILER_H_ */
