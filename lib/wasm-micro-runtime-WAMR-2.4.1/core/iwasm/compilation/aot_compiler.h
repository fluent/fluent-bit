/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_COMPILER_H_
#define _AOT_COMPILER_H_

#include "aot.h"
#include "aot_llvm.h"
#include "../interpreter/wasm_interp.h"
#include "../aot/aot_runtime.h"

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

/**
 * Check whether a value type is a GC reference type,
 * don't use wasm_is_type_reftype since it requires
 * GC feature and may result in compilation error when
 * GC feature isn't compiled
 */
static inline bool
aot_is_type_gc_reftype(uint8 type)
{
    return ((type >= (uint8)REF_TYPE_ARRAYREF
             && type <= (uint8)REF_TYPE_NULLFUNCREF)
            || (type >= (uint8)REF_TYPE_HT_NULLABLE
                && type <= (uint8)REF_TYPE_HT_NON_NULLABLE)
#if WASM_ENABLE_STRINGREF != 0
            || (type >= (uint8)REF_TYPE_STRINGVIEWWTF8
                && type <= (uint8)REF_TYPE_STRINGREF)
            || (type >= (uint8)REF_TYPE_STRINGVIEWITER
                && type <= (uint8)REF_TYPE_STRINGVIEWWTF16)
#endif
                )
               ? true
               : false;
}

static inline bool
check_type_compatible(const AOTCompContext *comp_ctx, uint8 src_type,
                      uint8 dst_type)
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
        && (comp_ctx->enable_ref_types
            && (dst_type == VALUE_TYPE_EXTERNREF
                || dst_type == VALUE_TYPE_FUNCREF))) {
        return true;
    }

    if (dst_type == VALUE_TYPE_I32
        && (comp_ctx->enable_ref_types
            && (src_type == VALUE_TYPE_FUNCREF
                || src_type == VALUE_TYPE_EXTERNREF))) {
        return true;
    }

    return false;
}

/**
 * Operations for AOTCompFrame
 */

/**
 * Get the offset from frame pointer to the n-th local variable slot.
 *
 * @param n the index to the local variable array
 *
 * @return the offset from frame pointer to the local variable slot
 */
static inline uint32
offset_of_local(AOTCompContext *comp_ctx, unsigned n)
{
    if (!comp_ctx->is_jit_mode)
        /* In AOTFrame, there are 7 pointers before field lp */
        return comp_ctx->pointer_size
                   * (offsetof(AOTFrame, lp) / sizeof(uintptr_t))
               + sizeof(uint32) * n;
    else
        return offsetof(WASMInterpFrame, lp) + sizeof(uint32) * n;
}

uint32
offset_of_local_in_outs_area(AOTCompContext *comp_ctx, unsigned n);

/**
 * Get the offset from frame pointer to the n-th local variable's
 * reference flag slot.
 *
 * @param n the index to the local variable array
 *
 * @return the offset from frame pointer to the local variable slot
 */
static inline unsigned
offset_of_ref(AOTCompContext *comp_ctx, unsigned n)
{
    AOTCompFrame *frame = comp_ctx->aot_frame;
    uint32 all_cell_num = frame->max_local_cell_num + frame->max_stack_cell_num;
    return offset_of_local(comp_ctx, all_cell_num) + n;
}

/**
 * Generate instructions to commit computation result to the frame.
 * The general principle is to only commit values that will be used
 * through the frame.
 *
 * @param frame the frame information
 */
bool
aot_gen_commit_values(AOTCompFrame *frame);

/**
 * Generate instructions to commit SP and IP pointers to the frame.
 *
 * @param frame the frame information
 */
bool
aot_gen_commit_sp_ip(AOTCompFrame *frame, bool commit_sp, bool commit_ip);

/**
 * Generate instructions to commit IP pointer to the frame.
 *
 * @param frame the frame information
 */
bool
aot_gen_commit_ip(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                  LLVMValueRef ip_value, bool is_64bit);

bool
aot_frame_store_value(AOTCompContext *comp_ctx, LLVMValueRef value,
                      uint8 value_type, LLVMValueRef cur_frame, uint32 offset);

static inline void
push_32bit(AOTCompFrame *frame, AOTValue *aot_value)
{
    frame->sp->value = aot_value->value;
    frame->sp->type = aot_value->type;
    frame->sp->dirty = 1;
    frame->sp++;
}

static inline void
push_64bit(AOTCompFrame *frame, AOTValue *aot_value)
{
    push_32bit(frame, aot_value);
    push_32bit(frame, aot_value);
}

static inline void
push_i32(AOTCompFrame *frame, AOTValue *aot_value)
{
    bh_assert(aot_value->type == VALUE_TYPE_I32
              || aot_value->type == VALUE_TYPE_I1);
    push_32bit(frame, aot_value);
}

static inline void
push_i64(AOTCompFrame *frame, AOTValue *aot_value)
{
    bh_assert(aot_value->type == VALUE_TYPE_I64);
    push_64bit(frame, aot_value);
}

static inline void
push_f32(AOTCompFrame *frame, AOTValue *aot_value)
{
    bh_assert(aot_value->type == VALUE_TYPE_F32);
    push_32bit(frame, aot_value);
}

static inline void
push_f64(AOTCompFrame *frame, AOTValue *aot_value)
{
    bh_assert(aot_value->type == VALUE_TYPE_F64);
    push_64bit(frame, aot_value);
}

static inline void
push_v128(AOTCompFrame *frame, AOTValue *aot_value)
{
    bh_assert(aot_value->type == VALUE_TYPE_V128);
    push_64bit(frame, aot_value);
    push_64bit(frame, aot_value);
}

static inline void
push_ref(AOTCompFrame *frame, AOTValue *aot_value)
{
    bh_assert(frame->comp_ctx->enable_ref_types);
    push_32bit(frame, aot_value);
}

#if WASM_ENABLE_GC != 0
static inline void
push_gc_ref(AOTCompFrame *frame, AOTValue *aot_value)
{
    bh_assert(frame->comp_ctx->enable_gc);
    bh_assert(aot_value->type == VALUE_TYPE_GC_REF);
    if (frame->comp_ctx->pointer_size == sizeof(uint64)) {
        push_64bit(frame, aot_value);
        (frame->sp - 1)->ref = (frame->sp - 2)->ref = 1;
    }
    else {
        push_32bit(frame, aot_value);
        (frame->sp - 1)->ref = 1;
    }
}
#endif

/* Clear value slots except ref and committed_ref */
static inline void
clear_frame_value_slots(AOTValueSlot *slots, uint32 n)
{
    uint32 i;
    for (i = 0; i < n; i++) {
        slots[i].value = 0;
        slots[i].type = 0;
        slots[i].dirty = 0;
    }
}

static inline void
pop_i32(AOTCompFrame *frame)
{
    bh_assert(frame->sp - frame->lp >= 1);
    bh_assert((frame->sp - 1)->type == VALUE_TYPE_I32
              || (frame->sp - 1)->type == VALUE_TYPE_I1);
    frame->sp--;
    clear_frame_value_slots(frame->sp, 1);
}

static inline void
pop_i64(AOTCompFrame *frame)
{
    bh_assert(frame->sp - frame->lp >= 2);
    bh_assert((frame->sp - 1)->type == VALUE_TYPE_I64
              && (frame->sp - 2)->type == VALUE_TYPE_I64);
    frame->sp -= 2;
    clear_frame_value_slots(frame->sp, 2);
}

static inline void
pop_f32(AOTCompFrame *frame)
{
    bh_assert(frame->sp - frame->lp >= 1);
    bh_assert((frame->sp - 1)->type == VALUE_TYPE_F32);
    frame->sp--;
    clear_frame_value_slots(frame->sp, 1);
}

static inline void
pop_f64(AOTCompFrame *frame)
{
    bh_assert(frame->sp - frame->lp >= 2);
    bh_assert((frame->sp - 1)->type == VALUE_TYPE_F64
              && (frame->sp - 2)->type == VALUE_TYPE_F64);
    frame->sp -= 2;
    clear_frame_value_slots(frame->sp, 2);
}

static inline void
pop_v128(AOTCompFrame *frame)
{
    bh_assert(frame->sp - frame->lp >= 4);
    bh_assert((frame->sp - 1)->type == VALUE_TYPE_V128
              && (frame->sp - 2)->type == VALUE_TYPE_V128
              && (frame->sp - 3)->type == VALUE_TYPE_V128
              && (frame->sp - 4)->type == VALUE_TYPE_V128);
    frame->sp -= 4;
    clear_frame_value_slots(frame->sp, 4);
}

static inline void
pop_ref(AOTCompFrame *frame)
{
    bh_assert(frame->sp - frame->lp >= 1);
    bh_assert((frame->sp - 1)->type == VALUE_TYPE_FUNCREF
              || (frame->sp - 1)->type == VALUE_TYPE_EXTERNREF);
    frame->sp -= 1;
    clear_frame_value_slots(frame->sp, 1);
}

#if WASM_ENABLE_GC != 0
static inline void
pop_gc_ref(AOTCompFrame *frame)
{
    bh_assert(frame->sp - frame->lp >= 1);
    bh_assert((frame->sp - 1)->type == VALUE_TYPE_GC_REF);
    frame->sp -= 1;
    clear_frame_value_slots(frame->sp, 1);
    frame->sp->ref = 0;
    if (frame->comp_ctx->pointer_size == sizeof(uint64)) {
        bh_assert(frame->sp - frame->lp >= 1);
        bh_assert((frame->sp - 1)->type == VALUE_TYPE_GC_REF);
        frame->sp -= 1;
        clear_frame_value_slots(frame->sp, 1);
        frame->sp->ref = 0;
    }
}
#endif

static inline void
set_local_i32(AOTCompFrame *frame, int n, LLVMValueRef value)
{
    frame->lp[n].value = value;
    frame->lp[n].type = VALUE_TYPE_I32;
    frame->lp[n].dirty = 1;
}

static inline void
set_local_i64(AOTCompFrame *frame, int n, LLVMValueRef value)
{
    frame->lp[n].value = value;
    frame->lp[n].type = VALUE_TYPE_I64;
    frame->lp[n].dirty = 1;
    frame->lp[n + 1].value = value;
    frame->lp[n + 1].type = VALUE_TYPE_I64;
    frame->lp[n + 1].dirty = 1;
}

static inline void
set_local_f32(AOTCompFrame *frame, int n, LLVMValueRef value)
{
    frame->lp[n].value = value;
    frame->lp[n].type = VALUE_TYPE_F32;
    frame->lp[n].dirty = 1;
}

static inline void
set_local_f64(AOTCompFrame *frame, int n, LLVMValueRef value)
{
    frame->lp[n].value = value;
    frame->lp[n].type = VALUE_TYPE_F64;
    frame->lp[n].dirty = 1;
    frame->lp[n + 1].value = value;
    frame->lp[n + 1].type = VALUE_TYPE_F64;
    frame->lp[n + 1].dirty = 1;
}

static inline void
set_local_v128(AOTCompFrame *frame, int n, LLVMValueRef value)
{
    uint32 i;
    for (i = 0; i < 4; i++) {
        frame->lp[n + i].value = value;
        frame->lp[n + i].type = VALUE_TYPE_V128;
        frame->lp[n + i].dirty = 1;
    }
}

static inline void
set_local_ref(AOTCompFrame *frame, int n, LLVMValueRef value, uint8 ref_type)
{
    bh_assert(frame->comp_ctx->enable_ref_types);
    frame->lp[n].value = value;
    frame->lp[n].type = ref_type;
    frame->lp[n].dirty = 1;
}

#if WASM_ENABLE_GC != 0
static inline void
set_local_gc_ref(AOTCompFrame *frame, int n, LLVMValueRef value, uint8 ref_type)
{
    bh_assert(frame->comp_ctx->enable_gc);
    bh_assert(ref_type == VALUE_TYPE_GC_REF);
    frame->lp[n].value = value;
    frame->lp[n].type = ref_type;
    frame->lp[n].dirty = 1;
    frame->lp[n].ref = 1;
    if (frame->comp_ctx->pointer_size == sizeof(uint64)) {
        frame->lp[n + 1].value = value;
        frame->lp[n + 1].type = ref_type;
        frame->lp[n + 1].dirty = 1;
        frame->lp[n + 1].ref = 1;
    }
}
#endif

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

#if WASM_ENABLE_GC != 0

#define GET_GC_REF_FROM_STACK(llvm_value)                                     \
    do {                                                                      \
        AOTValue *aot_value;                                                  \
        CHECK_STACK();                                                        \
        aot_value =                                                           \
            func_ctx->block_stack.block_list_end->value_stack.value_list_end; \
        if (aot_value->type != VALUE_TYPE_GC_REF) {                           \
            aot_set_last_error("WASM stack data type is not reference");      \
            goto fail;                                                        \
        }                                                                     \
        llvm_value = aot_value->value;                                        \
    } while (0)

#endif

#define POP(llvm_value, value_type)                                          \
    do {                                                                     \
        AOTValue *aot_value;                                                 \
        uint8 val_type_to_pop = value_type;                                  \
        CHECK_STACK();                                                       \
        aot_value = aot_value_stack_pop(                                     \
            comp_ctx, &func_ctx->block_stack.block_list_end->value_stack);   \
        if (comp_ctx->enable_gc && aot_is_type_gc_reftype(value_type))       \
            val_type_to_pop = VALUE_TYPE_GC_REF;                             \
        if (!check_type_compatible(comp_ctx, aot_value->type,                \
                                   val_type_to_pop)) {                       \
            aot_set_last_error("invalid WASM stack data type.");             \
            wasm_runtime_free(aot_value);                                    \
            goto fail;                                                       \
        }                                                                    \
        if (aot_value->type == val_type_to_pop)                              \
            llvm_value = aot_value->value;                                   \
        else {                                                               \
            if (aot_value->type == VALUE_TYPE_I1) {                          \
                if (!(llvm_value =                                           \
                          LLVMBuildZExt(comp_ctx->builder, aot_value->value, \
                                        I32_TYPE, "i1toi32"))) {             \
                    aot_set_last_error("invalid WASM stack data type.");     \
                    wasm_runtime_free(aot_value);                            \
                    goto fail;                                               \
                }                                                            \
            }                                                                \
            else {                                                           \
                bh_assert(                                                   \
                    aot_value->type == VALUE_TYPE_I32                        \
                    || (comp_ctx->enable_ref_types                           \
                        && (aot_value->type == VALUE_TYPE_FUNCREF            \
                            || aot_value->type == VALUE_TYPE_EXTERNREF)));   \
                bh_assert(                                                   \
                    val_type_to_pop == VALUE_TYPE_I32                        \
                    || (comp_ctx->enable_ref_types                           \
                        && (val_type_to_pop == VALUE_TYPE_FUNCREF            \
                            || val_type_to_pop == VALUE_TYPE_EXTERNREF)));   \
                llvm_value = aot_value->value;                               \
            }                                                                \
        }                                                                    \
        wasm_runtime_free(aot_value);                                        \
    } while (0)

#if WASM_ENABLE_MEMORY64 != 0
#define IS_MEMORY64 (comp_ctx->comp_data->memories[0].flags & MEMORY64_FLAG)
#define MEMORY64_COND_VALUE(VAL_IF_ENABLED, VAL_IF_DISABLED) \
    (IS_MEMORY64 ? VAL_IF_ENABLED : VAL_IF_DISABLED)
#define IS_TABLE64(i) \
    (comp_ctx->comp_data->tables[i].table_type.flags & TABLE64_FLAG)
#define TABLE64_COND_VALUE(i, VAL_IF_ENABLED, VAL_IF_DISABLED) \
    (IS_TABLE64(i) ? VAL_IF_ENABLED : VAL_IF_DISABLED)
#else
#define MEMORY64_COND_VALUE(VAL_IF_ENABLED, VAL_IF_DISABLED) (VAL_IF_DISABLED)
#define TABLE64_COND_VALUE(i, VAL_IF_ENABLED, VAL_IF_DISABLED) (VAL_IF_DISABLED)
#endif

#define POP_I32(v) POP(v, VALUE_TYPE_I32)
#define POP_I64(v) POP(v, VALUE_TYPE_I64)
#define POP_F32(v) POP(v, VALUE_TYPE_F32)
#define POP_F64(v) POP(v, VALUE_TYPE_F64)
#define POP_V128(v) POP(v, VALUE_TYPE_V128)
#define POP_FUNCREF(v) POP(v, VALUE_TYPE_FUNCREF)
#define POP_EXTERNREF(v) POP(v, VALUE_TYPE_EXTERNREF)
#define POP_GC_REF(v) POP(v, VALUE_TYPE_GC_REF)
#define POP_MEM_OFFSET(v) \
    POP(v, MEMORY64_COND_VALUE(VALUE_TYPE_I64, VALUE_TYPE_I32))
#define POP_PAGE_COUNT(v) \
    POP(v, MEMORY64_COND_VALUE(VALUE_TYPE_I64, VALUE_TYPE_I32))
#define POP_TBL_ELEM_IDX(v) \
    POP(v, TABLE64_COND_VALUE(tbl_idx, VALUE_TYPE_I64, VALUE_TYPE_I32))
#define POP_TBL_ELEM_LEN(v) POP_TBL_ELEM_IDX(v)

#define POP_COND(llvm_value)                                                   \
    do {                                                                       \
        AOTValue *aot_value;                                                   \
        CHECK_STACK();                                                         \
        aot_value = aot_value_stack_pop(                                       \
            comp_ctx, &func_ctx->block_stack.block_list_end->value_stack);     \
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

#define PUSH(llvm_value, value_type)                                      \
    do {                                                                  \
        AOTValue *aot_value;                                              \
        if (!func_ctx->block_stack.block_list_end) {                      \
            aot_set_last_error("WASM block stack underflow.");            \
            goto fail;                                                    \
        }                                                                 \
        aot_value = wasm_runtime_malloc(sizeof(AOTValue));                \
        if (!aot_value) {                                                 \
            aot_set_last_error("allocate memory failed.");                \
            goto fail;                                                    \
        }                                                                 \
        memset(aot_value, 0, sizeof(AOTValue));                           \
        if (comp_ctx->enable_gc && aot_is_type_gc_reftype(value_type))    \
            aot_value->type = VALUE_TYPE_GC_REF;                          \
        else if (comp_ctx->enable_ref_types                               \
                 && (value_type == VALUE_TYPE_FUNCREF                     \
                     || value_type == VALUE_TYPE_EXTERNREF))              \
            aot_value->type = VALUE_TYPE_I32;                             \
        else                                                              \
            aot_value->type = value_type;                                 \
        aot_value->value = llvm_value;                                    \
        aot_value_stack_push(                                             \
            comp_ctx, &func_ctx->block_stack.block_list_end->value_stack, \
            aot_value);                                                   \
    } while (0)

#define PUSH_I32(v) PUSH(v, VALUE_TYPE_I32)
#define PUSH_I64(v) PUSH(v, VALUE_TYPE_I64)
#define PUSH_F32(v) PUSH(v, VALUE_TYPE_F32)
#define PUSH_F64(v) PUSH(v, VALUE_TYPE_F64)
#define PUSH_V128(v) PUSH(v, VALUE_TYPE_V128)
#define PUSH_COND(v) PUSH(v, VALUE_TYPE_I1)
#define PUSH_FUNCREF(v) PUSH(v, VALUE_TYPE_FUNCREF)
#define PUSH_EXTERNREF(v) PUSH(v, VALUE_TYPE_EXTERNREF)
#define PUSH_GC_REF(v) PUSH(v, VALUE_TYPE_GC_REF)
#define PUSH_PAGE_COUNT(v) \
    PUSH(v, MEMORY64_COND_VALUE(VALUE_TYPE_I64, VALUE_TYPE_I32))
#define PUSH_TBL_ELEM_IDX(v) \
    PUSH(v, TABLE64_COND_VALUE(tbl_idx, VALUE_TYPE_I64, VALUE_TYPE_I32))
#define PUSH_TBL_ELEM_LEN(v) PUSH_TBL_ELEM_IDX(v)

#define SET_CONST(v)                                                          \
    do {                                                                      \
        AOTValue *aot_value =                                                 \
            func_ctx->block_stack.block_list_end->value_stack.value_list_end; \
        aot_value->is_const = true;                                           \
        aot_value->const_value = (v);                                         \
    } while (0)

#define TO_LLVM_TYPE(wasm_type) \
    wasm_type_to_llvm_type(comp_ctx, &comp_ctx->basic_types, wasm_type)

#define I32_TYPE comp_ctx->basic_types.int32_type
#define I64_TYPE comp_ctx->basic_types.int64_type
#define F32_TYPE comp_ctx->basic_types.float32_type
#define F64_TYPE comp_ctx->basic_types.float64_type
#define VOID_TYPE comp_ctx->basic_types.void_type
#define INT1_TYPE comp_ctx->basic_types.int1_type
#define INT8_TYPE comp_ctx->basic_types.int8_type
#define INT16_TYPE comp_ctx->basic_types.int16_type
#define INTPTR_T_TYPE comp_ctx->basic_types.intptr_t_type
#define SIZE_T_TYPE comp_ctx->basic_types.size_t_type
#define MD_TYPE comp_ctx->basic_types.meta_data_type
#define INT8_PTR_TYPE comp_ctx->basic_types.int8_ptr_type
#define INT16_PTR_TYPE comp_ctx->basic_types.int16_ptr_type
#define INT32_PTR_TYPE comp_ctx->basic_types.int32_ptr_type
#define INT64_PTR_TYPE comp_ctx->basic_types.int64_ptr_type
#define INTPTR_T_PTR_TYPE comp_ctx->basic_types.intptr_t_ptr_type
#define F32_PTR_TYPE comp_ctx->basic_types.float32_ptr_type
#define F64_PTR_TYPE comp_ctx->basic_types.float64_ptr_type
#define FUNC_REF_TYPE comp_ctx->basic_types.funcref_type
#define EXTERN_REF_TYPE comp_ctx->basic_types.externref_type
#define GC_REF_TYPE comp_ctx->basic_types.gc_ref_type
#define GC_REF_PTR_TYPE comp_ctx->basic_types.gc_ref_ptr_type

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

#define INT_CONST(variable, value, type, is_signed)        \
    do {                                                   \
        variable = LLVMConstInt(type, value, is_signed);   \
        if (!variable) {                                   \
            aot_set_last_error("llvm build const failed"); \
            return false;                                  \
        }                                                  \
    } while (0)

#define LLVM_CONST(name) (comp_ctx->llvm_consts.name)
#define I1_ZERO LLVM_CONST(i1_zero)
#define I1_ONE LLVM_CONST(i1_one)
#define I8_ZERO LLVM_CONST(i8_zero)
#define I8_ONE LLVM_CONST(i8_one)
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
#define I32_TEN LLVM_CONST(i32_ten)
#define I32_ELEVEN LLVM_CONST(i32_eleven)
#define I32_TWELVE LLVM_CONST(i32_twelve)
#define I32_NEG_ONE LLVM_CONST(i32_neg_one)
#define I64_NEG_ONE LLVM_CONST(i64_neg_one)
#define I32_MIN LLVM_CONST(i32_min)
#define I64_MIN LLVM_CONST(i64_min)
#define I32_31 LLVM_CONST(i32_31)
#define I32_32 LLVM_CONST(i32_32)
#define I64_63 LLVM_CONST(i64_63)
#define I64_64 LLVM_CONST(i64_64)
#define REF_NULL I32_NEG_ONE
#define GC_REF_NULL LLVM_CONST(gc_ref_null)
#define I8_PTR_NULL LLVM_CONST(i8_ptr_null)

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
            /* AOT mode, declare the function */                            \
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
aot_emit_object_file(AOTCompContext *comp_ctx, char *file_name);

char *
aot_generate_tempfile_name(const char *prefix, const char *extension,
                           char *buffer, uint32 len);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_COMPILER_H_ */
