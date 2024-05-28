/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_FRONTEND_H_
#define _JIT_FRONTEND_H_

#include "jit_utils.h"
#include "jit_ir.h"
#include "../interpreter/wasm_interp.h"
#if WASM_ENABLE_AOT != 0
#include "../aot/aot_runtime.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if WASM_ENABLE_AOT == 0
typedef enum IntCond {
    INT_EQZ = 0,
    INT_EQ,
    INT_NE,
    INT_LT_S,
    INT_LT_U,
    INT_GT_S,
    INT_GT_U,
    INT_LE_S,
    INT_LE_U,
    INT_GE_S,
    INT_GE_U
} IntCond;

typedef enum FloatCond {
    FLOAT_EQ = 0,
    FLOAT_NE,
    FLOAT_LT,
    FLOAT_GT,
    FLOAT_LE,
    FLOAT_GE,
    FLOAT_UNO
} FloatCond;
#else
#define IntCond AOTIntCond
#define FloatCond AOTFloatCond
#endif

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

#if WASM_ENABLE_SHARED_MEMORY != 0
typedef enum AtomicRMWBinOp {
    AtomicRMWBinOpAdd,
    AtomicRMWBinOpSub,
    AtomicRMWBinOpAnd,
    AtomicRMWBinOpOr,
    AtomicRMWBinOpXor,
    AtomicRMWBinOpXchg
} AtomicRMWBinOp;
#endif

/**
 * Translate instructions in a function. The translated block must
 * end with a branch instruction whose targets are offsets relating to
 * the end bcip of the translated block, which are integral constants.
 * If a target of a branch is really a constant value (which should be
 * rare), put it into a register and then jump to the register instead
 * of using the constant value directly in the target. In the
 * translation process, don't create any new labels. The code bcip of
 * the begin and end of the translated block is stored in the
 * jit_annl_begin_bcip and jit_annl_end_bcip annotations of the label
 * of the block, which must be the same as the bcips used in
 * profiling.
 *
 * NOTE: the function must explicitly set SP to correct value when the
 * entry's bcip is the function's entry address.
 *
 * @param cc containing compilation context of generated IR
 * @param entry entry of the basic block to be translated. If its
 * value is NULL, the function will clean up any pass local data that
 * might be created previously.
 * @param is_reached a bitmap recording which bytecode has been
 * reached as a block entry
 *
 * @return IR block containing translated instructions if succeeds,
 * NULL otherwise
 */
JitBasicBlock *
jit_frontend_translate_func(JitCompContext *cc);

/**
 * Lower the IR of the given compilation context.
 *
 * @param cc the compilation context
 *
 * @return true if succeeds, false otherwise
 */
bool
jit_frontend_lower(JitCompContext *cc);

uint32
jit_frontend_get_jitted_return_addr_offset();

uint32
jit_frontend_get_global_data_offset(const WASMModule *module,
                                    uint32 global_idx);

uint32
jit_frontend_get_table_inst_offset(const WASMModule *module, uint32 tbl_idx);

uint32
jit_frontend_get_module_inst_extra_offset(const WASMModule *module);

JitReg
get_module_inst_reg(JitFrame *frame);

JitReg
get_module_reg(JitFrame *frame);

JitReg
get_import_func_ptrs_reg(JitFrame *frame);

JitReg
get_fast_jit_func_ptrs_reg(JitFrame *frame);

JitReg
get_func_type_indexes_reg(JitFrame *frame);

JitReg
get_aux_stack_bound_reg(JitFrame *frame);

JitReg
get_aux_stack_bottom_reg(JitFrame *frame);

JitReg
get_memory_inst_reg(JitFrame *frame, uint32 mem_idx);

JitReg
get_cur_page_count_reg(JitFrame *frame, uint32 mem_idx);

JitReg
get_memory_data_reg(JitFrame *frame, uint32 mem_idx);

JitReg
get_memory_data_end_reg(JitFrame *frame, uint32 mem_idx);

JitReg
get_mem_bound_check_1byte_reg(JitFrame *frame, uint32 mem_idx);

JitReg
get_mem_bound_check_2bytes_reg(JitFrame *frame, uint32 mem_idx);

JitReg
get_mem_bound_check_4bytes_reg(JitFrame *frame, uint32 mem_idx);

JitReg
get_mem_bound_check_8bytes_reg(JitFrame *frame, uint32 mem_idx);

JitReg
get_mem_bound_check_16bytes_reg(JitFrame *frame, uint32 mem_idx);

JitReg
get_table_elems_reg(JitFrame *frame, uint32 table_idx);

JitReg
get_table_cur_size_reg(JitFrame *frame, uint32 table_idx);

void
clear_fixed_virtual_regs(JitFrame *frame);

void
clear_memory_regs(JitFrame *frame);

void
clear_table_regs(JitFrame *frame);

/**
 * Get the offset from frame pointer to the n-th local variable slot.
 *
 * @param n the index to the local variable array
 *
 * @return the offset from frame pointer to the local variable slot
 */
static inline unsigned
offset_of_local(unsigned n)
{
    return offsetof(WASMInterpFrame, lp) + n * 4;
}

/**
 * Generate instruction to load an integer from the frame.
 *
 * This and the below gen_load_X functions generate instructions to
 * load values from the frame into registers if the values have not
 * been loaded yet.
 *
 * @param frame the frame information
 * @param n slot index to the local variable array
 *
 * @return register holding the loaded value
 */
JitReg
gen_load_i32(JitFrame *frame, unsigned n);

/**
 * Generate instruction to load a i64 integer from the frame.
 *
 * @param frame the frame information
 * @param n slot index to the local variable array
 *
 * @return register holding the loaded value
 */
JitReg
gen_load_i64(JitFrame *frame, unsigned n);

/**
 * Generate instruction to load a floating point value from the frame.
 *
 * @param frame the frame information
 * @param n slot index to the local variable array
 *
 * @return register holding the loaded value
 */
JitReg
gen_load_f32(JitFrame *frame, unsigned n);

/**
 * Generate instruction to load a double value from the frame.
 *
 * @param frame the frame information
 * @param n slot index to the local variable array
 *
 * @return register holding the loaded value
 */
JitReg
gen_load_f64(JitFrame *frame, unsigned n);

/**
 * Generate instructions to commit computation result to the frame.
 * The general principle is to only commit values that will be used
 * through the frame.
 *
 * @param frame the frame information
 * @param begin the begin value slot to commit
 * @param end the end value slot to commit
 */
void
gen_commit_values(JitFrame *frame, JitValueSlot *begin, JitValueSlot *end);

/**
 * Generate instructions to commit SP and IP pointers to the frame.
 *
 * @param frame the frame information
 */
void
gen_commit_sp_ip(JitFrame *frame);

/**
 * Generate commit instructions for the block end.
 *
 * @param frame the frame information
 */
static inline void
gen_commit_for_branch(JitFrame *frame)
{
    gen_commit_values(frame, frame->lp, frame->sp);
}

/**
 * Generate commit instructions for exception checks.
 *
 * @param frame the frame information
 */
static inline void
gen_commit_for_exception(JitFrame *frame)
{
    gen_commit_values(frame, frame->lp, frame->lp + frame->max_locals);
    gen_commit_sp_ip(frame);
}

/**
 * Generate commit instructions to commit all status.
 *
 * @param frame the frame information
 */
static inline void
gen_commit_for_all(JitFrame *frame)
{
    gen_commit_values(frame, frame->lp, frame->sp);
    gen_commit_sp_ip(frame);
}

static inline void
clear_values(JitFrame *frame)
{
    size_t total_size =
        sizeof(JitValueSlot) * (frame->max_locals + frame->max_stacks);
    memset(frame->lp, 0, total_size);
    frame->committed_sp = NULL;
    frame->committed_ip = NULL;
    clear_fixed_virtual_regs(frame);
}

static inline void
push_i32(JitFrame *frame, JitReg value)
{
    frame->sp->reg = value;
    frame->sp->dirty = 1;
    frame->sp++;
}

static inline void
push_i64(JitFrame *frame, JitReg value)
{
    frame->sp->reg = value;
    frame->sp->dirty = 1;
    frame->sp++;
    frame->sp->reg = value;
    frame->sp->dirty = 1;
    frame->sp++;
}

static inline void
push_f32(JitFrame *frame, JitReg value)
{
    push_i32(frame, value);
}

static inline void
push_f64(JitFrame *frame, JitReg value)
{
    push_i64(frame, value);
}

static inline JitReg
pop_i32(JitFrame *frame)
{
    frame->sp--;
    return gen_load_i32(frame, frame->sp - frame->lp);
}

static inline JitReg
pop_i64(JitFrame *frame)
{
    frame->sp -= 2;
    return gen_load_i64(frame, frame->sp - frame->lp);
}

static inline JitReg
pop_f32(JitFrame *frame)
{
    frame->sp--;
    return gen_load_f32(frame, frame->sp - frame->lp);
}

static inline JitReg
pop_f64(JitFrame *frame)
{
    frame->sp -= 2;
    return gen_load_f64(frame, frame->sp - frame->lp);
}

static inline void
pop(JitFrame *frame, int n)
{
    frame->sp -= n;
    memset(frame->sp, 0, n * sizeof(*frame->sp));
}

static inline JitReg
local_i32(JitFrame *frame, int n)
{
    return gen_load_i32(frame, n);
}

static inline JitReg
local_i64(JitFrame *frame, int n)
{
    return gen_load_i64(frame, n);
}

static inline JitReg
local_f32(JitFrame *frame, int n)
{
    return gen_load_f32(frame, n);
}

static inline JitReg
local_f64(JitFrame *frame, int n)
{
    return gen_load_f64(frame, n);
}

static void
set_local_i32(JitFrame *frame, int n, JitReg val)
{
    frame->lp[n].reg = val;
    frame->lp[n].dirty = 1;
}

static void
set_local_i64(JitFrame *frame, int n, JitReg val)
{
    frame->lp[n].reg = val;
    frame->lp[n].dirty = 1;
    frame->lp[n + 1].reg = val;
    frame->lp[n + 1].dirty = 1;
}

static inline void
set_local_f32(JitFrame *frame, int n, JitReg val)
{
    set_local_i32(frame, n, val);
}

static inline void
set_local_f64(JitFrame *frame, int n, JitReg val)
{
    set_local_i64(frame, n, val);
}

#define POP(jit_value, value_type)                         \
    do {                                                   \
        if (!jit_cc_pop_value(cc, value_type, &jit_value)) \
            goto fail;                                     \
    } while (0)

#define POP_I32(v) POP(v, VALUE_TYPE_I32)
#define POP_I64(v) POP(v, VALUE_TYPE_I64)
#define POP_F32(v) POP(v, VALUE_TYPE_F32)
#define POP_F64(v) POP(v, VALUE_TYPE_F64)
#define POP_FUNCREF(v) POP(v, VALUE_TYPE_FUNCREF)
#define POP_EXTERNREF(v) POP(v, VALUE_TYPE_EXTERNREF)

#define PUSH(jit_value, value_type)                        \
    do {                                                   \
        if (!jit_value)                                    \
            goto fail;                                     \
        if (!jit_cc_push_value(cc, value_type, jit_value)) \
            goto fail;                                     \
    } while (0)

#define PUSH_I32(v) PUSH(v, VALUE_TYPE_I32)
#define PUSH_I64(v) PUSH(v, VALUE_TYPE_I64)
#define PUSH_F32(v) PUSH(v, VALUE_TYPE_F32)
#define PUSH_F64(v) PUSH(v, VALUE_TYPE_F64)
#define PUSH_FUNCREF(v) PUSH(v, VALUE_TYPE_FUNCREF)
#define PUSH_EXTERNREF(v) PUSH(v, VALUE_TYPE_EXTERNREF)

#ifdef __cplusplus
}
#endif

#endif
