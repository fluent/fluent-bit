/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_ir.h"
#include "jit_codegen.h"
#include "jit_frontend.h"

/**
 * Operand kinds of instructions.
 */
enum {
    JIT_OPND_KIND_Reg,
    JIT_OPND_KIND_VReg,
    JIT_OPND_KIND_LookupSwitch,
};

/**
 * Operand kind of each instruction.
 */
static const uint8 insn_opnd_kind[] = {
#define INSN(NAME, OPND_KIND, OPND_NUM, FIRST_USE) JIT_OPND_KIND_##OPND_KIND,
#include "jit_ir.def"
#undef INSN
};

/**
 * Operand number of each instruction.
 */
static const uint8 insn_opnd_num[] = {
#define INSN(NAME, OPND_KIND, OPND_NUM, FIRST_USE) OPND_NUM,
#include "jit_ir.def"
#undef INSN
};

/**
 * Operand number of each instruction.
 */
static const uint8 insn_opnd_first_use[] = {
#define INSN(NAME, OPND_KIND, OPND_NUM, FIRST_USE) FIRST_USE,
#include "jit_ir.def"
#undef INSN
};

#define JIT_INSN_NEW_Reg(OPND_NUM) \
    jit_calloc(offsetof(JitInsn, _opnd) + sizeof(JitReg) * (OPND_NUM))
#define JIT_INSN_NEW_VReg(OPND_NUM)                     \
    jit_calloc(offsetof(JitInsn, _opnd._opnd_VReg._reg) \
               + sizeof(JitReg) * (OPND_NUM))

JitInsn *
_jit_insn_new_Reg_0(JitOpcode opc)
{
    JitInsn *insn = JIT_INSN_NEW_Reg(0);

    if (insn) {
        insn->opcode = opc;
    }

    return insn;
}

JitInsn *
_jit_insn_new_Reg_1(JitOpcode opc, JitReg r0)
{
    JitInsn *insn = JIT_INSN_NEW_Reg(1);

    if (insn) {
        insn->opcode = opc;
        *jit_insn_opnd(insn, 0) = r0;
    }

    return insn;
}

JitInsn *
_jit_insn_new_Reg_2(JitOpcode opc, JitReg r0, JitReg r1)
{
    JitInsn *insn = JIT_INSN_NEW_Reg(2);

    if (insn) {
        insn->opcode = opc;
        *jit_insn_opnd(insn, 0) = r0;
        *jit_insn_opnd(insn, 1) = r1;
    }

    return insn;
}

JitInsn *
_jit_insn_new_Reg_3(JitOpcode opc, JitReg r0, JitReg r1, JitReg r2)
{
    JitInsn *insn = JIT_INSN_NEW_Reg(3);

    if (insn) {
        insn->opcode = opc;
        *jit_insn_opnd(insn, 0) = r0;
        *jit_insn_opnd(insn, 1) = r1;
        *jit_insn_opnd(insn, 2) = r2;
    }

    return insn;
}

JitInsn *
_jit_insn_new_Reg_4(JitOpcode opc, JitReg r0, JitReg r1, JitReg r2, JitReg r3)
{
    JitInsn *insn = JIT_INSN_NEW_Reg(4);

    if (insn) {
        insn->opcode = opc;
        *jit_insn_opnd(insn, 0) = r0;
        *jit_insn_opnd(insn, 1) = r1;
        *jit_insn_opnd(insn, 2) = r2;
        *jit_insn_opnd(insn, 3) = r3;
    }

    return insn;
}

JitInsn *
_jit_insn_new_Reg_5(JitOpcode opc, JitReg r0, JitReg r1, JitReg r2, JitReg r3,
                    JitReg r4)
{
    JitInsn *insn = JIT_INSN_NEW_Reg(5);

    if (insn) {
        insn->opcode = opc;
        *jit_insn_opnd(insn, 0) = r0;
        *jit_insn_opnd(insn, 1) = r1;
        *jit_insn_opnd(insn, 2) = r2;
        *jit_insn_opnd(insn, 3) = r3;
        *jit_insn_opnd(insn, 4) = r4;
    }

    return insn;
}

JitInsn *
_jit_insn_new_VReg_1(JitOpcode opc, JitReg r0, int n)
{
    JitInsn *insn = JIT_INSN_NEW_VReg(1 + n);

    if (insn) {
        insn->opcode = opc;
        insn->_opnd._opnd_VReg._reg_num = 1 + n;
        *(jit_insn_opndv(insn, 0)) = r0;
    }

    return insn;
}

JitInsn *
_jit_insn_new_VReg_2(JitOpcode opc, JitReg r0, JitReg r1, int n)
{
    JitInsn *insn = JIT_INSN_NEW_VReg(2 + n);

    if (insn) {
        insn->opcode = opc;
        insn->_opnd._opnd_VReg._reg_num = 2 + n;
        *(jit_insn_opndv(insn, 0)) = r0;
        *(jit_insn_opndv(insn, 1)) = r1;
    }

    return insn;
}

JitInsn *
_jit_insn_new_LookupSwitch_1(JitOpcode opc, JitReg value, uint32 num)
{
    JitOpndLookupSwitch *opnd = NULL;
    JitInsn *insn =
        jit_calloc(offsetof(JitInsn, _opnd._opnd_LookupSwitch.match_pairs)
                   + sizeof(opnd->match_pairs[0]) * num);

    if (insn) {
        insn->opcode = opc;
        opnd = jit_insn_opndls(insn);
        opnd->value = value;
        opnd->match_pairs_num = num;
    }

    return insn;
}

#undef JIT_INSN_NEW_Reg
#undef JIT_INSN_NEW_VReg

void
jit_insn_insert_before(JitInsn *insn1, JitInsn *insn2)
{
    bh_assert(insn1->prev);
    insn1->prev->next = insn2;
    insn2->prev = insn1->prev;
    insn2->next = insn1;
    insn1->prev = insn2;
}

void
jit_insn_insert_after(JitInsn *insn1, JitInsn *insn2)
{
    bh_assert(insn1->next);
    insn1->next->prev = insn2;
    insn2->next = insn1->next;
    insn2->prev = insn1;
    insn1->next = insn2;
}

void
jit_insn_unlink(JitInsn *insn)
{
    bh_assert(insn->prev);
    insn->prev->next = insn->next;
    bh_assert(insn->next);
    insn->next->prev = insn->prev;
    insn->prev = insn->next = NULL;
}

unsigned
jit_insn_hash(JitInsn *insn)
{
    const uint8 opcode = insn->opcode;
    unsigned hash = opcode, i;

    /* Currently, only instructions with Reg kind operand require
       hashing.  For others, simply use opcode as the hash value.  */
    if (insn_opnd_kind[opcode] != JIT_OPND_KIND_Reg
        || insn_opnd_num[opcode] < 1)
        return hash;

    /* All the instructions with hashing support must be in the
       assignment format, i.e. the first operand is the result (hence
       being ignored) and all the others are operands.  This is also
       true for CHK instructions, whose first operand is the instruction
       pointer.  */
    for (i = 1; i < insn_opnd_num[opcode]; i++)
        hash = ((hash << 5) - hash) + *(jit_insn_opnd(insn, i));

    return hash;
}

bool
jit_insn_equal(JitInsn *insn1, JitInsn *insn2)
{
    const uint8 opcode = insn1->opcode;
    unsigned i;

    if (insn2->opcode != opcode)
        return false;

    if (insn_opnd_kind[opcode] != JIT_OPND_KIND_Reg
        || insn_opnd_num[opcode] < 1)
        return false;

    for (i = 1; i < insn_opnd_num[opcode]; i++)
        if (*(jit_insn_opnd(insn1, i)) != *(jit_insn_opnd(insn2, i)))
            return false;

    return true;
}

JitRegVec
jit_insn_opnd_regs(JitInsn *insn)
{
    JitRegVec vec = { 0 };
    JitOpndLookupSwitch *ls;

    vec._stride = 1;

    switch (insn_opnd_kind[insn->opcode]) {
        case JIT_OPND_KIND_Reg:
            vec.num = insn_opnd_num[insn->opcode];
            vec._base = jit_insn_opnd(insn, 0);
            break;

        case JIT_OPND_KIND_VReg:
            vec.num = jit_insn_opndv_num(insn);
            vec._base = jit_insn_opndv(insn, 0);
            break;

        case JIT_OPND_KIND_LookupSwitch:
            ls = jit_insn_opndls(insn);
            vec.num = ls->match_pairs_num + 2;
            vec._base = &ls->value;
            vec._stride = sizeof(ls->match_pairs[0]) / sizeof(*vec._base);
            break;
    }

    return vec;
}

unsigned
jit_insn_opnd_first_use(JitInsn *insn)
{
    return insn_opnd_first_use[insn->opcode];
}

JitBasicBlock *
jit_basic_block_new(JitReg label, int n)
{
    JitBasicBlock *block = jit_insn_new_PHI(label, n);
    if (!block)
        return NULL;

    block->prev = block->next = block;
    return block;
}

void
jit_basic_block_delete(JitBasicBlock *block)
{
    JitInsn *insn, *next_insn, *end;

    if (!block)
        return;

    insn = jit_basic_block_first_insn(block);
    end = jit_basic_block_end_insn(block);

    for (; insn != end; insn = next_insn) {
        next_insn = insn->next;
        jit_insn_delete(insn);
    }

    jit_insn_delete(block);
}

JitRegVec
jit_basic_block_preds(JitBasicBlock *block)
{
    JitRegVec vec;

    vec.num = jit_insn_opndv_num(block) - 1;
    vec._base = vec.num > 0 ? jit_insn_opndv(block, 1) : NULL;
    vec._stride = 1;

    return vec;
}

JitRegVec
jit_basic_block_succs(JitBasicBlock *block)
{
    JitInsn *last_insn = jit_basic_block_last_insn(block);
    JitRegVec vec;

    vec.num = 0;
    vec._base = NULL;
    vec._stride = 1;

    switch (last_insn->opcode) {
        case JIT_OP_JMP:
            vec.num = 1;
            vec._base = jit_insn_opnd(last_insn, 0);
            break;

        case JIT_OP_BEQ:
        case JIT_OP_BNE:
        case JIT_OP_BGTS:
        case JIT_OP_BGES:
        case JIT_OP_BLTS:
        case JIT_OP_BLES:
        case JIT_OP_BGTU:
        case JIT_OP_BGEU:
        case JIT_OP_BLTU:
        case JIT_OP_BLEU:
            vec.num = 2;
            vec._base = jit_insn_opnd(last_insn, 1);
            break;

        case JIT_OP_LOOKUPSWITCH:
        {
            JitOpndLookupSwitch *opnd = jit_insn_opndls(last_insn);
            vec.num = opnd->match_pairs_num + 1;
            vec._base = &opnd->default_target;
            vec._stride = sizeof(opnd->match_pairs[0]) / sizeof(*vec._base);
            break;
        }

        default:
            vec._stride = 0;
    }

    return vec;
}

JitCompContext *
jit_cc_init(JitCompContext *cc, unsigned htab_size)
{
    JitBasicBlock *entry_block, *exit_block;
    unsigned i, num;

    memset(cc, 0, sizeof(*cc));
    cc->_reference_count = 1;
    jit_annl_enable_basic_block(cc);

    /* Create entry and exit blocks.  They must be the first two
       blocks respectively.  */
    if (!(entry_block = jit_cc_new_basic_block(cc, 0)))
        goto fail;

    if (!(exit_block = jit_cc_new_basic_block(cc, 0))) {
        jit_basic_block_delete(entry_block);
        goto fail;
    }

    /* Record the entry and exit labels, whose indexes must be 0 and 1
       respectively.  */
    cc->entry_label = jit_basic_block_label(entry_block);
    cc->exit_label = jit_basic_block_label(exit_block);
    bh_assert(jit_reg_no(cc->entry_label) == 0
              && jit_reg_no(cc->exit_label) == 1);

    if (!(cc->exce_basic_blocks =
              jit_calloc(sizeof(JitBasicBlock *) * EXCE_NUM)))
        goto fail;

    if (!(cc->incoming_insns_for_exec_bbs =
              jit_calloc(sizeof(JitIncomingInsnList) * EXCE_NUM)))
        goto fail;

    cc->hreg_info = jit_codegen_get_hreg_info();
    bh_assert(cc->hreg_info->info[JIT_REG_KIND_I32].num > 3);

    /* Initialize virtual registers for hard registers.  */
    for (i = JIT_REG_KIND_VOID; i < JIT_REG_KIND_L32; i++) {
        if ((num = cc->hreg_info->info[i].num)) {
            /* Initialize the capacity to be large enough.  */
            jit_cc_new_reg(cc, i);
            bh_assert(cc->_ann._reg_capacity[i] > num);
            cc->_ann._reg_num[i] = num;
        }
    }

    /* Create registers for frame pointer, exec_env and cmp.  */
    cc->fp_reg = jit_reg_new(JIT_REG_KIND_PTR, cc->hreg_info->fp_hreg_index);
    cc->exec_env_reg =
        jit_reg_new(JIT_REG_KIND_PTR, cc->hreg_info->exec_env_hreg_index);
    cc->cmp_reg = jit_reg_new(JIT_REG_KIND_I32, cc->hreg_info->cmp_hreg_index);

    cc->_const_val._hash_table_size = htab_size;

    if (!(cc->_const_val._hash_table =
              jit_calloc(htab_size * sizeof(*cc->_const_val._hash_table))))
        goto fail;

    return cc;

fail:
    jit_cc_destroy(cc);
    return NULL;
}

void
jit_cc_destroy(JitCompContext *cc)
{
    unsigned i, end;
    JitBasicBlock *block;
    JitIncomingInsn *incoming_insn, *incoming_insn_next;

    jit_block_stack_destroy(&cc->block_stack);

    if (cc->jit_frame) {
        if (cc->jit_frame->memory_regs)
            jit_free(cc->jit_frame->memory_regs);
        if (cc->jit_frame->table_regs)
            jit_free(cc->jit_frame->table_regs);
        jit_free(cc->jit_frame);
    }

    if (cc->memory_regs)
        jit_free(cc->memory_regs);

    if (cc->table_regs)
        jit_free(cc->table_regs);

    jit_free(cc->_const_val._hash_table);

    /* Release the instruction hash table.  */
    jit_cc_disable_insn_hash(cc);

    jit_free(cc->exce_basic_blocks);

    if (cc->incoming_insns_for_exec_bbs) {
        for (i = 0; i < EXCE_NUM; i++) {
            incoming_insn = cc->incoming_insns_for_exec_bbs[i];
            while (incoming_insn) {
                incoming_insn_next = incoming_insn->next;
                jit_free(incoming_insn);
                incoming_insn = incoming_insn_next;
            }
        }
        jit_free(cc->incoming_insns_for_exec_bbs);
    }

    /* Release entry and exit blocks.  */
    if (0 != cc->entry_label)
        jit_basic_block_delete(jit_cc_entry_basic_block(cc));
    if (0 != cc->exit_label)
        jit_basic_block_delete(jit_cc_exit_basic_block(cc));

    /* clang-format off */
    /* Release blocks and instructions.  */
    JIT_FOREACH_BLOCK(cc, i, end, block)
    {
        jit_basic_block_delete(block);
    }
    /* clang-format on */

    /* Release constant values.  */
    for (i = JIT_REG_KIND_VOID; i < JIT_REG_KIND_L32; i++) {
        jit_free(cc->_const_val._value[i]);
        jit_free(cc->_const_val._next[i]);
    }

    /* Release storage of annotations.  */
#define ANN_LABEL(TYPE, NAME) jit_annl_disable_##NAME(cc);
#define ANN_INSN(TYPE, NAME) jit_anni_disable_##NAME(cc);
#define ANN_REG(TYPE, NAME) jit_annr_disable_##NAME(cc);
#include "jit_ir.def"
#undef ANN_LABEL
#undef ANN_INSN
#undef ANN_REG
}

void
jit_cc_delete(JitCompContext *cc)
{
    if (cc && --cc->_reference_count == 0) {
        jit_cc_destroy(cc);
        jit_free(cc);
    }
}

/*
 * Reallocate a memory block with the new_size.
 * TODO: replace this with imported jit_realloc when it's available.
 */
static void *
_jit_realloc(void *ptr, unsigned new_size, unsigned old_size)
{
    void *new_ptr = jit_malloc(new_size);

    if (new_ptr) {
        bh_assert(new_size > old_size);

        if (ptr) {
            memcpy(new_ptr, ptr, old_size);
            memset((uint8 *)new_ptr + old_size, 0, new_size - old_size);
            jit_free(ptr);
        }
        else
            memset(new_ptr, 0, new_size);
    }

    return new_ptr;
}

static unsigned
hash_of_const(unsigned kind, unsigned size, void *val)
{
    uint8 *p = (uint8 *)val, *end = p + size;
    unsigned hash = kind;

    do
        hash = ((hash << 5) - hash) + *p++;
    while (p != end);

    return hash;
}

static inline void *
address_of_const(JitCompContext *cc, JitReg reg, unsigned size)
{
    int kind = jit_reg_kind(reg);
    unsigned no = jit_reg_no(reg);
    unsigned idx = no & ~_JIT_REG_CONST_IDX_FLAG;

    bh_assert(kind < JIT_REG_KIND_L32);
    bh_assert(jit_reg_is_const_idx(reg) && idx < cc->_const_val._num[kind]);

    return cc->_const_val._value[kind] + size * idx;
}

static inline JitReg
next_of_const(JitCompContext *cc, JitReg reg)
{
    int kind = jit_reg_kind(reg);
    unsigned no = jit_reg_no(reg);
    unsigned idx = no & ~_JIT_REG_CONST_IDX_FLAG;

    bh_assert(kind < JIT_REG_KIND_L32);
    bh_assert(jit_reg_is_const_idx(reg) && idx < cc->_const_val._num[kind]);

    return cc->_const_val._next[kind][idx];
}

/**
 * Put a constant value into the compilation context.
 *
 * @param cc compilation context
 * @param kind register kind
 * @param size size of the value
 * @param val pointer to value which must be aligned
 *
 * @return a constant register containing the value
 */
static JitReg
_jit_cc_new_const(JitCompContext *cc, int kind, unsigned size, void *val)
{
    unsigned num = cc->_const_val._num[kind], slot;
    unsigned capacity = cc->_const_val._capacity[kind];
    uint8 *new_value;
    JitReg r, *new_next;

    bh_assert(num <= capacity);

    /* Find the existing value first.  */
    slot = hash_of_const(kind, size, val) % cc->_const_val._hash_table_size;
    r = cc->_const_val._hash_table[slot];

    for (; r; r = next_of_const(cc, r))
        if (jit_reg_kind(r) == kind
            && !memcmp(val, address_of_const(cc, r, size), size))
            return r;

    if (num == capacity) {
        /* Increase the space of value and next.  */
        capacity = capacity > 0 ? (capacity + capacity / 2) : 16;
        new_value = _jit_realloc(cc->_const_val._value[kind], size * capacity,
                                 size * num);
        new_next =
            _jit_realloc(cc->_const_val._next[kind],
                         sizeof(*new_next) * capacity, sizeof(*new_next) * num);

        if (new_value && new_next) {
            cc->_const_val._value[kind] = new_value;
            cc->_const_val._next[kind] = new_next;
        }
        else {
            jit_set_last_error(cc, "create const register failed");
            jit_free(new_value);
            jit_free(new_next);
            return 0;
        }

        cc->_const_val._capacity[kind] = capacity;
    }

    bh_assert(num + 1 < (uint32)_JIT_REG_CONST_IDX_FLAG);
    r = jit_reg_new(kind, _JIT_REG_CONST_IDX_FLAG | num);
    memcpy(cc->_const_val._value[kind] + size * num, val, size);
    cc->_const_val._next[kind][num] = cc->_const_val._hash_table[slot];
    cc->_const_val._hash_table[slot] = r;
    cc->_const_val._num[kind] = num + 1;

    return r;
}

static inline int32
get_const_val_in_reg(JitReg reg)
{
    int shift = 8 * sizeof(reg) - _JIT_REG_KIND_SHIFT + 1;
    return ((int32)(reg << shift)) >> shift;
}

#define _JIT_CC_NEW_CONST_HELPER(KIND, TYPE, val)                             \
    do {                                                                      \
        JitReg reg = jit_reg_new(                                             \
            JIT_REG_KIND_##KIND,                                              \
            (_JIT_REG_CONST_VAL_FLAG | ((JitReg)val & ~_JIT_REG_KIND_MASK))); \
                                                                              \
        if ((TYPE)get_const_val_in_reg(reg) == val)                           \
            return reg;                                                       \
        return _jit_cc_new_const(cc, JIT_REG_KIND_##KIND, sizeof(val), &val); \
    } while (0)

JitReg
jit_cc_new_const_I32_rel(JitCompContext *cc, int32 val, uint32 rel)
{
    uint64 val64 = (uint64)(uint32)val | ((uint64)rel << 32);
    _JIT_CC_NEW_CONST_HELPER(I32, uint64, val64);
}

JitReg
jit_cc_new_const_I64(JitCompContext *cc, int64 val)
{
    _JIT_CC_NEW_CONST_HELPER(I64, int64, val);
}

JitReg
jit_cc_new_const_F32(JitCompContext *cc, float val)
{
    int32 float_neg_zero = 0x80000000;

    if (!memcmp(&val, &float_neg_zero, sizeof(float)))
        /* Create const -0.0f */
        return _jit_cc_new_const(cc, JIT_REG_KIND_F32, sizeof(float), &val);

    _JIT_CC_NEW_CONST_HELPER(F32, float, val);
}

JitReg
jit_cc_new_const_F64(JitCompContext *cc, double val)
{
    int64 double_neg_zero = 0x8000000000000000ll;

    if (!memcmp(&val, &double_neg_zero, sizeof(double)))
        /* Create const -0.0d */
        return _jit_cc_new_const(cc, JIT_REG_KIND_F64, sizeof(double), &val);

    _JIT_CC_NEW_CONST_HELPER(F64, double, val);
}

#undef _JIT_CC_NEW_CONST_HELPER

#define _JIT_CC_GET_CONST_HELPER(KIND, TYPE)                               \
    do {                                                                   \
        bh_assert(jit_reg_kind(reg) == JIT_REG_KIND_##KIND);               \
        bh_assert(jit_reg_is_const(reg));                                  \
                                                                           \
        return (jit_reg_is_const_val(reg)                                  \
                    ? (TYPE)get_const_val_in_reg(reg)                      \
                    : *(TYPE *)(address_of_const(cc, reg, sizeof(TYPE)))); \
    } while (0)

static uint64
jit_cc_get_const_I32_helper(JitCompContext *cc, JitReg reg)
{
    _JIT_CC_GET_CONST_HELPER(I32, uint64);
}

uint32
jit_cc_get_const_I32_rel(JitCompContext *cc, JitReg reg)
{
    return (uint32)(jit_cc_get_const_I32_helper(cc, reg) >> 32);
}

int32
jit_cc_get_const_I32(JitCompContext *cc, JitReg reg)
{
    return (int32)(jit_cc_get_const_I32_helper(cc, reg));
}

int64
jit_cc_get_const_I64(JitCompContext *cc, JitReg reg)
{
    _JIT_CC_GET_CONST_HELPER(I64, int64);
}

float
jit_cc_get_const_F32(JitCompContext *cc, JitReg reg)
{
    _JIT_CC_GET_CONST_HELPER(F32, float);
}

double
jit_cc_get_const_F64(JitCompContext *cc, JitReg reg)
{
    _JIT_CC_GET_CONST_HELPER(F64, double);
}

#undef _JIT_CC_GET_CONST_HELPER

#define _JIT_REALLOC_ANN(TYPE, NAME, ANN, POSTFIX)                             \
    if (successful && cc->_ann._##ANN##_##NAME##_enabled) {                    \
        TYPE *ptr = _jit_realloc(cc->_ann._##ANN##_##NAME POSTFIX,             \
                                 sizeof(TYPE) * capacity, sizeof(TYPE) * num); \
        if (ptr)                                                               \
            cc->_ann._##ANN##_##NAME POSTFIX = ptr;                            \
        else                                                                   \
            successful = false;                                                \
    }

JitReg
jit_cc_new_label(JitCompContext *cc)
{
    unsigned num = cc->_ann._label_num;
    unsigned capacity = cc->_ann._label_capacity;
    bool successful = true;

    bh_assert(num <= capacity);

    if (num == capacity) {
        capacity = capacity > 0 ? (capacity + capacity / 2) : 16;

#define EMPTY_POSTFIX
#define ANN_LABEL(TYPE, NAME) _JIT_REALLOC_ANN(TYPE, NAME, label, EMPTY_POSTFIX)
#include "jit_ir.def"
#undef ANN_LABEL
#undef EMPTY_POSTFIX

        if (!successful) {
            jit_set_last_error(cc, "create label register failed");
            return 0;
        }

        cc->_ann._label_capacity = capacity;
    }

    cc->_ann._label_num = num + 1;

    return jit_reg_new(JIT_REG_KIND_L32, num);
}

JitBasicBlock *
jit_cc_new_basic_block(JitCompContext *cc, int n)
{
    JitReg label = jit_cc_new_label(cc);
    JitBasicBlock *block = NULL;

    if (label && (block = jit_basic_block_new(label, n)))
        /* Void 0 register indicates error in creation.  */
        *(jit_annl_basic_block(cc, label)) = block;
    else
        jit_set_last_error(cc, "create basic block failed");

    return block;
}

JitBasicBlock *
jit_cc_resize_basic_block(JitCompContext *cc, JitBasicBlock *block, int n)
{
    JitReg label = jit_basic_block_label(block);
    JitInsn *insn = jit_basic_block_first_insn(block);
    JitBasicBlock *new_block = jit_basic_block_new(label, n);

    if (!new_block) {
        jit_set_last_error(cc, "resize basic block failed");
        return NULL;
    }

    jit_insn_unlink(block);

    if (insn != block)
        jit_insn_insert_before(insn, new_block);

    bh_assert(*(jit_annl_basic_block(cc, label)) == block);
    *(jit_annl_basic_block(cc, label)) = new_block;
    jit_insn_delete(block);

    return new_block;
}

bool
jit_cc_enable_insn_hash(JitCompContext *cc, unsigned n)
{
    if (jit_anni_is_enabled__hash_link(cc))
        return true;

    if (!jit_anni_enable__hash_link(cc))
        return false;

    /* The table must not exist.  */
    bh_assert(!cc->_insn_hash_table._table);

    /* Integer overflow cannot happen because n << 4G (at most several
       times of 64K in the most extreme case).  */
    if (!(cc->_insn_hash_table._table =
              jit_calloc(n * sizeof(*cc->_insn_hash_table._table)))) {
        jit_anni_disable__hash_link(cc);
        return false;
    }

    cc->_insn_hash_table._size = n;
    return true;
}

void
jit_cc_disable_insn_hash(JitCompContext *cc)
{
    jit_anni_disable__hash_link(cc);
    jit_free(cc->_insn_hash_table._table);
    cc->_insn_hash_table._table = NULL;
    cc->_insn_hash_table._size = 0;
}

void
jit_cc_reset_insn_hash(JitCompContext *cc)
{
    if (jit_anni_is_enabled__hash_link(cc))
        memset(cc->_insn_hash_table._table, 0,
               cc->_insn_hash_table._size
                   * sizeof(*cc->_insn_hash_table._table));
}

JitInsn *
jit_cc_set_insn_uid(JitCompContext *cc, JitInsn *insn)
{
    if (insn) {
        unsigned num = cc->_ann._insn_num;
        unsigned capacity = cc->_ann._insn_capacity;
        bool successful = true;

        bh_assert(num <= capacity);

        if (num == capacity) {
            capacity = capacity > 0 ? (capacity + capacity / 2) : 64;

#define EMPTY_POSTFIX
#define ANN_INSN(TYPE, NAME) _JIT_REALLOC_ANN(TYPE, NAME, insn, EMPTY_POSTFIX)
#include "jit_ir.def"
#undef ANN_INSN
#undef EMPTY_POSTFIX

            if (!successful) {
                jit_set_last_error(cc, "set insn uid failed");
                return NULL;
            }

            cc->_ann._insn_capacity = capacity;
        }

        cc->_ann._insn_num = num + 1;
        insn->uid = num;
    }

    return insn;
}

JitInsn *
_jit_cc_set_insn_uid_for_new_insn(JitCompContext *cc, JitInsn *insn)
{
    if (jit_cc_set_insn_uid(cc, insn))
        return insn;

    jit_insn_delete(insn);
    return NULL;
}

JitReg
jit_cc_new_reg(JitCompContext *cc, unsigned kind)
{
    unsigned num = jit_cc_reg_num(cc, kind);
    unsigned capacity = cc->_ann._reg_capacity[kind];
    bool successful = true;

    bh_assert(num <= capacity);

    if (num == capacity) {
        capacity = (capacity == 0
                        /* Initialize the capacity to be larger than hard
                           register number.  */
                        ? cc->hreg_info->info[kind].num + 16
                        : capacity + capacity / 2);

#define ANN_REG(TYPE, NAME) _JIT_REALLOC_ANN(TYPE, NAME, reg, [kind])
#include "jit_ir.def"
#undef ANN_REG

        if (!successful) {
            jit_set_last_error(cc, "create register failed");
            return 0;
        }

        cc->_ann._reg_capacity[kind] = capacity;
    }

    cc->_ann._reg_num[kind] = num + 1;

    return jit_reg_new(kind, num);
}

#undef _JIT_REALLOC_ANN

#define ANN_LABEL(TYPE, NAME)                                                \
    bool jit_annl_enable_##NAME(JitCompContext *cc)                          \
    {                                                                        \
        if (cc->_ann._label_##NAME##_enabled)                                \
            return true;                                                     \
                                                                             \
        if (cc->_ann._label_capacity > 0                                     \
            && !(cc->_ann._label_##NAME =                                    \
                     jit_calloc(cc->_ann._label_capacity * sizeof(TYPE)))) { \
            jit_set_last_error(cc, "annl enable " #NAME "failed");           \
            return false;                                                    \
        }                                                                    \
                                                                             \
        cc->_ann._label_##NAME##_enabled = 1;                                \
        return true;                                                         \
    }
#define ANN_INSN(TYPE, NAME)                                                \
    bool jit_anni_enable_##NAME(JitCompContext *cc)                         \
    {                                                                       \
        if (cc->_ann._insn_##NAME##_enabled)                                \
            return true;                                                    \
                                                                            \
        if (cc->_ann._insn_capacity > 0                                     \
            && !(cc->_ann._insn_##NAME =                                    \
                     jit_calloc(cc->_ann._insn_capacity * sizeof(TYPE)))) { \
            jit_set_last_error(cc, "anni enable " #NAME "failed");          \
            return false;                                                   \
        }                                                                   \
                                                                            \
        cc->_ann._insn_##NAME##_enabled = 1;                                \
        return true;                                                        \
    }
#define ANN_REG(TYPE, NAME)                                            \
    bool jit_annr_enable_##NAME(JitCompContext *cc)                    \
    {                                                                  \
        unsigned k;                                                    \
                                                                       \
        if (cc->_ann._reg_##NAME##_enabled)                            \
            return true;                                               \
                                                                       \
        for (k = JIT_REG_KIND_VOID; k < JIT_REG_KIND_L32; k++)         \
            if (cc->_ann._reg_capacity[k] > 0                          \
                && !(cc->_ann._reg_##NAME[k] = jit_calloc(             \
                         cc->_ann._reg_capacity[k] * sizeof(TYPE)))) { \
                jit_set_last_error(cc, "annr enable " #NAME "failed"); \
                jit_annr_disable_##NAME(cc);                           \
                return false;                                          \
            }                                                          \
                                                                       \
        cc->_ann._reg_##NAME##_enabled = 1;                            \
        return true;                                                   \
    }
#include "jit_ir.def"
#undef ANN_LABEL
#undef ANN_INSN
#undef ANN_REG

#define ANN_LABEL(TYPE, NAME)                        \
    void jit_annl_disable_##NAME(JitCompContext *cc) \
    {                                                \
        jit_free(cc->_ann._label_##NAME);            \
        cc->_ann._label_##NAME = NULL;               \
        cc->_ann._label_##NAME##_enabled = 0;        \
    }
#define ANN_INSN(TYPE, NAME)                         \
    void jit_anni_disable_##NAME(JitCompContext *cc) \
    {                                                \
        jit_free(cc->_ann._insn_##NAME);             \
        cc->_ann._insn_##NAME = NULL;                \
        cc->_ann._insn_##NAME##_enabled = 0;         \
    }
#define ANN_REG(TYPE, NAME)                                      \
    void jit_annr_disable_##NAME(JitCompContext *cc)             \
    {                                                            \
        unsigned k;                                              \
                                                                 \
        for (k = JIT_REG_KIND_VOID; k < JIT_REG_KIND_L32; k++) { \
            jit_free(cc->_ann._reg_##NAME[k]);                   \
            cc->_ann._reg_##NAME[k] = NULL;                      \
        }                                                        \
                                                                 \
        cc->_ann._reg_##NAME##_enabled = 0;                      \
    }
#include "jit_ir.def"
#undef ANN_LABEL
#undef ANN_INSN
#undef ANN_REG

char *
jit_get_last_error(JitCompContext *cc)
{
    return cc->last_error[0] == '\0' ? NULL : cc->last_error;
}

void
jit_set_last_error_v(JitCompContext *cc, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(cc->last_error, sizeof(cc->last_error), format, args);
    va_end(args);
}

void
jit_set_last_error(JitCompContext *cc, const char *error)
{
    if (error)
        snprintf(cc->last_error, sizeof(cc->last_error), "Error: %s", error);
    else
        cc->last_error[0] = '\0';
}

bool
jit_cc_update_cfg(JitCompContext *cc)
{
    JitBasicBlock *block;
    unsigned block_index, end, succ_index, idx;
    JitReg *target;
    bool retval = false;

    if (!jit_annl_enable_pred_num(cc))
        return false;

    /* Update pred_num of all blocks.  */
    JIT_FOREACH_BLOCK_ENTRY_EXIT(cc, block_index, end, block)
    {
        JitRegVec succs = jit_basic_block_succs(block);

        JIT_REG_VEC_FOREACH(succs, succ_index, target)
        if (jit_reg_is_kind(L32, *target))
            *(jit_annl_pred_num(cc, *target)) += 1;
    }

    /* Resize predecessor vectors of body blocks.  */
    JIT_FOREACH_BLOCK(cc, block_index, end, block)
    {
        if (!jit_cc_resize_basic_block(
                cc, block,
                *(jit_annl_pred_num(cc, jit_basic_block_label(block)))))
            goto cleanup_and_return;
    }

    /* Fill in predecessor vectors all blocks.  */
    JIT_FOREACH_BLOCK_REVERSE_ENTRY_EXIT(cc, block_index, block)
    {
        JitRegVec succs = jit_basic_block_succs(block), preds;

        JIT_REG_VEC_FOREACH(succs, succ_index, target)
        if (jit_reg_is_kind(L32, *target)) {
            preds = jit_basic_block_preds(*(jit_annl_basic_block(cc, *target)));
            bh_assert(*(jit_annl_pred_num(cc, *target)) > 0);
            idx = *(jit_annl_pred_num(cc, *target)) - 1;
            *(jit_annl_pred_num(cc, *target)) = idx;
            *(jit_reg_vec_at(&preds, idx)) = jit_basic_block_label(block);
        }
    }

    retval = true;

cleanup_and_return:
    jit_annl_disable_pred_num(cc);
    return retval;
}

void
jit_value_stack_push(JitValueStack *stack, JitValue *value)
{
    if (!stack->value_list_head)
        stack->value_list_head = stack->value_list_end = value;
    else {
        stack->value_list_end->next = value;
        value->prev = stack->value_list_end;
        stack->value_list_end = value;
    }
}

JitValue *
jit_value_stack_pop(JitValueStack *stack)
{
    JitValue *value = stack->value_list_end;

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
jit_value_stack_destroy(JitValueStack *stack)
{
    JitValue *value = stack->value_list_head, *p;

    while (value) {
        p = value->next;
        jit_free(value);
        value = p;
    }

    stack->value_list_head = NULL;
    stack->value_list_end = NULL;
}

void
jit_block_stack_push(JitBlockStack *stack, JitBlock *block)
{
    if (!stack->block_list_head)
        stack->block_list_head = stack->block_list_end = block;
    else {
        stack->block_list_end->next = block;
        block->prev = stack->block_list_end;
        stack->block_list_end = block;
    }
}

JitBlock *
jit_block_stack_top(JitBlockStack *stack)
{
    return stack->block_list_end;
}

JitBlock *
jit_block_stack_pop(JitBlockStack *stack)
{
    JitBlock *block = stack->block_list_end;

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
jit_block_stack_destroy(JitBlockStack *stack)
{
    JitBlock *block = stack->block_list_head, *p;

    while (block) {
        p = block->next;
        jit_value_stack_destroy(&block->value_stack);
        jit_block_destroy(block);
        block = p;
    }

    stack->block_list_head = NULL;
    stack->block_list_end = NULL;
}

bool
jit_block_add_incoming_insn(JitBlock *block, JitInsn *insn, uint32 opnd_idx)
{
    JitIncomingInsn *incoming_insn;

    if (!(incoming_insn = jit_calloc((uint32)sizeof(JitIncomingInsn))))
        return false;

    incoming_insn->insn = insn;
    incoming_insn->opnd_idx = opnd_idx;
    incoming_insn->next = block->incoming_insns_for_end_bb;
    block->incoming_insns_for_end_bb = incoming_insn;
    return true;
}

void
jit_block_destroy(JitBlock *block)
{
    JitIncomingInsn *incoming_insn, *incoming_insn_next;

    jit_value_stack_destroy(&block->value_stack);
    if (block->param_types)
        jit_free(block->param_types);
    if (block->result_types)
        jit_free(block->result_types);

    incoming_insn = block->incoming_insns_for_end_bb;
    while (incoming_insn) {
        incoming_insn_next = incoming_insn->next;
        jit_free(incoming_insn);
        incoming_insn = incoming_insn_next;
    }

    jit_free(block);
}

static inline uint8
to_stack_value_type(uint8 type)
{
#if WASM_ENABLE_REF_TYPES != 0
    if (type == VALUE_TYPE_EXTERNREF || type == VALUE_TYPE_FUNCREF)
        return VALUE_TYPE_I32;
#endif
    return type;
}

bool
jit_cc_pop_value(JitCompContext *cc, uint8 type, JitReg *p_value)
{
    JitValue *jit_value = NULL;
    JitReg value = 0;

    if (!jit_block_stack_top(&cc->block_stack)) {
        jit_set_last_error(cc, "WASM block stack underflow");
        return false;
    }
    if (!jit_block_stack_top(&cc->block_stack)->value_stack.value_list_end) {
        jit_set_last_error(cc, "WASM data stack underflow");
        return false;
    }

    jit_value = jit_value_stack_pop(
        &jit_block_stack_top(&cc->block_stack)->value_stack);
    bh_assert(jit_value);

    if (jit_value->type != to_stack_value_type(type)) {
        jit_set_last_error(cc, "invalid WASM stack data type");
        jit_free(jit_value);
        return false;
    }

    switch (jit_value->type) {
        case VALUE_TYPE_I32:
            value = pop_i32(cc->jit_frame);
            break;
        case VALUE_TYPE_I64:
            value = pop_i64(cc->jit_frame);
            break;
        case VALUE_TYPE_F32:
            value = pop_f32(cc->jit_frame);
            break;
        case VALUE_TYPE_F64:
            value = pop_f64(cc->jit_frame);
            break;
        default:
            bh_assert(0);
            break;
    }

    bh_assert(cc->jit_frame->sp == jit_value->value);
    bh_assert(value == jit_value->value->reg);
    *p_value = value;
    jit_free(jit_value);
    return true;
}

bool
jit_cc_push_value(JitCompContext *cc, uint8 type, JitReg value)
{
    JitValue *jit_value;

    if (!jit_block_stack_top(&cc->block_stack)) {
        jit_set_last_error(cc, "WASM block stack underflow");
        return false;
    }

    if (!(jit_value = jit_calloc(sizeof(JitValue)))) {
        jit_set_last_error(cc, "allocate memory failed");
        return false;
    }

    bh_assert(value);

    jit_value->type = to_stack_value_type(type);
    jit_value->value = cc->jit_frame->sp;
    jit_value_stack_push(&jit_block_stack_top(&cc->block_stack)->value_stack,
                         jit_value);

    switch (jit_value->type) {
        case VALUE_TYPE_I32:
            push_i32(cc->jit_frame, value);
            break;
        case VALUE_TYPE_I64:
            push_i64(cc->jit_frame, value);
            break;
        case VALUE_TYPE_F32:
            push_f32(cc->jit_frame, value);
            break;
        case VALUE_TYPE_F64:
            push_f64(cc->jit_frame, value);
            break;
    }

    return true;
}

bool
_jit_insn_check_opnd_access_Reg(const JitInsn *insn, unsigned n)
{
    unsigned opcode = insn->opcode;
    return (insn_opnd_kind[opcode] == JIT_OPND_KIND_Reg
            && n < insn_opnd_num[opcode]);
}

bool
_jit_insn_check_opnd_access_VReg(const JitInsn *insn, unsigned n)
{
    unsigned opcode = insn->opcode;
    return (insn_opnd_kind[opcode] == JIT_OPND_KIND_VReg
            && n < insn->_opnd._opnd_VReg._reg_num);
}

bool
_jit_insn_check_opnd_access_LookupSwitch(const JitInsn *insn)
{
    unsigned opcode = insn->opcode;
    return (insn_opnd_kind[opcode] == JIT_OPND_KIND_LookupSwitch);
}

bool
jit_lock_reg_in_insn(JitCompContext *cc, JitInsn *the_insn, JitReg reg_to_lock)
{
    bool ret = false;
    JitInsn *prevent_spill = NULL;
    JitInsn *indicate_using = NULL;

    if (!the_insn)
        goto just_return;

    if (jit_cc_is_hreg_fixed(cc, reg_to_lock)) {
        ret = true;
        goto just_return;
    }

    /**
     * give the virtual register of the locked hard register a minimum, non-zero
     * distance, * so as to prevent it from being spilled out
     */
    prevent_spill = jit_insn_new_MOV(reg_to_lock, reg_to_lock);
    if (!prevent_spill)
        goto just_return;

    jit_insn_insert_before(the_insn, prevent_spill);

    /**
     * announce the locked hard register is being used, and do necessary spill
     * ASAP
     */
    indicate_using = jit_insn_new_MOV(reg_to_lock, reg_to_lock);
    if (!indicate_using)
        goto just_return;

    jit_insn_insert_after(the_insn, indicate_using);

    ret = true;

just_return:
    if (!ret)
        jit_set_last_error(cc, "generate insn failed");
    return ret;
}
