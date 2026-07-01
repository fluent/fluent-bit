/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_IR_H_
#define _JIT_IR_H_

#include "bh_platform.h"
#include "../interpreter/wasm.h"
#include "jit_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register (operand) representation of JIT IR.
 *
 * Encoding: [4-bit: kind, 28-bit register no.]
 *
 * Registers in JIT IR are classified into different kinds according
 * to types of values they can hold. The classification is based on
 * most processors' hardware register classifications, which include
 * various sets of integer, floating point and vector registers with
 * different sizes. These registers can be mapped onto corresponding
 * kinds of hardware registers by register allocator. Instructions
 * can only operate on allowed kinds of registers. For example, an
 * integer instruction cannot operate on floating point or vector
 * registers. Some encodings of these kinds of registers also
 * represent immediate constant values and indexes to constant tables
 * (see below). In that case, those registers are read-only. Writing
 * to them is illegal. Reading from an immediate constant value
 * register always returns the constant value encoded in the register
 * no. Reading from a constant table index register always returns
 * the constant value stored at the encoded index of the constant
 * table of the register's kind. Immediate constant values and values
 * indexed by constant table indexes can only be loaded into the
 * corresponding kinds of registers if they must be loaded into
 * registers. Besides these common kinds of registers, labels of
 * basic blocks are also treated as registers of a special kind, which
 * hold code addresses of basic block labels and are read-only. Each
 * basic block is assigned one unique label register. With this
 * unification, we can use the same set of load instructions to load
 * values either from addresses stored in normal registers or from
 * addresses of labels. Besides these register kinds, the void kind
 * is a special kind of registers to denote some error occurs when a
 * normal register is expected. Or it can be used as result operand
 * of call and invoke instructions to denote no return values. The
 * variable registers are classified into two sets: the hard registers
 * whose register numbers are less than the hard register numbers of
 * their kinds and the virtual registers whose register numbers are
 * greater than or equal to the hard register numbers. Before
 * register allocation is done, hard registers may appear in the IR
 * due to special usages of passes frontend (e.g. fp_reg and exec_env_reg)
 * or lower_cg. In the mean time (including during register
 * allocation), those hard registers are treated same as virtual
 * registers except that they may not be SSA and they can only be
 * allocated to the hard registers of themselves.
 *
 * Classification of registers:
 *   + void register (kind == JIT_REG_KIND_VOID, no. must be 0)
 *   + label registers (kind == JIT_REG_KIND_L32)
 *   + value registers (kind == JIT_REG_KIND_I32/I64/F32/F64/V64/V128/V256)
 *   | + constants (_JIT_REG_CONST_VAL_FLAG | _JIT_REG_CONST_IDX_FLAG)
 *   | | + constant values (_JIT_REG_CONST_VAL_FLAG)
 *   | | + constant indexes (_JIT_REG_CONST_IDX_FLAG)
 *   | + variables (!(_JIT_REG_CONST_VAL_FLAG | _JIT_REG_CONST_IDX_FLAG))
 *   | | + hard registers (no. < hard register number)
 *   | | + virtual registers (no. >= hard register number)
 */
typedef uint32 JitReg;

/*
 * Mask and shift bits of register kind.
 */
#define _JIT_REG_KIND_MASK 0xf0000000
#define _JIT_REG_KIND_SHIFT 28

/*
 * Mask of register no. which must be the least significant bits.
 */
#define _JIT_REG_NO_MASK (~_JIT_REG_KIND_MASK)

/*
 * Constant value flag (the most significant bit) of register
 * no. field of integer, floating point and vector registers. If this
 * flag is set in the register no., the rest bits of register
 * no. represent a signed (27-bit) integer constant value of the
 * corresponding type of the register and the register is read-only.
 */
#define _JIT_REG_CONST_VAL_FLAG ((_JIT_REG_NO_MASK >> 1) + 1)

/*
 * Constant index flag of non-constant-value (constant value flag is
 * not set in register no. field) integer, floating point and vector
 * registers. If this flag is set, the rest bits of the register
 * no. represent an index to the constant value table of the
 * corresponding type of the register and the register is read-only.
 */
#define _JIT_REG_CONST_IDX_FLAG (_JIT_REG_CONST_VAL_FLAG >> 1)

/**
 * Register kinds. Don't change the order of the defined values. The
 * L32 kind must be after all normal kinds (see _const_val and _reg_ann
 * of JitCompContext).
 */
typedef enum JitRegKind {
    JIT_REG_KIND_VOID = 0x00, /* void type */
    JIT_REG_KIND_I32 = 0x01,  /* 32-bit signed or unsigned integer */
    JIT_REG_KIND_I64 = 0x02,  /* 64-bit signed or unsigned integer */
    JIT_REG_KIND_F32 = 0x03,  /* 32-bit floating point */
    JIT_REG_KIND_F64 = 0x04,  /* 64-bit floating point */
    JIT_REG_KIND_V64 = 0x05,  /* 64-bit vector */
    JIT_REG_KIND_V128 = 0x06, /* 128-bit vector */
    JIT_REG_KIND_V256 = 0x07, /* 256-bit vector */
    JIT_REG_KIND_L32 = 0x08,  /* 32-bit label address */
    JIT_REG_KIND_NUM          /* number of register kinds */
} JitRegKind;

#if UINTPTR_MAX == UINT64_MAX
#define JIT_REG_KIND_PTR JIT_REG_KIND_I64
#else
#define JIT_REG_KIND_PTR JIT_REG_KIND_I32
#endif

/**
 * Construct a new JIT IR register from the kind and no.
 *
 * @param reg_kind register kind
 * @param reg_no register no.
 *
 * @return the new register with the given kind and no.
 */
static inline JitReg
jit_reg_new(unsigned reg_kind, unsigned reg_no)
{
    return (JitReg)((reg_kind << _JIT_REG_KIND_SHIFT) | reg_no);
}

/**
 * Get the register kind of the given register.
 *
 * @param r a JIT IR register
 *
 * @return the register kind of register r
 */
static inline int
jit_reg_kind(JitReg r)
{
    return (r & _JIT_REG_KIND_MASK) >> _JIT_REG_KIND_SHIFT;
}

/**
 * Get the register no. of the given JIT IR register.
 *
 * @param r a JIT IR register
 *
 * @return the register no. of register r
 */
static inline int
jit_reg_no(JitReg r)
{
    return r & _JIT_REG_NO_MASK;
}

/**
 * Check whether the given register is a normal value register.
 *
 * @param r a JIT IR register
 *
 * @return true iff the register is a normal value register
 */
static inline bool
jit_reg_is_value(JitReg r)
{
    unsigned kind = jit_reg_kind(r);
    return kind > JIT_REG_KIND_VOID && kind < JIT_REG_KIND_L32;
}

/**
 * Check whether the given register is a constant value.
 *
 * @param r a JIT IR register
 *
 * @return true iff register r is a constant value
 */
static inline bool
jit_reg_is_const_val(JitReg r)
{
    return jit_reg_is_value(r) && (r & _JIT_REG_CONST_VAL_FLAG);
}

/**
 * Check whether the given register is a constant table index.
 *
 * @param r a JIT IR register
 *
 * @return true iff register r is a constant table index
 */
static inline bool
jit_reg_is_const_idx(JitReg r)
{
    return (jit_reg_is_value(r) && !jit_reg_is_const_val(r)
            && (r & _JIT_REG_CONST_IDX_FLAG));
}

/**
 * Check whether the given register is a constant.
 *
 * @param r a JIT IR register
 *
 * @return true iff register r is a constant
 */
static inline bool
jit_reg_is_const(JitReg r)
{
    return (jit_reg_is_value(r)
            && (r & (_JIT_REG_CONST_VAL_FLAG | _JIT_REG_CONST_IDX_FLAG)));
}

/**
 * Check whether the given register is a normal variable register.
 *
 * @param r a JIT IR register
 *
 * @return true iff the register is a normal variable register
 */
static inline bool
jit_reg_is_variable(JitReg r)
{
    return (jit_reg_is_value(r)
            && !(r & (_JIT_REG_CONST_VAL_FLAG | _JIT_REG_CONST_IDX_FLAG)));
}

/**
 * Test whether the register is the given kind.
 *
 * @param KIND register kind name
 * @param R register
 *
 * @return true if the register is the given kind
 */
#define jit_reg_is_kind(KIND, R) (jit_reg_kind(R) == JIT_REG_KIND_##KIND)

/**
 * Construct a zero IR register with given the kind.
 *
 * @param kind the kind of the value
 *
 * @return a constant register of zero
 */
static inline JitReg
jit_reg_new_zero(unsigned kind)
{
    bh_assert(kind != JIT_REG_KIND_VOID && kind < JIT_REG_KIND_L32);
    return jit_reg_new(kind, _JIT_REG_CONST_VAL_FLAG);
}

/**
 * Test whether the register is a zero constant value.
 *
 * @param reg an IR register
 *
 * @return true iff the register is a constant zero
 */
static inline JitReg
jit_reg_is_zero(JitReg reg)
{
    return (jit_reg_is_value(reg)
            && jit_reg_no(reg) == _JIT_REG_CONST_VAL_FLAG);
}

/**
 * Operand of instructions with fixed-number register operand(s).
 */
typedef JitReg JitOpndReg;

/**
 * Operand of instructions with variable-number register operand(s).
 */
typedef struct JitOpndVReg {
    uint32 _reg_num;
    JitReg _reg[1];
} JitOpndVReg;

/**
 * Operand of lookupswitch instruction.
 */
typedef struct JitOpndLookupSwitch {
    /* NOTE: distance between JitReg operands must be the same (see
       jit_insn_opnd_regs). */
    JitReg value;           /* the value to be compared */
    uint32 match_pairs_num; /* match pairs number */
    /* NOTE: offset between adjacent targets must be sizeof
       (match_pairs[0]) (see implementation of jit_basic_block_succs),
       so the default_target field must be here. */
    JitReg default_target; /* default target BB */
    struct {
        int32 value;   /* match value of the match pair */
        JitReg target; /* target BB of the match pair */
    } match_pairs[1];  /* match pairs of the instruction */
} JitOpndLookupSwitch;

/**
 * Instruction of JIT IR.
 */
typedef struct JitInsn {
    /* Pointers to the previous and next instructions. */
    struct JitInsn *prev;
    struct JitInsn *next;

    /* Opcode of the instruction. */
    uint16 opcode;

    /* Reserved field that may be used by optimizations locally.
     * bit_0(Least Significant Bit) is atomic flag for load/store */
    uint8 flags_u8;

    /* The unique ID of the instruction. */
    uint16 uid;

    /* Operands for different kinds of instructions. */
    union {
        /* For instructions with fixed-number register operand(s). */
        JitOpndReg _opnd_Reg[1];

        /* For instructions with variable-number register operand(s). */
        JitOpndVReg _opnd_VReg;

        /* For lookupswitch instruction. */
        JitOpndLookupSwitch _opnd_LookupSwitch;
    } _opnd;
} JitInsn;

/**
 * Opcodes of IR instructions.
 */
typedef enum JitOpcode {
#define INSN(NAME, OPND_KIND, OPND_NUM, FIRST_USE) JIT_OP_##NAME,
#include "jit_ir.def"
#undef INSN
    JIT_OP_OPCODE_NUMBER
} JitOpcode;

/*
 * Helper functions for creating new instructions.  Don't call them
 * directly.  Use jit_insn_new_NAME, such as jit_insn_new_MOV instead.
 */

JitInsn *
_jit_insn_new_Reg_0(JitOpcode opc);
JitInsn *
_jit_insn_new_Reg_1(JitOpcode opc, JitReg r0);
JitInsn *
_jit_insn_new_Reg_2(JitOpcode opc, JitReg r0, JitReg r1);
JitInsn *
_jit_insn_new_Reg_3(JitOpcode opc, JitReg r0, JitReg r1, JitReg r2);
JitInsn *
_jit_insn_new_Reg_4(JitOpcode opc, JitReg r0, JitReg r1, JitReg r2, JitReg r3);
JitInsn *
_jit_insn_new_Reg_5(JitOpcode opc, JitReg r0, JitReg r1, JitReg r2, JitReg r3,
                    JitReg r4);
JitInsn *
_jit_insn_new_VReg_1(JitOpcode opc, JitReg r0, int n);
JitInsn *
_jit_insn_new_VReg_2(JitOpcode opc, JitReg r0, JitReg r1, int n);
JitInsn *
_jit_insn_new_LookupSwitch_1(JitOpcode opc, JitReg value, uint32 num);

/*
 * Instruction creation functions jit_insn_new_NAME, where NAME is the
 * name of the instruction defined in jit_ir.def.
 */
#define ARG_DECL_Reg_0
#define ARG_LIST_Reg_0
#define ARG_DECL_Reg_1 JitReg r0
#define ARG_LIST_Reg_1 , r0
#define ARG_DECL_Reg_2 JitReg r0, JitReg r1
#define ARG_LIST_Reg_2 , r0, r1
#define ARG_DECL_Reg_3 JitReg r0, JitReg r1, JitReg r2
#define ARG_LIST_Reg_3 , r0, r1, r2
#define ARG_DECL_Reg_4 JitReg r0, JitReg r1, JitReg r2, JitReg r3
#define ARG_LIST_Reg_4 , r0, r1, r2, r3
#define ARG_DECL_Reg_5 JitReg r0, JitReg r1, JitReg r2, JitReg r3, JitReg r4
#define ARG_LIST_Reg_5 , r0, r1, r2, r3, r4
#define ARG_DECL_VReg_1 JitReg r0, int n
#define ARG_LIST_VReg_1 , r0, n
#define ARG_DECL_VReg_2 JitReg r0, JitReg r1, int n
#define ARG_LIST_VReg_2 , r0, r1, n
#define ARG_DECL_LookupSwitch_1 JitReg value, uint32 num
#define ARG_LIST_LookupSwitch_1 , value, num
#define INSN(NAME, OPND_KIND, OPND_NUM, FIRST_USE)            \
    static inline JitInsn *jit_insn_new_##NAME(               \
        ARG_DECL_##OPND_KIND##_##OPND_NUM)                    \
    {                                                         \
        return _jit_insn_new_##OPND_KIND##_##OPND_NUM(        \
            JIT_OP_##NAME ARG_LIST_##OPND_KIND##_##OPND_NUM); \
    }
#include "jit_ir.def"
#undef INSN
#undef ARG_DECL_Reg_0
#undef ARG_LIST_Reg_0
#undef ARG_DECL_Reg_1
#undef ARG_LIST_Reg_1
#undef ARG_DECL_Reg_2
#undef ARG_LIST_Reg_2
#undef ARG_DECL_Reg_3
#undef ARG_LIST_Reg_3
#undef ARG_DECL_Reg_4
#undef ARG_LIST_Reg_4
#undef ARG_DECL_Reg_5
#undef ARG_LIST_Reg_5
#undef ARG_DECL_VReg_1
#undef ARG_LIST_VReg_1
#undef ARG_DECL_VReg_2
#undef ARG_LIST_VReg_2
#undef ARG_DECL_LookupSwitch_1
#undef ARG_LIST_LookupSwitch_1

/**
 * Delete an instruction
 *
 * @param insn an instruction to be deleted
 */
static inline void
jit_insn_delete(JitInsn *insn)
{
    jit_free(insn);
}

/*
 * Runtime type check functions that check whether accessing the n-th
 * operand is legal. They are only used for in self-verification
 * mode.
 *
 * @param insn any JIT IR instruction
 * @param n index of the operand to access
 *
 * @return true if the access is legal
 */
bool
_jit_insn_check_opnd_access_Reg(const JitInsn *insn, unsigned n);
bool
_jit_insn_check_opnd_access_VReg(const JitInsn *insn, unsigned n);
bool
_jit_insn_check_opnd_access_LookupSwitch(const JitInsn *insn);

/**
 * Get the pointer to the n-th register operand of the given
 * instruction. The instruction format must be Reg.
 *
 * @param insn a Reg format instruction
 * @param n index of the operand to get
 *
 * @return pointer to the n-th operand
 */
static inline JitReg *
jit_insn_opnd(JitInsn *insn, int n)
{
    bh_assert(_jit_insn_check_opnd_access_Reg(insn, n));
    return &insn->_opnd._opnd_Reg[n];
}

/**
 * Get the pointer to the n-th register operand of the given
 * instruction. The instruction format must be VReg.
 *
 * @param insn a VReg format instruction
 * @param n index of the operand to get
 *
 * @return pointer to the n-th operand
 */
static inline JitReg *
jit_insn_opndv(JitInsn *insn, int n)
{
    bh_assert(_jit_insn_check_opnd_access_VReg(insn, n));
    return &insn->_opnd._opnd_VReg._reg[n];
}

/**
 * Get the operand number of the given instruction. The instruction
 * format must be VReg.
 *
 * @param insn a VReg format instruction
 *
 * @return operand number of the instruction
 */
static inline unsigned
jit_insn_opndv_num(const JitInsn *insn)
{
    bh_assert(_jit_insn_check_opnd_access_VReg(insn, 0));
    return insn->_opnd._opnd_VReg._reg_num;
}

/**
 * Get the pointer to the LookupSwitch operand of the given
 * instruction. The instruction format must be LookupSwitch.
 *
 * @param insn a LookupSwitch format instruction
 *
 * @return pointer to the operand
 */
static inline JitOpndLookupSwitch *
jit_insn_opndls(JitInsn *insn)
{
    bh_assert(_jit_insn_check_opnd_access_LookupSwitch(insn));
    return &insn->_opnd._opnd_LookupSwitch;
}

/**
 * Insert instruction @p insn2 before instruction @p insn1.
 *
 * @param insn1 any instruction
 * @param insn2 any instruction
 */
void
jit_insn_insert_before(JitInsn *insn1, JitInsn *insn2);

/**
 * Insert instruction @p insn2 after instruction @p insn1.
 *
 * @param insn1 any instruction
 * @param insn2 any instruction
 */
void
jit_insn_insert_after(JitInsn *insn1, JitInsn *insn2);

/**
 * Unlink the instruction @p insn from the containing list.
 *
 * @param insn an instruction
 */
void
jit_insn_unlink(JitInsn *insn);

/**
 * Get the hash value of the comparable instruction (pure functions
 * and exception check instructions).
 *
 * @param insn an instruction
 *
 * @return hash value of the instruction
 */
unsigned
jit_insn_hash(JitInsn *insn);

/**
 * Compare whether the two comparable instructions are the same.
 *
 * @param insn1 the first instruction
 * @param insn2 the second instruction
 *
 * @return true if the two instructions are the same
 */
bool
jit_insn_equal(JitInsn *insn1, JitInsn *insn2);

/**
 * Register vector for accessing predecessors and successors of a
 * basic block.
 */
typedef struct JitRegVec {
    JitReg *_base; /* points to the first register */
    int32 _stride; /* stride to the next register */
    uint32 num;    /* number of registers */
} JitRegVec;

/**
 * Get the address of the i-th register in the register vector.
 *
 * @param vec a register vector
 * @param i index to the register vector
 *
 * @return the address of the i-th register in the vector
 */
static inline JitReg *
jit_reg_vec_at(const JitRegVec *vec, unsigned i)
{
    bh_assert(i < vec->num);
    return vec->_base + vec->_stride * i;
}

/**
 * Visit each element in a register vector.
 *
 * @param V (JitRegVec) the register vector
 * @param I (unsigned) index variable in the vector
 * @param R (JitReg *) resiger pointer variable
 */
#define JIT_REG_VEC_FOREACH(V, I, R) \
    for ((I) = 0, (R) = (V)._base; (I) < (V).num; (I)++, (R) += (V)._stride)

/**
 * Visit each register defined by an instruction.
 *
 * @param V (JitRegVec) register vector of the instruction
 * @param I (unsigned) index variable in the vector
 * @param R (JitReg *) resiger pointer variable
 * @param F index of the first used register
 */
#define JIT_REG_VEC_FOREACH_DEF(V, I, R, F) \
    for ((I) = 0, (R) = (V)._base; (I) < (F); (I)++, (R) += (V)._stride)

/**
 * Visit each register used by an instruction.
 *
 * @param V (JitRegVec) register vector of the instruction
 * @param I (unsigned) index variable in the vector
 * @param R (JitReg *) resiger pointer variable
 * @param F index of the first used register
 */
#define JIT_REG_VEC_FOREACH_USE(V, I, R, F)                             \
    for ((I) = (F), (R) = (V)._base + (F) * (V)._stride; (I) < (V).num; \
         (I)++, (R) += (V)._stride)

/**
 * Get a generic register vector that contains all register operands.
 * The registers defined by the instruction, if any, appear before the
 * registers used by the instruction.
 *
 * @param insn an instruction
 *
 * @return a register vector containing register operands
 */
JitRegVec
jit_insn_opnd_regs(JitInsn *insn);

/**
 * Get the index of the first use register in the register vector
 * returned by jit_insn_opnd_regs.
 *
 * @param insn an instruction
 *
 * @return the index of the first use register in the register vector
 */
unsigned
jit_insn_opnd_first_use(JitInsn *insn);

/**
 * Basic Block of JIT IR. It is a basic block only if the IR is not in
 * non-BB form. The block is represented by a special phi node, whose
 * result and arguments are label registers. The result label is the
 * containing block's label. The arguments are labels of predecessors
 * of the block. Successor labels are stored in the last instruction,
 * which must be a control flow instruction. Instructions of a block
 * are linked in a circular linked list with the block phi node as the
 * end of the list. The next and prev field of the block phi node
 * point to the first and last instructions of the block.
 */
typedef JitInsn JitBasicBlock;

/**
 * Create a new basic block instance.
 *
 * @param label the label of the new basic block
 * @param n number of predecessors
 *
 * @return the created new basic block instance
 */
JitBasicBlock *
jit_basic_block_new(JitReg label, int n);

/**
 * Delete a basic block instance and all instructions init.
 *
 * @param block the basic block to be deleted
 */
void
jit_basic_block_delete(JitBasicBlock *block);

/**
 * Get the label of the basic block.
 *
 * @param block a basic block instance
 *
 * @return the label of the basic block
 */
static inline JitReg
jit_basic_block_label(JitBasicBlock *block)
{
    return *(jit_insn_opndv(block, 0));
}

/**
 * Get the first instruction of the basic block.
 *
 * @param block a basic block instance
 *
 * @return the first instruction of the basic block
 */
static inline JitInsn *
jit_basic_block_first_insn(JitBasicBlock *block)
{
    return block->next;
}

/**
 * Get the last instruction of the basic block.
 *
 * @param block a basic block instance
 *
 * @return the last instruction of the basic block
 */
static inline JitInsn *
jit_basic_block_last_insn(JitBasicBlock *block)
{
    return block->prev;
}

/**
 * Get the end of instruction list of the basic block (which is always
 * the block itself).
 *
 * @param block a basic block instance
 *
 * @return the end of instruction list of the basic block
 */
static inline JitInsn *
jit_basic_block_end_insn(JitBasicBlock *block)
{
    return block;
}

/**
 * Visit each instruction in the block from the first to the last. In
 * the code block, the instruction pointer @p I must be a valid
 * pointer to an instruction in the block. That means if the
 * instruction may be deleted, @p I must point to the previous or next
 * valid instruction before the next iteration.
 *
 * @param B (JitBasicBlock *) the block
 * @param I (JitInsn *) instruction visited
 */
#define JIT_FOREACH_INSN(B, I)                                                \
    for (I = jit_basic_block_first_insn(B); I != jit_basic_block_end_insn(B); \
         I = I->next)

/**
 * Visit each instruction in the block from the last to the first. In
 * the code block, the instruction pointer @p I must be a valid
 * pointer to an instruction in the block. That means if the
 * instruction may be deleted, @p I must point to the previous or next
 * valid instruction before the next iteration.
 *
 * @param B (JitBasicBlock *) the block
 * @param I (JitInsn *) instruction visited
 */
#define JIT_FOREACH_INSN_REVERSE(B, I)                                       \
    for (I = jit_basic_block_last_insn(B); I != jit_basic_block_end_insn(B); \
         I = I->prev)

/**
 * Prepend an instruction in the front of the block. The position is
 * just after the block phi node (the block instance itself).
 *
 * @param block a block
 * @param insn an instruction to be prepended
 */
static inline void
jit_basic_block_prepend_insn(JitBasicBlock *block, JitInsn *insn)
{
    jit_insn_insert_after(block, insn);
}

/**
 * Append an instruction to the end of the basic block.
 *
 * @param block a basic block
 * @param insn an instruction to be appended
 */
static inline void
jit_basic_block_append_insn(JitBasicBlock *block, JitInsn *insn)
{
    jit_insn_insert_before(block, insn);
}

/**
 * Get the register vector of predecessors of a basic block.
 *
 * @param block a JIT IR block
 *
 * @return register vector of the predecessors
 */
JitRegVec
jit_basic_block_preds(JitBasicBlock *block);

/**
 * Get the register vector of successors of a basic block.
 *
 * @param block a JIT IR basic block
 *
 * @return register vector of the successors
 */
JitRegVec
jit_basic_block_succs(JitBasicBlock *block);

/**
 * Hard register information of one kind.
 */
typedef struct JitHardRegInfo {
    struct {
        /* Hard register number of this kind. */
        uint32 num;

        /* Whether each register is fixed. */
        const uint8 *fixed;

        /* Whether each register is caller-saved in the native ABI. */
        const uint8 *caller_saved_native;

        /* Whether each register is caller-saved in the JITed ABI. */
        const uint8 *caller_saved_jitted;
    } info[JIT_REG_KIND_L32];

    /* The indexes of hard registers of frame pointer, exec_env and cmp. */
    uint32 fp_hreg_index;
    uint32 exec_env_hreg_index;
    uint32 cmp_hreg_index;
} JitHardRegInfo;

struct JitBlock;
struct JitCompContext;
struct JitValueSlot;

/**
 * Value in the WASM operation stack, each stack element
 * is a Jit register
 */
typedef struct JitValue {
    struct JitValue *next;
    struct JitValue *prev;
    struct JitValueSlot *value;
    /* VALUE_TYPE_I32/I64/F32/F64/VOID */
    uint8 type;
} JitValue;

/**
 * Value stack, represents stack elements in a WASM block
 */
typedef struct JitValueStack {
    JitValue *value_list_head;
    JitValue *value_list_end;
} JitValueStack;

/* Record information of a value slot of local variable or stack
   during translation.  */
typedef struct JitValueSlot {
    /* The virtual register that holds the value of the slot if the
       value of the slot is in register.  */
    JitReg reg;

    /* The dirty bit of the value slot. It's set if the value in
       register is newer than the value in memory.  */
    uint32 dirty : 1;

    /* Whether the new value in register is a reference, which is valid
       only when the dirty bit is set.  */
    uint32 ref : 1;

    /* Committed reference flag.  0: unknown, 1: not-reference, 2:
       reference.  */
    uint32 committed_ref : 2;
} JitValueSlot;

typedef struct JitMemRegs {
    /* The following registers should be re-loaded after
       memory.grow, callbc and callnative */
    JitReg memory_inst;
    JitReg cur_page_count;
    JitReg memory_data;
    JitReg memory_data_end;
    JitReg mem_bound_check_1byte;
    JitReg mem_bound_check_2bytes;
    JitReg mem_bound_check_4bytes;
    JitReg mem_bound_check_8bytes;
    JitReg mem_bound_check_16bytes;
} JitMemRegs;

typedef struct JitTableRegs {
    JitReg table_elems;
    /* Should be re-loaded after table.grow,
       callbc and callnative */
    JitReg table_cur_size;
} JitTableRegs;

/* Frame information for translation */
typedef struct JitFrame {
    /* The current wasm module */
    WASMModule *cur_wasm_module;
    /* The current wasm function */
    WASMFunction *cur_wasm_func;
    /* The current wasm function index */
    uint32 cur_wasm_func_idx;
    /* The current compilation context */
    struct JitCompContext *cc;

    /* Max local slot number.  */
    uint32 max_locals;

    /* Max operand stack slot number.  */
    uint32 max_stacks;

    /* Instruction pointer */
    uint8 *ip;

    /* Stack top pointer */
    JitValueSlot *sp;

    /* Committed instruction pointer */
    uint8 *committed_ip;

    /* Committed stack top pointer */
    JitValueSlot *committed_sp;

    /* WASM module instance */
    JitReg module_inst_reg;
    /* WASM module */
    JitReg module_reg;
    /* module_inst->import_func_ptrs */
    JitReg import_func_ptrs_reg;
    /* module_inst->fast_jit_func_ptrs */
    JitReg fast_jit_func_ptrs_reg;
    /* module_inst->func_type_indexes */
    JitReg func_type_indexes_reg;
    /* Boundary of auxiliary stack */
    JitReg aux_stack_bound_reg;
    /* Bottom of auxiliary stack */
    JitReg aux_stack_bottom_reg;
    /* Data of memory instances */
    JitMemRegs *memory_regs;
    /* Data of table instances */
    JitTableRegs *table_regs;

    /* Local variables */
    JitValueSlot lp[1];
} JitFrame;

typedef struct JitIncomingInsn {
    struct JitIncomingInsn *next;
    JitInsn *insn;
    uint32 opnd_idx;
} JitIncomingInsn, *JitIncomingInsnList;

typedef struct JitBlock {
    struct JitBlock *next;
    struct JitBlock *prev;

    /* The current Jit Block */
    struct JitCompContext *cc;

    /* LABEL_TYPE_BLOCK/LOOP/IF/FUNCTION */
    uint32 label_type;

    /* code of else opcode of this block, if it is a IF block  */
    uint8 *wasm_code_else;
    /* code of end opcode of this block */
    uint8 *wasm_code_end;

    /* JIT label points to code begin */
    JitBasicBlock *basic_block_entry;
    /* JIT label points to code else */
    JitBasicBlock *basic_block_else;
    /* JIT label points to code end */
    JitBasicBlock *basic_block_end;

    /* Incoming INSN for basic_block_else */
    JitInsn *incoming_insn_for_else_bb;
    /* Incoming INSNs for basic_block_end */
    JitIncomingInsnList incoming_insns_for_end_bb;

    /* WASM operation stack */
    JitValueStack value_stack;

    /* Param count/types/PHIs of this block */
    uint32 param_count;
    uint8 *param_types;

    /* Result count/types/PHIs of this block */
    uint32 result_count;
    uint8 *result_types;

    /* The begin frame stack pointer of this block */
    JitValueSlot *frame_sp_begin;
} JitBlock;

/**
 * Block stack, represents WASM block stack elements
 */
typedef struct JitBlockStack {
    JitBlock *block_list_head;
    JitBlock *block_list_end;
} JitBlockStack;

/**
 * The JIT compilation context for one compilation process of a
 * compilation unit.
 */
typedef struct JitCompContext {
    /* Hard register information of each kind. */
    const JitHardRegInfo *hreg_info;

    /* No. of the pass to be applied. */
    uint8 cur_pass_no;

    /* The current wasm module */
    WASMModule *cur_wasm_module;
    /* The current wasm function */
    WASMFunction *cur_wasm_func;
    /* The current wasm function index */
    uint32 cur_wasm_func_idx;
    /* The block stack */
    JitBlockStack block_stack;

    bool mem_space_unchanged;

    /* Entry and exit labels of the compilation unit, whose numbers must
       be 0 and 1 respectively (see JIT_FOREACH_BLOCK). */
    JitReg entry_label;
    JitReg exit_label;
    JitBasicBlock **exce_basic_blocks;
    JitIncomingInsnList *incoming_insns_for_exec_bbs;

    /* The current basic block to generate instructions */
    JitBasicBlock *cur_basic_block;

    /* Registers of frame pointer, exec_env and CMP result. */
    JitReg fp_reg;
    JitReg exec_env_reg;
    JitReg cmp_reg;

    /* WASM module instance */
    JitReg module_inst_reg;
    /* WASM module */
    JitReg module_reg;
    /* module_inst->import_func_ptrs */
    JitReg import_func_ptrs_reg;
    /* module_inst->fast_jit_func_ptrs */
    JitReg fast_jit_func_ptrs_reg;
    /* module_inst->func_type_indexes */
    JitReg func_type_indexes_reg;
    /* Boundary of auxiliary stack */
    JitReg aux_stack_bound_reg;
    /* Bottom of auxiliary stack */
    JitReg aux_stack_bottom_reg;
    /* Data of memory instances */
    JitMemRegs *memory_regs;
    /* Data of table instances */
    JitTableRegs *table_regs;

    /* Current frame information for translation */
    JitFrame *jit_frame;

    /* The total frame size of current function */
    uint32 total_frame_size;

    /* The spill cache offset to the interp frame */
    uint32 spill_cache_offset;
    /* The spill cache size */
    uint32 spill_cache_size;

    /* The offset of jitted_return_address in the frame, which is set by
       the pass frontend and used by the pass codegen. */
    uint32 jitted_return_address_offset;

    /* Begin and end addresses of the jitted code produced by the pass
       codegen and consumed by the region registration after codegen and
       the pass dump. */
    void *jitted_addr_begin;
    void *jitted_addr_end;

    char last_error[128];

    /* Below fields are all private.  Don't access them directly. */

    /* Reference count of the compilation context. */
    uint16 _reference_count;

    /* Constant values. */
    struct {
        /* Number of constant values of each kind. */
        uint32 _num[JIT_REG_KIND_L32];

        /* Capacity of register annotations of each kind. */
        uint32 _capacity[JIT_REG_KIND_L32];

        /* Constant values of each kind. */
        uint8 *_value[JIT_REG_KIND_L32];

        /* Next element on the list of values with the same hash code. */
        JitReg *_next[JIT_REG_KIND_L32];

        /* Size of the hash table. */
        uint32 _hash_table_size;

        /* Map values to JIT register. */
        JitReg *_hash_table;
    } _const_val;

    /* Annotations of labels, registers and instructions. */
    struct {
        /* Number of all ever created labels. */
        uint32 _label_num;

        /* Capacity of label annotations. */
        uint32 _label_capacity;

        /* Number of all ever created instructions. */
        uint32 _insn_num;

        /* Capacity of instruction annotations. */
        uint32 _insn_capacity;

        /* Number of ever created registers of each kind. */
        uint32 _reg_num[JIT_REG_KIND_L32];

        /* Capacity of register annotations of each kind. */
        uint32 _reg_capacity[JIT_REG_KIND_L32];

        /* Storage of annotations. */
#define ANN_LABEL(TYPE, NAME) TYPE *_label_##NAME;
#define ANN_INSN(TYPE, NAME) TYPE *_insn_##NAME;
#define ANN_REG(TYPE, NAME) TYPE *_reg_##NAME[JIT_REG_KIND_L32];
#include "jit_ir.def"
#undef ANN_LABEL
#undef ANN_INSN
#undef ANN_REG

        /* Flags of annotations. */
#define ANN_LABEL(TYPE, NAME) uint32 _label_##NAME##_enabled : 1;
#define ANN_INSN(TYPE, NAME) uint32 _insn_##NAME##_enabled : 1;
#define ANN_REG(TYPE, NAME) uint32 _reg_##NAME##_enabled : 1;
#include "jit_ir.def"
#undef ANN_LABEL
#undef ANN_INSN
#undef ANN_REG
    } _ann;

    /* Instruction hash table. */
    struct {
        /* Size of the hash table. */
        uint32 _size;

        /* The hash table. */
        JitInsn **_table;
    } _insn_hash_table;

    /* indicate if the last comparison is about floating-point numbers or not
     */
    bool last_cmp_on_fp;
} JitCompContext;

/*
 * Annotation accessing functions jit_annl_NAME, jit_anni_NAME and
 * jit_annr_NAME.
 */
#define ANN_LABEL(TYPE, NAME)                                             \
    static inline TYPE *jit_annl_##NAME(JitCompContext *cc, JitReg label) \
    {                                                                     \
        unsigned idx = jit_reg_no(label);                                 \
        bh_assert(jit_reg_kind(label) == JIT_REG_KIND_L32);               \
        bh_assert(idx < cc->_ann._label_num);                             \
        bh_assert(cc->_ann._label_##NAME##_enabled);                      \
        return &cc->_ann._label_##NAME[idx];                              \
    }
#define ANN_INSN(TYPE, NAME)                                               \
    static inline TYPE *jit_anni_##NAME(JitCompContext *cc, JitInsn *insn) \
    {                                                                      \
        unsigned uid = insn->uid;                                          \
        bh_assert(uid < cc->_ann._insn_num);                               \
        bh_assert(cc->_ann._insn_##NAME##_enabled);                        \
        return &cc->_ann._insn_##NAME[uid];                                \
    }
#define ANN_REG(TYPE, NAME)                                             \
    static inline TYPE *jit_annr_##NAME(JitCompContext *cc, JitReg reg) \
    {                                                                   \
        unsigned kind = jit_reg_kind(reg);                              \
        unsigned no = jit_reg_no(reg);                                  \
        bh_assert(kind < JIT_REG_KIND_L32);                             \
        bh_assert(no < cc->_ann._reg_num[kind]);                        \
        bh_assert(cc->_ann._reg_##NAME##_enabled);                      \
        return &cc->_ann._reg_##NAME[kind][no];                         \
    }
#include "jit_ir.def"
#undef ANN_LABEL
#undef ANN_INSN
#undef ANN_REG

/*
 * Annotation enabling functions jit_annl_enable_NAME,
 * jit_anni_enable_NAME and jit_annr_enable_NAME, which allocate
 * sufficient memory for the annotations.
 */
#define ANN_LABEL(TYPE, NAME) bool jit_annl_enable_##NAME(JitCompContext *cc);
#define ANN_INSN(TYPE, NAME) bool jit_anni_enable_##NAME(JitCompContext *cc);
#define ANN_REG(TYPE, NAME) bool jit_annr_enable_##NAME(JitCompContext *cc);
#include "jit_ir.def"
#undef ANN_LABEL
#undef ANN_INSN
#undef ANN_REG

/*
 * Annotation disabling functions jit_annl_disable_NAME,
 * jit_anni_disable_NAME and jit_annr_disable_NAME, which release
 * memory of the annotations.  Before calling these functions,
 * resources owned by the annotations must be explicitly released.
 */
#define ANN_LABEL(TYPE, NAME) void jit_annl_disable_##NAME(JitCompContext *cc);
#define ANN_INSN(TYPE, NAME) void jit_anni_disable_##NAME(JitCompContext *cc);
#define ANN_REG(TYPE, NAME) void jit_annr_disable_##NAME(JitCompContext *cc);
#include "jit_ir.def"
#undef ANN_LABEL
#undef ANN_INSN
#undef ANN_REG

/*
 * Functions jit_annl_is_enabled_NAME, jit_anni_is_enabled_NAME and
 * jit_annr_is_enabled_NAME for checking whether an annotation is
 * enabled.
 */
#define ANN_LABEL(TYPE, NAME)                                         \
    static inline bool jit_annl_is_enabled_##NAME(JitCompContext *cc) \
    {                                                                 \
        return !!cc->_ann._label_##NAME##_enabled;                    \
    }
#define ANN_INSN(TYPE, NAME)                                          \
    static inline bool jit_anni_is_enabled_##NAME(JitCompContext *cc) \
    {                                                                 \
        return !!cc->_ann._insn_##NAME##_enabled;                     \
    }
#define ANN_REG(TYPE, NAME)                                           \
    static inline bool jit_annr_is_enabled_##NAME(JitCompContext *cc) \
    {                                                                 \
        return !!cc->_ann._reg_##NAME##_enabled;                      \
    }
#include "jit_ir.def"
#undef ANN_LABEL
#undef ANN_INSN
#undef ANN_REG

/**
 * Initialize a compilation context.
 *
 * @param cc the compilation context
 * @param htab_size the initial hash table size of constant pool
 *
 * @return cc if succeeds, NULL otherwise
 */
JitCompContext *
jit_cc_init(JitCompContext *cc, unsigned htab_size);

/**
 * Release all resources of a compilation context, which doesn't
 * include the compilation context itself.
 *
 * @param cc the compilation context
 */
void
jit_cc_destroy(JitCompContext *cc);

/**
 * Increase the reference count of the compilation context.
 *
 * @param cc the compilation context
 */
static inline void
jit_cc_inc_ref(JitCompContext *cc)
{
    cc->_reference_count++;
}

/**
 * Decrease the reference_count and destroy and free the compilation
 * context if the reference_count is decreased to zero.
 *
 * @param cc the compilation context
 */
void
jit_cc_delete(JitCompContext *cc);

char *
jit_get_last_error(JitCompContext *cc);

void
jit_set_last_error(JitCompContext *cc, const char *error);

void
jit_set_last_error_v(JitCompContext *cc, const char *format, ...);

/**
 * Create a I32 constant value with relocatable into the compilation
 * context. A constant value that has relocation info cannot be
 * constant-folded as normal constants because its value depends on
 * runtime context and may be different in different executions.
 *
 * @param cc compilation context
 * @param val a I32 value
 * @param rel relocation information
 *
 * @return a constant register containing the value
 */
JitReg
jit_cc_new_const_I32_rel(JitCompContext *cc, int32 val, uint32 rel);

/**
 * Create a I32 constant value without relocation info (0) into the
 * compilation context.
 *
 * @param cc compilation context
 * @param val a I32 value
 *
 * @return a constant register containing the value
 */
static inline JitReg
jit_cc_new_const_I32(JitCompContext *cc, int32 val)
{
    return jit_cc_new_const_I32_rel(cc, val, 0);
}

/**
 * Create a I64 constant value into the compilation context.
 *
 * @param cc compilation context
 * @param val a I64 value
 *
 * @return a constant register containing the value
 */
JitReg
jit_cc_new_const_I64(JitCompContext *cc, int64 val);

#if UINTPTR_MAX == UINT64_MAX
#define jit_cc_new_const_PTR jit_cc_new_const_I64
#else
#define jit_cc_new_const_PTR jit_cc_new_const_I32
#endif

/**
 * Create a F32 constant value into the compilation context.
 *
 * @param cc compilation context
 * @param val a F32 value
 *
 * @return a constant register containing the value
 */
JitReg
jit_cc_new_const_F32(JitCompContext *cc, float val);

/**
 * Create a F64 constant value into the compilation context.
 *
 * @param cc compilation context
 * @param val a F64 value
 *
 * @return a constant register containing the value
 */
JitReg
jit_cc_new_const_F64(JitCompContext *cc, double val);

/**
 * Get the relocation info of a I32 constant register.
 *
 * @param cc compilation context
 * @param reg constant register
 *
 * @return the relocation info of the constant
 */
uint32
jit_cc_get_const_I32_rel(JitCompContext *cc, JitReg reg);

/**
 * Get the constant value of a I32 constant register.
 *
 * @param cc compilation context
 * @param reg constant register
 *
 * @return the constant value
 */
int32
jit_cc_get_const_I32(JitCompContext *cc, JitReg reg);

/**
 * Get the constant value of a I64 constant register.
 *
 * @param cc compilation context
 * @param reg constant register
 *
 * @return the constant value
 */
int64
jit_cc_get_const_I64(JitCompContext *cc, JitReg reg);

/**
 * Get the constant value of a F32 constant register.
 *
 * @param cc compilation context
 * @param reg constant register
 *
 * @return the constant value
 */
float
jit_cc_get_const_F32(JitCompContext *cc, JitReg reg);

/**
 * Get the constant value of a F64 constant register.
 *
 * @param cc compilation context
 * @param reg constant register
 *
 * @return the constant value
 */
double
jit_cc_get_const_F64(JitCompContext *cc, JitReg reg);

/**
 * Get the number of total created labels.
 *
 * @param cc the compilation context
 *
 * @return the number of total created labels
 */
static inline unsigned
jit_cc_label_num(JitCompContext *cc)
{
    return cc->_ann._label_num;
}

/**
 * Get the number of total created instructions.
 *
 * @param cc the compilation context
 *
 * @return the number of total created instructions
 */
static inline unsigned
jit_cc_insn_num(JitCompContext *cc)
{
    return cc->_ann._insn_num;
}

/**
 * Get the number of total created registers.
 *
 * @param cc the compilation context
 * @param kind the register kind
 *
 * @return the number of total created registers
 */
static inline unsigned
jit_cc_reg_num(JitCompContext *cc, unsigned kind)
{
    bh_assert(kind < JIT_REG_KIND_L32);
    return cc->_ann._reg_num[kind];
}

/**
 * Create a new label in the compilation context.
 *
 * @param cc the compilation context
 *
 * @return a new label in the compilation context
 */
JitReg
jit_cc_new_label(JitCompContext *cc);

/**
 * Create a new block with a new label in the compilation context.
 *
 * @param cc the compilation context
 * @param n number of predecessors
 *
 * @return a new block with a new label in the compilation context
 */
JitBasicBlock *
jit_cc_new_basic_block(JitCompContext *cc, int n);

/**
 * Resize the predecessor number of a block.
 *
 * @param cc the containing compilation context
 * @param block block to be resized
 * @param n new number of predecessors
 *
 * @return the new block if succeeds, NULL otherwise
 */
JitBasicBlock *
jit_cc_resize_basic_block(JitCompContext *cc, JitBasicBlock *block, int n);

/**
 * Initialize the instruction hash table to the given size and enable
 * the instruction's _hash_link annotation.
 *
 * @param cc the containing compilation context
 * @param n size of the hash table
 *
 * @return true if succeeds, false otherwise
 */
bool
jit_cc_enable_insn_hash(JitCompContext *cc, unsigned n);

/**
 * Destroy the instruction hash table and disable the instruction's
 * _hash_link annotation.
 *
 * @param cc the containing compilation context
 */
void
jit_cc_disable_insn_hash(JitCompContext *cc);

/**
 * Reset the hash table entries.
 *
 * @param cc the containing compilation context
 */
void
jit_cc_reset_insn_hash(JitCompContext *cc);

/**
 * Allocate a new instruction ID in the compilation context and set it
 * to the given instruction.
 *
 * @param cc the compilation context
 * @param insn IR instruction
 *
 * @return the insn with uid being set
 */
JitInsn *
jit_cc_set_insn_uid(JitCompContext *cc, JitInsn *insn);

/*
 * Similar to jit_cc_set_insn_uid except that if setting uid failed,
 * delete the insn.  Only used by jit_cc_new_insn
 */
JitInsn *
_jit_cc_set_insn_uid_for_new_insn(JitCompContext *cc, JitInsn *insn);

/**
 * Create a new instruction in the compilation context.
 *
 * @param cc the compilationo context
 * @param NAME instruction name
 *
 * @return a new instruction in the compilation context
 */
#define jit_cc_new_insn(cc, NAME, ...) \
    _jit_cc_set_insn_uid_for_new_insn(cc, jit_insn_new_##NAME(__VA_ARGS__))

/*
 * Helper function for jit_cc_new_insn_norm.
 */
JitInsn *
_jit_cc_new_insn_norm(JitCompContext *cc, JitReg *result, JitInsn *insn);

/**
 * Create a new instruction in the compilation context and normalize
 * the instruction (constant folding and simplification etc.). If the
 * instruction hashing is enabled (anni__hash_link is enabled), try to
 * find the existing equivalent insruction first before adding a new
 * one to the compilation contest.
 *
 * @param cc the compilationo context
 * @param result returned result of the instruction. If the value is
 * non-zero, it is the result of the constant-folding or an existing
 * equivalent instruction, in which case no instruction is added into
 * the compilation context. Otherwise, a new normalized instruction
 * has been added into the compilation context.
 * @param NAME instruction name
 *
 * @return a new or existing instruction in the compilation context
 */
#define jit_cc_new_insn_norm(cc, result, NAME, ...) \
    _jit_cc_new_insn_norm(cc, result, jit_insn_new_##NAME(__VA_ARGS__))

/**
 * Helper function for GEN_INSN
 *
 * @param cc compilation context
 * @param block the current block
 * @param insn the new instruction
 *
 * @return the new instruction if inserted, NULL otherwise
 */
static inline JitInsn *
_gen_insn(JitCompContext *cc, JitInsn *insn)
{
    if (insn)
        jit_basic_block_append_insn(cc->cur_basic_block, insn);
    else
        jit_set_last_error(cc, "generate insn failed");

    return insn;
}

/**
 * Generate and append an instruction to the current block.
 */
#define GEN_INSN(...) _gen_insn(cc, jit_cc_new_insn(cc, __VA_ARGS__))

/**
 * Create a constant register without relocation info.
 *
 * @param Type type of the register
 * @param val the constant value
 *
 * @return the constant register if succeeds, 0 otherwise
 */
#define NEW_CONST(Type, val) jit_cc_new_const_##Type(cc, val)

/**
 * Create a new virtual register in the compilation context.
 *
 * @param cc the compilation context
 * @param kind kind of the register
 *
 * @return a new label in the compilation context
 */
JitReg
jit_cc_new_reg(JitCompContext *cc, unsigned kind);

/*
 * Create virtual registers with specific types in the compilation
 * context. They are more convenient than the above one.
 */

static inline JitReg
jit_cc_new_reg_I32(JitCompContext *cc)
{
    return jit_cc_new_reg(cc, JIT_REG_KIND_I32);
}

static inline JitReg
jit_cc_new_reg_I64(JitCompContext *cc)
{
    return jit_cc_new_reg(cc, JIT_REG_KIND_I64);
}

#if UINTPTR_MAX == UINT64_MAX
#define jit_cc_new_reg_ptr jit_cc_new_reg_I64
#else
#define jit_cc_new_reg_ptr jit_cc_new_reg_I32
#endif

static inline JitReg
jit_cc_new_reg_F32(JitCompContext *cc)
{
    return jit_cc_new_reg(cc, JIT_REG_KIND_F32);
}

static inline JitReg
jit_cc_new_reg_F64(JitCompContext *cc)
{
    return jit_cc_new_reg(cc, JIT_REG_KIND_F64);
}

static inline JitReg
jit_cc_new_reg_V64(JitCompContext *cc)
{
    return jit_cc_new_reg(cc, JIT_REG_KIND_V64);
}

static inline JitReg
jit_cc_new_reg_V128(JitCompContext *cc)
{
    return jit_cc_new_reg(cc, JIT_REG_KIND_V128);
}

static inline JitReg
jit_cc_new_reg_V256(JitCompContext *cc)
{
    return jit_cc_new_reg(cc, JIT_REG_KIND_V256);
}

/**
 * Get the hard register numbe of the given kind
 *
 * @param cc the compilation context
 * @param kind the register kind
 *
 * @return number of hard registers of the given kind
 */
static inline unsigned
jit_cc_hreg_num(JitCompContext *cc, unsigned kind)
{
    bh_assert(kind < JIT_REG_KIND_L32);
    return cc->hreg_info->info[kind].num;
}

/**
 * Check whether a given register is a hard register.
 *
 * @param cc the compilation context
 * @param reg the register which must be a variable
 *
 * @return true if the register is a hard register
 */
static inline bool
jit_cc_is_hreg(JitCompContext *cc, JitReg reg)
{
    unsigned kind = jit_reg_kind(reg);
    unsigned no = jit_reg_no(reg);
    bh_assert(jit_reg_is_variable(reg));
    bh_assert(kind < JIT_REG_KIND_L32);
    return no < cc->hreg_info->info[kind].num;
}

/**
 * Check whether the given hard register is fixed.
 *
 * @param cc the compilation context
 * @param reg the hard register
 *
 * @return true if the hard register is fixed
 */
static inline bool
jit_cc_is_hreg_fixed(JitCompContext *cc, JitReg reg)
{
    unsigned kind = jit_reg_kind(reg);
    unsigned no = jit_reg_no(reg);
    bh_assert(jit_cc_is_hreg(cc, reg));
    bh_assert(kind < JIT_REG_KIND_L32);
    return !!cc->hreg_info->info[kind].fixed[no];
}

/**
 * Check whether the given hard register is caller-saved-native.
 *
 * @param cc the compilation context
 * @param reg the hard register
 *
 * @return true if the hard register is caller-saved-native
 */
static inline bool
jit_cc_is_hreg_caller_saved_native(JitCompContext *cc, JitReg reg)
{
    unsigned kind = jit_reg_kind(reg);
    unsigned no = jit_reg_no(reg);
    bh_assert(jit_cc_is_hreg(cc, reg));
    bh_assert(kind < JIT_REG_KIND_L32);
    return !!cc->hreg_info->info[kind].caller_saved_native[no];
}

/**
 * Check whether the given hard register is caller-saved-jitted.
 *
 * @param cc the compilation context
 * @param reg the hard register
 *
 * @return true if the hard register is caller-saved-jitted
 */
static inline bool
jit_cc_is_hreg_caller_saved_jitted(JitCompContext *cc, JitReg reg)
{
    unsigned kind = jit_reg_kind(reg);
    unsigned no = jit_reg_no(reg);
    bh_assert(jit_cc_is_hreg(cc, reg));
    bh_assert(kind < JIT_REG_KIND_L32);
    return !!cc->hreg_info->info[kind].caller_saved_jitted[no];
}

/**
 * Return the entry block of the compilation context.
 *
 * @param cc the compilation context
 *
 * @return the entry block of the compilation context
 */
static inline JitBasicBlock *
jit_cc_entry_basic_block(JitCompContext *cc)
{
    return *(jit_annl_basic_block(cc, cc->entry_label));
}

/**
 * Return the exit block of the compilation context.
 *
 * @param cc the compilation context
 *
 * @return the exit block of the compilation context
 */
static inline JitBasicBlock *
jit_cc_exit_basic_block(JitCompContext *cc)
{
    return *(jit_annl_basic_block(cc, cc->exit_label));
}

void
jit_value_stack_push(JitValueStack *stack, JitValue *value);

JitValue *
jit_value_stack_pop(JitValueStack *stack);

void
jit_value_stack_destroy(JitValueStack *stack);

JitBlock *
jit_block_stack_top(JitBlockStack *stack);

void
jit_block_stack_push(JitBlockStack *stack, JitBlock *block);

JitBlock *
jit_block_stack_pop(JitBlockStack *stack);

void
jit_block_stack_destroy(JitBlockStack *stack);

bool
jit_block_add_incoming_insn(JitBlock *block, JitInsn *insn, uint32 opnd_idx);

void
jit_block_destroy(JitBlock *block);

bool
jit_cc_push_value(JitCompContext *cc, uint8 type, JitReg value);

bool
jit_cc_pop_value(JitCompContext *cc, uint8 type, JitReg *p_value);

bool
jit_lock_reg_in_insn(JitCompContext *cc, JitInsn *the_insn, JitReg reg_to_lock);

/**
 * Update the control flow graph after successors of blocks are
 * changed so that the predecessor vector of each block represents the
 * updated status. The predecessors may not be required by all
 * passes, so we don't need to keep them always being updated.
 *
 * @param cc the compilation context
 *
 * @return true if succeeds, false otherwise
 */
bool
jit_cc_update_cfg(JitCompContext *cc);

/**
 * Visit each normal block (which is not entry nor exit block) in a
 * compilation context. New blocks can be added in the loop body, but
 * they won't be visited. Blocks can also be removed safely (by
 * setting the label's block annotation to NULL) in the loop body.
 *
 * @param CC (JitCompContext *) the compilation context
 * @param I (unsigned) index variable of the block (label no)
 * @param E (unsigned) end index variable of block (last index + 1)
 * @param B (JitBasicBlock *) block pointer variable
 */
#define JIT_FOREACH_BLOCK(CC, I, E, B)                           \
    for ((I) = 2, (E) = (CC)->_ann._label_num; (I) < (E); (I)++) \
        if (((B) = (CC)->_ann._label_basic_block[(I)]))

/**
 * The version that includes entry and exit block.
 */
#define JIT_FOREACH_BLOCK_ENTRY_EXIT(CC, I, E, B)                \
    for ((I) = 0, (E) = (CC)->_ann._label_num; (I) < (E); (I)++) \
        if (((B) = (CC)->_ann._label_basic_block[(I)]))

/**
 * Visit each normal block (which is not entry nor exit block) in a
 * compilation context in reverse order. New blocks can be added in
 * the loop body, but they won't be visited. Blocks can also be
 * removed safely (by setting the label's block annotation to NULL) in
 * the loop body.
 *
 * @param CC (JitCompContext *) the compilation context
 * @param I (unsigned) index of the block (label no)
 * @param B (JitBasicBlock *) block pointer
 */
#define JIT_FOREACH_BLOCK_REVERSE(CC, I, B)           \
    for ((I) = (CC)->_ann._label_num; (I) > 2; (I)--) \
        if (((B) = (CC)->_ann._label_basic_block[(I)-1]))

/**
 * The version that includes entry and exit block.
 */
#define JIT_FOREACH_BLOCK_REVERSE_ENTRY_EXIT(CC, I, B) \
    for ((I) = (CC)->_ann._label_num; (I) > 0; (I)--)  \
        if (((B) = (CC)->_ann._label_basic_block[(I)-1]))

#ifdef __cplusplus
}
#endif

#endif /* end of _JIT_IR_H_ */
