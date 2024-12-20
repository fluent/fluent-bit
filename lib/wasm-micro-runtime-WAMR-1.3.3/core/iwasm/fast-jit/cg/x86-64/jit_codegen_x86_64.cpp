/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_codegen.h"
#include "jit_codecache.h"
#include "jit_compiler.h"
#include "jit_frontend.h"
#include "jit_dump.h"

#include <asmjit/core.h>
#include <asmjit/x86.h>
#if WASM_ENABLE_FAST_JIT_DUMP != 0
#include <Zydis/Zydis.h>
#endif

#define CODEGEN_CHECK_ARGS 1
#define CODEGEN_DUMP 0

using namespace asmjit;

static char *code_block_switch_to_jitted_from_interp = NULL;
static char *code_block_return_to_interp_from_jitted = NULL;
#if WASM_ENABLE_LAZY_JIT != 0
static char *code_block_compile_fast_jit_and_then_call = NULL;
#endif

typedef enum {
    REG_BPL_IDX = 0,
    REG_AXL_IDX,
    REG_BXL_IDX,
    REG_CXL_IDX,
    REG_DXL_IDX,
    REG_DIL_IDX,
    REG_SIL_IDX,
    REG_I8_FREE_IDX = REG_SIL_IDX
} RegIndexI8;

typedef enum {
    REG_BP_IDX = 0,
    REG_AX_IDX,
    REG_BX_IDX,
    REG_CX_IDX,
    REG_DX_IDX,
    REG_DI_IDX,
    REG_SI_IDX,
    REG_I16_FREE_IDX = REG_SI_IDX
} RegIndexI16;

typedef enum {
    REG_EBP_IDX = 0,
    REG_EAX_IDX,
    REG_EBX_IDX,
    REG_ECX_IDX,
    REG_EDX_IDX,
    REG_EDI_IDX,
    REG_ESI_IDX,
    REG_I32_FREE_IDX = REG_ESI_IDX
} RegIndexI32;

typedef enum {
    REG_RBP_IDX = 0,
    REG_RAX_IDX,
    REG_RBX_IDX,
    REG_RCX_IDX,
    REG_RDX_IDX,
    REG_RDI_IDX,
    REG_RSI_IDX,
    REG_RSP_IDX,
    REG_R8_IDX,
    REG_R9_IDX,
    REG_R10_IDX,
    REG_R11_IDX,
    REG_R12_IDX,
    REG_R13_IDX,
    REG_R14_IDX,
    REG_R15_IDX,
    REG_I64_FREE_IDX = REG_RSI_IDX
} RegIndexI64;

/* clang-format off */
x86::Gp regs_i8[] = {
    x86::bpl,  x86::al, x86::bl, x86::cl,
    x86::dl,   x86::dil,  x86::sil,  x86::spl,
    x86::r8b,  x86::r9b,  x86::r10b, x86::r11b,
    x86::r12b, x86::r13b, x86::r14b, x86::r15b
};

x86::Gp regs_i16[] = {
    x86::bp,   x86::ax,   x86::bx,   x86::cx,
    x86::dx,   x86::di,   x86::si,   x86::sp,
    x86::r8w,  x86::r9w,  x86::r10w, x86::r11w,
    x86::r12w, x86::r13w, x86::r14w, x86::r15w
};

x86::Gp regs_i32[] = {
    x86::ebp,  x86::eax,  x86::ebx,  x86::ecx,
    x86::edx,  x86::edi,  x86::esi,  x86::esp,
    x86::r8d,  x86::r9d,  x86::r10d, x86::r11d,
    x86::r12d, x86::r13d, x86::r14d, x86::r15d
};

x86::Gp regs_i64[] = {
    x86::rbp, x86::rax, x86::rbx, x86::rcx,
    x86::rdx, x86::rdi, x86::rsi, x86::rsp,
    x86::r8,  x86::r9,  x86::r10, x86::r11,
    x86::r12, x86::r13, x86::r14, x86::r15,
};

#define REG_F32_FREE_IDX 15
#define REG_F64_FREE_IDX 15

x86::Xmm regs_float[] = {
    x86::xmm0,
    x86::xmm1,
    x86::xmm2,
    x86::xmm3,
    x86::xmm4,
    x86::xmm5,
    x86::xmm6,
    x86::xmm7,
    x86::xmm8,
    x86::xmm9,
    x86::xmm10,
    x86::xmm11,
    x86::xmm12,
    x86::xmm13,
    x86::xmm14,
    x86::xmm15,
};
/* clang-format on */

int
jit_codegen_interp_jitted_glue(void *exec_env, JitInterpSwitchInfo *info,
                               uint32 func_idx, void *target)
{
    typedef int32 (*F)(const void *exec_env, void *info, uint32 func_idx,
                       const void *target);
    union {
        F f;
        void *v;
    } u;

    u.v = code_block_switch_to_jitted_from_interp;
    return u.f(exec_env, info, func_idx, target);
}

#define PRINT_LINE() LOG_VERBOSE("<Line:%d>\n", __LINE__)

#if CODEGEN_DUMP != 0
#define GOTO_FAIL     \
    do {              \
        PRINT_LINE(); \
        goto fail;    \
    } while (0)
#else
#define GOTO_FAIL goto fail
#endif

#if CODEGEN_CHECK_ARGS == 0

#define CHECK_EQKIND(reg0, reg1) (void)0
#define CHECK_CONST(reg0) (void)0
#define CHECK_NCONST(reg0) (void)0
#define CHECK_KIND(reg0, type) (void)0
#define CHECK_REG_NO(no, kind) (void)0
#else

/* Check if two register's kind is equal */
#define CHECK_EQKIND(reg0, reg1)                        \
    do {                                                \
        if (jit_reg_kind(reg0) != jit_reg_kind(reg1)) { \
            PRINT_LINE();                               \
            LOG_VERBOSE("reg type not equal:\n");       \
            jit_dump_reg(cc, reg0);                     \
            jit_dump_reg(cc, reg1);                     \
            GOTO_FAIL;                                  \
        }                                               \
    } while (0)

/* Check if a register is an const */
#define CHECK_CONST(reg0)                       \
    do {                                        \
        if (!jit_reg_is_const(reg0)) {          \
            PRINT_LINE();                       \
            LOG_VERBOSE("reg is not const:\n"); \
            jit_dump_reg(cc, reg0);             \
            GOTO_FAIL;                          \
        }                                       \
    } while (0)

/* Check if a register is not an const */
#define CHECK_NCONST(reg0)                  \
    do {                                    \
        if (jit_reg_is_const(reg0)) {       \
            PRINT_LINE();                   \
            LOG_VERBOSE("reg is const:\n"); \
            jit_dump_reg(cc, reg0);         \
            GOTO_FAIL;                      \
        }                                   \
    } while (0)

/* Check if a register is a special type */
#define CHECK_KIND(reg0, type)                                  \
    do {                                                        \
        if (jit_reg_kind(reg0) != type) {                       \
            PRINT_LINE();                                       \
            LOG_VERBOSE("invalid reg type %d, expected is: %d", \
                        jit_reg_kind(reg0), type);              \
            jit_dump_reg(cc, reg0);                             \
            GOTO_FAIL;                                          \
        }                                                       \
    } while (0)

#define CHECK_I32_REG_NO(no)                                      \
    do {                                                          \
        if ((uint32)no >= sizeof(regs_i32) / sizeof(regs_i32[0])) \
            GOTO_FAIL;                                            \
    } while (0)

#define CHECK_I64_REG_NO(no)                                      \
    do {                                                          \
        if ((uint32)no >= sizeof(regs_i64) / sizeof(regs_i64[0])) \
            GOTO_FAIL;                                            \
    } while (0)

#define CHECK_F32_REG_NO(no)                                          \
    do {                                                              \
        if ((uint32)no >= sizeof(regs_float) / sizeof(regs_float[0])) \
            GOTO_FAIL;                                                \
    } while (0)

#define CHECK_F64_REG_NO(no)                                          \
    do {                                                              \
        if ((uint32)no >= sizeof(regs_float) / sizeof(regs_float[0])) \
            GOTO_FAIL;                                                \
    } while (0)

/* Check if a register number is valid */
#define CHECK_REG_NO(no, kind)                                           \
    do {                                                                 \
        if (kind == JIT_REG_KIND_I32 || kind == JIT_REG_KIND_I64) {      \
            CHECK_I32_REG_NO(no);                                        \
            CHECK_I64_REG_NO(no);                                        \
        }                                                                \
        else if (kind == JIT_REG_KIND_F32 || kind == JIT_REG_KIND_F64) { \
            CHECK_F32_REG_NO(no);                                        \
            CHECK_F64_REG_NO(no);                                        \
        }                                                                \
        else                                                             \
            GOTO_FAIL;                                                   \
    } while (0)

#endif /* end of CODEGEN_CHECK_ARGS == 0 */

/* Load one operand from insn and check none */
#define LOAD_1ARG() r0 = *jit_insn_opnd(insn, 0)

/* Load two operands from insn and check if r0 is non-const */
#define LOAD_2ARGS()              \
    r0 = *jit_insn_opnd(insn, 0); \
    r1 = *jit_insn_opnd(insn, 1); \
    CHECK_NCONST(r0)

/* Load three operands from insn and check if r0 is non-const */
#define LOAD_3ARGS()              \
    r0 = *jit_insn_opnd(insn, 0); \
    r1 = *jit_insn_opnd(insn, 1); \
    r2 = *jit_insn_opnd(insn, 2); \
    CHECK_NCONST(r0)

/* Load three operands from insn and check none */
#define LOAD_3ARGS_NO_ASSIGN()    \
    r0 = *jit_insn_opnd(insn, 0); \
    r1 = *jit_insn_opnd(insn, 1); \
    r2 = *jit_insn_opnd(insn, 2);

/* Load four operands from insn and check if r0 is non-const */
#define LOAD_4ARGS()              \
    r0 = *jit_insn_opnd(insn, 0); \
    r1 = *jit_insn_opnd(insn, 1); \
    r2 = *jit_insn_opnd(insn, 2); \
    r3 = *jit_insn_opnd(insn, 3); \
    CHECK_NCONST(r0)

/* Load five operands from insn and check if r0 is non-const */
#define LOAD_4ARGS_NO_ASSIGN()    \
    r0 = *jit_insn_opnd(insn, 0); \
    r1 = *jit_insn_opnd(insn, 1); \
    r2 = *jit_insn_opnd(insn, 2); \
    r3 = *jit_insn_opnd(insn, 3);

class JitErrorHandler : public ErrorHandler
{
  public:
    Error err;

    JitErrorHandler()
      : err(kErrorOk)
    {}

    void handleError(Error e, const char *msg, BaseEmitter *base) override
    {
        (void)msg;
        (void)base;
        this->err = e;
    }
};

/* Alu opcode */
typedef enum { ADD, SUB, MUL, DIV_S, REM_S, DIV_U, REM_U, MIN, MAX } ALU_OP;
/* Bit opcode */
typedef enum { OR, XOR, AND } BIT_OP;
/* Shift opcode */
typedef enum { SHL, SHRS, SHRU, ROTL, ROTR } SHIFT_OP;
/* Bitcount opcode */
typedef enum { CLZ, CTZ, POPCNT } BITCOUNT_OP;
/* Condition opcode */
typedef enum { EQ, NE, GTS, GES, LTS, LES, GTU, GEU, LTU, LEU } COND_OP;

typedef union _cast_float_to_integer {
    float f;
    uint32 i;
} cast_float_to_integer;

typedef union _cast_double_to_integer {
    double d;
    uint64 i;
} cast_double_to_integer;

static uint32
local_log2(uint32 data)
{
    uint32 ret = 0;
    while (data >>= 1) {
        ret++;
    }
    return ret;
}

static uint64
local_log2l(uint64 data)
{
    uint64 ret = 0;
    while (data >>= 1) {
        ret++;
    }
    return ret;
}

/* Jmp type */
typedef enum JmpType {
    JMP_DST_LABEL_REL,     /* jmp to dst label with relative addr */
    JMP_DST_LABEL_ABS,     /* jmp to dst label with absolute addr */
    JMP_END_OF_CALLBC,     /* jmp to end of CALLBC */
    JMP_LOOKUPSWITCH_BASE, /* LookupSwitch table base addr */
} JmpType;

/**
 * Jmp info, save the info on first encoding pass,
 * and replace the offset with exact offset when the code cache
 * has been allocated actually.
 */
typedef struct JmpInfo {
    bh_list_link link;
    JmpType type;
    uint32 label_src;
    uint32 offset;
    union {
        uint32 label_dst;
    } dst_info;
} JmpInfo;

static bool
label_is_neighboring(JitCompContext *cc, int32 label_prev, int32 label_succ)
{
    return (label_prev == 0 && label_succ == 2)
           || (label_prev >= 2 && label_succ == label_prev + 1)
           || (label_prev == (int32)jit_cc_label_num(cc) - 1
               && label_succ == 1);
}

static bool
label_is_ahead(JitCompContext *cc, int32 label_dst, int32 label_src)
{
    return (label_dst == 0 && label_src != 0)
           || (label_dst != 1 && label_src == 1)
           || (2 <= label_dst && label_dst < label_src
               && label_src <= (int32)jit_cc_label_num(cc) - 1);
}

/**
 * Encode jumping from one label to the other label
 *
 * @param a the assembler to emit the code
 * @param jmp_info_list the jmp info list
 * @param label_dst the index of dst label
 * @param label_src the index of src label
 *
 * @return true if success, false if failed
 */
static bool
jmp_from_label_to_label(x86::Assembler &a, bh_list *jmp_info_list,
                        int32 label_dst, int32 label_src)
{
    Imm imm(INT32_MAX);
    JmpInfo *node;

    node = (JmpInfo *)jit_calloc(sizeof(JmpInfo));
    if (!node)
        return false;

    node->type = JMP_DST_LABEL_REL;
    node->label_src = label_src;
    node->dst_info.label_dst = label_dst;
    node->offset = a.code()->sectionById(0)->buffer().size() + 2;
    bh_list_insert(jmp_info_list, node);

    a.jmp(imm);
    return true;
}

/**
 * Encode detecting compare result register according to condition code
 * and then jumping to suitable label when the condtion is met
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param jmp_info_list the jmp info list
 * @param label_src the index of src label
 * @param op the opcode of condition operation
 * @param r1 the label info when condition is met
 * @param r2 the label info when condition is unmet, do nonthing if VOID
 * @param is_last_insn if current insn is the last insn of current block
 *
 * @return true if success, false if failed
 */
static bool
cmp_r_and_jmp_label(JitCompContext *cc, x86::Assembler &a,
                    bh_list *jmp_info_list, int32 label_src, COND_OP op,
                    JitReg r1, JitReg r2, bool is_last_insn)
{
    Imm imm(INT32_MAX);
    JmpInfo *node;

    node = (JmpInfo *)jit_malloc(sizeof(JmpInfo));
    if (!node)
        return false;

    node->type = JMP_DST_LABEL_REL;
    node->label_src = label_src;
    node->dst_info.label_dst = jit_reg_no(r1);
    node->offset = a.code()->sectionById(0)->buffer().size() + 2;
    bh_list_insert(jmp_info_list, node);

    bool fp_cmp = cc->last_cmp_on_fp;

    bh_assert(!fp_cmp || (fp_cmp && (op == GTS || op == GES)));

    switch (op) {
        case EQ:
        {
            a.je(imm);
            break;
        }
        case NE:
        {
            a.jne(imm);
            break;
        }
        case GTS:
        {
            if (fp_cmp)
                a.ja(imm);
            else
                a.jg(imm);
            break;
        }
        case LES:
        {
            a.jng(imm);
            break;
        }
        case GES:
        {
            if (fp_cmp)
                a.jae(imm);
            else
                a.jnl(imm);
            break;
        }
        case LTS:
        {
            a.jl(imm);
            break;
        }
        case GTU:
        {
            a.ja(imm);
            break;
        }
        case LEU:
        {
            a.jna(imm);
            break;
        }
        case GEU:
        {
            a.jnb(imm);
            break;
        }
        case LTU:
        {
            a.jb(imm);
            break;
        }
        default:
        {
            bh_assert(0);
            break;
        }
    }

    if (r2) {
        int32 label_dst = jit_reg_no(r2);
        if (!(is_last_insn && label_is_neighboring(cc, label_src, label_dst)))
            if (!jmp_from_label_to_label(a, jmp_info_list, label_dst,
                                         label_src))
                return false;
    }

    return true;
}

#if WASM_ENABLE_FAST_JIT_DUMP != 0
static void
dump_native(char *data, uint32 length)
{
    /* Initialize decoder context */
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_STACK_WIDTH_64);

    /* Initialize formatter */
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    /* Loop over the instructions in our buffer */
    ZyanU64 runtime_address = (ZyanU64)(uintptr_t)data;
    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
        &decoder, data + offset, length - offset, &instruction, operands,
        ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY))) {
        /* Print current instruction pointer */
        os_printf("%012" PRIX64 "  ", runtime_address);

        /* Format & print the binary instruction structure to
           human readable format */
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
                                        instruction.operand_count_visible,
                                        buffer, sizeof(buffer),
                                        runtime_address);
        puts(buffer);

        offset += instruction.length;
        runtime_address += instruction.length;
    }
}
#endif

/**
 * Encode extending register of byte to register of dword
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src tho no of src register
 * @param is_signed the data is signed or unsigned
 *
 * @return true if success, false otherwise
 */
static bool
extend_r8_to_r32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src,
                 bool is_signed)
{
    if (is_signed) {
        a.movsx(regs_i32[reg_no_dst], regs_i8[reg_no_src]);
    }
    else {
        a.movzx(regs_i32[reg_no_dst], regs_i8[reg_no_src]);
    }
    return true;
}
/**
 * Encode extending register of word to register of dword
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src tho no of src register
 * @param is_signed the data is signed or unsigned
 *
 * @return true if success, false otherwise
 */
static bool
extend_r16_to_r32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src,
                  bool is_signed)
{
    if (is_signed) {
        a.movsx(regs_i32[reg_no_dst], regs_i16[reg_no_src]);
    }
    else {
        a.movzx(regs_i32[reg_no_dst], regs_i16[reg_no_src]);
    }
    return true;
}

/**
 * Encode extending register of byte to register of qword
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src tho no of src register
 * @param is_signed the data is signed or unsigned
 *
 * @return true if success, false otherwise
 */
static bool
extend_r8_to_r64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src,
                 bool is_signed)
{
    if (is_signed) {
        a.movsx(regs_i64[reg_no_dst], regs_i8[reg_no_src]);
    }
    else {
        a.movzx(regs_i64[reg_no_dst], regs_i8[reg_no_src]);
    }
    return true;
}

/**
 * Encode extending register of word to register of qword
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src tho no of src register
 * @param is_signed the data is signed or unsigned
 *
 * @return true if success, false otherwise
 */
static bool
extend_r16_to_r64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src,
                  bool is_signed)
{
    if (is_signed) {
        a.movsx(regs_i64[reg_no_dst], regs_i16[reg_no_src]);
    }
    else {
        a.movzx(regs_i64[reg_no_dst], regs_i16[reg_no_src]);
    }
    return true;
}

/**
 * Encode extending register of dword to register of qword
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src tho no of src register
 * @param is_signed the data is signed or unsigned
 *
 * @return true if success, false otherwise
 */
static bool
extend_r32_to_r64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src,
                  bool is_signed)
{
    if (is_signed) {
        a.movsxd(regs_i64[reg_no_dst], regs_i32[reg_no_src]);
    }
    else {
        /*
         * The upper 32-bit will be zero-extended, ref to Intel document,
         * 3.4.1.1 General-Purpose Registers: 32-bit operands generate
         * a 32-bit result, zero-extended to a 64-bit result in the
         * destination general-purpose register
         */
        a.mov(regs_i32[reg_no_dst], regs_i32[reg_no_src]);
    }
    return true;
}

static bool
mov_r_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src);

static bool
mov_r_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src);

static void
mov_r_to_r(x86::Assembler &a, uint32 kind_dst, int32 reg_no_dst,
           int32 reg_no_src)
{
    if (kind_dst == JIT_REG_KIND_I32)
        mov_r_to_r_i32(a, reg_no_dst, reg_no_src);
    else if (kind_dst == JIT_REG_KIND_I64)
        mov_r_to_r_i64(a, reg_no_dst, reg_no_src);
    else if (kind_dst == JIT_REG_KIND_F32) {
        /* TODO */
        bh_assert(0);
    }
    else if (kind_dst == JIT_REG_KIND_F64) {
        /* TODO */
        bh_assert(0);
    }
    else {
        bh_assert(0);
    }
}

/**
 * Encode moving memory to a register
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64),
 *        skipped by float and double
 * @param kind_dst the kind of data to move, could be I32, I64, F32 or F64
 * @param is_signed whether the data is signed or unsigned
 * @param reg_no_dst the index of dest register
 * @param m_src the memory operand which contains the source data
 *
 * @return true if success, false otherwise
 */
static bool
mov_m_to_r(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst, bool is_signed,
           int32 reg_no_dst, x86::Mem &m_src)
{
    if (kind_dst == JIT_REG_KIND_I32) {
        switch (bytes_dst) {
            case 1:
            case 2:
                if (is_signed)
                    a.movsx(regs_i32[reg_no_dst], m_src);
                else
                    a.movzx(regs_i32[reg_no_dst], m_src);
                break;
            case 4:
                a.mov(regs_i32[reg_no_dst], m_src);
                break;
            default:
                bh_assert(0);
                return false;
        }
    }
    else if (kind_dst == JIT_REG_KIND_I64) {
        switch (bytes_dst) {
            case 1:
            case 2:
                if (is_signed)
                    a.movsx(regs_i64[reg_no_dst], m_src);
                else
                    a.movzx(regs_i64[reg_no_dst], m_src);
                break;
            case 4:
                if (is_signed)
                    a.movsxd(regs_i64[reg_no_dst], m_src);
                else
                    /*
                     * The upper 32-bit will be zero-extended, ref to Intel
                     * document, 3.4.1.1 General-Purpose Registers: 32-bit
                     * operands generate a 32-bit result, zero-extended to
                     * a 64-bit result in the destination general-purpose
                     * register
                     */
                    a.mov(regs_i32[reg_no_dst], m_src);
                break;
            case 8:
                a.mov(regs_i64[reg_no_dst], m_src);
                break;
            default:
                bh_assert(0);
                return false;
        }
    }
    else if (kind_dst == JIT_REG_KIND_F32) {
        a.movss(regs_float[reg_no_dst], m_src);
    }
    else if (kind_dst == JIT_REG_KIND_F64) {
        a.movsd(regs_float[reg_no_dst], m_src);
    }
    return true;
}

/**
 * Encode moving register to memory
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64),
 *        skipped by float and double
 * @param kind_dst the kind of data to move, could be I32, I64, F32 or F64
 * @param is_signed whether the data is signed or unsigned
 * @param m_dst the dest memory operand
 * @param reg_no_src the index of dest register
 *
 * @return true if success, false otherwise
 */
static bool
mov_r_to_m(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst,
           x86::Mem &m_dst, int32 reg_no_src)
{
    if (kind_dst == JIT_REG_KIND_I32) {
        bh_assert(reg_no_src < 16);
        switch (bytes_dst) {
            case 1:
                a.mov(m_dst, regs_i8[reg_no_src]);
                break;
            case 2:
                a.mov(m_dst, regs_i16[reg_no_src]);
                break;
            case 4:
                a.mov(m_dst, regs_i32[reg_no_src]);
                break;
            default:
                bh_assert(0);
                return false;
        }
    }
    else if (kind_dst == JIT_REG_KIND_I64) {
        bh_assert(reg_no_src < 16);
        switch (bytes_dst) {
            case 1:
                a.mov(m_dst, regs_i8[reg_no_src]);
                break;
            case 2:
                a.mov(m_dst, regs_i16[reg_no_src]);
                break;
            case 4:
                a.mov(m_dst, regs_i32[reg_no_src]);
                break;
            case 8:
                a.mov(m_dst, regs_i64[reg_no_src]);
                break;
            default:
                bh_assert(0);
                return false;
        }
    }
    else if (kind_dst == JIT_REG_KIND_F32) {
        a.movss(m_dst, regs_float[reg_no_src]);
    }
    else if (kind_dst == JIT_REG_KIND_F64) {
        a.movsd(m_dst, regs_float[reg_no_src]);
    }
    return true;
}

/**
 * Encode moving immediate data to memory
 *
 * @param m dst memory
 * @param imm src immediate data
 *
 * @return new stream
 */
static bool
mov_imm_to_m(x86::Assembler &a, x86::Mem &m_dst, Imm imm_src, uint32 bytes_dst)
{
    if (bytes_dst == 8) {
        int64 value = imm_src.value();
        if (value >= INT32_MIN && value <= INT32_MAX) {
            imm_src.setValue((int32)value);
            a.mov(m_dst, imm_src);
        }
        else {
            /* There is no instruction `MOV m64, imm64`, we use
               two instructions to implement it */
            a.mov(regs_i64[REG_I64_FREE_IDX], imm_src);
            a.mov(m_dst, regs_i64[REG_I64_FREE_IDX]);
        }
    }
    else
        a.mov(m_dst, imm_src);
    return true;
}

#if WASM_ENABLE_SHARED_MEMORY != 0
/**
 * Encode exchange register with memory
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64),
 *        skipped by float and double
 * @param kind_dst the kind of data to move, could only be I32 or I64
 * @param m_dst the dest memory operand
 * @param reg_no_src the index of dest register
 *
 * @return true if success, false otherwise
 */
static bool
xchg_r_to_m(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst,
            x86::Mem &m_dst, int32 reg_no_src)
{
    bh_assert((kind_dst == JIT_REG_KIND_I32 && bytes_dst <= 4)
              || kind_dst == JIT_REG_KIND_I64);
    bh_assert(reg_no_src < 16);
    switch (bytes_dst) {
        case 1:
            a.xchg(m_dst, regs_i8[reg_no_src]);
            break;
        case 2:
            a.xchg(m_dst, regs_i16[reg_no_src]);
            break;
        case 4:
            a.xchg(m_dst, regs_i32[reg_no_src]);
            break;
        case 8:
            a.xchg(m_dst, regs_i64[reg_no_src]);
            break;
        default:
            bh_assert(0);
            return false;
    }
    return true;
}
#endif
/**
 * Encode loading register data from memory with imm base and imm offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64), skipped by
 * float/double
 * @param kind_dst the kind of data to move, could be I32, I64, F32 or F64
 * @param is_signed the data is signed or unsigned
 * @param reg_no_dst the index of dest register
 * @param base the base address of the memory
 * @param offset the offset address of the memory
 *
 * @return true if success, false otherwise
 */
static bool
ld_r_from_base_imm_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                              uint32 kind_dst, bool is_signed, int32 reg_no_dst,
                              int32 base, int32 offset)
{
    x86::Mem m((uintptr_t)(base + offset), bytes_dst);
    return mov_m_to_r(a, bytes_dst, kind_dst, is_signed, reg_no_dst, m);
}

/**
 * Encode loading register data from memory with imm base and register offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64), skipped by
 * float/double
 * @param kind_dst the kind of data to move, could be I32, I64, F32 or F64
 * @param is_signed the data is signed or unsigned
 * @param reg_no_dst the index of dest register
 * @param base the base address of the memory
 * @param reg_no_offset the no of register which stores the offset of the memory
 *
 * @return true if success, false otherwise
 */
static bool
ld_r_from_base_imm_offset_r(x86::Assembler &a, uint32 bytes_dst,
                            uint32 kind_dst, bool is_signed, int32 reg_no_dst,
                            int32 base, int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_offset], base, bytes_dst);
    return mov_m_to_r(a, bytes_dst, kind_dst, is_signed, reg_no_dst, m);
}

/**
 * Encode loading register data from memory with register base and imm offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64), skipped by
 * float/double
 * @param kind_dst the kind of data to move, could be I32, I64, F32 or F64
 * @param is_signed the data is signed or unsigned
 * @param reg_no_dst the index of dest register
 * @param reg_no_base the no of register which stores the base of the memory
 * @param offset the offset address of the memory
 *
 * @return true if success, false otherwise
 */
static bool
ld_r_from_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                            uint32 kind_dst, bool is_signed, int32 reg_no_dst,
                            int32 reg_no_base, int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    return mov_m_to_r(a, bytes_dst, kind_dst, is_signed, reg_no_dst, m);
}

/**
 * Encode loading register data from memory with register base and register
 * offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64), skipped by
 * float/double
 * @param kind_dst the kind of data to move, could be I32, I64, F32 or F64
 * @param is_signed the data is signed or unsigned
 * @param reg_no_dst the index of dest register
 * @param reg_no_base the no of register which stores the base of the memory
 * @param reg_no_offset the no of register which stores the offset of the memory
 *
 * @return true if success, false otherwise
 */
static bool
ld_r_from_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst,
                          bool is_signed, int32 reg_no_dst, int32 reg_no_base,
                          int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    return mov_m_to_r(a, bytes_dst, kind_dst, is_signed, reg_no_dst, m);
}

/**
 * Encode storing register data to memory with imm base and imm offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64), skipped by
 * float/double
 * @param kind_dst the kind of data to move, could be I32, I64, F32 or F64
 * @param reg_no_src the index of src register
 * @param base the base address of the dst memory
 * @param offset the offset address of the dst memory
 *
 * @return true if success, false otherwise
 */
static bool
st_r_to_base_imm_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                            uint32 kind_dst, int32 reg_no_src, int32 base,
                            int32 offset, bool atomic)
{
    x86::Mem m((uintptr_t)(base + offset), bytes_dst);
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic)
        return xchg_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src);
#endif
    return mov_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src);
}

/**
 * Encode storing register data to memory with imm base and register offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64), skipped by
 * float/double
 * @param kind_dst the kind of data to move, could be I32, I64, F32 or F64
 * @param reg_no_src the index of src register
 * @param base the base address of the dst memory
 * @param reg_no_offset the no of register which stores the offset of the dst
 * memory
 *
 * @return true if success, false otherwise
 */
static bool
st_r_to_base_imm_offset_r(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst,
                          int32 reg_no_src, int32 base, int32 reg_no_offset,
                          bool atomic)
{
    x86::Mem m(regs_i64[reg_no_offset], base, bytes_dst);
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic)
        return xchg_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src);
#endif
    return mov_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src);
}

/**
 * Encode storing register data to memory with register base and imm offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64), skipped by
 * float/double
 * @param kind_dst the kind of data to move, could be I32, I64, F32 or F64
 * @param reg_no_src the index of src register
 * @param reg_no_base the no of register which stores the base of the dst memory
 * @param offset the offset address of the dst memory
 *
 * @return true if success, false otherwise
 */
static bool
st_r_to_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst,
                          int32 reg_no_src, int32 reg_no_base, int32 offset,
                          bool atomic)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic)
        return xchg_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src);
#endif
    return mov_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src);
}

/**
 * Encode storing register data to memory with register base and register offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64), skipped by
 * float/double
 * @param kind_dst the kind of data to move, could be I32, I64, F32 or F64
 * @param reg_no_src the index of src register
 * @param reg_no_base the no of register which stores the base of the dst memory
 * @param reg_no_offset the no of register which stores the offset of the dst
 * memory
 *
 * @return true if success, false otherwise
 */
static bool
st_r_to_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst,
                        int32 reg_no_src, int32 reg_no_base,
                        int32 reg_no_offset, bool atomic)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (atomic)
        return xchg_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src);
#endif
    return mov_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src);
}

static void
imm_set_value(Imm &imm, void *data, uint32 bytes)
{
    switch (bytes) {
        case 1:
            imm.setValue(*(uint8 *)data);
            break;
        case 2:
            imm.setValue(*(uint16 *)data);
            break;
        case 4:
            imm.setValue(*(uint32 *)data);
            break;
        case 8:
            imm.setValue(*(uint64 *)data);
            break;
        default:
            bh_assert(0);
    }
}

#if WASM_ENABLE_SHARED_MEMORY != 0
static uint32
mov_imm_to_free_reg(x86::Assembler &a, Imm &imm, uint32 bytes)
{
    uint32 reg_no;

    switch (bytes) {
        case 1:
            reg_no = REG_I8_FREE_IDX;
            a.mov(regs_i8[reg_no], imm);
            break;
        case 2:
            reg_no = REG_I16_FREE_IDX;
            a.mov(regs_i16[reg_no], imm);
            break;
        case 4:
            reg_no = REG_I32_FREE_IDX;
            a.mov(regs_i32[reg_no], imm);
            break;
        case 8:
            reg_no = REG_I64_FREE_IDX;
            a.mov(regs_i64[reg_no], imm);
            break;
        default:
            bh_assert(0);
    }

    return reg_no;
}
#endif

/**
 * Encode storing int32 imm data to memory with imm base and imm offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param data_src the src immediate data
 * @param base the base address of dst memory
 * @param offset the offset address of dst memory
 *
 * @return true if success, false otherwise
 */
static bool
st_imm_to_base_imm_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                              void *data_src, int32 base, int32 offset,
                              bool atomic)
{
    x86::Mem m((uintptr_t)(base + offset), bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
#if WASM_ENABLE_SHARED_MEMORY != 0
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    if (atomic) {
        return xchg_r_to_m(a, bytes_dst, JIT_REG_KIND_I64, m, reg_no_src);
    }
#endif
    return mov_imm_to_m(a, m, imm, bytes_dst);
}

/**
 * Encode storing int32 imm data to memory with imm base and reg offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param data_src the src immediate data
 * @param base the base address of dst memory
 * @param reg_no_offset the no of register that stores the offset address
 *        of dst memory
 *
 * @return true if success, false otherwise
 */
static bool
st_imm_to_base_imm_offset_r(x86::Assembler &a, uint32 bytes_dst, void *data_src,
                            int32 base, int32 reg_no_offset, bool atomic)
{
    x86::Mem m(regs_i64[reg_no_offset], base, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
#if WASM_ENABLE_SHARED_MEMORY != 0
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    if (atomic) {
        return xchg_r_to_m(a, bytes_dst, JIT_REG_KIND_I64, m, reg_no_src);
    }
#endif
    return mov_imm_to_m(a, m, imm, bytes_dst);
}

/**
 * Encode storing int32 imm data to memory with reg base and imm offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param data_src the src immediate data
 * @param reg_no_base the no of register that stores the base address
 *        of dst memory
 * @param offset the offset address of dst memory
 *
 * @return true if success, false otherwise
 */
static bool
st_imm_to_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst, void *data_src,
                            int32 reg_no_base, int32 offset, bool atomic)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
#if WASM_ENABLE_SHARED_MEMORY != 0
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    if (atomic) {
        return xchg_r_to_m(a, bytes_dst, JIT_REG_KIND_I64, m, reg_no_src);
    }
#endif
    return mov_imm_to_m(a, m, imm, bytes_dst);
}

/**
 * Encode storing int32 imm data to memory with reg base and reg offset
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param data_src the src immediate data
 * @param reg_no_base the no of register that stores the base address
 *        of dst memory
 * @param reg_no_offset the no of register that stores the offset address
 *        of dst memory
 *
 * @return true if success, false otherwise
 */
static bool
st_imm_to_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst, void *data_src,
                          int32 reg_no_base, int32 reg_no_offset, bool atomic)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
#if WASM_ENABLE_SHARED_MEMORY != 0
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    if (atomic) {
        return xchg_r_to_m(a, bytes_dst, JIT_REG_KIND_I64, m, reg_no_src);
    }
#endif
    return mov_imm_to_m(a, m, imm, bytes_dst);
}

/**
 * Encode moving immediate int32 data to register
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst register
 * @param data the immediate data to move
 *
 * @return true if success, false otherwise
 */
static bool
mov_imm_to_r_i32(x86::Assembler &a, int32 reg_no, int32 data)
{
    Imm imm(data);
    a.mov(regs_i32[reg_no], imm);
    return true;
}

/**
 * Encode moving int32 data from src register to dst register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src the no of src register
 *
 * @return true if success, false otherwise
 */
static bool
mov_r_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    if (reg_no_dst != reg_no_src)
        a.mov(regs_i32[reg_no_dst], regs_i32[reg_no_src]);
    return true;
}

/**
 * Encode moving immediate int64 data to register
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst register
 * @param data the immediate data to move
 *
 * @return true if success, false otherwise
 */
static bool
mov_imm_to_r_i64(x86::Assembler &a, int32 reg_no, int64 data)
{
    Imm imm(data);
    a.mov(regs_i64[reg_no], imm);
    return true;
}

/**
 * Encode moving int64 data from src register to dst register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src the no of src register
 *
 * @return true if success, false otherwise
 */
static bool
mov_r_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    if (reg_no_dst != reg_no_src)
        a.mov(regs_i64[reg_no_dst], regs_i64[reg_no_src]);
    return true;
}

/**
 * Encode moving immediate float data to register
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst register
 * @param data the immediate data to move
 *
 * @return true if success, false otherwise
 */
static bool
mov_imm_to_r_f32(x86::Assembler &a, int32 reg_no, float data)
{
    /* imm -> gp -> xmm */
    cast_float_to_integer v = { .f = data };
    Imm imm(v.i);
    a.mov(regs_i32[REG_I32_FREE_IDX], imm);
    a.movd(regs_float[reg_no], regs_i32[REG_I32_FREE_IDX]);
    return true;
}

/**
 * Encode moving float data from src register to dst register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src the no of src register
 *
 * @return true if success, false otherwise
 */
static bool
mov_r_to_r_f32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    if (reg_no_dst != reg_no_src) {
        a.movss(regs_float[reg_no_dst], regs_float[reg_no_src]);
    }
    return true;
}

/**
 * Encode moving immediate double data to register
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst register
 * @param data the immediate data to move
 *
 * @return true if success, false otherwise
 */
static bool
mov_imm_to_r_f64(x86::Assembler &a, int32 reg_no, double data)
{
    cast_double_to_integer v = { .d = data };
    Imm imm(v.i);
    a.mov(regs_i64[REG_I32_FREE_IDX], imm);
    /* REG_I32_FREE_IDX == REG_I64_FREE_IDX */
    a.movq(regs_float[reg_no], regs_i64[REG_I64_FREE_IDX]);
    return true;
}

/**
 * Encode moving double data from src register to dst register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src the no of src register
 *
 * @return true if success, false otherwise
 */
static bool
mov_r_to_r_f64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    if (reg_no_dst != reg_no_src) {
        a.movsd(regs_float[reg_no_dst], regs_float[reg_no_src]);
    }
    return true;
}

/* Let compiler do the conversation job as much as possible */

/**
 * Encoding convert int8 immediate data to int32 register
 *
 * @param a the assembler to emit the code
 * @param reg_no the dst register, need to be converted to int32
 * @param data the src int8 immediate data
 *
 * @return  true if success, false otherwise
 */
static bool
convert_imm_i8_to_r_i32(x86::Assembler &a, int32 reg_no, int8 data)
{
    return mov_imm_to_r_i32(a, reg_no, (int32)data);
}

/**
 * encoding convert int8 register to int32 register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the dst register
 * @param reg_no_src the src register
 *
 * @return  true if success, false otherwise
 */
static bool
convert_r_i8_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    return extend_r8_to_r32(a, reg_no_dst, reg_no_src, true);
}

/**
 * encoding convert int8 immediate data to int64 register
 *
 * @param a the assembler to emit the code
 * @param reg_no the dst register, need to be converted to int64
 * @param data the src int8 immediate data
 *
 * @return  true if success, false otherwise
 */
static bool
convert_imm_i8_to_r_i64(x86::Assembler &a, int32 reg_no, int8 data)
{
    return mov_imm_to_r_i64(a, reg_no, (int64)data);
}

/**
 * encoding convert int8 register to int64 register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the dst register
 * @param reg_no_src the src register
 *
 * @return  true if success, false otherwise
 */
static bool
convert_r_i8_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    return extend_r8_to_r64(a, reg_no_dst, reg_no_src, true);
}

/**
 * Encoding convert int16 immediate data to int32 register
 *
 * @param a the assembler to emit the code
 * @param reg_no the dst register, need to be converted to int32
 * @param data the src int16 immediate data
 *
 * @return  true if success, false otherwise
 */
static bool
convert_imm_i16_to_r_i32(x86::Assembler &a, int32 reg_no, int16 data)
{
    return mov_imm_to_r_i32(a, reg_no, (int32)data);
}

/**
 * encoding convert int16 register to int32 register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the dst register
 * @param reg_no_src the src register
 *
 * @return  true if success, false otherwise
 */
static bool
convert_r_i16_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    return extend_r16_to_r32(a, reg_no_dst, reg_no_src, true);
}

/**
 * encoding convert int16 immediate data to int64 register
 *
 * @param a the assembler to emit the code
 * @param reg_no the dst register, need to be converted to int64
 * @param data the src int16 immediate data
 *
 * @return  true if success, false otherwise
 */
static bool
convert_imm_i16_to_r_i64(x86::Assembler &a, int32 reg_no, int16 data)
{
    return mov_imm_to_r_i64(a, reg_no, (int64)data);
}

/**
 * encoding convert int16 register to int64 register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the dst register
 * @param reg_no_src the src register
 *
 * @return  true if success, false otherwise
 */
static bool
convert_r_i16_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    return extend_r16_to_r64(a, reg_no_dst, reg_no_src, true);
}

/**
 * Encoding convert int32 immediate data to int8 register
 *
 * @param a the assembler to emit the code
 * @param reg_no the dst register, need to be converted to int8
 * @param data the src int32 immediate data
 *
 * @return  true if success, false otherwise
 */
static bool
convert_imm_i32_to_r_i8(x86::Assembler &a, int32 reg_no, int32 data)
{
    /* (int32)(int8)data will do sign-extension */
    /* (int32)(uint32)(int8)data is longer */
    return mov_imm_to_r_i32(a, reg_no, data & 0x000000FF);
}

/**
 * Encoding convert int32 immediate data to int8 register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the dst register, need to be converted to int8
 * @param reg_no_src the src register
 *
 * @return  true if success, false otherwise
 */
static bool
convert_r_i32_to_r_i8(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    mov_r_to_r_i32(a, reg_no_dst, reg_no_src);
    a.and_(regs_i32[reg_no_dst], 0x000000FF);
    return true;
}

/**
 * Encoding convert int32 immediate data to uint8 register
 *
 * @param a the assembler to emit the code
 * @param reg_no the dst register, need to be converted to uint8
 * @param data the src int32 immediate data
 *
 * @return  true if success, false otherwise
 */
static bool
convert_imm_i32_to_r_u8(x86::Assembler &a, int32 reg_no, int32 data)
{
    return mov_imm_to_r_i32(a, reg_no, (uint8)data);
}

/**
 * Encoding convert int32 immediate data to uint8 register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the dst register, need to be converted to uint8
 * @param reg_no_src the src register
 *
 * @return  true if success, false otherwise
 */
static bool
convert_r_i32_to_r_u8(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    return convert_r_i32_to_r_i8(a, reg_no_dst, reg_no_src);
}

/**
 * Encoding convert int32 immediate data to int16 register
 *
 * @param a the assembler to emit the code
 * @param reg_no the dst register, need to be converted to int16
 * @param data the src int32 immediate data
 *
 * @return  true if success, false otherwise
 */
static bool
convert_imm_i32_to_r_i16(x86::Assembler &a, int32 reg_no, int32 data)
{
    /* (int32)(int16)data will do sign-extension */
    /* (int32)(uint32)(int16)data is longer */
    return mov_imm_to_r_i32(a, reg_no, data & 0x0000FFFF);
}

/**
 * Encoding convert int32 immediate data to int16 register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the dst register, need to be converted to int16
 * @param reg_no_src the src register
 *
 * @return  true if success, false otherwise
 */
static bool
convert_r_i32_to_r_i16(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    mov_r_to_r_i32(a, reg_no_dst, reg_no_src);
    a.and_(regs_i32[reg_no_dst], 0x0000FFFF);
    return true;
}

/**
 * Encoding convert int32 immediate data to uint16 register
 *
 * @param a the assembler to emit the code
 * @param reg_no the dst register, need to be converted to uint16
 * @param data the src int32 immediate data
 *
 * @return  true if success, false otherwise
 */
static bool
convert_imm_i32_to_r_u16(x86::Assembler &a, int32 reg_no, int32 data)
{
    return mov_imm_to_r_i32(a, reg_no, (uint16)data);
}

/**
 * Encoding convert int32 immediate data to uint16 register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the dst register, need to be converted to uint16
 * @param reg_no_src the src register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_i32_to_r_u16(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    return convert_r_i32_to_r_i16(a, reg_no_dst, reg_no_src);
}

/**
 * Encoding convert int32 immediate data to int64 register
 *
 * @param a the assembler to emit the code
 * @param reg_no the dst register, need to be converted to uint64
 * @param data the src int32 immediate data
 *
 * @return  true if success, false otherwise
 */
static bool
convert_imm_i32_to_r_i64(x86::Assembler &a, int32 reg_no, int32 data)
{
    return mov_imm_to_r_i64(a, reg_no, (int64)data);
}

/**
 * Encoding convert int32 register data to int64 register with signed extension
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the dst register, need to be converted to uint64
 * @param reg_no_src the src register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_i32_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    return extend_r32_to_r64(a, reg_no_dst, reg_no_src, true);
}

/**
 * Encode converting int32 register data to float register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst float register
 * @param reg_no_src the no of src int32 register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_i32_to_r_f32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvtsi2ss(regs_float[reg_no_dst], regs_i32[reg_no_src]);
    return true;
}

/**
 * Encode converting int32 immediate data to float register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst float register
 * @param data the src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_i32_to_r_f32(x86::Assembler &a, int32 reg_no, int32 data)
{
    mov_imm_to_r_i32(a, REG_I32_FREE_IDX, data);
    return convert_r_i32_to_r_f32(a, reg_no, REG_I32_FREE_IDX);
}

/**
 * Encode converting int32 register data to double register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst double register
 * @param reg_no_src the no of src int32 register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_i32_to_r_f64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvtsi2sd(regs_float[reg_no_dst], regs_i32[reg_no_src]);
    return true;
}

/**
 * Encode converting int32 immediate data to double register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst double register
 * @param data the src immediate int32 data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_i32_to_r_f64(x86::Assembler &a, int32 reg_no, int32 data)
{
    mov_imm_to_r_i32(a, REG_I32_FREE_IDX, data);
    return convert_r_i32_to_r_f64(a, reg_no, REG_I32_FREE_IDX);
}

/**
 * Encode converting int64 immediate data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int32 register
 * @param data the src immediate int64 data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_i64_to_r_i32(x86::Assembler &a, int32 reg_no, int64 data)
{
    return mov_imm_to_r_i64(a, reg_no, (int32)data);
}

/**
 * Encode converting int64 register data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst int32 register
 * @param reg_no_src the no of src int64 register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_i64_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    mov_r_to_r_i64(a, reg_no_dst, reg_no_src);
    a.and_(regs_i64[reg_no_dst], 0x00000000FFFFFFFFLL);
    return true;
}

/**
 * Encode converting int64 immediate data to int8 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int32 register
 * @param data the src immediate int64 data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_i64_to_r_i8(x86::Assembler &a, int32 reg_no, int64 data)
{
    return mov_imm_to_r_i64(a, reg_no, (int8)data);
}

/**
 * Encode converting int64 register data to int8 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst int8 register
 * @param reg_no_src the no of src int64 register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_i64_to_r_i8(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    mov_r_to_r_i64(a, reg_no_dst, reg_no_src);
    a.and_(regs_i64[reg_no_dst], 0x00000000000000FFLL);
    return true;
}

/**
 * Encode converting int64 immediate data to int16 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int32 register
 * @param data the src immediate int64 data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_i64_to_r_i16(x86::Assembler &a, int32 reg_no, int64 data)
{
    return mov_imm_to_r_i64(a, reg_no, (int16)data);
}

/**
 * Encode converting int64 register data to int16 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst int16 register
 * @param reg_no_src the no of src int64 register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_i64_to_r_i16(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    mov_r_to_r_i64(a, reg_no_dst, reg_no_src);
    a.and_(regs_i64[reg_no_dst], 0x000000000000FFFFLL);
    return true;
}

/**
 * Encode converting uint32 immediate data to int64 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int64 register
 * @param data the src immediate uint32 data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_u32_to_r_i64(x86::Assembler &a, int32 reg_no, uint32 data)
{
    return mov_imm_to_r_i64(a, reg_no, (int64)(uint64)data);
}

/**
 * Encode converting uint32 register data to int64 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst uint32 register
 * @param reg_no_src the no of src int64 register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_u32_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    return extend_r32_to_r64(a, reg_no_dst, reg_no_src, false);
}

/**
 * Encode converting uint32 immediate data to float register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst float register
 * @param data the src immediate uint32 data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_u32_to_r_f32(x86::Assembler &a, int32 reg_no, uint32 data)
{
    mov_imm_to_r_i64(a, REG_I64_FREE_IDX, (int64)(uint64)data);
    a.cvtsi2ss(regs_float[reg_no], regs_i64[REG_I64_FREE_IDX]);
    return true;
}

/**
 * Encode converting uint32 register data to float register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst uint32 register
 * @param reg_no_src the no of src float register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_u32_to_r_f32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    extend_r32_to_r64(a, REG_I64_FREE_IDX, reg_no_src, false);
    a.cvtsi2ss(regs_float[reg_no_dst], regs_i64[REG_I64_FREE_IDX]);
    return true;
}

/**
 * Encode converting uint32 immediate data to double register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst double register
 * @param data the src immediate uint32 data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_u32_to_r_f64(x86::Assembler &a, int32 reg_no, uint32 data)
{
    mov_imm_to_r_i64(a, REG_I64_FREE_IDX, (int64)(uint64)data);
    a.cvtsi2sd(regs_float[reg_no], regs_i64[REG_I64_FREE_IDX]);
    return true;
}

/**
 * Encode converting uint32 register data to double register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst uint32 register
 * @param reg_no_src the no of src double register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_u32_to_r_f64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    extend_r32_to_r64(a, REG_I64_FREE_IDX, reg_no_src, false);
    a.cvtsi2sd(regs_float[reg_no_dst], regs_i64[REG_I64_FREE_IDX]);
    return true;
}

/**
 * Encode converting int64 register data to float register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst float register
 * @param reg_no_src the no of src int64 register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_i64_to_r_f32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvtsi2ss(regs_float[reg_no_dst], regs_i64[reg_no_src]);
    return true;
}

/**
 * Encode converting int64 immediate data to float register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst float register
 * @param data the src immediate int64 data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_i64_to_r_f32(x86::Assembler &a, int32 reg_no, int64 data)
{
    mov_imm_to_r_i64(a, REG_I64_FREE_IDX, data);
    return convert_r_i64_to_r_f32(a, reg_no, REG_I64_FREE_IDX);
}

/**
 * Encode converting int64 register data to double register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst double register
 * @param reg_no_src the no of src int64 register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_i64_to_r_f64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvtsi2sd(regs_float[reg_no_dst], regs_i64[reg_no_src]);
    return true;
}

/**
 * Encode converting int64 immediate data to double register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst double register
 * @param data the src immediate int64 data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_i64_to_r_f64(x86::Assembler &a, int32 reg_no, int64 data)
{
    mov_imm_to_r_i64(a, REG_I64_FREE_IDX, data);
    return convert_r_i64_to_r_f64(a, reg_no, REG_I64_FREE_IDX);
}

/**
 * Encode converting float immediate data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int32 register
 * @param data the src immediate float data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_f32_to_r_i32(x86::Assembler &a, int32 reg_no, float data)
{
    return mov_imm_to_r_i32(a, reg_no, (int32)data);
}

/**
 * Encode converting float register data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst int32 register
 * @param reg_no_src the no of src float register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_f32_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvttss2si(regs_i32[reg_no_dst], regs_float[reg_no_src]);
    return true;
}

/**
 * Encode converting float immediate data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int32 register
 * @param data the src immediate float data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_f32_to_r_u32(x86::Assembler &a, int32 reg_no, float data)
{
    return mov_imm_to_r_i32(a, reg_no, (uint32)data);
}

/**
 * Encode converting float register data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst int32 register
 * @param reg_no_src the no of src float register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_f32_to_r_u32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvttss2si(regs_i64[reg_no_dst], regs_float[reg_no_src]);
    return true;
}

/**
 * Encode converting float immediate data to int64 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int64 register
 * @param data the src immediate float data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_f32_to_r_i64(x86::Assembler &a, int32 reg_no, float data)
{
    return mov_imm_to_r_i64(a, reg_no, (int64)data);
}

/**
 * Encode converting float register data to int64 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst int64 register
 * @param reg_no_src the no of src float register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_f32_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvttss2si(regs_i64[reg_no_dst], regs_float[reg_no_src]);
    return true;
}

/**
 * Encode converting float immediate data to double register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst double register
 * @param data the src immediate float data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_f32_to_r_f64(x86::Assembler &a, int32 reg_no, float data)
{
    return mov_imm_to_r_f64(a, reg_no, (double)data);
}

/**
 * Encode converting float register data to double register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst double register
 * @param reg_no_src the no of src float register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_f32_to_r_f64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvtss2sd(regs_float[reg_no_dst], regs_float[reg_no_src]);
    return true;
}

/**
 * Encode converting double immediate data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int32 register
 * @param data the src immediate double data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_f64_to_r_i32(x86::Assembler &a, int32 reg_no, double data)
{
    return mov_imm_to_r_i32(a, reg_no, (int32)data);
}

/**
 * Encode converting double register data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst int32 register
 * @param reg_no_src the no of src double register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_f64_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvttsd2si(regs_i32[reg_no_dst], regs_float[reg_no_src]);
    return true;
}

/**
 * Encode converting double immediate data to int64 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int64 register
 * @param data the src immediate double data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_f64_to_r_i64(x86::Assembler &a, int32 reg_no, double data)
{
    return mov_imm_to_r_i64(a, reg_no, (int64)data);
}

/**
 * Encode converting double register data to int64 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst int64 register
 * @param reg_no_src the no of src double register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_f64_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvttsd2si(regs_i64[reg_no_dst], regs_float[reg_no_src]);
    return true;
}

/**
 * Encode converting double immediate data to float register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst float register
 * @param data the src immediate double data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_f64_to_r_f32(x86::Assembler &a, int32 reg_no, double data)
{
    return mov_imm_to_r_f32(a, reg_no, (float)data);
}

/**
 * Encode converting double register data to float register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst float register
 * @param reg_no_src the no of src double register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_f64_to_r_f32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvtsd2ss(regs_float[reg_no_dst], regs_float[reg_no_src]);
    return true;
}

/**
 * Encode converting double immediate data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int32 register
 * @param data the src immediate double data
 *
 * @return true if success, false otherwise
 */
static bool
convert_imm_f64_to_r_u32(x86::Assembler &a, int32 reg_no, double data)
{
    return mov_imm_to_r_i32(a, reg_no, (uint32)data);
}

/**
 * Encode converting double register data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst int32 register
 * @param reg_no_src the no of src double register
 *
 * @return true if success, false otherwise
 */
static bool
convert_r_f64_to_r_u32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.cvttsd2si(regs_i64[reg_no_dst], regs_float[reg_no_src]);
    return true;
}

/**
 * Encode making negative from int32 immediate data to int32 register
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst register
 * @param data the src int32 immediate data
 *
 * @return true if success, false otherwise
 */
static bool
neg_imm_to_r_i32(x86::Assembler &a, int32 reg_no, int32 data)
{
    Imm imm(-data);
    a.mov(regs_i32[reg_no], imm);
    return true;
}

/**
 * Encode making negative from int32 register to int32 register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src the no of src register
 *
 * @return true if success, false otherwise
 */
static bool
neg_r_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    mov_r_to_r_i32(a, reg_no_dst, reg_no_src);
    a.neg(regs_i32[reg_no_dst]);
    return true;
}

/**
 * Encode making negative from int64 immediate data to int64 register
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst register
 * @param data the src int64 immediate data
 *
 * @return true if success, false otherwise
 */
static bool
neg_imm_to_r_i64(x86::Assembler &a, int32 reg_no, int64 data)
{
    Imm imm(-data);
    a.mov(regs_i64[reg_no], imm);
    return true;
}

/**
 * Encode making negative from int64 register to int64 register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src the no of src register
 *
 * @return true if success, false otherwise
 */
static bool
neg_r_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    mov_r_to_r_i64(a, reg_no_dst, reg_no_src);
    a.neg(regs_i64[reg_no_dst]);
    return true;
}

/**
 * Encode making negative from float immediate data to float register
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst float register
 * @param data the src float immediate data
 *
 * @return true if success, false otherwise
 */
static bool
neg_imm_to_r_f32(x86::Assembler &a, int32 reg_no, float data)
{
    bh_assert(0);
    (void)a;
    (void)reg_no;
    (void)data;
    return false;
}

/**
 * Encode making negative from float register to float register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst register
 * @param reg_no_src the no of src register
 *
 * @return true if success, false otherwise
 */
static bool
neg_r_to_r_f32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    bh_assert(0);
    (void)a;
    (void)reg_no_dst;
    (void)reg_no_src;
    return false;
}

/**
 * Encode making negative from double immediate data to double register
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst double register
 * @param data the src double immediate data
 *
 * @return true if success, false otherwise
 */
static bool
neg_imm_to_r_f64(x86::Assembler &a, int32 reg_no, double data)
{
    bh_assert(0);
    (void)a;
    (void)reg_no;
    (void)data;
    return false;
}

/**
 * Encode making negative from double register to double register
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst double register
 * @param reg_no_src the no of src double register
 *
 * @return true if success, false otherwise
 */
static bool
neg_r_to_r_f64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    bh_assert(0);
    (void)a;
    (void)reg_no_dst;
    (void)reg_no_src;
    return false;
}

static COND_OP
not_cond(COND_OP op)
{
    COND_OP not_list[] = { NE, EQ, LES, LTS, GES, GTS, LEU, LTU, GEU, GTU };

    bh_assert(op <= LEU);
    return not_list[op];
}

/**
 * Encode int32 alu operation of reg and data, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no the no of register, as first operand, and save result
 * @param data the immediate data, as the second operand
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_r_imm_i32(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                int32 reg_no_src, int32 data)
{
    Imm imm(data);

    switch (op) {
        case ADD:
            mov_r_to_r(a, JIT_REG_KIND_I32, reg_no_dst, reg_no_src);
            if (data == 1)
                a.inc(regs_i32[reg_no_dst]);
            else if (data == -1)
                a.dec(regs_i32[reg_no_dst]);
            else if (data != 0)
                a.add(regs_i32[reg_no_dst], imm);
            break;
        case SUB:
            mov_r_to_r(a, JIT_REG_KIND_I32, reg_no_dst, reg_no_src);
            if (data == -1)
                a.inc(regs_i32[reg_no_dst]);
            else if (data == 1)
                a.dec(regs_i32[reg_no_dst]);
            else if (data != 0)
                a.sub(regs_i32[reg_no_dst], imm);
            break;
        case MUL:
            if (data == 0)
                a.xor_(regs_i32[reg_no_dst], regs_i32[reg_no_dst]);
            else if (data == -1) {
                mov_r_to_r(a, JIT_REG_KIND_I32, reg_no_dst, reg_no_src);
                a.neg(regs_i32[reg_no_dst]);
            }
            else if (data == 1) {
                mov_r_to_r(a, JIT_REG_KIND_I32, reg_no_dst, reg_no_src);
            }
            else if (data > 0 && (data & (data - 1)) == 0x0) {
                mov_r_to_r(a, JIT_REG_KIND_I32, reg_no_dst, reg_no_src);
                data = (int32)local_log2(data);
                imm.setValue(data);
                a.shl(regs_i32[reg_no_dst], imm);
            }
            else {
                a.imul(regs_i32[reg_no_dst], regs_i32[reg_no_src], imm);
            }
            break;
        case DIV_S:
        case REM_S:
            bh_assert(reg_no_src == REG_EAX_IDX);
            if (op == DIV_S) {
                bh_assert(reg_no_dst == REG_EAX_IDX);
            }
            else {
                bh_assert(reg_no_dst == REG_EDX_IDX);
            }
            a.mov(regs_i32[REG_I32_FREE_IDX], imm);
            /* signed extend eax to edx:eax */
            a.cdq();
            a.idiv(regs_i32[REG_I32_FREE_IDX]);
            break;
        case DIV_U:
        case REM_U:
            bh_assert(reg_no_src == REG_EAX_IDX);
            if (op == DIV_U) {
                bh_assert(reg_no_dst == REG_EAX_IDX);
            }
            else {
                bh_assert(reg_no_dst == REG_EDX_IDX);
            }
            a.mov(regs_i32[REG_I32_FREE_IDX], imm);
            /* unsigned extend eax to edx:eax */
            a.xor_(regs_i32[REG_EDX_IDX], regs_i32[REG_EDX_IDX]);
            a.div(regs_i32[REG_I32_FREE_IDX]);
            break;
        default:
            bh_assert(0);
            break;
    }

    return true;
}

/**
 * Encode int32 alu operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register, as first operand, and save result
 * @param reg_no_src the no of register, as the second operand
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_r_r_i32(x86::Assembler &a, ALU_OP op, int32 reg_no_dst, int32 reg_no1_src,
              int32 reg_no2_src)
{
    switch (op) {
        case ADD:
            if (reg_no_dst != reg_no2_src) {
                mov_r_to_r(a, JIT_REG_KIND_I32, reg_no_dst, reg_no1_src);
                a.add(regs_i32[reg_no_dst], regs_i32[reg_no2_src]);
            }
            else
                a.add(regs_i32[reg_no2_src], regs_i32[reg_no1_src]);
            break;
        case SUB:
            if (reg_no_dst != reg_no2_src) {
                mov_r_to_r(a, JIT_REG_KIND_I32, reg_no_dst, reg_no1_src);
                a.sub(regs_i32[reg_no_dst], regs_i32[reg_no2_src]);
            }
            else {
                a.sub(regs_i32[reg_no2_src], regs_i32[reg_no1_src]);
                a.neg(regs_i32[reg_no2_src]);
            }
            break;
        case MUL:
            if (reg_no_dst != reg_no2_src) {
                mov_r_to_r(a, JIT_REG_KIND_I32, reg_no_dst, reg_no1_src);
                a.imul(regs_i32[reg_no_dst], regs_i32[reg_no2_src]);
            }
            else
                a.imul(regs_i32[reg_no2_src], regs_i32[reg_no1_src]);
            break;
        case DIV_S:
        case REM_S:
            bh_assert(reg_no1_src == REG_EAX_IDX);
            if (op == DIV_S) {
                bh_assert(reg_no_dst == REG_EAX_IDX);
            }
            else {
                bh_assert(reg_no_dst == REG_EDX_IDX);
                if (reg_no2_src == REG_EDX_IDX) {
                    /* convert `REM_S edx, eax, edx` into
                       `mov esi, edx` and `REM_S edx eax, rsi` to
                       avoid overwritting edx when a.cdq() */
                    a.mov(regs_i32[REG_I32_FREE_IDX], regs_i32[REG_EDX_IDX]);
                    reg_no2_src = REG_I32_FREE_IDX;
                }
            }
            /* signed extend eax to edx:eax */
            a.cdq();
            a.idiv(regs_i32[reg_no2_src]);
            break;
        case DIV_U:
        case REM_U:
            bh_assert(reg_no1_src == REG_EAX_IDX);
            if (op == DIV_U) {
                bh_assert(reg_no_dst == REG_EAX_IDX);
            }
            else {
                bh_assert(reg_no_dst == REG_EDX_IDX);
                if (reg_no2_src == REG_EDX_IDX) {
                    /* convert `REM_U edx, eax, edx` into
                       `mov esi, edx` and `REM_U edx eax, rsi` to
                       avoid overwritting edx when unsigned extend
                       eax to edx:eax */
                    a.mov(regs_i32[REG_I32_FREE_IDX], regs_i32[REG_EDX_IDX]);
                    reg_no2_src = REG_I32_FREE_IDX;
                }
            }
            /* unsigned extend eax to edx:eax */
            a.xor_(regs_i32[REG_EDX_IDX], regs_i32[REG_EDX_IDX]);
            a.div(regs_i32[reg_no2_src]);
            break;
        default:
            bh_assert(0);
            return false;
    }

    return true;
}

/**
 * Encode int32 alu operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
alu_imm_imm_to_r_i32(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                     int32 data1_src, int32 data2_src)
{
    Imm imm;
    int32 data = 0;

    switch (op) {
        case ADD:
            data = data1_src + data2_src;
            break;
        case SUB:
            data = data1_src - data2_src;
            break;
        case MUL:
            data = data1_src * data2_src;
            break;
        case DIV_S:
            data = data1_src / data2_src;
            break;
        case REM_S:
            data = data1_src % data2_src;
            break;
        case DIV_U:
            data = (uint32)data1_src / (uint32)data2_src;
            break;
        case REM_U:
            data = (uint32)data1_src % (uint32)data2_src;
            break;
        default:
            bh_assert(0);
            return false;
    }

    imm.setValue(data);
    a.mov(regs_i32[reg_no_dst], imm);
    return true;
}

/**
 * Encode int32 alu operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
alu_imm_r_to_r_i32(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                   int32 data1_src, int32 reg_no2_src)
{
    if (op == ADD || op == MUL)
        return alu_r_r_imm_i32(a, op, reg_no_dst, reg_no2_src, data1_src);
    else if (op == SUB) {
        if (!alu_r_r_imm_i32(a, op, reg_no_dst, reg_no2_src, data1_src))
            return false;
        a.neg(regs_i32[reg_no_dst]);
        return true;
    }
    else {
        if (reg_no_dst != reg_no2_src) {
            if (!mov_imm_to_r_i32(a, reg_no_dst, data1_src)
                || !alu_r_r_r_i32(a, op, reg_no_dst, reg_no_dst, reg_no2_src))
                return false;
            return true;
        }
        else {
            if (!mov_imm_to_r_i32(a, REG_I32_FREE_IDX, data1_src)
                || !alu_r_r_r_i32(a, op, reg_no_dst, REG_I32_FREE_IDX,
                                  reg_no2_src))
                return false;
            return true;
        }
    }

    return true;
}

/**
 * Encode int32 alu operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_imm_to_r_i32(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                   int32 reg_no1_src, int32 data2_src)
{
    return alu_r_r_imm_i32(a, op, reg_no_dst, reg_no1_src, data2_src);
}

/**
 * Encode int32 alu operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_r_to_r_i32(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                 int32 reg_no1_src, int32 reg_no2_src)
{
    return alu_r_r_r_i32(a, op, reg_no_dst, reg_no1_src, reg_no2_src);
}

/**
 * Encode int64 alu operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register, as first operand, and save result
 * @param reg_no_src the no of register, as the second operand
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_r_r_i64(x86::Assembler &a, ALU_OP op, int32 reg_no_dst, int32 reg_no1_src,
              int32 reg_no2_src)
{
    switch (op) {
        case ADD:
            if (reg_no_dst != reg_no2_src) {
                mov_r_to_r(a, JIT_REG_KIND_I64, reg_no_dst, reg_no1_src);
                a.add(regs_i64[reg_no_dst], regs_i64[reg_no2_src]);
            }
            else
                a.add(regs_i64[reg_no2_src], regs_i64[reg_no1_src]);
            break;
        case SUB:
            if (reg_no_dst != reg_no2_src) {
                mov_r_to_r(a, JIT_REG_KIND_I64, reg_no_dst, reg_no1_src);
                a.sub(regs_i64[reg_no_dst], regs_i64[reg_no2_src]);
            }
            else {
                a.sub(regs_i64[reg_no2_src], regs_i64[reg_no1_src]);
                a.neg(regs_i64[reg_no2_src]);
            }
            break;
        case MUL:
            if (reg_no_dst != reg_no2_src) {
                mov_r_to_r(a, JIT_REG_KIND_I64, reg_no_dst, reg_no1_src);
                a.imul(regs_i64[reg_no_dst], regs_i64[reg_no2_src]);
            }
            else
                a.imul(regs_i64[reg_no2_src], regs_i64[reg_no1_src]);
            break;
        case DIV_S:
        case REM_S:
            bh_assert(reg_no1_src == REG_RAX_IDX);
            if (op == DIV_S) {
                bh_assert(reg_no_dst == REG_RAX_IDX);
            }
            else {
                bh_assert(reg_no_dst == REG_RDX_IDX);
            }
            /* signed extend rax to rdx:rax */
            a.cqo();
            a.idiv(regs_i64[reg_no2_src]);
            break;
        case DIV_U:
        case REM_U:
            bh_assert(reg_no1_src == REG_RAX_IDX);
            if (op == DIV_U) {
                bh_assert(reg_no_dst == REG_RAX_IDX);
            }
            else {
                bh_assert(reg_no_dst == REG_RDX_IDX);
            }
            /* unsigned extend rax to rdx:rax */
            a.xor_(regs_i64[REG_RDX_IDX], regs_i64[REG_RDX_IDX]);
            a.div(regs_i64[reg_no2_src]);
            break;
        default:
            bh_assert(0);
            break;
    }

    return true;
}

/**
 * Encode int64 alu operation of reg and data, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no the no of register, as first operand, and save result
 * @param data the immediate data, as the second operand
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_r_imm_i64(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                int32 reg_no_src, int64 data)
{
    Imm imm(data);

    switch (op) {
        case ADD:
            mov_r_to_r(a, JIT_REG_KIND_I64, reg_no_dst, reg_no_src);
            if (data == 1)
                a.inc(regs_i64[reg_no_dst]);
            else if (data == -1)
                a.dec(regs_i64[reg_no_dst]);
            else if (data != 0) {
                if (data >= INT32_MIN && data <= INT32_MAX) {
                    imm.setValue((int32)data);
                    a.add(regs_i64[reg_no_dst], imm);
                }
                else {
                    a.mov(regs_i64[REG_I64_FREE_IDX], imm);
                    a.add(regs_i64[reg_no_dst], regs_i64[REG_I64_FREE_IDX]);
                }
            }
            break;
        case SUB:
            mov_r_to_r(a, JIT_REG_KIND_I64, reg_no_dst, reg_no_src);
            if (data == -1)
                a.inc(regs_i64[reg_no_dst]);
            else if (data == 1)
                a.dec(regs_i64[reg_no_dst]);
            else if (data != 0) {
                if (data >= INT32_MIN && data <= INT32_MAX) {
                    imm.setValue((int32)data);
                    a.sub(regs_i64[reg_no_dst], imm);
                }
                else {
                    a.mov(regs_i64[REG_I64_FREE_IDX], imm);
                    a.sub(regs_i64[reg_no_dst], regs_i64[REG_I64_FREE_IDX]);
                }
            }
            break;
        case MUL:
            if (data == 0)
                a.xor_(regs_i64[reg_no_dst], regs_i64[reg_no_dst]);
            else if (data == -1) {
                mov_r_to_r(a, JIT_REG_KIND_I64, reg_no_dst, reg_no_src);
                a.neg(regs_i64[reg_no_dst]);
            }
            else if (data == 1) {
                mov_r_to_r(a, JIT_REG_KIND_I64, reg_no_dst, reg_no_src);
            }
            else if (data > 0 && (data & (data - 1)) == 0x0) {
                mov_r_to_r(a, JIT_REG_KIND_I64, reg_no_dst, reg_no_src);
                data = (int64)local_log2l(data);
                imm.setValue(data);
                a.shl(regs_i64[reg_no_dst], imm);
            }
            else if (INT32_MIN <= data && data <= INT32_MAX) {
                a.imul(regs_i64[reg_no_dst], regs_i64[reg_no_src], imm);
            }
            else {
                mov_imm_to_r_i64(
                    a, reg_no_dst == reg_no_src ? REG_I64_FREE_IDX : reg_no_dst,
                    data);
                alu_r_r_r_i64(a, op, reg_no_dst,
                              reg_no_dst == reg_no_src ? REG_I64_FREE_IDX
                                                       : reg_no_dst,
                              reg_no_src);
            }
            break;
        case DIV_S:
        case REM_S:
            bh_assert(reg_no_src == REG_RAX_IDX);
            if (op == DIV_S) {
                bh_assert(reg_no_dst == REG_RAX_IDX);
            }
            else {
                bh_assert(reg_no_dst == REG_RDX_IDX);
            }
            a.mov(regs_i64[REG_I64_FREE_IDX], imm);
            /* signed extend rax to rdx:rax */
            a.cqo();
            a.idiv(regs_i64[REG_I64_FREE_IDX]);
            break;
        case DIV_U:
        case REM_U:
            bh_assert(reg_no_src == REG_RAX_IDX);
            if (op == DIV_U) {
                bh_assert(reg_no_dst == REG_RAX_IDX);
            }
            else {
                bh_assert(reg_no_dst == REG_RDX_IDX);
            }
            a.mov(regs_i64[REG_I64_FREE_IDX], imm);
            /* unsigned extend rax to rdx:rax */
            a.xor_(regs_i64[REG_RDX_IDX], regs_i64[REG_RDX_IDX]);
            a.div(regs_i64[REG_I64_FREE_IDX]);
            break;
        default:
            bh_assert(0);
            break;
    }

    return true;
}

/**
 * Encode int64 alu operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
alu_imm_imm_to_r_i64(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                     int64 data1_src, int64 data2_src)
{
    Imm imm;
    int64 data = 0;

    switch (op) {
        case ADD:
            data = data1_src + data2_src;
            break;
        case SUB:
            data = data1_src - data2_src;
            break;
        case MUL:
            data = data1_src * data2_src;
            break;
        case DIV_S:
            data = data1_src / data2_src;
            break;
        case REM_S:
            data = data1_src % data2_src;
            break;
        case DIV_U:
            data = (uint64)data1_src / (uint64)data2_src;
            break;
        case REM_U:
            data = (uint64)data1_src % (uint64)data2_src;
            break;
        default:
            bh_assert(0);
            break;
    }

    imm.setValue(data);
    a.mov(regs_i64[reg_no_dst], imm);
    return true;
}

/**
 * Encode int64 alu operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
alu_imm_r_to_r_i64(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                   int64 data1_src, int32 reg_no2_src)
{
    if (op == ADD || op == MUL)
        return alu_r_r_imm_i64(a, op, reg_no_dst, reg_no2_src, data1_src);
    else if (op == SUB) {
        if (!alu_r_r_imm_i64(a, op, reg_no_dst, reg_no2_src, data1_src))
            return false;
        a.neg(regs_i64[reg_no_dst]);
        return true;
    }
    else {
        if (reg_no_dst != reg_no2_src) {
            if (!mov_imm_to_r_i64(a, reg_no_dst, data1_src)
                || !alu_r_r_r_i64(a, op, reg_no_dst, reg_no_dst, reg_no2_src))
                return false;
            return true;
        }
        else {
            if (!mov_imm_to_r_i64(a, REG_I64_FREE_IDX, data1_src)
                || !alu_r_r_r_i64(a, op, reg_no_dst, REG_I64_FREE_IDX,
                                  reg_no2_src))
                return false;
            return true;
        }
    }

    return true;
}

/**
 * Encode int64 alu operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_imm_to_r_i64(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                   int32 reg_no1_src, int64 data2_src)
{
    return alu_r_r_imm_i64(a, op, reg_no_dst, reg_no1_src, data2_src);
}

/**
 * Encode int64 alu operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_r_to_r_i64(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                 int32 reg_no1_src, int32 reg_no2_src)
{
    return alu_r_r_r_i64(a, op, reg_no_dst, reg_no1_src, reg_no2_src);
}

/**
 * Encode float alu operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
alu_imm_imm_to_r_f32(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                     float data1_src, float data2_src)
{
    Imm imm;
    float data = 0;

    switch (op) {
        case ADD:
        {
            data = data1_src + data2_src;
            break;
        }
        case SUB:
        {
            data = data1_src - data2_src;
            break;
        }
        case MUL:
        {
            data = data1_src * data2_src;
            break;
        }
        case DIV_S:
        {
            data = data1_src / data2_src;
            break;
        }
        case MAX:
        {
            data = fmaxf(data1_src, data2_src);
            break;
        }
        case MIN:
        {
            data = fminf(data1_src, data2_src);
            break;
        }
        default:
        {
            bh_assert(0);
            return false;
        }
    }

    return mov_imm_to_r_f32(a, reg_no_dst, data);
}

static bool
alu_r_m_float(x86::Assembler &a, ALU_OP op, int32 reg_no, x86::Mem &m,
              bool is_f32)
{
    switch (op) {
        case ADD:
        {
            if (is_f32)
                a.addss(regs_float[reg_no], m);
            else
                a.addsd(regs_float[reg_no], m);
            break;
        }
        case SUB:
        {
            if (is_f32)
                a.subss(regs_float[reg_no], m);
            else
                a.subsd(regs_float[reg_no], m);
            break;
        }
        case MUL:
        {
            if (is_f32)
                a.mulss(regs_float[reg_no], m);
            else
                a.mulsd(regs_float[reg_no], m);
            break;
        }
        case DIV_S:
        {
            if (is_f32)
                a.divss(regs_float[reg_no], m);
            else
                a.divsd(regs_float[reg_no], m);
            break;
        }
        case MAX:
        {
            if (is_f32)
                a.maxss(regs_float[reg_no], m);
            else
                a.maxsd(regs_float[reg_no], m);
            break;
        }
        case MIN:
        {
            if (is_f32)
                a.minss(regs_float[reg_no], m);
            else
                a.minsd(regs_float[reg_no], m);
            break;
        }
        default:
        {
            bh_assert(0);
            return false;
        }
    }
    return true;
}

/**
 * Encode float alu operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
alu_imm_r_to_r_f32(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                   float data1_src, int32 reg_no2_src)
{
    const JitHardRegInfo *hreg_info = jit_codegen_get_hreg_info();
    /* xmm -> m128 */
    x86::Mem cache = x86::xmmword_ptr(regs_i64[hreg_info->exec_env_hreg_index],
                                      offsetof(WASMExecEnv, jit_cache));
    a.movups(cache, regs_float[reg_no2_src]);

    /* imm -> gp -> xmm */
    mov_imm_to_r_f32(a, reg_no_dst, data1_src);

    return alu_r_m_float(a, op, reg_no_dst, cache, true);
}

/**
 * Encode float alu operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_imm_to_r_f32(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                   int32 reg_no1_src, float data2_src)
{
    const JitHardRegInfo *hreg_info = jit_codegen_get_hreg_info();
    /* imm -> m32 */
    x86::Mem cache = x86::dword_ptr(regs_i64[hreg_info->exec_env_hreg_index],
                                    offsetof(WASMExecEnv, jit_cache));
    cast_float_to_integer v = { .f = data2_src };
    Imm imm(v.i);
    mov_imm_to_m(a, cache, imm, 4);

    mov_r_to_r_f32(a, reg_no_dst, reg_no1_src);
    return alu_r_m_float(a, op, reg_no_dst, cache, true);
}

/**
 * Encode float alu operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_r_to_r_f32(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                 int32 reg_no1_src, int32 reg_no2_src)
{
    bool store_result = false;

    /**
     * - op r0,r0,r1. do nothing since instructions always store results in
     *   the first register
     *
     * - op r1,r0,r1. use FREE_REG to cache and replace r0, and then store
     *   results in r1
     *
     * - op r0,r1,r2. use r0 to cache and replace r1, and accept the result
     *   naturally
     **/
    if (reg_no_dst == reg_no2_src) {
        store_result = true;
        reg_no_dst = REG_F32_FREE_IDX;
    }
    mov_r_to_r_f32(a, reg_no_dst, reg_no1_src);

    switch (op) {
        case ADD:
        {
            a.addss(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        case SUB:
        {
            a.subss(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        case MUL:
        {
            a.mulss(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        case DIV_S:
        {
            a.divss(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        case MAX:
        {
            a.maxss(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        case MIN:
        {
            a.minss(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        default:
        {
            bh_assert(0);
            return false;
        }
    }

    if (store_result)
        mov_r_to_r_f32(a, reg_no2_src, REG_F32_FREE_IDX);

    return true;
}

/**
 * Encode double alu operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
alu_imm_imm_to_r_f64(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                     double data1_src, double data2_src)
{
    Imm imm;
    double data = 0;

    switch (op) {
        case ADD:
        {
            data = data1_src + data2_src;
            break;
        }
        case SUB:
        {
            data = data1_src - data2_src;
            break;
        }
        case MUL:
        {
            data = data1_src * data2_src;
            break;
        }
        case DIV_S:
        {
            data = data1_src / data2_src;
            break;
        }
        case MAX:
        {
            data = fmax(data1_src, data2_src);
            break;
        }
        case MIN:
        {
            data = fmin(data1_src, data2_src);
            break;
        }
        default:
        {
            bh_assert(0);
            return false;
        }
    }

    return mov_imm_to_r_f64(a, reg_no_dst, data);
}

/**
 * Encode double alu operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
alu_imm_r_to_r_f64(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                   double data1_src, int32 reg_no2_src)
{
    const JitHardRegInfo *hreg_info = jit_codegen_get_hreg_info();
    /* xmm -> m128 */
    x86::Mem cache = x86::qword_ptr(regs_i64[hreg_info->exec_env_hreg_index],
                                    offsetof(WASMExecEnv, jit_cache));
    a.movupd(cache, regs_float[reg_no2_src]);

    /* imm -> gp -> xmm */
    mov_imm_to_r_f64(a, reg_no_dst, data1_src);

    return alu_r_m_float(a, op, reg_no_dst, cache, false);
}

/**
 * Encode double alu operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_imm_to_r_f64(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                   int32 reg_no1_src, double data2_src)
{
    const JitHardRegInfo *hreg_info = jit_codegen_get_hreg_info();
    /* imm -> m64 */
    x86::Mem cache = x86::qword_ptr(regs_i64[hreg_info->exec_env_hreg_index],
                                    offsetof(WASMExecEnv, jit_cache));
    cast_double_to_integer v = { .d = data2_src };
    Imm imm(v.i);
    mov_imm_to_m(a, cache, imm, 8);

    mov_r_to_r_f64(a, reg_no_dst, reg_no1_src);
    return alu_r_m_float(a, op, reg_no_dst, cache, false);
}

/**
 * Encode double alu operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of ALU operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
alu_r_r_to_r_f64(x86::Assembler &a, ALU_OP op, int32 reg_no_dst,
                 int32 reg_no1_src, int32 reg_no2_src)
{
    bool store_result = false;

    /**
     * - op r0,r0,r1. do nothing since instructions always store results in
     *   the first register
     *
     * - op r1,r0,r1. use FREE_REG to cache and replace r0, and then store
     *   results in r1
     *
     * - op r0,r1,r2. use r0 to cache and replace r1, and accept the result
     *   naturally
     **/
    if (reg_no_dst == reg_no2_src) {
        store_result = true;
        reg_no_dst = REG_F64_FREE_IDX;
    }
    mov_r_to_r_f64(a, reg_no_dst, reg_no1_src);

    switch (op) {
        case ADD:
        {
            a.addsd(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        case SUB:
        {
            a.subsd(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        case MUL:
        {
            a.mulsd(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        case DIV_S:
        {
            a.divsd(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        case MAX:
        {
            a.maxsd(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        case MIN:
        {
            a.minsd(regs_float[reg_no_dst], regs_float[reg_no2_src]);
            break;
        }
        default:
        {
            bh_assert(0);
            return false;
        }
    }

    if (store_result)
        mov_r_to_r_f64(a, reg_no2_src, REG_F64_FREE_IDX);

    return true;
}

/**
 * Encode int32 bit operation of reg and data, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no the no of register, as first operand, and save result
 * @param data the immediate data, as the second operand
 *
 * @return true if success, false otherwise
 */
static bool
bit_r_imm_i32(x86::Assembler &a, BIT_OP op, int32 reg_no, int32 data)
{
    Imm imm(data);

    switch (op) {
        case OR:
            if (data != 0)
                a.or_(regs_i32[reg_no], imm);
            break;
        case XOR:
            if (data == -1)
                a.not_(regs_i32[reg_no]);
            else if (data != 0)
                a.xor_(regs_i32[reg_no], imm);
            break;
        case AND:
            if (data != -1)
                a.and_(regs_i32[reg_no], imm);
            break;
        default:
            bh_assert(0);
            break;
    }
    return true;
}

/**
 * Encode int32 bit operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no_dst the no of register, as first operand, and save result
 * @param reg_no_src the no of register, as second operand
 *
 * @return true if success, false otherwise
 */
static bool
bit_r_r_i32(x86::Assembler &a, BIT_OP op, int32 reg_no_dst, int32 reg_no_src)
{
    switch (op) {
        case OR:
            a.or_(regs_i32[reg_no_dst], regs_i32[reg_no_src]);
            break;
        case XOR:
            a.xor_(regs_i32[reg_no_dst], regs_i32[reg_no_src]);
            break;
        case AND:
            a.and_(regs_i32[reg_no_dst], regs_i32[reg_no_src]);
            break;
        default:
            bh_assert(0);
            break;
    }
    return true;
}

/**
 * Encode int32 bit operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
bit_imm_imm_to_r_i32(x86::Assembler &a, BIT_OP op, int32 reg_no_dst,
                     int32 data1_src, int32 data2_src)
{
    Imm imm;

    switch (op) {
        case OR:
            imm.setValue(data1_src | data2_src);
            break;
        case XOR:
            imm.setValue(data1_src ^ data2_src);
            break;
        case AND:
            imm.setValue(data1_src & data2_src);
            break;
        default:
            bh_assert(0);
            break;
    }

    a.mov(regs_i32[reg_no_dst], imm);
    return true;
}

/**
 * Encode int32 bit operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
bit_imm_r_to_r_i32(x86::Assembler &a, BIT_OP op, int32 reg_no_dst,
                   int32 data1_src, int32 reg_no2_src)
{
    if (op == AND && data1_src == 0)
        a.xor_(regs_i32[reg_no_dst], regs_i32[reg_no_dst]);
    else if (op == OR && data1_src == -1) {
        Imm imm(-1);
        a.mov(regs_i32[reg_no_dst], imm);
    }
    else {
        mov_r_to_r_i32(a, reg_no_dst, reg_no2_src);
        return bit_r_imm_i32(a, op, reg_no_dst, data1_src);
    }
    return true;
}

/**
 * Encode int32 bit operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
bit_r_imm_to_r_i32(x86::Assembler &a, BIT_OP op, int32 reg_no_dst,
                   int32 reg_no1_src, int32 data2_src)
{
    return bit_imm_r_to_r_i32(a, op, reg_no_dst, data2_src, reg_no1_src);
}

/**
 * Encode int32 bit operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
bit_r_r_to_r_i32(x86::Assembler &a, BIT_OP op, int32 reg_no_dst,
                 int32 reg_no1_src, int32 reg_no2_src)
{
    if (reg_no_dst != reg_no2_src) {
        mov_r_to_r_i32(a, reg_no_dst, reg_no1_src);
        return bit_r_r_i32(a, op, reg_no_dst, reg_no2_src);
    }
    else
        return bit_r_r_i32(a, op, reg_no_dst, reg_no1_src);
    return false;
}

/**
 * Encode int64 bit operation of reg and data, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no the no of register, as first operand, and save result
 * @param data the immediate data, as the second operand
 *
 * @return true if success, false otherwise
 */
static bool
bit_r_imm_i64(x86::Assembler &a, BIT_OP op, int32 reg_no, int64 data)
{
    Imm imm(data);

    switch (op) {
        case OR:
            if (data != 0) {
                if (data >= INT32_MIN && data <= INT32_MAX) {
                    imm.setValue((int32)data);
                    a.or_(regs_i64[reg_no], imm);
                }
                else {
                    a.mov(regs_i64[REG_I64_FREE_IDX], imm);
                    a.or_(regs_i64[reg_no], regs_i64[REG_I64_FREE_IDX]);
                }
            }
            break;
        case XOR:
            if (data == -1LL)
                a.not_(regs_i64[reg_no]);
            else if (data != 0) {
                if (data >= INT32_MIN && data <= INT32_MAX) {
                    imm.setValue((int32)data);
                    a.xor_(regs_i64[reg_no], imm);
                }
                else {
                    a.mov(regs_i64[REG_I64_FREE_IDX], imm);
                    a.xor_(regs_i64[reg_no], regs_i64[REG_I64_FREE_IDX]);
                }
            }
            break;
        case AND:
            if (data != -1LL) {
                if (data >= INT32_MIN && data <= INT32_MAX) {
                    imm.setValue((int32)data);
                    a.and_(regs_i64[reg_no], imm);
                }
                else {
                    a.mov(regs_i64[REG_I64_FREE_IDX], imm);
                    a.and_(regs_i64[reg_no], regs_i64[REG_I64_FREE_IDX]);
                }
            }
            break;
        default:
            bh_assert(0);
            break;
    }
    return true;
}

/**
 * Encode int64 bit operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no_dst the no of register, as first operand, and save result
 * @param reg_no_src the no of register, as second operand
 *
 * @return true if success, false otherwise
 */
static bool
bit_r_r_i64(x86::Assembler &a, BIT_OP op, int32 reg_no_dst, int32 reg_no_src)
{
    switch (op) {
        case OR:
            a.or_(regs_i64[reg_no_dst], regs_i64[reg_no_src]);
            break;
        case XOR:
            a.xor_(regs_i64[reg_no_dst], regs_i64[reg_no_src]);
            break;
        case AND:
            a.and_(regs_i64[reg_no_dst], regs_i64[reg_no_src]);
            break;
        default:
            bh_assert(0);
            break;
    }
    return true;
}

/**
 * Encode int64 bit operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
bit_imm_imm_to_r_i64(x86::Assembler &a, BIT_OP op, int32 reg_no_dst,
                     int32 data1_src, int64 data2_src)
{
    Imm imm;

    switch (op) {
        case OR:
            imm.setValue(data1_src | data2_src);
            break;
        case XOR:
            imm.setValue(data1_src ^ data2_src);
            break;
        case AND:
            imm.setValue(data1_src & data2_src);
            break;
        default:
            bh_assert(0);
            break;
    }

    a.mov(regs_i64[reg_no_dst], imm);
    return true;
}

/**
 * Encode int64 bit operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
bit_imm_r_to_r_i64(x86::Assembler &a, BIT_OP op, int32 reg_no_dst,
                   int64 data1_src, int32 reg_no2_src)
{
    if (op == AND && data1_src == 0)
        a.xor_(regs_i64[reg_no_dst], regs_i64[reg_no_dst]);
    else if (op == OR && data1_src == -1LL) {
        Imm imm(-1LL);
        a.mov(regs_i64[reg_no_dst], imm);
    }
    else {
        mov_r_to_r_i64(a, reg_no_dst, reg_no2_src);
        return bit_r_imm_i64(a, op, reg_no_dst, data1_src);
    }
    return true;
}

/**
 * Encode int64 bit operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
bit_r_imm_to_r_i64(x86::Assembler &a, BIT_OP op, int32 reg_no_dst,
                   int32 reg_no1_src, int64 data2_src)
{
    return bit_imm_r_to_r_i64(a, op, reg_no_dst, data2_src, reg_no1_src);
}

/**
 * Encode int64 bit operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BIT operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
bit_r_r_to_r_i64(x86::Assembler &a, BIT_OP op, int32 reg_no_dst,
                 int32 reg_no1_src, int32 reg_no2_src)
{
    if (reg_no_dst != reg_no2_src) {
        mov_r_to_r_i64(a, reg_no_dst, reg_no1_src);
        return bit_r_r_i64(a, op, reg_no_dst, reg_no2_src);
    }
    else
        return bit_r_r_i64(a, op, reg_no_dst, reg_no1_src);
    return false;
}

/**
 * Encode int32 shift operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of SHIFT operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
shift_imm_imm_to_r_i32(x86::Assembler &a, SHIFT_OP op, int32 reg_no_dst,
                       int32 data1_src, int32 data2_src)
{
    int32 data;
    switch (op) {
        case SHL:
        {
            data = data1_src << data2_src;
            break;
        }
        case SHRS:
        {
            data = data1_src >> data2_src;
            break;
        }
        case SHRU:
        {
            data = ((uint32)data1_src) >> data2_src;
            break;
        }
        case ROTL:
        {
            data = (data1_src << data2_src)
                   | (((uint32)data1_src) >> (32 - data2_src));
            break;
        }
        case ROTR:
        {
            data = (((uint32)data1_src) >> data2_src)
                   | (data1_src << (32 - data2_src));
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

    return mov_imm_to_r_i32(a, reg_no_dst, data);
fail:
    return false;
}

/**
 * Encode int32 shift operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of SHIFT operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
shift_imm_r_to_r_i32(x86::Assembler &a, SHIFT_OP op, int32 reg_no_dst,
                     int32 data1_src, int32 reg_no2_src)
{
    /* Should have been optimized by previous lower */
    bh_assert(0);
    (void)a;
    (void)op;
    (void)reg_no_dst;
    (void)data1_src;
    (void)reg_no2_src;
    return false;
}

/**
 * Encode int32 shift operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of SHIFT operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
shift_r_imm_to_r_i32(x86::Assembler &a, SHIFT_OP op, int32 reg_no_dst,
                     int32 reg_no1_src, int32 data2_src)
{
    /* SHL/SHA/SHR r/m32, imm8 */
    Imm imm((uint8)data2_src);

    mov_r_to_r_i32(a, reg_no_dst, reg_no1_src);
    switch (op) {
        case SHL:
        {
            a.shl(regs_i32[reg_no_dst], imm);
            break;
        }
        case SHRS:
        {
            a.sar(regs_i32[reg_no_dst], imm);
            break;
        }
        case SHRU:
        {
            a.shr(regs_i32[reg_no_dst], imm);
            break;
        }
        case ROTL:
        {
            a.rol(regs_i32[reg_no_dst], imm);
            break;
        }
        case ROTR:
        {
            a.ror(regs_i32[reg_no_dst], imm);
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

/**
 * Encode int32 shift operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of shift operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
shift_r_r_to_r_i32(x86::Assembler &a, SHIFT_OP op, int32 reg_no_dst,
                   int32 reg_no1_src, int32 reg_no2_src)
{
    /* should be CL */
    if (reg_no2_src != REG_ECX_IDX)
        return false;

    mov_r_to_r_i32(a, reg_no_dst, reg_no1_src);

    switch (op) {
        case SHL:
        {
            a.shl(regs_i32[reg_no_dst], x86::cl);
            break;
        }
        case SHRS:
        {
            a.sar(regs_i32[reg_no_dst], x86::cl);
            break;
        }
        case SHRU:
        {
            a.shr(regs_i32[reg_no_dst], x86::cl);
            break;
        }
        case ROTL:
        {
            a.rol(regs_i32[reg_no_dst], x86::cl);
            break;
        }
        case ROTR:
        {
            a.ror(regs_i32[reg_no_dst], x86::cl);
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

/**
 * Encode int64 shift operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of SHIFT operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
shift_imm_imm_to_r_i64(x86::Assembler &a, SHIFT_OP op, int32 reg_no_dst,
                       int64 data1_src, int64 data2_src)
{
    int64 data;

    switch (op) {
        case SHL:
        {
            data = data1_src << data2_src;
            break;
        }
        case SHRS:
        {
            data = data1_src >> data2_src;
            break;
        }
        case SHRU:
        {
            data = ((uint64)data1_src) >> data2_src;
            break;
        }
        case ROTL:
        {
            data = (data1_src << data2_src)
                   | (((uint64)data1_src) >> (64LL - data2_src));
            break;
        }
        case ROTR:
        {
            data = (((uint64)data1_src) >> data2_src)
                   | (data1_src << (64LL - data2_src));
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

    return mov_imm_to_r_i64(a, reg_no_dst, data);
fail:
    return false;
}

/**
 * Encode int64 shift operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of SHIFT operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
shift_imm_r_to_r_i64(x86::Assembler &a, SHIFT_OP op, int32 reg_no_dst,
                     int64 data1_src, int32 reg_no2_src)
{
    /* Should have been optimized by previous lower */
    bh_assert(0);
    (void)a;
    (void)op;
    (void)reg_no_dst;
    (void)data1_src;
    (void)reg_no2_src;
    return false;
}

/**
 * Encode int64 shift operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of SHIFT operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
shift_r_imm_to_r_i64(x86::Assembler &a, SHIFT_OP op, int32 reg_no_dst,
                     int32 reg_no1_src, int64 data2_src)
{
    /* SHL/SHA/SHR r/m64, imm8 */
    Imm imm((uint8)data2_src);

    mov_r_to_r_i64(a, reg_no_dst, reg_no1_src);
    switch (op) {
        case SHL:
        {
            a.shl(regs_i64[reg_no_dst], imm);
            break;
        }
        case SHRS:
        {
            a.sar(regs_i64[reg_no_dst], imm);
            break;
        }
        case SHRU:
        {
            a.shr(regs_i64[reg_no_dst], imm);
            break;
        }
        case ROTL:
        {
            a.rol(regs_i64[reg_no_dst], imm);
            break;
        }
        case ROTR:
        {
            a.ror(regs_i64[reg_no_dst], imm);
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

/**
 * Encode int64 shift operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of shift operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
shift_r_r_to_r_i64(x86::Assembler &a, SHIFT_OP op, int32 reg_no_dst,
                   int32 reg_no1_src, int32 reg_no2_src)
{
    /* should be CL */
    if (reg_no2_src != REG_ECX_IDX)
        return false;

    mov_r_to_r_i64(a, reg_no_dst, reg_no1_src);

    switch (op) {
        case SHL:
        {
            a.shl(regs_i64[reg_no_dst], x86::cl);
            break;
        }
        case SHRS:
        {
            a.sar(regs_i64[reg_no_dst], x86::cl);
            break;
        }
        case SHRU:
        {
            a.shr(regs_i64[reg_no_dst], x86::cl);
            break;
        }
        case ROTL:
        {
            a.rol(regs_i64[reg_no_dst], x86::cl);
            break;
        }
        case ROTR:
        {
            a.ror(regs_i64[reg_no_dst], x86::cl);
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

/**
 * Encode int32 cmp operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_imm_imm_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 data1_src,
                     int32 data2_src)
{
    Imm imm(data1_src);
    a.mov(regs_i32[REG_I32_FREE_IDX], imm);
    imm.setValue(data2_src);
    a.cmp(regs_i32[REG_I32_FREE_IDX], imm);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode int32 cmp operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_imm_r_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 data1_src,
                   int32 reg_no2_src)
{
    Imm imm(data1_src);
    a.mov(regs_i32[REG_I32_FREE_IDX], imm);
    a.cmp(regs_i32[REG_I32_FREE_IDX], regs_i32[reg_no2_src]);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode int32 cmp operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_r_imm_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no1_src,
                   int32 data2_src)
{
    Imm imm(data2_src);
    a.cmp(regs_i32[reg_no1_src], imm);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode int32 cmp operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_r_r_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no1_src,
                 int32 reg_no2_src)
{
    a.cmp(regs_i32[reg_no1_src], regs_i32[reg_no2_src]);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode int64 cmp operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_imm_imm_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int64 data1_src,
                     int64 data2_src)
{
    /* imm -> m64 */
    const JitHardRegInfo *hreg_info = jit_codegen_get_hreg_info();
    x86::Mem mem = x86::qword_ptr(regs_i64[hreg_info->exec_env_hreg_index],
                                  offsetof(WASMExecEnv, jit_cache));
    Imm imm(data2_src);
    mov_imm_to_m(a, mem, imm, 8);

    a.mov(regs_i64[REG_I64_FREE_IDX], data1_src);
    a.cmp(regs_i64[REG_I64_FREE_IDX], mem);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode int64 cmp operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_imm_r_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int64 data1_src,
                   int32 reg_no2_src)
{
    Imm imm(data1_src);
    a.mov(regs_i64[REG_I64_FREE_IDX], imm);
    a.cmp(regs_i64[REG_I64_FREE_IDX], regs_i64[reg_no2_src]);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode int64 cmp operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_r_imm_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no1_src,
                   int64 data2_src)
{
    Imm imm(data2_src);

    if (data2_src >= INT32_MIN && data2_src <= INT32_MAX) {
        imm.setValue((int32)data2_src);
        a.cmp(regs_i64[reg_no1_src], imm);
    }
    else {
        a.mov(regs_i64[REG_I64_FREE_IDX], imm);
        a.cmp(regs_i64[reg_no1_src], regs_i64[REG_I64_FREE_IDX]);
    }
    (void)reg_no_dst;
    return true;
}

/**
 * Encode int64 cmp operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_r_r_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no1_src,
                 int32 reg_no2_src)
{
    a.cmp(regs_i64[reg_no1_src], regs_i64[reg_no2_src]);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode float cmp operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_r_r_to_r_f32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no1_src,
                 int32 reg_no2_src)
{
    a.comiss(regs_float[reg_no1_src], regs_float[reg_no2_src]);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode float cmp operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_imm_imm_to_r_f32(x86::Assembler &a, int32 reg_no_dst, float data1_src,
                     float data2_src)
{
    /* should have been optimized in the frontend */
    bh_assert(0);
    (void)a;
    (void)reg_no_dst;
    (void)data1_src;
    (void)data2_src;
    return false;
}

/**
 * Encode float cmp operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_imm_r_to_r_f32(x86::Assembler &a, int32 reg_no_dst, float data1_src,
                   int32 reg_no2_src)
{
    mov_imm_to_r_f32(a, REG_F32_FREE_IDX, data1_src);
    a.comiss(regs_float[REG_F32_FREE_IDX], regs_float[reg_no2_src]);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode float cmp operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_r_imm_to_r_f32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no1_src,
                   float data2_src)
{
    mov_imm_to_r_f32(a, REG_F32_FREE_IDX, data2_src);
    a.comiss(regs_float[reg_no1_src], regs_float[REG_F32_FREE_IDX]);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode double cmp operation of reg and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_r_r_to_r_f64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no1_src,
                 int32 reg_no2_src)
{
    a.comisd(regs_float[reg_no1_src], regs_float[reg_no2_src]);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode double cmp operation of imm and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_imm_imm_to_r_f64(x86::Assembler &a, int32 reg_no_dst, double data1_src,
                     double data2_src)
{
    /* should have been optimized in the frontend */
    bh_assert(0);
    (void)a;
    (void)reg_no_dst;
    (void)data1_src;
    (void)data2_src;
    return false;
}

/**
 * Encode double cmp operation of imm and reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param data1_src the first src immediate data
 * @param reg_no2_src the reg no of second src register data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_imm_r_to_r_f64(x86::Assembler &a, int32 reg_no_dst, double data1_src,
                   int32 reg_no2_src)
{
    mov_imm_to_r_f64(a, REG_F64_FREE_IDX, data1_src);
    a.comisd(regs_float[REG_F64_FREE_IDX], regs_float[reg_no2_src]);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode double cmp operation of reg and imm, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of cmp operation
 * @param reg_no_dst the no of register
 * @param reg_no1_src the reg no of first src register data
 * @param data2_src the second src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cmp_r_imm_to_r_f64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no1_src,
                   double data2_src)
{
    mov_imm_to_r_f64(a, REG_F64_FREE_IDX, data2_src);
    a.comisd(regs_float[reg_no1_src], regs_float[REG_F64_FREE_IDX]);
    (void)reg_no_dst;
    return true;
}

/**
 * Encode insn ld: LD_type r0, r1, r2
 * @param kind the data kind, such as I32, I64, F32 and F64
 * @param bytes_dst the byte number of dst data
 * @param is_signed the data is signed or unsigned
 */
#define LD_R_R_R(kind, bytes_dst, is_signed)                                  \
    do {                                                                      \
        int32 reg_no_dst = 0, reg_no_base = 0, reg_no_offset = 0;             \
        int32 base = 0, offset = 0;                                           \
        bool _ret = false;                                                    \
                                                                              \
        if (jit_reg_is_const(r1)) {                                           \
            CHECK_KIND(r1, JIT_REG_KIND_I32);                                 \
        }                                                                     \
        else {                                                                \
            CHECK_KIND(r1, JIT_REG_KIND_I64);                                 \
        }                                                                     \
        if (jit_reg_is_const(r2)) {                                           \
            CHECK_KIND(r2, JIT_REG_KIND_I32);                                 \
        }                                                                     \
        else {                                                                \
            CHECK_KIND(r2, JIT_REG_KIND_I64);                                 \
        }                                                                     \
                                                                              \
        reg_no_dst = jit_reg_no(r0);                                          \
        CHECK_REG_NO(reg_no_dst, jit_reg_kind(r0));                           \
        if (jit_reg_is_const(r1))                                             \
            base = jit_cc_get_const_I32(cc, r1);                              \
        else {                                                                \
            reg_no_base = jit_reg_no(r1);                                     \
            CHECK_REG_NO(reg_no_base, jit_reg_kind(r1));                      \
        }                                                                     \
        if (jit_reg_is_const(r2))                                             \
            offset = jit_cc_get_const_I32(cc, r2);                            \
        else {                                                                \
            reg_no_offset = jit_reg_no(r2);                                   \
            CHECK_REG_NO(reg_no_offset, jit_reg_kind(r2));                    \
        }                                                                     \
                                                                              \
        if (jit_reg_is_const(r1)) {                                           \
            if (jit_reg_is_const(r2))                                         \
                _ret = ld_r_from_base_imm_offset_imm(                         \
                    a, bytes_dst, JIT_REG_KIND_##kind, is_signed, reg_no_dst, \
                    base, offset);                                            \
            else                                                              \
                _ret = ld_r_from_base_imm_offset_r(                           \
                    a, bytes_dst, JIT_REG_KIND_##kind, is_signed, reg_no_dst, \
                    base, reg_no_offset);                                     \
        }                                                                     \
        else if (jit_reg_is_const(r2))                                        \
            _ret = ld_r_from_base_r_offset_imm(                               \
                a, bytes_dst, JIT_REG_KIND_##kind, is_signed, reg_no_dst,     \
                reg_no_base, offset);                                         \
        else                                                                  \
            _ret = ld_r_from_base_r_offset_r(                                 \
                a, bytes_dst, JIT_REG_KIND_##kind, is_signed, reg_no_dst,     \
                reg_no_base, reg_no_offset);                                  \
        if (!_ret)                                                            \
            GOTO_FAIL;                                                        \
    } while (0)

/**
 * Encode insn sd: ST_type r0, r1, r2
 * @param kind the data kind, such as I32, I64, F32 and F64
 * @param bytes_dst the byte number of dst data
 * @param atomic whether it's atomic store
 */
#define ST_R_R_R(kind, type, bytes_dst, atomic)                                \
    do {                                                                       \
        type data_src = 0;                                                     \
        int32 reg_no_src = 0, reg_no_base = 0, reg_no_offset = 0;              \
        int32 base = 0, offset = 0;                                            \
        bool _ret = false;                                                     \
                                                                               \
        if (jit_reg_is_const(r1)) {                                            \
            CHECK_KIND(r1, JIT_REG_KIND_I32);                                  \
        }                                                                      \
        else {                                                                 \
            CHECK_KIND(r1, JIT_REG_KIND_I64);                                  \
        }                                                                      \
        if (jit_reg_is_const(r2)) {                                            \
            CHECK_KIND(r2, JIT_REG_KIND_I32);                                  \
        }                                                                      \
        else {                                                                 \
            CHECK_KIND(r2, JIT_REG_KIND_I64);                                  \
        }                                                                      \
                                                                               \
        if (jit_reg_is_const(r0))                                              \
            data_src = jit_cc_get_const_##kind(cc, r0);                        \
        else {                                                                 \
            reg_no_src = jit_reg_no(r0);                                       \
            CHECK_REG_NO(reg_no_src, jit_reg_kind(r0));                        \
        }                                                                      \
        if (jit_reg_is_const(r1))                                              \
            base = jit_cc_get_const_I32(cc, r1);                               \
        else {                                                                 \
            reg_no_base = jit_reg_no(r1);                                      \
            CHECK_REG_NO(reg_no_base, jit_reg_kind(r1));                       \
        }                                                                      \
        if (jit_reg_is_const(r2))                                              \
            offset = jit_cc_get_const_I32(cc, r2);                             \
        else {                                                                 \
            reg_no_offset = jit_reg_no(r2);                                    \
            CHECK_REG_NO(reg_no_offset, jit_reg_kind(r2));                     \
        }                                                                      \
                                                                               \
        if (jit_reg_is_const(r0)) {                                            \
            if (jit_reg_is_const(r1)) {                                        \
                if (jit_reg_is_const(r2))                                      \
                    _ret = st_imm_to_base_imm_offset_imm(                      \
                        a, bytes_dst, &data_src, base, offset, atomic);        \
                else                                                           \
                    _ret = st_imm_to_base_imm_offset_r(                        \
                        a, bytes_dst, &data_src, base, reg_no_offset, atomic); \
            }                                                                  \
            else if (jit_reg_is_const(r2))                                     \
                _ret = st_imm_to_base_r_offset_imm(                            \
                    a, bytes_dst, &data_src, reg_no_base, offset, atomic);     \
            else                                                               \
                _ret = st_imm_to_base_r_offset_r(a, bytes_dst, &data_src,      \
                                                 reg_no_base, reg_no_offset,   \
                                                 atomic);                      \
        }                                                                      \
        else if (jit_reg_is_const(r1)) {                                       \
            if (jit_reg_is_const(r2))                                          \
                _ret = st_r_to_base_imm_offset_imm(                            \
                    a, bytes_dst, JIT_REG_KIND_##kind, reg_no_src, base,       \
                    offset, atomic);                                           \
            else                                                               \
                _ret = st_r_to_base_imm_offset_r(                              \
                    a, bytes_dst, JIT_REG_KIND_##kind, reg_no_src, base,       \
                    reg_no_offset, atomic);                                    \
        }                                                                      \
        else if (jit_reg_is_const(r2))                                         \
            _ret = st_r_to_base_r_offset_imm(a, bytes_dst,                     \
                                             JIT_REG_KIND_##kind, reg_no_src,  \
                                             reg_no_base, offset, atomic);     \
        else                                                                   \
            _ret = st_r_to_base_r_offset_r(a, bytes_dst, JIT_REG_KIND_##kind,  \
                                           reg_no_src, reg_no_base,            \
                                           reg_no_offset, atomic);             \
        if (!_ret)                                                             \
            GOTO_FAIL;                                                         \
    } while (0)

/**
 * Encode insn mov: MOV r0, r1
 * @param kind the data kind, such as I32, I64, F32 and F64
 * @param Type the data type, such as int32, int64, float32, and float64
 * @param type the abbreviation of data type, such as i32, i64, f32, and f64
 * @param bytes_dst the byte number of dst data
 */
#define MOV_R_R(kind, Type, type)                                \
    do {                                                         \
        bool _ret = false;                                       \
        int32 reg_no_dst = 0, reg_no_src = 0;                    \
        CHECK_EQKIND(r0, r1);                                    \
                                                                 \
        CHECK_NCONST(r0);                                        \
        reg_no_dst = jit_reg_no(r0);                             \
        CHECK_REG_NO(reg_no_dst, jit_reg_kind(r0));              \
                                                                 \
        if (jit_reg_is_const(r1)) {                              \
            Type data = jit_cc_get_const_##kind(cc, r1);         \
            _ret = mov_imm_to_r_##type(a, reg_no_dst, data);     \
        }                                                        \
        else {                                                   \
            reg_no_src = jit_reg_no(r1);                         \
            CHECK_REG_NO(reg_no_src, jit_reg_kind(r1));          \
            _ret = mov_r_to_r_##type(a, reg_no_dst, reg_no_src); \
        }                                                        \
        if (!_ret)                                               \
            GOTO_FAIL;                                           \
    } while (0)

/**
 * Encode mov insn, MOV r0, r1
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param r0 dst jit register that contains the dst operand info
 * @param r1 src jit register that contains the src operand info
 *
 * @return true if success, false if failed
 */
static bool
lower_mov(JitCompContext *cc, x86::Assembler &a, JitReg r0, JitReg r1)
{
    switch (jit_reg_kind(r0)) {
        case JIT_REG_KIND_I32:
            MOV_R_R(I32, int32, i32);
            break;
        case JIT_REG_KIND_I64:
            MOV_R_R(I64, int64, i64);
            break;
        case JIT_REG_KIND_F32:
            MOV_R_R(F32, float32, f32);
            break;
        case JIT_REG_KIND_F64:
            MOV_R_R(F64, float64, f64);
            break;
        default:
            LOG_VERBOSE("Invalid reg type of mov: %d\n", jit_reg_kind(r0));
            GOTO_FAIL;
    }

    return true;
fail:
    return false;
}

/**
 * Encode insn neg: NEG r0, r1
 * @param kind the data kind, such as I32, I64, F32 and F64
 * @param Type the data type, such as int32, int64, float32, and float64
 * @param type the abbreviation of data type, such as i32, i64, f32, and f64
 */
#define NEG_R_R(kind, Type, type)                                \
    do {                                                         \
        bool _ret = false;                                       \
        int32 reg_no_dst = 0, reg_no_src = 0;                    \
        CHECK_EQKIND(r0, r1);                                    \
                                                                 \
        CHECK_NCONST(r0);                                        \
        reg_no_dst = jit_reg_no(r0);                             \
        CHECK_REG_NO(reg_no_dst, jit_reg_kind(r0));              \
                                                                 \
        if (jit_reg_is_const(r1)) {                              \
            Type data = jit_cc_get_const_##kind(cc, r1);         \
            _ret = neg_imm_to_r_##type(a, reg_no_dst, data);     \
        }                                                        \
        else {                                                   \
            reg_no_src = jit_reg_no(r1);                         \
            CHECK_REG_NO(reg_no_src, jit_reg_kind(r1));          \
            _ret = neg_r_to_r_##type(a, reg_no_dst, reg_no_src); \
        }                                                        \
        if (!_ret)                                               \
            GOTO_FAIL;                                           \
    } while (0)

/**
 * Encode neg insn, NEG r0, r1
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param r0 dst jit register that contains the dst operand info
 * @param r1 src jit register that contains the src operand info
 *
 * @return true if success, false if failed
 */
static bool
lower_neg(JitCompContext *cc, x86::Assembler &a, JitReg r0, JitReg r1)
{
    switch (jit_reg_kind(r0)) {
        case JIT_REG_KIND_I32:
            NEG_R_R(I32, int32, i32);
            break;
        case JIT_REG_KIND_I64:
            NEG_R_R(I64, int64, i64);
            break;
        case JIT_REG_KIND_F32:
            NEG_R_R(F32, float32, f32);
            break;
        case JIT_REG_KIND_F64:
            NEG_R_R(F64, float64, f64);
            break;
        default:
            LOG_VERBOSE("Invalid reg type of neg: %d\n", jit_reg_kind(r0));
            GOTO_FAIL;
    }

    return true;
fail:
    return false;
}

/**
 * Encode insn convert: I32TOI8 r0, r1, or I32TOI16, I32TOF32, F32TOF64, etc.
 * @param kind0 the dst JIT_REG_KIND, such as I32, I64, F32 and F64
 * @param kind1 the src JIT_REG_KIND, such as I32, I64, F32 and F64
 * @param type0 the dst data type, such as i8, u8, i16, u16, i32, f32, i64, f32,
 * f64
 * @param type1 the src data type, such as i8, u8, i16, u16, i32, f32, i64, f32,
 * f64
 */
#define CONVERT_R_R(kind0, kind1, type0, type1, Type1)                       \
    do {                                                                     \
        bool _ret = false;                                                   \
        int32 reg_no_dst = 0, reg_no_src = 0;                                \
        CHECK_KIND(r0, JIT_REG_KIND_##kind0);                                \
        CHECK_KIND(r1, JIT_REG_KIND_##kind1);                                \
                                                                             \
        CHECK_NCONST(r0);                                                    \
        reg_no_dst = jit_reg_no(r0);                                         \
        CHECK_REG_NO(reg_no_dst, jit_reg_kind(r0));                          \
                                                                             \
        if (jit_reg_is_const(r1)) {                                          \
            Type1 data = jit_cc_get_const_##kind1(cc, r1);                   \
            _ret = convert_imm_##type1##_to_r_##type0(a, reg_no_dst, data);  \
        }                                                                    \
        else {                                                               \
            reg_no_src = jit_reg_no(r1);                                     \
            CHECK_REG_NO(reg_no_src, jit_reg_kind(r1));                      \
            _ret =                                                           \
                convert_r_##type1##_to_r_##type0(a, reg_no_dst, reg_no_src); \
        }                                                                    \
        if (!_ret)                                                           \
            GOTO_FAIL;                                                       \
    } while (0)

/**
 * Encode insn alu: ADD/SUB/MUL/DIV/REM r0, r1, r2
 * @param kind the data kind, such as I32, I64, F32 and F64
 * @param Type the data type, such as int32, int64, float32, and float64
 * @param type the abbreviation of data type, such as i32, i64, f32, and f64
 * @param op the opcode of alu
 */
#define ALU_R_R_R(kind, Type, type, op)                                       \
    do {                                                                      \
        Type data1, data2;                                                    \
        int32 reg_no_dst = 0, reg_no_src1 = 0, reg_no_src2 = 0;               \
        bool _ret = false;                                                    \
                                                                              \
        CHECK_EQKIND(r0, r1);                                                 \
        CHECK_EQKIND(r0, r2);                                                 \
        memset(&data1, 0, sizeof(Type));                                      \
        memset(&data2, 0, sizeof(Type));                                      \
                                                                              \
        reg_no_dst = jit_reg_no(r0);                                          \
        CHECK_REG_NO(reg_no_dst, jit_reg_kind(r0));                           \
        if (jit_reg_is_const(r1))                                             \
            data1 = jit_cc_get_const_##kind(cc, r1);                          \
        else {                                                                \
            reg_no_src1 = jit_reg_no(r1);                                     \
            CHECK_REG_NO(reg_no_src1, jit_reg_kind(r1));                      \
        }                                                                     \
        if (jit_reg_is_const(r2))                                             \
            data2 = jit_cc_get_const_##kind(cc, r2);                          \
        else {                                                                \
            reg_no_src2 = jit_reg_no(r2);                                     \
            CHECK_REG_NO(reg_no_src2, jit_reg_kind(r2));                      \
        }                                                                     \
                                                                              \
        if (jit_reg_is_const(r1)) {                                           \
            if (jit_reg_is_const(r2))                                         \
                _ret =                                                        \
                    alu_imm_imm_to_r_##type(a, op, reg_no_dst, data1, data2); \
            else                                                              \
                _ret = alu_imm_r_to_r_##type(a, op, reg_no_dst, data1,        \
                                             reg_no_src2);                    \
        }                                                                     \
        else if (jit_reg_is_const(r2))                                        \
            _ret =                                                            \
                alu_r_imm_to_r_##type(a, op, reg_no_dst, reg_no_src1, data2); \
        else                                                                  \
            _ret = alu_r_r_to_r_##type(a, op, reg_no_dst, reg_no_src1,        \
                                       reg_no_src2);                          \
        if (!_ret)                                                            \
            GOTO_FAIL;                                                        \
    } while (0)

/**
 * Encode alu insn, ADD/SUB/MUL/DIV/REM r0, r1, r2
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param op the opcode of alu operations
 * @param r0 dst jit register that contains the dst operand info
 * @param r1 src jit register that contains the first src operand info
 * @param r2 src jit register that contains the second src operand info
 *
 * @return true if success, false if failed
 */
static bool
lower_alu(JitCompContext *cc, x86::Assembler &a, ALU_OP op, JitReg r0,
          JitReg r1, JitReg r2)
{
    switch (jit_reg_kind(r0)) {
        case JIT_REG_KIND_I32:
            ALU_R_R_R(I32, int32, i32, op);
            break;
        case JIT_REG_KIND_I64:
            ALU_R_R_R(I64, int64, i64, op);
            break;
        case JIT_REG_KIND_F32:
            ALU_R_R_R(F32, float32, f32, op);
            break;
        case JIT_REG_KIND_F64:
            ALU_R_R_R(F64, float64, f64, op);
            break;
        default:
            LOG_VERBOSE("Invalid reg type of alu: %d\n", jit_reg_kind(r0));
            GOTO_FAIL;
    }

    return true;
fail:
    return false;
}

/**
 * Encode insn bit: AND/OR/XOR r0, r1, r2
 * @param kind the data kind, such as I32, I64
 * @param Type the data type, such as int32, int64
 * @param type the abbreviation of data type, such as i32, i64
 * @param op the opcode of bit operation
 */
#define BIT_R_R_R(kind, Type, type, op)                                       \
    do {                                                                      \
        Type data1, data2;                                                    \
        int32 reg_no_dst = 0, reg_no_src1 = 0, reg_no_src2 = 0;               \
        bool _ret = false;                                                    \
                                                                              \
        CHECK_EQKIND(r0, r1);                                                 \
        CHECK_EQKIND(r0, r2);                                                 \
        memset(&data1, 0, sizeof(Type));                                      \
        memset(&data2, 0, sizeof(Type));                                      \
                                                                              \
        reg_no_dst = jit_reg_no(r0);                                          \
        CHECK_REG_NO(reg_no_dst, jit_reg_kind(r0));                           \
        if (jit_reg_is_const(r1))                                             \
            data1 = jit_cc_get_const_##kind(cc, r1);                          \
        else {                                                                \
            reg_no_src1 = jit_reg_no(r1);                                     \
            CHECK_REG_NO(reg_no_src1, jit_reg_kind(r1));                      \
        }                                                                     \
        if (jit_reg_is_const(r2))                                             \
            data2 = jit_cc_get_const_##kind(cc, r2);                          \
        else {                                                                \
            reg_no_src2 = jit_reg_no(r2);                                     \
            CHECK_REG_NO(reg_no_src2, jit_reg_kind(r2));                      \
        }                                                                     \
                                                                              \
        if (jit_reg_is_const(r1)) {                                           \
            if (jit_reg_is_const(r2))                                         \
                _ret =                                                        \
                    bit_imm_imm_to_r_##type(a, op, reg_no_dst, data1, data2); \
            else                                                              \
                _ret = bit_imm_r_to_r_##type(a, op, reg_no_dst, data1,        \
                                             reg_no_src2);                    \
        }                                                                     \
        else if (jit_reg_is_const(r2))                                        \
            _ret =                                                            \
                bit_r_imm_to_r_##type(a, op, reg_no_dst, reg_no_src1, data2); \
        else                                                                  \
            _ret = bit_r_r_to_r_##type(a, op, reg_no_dst, reg_no_src1,        \
                                       reg_no_src2);                          \
        if (!_ret)                                                            \
            GOTO_FAIL;                                                        \
    } while (0)

/**
 * Encode bit insn, AND/OR/XOR r0, r1, r2
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param op the opcode of bit operations
 * @param r0 dst jit register that contains the dst operand info
 * @param r1 src jit register that contains the first src operand info
 * @param r2 src jit register that contains the second src operand info
 *
 * @return true if success, false if failed
 */
static bool
lower_bit(JitCompContext *cc, x86::Assembler &a, BIT_OP op, JitReg r0,
          JitReg r1, JitReg r2)
{
    switch (jit_reg_kind(r0)) {
        case JIT_REG_KIND_I32:
            BIT_R_R_R(I32, int32, i32, op);
            break;
        case JIT_REG_KIND_I64:
            BIT_R_R_R(I64, int64, i64, op);
            break;
        default:
            LOG_VERBOSE("Invalid reg type of bit: %d\n", jit_reg_kind(r0));
            GOTO_FAIL;
    }

    return true;
fail:
    return false;
}

/**
 * Encode insn shift: SHL/SHRS/SHRU r0, r1, r2
 * @param kind the data kind, such as I32, I64
 * @param Type the data type, such as int32, int64
 * @param type the abbreviation of data type, such as i32, i64
 * @param op the opcode of shift operation
 */
#define SHIFT_R_R_R(kind, Type, type, op)                                  \
    do {                                                                   \
        Type data1, data2;                                                 \
        int32 reg_no_dst = 0, reg_no_src1 = 0, reg_no_src2 = 0;            \
        bool _ret = false;                                                 \
                                                                           \
        CHECK_EQKIND(r0, r1);                                              \
        CHECK_KIND(r2, JIT_REG_KIND_##kind);                               \
        memset(&data1, 0, sizeof(Type));                                   \
        memset(&data2, 0, sizeof(Type));                                   \
                                                                           \
        reg_no_dst = jit_reg_no(r0);                                       \
        CHECK_REG_NO(reg_no_dst, jit_reg_kind(r0));                        \
        if (jit_reg_is_const(r1))                                          \
            data1 = jit_cc_get_const_##kind(cc, r1);                       \
        else {                                                             \
            reg_no_src1 = jit_reg_no(r1);                                  \
            CHECK_REG_NO(reg_no_src1, jit_reg_kind(r1));                   \
        }                                                                  \
        if (jit_reg_is_const(r2))                                          \
            data2 = jit_cc_get_const_##kind(cc, r2);                       \
        else {                                                             \
            reg_no_src2 = jit_reg_no(r2);                                  \
            CHECK_REG_NO(reg_no_src2, jit_reg_kind(r2));                   \
        }                                                                  \
                                                                           \
        if (jit_reg_is_const(r1)) {                                        \
            if (jit_reg_is_const(r2))                                      \
                _ret = shift_imm_imm_to_r_##type(a, op, reg_no_dst, data1, \
                                                 data2);                   \
            else                                                           \
                _ret = shift_imm_r_to_r_##type(a, op, reg_no_dst, data1,   \
                                               reg_no_src2);               \
        }                                                                  \
        else if (jit_reg_is_const(r2))                                     \
            _ret = shift_r_imm_to_r_##type(a, op, reg_no_dst, reg_no_src1, \
                                           data2);                         \
        else                                                               \
            _ret = shift_r_r_to_r_##type(a, op, reg_no_dst, reg_no_src1,   \
                                         reg_no_src2);                     \
        if (!_ret)                                                         \
            GOTO_FAIL;                                                     \
    } while (0)

/**
 * Encode shift insn, SHL/SHRS/SHRU r0, r1, r2
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param op the opcode of shift operations
 * @param r0 dst jit register that contains the dst operand info
 * @param r1 src jit register that contains the first src operand info
 * @param r2 src jit register that contains the second src operand info
 *
 * @return true if success, false if failed
 */
static bool
lower_shift(JitCompContext *cc, x86::Assembler &a, SHIFT_OP op, JitReg r0,
            JitReg r1, JitReg r2)
{
    switch (jit_reg_kind(r0)) {
        case JIT_REG_KIND_I32:
            SHIFT_R_R_R(I32, int32, i32, op);
            break;
        case JIT_REG_KIND_I64:
            SHIFT_R_R_R(I64, int64, i64, op);
            break;
        default:
            LOG_VERBOSE("Invalid reg type of shift: %d\n", jit_reg_kind(r0));
            GOTO_FAIL;
    }

    return true;
fail:
    return false;
}

/**
 * Encode int32 bitcount operation of reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BITCOUNT operation
 * @param reg_no_dst the no of register
 * @param reg_no_src the reg no of first src register data
 *
 * @return true if success, false otherwise
 */
static bool
bitcount_r_to_r_i32(x86::Assembler &a, BITCOUNT_OP op, int32 reg_no_dst,
                    int32 reg_no_src)
{
    switch (op) {
        case CLZ:
            a.lzcnt(regs_i32[reg_no_dst], regs_i32[reg_no_src]);
            break;
        case CTZ:
            a.tzcnt(regs_i32[reg_no_dst], regs_i32[reg_no_src]);
            break;
        case POPCNT:
            a.popcnt(regs_i32[reg_no_dst], regs_i32[reg_no_src]);
            break;
        default:
            bh_assert(0);
            return false;
    }
    return true;
}

/**
 * Encode int64 bitcount operation of reg, and save result to reg
 *
 * @param a the assembler to emit the code
 * @param op the opcode of BITCOUNT operation
 * @param reg_no_dst the no of register
 * @param reg_no_src the reg no of first src register data
 *
 * @return true if success, false otherwise
 */
static bool
bitcount_r_to_r_i64(x86::Assembler &a, BITCOUNT_OP op, int32 reg_no_dst,
                    int32 reg_no_src)
{
    switch (op) {
        case CLZ:
            a.lzcnt(regs_i64[reg_no_dst], regs_i64[reg_no_src]);
            break;
        case CTZ:
            a.tzcnt(regs_i64[reg_no_dst], regs_i64[reg_no_src]);
            break;
        case POPCNT:
            a.popcnt(regs_i64[reg_no_dst], regs_i64[reg_no_src]);
            break;
        default:
            bh_assert(0);
            return false;
    }
    return true;
}

/**
 * Encode insn bitcount: CLZ/CTZ/POPCNT r0, r1
 * @param kind the data kind, such as I32, I64
 * @param Type the data type, such as int32, int64
 * @param type the abbreviation of data type, such as i32, i64
 * @param op the opcode of bit operation
 */
#define BITCOUNT_R_R(kind, Type, type, op)                          \
    do {                                                            \
        int32 reg_no_dst = 0, reg_no_src = 0;                       \
                                                                    \
        CHECK_EQKIND(r0, r1);                                       \
        CHECK_NCONST(r0);                                           \
        CHECK_NCONST(r1);                                           \
                                                                    \
        reg_no_dst = jit_reg_no(r0);                                \
        CHECK_REG_NO(reg_no_dst, jit_reg_kind(r0));                 \
        reg_no_src = jit_reg_no(r1);                                \
        CHECK_REG_NO(reg_no_src, jit_reg_kind(r1));                 \
        if (!bitcount_r_to_r_##type(a, op, reg_no_dst, reg_no_src)) \
            GOTO_FAIL;                                              \
    } while (0)

/**
 * Encode bitcount insn, CLZ/CTZ/POPCNT r0, r1
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param op the opcode of bitcount operations
 * @param r0 dst jit register that contains the dst operand info
 * @param r1 src jit register that contains the src operand info
 *
 * @return true if success, false if failed
 */
static bool
lower_bitcount(JitCompContext *cc, x86::Assembler &a, BITCOUNT_OP op, JitReg r0,
               JitReg r1)
{
    switch (jit_reg_kind(r0)) {
        case JIT_REG_KIND_I32:
            BITCOUNT_R_R(I32, int32, i32, op);
            break;
        case JIT_REG_KIND_I64:
            BITCOUNT_R_R(I64, int64, i64, op);
            break;
        default:
            LOG_VERBOSE("Invalid reg type of bit: %d\n", jit_reg_kind(r0));
            GOTO_FAIL;
    }

    return true;
fail:
    return false;
}

/**
 * Encode insn cmp: CMP r0, r1, r2
 * @param kind the data kind, such as I32, I64, F32 and F64
 * @param Type the data type, such as int32, int64, float32, and float64
 * @param type the abbreviation of data type, such as i32, i64, f32, and f64
 */
#define CMP_R_R_R(kind, Type, type)                                           \
    do {                                                                      \
        Type data1, data2;                                                    \
        int32 reg_no_dst = 0, reg_no_src1 = 0, reg_no_src2 = 0;               \
        bool _ret = false;                                                    \
                                                                              \
        CHECK_KIND(r0, JIT_REG_KIND_I32);                                     \
        CHECK_KIND(r1, JIT_REG_KIND_##kind);                                  \
        CHECK_EQKIND(r1, r2);                                                 \
        memset(&data1, 0, sizeof(Type));                                      \
        memset(&data2, 0, sizeof(Type));                                      \
                                                                              \
        reg_no_dst = jit_reg_no(r0);                                          \
        CHECK_REG_NO(reg_no_dst, jit_reg_kind(r0));                           \
        if (jit_reg_is_const(r1))                                             \
            data1 = jit_cc_get_const_##kind(cc, r1);                          \
        else {                                                                \
            reg_no_src1 = jit_reg_no(r1);                                     \
            CHECK_REG_NO(reg_no_src1, jit_reg_kind(r1));                      \
        }                                                                     \
        if (jit_reg_is_const(r2))                                             \
            data2 = jit_cc_get_const_##kind(cc, r2);                          \
        else {                                                                \
            reg_no_src2 = jit_reg_no(r2);                                     \
            CHECK_REG_NO(reg_no_src2, jit_reg_kind(r2));                      \
        }                                                                     \
                                                                              \
        if (jit_reg_is_const(r1)) {                                           \
            if (jit_reg_is_const(r2))                                         \
                _ret = cmp_imm_imm_to_r_##type(a, reg_no_dst, data1, data2);  \
            else                                                              \
                _ret =                                                        \
                    cmp_imm_r_to_r_##type(a, reg_no_dst, data1, reg_no_src2); \
        }                                                                     \
        else if (jit_reg_is_const(r2))                                        \
            _ret = cmp_r_imm_to_r_##type(a, reg_no_dst, reg_no_src1, data2);  \
        else                                                                  \
            _ret =                                                            \
                cmp_r_r_to_r_##type(a, reg_no_dst, reg_no_src1, reg_no_src2); \
        if (!_ret)                                                            \
            GOTO_FAIL;                                                        \
    } while (0)

/**
 * Encode cmp insn, CMP r0, r1, r2
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param r0 dst jit register that contains the dst operand info
 * @param r1 condition jit register
 * @param r2 src jit register that contains the first src operand info
 * @param r3 src jit register that contains the second src operand info
 *
 * @return true if success, false if failed
 */
static bool
lower_cmp(JitCompContext *cc, x86::Assembler &a, JitReg r0, JitReg r1,
          JitReg r2)
{
    switch (jit_reg_kind(r1)) {
        case JIT_REG_KIND_I32:
            CMP_R_R_R(I32, int32, i32);
            cc->last_cmp_on_fp = false;
            break;
        case JIT_REG_KIND_I64:
            CMP_R_R_R(I64, int64, i64);
            cc->last_cmp_on_fp = false;
            break;
        case JIT_REG_KIND_F32:
            CMP_R_R_R(F32, float32, f32);
            cc->last_cmp_on_fp = true;
            break;
        case JIT_REG_KIND_F64:
            CMP_R_R_R(F64, float64, f64);
            cc->last_cmp_on_fp = true;
            break;
        default:
            cc->last_cmp_on_fp = false;
            LOG_VERBOSE("Invalid reg type of cmp: %d\n", jit_reg_kind(r1));
            GOTO_FAIL;
    }

    return true;
fail:
    return false;
}

/**
 * Encode detecting the cmp flags in reg, and jmp to the relative address
 * according to the condition opcode
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param op the condition opcode to jmp
 * @param offset the relative offset to jmp when the contidtion meeted
 *
 * @return return the next address of native code after encoded
 */
static bool
cmp_r_and_jmp_relative(JitCompContext *cc, x86::Assembler &a, COND_OP op,
                       int32 offset)
{
    Imm target(INT32_MAX);
    char *stream;
    bool fp_cmp = cc->last_cmp_on_fp;

    bh_assert(!fp_cmp || (fp_cmp && (op == GTS || op == GES)));

    switch (op) {
        case EQ:
        {
            a.je(target);
            break;
        }
        case NE:
        {
            a.jne(target);
            break;
        }
        case GTS:
        {
            if (fp_cmp) {
                a.ja(target);
            }
            else {
                a.jg(target);
            }
            break;
        }
        case LES:
        {
            a.jng(target);
            break;
        }
        case GES:
        {
            if (fp_cmp) {
                a.jae(target);
            }
            else {
                a.jnl(target);
            }
            break;
        }
        case LTS:
        {
            a.jl(target);
            break;
        }
        case GTU:
        {
            a.ja(target);
            break;
        }
        case LEU:
        {
            a.jna(target);
            break;
        }
        case GEU:
        {
            a.jae(target);
            break;
        }
        case LTU:
        {
            a.jb(target);
            break;
        }
        default:
        {
            bh_assert(0);
            break;
        }
    }

    JitErrorHandler *err_handler = (JitErrorHandler *)a.code()->errorHandler();

    if (!err_handler->err) {
        /* The offset written by asmjit is always 0, we patch it again */
        stream = (char *)a.code()->sectionById(0)->buffer().data()
                 + a.code()->sectionById(0)->buffer().size() - 6;
        *(int32 *)(stream + 2) = offset;
    }
    return true;
}

/**
 * Encode select insn, SELECT r0, r1, r2, r3
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param r0 dst jit register that contains the dst operand info
 * @param r1 src jit register that contains the first src operand info
 * @param r2 src jit register that contains the second src operand info
 *
 * @return true if success, false if failed
 */
/* TODO: optimize with setcc */
static bool
lower_select(JitCompContext *cc, x86::Assembler &a, COND_OP op, JitReg r0,
             JitReg r1, JitReg r2, JitReg r3)
{
    JitErrorHandler err_handler;
    Environment env(Arch::kX64);
    CodeHolder code1, code2;
    char *stream_mov1, *stream_mov2;
    uint32 size_mov1, size_mov2;

    code1.init(env);
    code1.setErrorHandler(&err_handler);
    x86::Assembler a1(&code1);

    code2.init(env);
    code2.setErrorHandler(&err_handler);
    x86::Assembler a2(&code2);

    CHECK_NCONST(r0);
    CHECK_NCONST(r1);
    CHECK_KIND(r1, JIT_REG_KIND_I32);

    if (r0 == r3 && r0 != r2 && !cc->last_cmp_on_fp) {
        JitReg r_tmp;

        /* For i32/i64, exchange r2 and r3 to make r0 equal to r2,
           so as to decrease possible execution instructions.
           For f32/f64 comparison, should not change the order as
           the result of comparison with NaN may be different. */
        r_tmp = r2;
        r2 = r3;
        r3 = r_tmp;
        op = not_cond(op);
    }

    if (!lower_mov(cc, a1, r0, r2))
        GOTO_FAIL;

    if (!lower_mov(cc, a2, r0, r3))
        GOTO_FAIL;

    stream_mov1 = (char *)a1.code()->sectionById(0)->buffer().data();
    size_mov1 = a1.code()->sectionById(0)->buffer().size();
    stream_mov2 = (char *)a2.code()->sectionById(0)->buffer().data();
    size_mov2 = a2.code()->sectionById(0)->buffer().size();

    if (r0 != r2) {
        a.embedDataArray(TypeId::kInt8, stream_mov1, size_mov1);
    }

    if (r3 && r0 != r3) {
        if (!cmp_r_and_jmp_relative(cc, a, op, (int32)size_mov2))
            return false;
        a.embedDataArray(TypeId::kInt8, stream_mov2, size_mov2);
    }

    return true;
fail:
    return false;
}

/* jmp to dst label */
#define JMP_TO_LABEL(label_dst, label_src)                                 \
    do {                                                                   \
        if (label_is_ahead(cc, label_dst, label_src)) {                    \
            JitErrorHandler *err_handler =                                 \
                (JitErrorHandler *)a.code()->errorHandler();               \
            int32 _offset;                                                 \
            char *stream;                                                  \
            Imm imm(INT32_MAX);                                            \
            a.jmp(imm);                                                    \
            if (!err_handler->err) {                                       \
                /* The offset written by asmjit is always 0, we patch it   \
                   again, 6 is the size of jmp instruciton */              \
                stream = (char *)a.code()->sectionById(0)->buffer().data() \
                         + a.code()->sectionById(0)->buffer().size() - 6;  \
                _offset = label_offsets[label_dst]                         \
                          - a.code()->sectionById(0)->buffer().size();     \
                *(int32 *)(stream + 2) = _offset;                          \
            }                                                              \
        }                                                                  \
        else {                                                             \
            if (!jmp_from_label_to_label(a, jmp_info_list, label_dst,      \
                                         label_src))                       \
                GOTO_FAIL;                                                 \
        }                                                                  \
    } while (0)

/**
 * Encode branch insn, BEQ/BNE/../BLTU r0, r1, r2
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param jmp_info_list the jmp info list
 * @param r0 dst jit register that contains the dst operand info
 * @param r1 src jit register that contains the first src operand info
 * @param r2 src jit register that contains the second src operand info
 * @param is_last_insn if current insn is the last insn of current block
 *
 * @return true if success, false if failed
 */
static bool
lower_branch(JitCompContext *cc, x86::Assembler &a, bh_list *jmp_info_list,
             int32 label_src, COND_OP op, JitReg r0, JitReg r1, JitReg r2,
             bool is_last_insn)
{
    int32 label_dst;

    CHECK_NCONST(r0);
    CHECK_KIND(r0, JIT_REG_KIND_I32);
    CHECK_KIND(r1, JIT_REG_KIND_L32);

    CHECK_REG_NO(jit_reg_no(r0), jit_reg_kind(r0));

    label_dst = jit_reg_no(r1);
    if (label_dst < (int32)jit_cc_label_num(cc) - 1 && is_last_insn
        && label_is_neighboring(cc, label_src, label_dst)
        && !cc->last_cmp_on_fp) {
        JitReg r_tmp;

        r_tmp = r1;
        r1 = r2;
        r2 = r_tmp;
        op = not_cond(op);
    }

    if (!cmp_r_and_jmp_label(cc, a, jmp_info_list, label_src, op, r1, r2,
                             is_last_insn))
        GOTO_FAIL;

    return true;
fail:
    return false;
}

/**
 * Encode lookupswitch with key of immediate data
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param jmp_info_list the jmp info list
 * @param label_offsets the offsets of each label
 * @param label_src the index of src label
 * @param key the entry key
 * @param opnd the lookup switch operand
 * @param is_last_insn if current insn is the last insn of current block
 *
 * @return true if success, false if failed
 */
static bool
lookupswitch_imm(JitCompContext *cc, x86::Assembler &a, bh_list *jmp_info_list,
                 uint32 *label_offsets, int32 label_src, int32 key,
                 const JitOpndLookupSwitch *opnd, bool is_last_insn)
{
    uint32 i;
    int32 label_dst;

    for (i = 0; i < opnd->match_pairs_num; i++)
        if (key == opnd->match_pairs[i].value) {
            label_dst = jit_reg_no(opnd->match_pairs[i].target);
            if (!(is_last_insn
                  && label_is_neighboring(cc, label_src, label_dst))) {
                JMP_TO_LABEL(label_dst, label_src);
            }
            return true;
        }

    if (opnd->default_target) {
        label_dst = jit_reg_no(opnd->default_target);
        if (!(is_last_insn && label_is_neighboring(cc, label_src, label_dst))) {
            JMP_TO_LABEL(label_dst, label_src);
        }
    }

    return true;
fail:
    return false;
}

/**
 * Encode detecting lookupswitch entry register and jumping to matched label
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param jmp_info_list the jmp info list
 * @param label_offsets the offsets of each label
 * @param label_src the index of src label
 * @param reg_no the no of entry register
 * @param opnd the lookup switch operand
 * @param is_last_insn if current insn is the last insn of current block
 *
 * @return true if success, false if failed
 */
static bool
lookupswitch_r(JitCompContext *cc, x86::Assembler &a, bh_list *jmp_info_list,
               uint32 *label_offsets, int32 label_src, int32 reg_no,
               const JitOpndLookupSwitch *opnd, bool is_last_insn)
{
    JmpInfo *node;
    Imm imm;
    x86::Mem m;
    uint32 i;
    int32 label_dst = 0;
    char *stream;

    if (opnd->match_pairs_num < 10) {
        /* For small count of branches, it is better to compare
           the key with branch value and jump one by one */
        for (i = 0; i < opnd->match_pairs_num; i++) {
            imm.setValue(opnd->match_pairs[i].value);
            a.cmp(regs_i32[reg_no], imm);

            node = (JmpInfo *)jit_malloc(sizeof(JmpInfo));
            if (!node)
                GOTO_FAIL;

            node->type = JMP_DST_LABEL_REL;
            node->label_src = label_src;
            node->dst_info.label_dst = jit_reg_no(opnd->match_pairs[i].target);
            node->offset = a.code()->sectionById(0)->buffer().size() + 2;
            bh_list_insert(jmp_info_list, node);

            imm.setValue(INT32_MAX);
            a.je(imm);
        }

        if (opnd->default_target) {
            label_dst = jit_reg_no(opnd->default_target);
            if (!(is_last_insn
                  && label_is_neighboring(cc, label_src, label_dst)))
                JMP_TO_LABEL(label_dst, label_src);
        }
    }
    else {
        /* For bigger count of branches, use indirect jump */
        /* unsigned extend to rsi */
        a.mov(regs_i32[REG_I32_FREE_IDX], regs_i32[reg_no]);
        imm.setValue(opnd->match_pairs_num);
        a.cmp(regs_i64[REG_I64_FREE_IDX], imm);

        /* Jump to default label if rsi >= br_count */
        stream = (char *)a.code()->sectionById(0)->buffer().data()
                 + a.code()->sectionById(0)->buffer().size();
        imm.setValue(INT32_MAX);
        a.jb(imm);
        *(uint32 *)(stream + 2) = 6;

        node = (JmpInfo *)jit_calloc(sizeof(JmpInfo));
        if (!node)
            goto fail;

        node->type = JMP_DST_LABEL_REL;
        node->label_src = label_src;
        node->dst_info.label_dst = jit_reg_no(opnd->default_target);
        node->offset = a.code()->sectionById(0)->buffer().size() + 2;
        bh_list_insert(jmp_info_list, node);

        imm.setValue(INT32_MAX);
        a.jmp(imm);

        node = (JmpInfo *)jit_malloc(sizeof(JmpInfo));
        if (!node)
            GOTO_FAIL;

        node->type = JMP_LOOKUPSWITCH_BASE;
        node->offset = a.code()->sectionById(0)->buffer().size() + 2;
        bh_list_insert(jmp_info_list, node);

        /* LookupSwitch table base addr */
        imm.setValue(INT64_MAX);
        a.mov(regs_i64[reg_no], imm);

        /* jmp *(base_addr + rsi * 8) */
        m = x86::ptr(regs_i64[reg_no], regs_i64[REG_I64_FREE_IDX], 3);
        a.jmp(m);

        /* Store each dst label absolute address */
        for (i = 0; i < opnd->match_pairs_num; i++) {
            node = (JmpInfo *)jit_malloc(sizeof(JmpInfo));
            if (!node)
                GOTO_FAIL;

            node->type = JMP_DST_LABEL_ABS;
            node->dst_info.label_dst = jit_reg_no(opnd->match_pairs[i].target);
            node->offset = a.code()->sectionById(0)->buffer().size();
            bh_list_insert(jmp_info_list, node);

            a.embedUInt64(UINT64_MAX);
        }
    }

    return true;
fail:
    return false;
}

/**
 * Encode lookupswitch insn, LOOKUPSWITCH opnd
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param jmp_info_list the jmp info list
 * @param label_offsets the offsets of each label
 * @param label_src the index of src label
 * @param opnd the lookup switch operand
 * @param is_last_insn if current insn is the last insn of current block
 *
 * @return true if success, false if failed
 */
static bool
lower_lookupswitch(JitCompContext *cc, x86::Assembler &a,
                   bh_list *jmp_info_list, uint32 *label_offsets,
                   int32 label_src, const JitOpndLookupSwitch *opnd,
                   bool is_last_insn)
{
    JitReg r0 = opnd->value;
    int32 key, reg_no;

    CHECK_KIND(r0, JIT_REG_KIND_I32);
    CHECK_KIND(opnd->default_target, JIT_REG_KIND_L32);

    if (jit_reg_is_const(r0)) {
        key = jit_cc_get_const_I32(cc, r0);
        if (!lookupswitch_imm(cc, a, jmp_info_list, label_offsets, label_src,
                              key, opnd, is_last_insn))
            GOTO_FAIL;
    }
    else {
        reg_no = jit_reg_no(r0);
        CHECK_I32_REG_NO(reg_no);
        if (!lookupswitch_r(cc, a, jmp_info_list, label_offsets, label_src,
                            reg_no, opnd, is_last_insn))
            GOTO_FAIL;
    }

    return true;
fail:
    return false;
}

/**
 * Encode callnative insn, CALLNATIVE r0, r1, ...
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param insn current insn info
 *
 * @return true if success, false if failed
 */
static bool
lower_callnative(JitCompContext *cc, x86::Assembler &a, JitInsn *insn)
{
    void (*func_ptr)(void);
    JitReg ret_reg, func_reg, arg_reg;
    /* the index of callee saved registers in regs_i64 */
    uint8 regs_arg_idx[] = { REG_RDI_IDX, REG_RSI_IDX, REG_RDX_IDX,
                             REG_RCX_IDX, REG_R8_IDX,  REG_R9_IDX };
    Imm imm;
    uint32 i, opnd_num;
    int32 integer_reg_index = 0, floatpoint_reg_index = 0;

    ret_reg = *(jit_insn_opndv(insn, 0));
    func_reg = *(jit_insn_opndv(insn, 1));
    CHECK_KIND(func_reg, JIT_REG_KIND_I64);
    CHECK_CONST(func_reg);

    func_ptr = (void (*)(void))jit_cc_get_const_I64(cc, func_reg);

    opnd_num = jit_insn_opndv_num(insn);
    for (i = 0; i < opnd_num - 2; i++) {
        /*TODO: if arguments number is greater than 6 */
        bh_assert(integer_reg_index < 6);
        bh_assert(floatpoint_reg_index < 6);

        arg_reg = *(jit_insn_opndv(insn, i + 2));
        switch (jit_reg_kind(arg_reg)) {
            case JIT_REG_KIND_I32:
            {
                int32 reg_no = regs_arg_idx[integer_reg_index++];
                CHECK_I64_REG_NO(reg_no);
                if (jit_reg_is_const(arg_reg)) {
                    mov_imm_to_r_i64(a, reg_no,
                                     (int64)jit_cc_get_const_I32(cc, arg_reg));
                }
                else {
                    int32 arg_reg_no = jit_reg_no(arg_reg);
                    CHECK_I32_REG_NO(arg_reg_no);
                    extend_r32_to_r64(a, reg_no, arg_reg_no, true);
                }
                break;
            }
            case JIT_REG_KIND_I64:
            {
                int32 reg_no = regs_arg_idx[integer_reg_index++];
                CHECK_I64_REG_NO(reg_no);
                if (jit_reg_is_const(arg_reg)) {
                    mov_imm_to_r_i64(a, reg_no,
                                     jit_cc_get_const_I64(cc, arg_reg));
                }
                else {
                    int32 arg_reg_no = jit_reg_no(arg_reg);
                    CHECK_I64_REG_NO(arg_reg_no);
                    mov_r_to_r_i64(a, reg_no, arg_reg_no);
                }
                break;
            }
            case JIT_REG_KIND_F32:
            {
                CHECK_F32_REG_NO((int32)floatpoint_reg_index);
                if (jit_reg_is_const(arg_reg)) {
                    mov_imm_to_r_f32(a, floatpoint_reg_index,
                                     jit_cc_get_const_F32(cc, arg_reg));
                }
                else {
                    int32 arg_reg_no = jit_reg_no(arg_reg);
                    CHECK_F32_REG_NO(arg_reg_no);
                    mov_r_to_r_f32(a, floatpoint_reg_index, arg_reg_no);
                }
                floatpoint_reg_index++;
                break;
            }
            case JIT_REG_KIND_F64:
            {
                CHECK_F64_REG_NO((int32)floatpoint_reg_index);
                if (jit_reg_is_const(arg_reg)) {
                    mov_imm_to_r_f64(a, floatpoint_reg_index,
                                     jit_cc_get_const_F64(cc, arg_reg));
                }
                else {
                    int32 arg_reg_no = jit_reg_no(arg_reg);
                    CHECK_F64_REG_NO(arg_reg_no);
                    mov_r_to_r_f64(a, floatpoint_reg_index, arg_reg_no);
                }
                floatpoint_reg_index++;
                break;
            }
            default:
            {

                bh_assert(0);
                goto fail;
            }
        }
    }

    imm.setValue((uint64)func_ptr);
    a.mov(regs_i64[REG_RAX_IDX], imm);
    a.call(regs_i64[REG_RAX_IDX]);

    if (ret_reg) {
        uint32 ret_reg_no = jit_reg_no(ret_reg);
        if (jit_reg_kind(ret_reg) == JIT_REG_KIND_I64) {
            CHECK_I64_REG_NO(ret_reg_no);
            /* mov res, rax */
            mov_r_to_r_i64(a, ret_reg_no, REG_RAX_IDX);
        }
        else if (jit_reg_kind(ret_reg) == JIT_REG_KIND_F64) {
            CHECK_F64_REG_NO(ret_reg_no);
            /* mov res, xmm0_f64 */
            mov_r_to_r_f64(a, ret_reg_no, 0);
        }
        else {
            bh_assert((jit_reg_kind(ret_reg) == JIT_REG_KIND_I32
                       && ret_reg_no == REG_EAX_IDX)
                      || (jit_reg_kind(ret_reg) == JIT_REG_KIND_F32
                          && ret_reg_no == 0));
        }
    }

    return true;
fail:
    return false;
}

/**
 * Encode callbc insn, CALLBC r0, r1, r2
 *
 * @param cc the compiler context
 * @param a the assembler to emit the code
 * @param jmp_info_list the jmp info list
 * @param label_src the index of src label
 * @param insn current insn info
 *
 * @return true if success, false if failed
 */
static bool
lower_callbc(JitCompContext *cc, x86::Assembler &a, bh_list *jmp_info_list,
             int32 label_src, JitInsn *insn)
{
    JmpInfo *node;
    Imm imm;
    JitReg edx_hreg = jit_reg_new(JIT_REG_KIND_I32, REG_EDX_IDX);
    JitReg rdx_hreg = jit_reg_new(JIT_REG_KIND_I64, REG_RDX_IDX);
    JitReg xmm0_f32_hreg = jit_reg_new(JIT_REG_KIND_F32, 0);
    JitReg xmm0_f64_hreg = jit_reg_new(JIT_REG_KIND_F64, 0);
    JitReg ret_reg = *(jit_insn_opnd(insn, 0));
    JitReg func_reg = *(jit_insn_opnd(insn, 2));
    JitReg func_idx = *(jit_insn_opnd(insn, 3));
    JitReg src_reg;
    int32 func_reg_no;

    /* Load return_jitted_addr from stack */
    x86::Mem m(x86::rbp, cc->jitted_return_address_offset);

    CHECK_KIND(func_reg, JIT_REG_KIND_I64);
    func_reg_no = jit_reg_no(func_reg);
    CHECK_I64_REG_NO(func_reg_no);

    CHECK_KIND(func_idx, JIT_REG_KIND_I32);
    if (jit_reg_is_const(func_idx)) {
        imm.setValue(jit_cc_get_const_I32(cc, func_idx));
        a.mov(regs_i64[REG_RDX_IDX], imm);
    }
    else {
        a.movzx(regs_i64[REG_RDX_IDX], regs_i32[jit_reg_no(func_idx)]);
    }

    node = (JmpInfo *)jit_malloc(sizeof(JmpInfo));
    if (!node)
        GOTO_FAIL;

    node->type = JMP_END_OF_CALLBC;
    node->label_src = label_src;
    node->offset = a.code()->sectionById(0)->buffer().size() + 2;
    bh_list_insert(jmp_info_list, node);

    /* Set next jited addr to glue_ret_jited_addr, 0 will be replaced with
       actual offset after actual code cache is allocated */
    imm.setValue(INT64_MAX);
    a.mov(regs_i64[REG_I64_FREE_IDX], imm);
    a.mov(m, regs_i64[REG_I64_FREE_IDX]);
    a.jmp(regs_i64[func_reg_no]);

    if (ret_reg) {
        switch (jit_reg_kind(ret_reg)) {
            case JIT_REG_KIND_I32:
                src_reg = edx_hreg;
                break;
            case JIT_REG_KIND_I64:
                src_reg = rdx_hreg;
                break;
            case JIT_REG_KIND_F32:
                src_reg = xmm0_f32_hreg;
                break;
            case JIT_REG_KIND_F64:
                src_reg = xmm0_f64_hreg;
                break;
            default:
                bh_assert(0);
                return false;
        }

        if (!lower_mov(cc, a, ret_reg, src_reg))
            return false;
    }
    return true;
fail:
    return false;
}

static bool
lower_returnbc(JitCompContext *cc, x86::Assembler &a, JitInsn *insn)
{
    JitReg edx_hreg = jit_reg_new(JIT_REG_KIND_I32, REG_EDX_IDX);
    JitReg rdx_hreg = jit_reg_new(JIT_REG_KIND_I64, REG_RDX_IDX);
    JitReg xmm0_f32_hreg = jit_reg_new(JIT_REG_KIND_F32, 0);
    JitReg xmm0_f64_hreg = jit_reg_new(JIT_REG_KIND_F64, 0);
    JitReg act_reg = *(jit_insn_opnd(insn, 0));
    JitReg ret_reg = *(jit_insn_opnd(insn, 1));
    JitReg dst_reg;
    int32 act;

    CHECK_CONST(act_reg);
    CHECK_KIND(act_reg, JIT_REG_KIND_I32);

    act = jit_cc_get_const_I32(cc, act_reg);

    if (ret_reg) {
        switch (jit_reg_kind(ret_reg)) {
            case JIT_REG_KIND_I32:
                dst_reg = edx_hreg;
                break;
            case JIT_REG_KIND_I64:
                dst_reg = rdx_hreg;
                break;
            case JIT_REG_KIND_F32:
                dst_reg = xmm0_f32_hreg;
                break;
            case JIT_REG_KIND_F64:
                dst_reg = xmm0_f64_hreg;
                break;
            default:
                bh_assert(0);
                return false;
        }
        if (!lower_mov(cc, a, dst_reg, ret_reg))
            return false;
    }

    {
        /* eax = act */
        Imm imm(act);
        a.mov(x86::eax, imm);

        x86::Mem m(x86::rbp, cc->jitted_return_address_offset);
        a.jmp(m);
    }
    return true;
fail:
    return false;
}

static bool
lower_return(JitCompContext *cc, x86::Assembler &a, JitInsn *insn)
{
    JitReg act_reg = *(jit_insn_opnd(insn, 0));
    int32 act;

    CHECK_CONST(act_reg);
    CHECK_KIND(act_reg, JIT_REG_KIND_I32);

    act = jit_cc_get_const_I32(cc, act_reg);
    {
        /* eax = act */
        Imm imm(act);
        a.mov(x86::eax, imm);

        imm.setValue((uintptr_t)code_block_return_to_interp_from_jitted);
        a.mov(regs_i64[REG_I64_FREE_IDX], imm);
        a.jmp(regs_i64[REG_I64_FREE_IDX]);
    }
    return true;
fail:
    return false;
}

/**
 * Replace all the jmp address pre-saved when the code cache hasn't been
 * allocated with actual address after code cache allocated
 *
 * @param cc compiler context containting the allocated code cacha info
 * @param jmp_info_list the jmp info list
 */
static void
patch_jmp_info_list(JitCompContext *cc, bh_list *jmp_info_list)
{
    JmpInfo *jmp_info, *jmp_info_next;
    JitReg reg_dst;
    char *stream;

    jmp_info = (JmpInfo *)bh_list_first_elem(jmp_info_list);

    while (jmp_info) {
        jmp_info_next = (JmpInfo *)bh_list_elem_next(jmp_info);

        stream = (char *)cc->jitted_addr_begin + jmp_info->offset;

        if (jmp_info->type == JMP_DST_LABEL_REL) {
            /* Jmp with relative address */
            reg_dst =
                jit_reg_new(JIT_REG_KIND_L32, jmp_info->dst_info.label_dst);
            *(int32 *)stream =
                (int32)((uintptr_t)*jit_annl_jitted_addr(cc, reg_dst)
                        - (uintptr_t)stream)
                - 4;
        }
        else if (jmp_info->type == JMP_DST_LABEL_ABS) {
            /* Jmp with absolute address */
            reg_dst =
                jit_reg_new(JIT_REG_KIND_L32, jmp_info->dst_info.label_dst);
            *(uintptr_t *)stream =
                (uintptr_t)*jit_annl_jitted_addr(cc, reg_dst);
        }
        else if (jmp_info->type == JMP_END_OF_CALLBC) {
            /* 7 is the size of mov and jmp instruction */
            *(uintptr_t *)stream = (uintptr_t)stream + sizeof(uintptr_t) + 7;
        }
        else if (jmp_info->type == JMP_LOOKUPSWITCH_BASE) {
            /* 11 is the size of 8-byte addr and 3-byte jmp instruction */
            *(uintptr_t *)stream = (uintptr_t)stream + 11;
        }

        jmp_info = jmp_info_next;
    }
}

/* Free the jmp info list */
static void
free_jmp_info_list(bh_list *jmp_info_list)
{
    void *cur_node = bh_list_first_elem(jmp_info_list);

    while (cur_node) {
        void *next_node = bh_list_elem_next(cur_node);

        bh_list_remove(jmp_info_list, cur_node);
        jit_free(cur_node);
        cur_node = next_node;
    }
}

/**
 * Encode cast int32 immediate data to float register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst float register
 * @param data the src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cast_imm_i32_to_r_f32(x86::Assembler &a, int32 reg_no, int32 data)
{
    Imm imm(data);
    a.mov(regs_i32[REG_I32_FREE_IDX], imm);
    a.movd(regs_float[reg_no], regs_i32[REG_I32_FREE_IDX]);
    return true;
}

/**
 * Encode cast int32 register data to float register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst float register
 * @param reg_no_src the no of src int32 register
 *
 * @return true if success, false otherwise
 */
static bool
cast_r_i32_to_r_f32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.movd(regs_float[reg_no_dst], regs_i32[reg_no_src]);
    return true;
}

/**
 * Encode cast int64 immediate data to double register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst double register
 * @param data the src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cast_imm_i64_to_r_f64(x86::Assembler &a, int32 reg_no, int64 data)
{
    Imm imm(data);
    a.mov(regs_i64[REG_I64_FREE_IDX], imm);
    a.movq(regs_float[reg_no], regs_i64[REG_I64_FREE_IDX]);
    return true;
}

/**
 * Encode cast int64 register data to double register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst double register
 * @param reg_no_src the no of src int64 register
 *
 * @return true if success, false otherwise
 */
static bool
cast_r_i64_to_r_f64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.movq(regs_float[reg_no_dst], regs_i64[reg_no_src]);
    return true;
}

/**
 * Encode cast float immediate data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int32 register
 * @param data the src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cast_imm_f32_to_r_i32(x86::Assembler &a, int32 reg_no, float data)
{
    cast_float_to_integer v = { .f = data };
    return mov_imm_to_r_i32(a, reg_no, v.i);
}

/**
 * Encode cast float register data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst int32 register
 * @param reg_no_src the no of src float register
 *
 * @return true if success, false otherwise
 */
static bool
cast_r_f32_to_r_i32(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.movd(regs_i32[reg_no_dst], regs_float[reg_no_src]);
    return true;
}

/**
 * Encode cast double immediate data to int64 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no the no of dst int64 register
 * @param data the src immediate data
 *
 * @return true if success, false otherwise
 */
static bool
cast_imm_f64_to_r_i64(x86::Assembler &a, int32 reg_no, double data)
{
    cast_double_to_integer v = { .d = data };
    return mov_imm_to_r_i64(a, reg_no, v.i);
}

/**
 * Encode cast float register data to int32 register data
 *
 * @param a the assembler to emit the code
 * @param reg_no_dst the no of dst int32 register
 * @param reg_no_src the no of src float register
 *
 * @return true if success, false otherwise
 */
static bool
cast_r_f64_to_r_i64(x86::Assembler &a, int32 reg_no_dst, int32 reg_no_src)
{
    a.movq(regs_i64[reg_no_dst], regs_float[reg_no_src]);
    return true;
}

/**
 * Encode insn cast: F32CASTI32,
 * @param kind0 the dst JIT_REG_KIND, such as I32, I64, F32 and F64
 * @param kind1 the src JIT_REG_KIND, such as I32, I64, F32 and F64
 * @param type0 the dst data type, such as i8, u8, i16, u16, i32, f32, i64, f32,
 * f64
 * @param type1 the src data type, such as i8, u8, i16, u16, i32, f32, i64, f32,
 * f64
 */
#define CAST_R_R(kind0, kind1, type0, type1, Type1)                          \
    do {                                                                     \
        bool _ret = false;                                                   \
        int32 reg_no_dst = 0, reg_no_src = 0;                                \
        CHECK_KIND(r0, JIT_REG_KIND_##kind0);                                \
        CHECK_KIND(r1, JIT_REG_KIND_##kind1);                                \
                                                                             \
        reg_no_dst = jit_reg_no(r0);                                         \
        CHECK_REG_NO(reg_no_dst, JIT_REG_KIND_##kind0);                      \
        if (jit_reg_is_const(r1)) {                                          \
            Type1 data = jit_cc_get_const_##kind1(cc, r1);                   \
            _ret = cast_imm_##type1##_to_r_##type0(a, reg_no_dst, data);     \
        }                                                                    \
        else {                                                               \
            reg_no_src = jit_reg_no(r1);                                     \
            CHECK_REG_NO(reg_no_src, JIT_REG_KIND_##kind1);                  \
            _ret = cast_r_##type1##_to_r_##type0(a, reg_no_dst, reg_no_src); \
        }                                                                    \
        if (!_ret)                                                           \
            GOTO_FAIL;                                                       \
    } while (0)

#if WASM_ENABLE_SHARED_MEMORY != 0

/**
 * Encode extend certain bytes in the src register to a I32 or I64 kind value in
 * dst register
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64),
 * @param kind_dst the kind of data to extend to, could be I32, I64
 * @param reg_no_src the index of register hold src value
 *
 * @return true if success, false otherwise
 */
static bool
extend_r_to_r(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst,
              int32 reg_no_src, int32 reg_no_dst)
{
    if (kind_dst == JIT_REG_KIND_I32) {
        bh_assert(reg_no_src < 16 && reg_no_dst < 16);
        switch (bytes_dst) {
            case 1:
                extend_r8_to_r32(a, reg_no_dst, reg_no_src, false);
                break;
            case 2:
                extend_r16_to_r32(a, reg_no_dst, reg_no_src, false);
                break;
            case 4:
                mov_r_to_r_i32(a, reg_no_dst, reg_no_src);
                break;
            default:
                bh_assert(0);
                return false;
        }
    }
    else if (kind_dst == JIT_REG_KIND_I64) {
        bh_assert(reg_no_src < 16 && reg_no_dst < 16);
        switch (bytes_dst) {
            case 1:
                extend_r8_to_r64(a, reg_no_dst, reg_no_src, false);
                break;
            case 2:
                extend_r16_to_r64(a, reg_no_dst, reg_no_src, false);
                break;
            case 4:
                extend_r32_to_r64(a, reg_no_dst, reg_no_src, false);
                break;
            case 8:
                mov_r_to_r_i64(a, reg_no_dst, reg_no_src);
                break;
            default:
                bh_assert(0);
                return false;
        }
    }
    else {
        bh_assert(0);
    }
    return true;
}

/**
 * Encode atomic compare and exchange, when calling this function,
 * value for comparison should be already moved in register
 * al/ax/eax/rax
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64),
 * @param kind_dst the kind of data to move, could be I32, I64
 * @param m_dst the dest memory operand
 * @param reg_no_xchg the index of register hold exchange value
 *
 * @return true if success, false otherwise
 */
static bool
at_cmpxchg(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst,
           int32 reg_no_xchg, x86::Mem &m_dst)
{
    bh_assert((kind_dst == JIT_REG_KIND_I32 && bytes_dst <= 4)
              || kind_dst == JIT_REG_KIND_I64);
    bh_assert(reg_no_xchg < 16);
    switch (bytes_dst) {
        case 1:
            a.lock().cmpxchg(m_dst, regs_i8[reg_no_xchg]);
            break;
        case 2:
            a.lock().cmpxchg(m_dst, regs_i16[reg_no_xchg]);
            break;
        case 4:
            a.lock().cmpxchg(m_dst, regs_i32[reg_no_xchg]);
            break;
        case 8:
            a.lock().cmpxchg(m_dst, regs_i64[reg_no_xchg]);
            break;
        default:
            bh_assert(0);
            return false;
    }
    return true;
}

/**
 * Encode atomic compare and exchange: load value into a register from
 * memory with reg base and reg offset, compare (expected) reg data with the
 * loaded value, if equal, store the (replacement) reg data to the same
 * memory, else, do nothing. Either way, returns the loaded value
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_xchg the no of register that stores the conditionally
 * replacement value
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory
 * @param reg_no_offset the no of register that stores the offset address
 *        of src&dst memory
 * @return true if success, false otherwise
 */
static bool
at_cmpxchg_r_ra_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                                uint32 kind_dst, int32 reg_no_xchg,
                                int32 reg_no_base, int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    return at_cmpxchg(a, bytes_dst, kind_dst, reg_no_xchg, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, REG_RAX_IDX);
}

/**
 * Encode atomic compare and exchange: load value into a register from
 * memory with reg base and imm offset, compare (expected) reg data with the
 * loaded value, if equal, store the (replacement) reg data to the same
 * memory, else, do nothing. Either way, returns the loaded value
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_xchg the no of register that stores the conditionally
 * replacement value
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_cmpxchg_r_ra_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                                  uint32 kind_dst, int32 reg_no_xchg,
                                  int32 reg_no_base, int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    return at_cmpxchg(a, bytes_dst, kind_dst, reg_no_xchg, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, REG_RAX_IDX);
}

/**
 * Encode atomic compare and exchange: load value into a register from
 * memory with reg base and reg offset, compare (expected) reg data with the
 * loaded value, if equal, store the (replacement) imm data to the same
 * memory, else, do nothing. Either way, returns the loaded value
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param data_xchg the immediate data for exchange(conditionally replacment
 * value)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory
 * @param reg_no_offset the no of register that stores the offset address
 *        of src&dst memory
 * @return true if success, false otherwise
 */
static bool
at_cmpxchg_imm_ra_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                                  uint32 kind_dst, void *data_xchg,
                                  int32 reg_no_base, int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_xchg, bytes_dst);
    uint32 reg_no_xchg = mov_imm_to_free_reg(a, imm, bytes_dst);
    return at_cmpxchg(a, bytes_dst, kind_dst, reg_no_xchg, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, REG_RAX_IDX);
}

/**
 * Encode atomic compare and exchange: load value into a register from
 * memory with reg base and imm offset, compare (expected) reg data with the
 * loaded value, if equal, store the (replacement) imm data to the same
 * memory, else, do nothing. Either way, returns the loaded value
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param data_xchg the immediate data for exchange(conditionally replacment
 * value)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_cmpxchg_imm_ra_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                                    uint32 kind_dst, void *data_xchg,
                                    int32 reg_no_base, int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_xchg, bytes_dst);
    uint32 reg_no_xchg = mov_imm_to_free_reg(a, imm, bytes_dst);
    return at_cmpxchg(a, bytes_dst, kind_dst, reg_no_xchg, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, REG_RAX_IDX);
}

/**
 * Encode insn cmpxchg: CMPXCHG_type r0, r1, r2, r3, r4
 * @param kind the data kind, can only be I32 or I64
 * @param bytes_dst the byte number of dst data
 */
#define CMPXCHG_R_R_R_R_R(kind, type, bytes_dst)                           \
    do {                                                                   \
        type data_xchg = 0;                                                \
        int32 reg_no_xchg = 0, reg_no_cmp = 0, reg_no_base = 0,            \
              reg_no_offset = 0;                                           \
        int32 offset = 0;                                                  \
        bool _ret = false;                                                 \
        if (jit_reg_is_const(r3)) {                                        \
            CHECK_KIND(r3, JIT_REG_KIND_I32);                              \
        }                                                                  \
        else {                                                             \
            CHECK_KIND(r3, JIT_REG_KIND_I64);                              \
        }                                                                  \
        /* r1: expected value(it must in register a)                       \
         * r2: memory base addr can't be const */                          \
        CHECK_NCONST(r1);                                                  \
        reg_no_cmp = jit_reg_no(r1);                                       \
        bh_assert(reg_no_cmp == REG_EAX_IDX || reg_no_cmp == REG_RAX_IDX); \
        CHECK_REG_NO(reg_no_cmp, jit_reg_kind(r1));                        \
        CHECK_NCONST(r2);                                                  \
        reg_no_base = jit_reg_no(r2);                                      \
        CHECK_REG_NO(reg_no_base, jit_reg_kind(r2));                       \
        /* r0: replacement value r3: offset can be const */                \
        if (jit_reg_is_const(r0))                                          \
            data_xchg = jit_cc_get_const_##kind(cc, r0);                   \
        else {                                                             \
            reg_no_xchg = jit_reg_no(r0);                                  \
            CHECK_REG_NO(reg_no_xchg, jit_reg_kind(r0));                   \
        }                                                                  \
        if (jit_reg_is_const(r3))                                          \
            offset = jit_cc_get_const_I32(cc, r3);                         \
        else {                                                             \
            reg_no_offset = jit_reg_no(r3);                                \
            CHECK_REG_NO(reg_no_offset, jit_reg_kind(r3));                 \
        }                                                                  \
                                                                           \
        if (jit_reg_is_const(r0)) {                                        \
            if (jit_reg_is_const(r3))                                      \
                _ret = at_cmpxchg_imm_ra_base_r_offset_imm(                \
                    a, bytes_dst, JIT_REG_KIND_##kind, &data_xchg,         \
                    reg_no_base, offset);                                  \
            else                                                           \
                _ret = at_cmpxchg_imm_ra_base_r_offset_r(                  \
                    a, bytes_dst, JIT_REG_KIND_##kind, &data_xchg,         \
                    reg_no_base, reg_no_offset);                           \
        }                                                                  \
        else {                                                             \
            if (jit_reg_is_const(r3))                                      \
                _ret = at_cmpxchg_r_ra_base_r_offset_imm(                  \
                    a, bytes_dst, JIT_REG_KIND_##kind, reg_no_xchg,        \
                    reg_no_base, offset);                                  \
            else                                                           \
                _ret = at_cmpxchg_r_ra_base_r_offset_r(                    \
                    a, bytes_dst, JIT_REG_KIND_##kind, reg_no_xchg,        \
                    reg_no_base, reg_no_offset);                           \
        }                                                                  \
        if (!_ret)                                                         \
            GOTO_FAIL;                                                     \
    } while (0)

/**
 * Encode negate a value in the register
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64),
 * @param kind_dst the kind of data to move, could be I32, I64
 * @param reg_no_src the index of register hold src value
 *
 * @return true if success, false otherwise
 */
static bool
neg_r(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst, int32 reg_no_src)
{
    bh_assert((kind_dst == JIT_REG_KIND_I32 && bytes_dst <= 4)
              || kind_dst == JIT_REG_KIND_I64);
    bh_assert(reg_no_src < 16);
    switch (bytes_dst) {
        case 1:
            a.neg(regs_i8[reg_no_src]);
            break;
        case 2:
            a.neg(regs_i16[reg_no_src]);
            break;
        case 4:
            a.neg(regs_i32[reg_no_src]);
            break;
        case 8:
            a.neg(regs_i64[reg_no_src]);
            break;
        default:
            bh_assert(0);
            return false;
    }
    return true;
}

/**
 * Encode atomic exchange and add
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64),
 * @param kind_dst the kind of data to move, could be I32, I64
 * @param reg_no_src the index of register hold operand value of add operation
 * @param m_dst the dest memory operand
 *
 * @return true if success, false otherwise
 */
static bool
at_xadd(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst, int32 reg_no_src,
        x86::Mem &m_dst)
{
    bh_assert((kind_dst == JIT_REG_KIND_I32 && bytes_dst <= 4)
              || kind_dst == JIT_REG_KIND_I64);
    bh_assert(reg_no_src < 16);
    switch (bytes_dst) {
        case 1:
            a.lock().xadd(m_dst, regs_i8[reg_no_src]);
            break;
        case 2:
            a.lock().xadd(m_dst, regs_i16[reg_no_src]);
            break;
        case 4:
            a.lock().xadd(m_dst, regs_i32[reg_no_src]);
            break;
        case 8:
            a.lock().xadd(m_dst, regs_i64[reg_no_src]);
            break;
        default:
            bh_assert(0);
            return false;
    }

    return true;
}

/**
 * Encode atomic rmw add: load value into a register from memory
 * with reg base and reg offset, add loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(first operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(second operand&store back)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_add_imm_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                                 uint32 kind_dst, int32 reg_no_dst,
                                 void *data_src, int32 reg_no_base,
                                 int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return at_xadd(a, bytes_dst, kind_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode atomic rmw add: load value into a register from memory
 * with reg base and reg offset, add loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_add_imm_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                               uint32 kind_dst, int32 reg_no_dst,
                               void *data_src, int32 reg_no_base,
                               int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return at_xadd(a, bytes_dst, kind_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode atomic rmw add: load value into a register from memory
 * with reg base and imm offset, add loaded value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_add_r_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                               uint32 kind_dst, int32 reg_no_dst,
                               int32 reg_no_src, int32 reg_no_base,
                               int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    return at_xadd(a, bytes_dst, kind_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode atomic rmw add: load value into a register from memory
 * with reg base and reg offset, add loaded value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_add_r_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                             uint32 kind_dst, int32 reg_no_dst,
                             int32 reg_no_src, int32 reg_no_base,
                             int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    return at_xadd(a, bytes_dst, kind_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode atomic rmw sub: load value into a register from memory
 * with reg base and reg offset, sub loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(first operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(second operand&store back)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_sub_imm_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                                 uint32 kind_dst, int32 reg_no_dst,
                                 void *data_src, int32 reg_no_base,
                                 int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return neg_r(a, bytes_dst, kind_dst, reg_no_src)
           && at_xadd(a, bytes_dst, kind_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode atomic rmw sub: load value into a register from memory
 * with reg base and reg offset, sub loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_sub_imm_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                               uint32 kind_dst, int32 reg_no_dst,
                               void *data_src, int32 reg_no_base,
                               int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return neg_r(a, bytes_dst, kind_dst, reg_no_src)
           && at_xadd(a, bytes_dst, kind_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode atomic rmw sub: load value into a register from memory
 * with reg base and imm offset, sub loaded value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_sub_r_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                               uint32 kind_dst, int32 reg_no_dst,
                               int32 reg_no_src, int32 reg_no_base,
                               int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    return neg_r(a, bytes_dst, kind_dst, reg_no_src)
           && at_xadd(a, bytes_dst, kind_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode atomic rmw sub: load value into a register from memory
 * with reg base and reg offset, sub loaded value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_sub_r_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                             uint32 kind_dst, int32 reg_no_dst,
                             int32 reg_no_src, int32 reg_no_base,
                             int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    return neg_r(a, bytes_dst, kind_dst, reg_no_src)
           && at_xadd(a, bytes_dst, kind_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode atomic rmw xchg: load value into a register from memory
 * with reg base and reg offset, exchange loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(first operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(second operand&store back)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_xchg_imm_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                                  uint32 kind_dst, int32 reg_no_dst,
                                  void *data_src, int32 reg_no_base,
                                  int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return xchg_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode atomic rmw xchg: load value into a register from memory
 * with reg base and reg offset, exchange loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_xchg_imm_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                                uint32 kind_dst, int32 reg_no_dst,
                                void *data_src, int32 reg_no_base,
                                int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return xchg_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode atomic rmw xchg: load value into a register from memory
 * with reg base and imm offset, exchange loaded value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_xchg_r_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                                uint32 kind_dst, int32 reg_no_dst,
                                int32 reg_no_src, int32 reg_no_base,
                                int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    return xchg_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode atomic rmw xchg: load value into a register from memory
 * with reg base and reg offset, exchange loaded value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_xchg_r_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                              uint32 kind_dst, int32 reg_no_dst,
                              int32 reg_no_src, int32 reg_no_base,
                              int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    return xchg_r_to_m(a, bytes_dst, kind_dst, m, reg_no_src)
           && extend_r_to_r(a, bytes_dst, kind_dst, reg_no_src, reg_no_dst);
}

/**
 * Encode insn rmw logical operation: generate a loop to make sure it's atomic
 * @param bin_op the operation, can be and/or/xor
 * @param kind the data kind, can only be I32 or I64
 * @param bytes_dst the byte number of dst data
 */
#define AT_RMW_LOGICAL_LOOP(bin_op, kind, bytes_dst)                           \
    do {                                                                       \
        bh_assert((kind_dst == JIT_REG_KIND_I32 && bytes_dst <= 4)             \
                  || kind_dst == JIT_REG_KIND_I64);                            \
        bh_assert(reg_no_src < 16 && reg_no_dst < 16);                         \
        /* read original value in memory(operand 1) to rax(expected) */        \
        mov_m_to_r(a, bytes_dst, kind_dst, false, REG_RAX_IDX, m_dst);         \
        Label loop = a.newLabel();                                             \
        /* check whether loop is valid, and bind the loop label                \
         * to the current position in the code. */                             \
        if (!loop.isValid() || a.bind(loop) != kErrorOk)                       \
            return false;                                                      \
        /* move operand 1 to temp reg rb */                                    \
        mov_r_to_r(a, kind_dst, REG_RBX_IDX, REG_RAX_IDX);                     \
        /* actual logical operation with operand 2, result save to rbx */      \
        switch (bytes_dst) {                                                   \
            case 1:                                                            \
                a.bin_op##_(regs_i8[REG_RBX_IDX], regs_i8[reg_no_src]);        \
                break;                                                         \
            case 2:                                                            \
                a.bin_op##_(regs_i16[REG_RBX_IDX], regs_i16[reg_no_src]);      \
                break;                                                         \
            case 4:                                                            \
                a.bin_op##_(regs_i32[REG_RBX_IDX], regs_i32[reg_no_src]);      \
                break;                                                         \
            case 8:                                                            \
                a.bin_op##_(regs_i64[REG_RBX_IDX], regs_i64[reg_no_src]);      \
                break;                                                         \
            default:                                                           \
                bh_assert(0);                                                  \
                return false;                                                  \
        }                                                                      \
        /* cmp with read value in RAX, try to change with result value in RBX  \
         * REG, if change successfully, mem data is changed and exit loop(ZF   \
         * is set) if not, loop again(ZF is clear) and tries to do logical ops \
         * atomically */                                                       \
        at_cmpxchg(a, bytes_dst, kind_dst, REG_RBX_IDX, m_dst);                \
        a.jne(loop);                                                           \
        return true;                                                           \
    } while (0)

/**
 * Encode atomic logical binary operation: and
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64),
 * @param kind_dst the kind of data to move, could be I32, I64
 * @param reg_no_dst the index of dest register
 * @param reg_no_src the index of register hold operand value of add operation
 * @param m_dst the dest memory operand
 *
 * @return true if success, false otherwise
 */
static bool
at_and(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst, int32 reg_no_dst,
       int32 reg_no_src, x86::Mem &m_dst)
{
    AT_RMW_LOGICAL_LOOP(and, kind_dst, bytes_dst);
}

/**
 * Encode atomic logical binary operation: or
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64),
 * @param kind_dst the kind of data to move, could be I32, I64
 * @param reg_no_dst the index of dest register
 * @param reg_no_src the index of register hold operand value of add operation
 * @param m_dst the dest memory operand
 *
 * @return true if success, false otherwise
 */
static bool
at_or(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst, int32 reg_no_dst,
      int32 reg_no_src, x86::Mem &m_dst)
{
    AT_RMW_LOGICAL_LOOP(or, kind_dst, bytes_dst);
}
/**
 * Encode atomic logical binary operation: xor
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data,
 *        could be 1(byte), 2(short), 4(int32), 8(int64),
 * @param kind_dst the kind of data to move, could be I32, I64
 * @param reg_no_dst the index of dest register
 * @param reg_no_src the index of register hold operand value of add operation
 * @param m_dst the dest memory operand
 *
 * @return true if success, false otherwise
 */
static bool
at_xor(x86::Assembler &a, uint32 bytes_dst, uint32 kind_dst, int32 reg_no_dst,
       int32 reg_no_src, x86::Mem &m_dst)
{
    AT_RMW_LOGICAL_LOOP(xor, kind_dst, bytes_dst);
}

/**
 * Encode atomic rmw and: load value into a register from memory with reg base
 * and reg offset, bitwise and loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(first operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(second operand&store back)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_and_imm_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                                 uint32 kind_dst, int32 reg_no_dst,
                                 void *data_src, int32 reg_no_base,
                                 int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return at_and(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode atomic rmw and: load value into a register from memory with reg base
 * and reg offset, bitwise and loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_and_imm_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                               uint32 kind_dst, int32 reg_no_dst,
                               void *data_src, int32 reg_no_base,
                               int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return at_and(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode atomic rmw and: load value into a register from memory with reg base
 * and imm offset, bitwise and value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_and_r_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                               uint32 kind_dst, int32 reg_no_dst,
                               int32 reg_no_src, int32 reg_no_base,
                               int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    return at_and(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode atomic rmw and: load value into a register from memory with reg base
 * and reg offset, bitwise and loaded value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_and_r_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                             uint32 kind_dst, int32 reg_no_dst,
                             int32 reg_no_src, int32 reg_no_base,
                             int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    return at_and(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode atomic rmw or: load value into a register from memory with reg base
 * and reg offset, bitwise or loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(first operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(second operand&store back)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_or_imm_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                                uint32 kind_dst, int32 reg_no_dst,
                                void *data_src, int32 reg_no_base, int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return at_or(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode atomic rmw or: load value into a register from memory with reg base
 * and reg offset, bitwise or loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_or_imm_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                              uint32 kind_dst, int32 reg_no_dst, void *data_src,
                              int32 reg_no_base, int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return at_or(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode atomic rmw or: load value into a register from memory with reg base
 * and imm offset, bitwise or loaded value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_or_r_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                              uint32 kind_dst, int32 reg_no_dst,
                              int32 reg_no_src, int32 reg_no_base, int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    return at_or(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode atomic rmw or: load value into a register from memory with reg base
 * and reg offset, bitwise or loaded value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_or_r_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                            uint32 kind_dst, int32 reg_no_dst, int32 reg_no_src,
                            int32 reg_no_base, int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    return at_or(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode atomic rmw xor: load value into a register from memory with reg base
 * and reg offset, bitwise xor loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(first operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(second operand&store back)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_xor_imm_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                                 uint32 kind_dst, int32 reg_no_dst,
                                 void *data_src, int32 reg_no_base,
                                 int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return at_xor(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode atomic rmw xor: load value into a register from memory with reg base
 * and reg offset, bitwise xor loaded value with imm data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param data_src the immediate data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_xor_imm_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                               uint32 kind_dst, int32 reg_no_dst,
                               void *data_src, int32 reg_no_base,
                               int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    Imm imm;
    imm_set_value(imm, data_src, bytes_dst);
    uint32 reg_no_src = mov_imm_to_free_reg(a, imm, bytes_dst);
    return at_xor(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode atomic rmw xor: load value into a register from memory with reg base
 * and imm offset, bitwise xor exchange loaded value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back location)
 * @param offset the offset address of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_xor_r_base_r_offset_imm(x86::Assembler &a, uint32 bytes_dst,
                               uint32 kind_dst, int32 reg_no_dst,
                               int32 reg_no_src, int32 reg_no_base,
                               int32 offset)
{
    x86::Mem m(regs_i64[reg_no_base], offset, bytes_dst);
    return at_xor(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode atomic rmw xor: load value into a register from memory with reg base
 * and reg offset, bitwise xor loaded value with reg data, store back
 *
 * @param a the assembler to emit the code
 * @param bytes_dst the bytes number of the data to actual operated on(load,
 * compare, replacement) could be 1(byte), 2(short), 4(int32), 8(int64)
 * @param reg_no_dst the no of register that stores the returned value
 * @param reg_no_src the no of register store the src data(second operand)
 * @param reg_no_base the no of register that stores the base address
 *        of src&dst memory(first operand&store back)
 * @param reg_no_offset the no of register that stores the offset of the memory
 * @return true if success, false otherwise
 */
static bool
at_rmw_xor_r_base_r_offset_r(x86::Assembler &a, uint32 bytes_dst,
                             uint32 kind_dst, int32 reg_no_dst,
                             int32 reg_no_src, int32 reg_no_base,
                             int32 reg_no_offset)
{
    x86::Mem m(regs_i64[reg_no_base], regs_i64[reg_no_offset], 0, 0, bytes_dst);
    return at_xor(a, bytes_dst, kind_dst, reg_no_dst, reg_no_src, m)
           && extend_r_to_r(a, bytes_dst, kind_dst, REG_RAX_IDX, reg_no_dst);
}

/**
 * Encode insn rmw RMW_type r0, r1, r2, r3
 * @param bin_op the operation, can be add/sub/xchg/and/or/xor
 * @param kind the data kind, can only be I32 or I64
 * @param bytes_dst the byte number of dst data
 */
#define AT_RMW_R_R_R_R(bin_op, kind, type, bytes_dst)                          \
    do {                                                                       \
        type data_src = 0;                                                     \
        int32 reg_no_dst = 0, reg_no_src = 0, reg_no_base = 0,                 \
              reg_no_offset = 0;                                               \
        int32 offset = 0;                                                      \
        bool _ret = false;                                                     \
        if (jit_reg_is_const(r3)) {                                            \
            CHECK_KIND(r3, JIT_REG_KIND_I32);                                  \
        }                                                                      \
        else {                                                                 \
            CHECK_KIND(r3, JIT_REG_KIND_I64);                                  \
        }                                                                      \
        /* r0: read/return value r2: memory base addr can't be const */        \
        /* already check it's not const in LOAD_4ARGS() */                     \
        reg_no_dst = jit_reg_no(r0);                                           \
        CHECK_REG_NO(reg_no_dst, jit_reg_kind(r0));                            \
        /* mem_data base address has to be non-const */                        \
        CHECK_NCONST(r2);                                                      \
        reg_no_base = jit_reg_no(r2);                                          \
        CHECK_REG_NO(reg_no_base, jit_reg_kind(r2));                           \
        /* r1: source operand value r3: offset can be const */                 \
        if (jit_reg_is_const(r1))                                              \
            data_src = jit_cc_get_const_##kind(cc, r1);                        \
        else {                                                                 \
            reg_no_src = jit_reg_no(r1);                                       \
            CHECK_REG_NO(reg_no_src, jit_reg_kind(r1));                        \
        }                                                                      \
        if (jit_reg_is_const(r3))                                              \
            offset = jit_cc_get_const_I32(cc, r3);                             \
        else {                                                                 \
            reg_no_offset = jit_reg_no(r3);                                    \
            CHECK_REG_NO(reg_no_offset, jit_reg_kind(r3));                     \
        }                                                                      \
                                                                               \
        if (jit_reg_is_const(r1)) {                                            \
            if (jit_reg_is_const(r3))                                          \
                _ret = at_rmw_##bin_op##_imm_base_r_offset_imm(                \
                    a, bytes_dst, JIT_REG_KIND_##kind, reg_no_dst, &data_src,  \
                    reg_no_base, offset);                                      \
            else                                                               \
                _ret = at_rmw_##bin_op##_imm_base_r_offset_r(                  \
                    a, bytes_dst, JIT_REG_KIND_##kind, reg_no_dst, &data_src,  \
                    reg_no_base, reg_no_offset);                               \
        }                                                                      \
        else {                                                                 \
            if (jit_reg_is_const(r3))                                          \
                _ret = at_rmw_##bin_op##_r_base_r_offset_imm(                  \
                    a, bytes_dst, JIT_REG_KIND_##kind, reg_no_dst, reg_no_src, \
                    reg_no_base, offset);                                      \
            else                                                               \
                _ret = at_rmw_##bin_op##_r_base_r_offset_r(                    \
                    a, bytes_dst, JIT_REG_KIND_##kind, reg_no_dst, reg_no_src, \
                    reg_no_base, reg_no_offset);                               \
        }                                                                      \
        if (!_ret)                                                             \
            GOTO_FAIL;                                                         \
    } while (0)

/**
 * Encode insn mfence
 **/
static void
fence(x86::Assembler &a)
{
    a.mfence();
}

/**
 * Encode insn fence
 */
#define FENCE() fence(a)

#endif

bool
jit_codegen_gen_native(JitCompContext *cc)
{
    bool atomic;
    JitBasicBlock *block;
    JitInsn *insn;
    JitReg r0, r1, r2, r3, r4;
    JmpInfo jmp_info_head;
    bh_list *jmp_info_list = (bh_list *)&jmp_info_head;
    uint32 label_index, label_num, i;
    uint32 *label_offsets = NULL, code_size;
#if CODEGEN_DUMP != 0
    uint32 code_offset = 0;
#endif
    bool return_value = false, is_last_insn;
    void **jitted_addr;
    char *code_buf, *stream;

    JitErrorHandler err_handler;
    Environment env(Arch::kX64);
    CodeHolder code;
    code.init(env);
    code.setErrorHandler(&err_handler);
    x86::Assembler a(&code);

    if (BH_LIST_SUCCESS != bh_list_init(jmp_info_list)) {
        jit_set_last_error(cc, "init jmp info list failed");
        return false;
    }

    label_num = jit_cc_label_num(cc);

    if (!(label_offsets =
              (uint32 *)jit_calloc(((uint32)sizeof(uint32)) * label_num))) {
        jit_set_last_error(cc, "allocate memory failed");
        goto fail;
    }

    for (i = 0; i < label_num; i++) {
        if (i == 0)
            label_index = 0;
        else if (i == label_num - 1)
            label_index = 1;
        else
            label_index = i + 1;

        label_offsets[label_index] = code.sectionById(0)->buffer().size();

        block = *jit_annl_basic_block(
            cc, jit_reg_new(JIT_REG_KIND_L32, label_index));

#if CODEGEN_DUMP != 0
        os_printf("\nL%d:\n\n", label_index);
#endif

        JIT_FOREACH_INSN(block, insn)
        {
            is_last_insn = (insn->next == block) ? true : false;

#if CODEGEN_DUMP != 0
            os_printf("\n");
            jit_dump_insn(cc, insn);
#endif
            switch (insn->opcode) {
                case JIT_OP_MOV:
                    LOAD_2ARGS();
                    if (!lower_mov(cc, a, r0, r1))
                        GOTO_FAIL;
                    break;

                case JIT_OP_I8TOI32:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, I32, i32, i8, int8);
                    break;

                case JIT_OP_I8TOI64:
                    LOAD_2ARGS();
                    CONVERT_R_R(I64, I32, i64, i8, int8);
                    break;

                case JIT_OP_I16TOI32:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, I32, i32, i16, int16);
                    break;

                case JIT_OP_I16TOI64:
                    LOAD_2ARGS();
                    CONVERT_R_R(I64, I32, i64, i16, int16);
                    break;

                case JIT_OP_I32TOI8:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, I32, i8, i32, int32);
                    break;

                case JIT_OP_I32TOU8:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, I32, u8, i32, int32);
                    break;

                case JIT_OP_I32TOI16:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, I32, i16, i32, int32);
                    break;

                case JIT_OP_I32TOU16:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, I32, u16, i32, int32);
                    break;

                case JIT_OP_I32TOI64:
                    LOAD_2ARGS();
                    CONVERT_R_R(I64, I32, i64, i32, int32);
                    break;

                case JIT_OP_U32TOI64:
                    LOAD_2ARGS();
                    CONVERT_R_R(I64, I32, i64, u32, int32);
                    break;

                case JIT_OP_I32TOF32:
                    LOAD_2ARGS();
                    CONVERT_R_R(F32, I32, f32, i32, int32);
                    break;

                case JIT_OP_U32TOF32:
                    LOAD_2ARGS();
                    CONVERT_R_R(F32, I32, f32, u32, uint32);
                    break;

                case JIT_OP_I32TOF64:
                    LOAD_2ARGS();
                    CONVERT_R_R(F64, I32, f64, i32, int32);
                    break;

                case JIT_OP_U32TOF64:
                    LOAD_2ARGS();
                    CONVERT_R_R(F64, I32, f64, u32, uint32);
                    break;

                case JIT_OP_I64TOI8:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, I64, i8, i64, int64);
                    break;

                case JIT_OP_I64TOI16:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, I64, i16, i64, int64);
                    break;

                case JIT_OP_I64TOI32:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, I64, i32, i64, int64);
                    break;

                case JIT_OP_I64TOF32:
                    LOAD_2ARGS();
                    CONVERT_R_R(F32, I64, f32, i64, int64);
                    break;

                case JIT_OP_I64TOF64:
                    LOAD_2ARGS();
                    CONVERT_R_R(F64, I64, f64, i64, int64);
                    break;

                case JIT_OP_F32TOI32:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, F32, i32, f32, float32);
                    break;

                case JIT_OP_F32TOI64:
                    LOAD_2ARGS();
                    CONVERT_R_R(I64, F32, i64, f32, float32);
                    break;

                case JIT_OP_F32TOF64:
                    LOAD_2ARGS();
                    CONVERT_R_R(F64, F32, f64, f32, float32);
                    break;

                case JIT_OP_F32TOU32:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, F32, u32, f32, float32);
                    break;

                case JIT_OP_F64TOI32:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, F64, i32, f64, float64);
                    break;

                case JIT_OP_F64TOI64:
                    LOAD_2ARGS();
                    CONVERT_R_R(I64, F64, i64, f64, float64);
                    break;

                case JIT_OP_F64TOF32:
                    LOAD_2ARGS();
                    CONVERT_R_R(F32, F64, f32, f64, float64);
                    break;

                case JIT_OP_F64TOU32:
                    LOAD_2ARGS();
                    CONVERT_R_R(I32, F64, u32, f64, float64);
                    break;

                case JIT_OP_NEG:
                    LOAD_2ARGS();
                    if (!lower_neg(cc, a, r0, r1))
                        GOTO_FAIL;
                    break;

                case JIT_OP_ADD:
                case JIT_OP_SUB:
                case JIT_OP_MUL:
                case JIT_OP_DIV_S:
                case JIT_OP_REM_S:
                case JIT_OP_DIV_U:
                case JIT_OP_REM_U:
                    LOAD_3ARGS();
                    if (!lower_alu(cc, a,
                                   (ALU_OP)(ADD + (insn->opcode - JIT_OP_ADD)),
                                   r0, r1, r2))
                        GOTO_FAIL;
                    break;

                case JIT_OP_SHL:
                case JIT_OP_SHRS:
                case JIT_OP_SHRU:
                case JIT_OP_ROTL:
                case JIT_OP_ROTR:
                    LOAD_3ARGS();
                    if (!lower_shift(
                            cc, a,
                            (SHIFT_OP)(SHL + (insn->opcode - JIT_OP_SHL)), r0,
                            r1, r2))
                        GOTO_FAIL;
                    break;

                case JIT_OP_OR:
                case JIT_OP_XOR:
                case JIT_OP_AND:
                    LOAD_3ARGS();
                    if (!lower_bit(cc, a,
                                   (BIT_OP)(OR + (insn->opcode - JIT_OP_OR)),
                                   r0, r1, r2))
                        GOTO_FAIL;
                    break;

                case JIT_OP_CLZ:
                case JIT_OP_CTZ:
                case JIT_OP_POPCNT:
                    LOAD_2ARGS();
                    if (!lower_bitcount(
                            cc, a,
                            (BITCOUNT_OP)(CLZ + (insn->opcode - JIT_OP_CLZ)),
                            r0, r1))
                        GOTO_FAIL;
                    break;

                case JIT_OP_CMP:
                    LOAD_3ARGS();
                    if (!lower_cmp(cc, a, r0, r1, r2))
                        GOTO_FAIL;
                    break;

                case JIT_OP_SELECTEQ:
                case JIT_OP_SELECTNE:
                case JIT_OP_SELECTGTS:
                case JIT_OP_SELECTGES:
                case JIT_OP_SELECTLTS:
                case JIT_OP_SELECTLES:
                case JIT_OP_SELECTGTU:
                case JIT_OP_SELECTGEU:
                case JIT_OP_SELECTLTU:
                case JIT_OP_SELECTLEU:
                    LOAD_4ARGS();
                    if (!lower_select(
                            cc, a,
                            (COND_OP)(EQ + (insn->opcode - JIT_OP_SELECTEQ)),
                            r0, r1, r2, r3))
                        GOTO_FAIL;
                    break;

                case JIT_OP_LDEXECENV:
                    LOAD_1ARG();
                    CHECK_KIND(r0, JIT_REG_KIND_I32);
                    /* TODO */
                    break;

                case JIT_OP_LDJITINFO:
                    LOAD_1ARG();
                    CHECK_KIND(r0, JIT_REG_KIND_I32);
                    /* TODO */
                    break;

                case JIT_OP_LDI8:
                    LOAD_3ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        LD_R_R_R(I32, 1, true);
                    else
                        LD_R_R_R(I64, 1, true);
                    break;

                case JIT_OP_LDU8:
                    LOAD_3ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        LD_R_R_R(I32, 1, false);
                    else
                        LD_R_R_R(I64, 1, false);
                    break;

                case JIT_OP_LDI16:
                    LOAD_3ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        LD_R_R_R(I32, 2, true);
                    else
                        LD_R_R_R(I64, 2, true);
                    break;

                case JIT_OP_LDU16:
                    LOAD_3ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        LD_R_R_R(I32, 2, false);
                    else
                        LD_R_R_R(I64, 2, false);
                    break;

                case JIT_OP_LDI32:
                    LOAD_3ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        LD_R_R_R(I32, 4, true);
                    else
                        LD_R_R_R(I64, 4, true);
                    break;

                case JIT_OP_LDU32:
                    LOAD_3ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        LD_R_R_R(I32, 4, false);
                    else
                        LD_R_R_R(I64, 4, false);
                    break;

                case JIT_OP_LDI64:
                case JIT_OP_LDU64:
                case JIT_OP_LDPTR:
                    LOAD_3ARGS();
                    LD_R_R_R(I64, 8, false);
                    break;

                case JIT_OP_LDF32:
                    LOAD_3ARGS();
                    LD_R_R_R(F32, 4, false);
                    break;

                case JIT_OP_LDF64:
                    LOAD_3ARGS();
                    LD_R_R_R(F64, 8, false);
                    break;

                case JIT_OP_STI8:
                    LOAD_3ARGS_NO_ASSIGN();
                    atomic = insn->flags_u8 & 0x1;
                    ST_R_R_R(I32, int32, 1, atomic);
                    break;

                case JIT_OP_STI16:
                    LOAD_3ARGS_NO_ASSIGN();
                    atomic = insn->flags_u8 & 0x1;
                    ST_R_R_R(I32, int32, 2, atomic);
                    break;

                case JIT_OP_STI32:
                    LOAD_3ARGS_NO_ASSIGN();
                    atomic = insn->flags_u8 & 0x1;
                    ST_R_R_R(I32, int32, 4, atomic);
                    break;

                case JIT_OP_STI64:
                    LOAD_3ARGS_NO_ASSIGN();
                    atomic = insn->flags_u8 & 0x1;
                    ST_R_R_R(I64, int64, 8, atomic);
                    break;

                case JIT_OP_STPTR:
                    LOAD_3ARGS_NO_ASSIGN();
                    ST_R_R_R(I64, int64, 8, false);
                    break;

                case JIT_OP_STF32:
                    LOAD_3ARGS_NO_ASSIGN();
                    ST_R_R_R(F32, float32, 4, false);
                    break;

                case JIT_OP_STF64:
                    LOAD_3ARGS_NO_ASSIGN();
                    ST_R_R_R(F64, float64, 8, false);
                    break;

                case JIT_OP_JMP:
                    LOAD_1ARG();
                    CHECK_KIND(r0, JIT_REG_KIND_L32);
                    if (!(is_last_insn
                          && label_is_neighboring(cc, label_index,
                                                  jit_reg_no(r0))))
                        JMP_TO_LABEL(jit_reg_no(r0), label_index);
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
                    LOAD_3ARGS();
                    if (!lower_branch(
                            cc, a, jmp_info_list, label_index,
                            (COND_OP)(EQ + (insn->opcode - JIT_OP_BEQ)), r0, r1,
                            r2, is_last_insn))
                        GOTO_FAIL;
                    break;

                case JIT_OP_LOOKUPSWITCH:
                {
                    JitOpndLookupSwitch *opnd = jit_insn_opndls(insn);
                    if (!lower_lookupswitch(cc, a, jmp_info_list, label_offsets,
                                            label_index, opnd, is_last_insn))
                        GOTO_FAIL;
                    break;
                }

                case JIT_OP_CALLNATIVE:
                    if (!lower_callnative(cc, a, insn))
                        GOTO_FAIL;
                    break;

                case JIT_OP_CALLBC:
                    if (!lower_callbc(cc, a, jmp_info_list, label_index, insn))
                        GOTO_FAIL;
                    break;

                case JIT_OP_RETURNBC:
                    if (!lower_returnbc(cc, a, insn))
                        GOTO_FAIL;
                    break;

                case JIT_OP_RETURN:
                    if (!lower_return(cc, a, insn))
                        GOTO_FAIL;
                    break;

                case JIT_OP_I32CASTF32:
                    LOAD_2ARGS();
                    CAST_R_R(F32, I32, f32, i32, int32);
                    break;

                case JIT_OP_I64CASTF64:
                    LOAD_2ARGS();
                    CAST_R_R(F64, I64, f64, i64, int64);
                    break;

                case JIT_OP_F32CASTI32:
                    LOAD_2ARGS();
                    CAST_R_R(I32, F32, i32, f32, float);
                    break;

                case JIT_OP_F64CASTI64:
                    LOAD_2ARGS();
                    CAST_R_R(I64, F64, i64, f64, double);
                    break;

#if WASM_ENABLE_SHARED_MEMORY != 0
                case JIT_OP_AT_CMPXCHGU8:
                    LOAD_4ARGS_NO_ASSIGN();
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        CMPXCHG_R_R_R_R_R(I32, int32, 1);
                    else
                        CMPXCHG_R_R_R_R_R(I64, int64, 1);
                    break;

                case JIT_OP_AT_CMPXCHGU16:
                    LOAD_4ARGS_NO_ASSIGN();
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        CMPXCHG_R_R_R_R_R(I32, int32, 2);
                    else
                        CMPXCHG_R_R_R_R_R(I64, int64, 2);
                    break;

                case JIT_OP_AT_CMPXCHGI32:
                    LOAD_4ARGS_NO_ASSIGN();
                    CMPXCHG_R_R_R_R_R(I32, int32, 4);
                    break;

                case JIT_OP_AT_CMPXCHGU32:
                    LOAD_4ARGS_NO_ASSIGN();
                    CMPXCHG_R_R_R_R_R(I64, int32, 4);
                    break;

                case JIT_OP_AT_CMPXCHGI64:
                    LOAD_4ARGS_NO_ASSIGN();
                    CMPXCHG_R_R_R_R_R(I64, int64, 8);
                    break;

                case JIT_OP_AT_ADDU8:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(add, I32, int32, 1);
                    else
                        AT_RMW_R_R_R_R(add, I64, int64, 1);
                    break;

                case JIT_OP_AT_ADDU16:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(add, I32, int32, 2);
                    else
                        AT_RMW_R_R_R_R(add, I64, int64, 2);
                    break;

                case JIT_OP_AT_ADDI32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(add, I32, int32, 4);
                    break;

                case JIT_OP_AT_ADDU32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(add, I64, int64, 4);
                    break;

                case JIT_OP_AT_ADDI64:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(add, I64, int64, 8);
                    break;

                case JIT_OP_AT_SUBU8:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(sub, I32, int32, 1);
                    else
                        AT_RMW_R_R_R_R(sub, I64, int64, 1);
                    break;

                case JIT_OP_AT_SUBU16:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(sub, I32, int32, 2);
                    else
                        AT_RMW_R_R_R_R(sub, I64, int64, 2);
                    break;

                case JIT_OP_AT_SUBI32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(sub, I32, int32, 4);
                    break;

                case JIT_OP_AT_SUBU32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(sub, I64, int64, 4);
                    break;

                case JIT_OP_AT_SUBI64:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(sub, I64, int64, 8);
                    break;

                case JIT_OP_AT_XCHGU8:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(xchg, I32, int32, 1);
                    else
                        AT_RMW_R_R_R_R(xchg, I64, int64, 1);
                    break;

                case JIT_OP_AT_XCHGU16:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(xchg, I32, int32, 2);
                    else
                        AT_RMW_R_R_R_R(xchg, I64, int64, 2);
                    break;

                case JIT_OP_AT_XCHGI32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(xchg, I32, int32, 4);
                    break;

                case JIT_OP_AT_XCHGU32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(xchg, I64, int64, 4);
                    break;

                case JIT_OP_AT_XCHGI64:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(xchg, I64, int64, 8);
                    break;

                case JIT_OP_AT_ANDU8:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(and, I32, int32, 1);
                    else
                        AT_RMW_R_R_R_R(and, I64, int64, 1);
                    break;

                case JIT_OP_AT_ANDU16:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(and, I32, int32, 2);
                    else
                        AT_RMW_R_R_R_R(and, I64, int64, 2);
                    break;

                case JIT_OP_AT_ANDI32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(and, I32, int32, 4);
                    break;

                case JIT_OP_AT_ANDU32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(and, I64, int64, 4);
                    break;

                case JIT_OP_AT_ANDI64:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(and, I64, int64, 8);
                    break;

                case JIT_OP_AT_ORU8:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(or, I32, int32, 1);
                    else
                        AT_RMW_R_R_R_R(or, I64, int64, 1);
                    break;

                case JIT_OP_AT_ORU16:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(or, I32, int32, 2);
                    else
                        AT_RMW_R_R_R_R(or, I64, int64, 2);
                    break;

                case JIT_OP_AT_ORI32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(or, I32, int32, 4);
                    break;

                case JIT_OP_AT_ORU32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(or, I64, int64, 4);
                    break;

                case JIT_OP_AT_ORI64:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(or, I64, int64, 8);
                    break;

                case JIT_OP_AT_XORU8:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(xor, I32, int32, 1);
                    else
                        AT_RMW_R_R_R_R(xor, I64, int64, 1);
                    break;

                case JIT_OP_AT_XORU16:
                    LOAD_4ARGS();
                    bh_assert(jit_reg_kind(r0) == JIT_REG_KIND_I32
                              || jit_reg_kind(r0) == JIT_REG_KIND_I64);
                    if (jit_reg_kind(r0) == JIT_REG_KIND_I32)
                        AT_RMW_R_R_R_R(xor, I32, int32, 2);
                    else
                        AT_RMW_R_R_R_R(xor, I64, int64, 2);
                    break;

                case JIT_OP_AT_XORI32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(xor, I32, int32, 4);
                    break;

                case JIT_OP_AT_XORU32:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(xor, I64, int64, 4);
                    break;

                case JIT_OP_AT_XORI64:
                    LOAD_4ARGS();
                    AT_RMW_R_R_R_R(xor, I64, int64, 8);
                    break;

                case JIT_OP_FENCE:
                    FENCE();
                    break;

#endif

                default:
                    jit_set_last_error_v(cc, "unsupported JIT opcode 0x%2x",
                                         insn->opcode);
                    GOTO_FAIL;
            }

            if (err_handler.err) {
                jit_set_last_error_v(cc,
                                     "failed to generate native code for JIT "
                                     "opcode 0x%02x, ErrorCode is %u",
                                     insn->opcode, err_handler.err);
                GOTO_FAIL;
            }

#if CODEGEN_DUMP != 0
            dump_native((char *)code.sectionById(0)->buffer().data()
                            + code_offset,
                        code.sectionById(0)->buffer().size() - code_offset);
            code_offset = code.sectionById(0)->buffer().size();
#endif
        }
    }

    code_buf = (char *)code.sectionById(0)->buffer().data();
    code_size = code.sectionById(0)->buffer().size();
    if (!(stream = (char *)jit_code_cache_alloc(code_size))) {
        jit_set_last_error(cc, "allocate memory failed");
        goto fail;
    }

    bh_memcpy_s(stream, code_size, code_buf, code_size);
    cc->jitted_addr_begin = stream;
    cc->jitted_addr_end = stream + code_size;

    for (i = 0; i < label_num; i++) {
        if (i == 0)
            label_index = 0;
        else if (i == label_num - 1)
            label_index = 1;
        else
            label_index = i + 1;

        jitted_addr = jit_annl_jitted_addr(
            cc, jit_reg_new(JIT_REG_KIND_L32, label_index));
        *jitted_addr = stream + label_offsets[label_index];
    }

    patch_jmp_info_list(cc, jmp_info_list);
    return_value = true;

fail:

    jit_free(label_offsets);
    free_jmp_info_list(jmp_info_list);
    return return_value;
}

#if WASM_ENABLE_LAZY_JIT != 0 && WASM_ENABLE_JIT != 0

#define MAX_REG_INTS 6
#define MAX_REG_FLOATS 8

void *
jit_codegen_compile_call_to_llvm_jit(const WASMType *func_type)
{
    const JitHardRegInfo *hreg_info = jit_codegen_get_hreg_info();
    x86::Gp reg_lp = x86::r10, reg_res = x86::r12;
    x86::Gp reg_tmp_i64 = x86::r11, reg_tmp_i32 = x86::r11d;
    /* the index of integer argument registers */
    uint8 reg_idx_of_int_args[] = { REG_RDI_IDX, REG_RSI_IDX, REG_RDX_IDX,
                                    REG_RCX_IDX, REG_R8_IDX,  REG_R9_IDX };
    uint32 n_ints = 0, n_fps = 0, n_stacks = 0, n_pushed;
    uint32 int_reg_idx = 0, fp_reg_idx = 0, stack_arg_idx = 0;
    uint32 off_to_lp = 0, off_to_res = 0, code_size, i;
    uint32 param_count = func_type->param_count;
    uint32 result_count = func_type->result_count;
    uint32 ext_result_count;
    char *code_buf, *stream;
    Imm imm;

    JitErrorHandler err_handler;
    Environment env(Arch::kX64);
    CodeHolder code;
    code.init(env);
    code.setErrorHandler(&err_handler);
    x86::Assembler a(&code);

    /* Load the llvm jit function pointer */
    {
        /* r11 = exec_env->module_inst */
        x86::Mem m1(regs_i64[hreg_info->exec_env_hreg_index],
                    (uint32)offsetof(WASMExecEnv, module_inst));
        a.mov(reg_tmp_i64, m1);
        /* r11 = module_inst->func_ptrs */
        x86::Mem m2(reg_tmp_i64,
                    (uint32)offsetof(WASMModuleInstance, func_ptrs));
        a.mov(reg_tmp_i64, m2);
        /* rax = func_ptrs[func_idx] */
        x86::Mem m3(reg_tmp_i64, x86::rdx, 3, 0);
        a.mov(x86::rax, m3);
    }

    n_ints++; /* exec_env */

    for (i = 0; i < param_count; i++) {
        switch (func_type->types[i]) {
            case VALUE_TYPE_I32:
            case VALUE_TYPE_I64:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
#endif
                if (n_ints < MAX_REG_INTS)
                    n_ints++;
                else
                    n_stacks++;
                break;
            case VALUE_TYPE_F32:
            case VALUE_TYPE_F64:
                if (n_fps < MAX_REG_FLOATS)
                    n_fps++;
                else
                    n_stacks++;
                break;
        }
    }

    ext_result_count = result_count > 1 ? result_count - 1 : 0;

    if (ext_result_count > 0) {
        if (n_ints + ext_result_count <= MAX_REG_INTS) {
            /* extra result pointers can be stored into int registers */
            n_ints += ext_result_count;
        }
        else {
            /* part or all extra result pointers must be stored into stack */
            n_stacks += n_ints + ext_result_count - MAX_REG_INTS;
            n_ints = MAX_REG_INTS;
        }
    }

    n_pushed = n_stacks;
    if (n_stacks & 1) {
        /* Align stack on 16 bytes */
        n_pushed++;
    }
    if (n_pushed > 0) {
        imm.setValue(n_pushed * 8);
        a.sub(x86::rsp, imm);
    }

    /* r10 = outs_area->lp */
    {
        x86::Mem m(regs_i64[hreg_info->exec_env_hreg_index],
                   (uint32)offsetof(WASMExecEnv, wasm_stack.s.top));
        a.mov(reg_lp, m);
        a.add(reg_lp, (uint32)offsetof(WASMInterpFrame, lp));
    }

    /* rdi = exec_env */
    a.mov(regs_i64[reg_idx_of_int_args[int_reg_idx++]],
          regs_i64[hreg_info->exec_env_hreg_index]);

    for (i = 0; i < param_count; i++) {
        x86::Mem m_src(reg_lp, off_to_lp);

        switch (func_type->types[i]) {
            case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
#endif
            {
                if (int_reg_idx < MAX_REG_INTS) {
                    a.mov(regs_i32[reg_idx_of_int_args[int_reg_idx]], m_src);
                    int_reg_idx++;
                }
                else {
                    a.mov(reg_tmp_i32, m_src);
                    x86::Mem m_dst(x86::rsp, stack_arg_idx * 8);
                    a.mov(m_dst, reg_tmp_i32);
                    stack_arg_idx++;
                }
                off_to_lp += 4;
                break;
            }
            case VALUE_TYPE_I64:
            {
                if (int_reg_idx < MAX_REG_INTS) {
                    a.mov(regs_i64[reg_idx_of_int_args[int_reg_idx]], m_src);
                    int_reg_idx++;
                }
                else {
                    a.mov(reg_tmp_i64, m_src);
                    x86::Mem m_dst(x86::rsp, stack_arg_idx * 8);
                    a.mov(m_dst, reg_tmp_i64);
                    stack_arg_idx++;
                }
                off_to_lp += 8;
                break;
            }
            case VALUE_TYPE_F32:
            {
                if (fp_reg_idx < MAX_REG_FLOATS) {
                    a.movss(regs_float[fp_reg_idx], m_src);
                    fp_reg_idx++;
                }
                else {
                    a.mov(reg_tmp_i32, m_src);
                    x86::Mem m_dst(x86::rsp, stack_arg_idx * 8);
                    a.mov(m_dst, reg_tmp_i32);
                    stack_arg_idx++;
                }
                off_to_lp += 4;
                break;
            }
            case VALUE_TYPE_F64:
            {
                if (fp_reg_idx < MAX_REG_FLOATS) {
                    a.movsd(regs_float[fp_reg_idx], m_src);
                    fp_reg_idx++;
                }
                else {
                    a.mov(reg_tmp_i64, m_src);
                    x86::Mem m_dst(x86::rsp, stack_arg_idx * 8);
                    a.mov(m_dst, reg_tmp_i64);
                    stack_arg_idx++;
                }
                off_to_lp += 8;
                break;
            }
        }
    }

    if (result_count > 0) {
        switch (func_type->types[param_count]) {
            case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
#endif
            case VALUE_TYPE_F32:
                off_to_res = 4;
                break;
            case VALUE_TYPE_I64:
            case VALUE_TYPE_F64:
                off_to_res = 8;
                break;
        }

        /* r12 = cur_frame->sp */
        x86::Mem m(x86::rbp, (uint32)offsetof(WASMInterpFrame, sp));
        a.mov(reg_res, m);

        for (i = 0; i < ext_result_count; i++) {
            x86::Mem m(reg_res, off_to_res);

            if (int_reg_idx < MAX_REG_INTS) {
                a.lea(regs_i64[reg_idx_of_int_args[int_reg_idx]], m);
                int_reg_idx++;
            }
            else {
                a.lea(reg_tmp_i64, m);
                x86::Mem m_dst(x86::rsp, stack_arg_idx * 8);
                a.mov(m_dst, reg_tmp_i64);
                stack_arg_idx++;
            }

            switch (func_type->types[param_count + 1 + i]) {
                case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
                case VALUE_TYPE_FUNCREF:
                case VALUE_TYPE_EXTERNREF:
#endif
                case VALUE_TYPE_F32:
                    off_to_res += 4;
                    break;
                case VALUE_TYPE_I64:
                case VALUE_TYPE_F64:
                    off_to_res += 8;
                    break;
            }
        }
    }

    bh_assert(int_reg_idx == n_ints);
    bh_assert(fp_reg_idx == n_fps);
    bh_assert(stack_arg_idx == n_stacks);

    /* Call the llvm jit function */
    a.call(x86::rax);

    /* Check if there was exception thrown */
    {
        /* r11 = exec_env->module_inst */
        x86::Mem m1(regs_i64[hreg_info->exec_env_hreg_index],
                    (uint32)offsetof(WASMExecEnv, module_inst));
        a.mov(reg_tmp_i64, m1);
        /* module_inst->cur_exception */
        x86::Mem m2(reg_tmp_i64,
                    (uint32)offsetof(WASMModuleInstance, cur_exception));
        /* bl = module_inst->cur_exception[0] */
        a.mov(x86::bl, m2);

        /* cur_exception[0] == 0 ? */
        Imm imm((uint8)0);
        a.cmp(x86::bl, imm);
        /* If yes, jump to `Get function result and return` */
        imm.setValue(INT32_MAX);
        a.je(imm);

        char *stream = (char *)a.code()->sectionById(0)->buffer().data()
                       + a.code()->sectionById(0)->buffer().size();

        /* If no, set eax to JIT_INTERP_ACTION_THROWN, and
           jump to code_block_return_to_interp_from_jitted to
           return to interpreter */
        imm.setValue(JIT_INTERP_ACTION_THROWN);
        a.mov(x86::eax, imm);
        imm.setValue(code_block_return_to_interp_from_jitted);
        a.mov(x86::rsi, imm);
        a.jmp(x86::rsi);

        char *stream_new = (char *)a.code()->sectionById(0)->buffer().data()
                           + a.code()->sectionById(0)->buffer().size();

        *(int32 *)(stream - 4) = (uint32)(stream_new - stream);
    }

    /* Get function result and return */

    if (result_count > 0 && func_type->types[param_count] != VALUE_TYPE_F32
        && func_type->types[param_count] != VALUE_TYPE_F64) {
        a.mov(x86::rdx, x86::rax);
    }

    if (off_to_res > 0) {
        imm.setValue(off_to_res);
        a.add(reg_res, imm);
        /* cur_frame->sp = r12 */
        x86::Mem m(x86::rbp, (uint32)offsetof(WASMInterpFrame, sp));
        a.mov(m, reg_res);
    }

    if (n_pushed > 0) {
        imm.setValue(n_pushed * 8);
        a.add(x86::rsp, imm);
    }

    /* Return to the caller */
    {
        /* eax = action = JIT_INTERP_ACTION_NORMAL */
        Imm imm(0);
        a.mov(x86::eax, imm);

        uint32 jitted_return_addr_offset =
            jit_frontend_get_jitted_return_addr_offset();
        x86::Mem m(x86::rbp, jitted_return_addr_offset);
        a.jmp(m);
    }

    if (err_handler.err)
        return NULL;

    code_buf = (char *)code.sectionById(0)->buffer().data();
    code_size = code.sectionById(0)->buffer().size();
    stream = (char *)jit_code_cache_alloc(code_size);
    if (!stream)
        return NULL;

    bh_memcpy_s(stream, code_size, code_buf, code_size);

#if 0
    dump_native(stream, code_size);
#endif

    return stream;
}

static WASMInterpFrame *
fast_jit_alloc_frame(WASMExecEnv *exec_env, uint32 param_cell_num,
                     uint32 ret_cell_num)
{
    WASMModuleInstance *module_inst =
        (WASMModuleInstance *)exec_env->module_inst;
    WASMInterpFrame *frame;
    uint32 size_frame1 = wasm_interp_interp_frame_size(ret_cell_num);
    uint32 size_frame2 = wasm_interp_interp_frame_size(param_cell_num);

    /**
     * Check whether we can allocate two frames: the first is an implied
     * frame to store the function results from jit function to call,
     * the second is the frame for the jit function
     */
    if ((uint8 *)exec_env->wasm_stack.s.top + size_frame1 + size_frame2
        > exec_env->wasm_stack.s.top_boundary) {
        wasm_set_exception(module_inst, "wasm operand stack overflow");
        return NULL;
    }

    /* Allocate the frame */
    frame = (WASMInterpFrame *)exec_env->wasm_stack.s.top;
    exec_env->wasm_stack.s.top += size_frame1;

    frame->function = NULL;
    frame->ip = NULL;
    frame->sp = frame->lp;
    frame->prev_frame = wasm_exec_env_get_cur_frame(exec_env);
    frame->jitted_return_addr =
        (uint8 *)code_block_return_to_interp_from_jitted;

    wasm_exec_env_set_cur_frame(exec_env, frame);

    return frame;
}

void *
jit_codegen_compile_call_to_fast_jit(const WASMModule *module, uint32 func_idx)
{
    uint32 func_idx_non_import = func_idx - module->import_function_count;
    WASMType *func_type = module->functions[func_idx_non_import]->func_type;
    /* the index of integer argument registers */
    uint8 reg_idx_of_int_args[] = { REG_RDI_IDX, REG_RSI_IDX, REG_RDX_IDX,
                                    REG_RCX_IDX, REG_R8_IDX,  REG_R9_IDX };
    uint32 int_reg_idx, fp_reg_idx, stack_arg_idx;
    uint32 switch_info_offset, exec_env_offset, stack_arg_offset;
    uint32 int_reg_offset, frame_lp_offset;
    uint32 switch_info_size, code_size, i;
    uint32 param_count = func_type->param_count;
    uint32 result_count = func_type->result_count;
    uint32 ext_result_count = result_count > 1 ? result_count - 1 : 0;
    uint32 param_cell_num = func_type->param_cell_num;
    uint32 ret_cell_num =
        func_type->ret_cell_num > 2 ? func_type->ret_cell_num : 2;
    char *code_buf, *stream;
    Imm imm;

    JitErrorHandler err_handler;
    Environment env(Arch::kX64);
    CodeHolder code;
    code.init(env);
    code.setErrorHandler(&err_handler);
    x86::Assembler a(&code);

    /**
     * Push JitInterpSwitchInfo and make stack 16-byte aligned:
     *   the size pushed must be odd multiples of 8, as the stack pointer
     *   %rsp must be aligned to a 16-byte boundary before making a call,
     *   and when a function (including this llvm jit function) gets
     *   control, the %rsp is not 16-byte aligned (call instruction will
     *   push the ret address to stack).
     */
    switch_info_size = align_uint((uint32)sizeof(JitInterpSwitchInfo), 16) + 8;
    imm.setValue((uint64)switch_info_size);
    a.sub(x86::rsp, imm);

    /* Push all integer argument registers since we will use them as
       temporarily registers to load/store data */
    for (i = 0; i < MAX_REG_INTS; i++) {
        a.push(regs_i64[reg_idx_of_int_args[MAX_REG_INTS - 1 - i]]);
    }

    /* We don't push float/double register since we don't use them here */

    /**
     * Layout of the stack now:
     *   stack arguments
     *   ret address of the caller
     *   switch info
     *   int registers: r9, r8, rcx, rdx, rsi
     *   exec_env: rdi
     */

    /* offset of the first stack argument to the stack pointer,
       add 8 to skip the ret address of the caller */
    stack_arg_offset = switch_info_size + 8 * MAX_REG_INTS + 8;
    /* offset of jit interp switch info to the stack pointer */
    switch_info_offset = 8 * MAX_REG_INTS;
    /* offset of the first int register to the stack pointer */
    int_reg_offset = 8;
    /* offset of exec_env to the stack pointer */
    exec_env_offset = 0;

    /* Call fast_jit_alloc_frame to allocate the stack frame to
       receive the results of the fast jit function to call */

    /* rdi = exec_env, has been already set as exec_env is
       the first argument of LLVM JIT function */
    /* rsi = param_cell_num */
    imm.setValue(param_cell_num);
    a.mov(x86::rsi, imm);
    /* rdx = ret_cell_num */
    imm.setValue(ret_cell_num);
    a.mov(x86::rdx, imm);
    /* call fast_jit_alloc_frame */
    imm.setValue((uint64)(uintptr_t)fast_jit_alloc_frame);
    a.mov(x86::rax, imm);
    a.call(x86::rax);

    /* Check the return value, note now rax is the allocated frame */
    {
        /* Did fast_jit_alloc_frame return NULL? */
        Imm imm((uint64)0);
        a.cmp(x86::rax, imm);
        /* If no, jump to `Copy arguments to frame lp area` */
        imm.setValue(INT32_MAX);
        a.jne(imm);

        char *stream = (char *)a.code()->sectionById(0)->buffer().data()
                       + a.code()->sectionById(0)->buffer().size();

        /* If yes, set eax to 0, return to caller */

        /* Pop all integer arument registers */
        for (i = 0; i < MAX_REG_INTS; i++) {
            a.pop(regs_i64[reg_idx_of_int_args[i]]);
        }
        /* Pop jit interp switch info */
        imm.setValue((uint64)switch_info_size);
        a.add(x86::rsp, imm);

        /* Return to the caller, don't use leave as we didn't
           `push rbp` and `mov rbp, rsp` */
        a.ret();

        /* Patch the offset of jne instruction */
        char *stream_new = (char *)a.code()->sectionById(0)->buffer().data()
                           + a.code()->sectionById(0)->buffer().size();
        *(int32 *)(stream - 4) = (int32)(stream_new - stream);
    }

    int_reg_idx = 1; /* skip exec_env */
    fp_reg_idx = 0;
    stack_arg_idx = 0;

    /* Offset of the dest arguments to outs area */
    frame_lp_offset = wasm_interp_interp_frame_size(ret_cell_num)
                      + (uint32)offsetof(WASMInterpFrame, lp);

    /* Copy arguments to frame lp area */
    for (i = 0; i < func_type->param_count; i++) {
        x86::Mem m_dst(x86::rax, frame_lp_offset);
        switch (func_type->types[i]) {
            case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
#endif
                if (int_reg_idx < MAX_REG_INTS) {
                    /* Copy i32 argument from int register */
                    x86::Mem m_src(x86::rsp, int_reg_offset);
                    a.mov(x86::esi, m_src);
                    a.mov(m_dst, x86::esi);
                    int_reg_offset += 8;
                    int_reg_idx++;
                }
                else {
                    /* Copy i32 argument from stack */
                    x86::Mem m_src(x86::rsp, stack_arg_offset);
                    a.mov(x86::esi, m_src);
                    a.mov(m_dst, x86::esi);
                    stack_arg_offset += 8;
                    stack_arg_idx++;
                }
                frame_lp_offset += 4;
                break;
            case VALUE_TYPE_I64:
                if (int_reg_idx < MAX_REG_INTS) {
                    /* Copy i64 argument from int register */
                    x86::Mem m_src(x86::rsp, int_reg_offset);
                    a.mov(x86::rsi, m_src);
                    a.mov(m_dst, x86::rsi);
                    int_reg_offset += 8;
                    int_reg_idx++;
                }
                else {
                    /* Copy i64 argument from stack */
                    x86::Mem m_src(x86::rsp, stack_arg_offset);
                    a.mov(x86::rsi, m_src);
                    a.mov(m_dst, x86::rsi);
                    stack_arg_offset += 8;
                    stack_arg_idx++;
                }
                frame_lp_offset += 8;
                break;
            case VALUE_TYPE_F32:
                if (fp_reg_idx < MAX_REG_FLOATS) {
                    /* Copy f32 argument from fp register */
                    a.movss(m_dst, regs_float[fp_reg_idx++]);
                }
                else {
                    /* Copy f32 argument from stack */
                    x86::Mem m_src(x86::rsp, stack_arg_offset);
                    a.mov(x86::esi, m_src);
                    a.mov(m_dst, x86::esi);
                    stack_arg_offset += 8;
                    stack_arg_idx++;
                }
                frame_lp_offset += 4;
                break;
            case VALUE_TYPE_F64:
                if (fp_reg_idx < MAX_REG_FLOATS) {
                    /* Copy f64 argument from fp register */
                    a.movsd(m_dst, regs_float[fp_reg_idx++]);
                }
                else {
                    /* Copy f64 argument from stack */
                    x86::Mem m_src(x86::rsp, stack_arg_offset);
                    a.mov(x86::rsi, m_src);
                    a.mov(m_dst, x86::rsi);
                    stack_arg_offset += 8;
                    stack_arg_idx++;
                }
                frame_lp_offset += 8;
                break;
            default:
                bh_assert(0);
        }
    }

    /* Call the fast jit function */
    {
        /* info = rsp + switch_info_offset */
        a.lea(x86::rsi, x86::ptr(x86::rsp, switch_info_offset));
        /* info.frame = frame = rax, or return of fast_jit_alloc_frame */
        x86::Mem m1(x86::rsi, (uint32)offsetof(JitInterpSwitchInfo, frame));
        a.mov(m1, x86::rax);

        /* Call code_block_switch_to_jitted_from_interp
           with argument (exec_env, info, func_idx, pc) */
        /* rdi = exec_env */
        a.mov(x86::rdi, x86::ptr(x86::rsp, exec_env_offset));
        /* rsi = info, has been set */
        /* rdx = func_idx */
        imm.setValue(func_idx);
        a.mov(x86::rdx, imm);
        /* module_inst = exec_env->module_inst */
        a.mov(x86::rcx,
              x86::ptr(x86::rdi, (uint32)offsetof(WASMExecEnv, module_inst)));
        /* fast_jit_func_ptrs = module_inst->fast_jit_func_ptrs */
        a.mov(x86::rcx,
              x86::ptr(x86::rcx, (uint32)offsetof(WASMModuleInstance,
                                                  fast_jit_func_ptrs)));
        imm.setValue(func_idx_non_import);
        a.mov(x86::rax, imm);
        x86::Mem m3(x86::rcx, x86::rax, 3, 0);
        /* rcx = module_inst->fast_jit_func_ptrs[func_idx_non_import] */
        a.mov(x86::rcx, m3);

        imm.setValue(
            (uint64)(uintptr_t)code_block_switch_to_jitted_from_interp);
        a.mov(x86::rax, imm);
        a.call(x86::rax);
    }

    /* No need to check exception thrown here as it will be checked
       in the caller */

    /* Copy function results */
    if (result_count > 0) {
        frame_lp_offset = offsetof(WASMInterpFrame, lp);

        switch (func_type->types[param_count]) {
            case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
#endif
                a.mov(x86::eax, x86::edx);
                frame_lp_offset += 4;
                break;
            case VALUE_TYPE_I64:
                a.mov(x86::rax, x86::rdx);
                frame_lp_offset += 8;
                break;
            case VALUE_TYPE_F32:
                /* The first result has been put to xmm0 */
                frame_lp_offset += 4;
                break;
            case VALUE_TYPE_F64:
                /* The first result has been put to xmm0 */
                frame_lp_offset += 8;
                break;
            default:
                bh_assert(0);
        }

        /* Copy extra results from exec_env->cur_frame */
        if (ext_result_count > 0) {
            /* rdi = exec_env */
            a.mov(x86::rdi, x86::ptr(x86::rsp, exec_env_offset));
            /* rsi = exec_env->cur_frame */
            a.mov(x86::rsi,
                  x86::ptr(x86::rdi, (uint32)offsetof(WASMExecEnv, cur_frame)));

            for (i = 0; i < ext_result_count; i++) {
                switch (func_type->types[param_count + 1 + i]) {
                    case VALUE_TYPE_I32:
#if WASM_ENABLE_REF_TYPES != 0
                    case VALUE_TYPE_FUNCREF:
                    case VALUE_TYPE_EXTERNREF:
#endif
                    case VALUE_TYPE_F32:
                    {
                        /* Copy 32-bit result */
                        a.mov(x86::ecx, x86::ptr(x86::rsi, frame_lp_offset));
                        if (int_reg_idx < MAX_REG_INTS) {
                            x86::Mem m1(x86::rsp,
                                        exec_env_offset + int_reg_idx * 8);
                            a.mov(x86::rdx, m1);
                            x86::Mem m2(x86::rdx, 0);
                            a.mov(m2, x86::ecx);
                            int_reg_idx++;
                        }
                        else {
                            x86::Mem m1(x86::rsp, stack_arg_offset);
                            a.mov(x86::rdx, m1);
                            x86::Mem m2(x86::rdx, 0);
                            a.mov(m2, x86::ecx);
                            stack_arg_offset += 8;
                            stack_arg_idx++;
                        }
                        frame_lp_offset += 4;
                        break;
                    }
                    case VALUE_TYPE_I64:
                    case VALUE_TYPE_F64:
                    {
                        /* Copy 64-bit result */
                        a.mov(x86::rcx, x86::ptr(x86::rsi, frame_lp_offset));
                        if (int_reg_idx < MAX_REG_INTS) {
                            x86::Mem m1(x86::rsp,
                                        exec_env_offset + int_reg_idx * 8);
                            a.mov(x86::rdx, m1);
                            x86::Mem m2(x86::rdx, 0);
                            a.mov(m2, x86::rcx);
                            int_reg_idx++;
                        }
                        else {
                            x86::Mem m1(x86::rsp, stack_arg_offset);
                            a.mov(x86::rdx, m1);
                            x86::Mem m2(x86::rdx, 0);
                            a.mov(m2, x86::rcx);
                            stack_arg_offset += 8;
                            stack_arg_idx++;
                        }
                        frame_lp_offset += 8;
                        break;
                    }
                    default:
                        bh_assert(0);
                }
            }
        }
    }

    /* Free the frame allocated */

    /* rdi = exec_env */
    a.mov(x86::rdi, x86::ptr(x86::rsp, exec_env_offset));
    /* rsi = exec_env->cur_frame */
    a.mov(x86::rsi,
          x86::ptr(x86::rdi, (uint32)offsetof(WASMExecEnv, cur_frame)));
    /* rdx = exec_env->cur_frame->prev_frame */
    a.mov(x86::rdx,
          x86::ptr(x86::rsi, (uint32)offsetof(WASMInterpFrame, prev_frame)));
    /* exec_env->wasm_stack.s.top = cur_frame */
    {
        x86::Mem m(x86::rdi, offsetof(WASMExecEnv, wasm_stack.s.top));
        a.mov(m, x86::rsi);
    }
    /* exec_env->cur_frame = prev_frame */
    {
        x86::Mem m(x86::rdi, offsetof(WASMExecEnv, cur_frame));
        a.mov(m, x86::rdx);
    }

    /* Pop all integer arument registers */
    for (i = 0; i < MAX_REG_INTS; i++) {
        a.pop(regs_i64[reg_idx_of_int_args[i]]);
    }
    /* Pop jit interp switch info */
    imm.setValue((uint64)switch_info_size);
    a.add(x86::rsp, imm);

    /* Return to the caller, don't use leave as we didn't
       `push rbp` and `mov rbp, rsp` */
    a.ret();

    if (err_handler.err) {
        return NULL;
    }

    code_buf = (char *)code.sectionById(0)->buffer().data();
    code_size = code.sectionById(0)->buffer().size();
    stream = (char *)jit_code_cache_alloc(code_size);
    if (!stream)
        return NULL;

    bh_memcpy_s(stream, code_size, code_buf, code_size);

#if 0
    printf("Code of call to fast jit of func %u:\n", func_idx);
    dump_native(stream, code_size);
    printf("\n");
#endif

    return stream;
}

#endif /* end of WASM_ENABLE_LAZY_JIT != 0 && WASM_ENABLE_JIT != 0 */

bool
jit_codegen_lower(JitCompContext *cc)
{
    (void)cc;
    return true;
}

void
jit_codegen_free_native(JitCompContext *cc)
{
    (void)cc;
}

void
jit_codegen_dump_native(void *begin_addr, void *end_addr)
{
#if WASM_ENABLE_FAST_JIT_DUMP != 0
    os_printf("\n");
    dump_native((char *)begin_addr, (char *)end_addr - (char *)begin_addr);
    os_printf("\n");
#else
    (void)begin_addr;
    (void)end_addr;
#endif
}

bool
jit_codegen_init()
{
    const JitHardRegInfo *hreg_info = jit_codegen_get_hreg_info();
    JitGlobals *jit_globals = jit_compiler_get_jit_globals();
    char *code_buf, *stream;
    uint32 code_size;

    JitErrorHandler err_handler;
    Environment env(Arch::kX64);
    CodeHolder code;
    code.init(env);
    code.setErrorHandler(&err_handler);
    x86::Assembler a(&code);

    /* Initialize code_block_switch_to_jitted_from_interp */

    /* push callee-save registers */
    a.push(x86::rbp);
    a.push(x86::rbx);
    a.push(x86::r12);
    a.push(x86::r13);
    a.push(x86::r14);
    a.push(x86::r15);
    /* push info */
    a.push(x86::rsi);

    /* Note: the number of register pushed must be odd, as the stack pointer
       %rsp must be aligned to a 16-byte boundary before making a call, so
       when a function (including this function) gets control, %rsp is not
       aligned. We push odd number registers here to make %rsp happy before
       calling native functions. */

    /* exec_env_reg = exec_env */
    a.mov(regs_i64[hreg_info->exec_env_hreg_index], x86::rdi);
    /* fp_reg = info->frame */
    a.mov(x86::rbp, x86::ptr(x86::rsi, offsetof(JitInterpSwitchInfo, frame)));
    /* rdx = func_idx, is already set in the func_idx argument of
       jit_codegen_interp_jitted_glue  */
    /* jmp target, rcx = pc */
    a.jmp(x86::rcx);

    if (err_handler.err)
        return false;

    code_buf = (char *)code.sectionById(0)->buffer().data();
    code_size = code.sectionById(0)->buffer().size();
    stream = (char *)jit_code_cache_alloc(code_size);
    if (!stream)
        return false;

    bh_memcpy_s(stream, code_size, code_buf, code_size);
    code_block_switch_to_jitted_from_interp = stream;

#if 0
    dump_native(stream, code_size);
#endif

    /* Initialize code_block_return_to_interp_from_jitted */

    a.setOffset(0);

    /* pop info */
    a.pop(x86::rsi);
    /* info->frame = fp_reg */
    {
        x86::Mem m(x86::rsi, offsetof(JitInterpSwitchInfo, frame));
        a.mov(m, x86::rbp);
    }
    /* info->out.ret.ival[0, 1] = rdx */
    {
        x86::Mem m(x86::rsi, offsetof(JitInterpSwitchInfo, out.ret.ival));
        a.mov(m, x86::rdx);
    }
    /* info->out.ret.fval[0, 1] = xmm0 */
    {
        x86::Mem m(x86::rsi, offsetof(JitInterpSwitchInfo, out.ret.fval));
        a.movsd(m, x86::xmm0);
    }

    /* pop callee-save registers */
    a.pop(x86::r15);
    a.pop(x86::r14);
    a.pop(x86::r13);
    a.pop(x86::r12);
    a.pop(x86::rbx);
    a.pop(x86::rbp);
    a.ret();

    if (err_handler.err)
        goto fail1;

    code_buf = (char *)code.sectionById(0)->buffer().data();
    code_size = code.sectionById(0)->buffer().size();
    stream = (char *)jit_code_cache_alloc(code_size);
    if (!stream)
        goto fail1;

    bh_memcpy_s(stream, code_size, code_buf, code_size);
    code_block_return_to_interp_from_jitted =
        jit_globals->return_to_interp_from_jitted = stream;

#if 0
    dump_native(stream, code_size);
#endif

#if WASM_ENABLE_LAZY_JIT != 0
    /* Initialize code_block_compile_fast_jit_and_then_call */

    a.setOffset(0);

    /* Use rbx, r12, r13 to save func_dix, module_inst and module,
       as they are callee-save registers */

    /* Backup func_idx: rbx = rdx = func_idx, note that rdx has
       been prepared in the caller:
         callbc or code_block_switch_to_jitted_from_interp */
    a.mov(x86::rbx, x86::rdx);
    /* r12 = module_inst = exec_env->module_inst */
    {
        x86::Mem m(regs_i64[hreg_info->exec_env_hreg_index],
                   (uint32)offsetof(WASMExecEnv, module_inst));
        a.mov(x86::r12, m);
    }
    /* rdi = r13 = module_inst->module */
    {
        x86::Mem m(x86::r12, (uint32)offsetof(WASMModuleInstance, module));
        a.mov(x86::rdi, m);
        a.mov(x86::r13, x86::rdi);
    }
    /* rsi = rdx = func_idx */
    a.mov(x86::rsi, x86::rdx);
    /* Call jit_compiler_compile(module, func_idx) */
    {
        Imm imm((uint64)(uintptr_t)jit_compiler_compile);
        a.mov(x86::rax, imm);
        a.call(x86::rax);
    }

    /* Check if failed to compile the jit function */
    {
        /* Did jit_compiler_compile return false? */
        Imm imm((uint8)0);
        a.cmp(x86::al, imm);
        /* If no, jump to `Load compiled func ptr and call it` */
        imm.setValue(INT32_MAX);
        a.jne(imm);

        char *stream_old = (char *)a.code()->sectionById(0)->buffer().data()
                           + a.code()->sectionById(0)->buffer().size();

        /* If yes, call jit_set_exception_with_id to throw exception,
           and then set eax to JIT_INTERP_ACTION_THROWN, and jump to
           code_block_return_to_interp_from_jitted to return */

        /* rdi = module_inst */
        a.mov(x86::rdi, x86::r12);
        /* rsi = EXCE_FAILED_TO_COMPILE_FAST_JIT_FUNC */
        imm.setValue(EXCE_FAILED_TO_COMPILE_FAST_JIT_FUNC);
        a.mov(x86::rsi, imm);
        /* Call jit_set_exception_with_id */
        imm.setValue((uint64)(uintptr_t)jit_set_exception_with_id);
        a.mov(x86::rax, imm);
        a.call(x86::rax);
        /* Return to the caller */
        imm.setValue(JIT_INTERP_ACTION_THROWN);
        a.mov(x86::eax, imm);
        imm.setValue(code_block_return_to_interp_from_jitted);
        a.mov(x86::rsi, imm);
        a.jmp(x86::rsi);

        /* Patch the offset of jne instruction */
        char *stream_new = (char *)a.code()->sectionById(0)->buffer().data()
                           + a.code()->sectionById(0)->buffer().size();
        *(int32 *)(stream_old - 4) = (int32)(stream_new - stream_old);
    }

    /* Load compiled func ptr and call it */
    {
        /* rsi = module->import_function_count */
        x86::Mem m1(x86::r13,
                    (uint32)offsetof(WASMModule, import_function_count));
        a.movzx(x86::rsi, m1);
        /* rbx = rbx - module->import_function_count */
        a.sub(x86::rbx, x86::rsi);
        /* rax = module->fast_jit_func_ptrs */
        x86::Mem m2(x86::r13, (uint32)offsetof(WASMModule, fast_jit_func_ptrs));
        a.mov(x86::rax, m2);
        /* rax = fast_jit_func_ptrs[rbx] */
        x86::Mem m3(x86::rax, x86::rbx, 3, 0);
        a.mov(x86::rax, m3);
        a.jmp(x86::rax);
    }

    if (err_handler.err)
        goto fail2;

    code_buf = (char *)code.sectionById(0)->buffer().data();
    code_size = code.sectionById(0)->buffer().size();
    stream = (char *)jit_code_cache_alloc(code_size);
    if (!stream)
        goto fail2;

    bh_memcpy_s(stream, code_size, code_buf, code_size);
    code_block_compile_fast_jit_and_then_call =
        jit_globals->compile_fast_jit_and_then_call = stream;

#if 0
    dump_native(stream, code_size);
#endif
#endif /* end of WASM_ENABLE_LAZY_JIT != 0 */

    return true;

#if WASM_ENABLE_LAZY_JIT != 0
fail2:
    jit_code_cache_free(code_block_return_to_interp_from_jitted);
#endif
fail1:
    jit_code_cache_free(code_block_switch_to_jitted_from_interp);
    return false;
}

void
jit_codegen_destroy()
{
#if WASM_ENABLE_LAZY_JIT != 0
    jit_code_cache_free(code_block_compile_fast_jit_and_then_call);
#endif
    jit_code_cache_free(code_block_return_to_interp_from_jitted);
    jit_code_cache_free(code_block_switch_to_jitted_from_interp);
}

/* clang-format off */
static const uint8 hreg_info_I32[3][7] = {
    /* ebp, eax, ebx, ecx, edx, edi, esi */
    { 1, 0, 0, 0, 0, 0, 1 }, /* fixed, esi is freely used */
    { 0, 1, 0, 1, 1, 1, 0 }, /* caller_saved_native */
    { 0, 1, 1, 1, 1, 1, 0 }  /* caller_saved_jitted */
};

static const uint8 hreg_info_I64[3][16] = {
    /* rbp, rax, rbx, rcx, rdx, rdi, rsi, rsp,
       r8,  r9,  r10, r11, r12, r13, r14, r15 */
    { 1, 1, 1, 1, 1, 1, 1, 1,
      0, 0, 0, 0, 0, 0, 0, 1 }, /* fixed, rsi is freely used */
    { 0, 1, 0, 1, 1, 1, 0, 0,
      1, 1, 1, 1, 0, 0, 0, 0 }, /* caller_saved_native */
    { 0, 1, 1, 1, 1, 1, 0, 0,
      1, 1, 1, 1, 1, 1, 1, 0 }, /* caller_saved_jitted */
};

/* System V AMD64 ABI Calling Conversion. [XYZ]MM0-7 */
static uint8 hreg_info_F32[3][16] = {
    /* xmm0 ~ xmm15 */
    { 0, 0, 0, 0, 0, 0, 0, 0,
      1, 1, 1, 1, 1, 1, 1, 1 },
    { 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 0 }, /* caller_saved_native */
    { 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 0 }, /* caller_saved_jitted */
};

/* System V AMD64 ABI Calling Conversion. [XYZ]MM0-7 */
static uint8 hreg_info_F64[3][16] = {
    /* xmm0 ~ xmm15 */
    { 1, 1, 1, 1, 1, 1, 1, 1,
      0, 0, 0, 0, 0, 0, 0, 1 },
    { 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 0 }, /* caller_saved_native */
    { 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 0 }, /* caller_saved_jitted */
};

static const JitHardRegInfo g_hreg_info = {
    {
        { 0, NULL, NULL, NULL }, /* VOID */

        { sizeof(hreg_info_I32[0]), /* I32 */
          hreg_info_I32[0],
          hreg_info_I32[1],
          hreg_info_I32[2] },

        { sizeof(hreg_info_I64[0]), /* I64 */
          hreg_info_I64[0],
          hreg_info_I64[1],
          hreg_info_I64[2] },

        { sizeof(hreg_info_F32[0]), /* F32 */
          hreg_info_F32[0],
          hreg_info_F32[1],
          hreg_info_F32[2] },

        { sizeof(hreg_info_F64[0]), /* F64 */
          hreg_info_F64[0],
          hreg_info_F64[1],
          hreg_info_F64[2] },

        { 0, NULL, NULL, NULL }, /* V8 */
        { 0, NULL, NULL, NULL }, /* V16 */
        { 0, NULL, NULL, NULL }  /* V32 */
    },
    /* frame pointer hreg index: rbp */
    0,
    /* exec_env hreg index: r15 */
    15,
    /* cmp hreg index: esi */
    6
};
/* clang-format on */

const JitHardRegInfo *
jit_codegen_get_hreg_info()
{
    return &g_hreg_info;
}

static const char *reg_names_i32[] = {
    "ebp", "eax", "ebx", "ecx", "edx", "edi", "esi", "esp",
};

static const char *reg_names_i64[] = {
    "rbp", "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rsp",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
};

static const char *reg_names_f32[] = { "xmm0",  "xmm1",  "xmm2",  "xmm3",
                                       "xmm4",  "xmm5",  "xmm6",  "xmm7",
                                       "xmm8",  "xmm9",  "xmm10", "xmm11",
                                       "xmm12", "xmm13", "xmm14", "xmm15" };

static const char *reg_names_f64[] = {
    "xmm0_f64",  "xmm1_f64",  "xmm2_f64",  "xmm3_f64", "xmm4_f64",  "xmm5_f64",
    "xmm6_f64",  "xmm7_f64",  "xmm8_f64",  "xmm9_f64", "xmm10_f64", "xmm11_f64",
    "xmm12_f64", "xmm13_f64", "xmm14_f64", "xmm15_f64"
};

JitReg
jit_codegen_get_hreg_by_name(const char *name)
{
    size_t i;

    if (name[0] == 'e') {
        for (i = 0; i < sizeof(reg_names_i32) / sizeof(char *); i++)
            if (!strcmp(reg_names_i32[i], name))
                return jit_reg_new(JIT_REG_KIND_I32, i);
    }
    else if (name[0] == 'r') {
        for (i = 0; i < sizeof(reg_names_i64) / sizeof(char *); i++)
            if (!strcmp(reg_names_i64[i], name))
                return jit_reg_new(JIT_REG_KIND_I64, i);
    }
    else if (!strncmp(name, "xmm", 3)) {
        if (!strstr(name, "_f64")) {
            for (i = 0; i < sizeof(reg_names_f32) / sizeof(char *); i++)
                if (!strcmp(reg_names_f32[i], name))
                    return jit_reg_new(JIT_REG_KIND_F32, i);
        }
        else {
            for (i = 0; i < sizeof(reg_names_f64) / sizeof(char *); i++)
                if (!strcmp(reg_names_f64[i], name))
                    return jit_reg_new(JIT_REG_KIND_F64, i);
        }
    }
    return 0;
}
