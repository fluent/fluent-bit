/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_reloc.h"

#define R_ARC_S21H_PCREL 14
#define R_ARC_S21W_PCREL 15
#define R_ARC_S25H_PCREL 16
#define R_ARC_S25W_PCREL 17
#define R_ARC_32 4
#define R_ARC_32_ME 27

/* clang-format off */
#ifndef __CCAC__
void __st_r13_to_r15();
void __st_r13_to_r16();
void __st_r13_to_r17();
void __st_r13_to_r18();
void __st_r13_to_r19();
void __st_r13_to_r20();
void __st_r13_to_r21();
void __st_r13_to_r22();
void __st_r13_to_r23();
void __st_r13_to_r24();
void __st_r13_to_r25();
void __ld_r13_to_r15();
void __ld_r13_to_r16();
void __ld_r13_to_r17();
void __ld_r13_to_r18();
void __ld_r13_to_r19();
void __ld_r13_to_r20();
void __ld_r13_to_r21();
void __ld_r13_to_r22();
void __ld_r13_to_r23();
void __ld_r13_to_r24();
void __ld_r13_to_r25();
void __adddf3();
void __addsf3();
void __divdf3();
void __divdi3();
void __divsf3();
void __divsi3();
void __extendsfdf2();
void __fixdfsi();
void __floatsidf();
void __floatsisf();
void __muldf3();
void __mulsf3();
void __subdf3();
void __subsf3();
void __truncdfsf2();
void __floatunsisf();
void __fixunsdfsi();
void __floatdisf();
void __floatdidf();
void __fixdfdi();
void __ltsf2();
void __gesf2();
void __eqdf2();
void __nedf2();
void __ltsf2();
void __nesf2();
void __unordsf2();
void __fixunssfsi();
#else
void __ac_push_13_to_13();
void __ac_push_13_to_14();
void __ac_push_13_to_15();
void __ac_push_13_to_16();
void __ac_push_13_to_17();
void __ac_push_13_to_18();
void __ac_push_13_to_19();
void __ac_push_13_to_20();
void __ac_push_13_to_21();
void __ac_push_13_to_22();
void __ac_push_13_to_23();
void __ac_push_13_to_24();
void __ac_push_13_to_25();
void __ac_push_13_to_26();
void __ac_push_none();
void __ac_pop_13_to_26();
void __ac_pop_13_to_26v();
void __ac_pop_13_to_25();
void __ac_pop_13_to_25v();
void __ac_pop_13_to_24();
void __ac_pop_13_to_24v();
void __ac_pop_13_to_23();
void __ac_pop_13_to_23v();
void __ac_pop_13_to_22();
void __ac_pop_13_to_22v();
void __ac_pop_13_to_21();
void __ac_pop_13_to_21v();
void __ac_pop_13_to_20();
void __ac_pop_13_to_20v();
void __ac_pop_13_to_19();
void __ac_pop_13_to_19v();
void __ac_pop_13_to_18();
void __ac_pop_13_to_18v();
void __ac_pop_13_to_17();
void __ac_pop_13_to_17v();
void __ac_pop_13_to_16();
void __ac_pop_13_to_16v();
void __ac_pop_13_to_15();
void __ac_pop_13_to_15v();
void __ac_pop_13_to_14();
void __ac_pop_13_to_14v();
void __ac_pop_13_to_13();
void __ac_pop_13_to_13v();
void __ac_pop_none();
void __ac_pop_nonev();
void __eqdf2();
void __nedf2();
void __ltsf2();
void __nesf2();
void __gesf2();
void __gtsf2();
void __unordsf2();
void __truncdfhf2();
void __truncsfhf2();
#endif /* end of __CCAC__ */

void __ledf2();
void __ltdf2();
void __gedf2();
void __gtdf2();
void __eqsf2();
void __lesf2();
void __unorddf2();
/* clang-format on */

static SymbolMap target_sym_map[] = {
    /* clang-format off */
    REG_COMMON_SYMBOLS
#ifndef __CCAC__
    REG_SYM(__st_r13_to_r15),
    REG_SYM(__st_r13_to_r16),
    REG_SYM(__st_r13_to_r17),
    REG_SYM(__st_r13_to_r18),
    REG_SYM(__st_r13_to_r19),
    REG_SYM(__st_r13_to_r20),
    REG_SYM(__st_r13_to_r21),
    REG_SYM(__st_r13_to_r22),
    REG_SYM(__st_r13_to_r23),
    REG_SYM(__st_r13_to_r24),
    REG_SYM(__st_r13_to_r25),
    REG_SYM(__ld_r13_to_r15),
    REG_SYM(__ld_r13_to_r16),
    REG_SYM(__ld_r13_to_r17),
    REG_SYM(__ld_r13_to_r18),
    REG_SYM(__ld_r13_to_r19),
    REG_SYM(__ld_r13_to_r20),
    REG_SYM(__ld_r13_to_r21),
    REG_SYM(__ld_r13_to_r22),
    REG_SYM(__ld_r13_to_r23),
    REG_SYM(__ld_r13_to_r24),
    REG_SYM(__ld_r13_to_r25),
    REG_SYM(__adddf3),
    REG_SYM(__addsf3),
    REG_SYM(__divdf3),
    REG_SYM(__divdi3),
    REG_SYM(__divsf3),
    REG_SYM(__divsi3),
    REG_SYM(__extendsfdf2),
    REG_SYM(__fixdfsi),
    REG_SYM(__floatsidf),
    REG_SYM(__floatsisf),
    REG_SYM(__muldf3),
    REG_SYM(__mulsf3),
    REG_SYM(__subdf3),
    REG_SYM(__subsf3),
    REG_SYM(__truncdfsf2),
    REG_SYM(__floatunsisf),
    REG_SYM(__fixunsdfsi),
    REG_SYM(__floatdisf),
    REG_SYM(__floatdidf),
    REG_SYM(__fixdfdi),
    REG_SYM(__ltsf2),
    REG_SYM(__gesf2),
    REG_SYM(__eqdf2),
    REG_SYM(__nedf2),
    REG_SYM(__ltsf2),
    REG_SYM(__nesf2),
    REG_SYM(__unordsf2),
    REG_SYM(__fixunssfsi),
#else
    REG_SYM(__ac_push_13_to_13),
    REG_SYM(__ac_push_13_to_14),
    REG_SYM(__ac_push_13_to_15),
    REG_SYM(__ac_push_13_to_16),
    REG_SYM(__ac_push_13_to_17),
    REG_SYM(__ac_push_13_to_18),
    REG_SYM(__ac_push_13_to_19),
    REG_SYM(__ac_push_13_to_20),
    REG_SYM(__ac_push_13_to_21),
    REG_SYM(__ac_push_13_to_22),
    REG_SYM(__ac_push_13_to_23),
    REG_SYM(__ac_push_13_to_24),
    REG_SYM(__ac_push_13_to_25),
    REG_SYM(__ac_push_13_to_26),
    REG_SYM(__ac_push_none),
    REG_SYM(__ac_pop_13_to_26),
    REG_SYM(__ac_pop_13_to_26v),
    REG_SYM(__ac_pop_13_to_25),
    REG_SYM(__ac_pop_13_to_25v),
    REG_SYM(__ac_pop_13_to_24),
    REG_SYM(__ac_pop_13_to_24v),
    REG_SYM(__ac_pop_13_to_23),
    REG_SYM(__ac_pop_13_to_23v),
    REG_SYM(__ac_pop_13_to_22),
    REG_SYM(__ac_pop_13_to_22v),
    REG_SYM(__ac_pop_13_to_21),
    REG_SYM(__ac_pop_13_to_21v),
    REG_SYM(__ac_pop_13_to_20),
    REG_SYM(__ac_pop_13_to_20v),
    REG_SYM(__ac_pop_13_to_19),
    REG_SYM(__ac_pop_13_to_19v),
    REG_SYM(__ac_pop_13_to_18),
    REG_SYM(__ac_pop_13_to_18v),
    REG_SYM(__ac_pop_13_to_17),
    REG_SYM(__ac_pop_13_to_17v),
    REG_SYM(__ac_pop_13_to_16),
    REG_SYM(__ac_pop_13_to_16v),
    REG_SYM(__ac_pop_13_to_15),
    REG_SYM(__ac_pop_13_to_15v),
    REG_SYM(__ac_pop_13_to_14),
    REG_SYM(__ac_pop_13_to_14v),
    REG_SYM(__ac_pop_13_to_13),
    REG_SYM(__ac_pop_13_to_13v),
    REG_SYM(__ac_pop_none),
    REG_SYM(__ac_pop_nonev),
    REG_SYM(__eqdf2),
    REG_SYM(__nedf2),
    REG_SYM(__ltsf2),
    REG_SYM(__nesf2),
    REG_SYM(__gesf2),
    REG_SYM(__gtsf2),
    REG_SYM(__unordsf2),
    REG_SYM(__truncdfhf2),
    REG_SYM(__truncsfhf2),
#endif /* end of __CCAC__ */

    REG_SYM(__ledf2),
    REG_SYM(__ltdf2),
    REG_SYM(__gedf2),
    REG_SYM(__gtdf2),
    REG_SYM(__eqsf2),
    REG_SYM(__lesf2),
    REG_SYM(__unorddf2),
    /* clang-format on */
};

static void
set_error_buf(char *error_buf, uint32 error_buf_size, const char *string)
{
    if (error_buf != NULL)
        snprintf(error_buf, error_buf_size, "%s", string);
}

SymbolMap *
get_target_symbol_map(uint32 *sym_num)
{
    *sym_num = sizeof(target_sym_map) / sizeof(SymbolMap);
    return target_sym_map;
}

void
get_current_target(char *target_buf, uint32 target_buf_size)
{
    snprintf(target_buf, target_buf_size, "arc");
}

uint32
get_plt_table_size()
{
    return 0;
}

void
init_plt_table(uint8 *plt)
{
    (void)plt;
}

static bool
check_reloc_offset(uint32 target_section_size, uint64 reloc_offset,
                   uint32 reloc_data_size, char *error_buf,
                   uint32 error_buf_size)
{
    if (!(reloc_offset < (uint64)target_section_size
          && reloc_offset + reloc_data_size <= (uint64)target_section_size)) {
        set_error_buf(error_buf, error_buf_size,
                      "AOT module load failed: invalid relocation offset.");
        return false;
    }
    return true;
}

static uint32
middle_endian_convert(uint32 insn)
{
    return ((insn & 0xFFFF0000) >> 16) | ((insn & 0x0000FFFF) << 16);
}

bool
apply_relocation(AOTModule *module, uint8 *target_section_addr,
                 uint32 target_section_size, uint64 reloc_offset,
                 int64 reloc_addend, uint32 reloc_type, void *symbol_addr,
                 int32 symbol_index, char *error_buf, uint32 error_buf_size)
{
    switch (reloc_type) {
        case R_ARC_S25H_PCREL:
        {
            uint32 insn = LOAD_I32(target_section_addr + reloc_offset);
            int32 addend, value;
            uintptr_t S, P;
            intptr_t A;

            CHECK_RELOC_OFFSET(sizeof(void *));

            /* Convert from middle endian */
            insn = middle_endian_convert(insn);

            addend = ((insn << 28) >> 28) << 10;
            /* Extract the next 10 bits from Position 6 to 15 in insn */
            addend |= ((insn << 16) >> 22);
            addend = addend << 10;
            /* Extract the remaining 10 bits from Position 17 to 26 in insn */
            addend |= ((insn << 5) >> 22);
            /* Fill in 1 bits to get the 25 bit Offset Value */
            addend = addend << 1;

            /* (S + A) - P */
            S = (uintptr_t)(uint8 *)symbol_addr;
            A = (intptr_t)reloc_addend;
            P = (uintptr_t)(target_section_addr + reloc_offset);
            P &= (uintptr_t)~1;
            value = (int32)(S + A + addend - P);

            insn = insn & 0xf8010030;
            insn |= ((((value >> 1) & 0x3ff) << 17)
                     | (((value >> 1) & 0xffc00) >> 3)
                     | (((value >> 1) & 0xf00000) >> 19));

            /* Convert to middle endian */
            insn = middle_endian_convert(insn);

            STORE_U32(target_section_addr + reloc_offset, insn);
            break;
        }
        case R_ARC_S25W_PCREL:
        {
            uint32 insn = LOAD_I32(target_section_addr + reloc_offset);
            int32 addend, value;
            uintptr_t S, P;
            intptr_t A;

            CHECK_RELOC_OFFSET(sizeof(void *));

            /* Convert from middle endian */
            insn = middle_endian_convert(insn);

            addend = ((insn << 28) >> 28) << 10;
            /* Extract the next 10 bits from Position 6 to 15 in insn */
            addend |= ((insn << 16) >> 22);
            addend = addend << 9;
            /* Extract the remaining 9 bits from Position 18 to 26 in insn */
            addend |= ((insn << 5) >> 23);
            /* Fill in 2 bits to get the 25 bit Offset Value */
            addend = addend << 2;

            /* (S + A) - P */
            S = (uintptr_t)(uint8 *)symbol_addr;
            A = (intptr_t)reloc_addend;
            P = (uintptr_t)(target_section_addr + reloc_offset);
            P &= (uintptr_t)~3;
            value = (int32)(S + A + addend - P);

            insn = insn & 0xf8030030;
            insn |= ((((value >> 2) & 0x1ff) << 18)
                     | (((value >> 2) & 0x7fe00) >> 3)
                     | (((value >> 2) & 0x780000) >> 19));

            /* Convert to middle endian */
            insn = middle_endian_convert(insn);

            STORE_U32(target_section_addr + reloc_offset, insn);
            break;
        }
        case R_ARC_32:
        case R_ARC_32_ME:
        {
            uint32 insn;

            CHECK_RELOC_OFFSET(sizeof(void *));

            /* (S + A) */
            insn = (uint32)((uintptr_t)symbol_addr + (intptr_t)reloc_addend);

            if (reloc_type == R_ARC_32_ME)
                /* Convert to middle endian */
                insn = middle_endian_convert(insn);

            STORE_U32(target_section_addr + reloc_offset, insn);
            break;
        }
        default:
        {
            if (error_buf != NULL)
                snprintf(error_buf, error_buf_size,
                         "Load relocation section failed: "
                         "invalid relocation type %d.",
                         reloc_type);
            return false;
        }
    }
    return true;
}
