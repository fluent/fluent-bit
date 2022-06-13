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
void __eqsf2();
void __extendsfdf2();
void __fixdfsi();
void __floatsidf();
void __floatsisf();
void __gedf2();
void __gtdf2();
void __ledf2();
void __lesf2();
void __ltdf2();
void __muldf3();
void __mulsf3();
void __subdf3();
void __subsf3();
void __truncdfsf2();
void __unorddf2();
/* clang-format on */

static SymbolMap target_sym_map[] = {
    /* clang-format off */
    REG_COMMON_SYMBOLS
    REG_SYM(__st_r13_to_r15),
    /* clang-format on */
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
    REG_SYM(__eqsf2),
    REG_SYM(__extendsfdf2),
    REG_SYM(__fixdfsi),
    REG_SYM(__floatsidf),
    REG_SYM(__floatsisf),
    REG_SYM(__gedf2),
    REG_SYM(__gtdf2),
    REG_SYM(__ledf2),
    REG_SYM(__lesf2),
    REG_SYM(__ltdf2),
    REG_SYM(__muldf3),
    REG_SYM(__mulsf3),
    REG_SYM(__subdf3),
    REG_SYM(__subsf3),
    REG_SYM(__truncdfsf2),
    REG_SYM(__unorddf2),
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
