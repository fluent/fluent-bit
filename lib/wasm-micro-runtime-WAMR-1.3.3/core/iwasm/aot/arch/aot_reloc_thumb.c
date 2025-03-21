/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_reloc.h"

#define R_ARM_ABS32 2      /* Direct 32 bit */
#define R_ARM_THM_CALL 10  /* PC relative (Thumb BL and ARMv5 Thumb BLX). */
#define R_ARM_THM_JMP24 30 /* B.W */
#define R_ARM_THM_MOVW_ABS_NC 47
#define R_ARM_THM_MOVT_ABS 48
#define R_ARM_THM_MOVW_PREL_NC 49
#define R_ARM_THM_MOVT_PREL 50

/* clang-format off */
void __adddf3();
void __addsf3();
void __aeabi_d2iz();
void __aeabi_d2lz();
void __aeabi_d2uiz();
void __aeabi_d2ulz();
void __aeabi_dadd();
void __aeabi_dcmpge();
void __aeabi_dcmpgt();
void __aeabi_dcmple();
void __aeabi_dcmplt();
void __aeabi_dcmpun();
void __aeabi_ddiv();
void __aeabi_f2d();
void __aeabi_f2iz();
void __aeabi_f2lz();
void __aeabi_f2ulz();
void __aeabi_fcmpge();
void __aeabi_fcmple();
void __aeabi_fcmplt();
void __aeabi_fcmpun();
void __aeabi_i2d();
void __aeabi_idiv();
void __aeabi_idivmod();
void __aeabi_l2d();
void __aeabi_l2f();
void __aeabi_ldivmod();
void __aeabi_ui2d();
void __aeabi_uidiv();
void __aeabi_uidivmod();
void __aeabi_ul2d();
void __aeabi_ul2f();
void __aeabi_uldivmod();
void __ashldi3();
void __clzsi2();
void __divdf3();
void __divdi3();
void __divsi3();
void __eqdf2();
void __eqsf2();
void __extendsfdf2();
void __fixdfdi();
void __fixdfsi();
void __fixsfdi();
void __fixunsdfdi();
void __fixunsdfsi();
void __fixunssfdi();
void __floatdidf();
void __floatdisf();
void __floatsidf();
void __floatsisf();
void __floatundidf();
void __floatundisf();
void __floatunsidf();
void __floatunsisf();
void __gedf2();
void __gesf2();
void __gtdf2();
void __gtsf2();
void __ledf2();
void __lesf2();
void __lshrdi3();
void __ltdf2();
void __ltsf2();
void __moddi3();
void __modsi3();
void __muldf3();
void __muldi3();
void __mulsf3();
void __nedf2();
void __nesf2();
void __subdf3();
void __subsf3();
void __truncdfsf2();
void __udivdi3();
void __udivmoddi4();
void __udivsi3();
void __umoddi3();
void __umodsi3();
void __unorddf2();
void __unordsf2();
/* clang-format on */

static SymbolMap target_sym_map[] = {
    /* clang-format off */
    REG_COMMON_SYMBOLS
    /* compiler-rt symbols that come from compiler(e.g. gcc) */
#if __ARM_ARCH != 6
    REG_SYM(__adddf3),
    REG_SYM(__addsf3),
    REG_SYM(__divdf3),
    REG_SYM(__extendsfdf2),
    REG_SYM(__fixdfsi),
    REG_SYM(__floatsidf),
    REG_SYM(__floatsisf),
    REG_SYM(__floatunsidf),
    REG_SYM(__floatunsisf),
    REG_SYM(__muldf3),
    REG_SYM(__mulsf3),
    REG_SYM(__subdf3),
    REG_SYM(__subsf3),
    REG_SYM(__truncdfsf2),
    REG_SYM(__unorddf2),
    REG_SYM(__unordsf2),
#endif
    /* clang-format on */
    REG_SYM(__aeabi_d2iz),
    REG_SYM(__aeabi_d2lz),
    REG_SYM(__aeabi_d2uiz),
    REG_SYM(__aeabi_d2ulz),
    REG_SYM(__aeabi_dadd),
    REG_SYM(__aeabi_dcmpge),
    REG_SYM(__aeabi_dcmpgt),
    REG_SYM(__aeabi_dcmple),
    REG_SYM(__aeabi_dcmplt),
    REG_SYM(__aeabi_dcmpun),
    REG_SYM(__aeabi_ddiv),
    REG_SYM(__aeabi_f2d),
    REG_SYM(__aeabi_f2iz),
    REG_SYM(__aeabi_f2lz),
    REG_SYM(__aeabi_f2ulz),
    REG_SYM(__aeabi_fcmpge),
    REG_SYM(__aeabi_fcmple),
    REG_SYM(__aeabi_fcmplt),
    REG_SYM(__aeabi_fcmpun),
    REG_SYM(__aeabi_i2d),
    REG_SYM(__aeabi_idiv),
    REG_SYM(__aeabi_idivmod),
    REG_SYM(__aeabi_l2d),
    REG_SYM(__aeabi_l2f),
    REG_SYM(__aeabi_ldivmod),
    REG_SYM(__aeabi_ui2d),
    REG_SYM(__aeabi_uidiv),
    REG_SYM(__aeabi_uidivmod),
    REG_SYM(__aeabi_ul2d),
    REG_SYM(__aeabi_ul2f),
    REG_SYM(__aeabi_uldivmod),
    REG_SYM(__ashldi3),
    REG_SYM(__clzsi2),
    REG_SYM(__divdi3),
    REG_SYM(__divsi3),
    REG_SYM(__eqdf2),
    REG_SYM(__eqsf2),
    REG_SYM(__fixdfdi),
    REG_SYM(__fixsfdi),
    REG_SYM(__fixunsdfdi),
    REG_SYM(__fixunsdfsi),
    REG_SYM(__fixunssfdi),
    REG_SYM(__floatdidf),
    REG_SYM(__floatdisf),
    REG_SYM(__floatundidf),
    REG_SYM(__floatundisf),
    REG_SYM(__gedf2),
    REG_SYM(__gesf2),
    REG_SYM(__gtdf2),
    REG_SYM(__gtsf2),
    REG_SYM(__ledf2),
    REG_SYM(__lesf2),
    REG_SYM(__lshrdi3),
    REG_SYM(__ltdf2),
    REG_SYM(__ltsf2),
    REG_SYM(__moddi3),
    REG_SYM(__modsi3),
    REG_SYM(__muldi3),
    REG_SYM(__nedf2),
    REG_SYM(__nesf2),
    REG_SYM(__udivdi3),
    REG_SYM(__udivmoddi4),
    REG_SYM(__udivsi3),
    REG_SYM(__umoddi3),
    REG_SYM(__umodsi3),
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

#define BUILD_TARGET_THUMB_V4T "thumbv4t"
void
get_current_target(char *target_buf, uint32 target_buf_size)
{
    const char *s = BUILD_TARGET;
    size_t s_size = sizeof(BUILD_TARGET);
    char *d = target_buf;

    /* Set to "thumbv4t" by default if sub version isn't specified */
    if (strcmp(s, "THUMB") == 0) {
        s = BUILD_TARGET_THUMB_V4T;
        s_size = sizeof(BUILD_TARGET_THUMB_V4T);
    }
    if (target_buf_size < s_size) {
        s_size = target_buf_size;
    }
    while (--s_size) {
        if (*s >= 'A' && *s <= 'Z')
            *d++ = *s++ + 'a' - 'A';
        else
            *d++ = *s++;
    }
    /* Ensure the string is null byte ('\0') terminated */
    *d = '\0';
}
#undef BUILD_TARGET_THUMB_V4T

uint32
get_plt_item_size()
{
    /* 16 bytes instructions and 4 bytes symbol address */
    return 20;
}

uint32
get_plt_table_size()
{
    return get_plt_item_size() * (sizeof(target_sym_map) / sizeof(SymbolMap));
}

void
init_plt_table(uint8 *plt)
{
    uint32 i, num = sizeof(target_sym_map) / sizeof(SymbolMap);
    for (i = 0; i < num; i++) {
        uint16 *p = (uint16 *)plt;
        /* nop */
        *p++ = 0xbf00;
        /* push {r4} */
        *p++ = 0xb410;
        /* add  r4, pc, #8 */
        *p++ = 0xa402;
        /* ldr  r4, [r4, #0] */
        *p++ = 0x6824;
        /* mov  ip, r4 */
        *p++ = 0x46a4;
        /* pop  {r4} */
        *p++ = 0xbc10;
        /* mov  pc, ip */
        *p++ = 0x46e7;
        /* nop */
        *p++ = 0xbf00;
        /* symbol addr */
        *(uint32 *)p = (uint32)(uintptr_t)target_sym_map[i].symbol_addr;
        plt += get_plt_item_size();
    }
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

bool
apply_relocation(AOTModule *module, uint8 *target_section_addr,
                 uint32 target_section_size, uint64 reloc_offset,
                 int64 reloc_addend, uint32 reloc_type, void *symbol_addr,
                 int32 symbol_index, char *error_buf, uint32 error_buf_size)
{
    switch (reloc_type) {
        case R_ARM_THM_CALL:
        case R_ARM_THM_JMP24:
        {
            int32 RESULT_MASK = 0x01FFFFFE;
            int32 result, result_masked;
            int16 *reloc_addr;
            int32 initial_addend_0, initial_addend_1, initial_addend;
            bool sign;

            CHECK_RELOC_OFFSET(sizeof(int32));

            reloc_addr = (int16 *)(target_section_addr + reloc_offset);
            initial_addend_0 = (*reloc_addr) & 0x7FF;
            initial_addend_1 = (*(reloc_addr + 1)) & 0x7FF;
            sign = (initial_addend_0 & 0x400) ? true : false;
            initial_addend = (initial_addend_0 << 12) | (initial_addend_1 << 1)
                             | (sign ? 0xFF800000 : 0);

            if (symbol_index < 0) {
                /* Symbol address itself is an AOT function.
                 * Apply relocation with the symbol directly.
                 * Suppose the symbol address is in +-4MB relative
                 * to the relocation address.
                 */
                /* operation: ((S + A) | T) - P  where S is symbol address
                   and T is 1 */
                result =
                    (int32)(((intptr_t)((uintptr_t)symbol_addr
                                        + (intptr_t)reloc_addend)
                             | 1)
                            - (intptr_t)(target_section_addr + reloc_offset));
            }
            else {
                if (reloc_addend > 0) {
                    set_error_buf(
                        error_buf, error_buf_size,
                        "AOT module load failed: relocate to plt table "
                        "with reloc addend larger than 0 is unsupported.");
                    return false;
                }

                /* Symbol address is not an AOT function,
                 * but a function of runtime or native. Its address is
                 * beyond of the +-4MB space. Apply relocation with
                 * the PLT which branch to the target symbol address.
                 */
                /* operation: ((S + A) | T) - P  where S is PLT address
                   and T is 1 */
                uint8 *plt = (uint8 *)module->code + module->code_size
                             - get_plt_table_size()
                             + get_plt_item_size() * symbol_index + 1;
                result =
                    (int32)(((intptr_t)plt | 1)
                            - (intptr_t)(target_section_addr + reloc_offset));
            }

            result += initial_addend;

            /* Check overflow: +-4MB */
            if (result > (4 * BH_MB) || result < (-4 * BH_MB)) {
                set_error_buf(error_buf, error_buf_size,
                              "AOT module load failed: "
                              "target address out of range.");
                return false;
            }

            result_masked = (int32)result & RESULT_MASK;
            initial_addend_0 = (result_masked >> 12) & 0x7FF;
            initial_addend_1 = (result_masked >> 1) & 0x7FF;

            *reloc_addr = (*reloc_addr & ~0x7FF) | initial_addend_0;
            *(reloc_addr + 1) = (*(reloc_addr + 1) & ~0x7FF) | initial_addend_1;
            break;
        }
        case R_ARM_ABS32:
        {
            intptr_t initial_addend;
            /* (S + A) | T where T is 0 */
            CHECK_RELOC_OFFSET(sizeof(void *));
            initial_addend =
                *(intptr_t *)(target_section_addr + (uint32)reloc_offset);
            *(uintptr_t *)(target_section_addr + reloc_offset) =
                (uintptr_t)symbol_addr + initial_addend
                + (intptr_t)reloc_addend;
            break;
        }
        case R_ARM_THM_MOVW_ABS_NC:
        case R_ARM_THM_MOVT_ABS:
        case R_ARM_THM_MOVW_PREL_NC:
        case R_ARM_THM_MOVT_PREL:
        {
            uint16 upper = *(uint16 *)(target_section_addr + reloc_offset);
            uint16 lower = *(uint16 *)(target_section_addr + reloc_offset + 2);
            int32 offset;

            /*
             * MOVT/MOVW instructions encoding in Thumb-2:
             *
             * i	= upper[10]
             * imm4	= upper[3:0]
             * imm3	= lower[14:12]
             * imm8	= lower[7:0]
             *
             * imm16 = imm4:i:imm3:imm8
             */

            offset = ((upper & 0x000f) << 12) | ((upper & 0x0400) << 1)
                     | ((lower & 0x7000) >> 4) | (lower & 0x00ff);
            offset = (offset ^ 0x8000) - 0x8000;

            offset += (symbol_addr + reloc_addend);

            if (reloc_type == R_ARM_THM_MOVT_PREL
                || reloc_type == R_ARM_THM_MOVW_PREL_NC)
                offset -= (int32)(target_section_addr + reloc_offset);
            if (reloc_type == R_ARM_THM_MOVT_ABS
                || reloc_type == R_ARM_THM_MOVT_PREL)
                offset >>= 16;

            upper = (uint16)((upper & 0xfbf0) | ((offset & 0xf000) >> 12)
                             | ((offset & 0x0800) >> 1));
            lower = (uint16)((lower & 0x8f00) | ((offset & 0x0700) << 4)
                             | (offset & 0x00ff));

            *(uint16 *)(target_section_addr + reloc_offset) = upper;
            *(uint16 *)(target_section_addr + reloc_offset + 2) = lower;
            break;
        }

        default:
            if (error_buf != NULL)
                snprintf(error_buf, error_buf_size,
                         "Load relocation section failed: "
                         "invalid relocation type %" PRId32 ".",
                         reloc_type);
            return false;
    }
    return true;
}
