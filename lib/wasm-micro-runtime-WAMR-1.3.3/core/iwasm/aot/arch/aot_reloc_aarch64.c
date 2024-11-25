/*
 * Copyright (C) 2020 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_reloc.h"

#define R_AARCH64_MOVW_UABS_G0 263
#define R_AARCH64_MOVW_UABS_G0_NC 264
#define R_AARCH64_MOVW_UABS_G1 265
#define R_AARCH64_MOVW_UABS_G1_NC 266
#define R_AARCH64_MOVW_UABS_G2 267
#define R_AARCH64_MOVW_UABS_G2_NC 268
#define R_AARCH64_MOVW_UABS_G3 269

#define R_AARCH64_MOVW_SABS_G0 270
#define R_AARCH64_MOVW_SABS_G1 271
#define R_AARCH64_MOVW_SABS_G2 272

#define R_AARCH64_ADR_PREL_LO19 273
#define R_AARCH64_ADR_PREL_LO21 274
#define R_AARCH64_ADR_PREL_PG_HI21 275
#define R_AARCH64_ADR_PREL_PG_HI21_NC 276

#define R_AARCH64_ADD_ABS_LO12_NC 277

#define R_AARCH64_LDST8_ABS_LO12_NC 278
#define R_AARCH64_LDST16_ABS_LO12_NC 284
#define R_AARCH64_LDST32_ABS_LO12_NC 285
#define R_AARCH64_LDST64_ABS_LO12_NC 286
#define R_AARCH64_LDST128_ABS_LO12_NC 299

#define R_AARCH64_JUMP26 282
#define R_AARCH64_CALL26 283

/* clang-format off */
static SymbolMap target_sym_map[] = {
    REG_COMMON_SYMBOLS
};
/* clang-format on */

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

#if (defined(__APPLE__) || defined(__MACH__)) && defined(__arm64__)
#define BUILD_TARGET_AARCH64_DEFAULT "arm64"
#else
#define BUILD_TARGET_AARCH64_DEFAULT "aarch64v8"
#endif

void
get_current_target(char *target_buf, uint32 target_buf_size)
{
    const char *s = BUILD_TARGET;
    size_t s_size = sizeof(BUILD_TARGET);
    char *d = target_buf;

    /* Set to "aarch64v8" by default if sub version isn't specified */
    if (strcmp(s, "AARCH64") == 0) {
        s = BUILD_TARGET_AARCH64_DEFAULT;
        s_size = sizeof(BUILD_TARGET_AARCH64_DEFAULT);
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
#undef BUILD_TARGET_AARCH64_DEFAULT

static uint32
get_plt_item_size()
{
    /* 6*4 bytes instructions and 8 bytes symbol address */
    return 32;
}

void
init_plt_table(uint8 *plt)
{
    uint32 i, num = sizeof(target_sym_map) / sizeof(SymbolMap);
    for (i = 0; i < num; i++) {
        uint32 *p = (uint32 *)plt;
        *p++ = 0xf81f0ffe; /* str  x30, [sp, #-16]! */
        *p++ = 0x100000be; /* adr  x30, #20; symbol addr is PC + 5 instructions
                              below */
        *p++ = 0xf94003de; /* ldr  x30, [x30]   */
        *p++ = 0xd63f03c0; /* blr  x30          */
        *p++ = 0xf84107fe; /* ldr  x30, [sp], #16  */
        *p++ = 0xd61f03c0; /* br   x30          */
        /* symbol addr */
        *(uint64 *)p = (uint64)(uintptr_t)target_sym_map[i].symbol_addr;
        p += 2;
        plt += get_plt_item_size();
    }
}

uint32
get_plt_table_size()
{
    return get_plt_item_size() * (sizeof(target_sym_map) / sizeof(SymbolMap));
}

#define SIGN_EXTEND_TO_INT64(val, bits, val_ext)    \
    do {                                            \
        int64 m = (int64)((uint64)1 << (bits - 1)); \
        val_ext = ((int64)val ^ m) - m;             \
    } while (0)

#define Page(expr) ((expr) & ~0xFFF)

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
        case R_AARCH64_CALL26:
        case R_AARCH64_JUMP26:
        {
            void *S, *P = (void *)(target_section_addr + reloc_offset);
            int64 X, A, initial_addend;
            int32 insn, imm26;

            CHECK_RELOC_OFFSET(sizeof(int32));

            insn = *(int32 *)P;
            imm26 = insn & 0x3FFFFFF;
            SIGN_EXTEND_TO_INT64(imm26 << 2, 28, initial_addend);
            A = initial_addend;
            A += (int64)reloc_addend;

            if (symbol_index < 0) {
                /* Symbol address itself is an AOT function.
                 * Apply relocation with the symbol directly.
                 * Suppose the symbol address is in +-128MB relative
                 * to the relocation address.
                 */
                S = symbol_addr;
            }
            else {
                uint8 *plt;
                if (reloc_addend > 0) {
                    set_error_buf(
                        error_buf, error_buf_size,
                        "AOT module load failed: relocate to plt table "
                        "with reloc addend larger than 0 is unsupported.");
                    return false;
                }
                /* Symbol address is not an AOT function,
                 * but a function of runtime or native. Its address is
                 * beyond of the +-128MB space. Apply relocation with
                 * the PLT which branch to the target symbol address.
                 */
                S = plt = (uint8 *)module->code + module->code_size
                          - get_plt_table_size()
                          + get_plt_item_size() * symbol_index;
            }

            /* S + A - P */
            X = (int64)S + A - (int64)P;

            /* Check overflow: +-128MB */
            if (X > (128 * BH_MB) || X < (-128 * BH_MB)) {
                set_error_buf(error_buf, error_buf_size,
                              "AOT module load failed: "
                              "target address out of range.");
                return false;
            }

            /* write the imm26 back to instruction */
            *(int32 *)P = (insn & 0xFC000000) | ((int32)((X >> 2) & 0x3FFFFFF));
            break;
        }

        case R_AARCH64_MOVW_UABS_G0:
        case R_AARCH64_MOVW_UABS_G0_NC:
        case R_AARCH64_MOVW_UABS_G1:
        case R_AARCH64_MOVW_UABS_G1_NC:
        case R_AARCH64_MOVW_UABS_G2:
        case R_AARCH64_MOVW_UABS_G2_NC:
        case R_AARCH64_MOVW_UABS_G3:
        {
            void *S = symbol_addr,
                 *P = (void *)(target_section_addr + reloc_offset);
            int64 X, A, initial_addend;
            int32 insn, imm16;

            CHECK_RELOC_OFFSET(sizeof(int32));

            insn = *(int32 *)P;
            imm16 = (insn >> 5) & 0xFFFF;

            SIGN_EXTEND_TO_INT64(imm16, 16, initial_addend);
            A = initial_addend;
            A += (int64)reloc_addend;

            /* S + A */
            X = (int64)S + A;

            /* No need to check overflow for this relocation type */
            switch (reloc_type) {
                case R_AARCH64_MOVW_UABS_G0:
                    if (X < 0 || X >= (1LL << 16))
                        goto overflow_check_fail;
                    break;
                case R_AARCH64_MOVW_UABS_G1:
                    if (X < 0 || X >= (1LL << 32))
                        goto overflow_check_fail;
                    break;
                case R_AARCH64_MOVW_UABS_G2:
                    if (X < 0 || X >= (1LL << 48))
                        goto overflow_check_fail;
                    break;
                default:
                    break;
            }

            /* write the imm16 back to bits[5:20] of instruction */
            switch (reloc_type) {
                case R_AARCH64_MOVW_UABS_G0:
                case R_AARCH64_MOVW_UABS_G0_NC:
                    *(int32 *)P =
                        (insn & 0xFFE0001F) | ((int32)((X & 0xFFFF) << 5));
                    break;
                case R_AARCH64_MOVW_UABS_G1:
                case R_AARCH64_MOVW_UABS_G1_NC:
                    *(int32 *)P = (insn & 0xFFE0001F)
                                  | ((int32)(((X >> 16) & 0xFFFF) << 5));
                    break;
                case R_AARCH64_MOVW_UABS_G2:
                case R_AARCH64_MOVW_UABS_G2_NC:
                    *(int32 *)P = (insn & 0xFFE0001F)
                                  | ((int32)(((X >> 32) & 0xFFFF) << 5));
                    break;
                case R_AARCH64_MOVW_UABS_G3:
                    *(int32 *)P = (insn & 0xFFE0001F)
                                  | ((int32)(((X >> 48) & 0xFFFF) << 5));
                    break;
                default:
                    bh_assert(0);
                    break;
            }
            break;
        }

        case R_AARCH64_ADR_PREL_PG_HI21:
        case R_AARCH64_ADR_PREL_PG_HI21_NC:
        {
            void *S = symbol_addr,
                 *P = (void *)(target_section_addr + reloc_offset);
            int64 X, A, initial_addend;
            int32 insn, immhi19, immlo2, imm21;

            CHECK_RELOC_OFFSET(sizeof(int32));

            insn = *(int32 *)P;
            immhi19 = (insn >> 5) & 0x7FFFF;
            immlo2 = (insn >> 29) & 0x3;
            imm21 = (immhi19 << 2) | immlo2;

            SIGN_EXTEND_TO_INT64(imm21 << 12, 33, initial_addend);
            A = initial_addend;
            A += (int64)reloc_addend;

            /* Page(S+A) - Page(P) */
            X = Page((int64)S + A) - Page((int64)P);

            /* Check overflow: +-4GB */
            if (reloc_type == R_AARCH64_ADR_PREL_PG_HI21
                && (X > ((int64)4 * BH_GB) || X < ((int64)-4 * BH_GB)))
                goto overflow_check_fail;

            /* write the imm21 back to instruction */
            immhi19 = (int32)(((X >> 12) >> 2) & 0x7FFFF);
            immlo2 = (int32)((X >> 12) & 0x3);
            *(int32 *)P = (insn & 0x9F00001F) | (immlo2 << 29) | (immhi19 << 5);

            break;
        }

        case R_AARCH64_ADD_ABS_LO12_NC:
        {
            void *S = symbol_addr,
                 *P = (void *)(target_section_addr + reloc_offset);
            int64 X, A, initial_addend;
            int32 insn, imm12;

            CHECK_RELOC_OFFSET(sizeof(int32));

            insn = *(int32 *)P;
            imm12 = (insn >> 10) & 0xFFF;

            SIGN_EXTEND_TO_INT64(imm12, 12, initial_addend);
            A = initial_addend;
            A += (int64)reloc_addend;

            /* S + A */
            X = (int64)S + A;

            /* No need to check overflow for this relocation type */

            /* write the imm12 back to instruction */
            *(int32 *)P = (insn & 0xFFC003FF) | ((int32)((X & 0xFFF) << 10));
            break;
        }

        case R_AARCH64_LDST8_ABS_LO12_NC:
        case R_AARCH64_LDST16_ABS_LO12_NC:
        case R_AARCH64_LDST32_ABS_LO12_NC:
        case R_AARCH64_LDST64_ABS_LO12_NC:
        case R_AARCH64_LDST128_ABS_LO12_NC:
        {
            void *S = symbol_addr,
                 *P = (void *)(target_section_addr + reloc_offset);
            int64 X, A, initial_addend;
            int32 insn, imm12;

            CHECK_RELOC_OFFSET(sizeof(int32));

            insn = *(int32 *)P;
            imm12 = (insn >> 10) & 0xFFF;

            SIGN_EXTEND_TO_INT64(imm12, 12, initial_addend);
            A = initial_addend;
            A += (int64)reloc_addend;

            /* S + A */
            X = (int64)S + A;

            /* No need to check overflow for this relocation type */

            /* write the imm12 back to instruction */
            switch (reloc_type) {
                case R_AARCH64_LDST8_ABS_LO12_NC:
                    *(int32 *)P =
                        (insn & 0xFFC003FF) | ((int32)((X & 0xFFF) << 10));
                    break;
                case R_AARCH64_LDST16_ABS_LO12_NC:
                    *(int32 *)P = (insn & 0xFFC003FF)
                                  | ((int32)(((X & 0xFFF) >> 1) << 10));
                    break;
                case R_AARCH64_LDST32_ABS_LO12_NC:
                    *(int32 *)P = (insn & 0xFFC003FF)
                                  | ((int32)(((X & 0xFFF) >> 2) << 10));
                    break;
                case R_AARCH64_LDST64_ABS_LO12_NC:
                    *(int32 *)P = (insn & 0xFFC003FF)
                                  | ((int32)(((X & 0xFFF) >> 3) << 10));
                    break;
                case R_AARCH64_LDST128_ABS_LO12_NC:
                    *(int32 *)P = (insn & 0xFFC003FF)
                                  | ((int32)(((X & 0xFFF) >> 4) << 10));
                    break;
                default:
                    bh_assert(0);
                    break;
            }
            break;
        }

        default:
            if (error_buf != NULL)
                snprintf(error_buf, error_buf_size,
                         "Load relocation section failed: "
                         "invalid relocation type %d.",
                         reloc_type);
            return false;
    }

    return true;

overflow_check_fail:
    set_error_buf(error_buf, error_buf_size,
                  "AOT module load failed: "
                  "target address out of range.");
    return false;
}
