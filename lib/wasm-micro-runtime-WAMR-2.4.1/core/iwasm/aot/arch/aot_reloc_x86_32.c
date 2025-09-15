/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_reloc.h"

/* clang-format off */
#if !defined(BH_PLATFORM_WINDOWS)
#define R_386_32 1    /* Direct 32 bit  */
#define R_386_PC32 2  /* PC relative 32 bit */
#define R_386_PLT32 4 /* 32-bit address ProcedureLinkageTable */
#define R_386_TLS_GD_32 24 /* Direct 32 bit for general dynamic
                              thread local data */
#else
#define IMAGE_REL_I386_DIR32 6 /* The target's 32-bit VA */
#define IMAGE_REL_I386_REL32 20 /* The 32-bit relative displacement
                                   to the target */
#endif
/* clang-format on */

#if !defined(_WIN32) && !defined(_WIN32_)
/* clang-format off */
void __divdi3();
void __udivdi3();
void __moddi3();
void __umoddi3();
/* clang-format on */
#else
#pragma function(floor)
#pragma function(ceil)

static int64 __stdcall __divdi3(int64 a, int64 b)
{
    return a / b;
}

static uint64 __stdcall __udivdi3(uint64 a, uint64 b)
{
    return a / b;
}

static int64 __stdcall __moddi3(int64 a, int64 b)
{
    return a % b;
}

static uint64 __stdcall __umoddi3(uint64 a, uint64 b)
{
    return a % b;
}

static uint64 __stdcall __aulldiv(uint64 a, uint64 b)
{
    return a / b;
}
static int64 __stdcall __alldiv(int64 a, int64 b)
{
    return a / b;
}
static int64 __stdcall __allrem(int64 a, int64 b)
{
    return a % b;
}
#endif /* !defined(_WIN32) && !defined(_WIN32_) */

/* clang-format off */
static SymbolMap target_sym_map[] = {
    REG_COMMON_SYMBOLS
    /* compiler-rt symbols that come from compiler(e.g. gcc) */
    REG_SYM(__divdi3),
    REG_SYM(__udivdi3),
    REG_SYM(__moddi3),
    REG_SYM(__umoddi3),
#if defined(_WIN32) || defined(_WIN32_)
    REG_SYM(__aulldiv),
    REG_SYM(__alldiv),
    REG_SYM(__allrem)
#endif /* defined(_WIN32) || defined(_WIN32_) */
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

void
get_current_target(char *target_buf, uint32 target_buf_size)
{
    snprintf(target_buf, target_buf_size, "i386");
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

bool
apply_relocation(AOTModule *module, uint8 *target_section_addr,
                 uint32 target_section_size, uint64 reloc_offset,
                 int64 reloc_addend, uint32 reloc_type, void *symbol_addr,
                 int32 symbol_index, char *error_buf, uint32 error_buf_size)
{
    switch (reloc_type) {
#if !defined(BH_PLATFORM_WINDOWS)
        case R_386_32:
#if WASM_ENABLE_STATIC_PGO != 0
        case R_386_TLS_GD_32:
#endif
#else
        case IMAGE_REL_I386_DIR32:
#endif
        {
            intptr_t value;

            CHECK_RELOC_OFFSET(sizeof(void *));
            value = *(intptr_t *)(target_section_addr + (uint32)reloc_offset);
            *(uintptr_t *)(target_section_addr + reloc_offset) =
                (uintptr_t)symbol_addr + (intptr_t)reloc_addend
                + value; /* S + A */
            break;
        }

#if !defined(BH_PLATFORM_WINDOWS)
        /*
         * Handle R_386_PLT32 like R_386_PC32 since it should be able to reach
         * any 32 bit address
         */
        case R_386_PLT32:
        case R_386_PC32:
#else
        case IMAGE_REL_I386_REL32:
#endif
        {
            int32 value;

            CHECK_RELOC_OFFSET(sizeof(void *));
            value = *(int32 *)(target_section_addr + (uint32)reloc_offset);
            *(uint32 *)(target_section_addr + (uint32)reloc_offset) =
                (uint32)((uintptr_t)symbol_addr + (intptr_t)reloc_addend
                         - (uintptr_t)(target_section_addr
                                       + (uint32)reloc_offset)
#if defined(BH_PLATFORM_WINDOWS)
                         - sizeof(int32)
#endif
                         + value); /* S + A - P */
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
}
