/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_reloc.h"

#define R_XTENSA_32 1        /* Direct 32 bit */
#define R_XTENSA_SLOT0_OP 20 /* PC relative */

/* clang-format off */
/* for soft-float */
void __floatsidf(void);
void __divdf3(void);
void __ltdf2(void);

/* for mul32 */
void __mulsi3(void);
void __muldi3(void);

void __modsi3(void);

void __divdi3(void);

void __udivdi3(void);
void __unorddf2(void);
void __adddf3(void);
void __eqdf2(void);
void __muldf3(void);
void __gedf2(void);
void __ledf2(void);
void __fixunsdfsi(void);
void __floatunsidf(void);
void __subdf3(void);
void __nedf2(void);
void __fixdfsi(void);
void __moddi3(void);
void __extendsfdf2(void);
void __truncdfsf2(void);
void __gtdf2(void);
void __umoddi3(void);
void __floatdidf(void);
void __divsf3(void);
void __fixdfdi(void);
void __floatundidf(void);
void __fixsfdi(void);
void __fixunssfdi(void);
void __fixunsdfdi(void);
void __floatdisf(void);
void __floatundisf(void);


static SymbolMap target_sym_map[] = {
    REG_COMMON_SYMBOLS

    /* API's for soft-float */
    /* TODO: only register these symbols when Floating-Point Coprocessor
     * Option is not enabled */
    REG_SYM(__floatsidf),
    REG_SYM(__divdf3),
    REG_SYM(__ltdf2),

    /* API's for 32-bit integer multiply */
    /* TODO: only register these symbols when 32-bit Integer Multiply Option
     * is not enabled */
    REG_SYM(__mulsi3),
    REG_SYM(__muldi3),

    REG_SYM(__modsi3),
    REG_SYM(__divdi3),

    REG_SYM(__udivdi3),
    REG_SYM(__unorddf2),
    REG_SYM(__adddf3),
    REG_SYM(__eqdf2),
    REG_SYM(__muldf3),
    REG_SYM(__gedf2),
    REG_SYM(__ledf2),
    REG_SYM(__fixunsdfsi),
    REG_SYM(__floatunsidf),
    REG_SYM(__subdf3),
    REG_SYM(__nedf2),
    REG_SYM(__fixdfsi),
    REG_SYM(__moddi3),
    REG_SYM(__extendsfdf2),
    REG_SYM(__truncdfsf2),
    REG_SYM(__gtdf2),
    REG_SYM(__umoddi3),
    REG_SYM(__floatdidf),
    REG_SYM(__divsf3),
    REG_SYM(__fixdfdi),
    REG_SYM(__floatundidf),
    REG_SYM(__fixsfdi),
    REG_SYM(__fixunssfdi),
    REG_SYM(__fixunsdfdi),
    REG_SYM(__floatdisf),
    REG_SYM(__floatundisf),
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
    snprintf(target_buf, target_buf_size, "xtensa");
}

static uint32
get_plt_item_size(void)
{
    return 0;
}

void
init_plt_table(uint8 *plt)
{
    (void)plt;
}

uint32
get_plt_table_size()
{
    return get_plt_item_size() * (sizeof(target_sym_map) / sizeof(SymbolMap));
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

/*
 * CPU like esp32 can read and write data through the instruction bus, but only
 * in a word aligned manner; non-word-aligned access will cause a CPU exception.
 * This function uses a world aligned manner to write 16bit value to instruction
 * address.
 */
static void
put_imm16_to_addr(int16 imm16, int16 *addr)
{
    int8 bytes[8];
    int32 *addr_aligned1, *addr_aligned2;

    addr_aligned1 = (int32 *)((intptr_t)addr & ~3);

    if ((intptr_t)addr % 4 != 3) {
        *(int32 *)bytes = *addr_aligned1;
        *(int16 *)(bytes + ((intptr_t)addr % 4)) = imm16;
        *addr_aligned1 = *(int32 *)bytes;
    }
    else {
        addr_aligned2 = (int32 *)(((intptr_t)addr + 3) & ~3);
        *(int32 *)bytes = *addr_aligned1;
        *(int32 *)(bytes + 4) = *addr_aligned2;
        *(int16 *)(bytes + 3) = imm16;
        memcpy(addr_aligned1, bytes, 8);
    }
}

static union {
    int a;
    char b;
} __ue = { .a = 1 };

#define is_little_endian() (__ue.b == 1)

#if !defined(__packed)
/*
 * Note: This version check is a bit relaxed.
 * The __packed__ attribute has been there since gcc 2 era.
 */
#if __GNUC__ >= 3
#define __packed __attribute__((__packed__))
#endif
#endif

typedef union {
    struct l32r_le {
        int8 other;
        int16 imm16;
    } __packed l;

    struct l32r_be {
        int16 imm16;
        int8 other;
    } __packed b;
} l32r_insn_t;

bool
apply_relocation(AOTModule *module, uint8 *target_section_addr,
                 uint32 target_section_size, uint64 reloc_offset,
                 int64 reloc_addend, uint32 reloc_type, void *symbol_addr,
                 int32 symbol_index, char *error_buf, uint32 error_buf_size)
{
    switch (reloc_type) {
        case R_XTENSA_32:
        {
            uint8 *insn_addr = target_section_addr + reloc_offset;
#if (WASM_MEM_DUAL_BUS_MIRROR != 0)
            insn_addr = os_get_dbus_mirror((void *)insn_addr);
            bh_assert(insn_addr != NULL);
#endif
            int32 initial_addend;
            /* (S + A) */
            if ((intptr_t)insn_addr & 3) {
                set_error_buf(error_buf, error_buf_size,
                              "AOT module load failed: "
                              "instruction address unaligned.");
                return false;
            }
            CHECK_RELOC_OFFSET(4);
            initial_addend = *(int32 *)insn_addr;
            *(uintptr_t *)insn_addr = (uintptr_t)symbol_addr + initial_addend
                                      + (intptr_t)reloc_addend;
            break;
        }

        case R_XTENSA_SLOT0_OP:
        {
            uint8 *insn_addr = target_section_addr + reloc_offset;
            /* Currently only l32r instruction generates R_XTENSA_SLOT0_OP
             * relocation */
            l32r_insn_t *l32r_insn = (l32r_insn_t *)insn_addr;
            uint8 *reloc_addr;
            int32 relative_offset /*, initial_addend */;
            int16 imm16;

            CHECK_RELOC_OFFSET(3); /* size of l32r instruction */

            /*
            imm16 = is_little_endian() ?
                    l32r_insn->l.imm16 : l32r_insn->b.imm16;
            initial_addend = (int32)imm16 << 2;
            */

            reloc_addr =
                (uint8 *)((uintptr_t)symbol_addr + (intptr_t)reloc_addend);

            if ((intptr_t)reloc_addr & 3) {
                set_error_buf(error_buf, error_buf_size,
                              "AOT module load failed: "
                              "relocation address unaligned.");
                return false;
            }

            relative_offset =
                (int32)((intptr_t)reloc_addr
                        - (((intptr_t)insn_addr + 3) & ~(intptr_t)3));
            /* relative_offset += initial_addend; */

            /* check relative offset boundary */
            if (relative_offset < -256 * BH_KB || relative_offset > -4) {
                set_error_buf(error_buf, error_buf_size,
                              "AOT module load failed: "
                              "target address out of range.\n"
                              "Try using `wamrc --size-level=0` to generate "
                              ".literal island.");
                return false;
            }

#if (WASM_MEM_DUAL_BUS_MIRROR != 0)
            insn_addr = os_get_dbus_mirror((void *)insn_addr);
            bh_assert(insn_addr != NULL);
            l32r_insn = (l32r_insn_t *)insn_addr;
#endif
            imm16 = (int16)(relative_offset >> 2);

            /* write back the imm16 to the l32r instruction */

            /* GCC >= 9 complains if we have a pointer that could be
             * unaligned. This can happen because the struct is packed.
             * These pragma are to suppress the warnings because the
             * function put_imm16_to_addr already handles unaligned
             * pointers correctly. */
#if __GNUC__ >= 9
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif
            if (is_little_endian())
                put_imm16_to_addr(imm16, &l32r_insn->l.imm16);
            else
                put_imm16_to_addr(imm16, &l32r_insn->b.imm16);
#if __GNUC__ >= 9
#pragma GCC diagnostic pop
#endif
            break;
        }

        default:
            if (error_buf != NULL)
                snprintf(error_buf, error_buf_size,
                         "Load relocation section failed: "
                         "invalid relocation type %d.",
                         (int)reloc_type);
            return false;
    }

    return true;
}
