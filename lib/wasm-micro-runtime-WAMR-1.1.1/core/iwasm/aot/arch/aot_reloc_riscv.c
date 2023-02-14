/*
 * Copyright (C) 2021 XiaoMi Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_reloc.h"

#define R_RISCV_32 1
#define R_RISCV_64 2
#define R_RISCV_CALL 18
#define R_RISCV_CALL_PLT 19
#define R_RISCV_HI20 26
#define R_RISCV_LO12_I 27
#define R_RISCV_LO12_S 28

#define RV_OPCODE_SW 0x23

/* clang-format off */
void __divdi3();
void __divsi3();
void __fixdfdi();
void __fixsfdi();
void __fixunsdfdi();
void __fixunssfdi();
void __floatdidf();
void __floatdisf();
void __floatundidf();
void __floatundisf();
void __moddi3();
void __modsi3();
void __muldi3();
void __mulsi3();
void __udivdi3();
void __udivsi3();
void __umoddi3();
void __umodsi3();
/* clang-format on */

static SymbolMap target_sym_map[] = {
    /* clang-format off */
    REG_COMMON_SYMBOLS
    REG_SYM(__divdi3),
    REG_SYM(__divsi3),
#if __riscv_xlen == 32
    REG_SYM(__fixdfdi),
    REG_SYM(__fixsfdi),
#endif
    REG_SYM(__fixunsdfdi),
    REG_SYM(__fixunssfdi),
#if __riscv_xlen == 32
    REG_SYM(__floatdidf),
    REG_SYM(__floatdisf),
    REG_SYM(__floatundidf),
    REG_SYM(__floatundisf),
#endif
    REG_SYM(__moddi3),
    REG_SYM(__modsi3),
    REG_SYM(__muldi3),
#if __riscv_xlen == 32
    REG_SYM(__mulsi3),
#endif
    REG_SYM(__udivdi3),
    REG_SYM(__udivsi3),
    REG_SYM(__umoddi3),
    REG_SYM(__umodsi3),
    /* clang-format on */
};

static void
set_error_buf(char *error_buf, uint32 error_buf_size, const char *string)
{
    if (error_buf != NULL)
        snprintf(error_buf, error_buf_size, "%s", string);
}

void
get_current_target(char *target_buf, uint32 target_buf_size)
{
    snprintf(target_buf, target_buf_size, "riscv");
}

uint32
get_plt_item_size()
{
#if __riscv_xlen == 64
    /* auipc + ld + jalr + nop + addr */
    return 20;
#else
    return 0;
#endif
}

SymbolMap *
get_target_symbol_map(uint32 *sym_num)
{
    *sym_num = sizeof(target_sym_map) / sizeof(SymbolMap);
    return target_sym_map;
}

/* Get a val from given address */
static uint32
rv_get_val(uint16 *addr)
{
    uint32 ret;
    ret = *addr | (*(addr + 1)) << 16;
    return ret;
}

/* Set a val to given address */
static void
rv_set_val(uint16 *addr, uint32 val)
{
    *addr = (val & 0xffff);
    *(addr + 1) = (val >> 16);

    __asm__ volatile("fence.i");
}

/* Add a val to given address */
static void
rv_add_val(uint16 *addr, uint32 val)
{
    uint32 cur = rv_get_val(addr);
    rv_set_val(addr, cur + val);
}

/**
 * Get imm_hi and imm_lo from given integer
 *
 * @param imm given integer, signed 32bit
 * @param imm_hi signed 20bit
 * @param imm_lo signed 12bit
 *
 */
static void
rv_calc_imm(int32 imm, int32 *imm_hi, int32 *imm_lo)
{
    int32 lo;
    int32 hi = imm / 4096;
    int32 r = imm % 4096;

    if (2047 < r) {
        hi++;
    }
    else if (r < -2048) {
        hi--;
    }

    lo = imm - (hi * 4096);

    *imm_lo = lo;
    *imm_hi = hi;
}

uint32
get_plt_table_size()
{
    return get_plt_item_size() * (sizeof(target_sym_map) / sizeof(SymbolMap));
}

void
init_plt_table(uint8 *plt)
{
#if __riscv_xlen == 64
    uint32 i, num = sizeof(target_sym_map) / sizeof(SymbolMap);
    uint8 *p;

    for (i = 0; i < num; i++) {
        p = plt;
        /* auipc t1, 0 */
        *(uint16 *)p = 0x0317;
        p += 2;
        *(uint16 *)p = 0x0000;
        p += 2;
        /* ld t1, 8(t1) */
        *(uint16 *)p = 0x3303;
        p += 2;
        *(uint16 *)p = 0x00C3;
        p += 2;
        /* jr t1 */
        *(uint16 *)p = 0x8302;
        p += 2;
        /* nop */
        *(uint16 *)p = 0x0001;
        p += 2;
        bh_memcpy_s(p, 8, &target_sym_map[i].symbol_addr, 8);
        p += 8;
        plt += get_plt_item_size();
    }
#endif
}

typedef struct RelocTypeStrMap {
    uint32 reloc_type;
    char *reloc_str;
} RelocTypeStrMap;

#define RELOC_TYPE_MAP(reloc_type) \
    {                              \
        reloc_type, #reloc_type    \
    }

static RelocTypeStrMap reloc_type_str_maps[] = {
    RELOC_TYPE_MAP(R_RISCV_32),       RELOC_TYPE_MAP(R_RISCV_CALL),
    RELOC_TYPE_MAP(R_RISCV_CALL_PLT), RELOC_TYPE_MAP(R_RISCV_HI20),
    RELOC_TYPE_MAP(R_RISCV_LO12_I),   RELOC_TYPE_MAP(R_RISCV_LO12_S),
};

static const char *
reloc_type_to_str(uint32 reloc_type)
{
    uint32 i;

    for (i = 0; i < sizeof(reloc_type_str_maps) / sizeof(RelocTypeStrMap);
         i++) {
        if (reloc_type_str_maps[i].reloc_type == reloc_type)
            return reloc_type_str_maps[i].reloc_str;
    }

    return "Unknown_Reloc_Type";
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
    int32 val, imm_hi, imm_lo, insn;
    uint8 *addr = target_section_addr + reloc_offset;
    char buf[128];

    switch (reloc_type) {
        case R_RISCV_32:
        {
            uint32 val_32 =
                (uint32)((uintptr_t)symbol_addr + (intptr_t)reloc_addend);

            CHECK_RELOC_OFFSET(sizeof(uint32));
            if (val_32 != ((uintptr_t)symbol_addr + (intptr_t)reloc_addend)) {
                goto fail_addr_out_of_range;
            }

            rv_set_val((uint16 *)addr, val_32);
            break;
        }
        case R_RISCV_64:
        {
            uint64 val_64 =
                (uint64)((uintptr_t)symbol_addr + (intptr_t)reloc_addend);
            CHECK_RELOC_OFFSET(sizeof(uint64));
            bh_memcpy_s(addr, 8, &val_64, 8);
            break;
        }
        case R_RISCV_CALL:
        case R_RISCV_CALL_PLT:
        {
            val = (int32)(intptr_t)((uint8 *)symbol_addr - addr);

            CHECK_RELOC_OFFSET(sizeof(uint32));
            if (val != (intptr_t)((uint8 *)symbol_addr - addr)) {
                if (symbol_index >= 0) {
                    /* Call runtime function by plt code */
                    symbol_addr = (uint8 *)module->code + module->code_size
                                  - get_plt_table_size()
                                  + get_plt_item_size() * symbol_index;
                    val = (int32)(intptr_t)((uint8 *)symbol_addr - addr);
                }
            }

            if (val != (intptr_t)((uint8 *)symbol_addr - addr)) {
                goto fail_addr_out_of_range;
            }

            rv_calc_imm(val, &imm_hi, &imm_lo);

            rv_add_val((uint16 *)addr, (imm_hi << 12));
            if ((rv_get_val((uint16 *)(addr + 4)) & 0x7f) == RV_OPCODE_SW) {
                /* Adjust imm for SW : S-type */
                val = (((int32)imm_lo >> 5) << 25)
                      + (((int32)imm_lo & 0x1f) << 7);

                rv_add_val((uint16 *)(addr + 4), val);
            }
            else {
                /* Adjust imm for MV(ADDI)/JALR : I-type */
                rv_add_val((uint16 *)(addr + 4), ((int32)imm_lo << 20));
            }
            break;
        }

        case R_RISCV_HI20:
        {
            val = (int32)((intptr_t)symbol_addr + (intptr_t)reloc_addend);

            CHECK_RELOC_OFFSET(sizeof(uint32));
            if (val != ((intptr_t)symbol_addr + (intptr_t)reloc_addend)) {
                goto fail_addr_out_of_range;
            }

            addr = target_section_addr + reloc_offset;
            insn = rv_get_val((uint16 *)addr);
            rv_calc_imm(val, &imm_hi, &imm_lo);
            insn = (insn & 0x00000fff) | (imm_hi << 12);
            rv_set_val((uint16 *)addr, insn);
            break;
        }

        case R_RISCV_LO12_I:
        {
            val = (int32)((intptr_t)symbol_addr + (intptr_t)reloc_addend);

            CHECK_RELOC_OFFSET(sizeof(uint32));
            if (val != (intptr_t)symbol_addr + (intptr_t)reloc_addend) {
                goto fail_addr_out_of_range;
            }

            addr = target_section_addr + reloc_offset;
            insn = rv_get_val((uint16 *)addr);
            rv_calc_imm(val, &imm_hi, &imm_lo);
            insn = (insn & 0x000fffff) | (imm_lo << 20);
            rv_set_val((uint16 *)addr, insn);
            break;
        }

        case R_RISCV_LO12_S:
        {
            val = (int32)((intptr_t)symbol_addr + (intptr_t)reloc_addend);

            CHECK_RELOC_OFFSET(sizeof(uint32));
            if (val != ((intptr_t)symbol_addr + (intptr_t)reloc_addend)) {
                goto fail_addr_out_of_range;
            }

            addr = target_section_addr + reloc_offset;
            rv_calc_imm(val, &imm_hi, &imm_lo);
            val = (((int32)imm_lo >> 5) << 25) + (((int32)imm_lo & 0x1f) << 7);
            rv_add_val((uint16 *)addr, val);
            break;
        }

        default:
            if (error_buf != NULL)
                snprintf(error_buf, error_buf_size,
                         "Load relocation section failed: "
                         "invalid relocation type %" PRIu32 ".",
                         reloc_type);
            return false;
    }

    return true;

fail_addr_out_of_range:
    snprintf(buf, sizeof(buf),
             "AOT module load failed: "
             "relocation truncated to fit %s failed.",
             reloc_type_to_str(reloc_type));
    set_error_buf(error_buf, error_buf_size, buf);
    return false;
}
