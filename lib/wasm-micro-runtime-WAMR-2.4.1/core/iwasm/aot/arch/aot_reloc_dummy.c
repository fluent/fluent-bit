/*
 * Copyright (C) 2020 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_reloc.h"

SymbolMap *
get_target_symbol_map(uint32 *sym_num)
{
    abort();
}

uint32
get_plt_table_size(void)
{
    abort();
}

void
init_plt_table(uint8 *plt)
{
    abort();
}

void
get_current_target(char *target_buf, uint32 target_buf_size)
{
    abort();
}

bool
apply_relocation(AOTModule *module, uint8 *target_section_addr,
                 uint32 target_section_size, uint64 reloc_offset,
                 int64 reloc_addend, uint32 reloc_type, void *symbol_addr,
                 int32 symbol_index, char *error_buf, uint32 error_buf_size)
{
    abort();
}
