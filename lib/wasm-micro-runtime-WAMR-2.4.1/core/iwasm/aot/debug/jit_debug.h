/*
 * Copyright (C) 2021 Ant Group.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_DEBUG_H_
#define _JIT_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

bool
jit_debug_engine_init(void);

void
jit_debug_engine_destroy(void);

bool
jit_code_entry_create(const uint8 *symfile_addr, uint64 symfile_size);

void
jit_code_entry_destroy(const uint8 *symfile_addr);

#ifdef __cplusplus
}
#endif

#endif
