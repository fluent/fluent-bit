
/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_EMIT_TABLE_H_
#define _JIT_EMIT_TABLE_H_

#include "../jit_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

#if WASM_ENABLE_REF_TYPES != 0
bool
jit_compile_op_elem_drop(JitCompContext *cc, uint32 tbl_seg_idx);

bool
jit_compile_op_table_get(JitCompContext *cc, uint32 tbl_idx);

bool
jit_compile_op_table_set(JitCompContext *cc, uint32 tbl_idx);

bool
jit_compile_op_table_init(JitCompContext *cc, uint32 tbl_idx,
                          uint32 tbl_seg_idx);

bool
jit_compile_op_table_copy(JitCompContext *cc, uint32 src_tbl_idx,
                          uint32 dst_tbl_idx);

bool
jit_compile_op_table_size(JitCompContext *cc, uint32 tbl_idx);

bool
jit_compile_op_table_grow(JitCompContext *cc, uint32 tbl_idx);

bool
jit_compile_op_table_fill(JitCompContext *cc, uint32 tbl_idx);
#endif

#ifdef __cplusplus
} /* end of extern "C" */
#endif
#endif
