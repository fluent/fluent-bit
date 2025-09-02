
/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_TABLE_H_
#define _AOT_EMIT_TABLE_H_

#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_op_elem_drop(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 tbl_seg_idx);

bool
aot_compile_op_table_get(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 tbl_idx);

bool
aot_compile_op_table_set(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 tbl_idx);

bool
aot_compile_op_table_init(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 tbl_idx, uint32 tbl_seg_idx);

bool
aot_compile_op_table_copy(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 src_tbl_idx, uint32 dst_tbl_idx);

bool
aot_compile_op_table_size(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 tbl_idx);

bool
aot_compile_op_table_grow(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 tbl_idx);

bool
aot_compile_op_table_fill(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 tbl_idx);

uint64
get_tbl_inst_offset(const AOTCompContext *comp_ctx,
                    const AOTFuncContext *func_ctx, uint32 tbl_idx);

uint32
get_module_inst_extra_offset(AOTCompContext *comp_ctx);

LLVMValueRef
aot_compile_get_tbl_inst(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 tbl_idx);

#ifdef __cplusplus
} /* end of extern "C" */
#endif
#endif
