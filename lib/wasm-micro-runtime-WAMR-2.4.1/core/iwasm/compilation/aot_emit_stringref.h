/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_STRINGREF_H_
#define _AOT_EMIT_STRINGREF_H_

#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_op_string_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 encoding);

bool
aot_compile_op_string_const(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            uint32 contents);

bool
aot_compile_op_string_measure(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, uint32 encoding);

bool
aot_compile_op_string_encode(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             uint32 mem_idx, uint32 encoding);

bool
aot_compile_op_string_concat(AOTCompContext *comp_ctx,
                             AOTFuncContext *func_ctx);

bool
aot_compile_op_string_eq(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_op_string_is_usv_sequence(AOTCompContext *comp_ctx,
                                      AOTFuncContext *func_ctx);

bool
aot_compile_op_string_as_wtf8(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx);

bool
aot_compile_op_stringview_wtf8_advance(AOTCompContext *comp_ctx,
                                       AOTFuncContext *func_ctx);

bool
aot_compile_op_stringview_wtf8_encode(AOTCompContext *comp_ctx,
                                      AOTFuncContext *func_ctx, uint32 mem_idx,
                                      uint32 encoding);

bool
aot_compile_op_stringview_wtf8_slice(AOTCompContext *comp_ctx,
                                     AOTFuncContext *func_ctx);

bool
aot_compile_op_string_as_wtf16(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx);

bool
aot_compile_op_stringview_wtf16_length(AOTCompContext *comp_ctx,
                                       AOTFuncContext *func_ctx);

bool
aot_compile_op_stringview_wtf16_get_codeunit(AOTCompContext *comp_ctx,
                                             AOTFuncContext *func_ctx);

bool
aot_compile_op_stringview_wtf16_encode(AOTCompContext *comp_ctx,
                                       AOTFuncContext *func_ctx,
                                       uint32 mem_idx);

bool
aot_compile_op_stringview_wtf16_slice(AOTCompContext *comp_ctx,
                                      AOTFuncContext *func_ctx);

bool
aot_compile_op_string_as_iter(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx);

bool
aot_compile_op_stringview_iter_next(AOTCompContext *comp_ctx,
                                    AOTFuncContext *func_ctx);

bool
aot_compile_op_stringview_iter_advance(AOTCompContext *comp_ctx,
                                       AOTFuncContext *func_ctx);

bool
aot_compile_op_stringview_iter_rewind(AOTCompContext *comp_ctx,
                                      AOTFuncContext *func_ctx);

bool
aot_compile_op_stringview_iter_slice(AOTCompContext *comp_ctx,
                                     AOTFuncContext *func_ctx);

bool
aot_compile_op_string_new_array(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx, uint32 encoding);

bool
aot_compile_op_string_encode_array(AOTCompContext *comp_ctx,
                                   AOTFuncContext *func_ctx, uint32 encoding);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_EMIT_STRINGREF_H_ */
