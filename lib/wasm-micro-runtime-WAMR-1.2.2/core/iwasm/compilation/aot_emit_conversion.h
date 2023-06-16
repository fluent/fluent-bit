/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_CONVERSION_H_
#define _AOT_EMIT_CONVERSION_H_

#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_op_i32_wrap_i64(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_op_i32_trunc_f32(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             bool sign, bool saturating);

bool
aot_compile_op_i32_trunc_f64(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             bool sign, bool saturating);

bool
aot_compile_op_i64_extend_i32(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, bool sign);

bool
aot_compile_op_i64_extend_i64(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, int8 bitwidth);

bool
aot_compile_op_i32_extend_i32(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, int8 bitwidth);

bool
aot_compile_op_i64_trunc_f32(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             bool sign, bool saturating);

bool
aot_compile_op_i64_trunc_f64(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             bool sign, bool saturating);

bool
aot_compile_op_f32_convert_i32(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, bool sign);

bool
aot_compile_op_f32_convert_i64(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, bool sign);

bool
aot_compile_op_f32_demote_f64(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx);

bool
aot_compile_op_f64_convert_i32(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, bool sign);

bool
aot_compile_op_f64_convert_i64(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, bool sign);

bool
aot_compile_op_f64_promote_f32(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx);

bool
aot_compile_op_i64_reinterpret_f64(AOTCompContext *comp_ctx,
                                   AOTFuncContext *func_ctx);

bool
aot_compile_op_i32_reinterpret_f32(AOTCompContext *comp_ctx,
                                   AOTFuncContext *func_ctx);

bool
aot_compile_op_f64_reinterpret_i64(AOTCompContext *comp_ctx,
                                   AOTFuncContext *func_ctx);

bool
aot_compile_op_f32_reinterpret_i32(AOTCompContext *comp_ctx,
                                   AOTFuncContext *func_ctx);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_EMIT_CONVERSION_H_ */
