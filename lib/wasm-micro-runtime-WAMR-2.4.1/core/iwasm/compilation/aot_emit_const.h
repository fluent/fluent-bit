/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_CONST_H_
#define _AOT_EMIT_CONST_H_

#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_op_i32_const(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         int32 i32_const);

bool
aot_compile_op_i64_const(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         int64 i64_const);

bool
aot_compile_op_f32_const(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         float32 f32_const);

bool
aot_compile_op_f64_const(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         float64 f64_const);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_EMIT_CONST_H_ */
