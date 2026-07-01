/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_COMPARE_H_
#define _AOT_EMIT_COMPARE_H_

#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_op_i32_compare(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           IntCond cond);

bool
aot_compile_op_i64_compare(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           IntCond cond);

bool
aot_compile_op_f32_compare(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           FloatCond cond);

bool
aot_compile_op_f64_compare(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           FloatCond cond);

#if WASM_ENABLE_GC != 0

bool
aot_compile_op_ref_eq(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

#endif

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_EMIT_COMPARE_H_ */
