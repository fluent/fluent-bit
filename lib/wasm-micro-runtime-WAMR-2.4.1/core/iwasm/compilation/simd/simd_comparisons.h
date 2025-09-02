/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SIMD_COMPARISONS_H_
#define _SIMD_COMPARISONS_H_

#include "../aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_simd_i8x16_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, IntCond cond);

bool
aot_compile_simd_i16x8_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, IntCond cond);

bool
aot_compile_simd_i32x4_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, IntCond cond);

bool
aot_compile_simd_i64x2_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, IntCond cond);

bool
aot_compile_simd_f32x4_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, FloatCond cond);

bool
aot_compile_simd_f64x2_compare(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, FloatCond cond);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _SIMD_COMPARISONS_H_ */
