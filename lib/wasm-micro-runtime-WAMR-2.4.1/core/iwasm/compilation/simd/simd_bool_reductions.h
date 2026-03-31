/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SIMD_BOOL_REDUCTIONS_H_
#define _SIMD_BOOL_REDUCTIONS_H_

#include "../aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_simd_i8x16_all_true(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx);

bool
aot_compile_simd_i16x8_all_true(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx);

bool
aot_compile_simd_i32x4_all_true(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx);

bool
aot_compile_simd_i64x2_all_true(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx);

bool
aot_compile_simd_v128_any_true(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _SIMD_BOOL_REDUCTIONS_H_ */
