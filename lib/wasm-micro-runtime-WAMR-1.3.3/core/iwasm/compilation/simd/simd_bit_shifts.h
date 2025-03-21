/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SIMD_BIT_SHIFTS_H_
#define _SIMD_BIT_SHIFTS_H_

#include "../aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_simd_i8x16_shift(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             IntShift shift_op);

bool
aot_compile_simd_i16x8_shift(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             IntShift shift_op);

bool
aot_compile_simd_i32x4_shift(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             IntShift shift_op);

bool
aot_compile_simd_i64x2_shift(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             IntShift shift_op);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _SIMD_BIT_SHIFTS_H_ */
