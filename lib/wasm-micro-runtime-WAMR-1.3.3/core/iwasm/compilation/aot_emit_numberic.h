/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_NUMBERIC_H_
#define _AOT_EMIT_NUMBERIC_H_

#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_op_i32_clz(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_op_i32_ctz(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_op_i32_popcnt(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_op_i64_clz(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_op_i64_ctz(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_op_i64_popcnt(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_op_i32_arithmetic(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, IntArithmetic arith_op,
                              uint8 **p_frame_ip);

bool
aot_compile_op_i64_arithmetic(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, IntArithmetic arith_op,
                              uint8 **p_frame_ip);

bool
aot_compile_op_i32_bitwise(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           IntBitwise bitwise_op);

bool
aot_compile_op_i64_bitwise(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           IntBitwise bitwise_op);

bool
aot_compile_op_i32_shift(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         IntShift shift_op);

bool
aot_compile_op_i64_shift(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         IntShift shift_op);

bool
aot_compile_op_f32_math(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        FloatMath math_op);

bool
aot_compile_op_f64_math(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        FloatMath math_op);

bool
aot_compile_op_f32_arithmetic(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx,
                              FloatArithmetic arith_op);

bool
aot_compile_op_f64_arithmetic(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx,
                              FloatArithmetic arith_op);

bool
aot_compile_op_f32_copysign(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_op_f64_copysign(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_EMIT_NUMBERIC_H_ */
