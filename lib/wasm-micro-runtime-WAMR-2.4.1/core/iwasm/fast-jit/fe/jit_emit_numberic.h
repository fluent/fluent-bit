/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_EMIT_NUMBERIC_H_
#define _JIT_EMIT_NUMBERIC_H_

#include "../jit_compiler.h"
#include "../jit_frontend.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
jit_compile_op_i32_clz(JitCompContext *cc);

bool
jit_compile_op_i32_ctz(JitCompContext *cc);

bool
jit_compile_op_i32_popcnt(JitCompContext *cc);

bool
jit_compile_op_i64_clz(JitCompContext *cc);

bool
jit_compile_op_i64_ctz(JitCompContext *cc);

bool
jit_compile_op_i64_popcnt(JitCompContext *cc);

bool
jit_compile_op_i32_arithmetic(JitCompContext *cc, IntArithmetic arith_op,
                              uint8 **p_frame_ip);

bool
jit_compile_op_i64_arithmetic(JitCompContext *cc, IntArithmetic arith_op,
                              uint8 **p_frame_ip);

bool
jit_compile_op_i32_bitwise(JitCompContext *cc, IntBitwise bitwise_op);

bool
jit_compile_op_i64_bitwise(JitCompContext *cc, IntBitwise bitwise_op);

bool
jit_compile_op_i32_shift(JitCompContext *cc, IntShift shift_op);

bool
jit_compile_op_i64_shift(JitCompContext *cc, IntShift shift_op);

bool
jit_compile_op_f32_math(JitCompContext *cc, FloatMath math_op);

bool
jit_compile_op_f64_math(JitCompContext *cc, FloatMath math_op);

bool
jit_compile_op_f32_arithmetic(JitCompContext *cc, FloatArithmetic arith_op);

bool
jit_compile_op_f64_arithmetic(JitCompContext *cc, FloatArithmetic arith_op);

bool
jit_compile_op_f32_copysign(JitCompContext *cc);

bool
jit_compile_op_f64_copysign(JitCompContext *cc);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _JIT_EMIT_NUMBERIC_H_ */
