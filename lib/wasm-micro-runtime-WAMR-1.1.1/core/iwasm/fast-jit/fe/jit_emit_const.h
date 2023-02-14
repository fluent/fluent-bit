/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_EMIT_CONST_H_
#define _JIT_EMIT_CONST_H_

#include "../jit_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
jit_compile_op_i32_const(JitCompContext *cc, int32 i32_const);

bool
jit_compile_op_i64_const(JitCompContext *cc, int64 i64_const);

bool
jit_compile_op_f32_const(JitCompContext *cc, float32 f32_const);

bool
jit_compile_op_f64_const(JitCompContext *cc, float64 f64_const);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _JIT_EMIT_CONST_H_ */
