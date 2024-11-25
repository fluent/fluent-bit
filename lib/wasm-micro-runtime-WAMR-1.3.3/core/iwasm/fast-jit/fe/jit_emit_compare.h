/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_EMIT_COMPARE_H_
#define _JIT_EMIT_COMPARE_H_

#include "../jit_compiler.h"
#include "../jit_frontend.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
jit_compile_op_i32_compare(JitCompContext *cc, IntCond cond);

bool
jit_compile_op_i64_compare(JitCompContext *cc, IntCond cond);

bool
jit_compile_op_f32_compare(JitCompContext *cc, FloatCond cond);

bool
jit_compile_op_f64_compare(JitCompContext *cc, FloatCond cond);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _JIT_EMIT_COMPARE_H_ */
