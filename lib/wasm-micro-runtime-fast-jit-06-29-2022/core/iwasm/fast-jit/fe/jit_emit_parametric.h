/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_EMIT_PARAMETRIC_H_
#define _JIT_EMIT_PARAMETRIC_H_

#include "../jit_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
jit_compile_op_drop(JitCompContext *cc, bool is_drop_32);

bool
jit_compile_op_select(JitCompContext *cc, bool is_select_32);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _JIT_EMIT_PARAMETRIC_H_ */
