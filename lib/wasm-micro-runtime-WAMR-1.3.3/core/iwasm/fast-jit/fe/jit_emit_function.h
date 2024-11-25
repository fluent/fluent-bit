/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_EMIT_FUNCTION_H_
#define _JIT_EMIT_FUNCTION_H_

#include "../jit_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
jit_compile_op_call(JitCompContext *cc, uint32 func_idx, bool tail_call);

bool
jit_compile_op_call_indirect(JitCompContext *cc, uint32 type_idx,
                             uint32 tbl_idx);

bool
jit_compile_op_ref_null(JitCompContext *cc, uint32 ref_type);

bool
jit_compile_op_ref_is_null(JitCompContext *cc);

bool
jit_compile_op_ref_func(JitCompContext *cc, uint32 func_idx);

bool
jit_emit_callnative(JitCompContext *cc, void *native_func, JitReg res,
                    JitReg *params, uint32 param_count);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _JIT_EMIT_FUNCTION_H_ */
