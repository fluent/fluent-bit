/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_EMIT_VARIABLE_H_
#define _JIT_EMIT_VARIABLE_H_

#include "../jit_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
jit_compile_op_get_local(JitCompContext *cc, uint32 local_idx);

bool
jit_compile_op_set_local(JitCompContext *cc, uint32 local_idx);

bool
jit_compile_op_tee_local(JitCompContext *cc, uint32 local_idx);

bool
jit_compile_op_get_global(JitCompContext *cc, uint32 global_idx);

bool
jit_compile_op_set_global(JitCompContext *cc, uint32 global_idx,
                          bool is_aux_stack);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _JIT_EMIT_VARIABLE_H_ */
