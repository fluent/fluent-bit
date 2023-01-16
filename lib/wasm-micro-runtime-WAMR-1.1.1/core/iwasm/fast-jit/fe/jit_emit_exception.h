/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_EMIT_EXCEPTION_H_
#define _JIT_EMIT_EXCEPTION_H_

#include "../jit_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
jit_emit_exception(JitCompContext *cc, int32 exception_id, uint8 jit_opcode,
                   JitReg cond_br_if, JitBasicBlock *cond_br_else_block);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _JIT_EMIT_EXCEPTION_H_ */
