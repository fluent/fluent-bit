/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_DUMP_H_
#define _JIT_DUMP_H_

#include "jit_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Dump a register.
 *
 * @param cc compilation context of the register
 * @param reg register to be dumped
 */
void
jit_dump_reg(JitCompContext *cc, JitReg reg);

/**
 * Dump an instruction.
 *
 * @param cc compilation context of the instruction
 * @param insn instruction to be dumped
 */
void
jit_dump_insn(JitCompContext *cc, JitInsn *insn);

/**
 * Dump a block.
 *
 * @param cc compilation context of the block
 * @param block block to be dumped
 */
void
jit_dump_block(JitCompContext *cc, JitBlock *block);

/**
 * Dump a compilation context.
 *
 * @param cc compilation context to be dumped
 */
void
jit_dump_cc(JitCompContext *cc);

#ifdef __cplusplus
}
#endif

#endif /* end of _JIT_DUMP_H_ */
