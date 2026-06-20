/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_CODEGEN_H_
#define _JIT_CODEGEN_H_

#include "bh_platform.h"
#include "jit_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize codegen module, such as instruction encoder.
 *
 * @return true if succeeded; false if failed.
 */
bool
jit_codegen_init();

/**
 * Destroy codegen module, such as instruction encoder.
 */
void
jit_codegen_destroy();

/**
 * Get hard register information of each kind.
 *
 * @return the JitHardRegInfo array of each kind
 */
const JitHardRegInfo *
jit_codegen_get_hreg_info();

/**
 * Get hard register by name.
 *
 * @param name the name of the hard register
 *
 * @return the hard register of the name
 */
JitReg
jit_codegen_get_hreg_by_name(const char *name);

/**
 * Generate native code for the given compilation context
 *
 * @param cc the compilation context that is ready to do codegen
 *
 * @return true if succeeds, false otherwise
 */
bool
jit_codegen_gen_native(JitCompContext *cc);

/**
 * lower unsupported operations to supported ones for the target.
 *
 * @param cc the compilation context that is ready to do codegen
 *
 * @return true if succeeds, false otherwise
 */
bool
jit_codegen_lower(JitCompContext *cc);

#if WASM_ENABLE_LAZY_JIT != 0 && WASM_ENABLE_JIT != 0
void *
jit_codegen_compile_call_to_llvm_jit(const WASMType *func_type);

void *
jit_codegen_compile_call_to_fast_jit(const WASMModule *module, uint32 func_idx);
#endif

/**
 * Dump native code in the given range to assembly.
 *
 * @param begin_addr begin address of the native code
 * @param end_addr end address of the native code
 */
void
jit_codegen_dump_native(void *begin_addr, void *end_addr);

int
jit_codegen_interp_jitted_glue(void *self, JitInterpSwitchInfo *info,
                               uint32 func_idx, void *pc);

#ifdef __cplusplus
}
#endif

#endif /* end of _JIT_CODEGEN_H_ */
