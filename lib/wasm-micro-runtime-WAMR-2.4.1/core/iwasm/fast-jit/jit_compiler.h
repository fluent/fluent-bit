/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_COMPILER_H_
#define _JIT_COMPILER_H_

#include "bh_platform.h"
#include "../interpreter/wasm_runtime.h"
#include "jit_ir.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct JitGlobals {
    /* Compiler pass sequence, the last element must be 0 */
    const uint8 *passes;
    char *return_to_interp_from_jitted;
#if WASM_ENABLE_LAZY_JIT != 0
    char *compile_fast_jit_and_then_call;
#endif
} JitGlobals;

/**
 * Actions the interpreter should do when jitted code returns to
 * interpreter.
 */
typedef enum JitInterpAction {
    JIT_INTERP_ACTION_NORMAL, /* normal execution */
    JIT_INTERP_ACTION_THROWN, /* exception was thrown */
    JIT_INTERP_ACTION_CALL    /* call wasm function */
} JitInterpAction;

/**
 * Information exchanged between jitted code and interpreter.
 */
typedef struct JitInterpSwitchInfo {
    /* Points to the frame that is passed to jitted code and the frame
       that is returned from jitted code */
    void *frame;

    /* Output values from jitted code of different actions */
    union {
        /* IP and SP offsets for NORMAL */
        struct {
            int32 ip;
            int32 sp;
        } normal;

        /* Function called from jitted code for CALL */
        struct {
            void *function;
        } call;

        /* Returned integer and/or floating point values for RETURN. This
           is also used to pass return values from interpreter to jitted
           code if the caller is in jitted code and the callee is in
           interpreter. */
        struct {
            uint32 ival[2];
            uint32 fval[2];
            uint32 last_return_type;
        } ret;
    } out;
} JitInterpSwitchInfo;

/* Jit compiler options */
typedef struct JitCompOptions {
    uint32 code_cache_size;
    uint32 opt_level;
} JitCompOptions;

bool
jit_compiler_init(const JitCompOptions *option);

void
jit_compiler_destroy();

JitGlobals *
jit_compiler_get_jit_globals();

const char *
jit_compiler_get_pass_name(unsigned i);

bool
jit_compiler_compile(WASMModule *module, uint32 func_idx);

bool
jit_compiler_compile_all(WASMModule *module);

bool
jit_compiler_is_compiled(const WASMModule *module, uint32 func_idx);

#if WASM_ENABLE_LAZY_JIT != 0 && WASM_ENABLE_JIT != 0
bool
jit_compiler_set_call_to_llvm_jit(WASMModule *module, uint32 func_idx);

bool
jit_compiler_set_call_to_fast_jit(WASMModule *module, uint32 func_idx);

void
jit_compiler_set_llvm_jit_func_ptr(WASMModule *module, uint32 func_idx,
                                   void *func_ptr);
#endif

int
jit_interp_switch_to_jitted(void *self, JitInterpSwitchInfo *info,
                            uint32 func_idx, void *pc);

/*
 * Pass declarations:
 */

/**
 * Dump the compilation context.
 */
bool
jit_pass_dump(JitCompContext *cc);

/**
 * Update CFG (usually before dump for better readability).
 */
bool
jit_pass_update_cfg(JitCompContext *cc);

/**
 * Translate profiling result into MIR.
 */
bool
jit_pass_frontend(JitCompContext *cc);

/**
 * Lower unsupported operations into supported ones.
 */
bool
jit_pass_lower_cg(JitCompContext *cc);

/**
 * Register allocation.
 */
bool
jit_pass_regalloc(JitCompContext *cc);

/**
 * Native code generation.
 */
bool
jit_pass_codegen(JitCompContext *cc);

/**
 * Register the jitted code so that it can be executed.
 */
bool
jit_pass_register_jitted_code(JitCompContext *cc);

#ifdef __cplusplus
}
#endif

#endif /* end of _JIT_COMPILER_H_ */
