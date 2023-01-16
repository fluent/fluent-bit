/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WASM_INTERP_H
#define _WASM_INTERP_H

#include "wasm.h"

#ifdef __cplusplus
extern "C" {
#endif

struct WASMModuleInstance;
struct WASMFunctionInstance;
struct WASMExecEnv;

typedef struct WASMInterpFrame {
    /* The frame of the caller that are calling the current function. */
    struct WASMInterpFrame *prev_frame;

    /* The current WASM function. */
    struct WASMFunctionInstance *function;

    /* Instruction pointer of the bytecode array.  */
    uint8 *ip;

#if WASM_ENABLE_FAST_JIT != 0
    uint8 *jitted_return_addr;
#endif

#if WASM_ENABLE_PERF_PROFILING != 0
    uint64 time_started;
#endif

#if WASM_ENABLE_FAST_INTERP != 0
    /* Return offset of the first return value of current frame,
       the callee will put return values here continuously */
    uint32 ret_offset;
    uint32 *lp;
    uint32 operand[1];
#else
    /* Operand stack top pointer of the current frame. The bottom of
       the stack is the next cell after the last local variable. */
    uint32 *sp_bottom;
    uint32 *sp_boundary;
    uint32 *sp;

    WASMBranchBlock *csp_bottom;
    WASMBranchBlock *csp_boundary;
    WASMBranchBlock *csp;

    /**
     * Frame data, the layout is:
     *  lp: parameters and local variables
     *  sp_bottom to sp_boundary: wasm operand stack
     *  csp_bottom to csp_boundary: wasm label stack
     *  jit spill cache: only available for fast jit
     */
    uint32 lp[1];
#endif
} WASMInterpFrame;

/**
 * Calculate the size of interpreter area of frame of a function.
 *
 * @param all_cell_num number of all cells including local variables
 * and the working stack slots
 *
 * @return the size of interpreter area of the frame
 */
static inline unsigned
wasm_interp_interp_frame_size(unsigned all_cell_num)
{
    unsigned frame_size;

#if WASM_ENABLE_FAST_INTERP == 0
    frame_size = (uint32)offsetof(WASMInterpFrame, lp) + all_cell_num * 4;
#else
    frame_size = (uint32)offsetof(WASMInterpFrame, operand) + all_cell_num * 4;
#endif
    return align_uint(frame_size, 4);
}

void
wasm_interp_call_wasm(struct WASMModuleInstance *module_inst,
                      struct WASMExecEnv *exec_env,
                      struct WASMFunctionInstance *function, uint32 argc,
                      uint32 argv[]);

/**
 * @brief Restore the wasm stack frame to the last native frame or the begging
 * of the whole stack
 * @note e.g. for stack "begin --> interp --> interp", it will back to the
 * "begin", for stack "begin --> interp --> native --> interp", it will become
 * "begin --> interp --> native"
 *
 * @param exec_env the execution environment
 */
void
wasm_interp_restore_wasm_frame(struct WASMExecEnv *exec_env);

#ifdef __cplusplus
}
#endif

#endif /* end of _WASM_INTERP_H */
