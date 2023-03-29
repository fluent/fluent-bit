/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_EMIT_CONTROL_H_
#define _JIT_EMIT_CONTROL_H_

#include "../jit_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
jit_compile_op_block(JitCompContext *cc, uint8 **p_frame_ip,
                     uint8 *frame_ip_end, uint32 label_type, uint32 param_count,
                     uint8 *param_types, uint32 result_count,
                     uint8 *result_types, bool merge_cmp_and_if);

bool
jit_compile_op_else(JitCompContext *cc, uint8 **p_frame_ip);

bool
jit_compile_op_end(JitCompContext *cc, uint8 **p_frame_ip);

bool
jit_compile_op_br(JitCompContext *cc, uint32 br_depth, uint8 **p_frame_ip);

bool
jit_compile_op_br_if(JitCompContext *cc, uint32 br_depth,
                     bool merge_cmp_and_br_if, uint8 **p_frame_ip);

bool
jit_compile_op_br_table(JitCompContext *cc, uint32 *br_depths, uint32 br_count,
                        uint8 **p_frame_ip);

bool
jit_compile_op_return(JitCompContext *cc, uint8 **p_frame_ip);

bool
jit_compile_op_unreachable(JitCompContext *cc, uint8 **p_frame_ip);

bool
jit_handle_next_reachable_block(JitCompContext *cc, uint8 **p_frame_ip);

#if WASM_ENABLE_THREAD_MGR != 0
bool
jit_check_suspend_flags(JitCompContext *cc);
#endif

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _JIT_EMIT_CONTROL_H_ */
