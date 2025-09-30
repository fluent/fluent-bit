/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_CONTROL_H_
#define _AOT_EMIT_CONTROL_H_

#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_op_block(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                     uint8 **p_frame_ip, uint8 *frame_ip_end, uint32 label_type,
                     uint32 param_count, uint8 *param_types,
                     uint32 result_count, uint8 *result_types);

bool
aot_compile_op_else(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                    uint8 **p_frame_ip);

bool
aot_compile_op_end(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                   uint8 **p_frame_ip);

bool
aot_compile_op_br(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                  uint32 br_depth, uint8 **p_frame_ip);

bool
aot_compile_op_br_if(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                     uint32 br_depth, uint8 **p_frame_ip);

bool
aot_compile_op_br_table(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        uint32 *br_depths, uint32 br_count, uint8 **p_frame_ip);

bool
aot_compile_op_return(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                      uint8 **p_frame_ip);

bool
aot_compile_op_unreachable(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           uint8 **p_frame_ip);

bool
aot_handle_next_reachable_block(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx, uint8 **p_frame_ip);

bool
check_suspend_flags(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                    bool check_terminate_and_suspend);

#if WASM_ENABLE_GC != 0
bool
aot_compile_op_br_on_null(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 br_depth, uint8 **p_frame_ip);

bool
aot_compile_op_br_on_non_null(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, uint32 br_depth,

                              uint8 **p_frame_ip);

bool
aot_compile_op_br_on_cast(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          int32 heap_type, bool nullable, bool br_on_fail,
                          uint32 br_depth, uint8 **p_frame_ip);
#endif

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_EMIT_CONTROL_H_ */
