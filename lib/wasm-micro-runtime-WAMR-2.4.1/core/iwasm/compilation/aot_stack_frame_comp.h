/*
 * Copyright (C) 2024 Amazon Inc.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_STACK_FRAME_COMP_H_
#define _AOT_STACK_FRAME_COMP_H_

#include "aot_stack_frame.h"
#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_alloc_frame_per_function_frame_for_aot_func(AOTCompContext *comp_ctx,
                                                AOTFuncContext *func_ctx,
                                                LLVMValueRef func_index);

bool
aot_free_frame_per_function_frame_for_aot_func(AOTCompContext *comp_ctx,
                                               AOTFuncContext *func_ctx);

bool
aot_tiny_frame_gen_commit_ip(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef ip_value);

#ifdef __cplusplus
}
#endif

#endif
