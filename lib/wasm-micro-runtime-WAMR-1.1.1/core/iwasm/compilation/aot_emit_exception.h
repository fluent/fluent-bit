/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_EXCEPTION_H_
#define _AOT_EMIT_EXCEPTION_H_

#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_emit_exception(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                   int32 exception_id, bool is_cond_br, LLVMValueRef cond_br_if,
                   LLVMBasicBlockRef cond_br_else_block);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_EMIT_EXCEPTION_H_ */
