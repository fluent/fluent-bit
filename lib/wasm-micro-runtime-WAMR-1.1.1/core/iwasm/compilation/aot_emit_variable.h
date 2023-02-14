/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_VARIABLE_H_
#define _AOT_EMIT_VARIABLE_H_

#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_op_get_local(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 local_idx);

bool
aot_compile_op_set_local(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 local_idx);

bool
aot_compile_op_tee_local(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 local_idx);

bool
aot_compile_op_get_global(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 global_idx);

bool
aot_compile_op_set_global(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 global_idx, bool is_aux_stack);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_EMIT_VARIABLE_H_ */
