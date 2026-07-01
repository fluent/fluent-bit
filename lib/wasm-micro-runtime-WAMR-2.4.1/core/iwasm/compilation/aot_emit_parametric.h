/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_PARAMETRIC_H_
#define _AOT_EMIT_PARAMETRIC_H_

#include "aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_op_drop(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                    bool is_drop_32);

bool
aot_compile_op_select(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                      bool is_select_32);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_EMIT_PARAMETRIC_H_ */
