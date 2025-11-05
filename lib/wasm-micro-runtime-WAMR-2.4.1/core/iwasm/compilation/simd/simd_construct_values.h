/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SIMD_CONSTRUCT_VALUES_H_
#define _SIMD_CONSTRUCT_VALUES_H_

#include "../aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_simd_v128_const(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            const uint8 *imm_bytes);

bool
aot_compile_simd_splat(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                       uint8 splat_opcode);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _SIMD_CONSTRUCT_VALUES_H_ */
