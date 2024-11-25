/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SIMD_COMMON_H_
#define _SIMD_COMMON_H_

#include "../aot_compiler.h"

static inline bool
is_target_x86(AOTCompContext *comp_ctx)
{
    return !strncmp(comp_ctx->target_arch, "x86_64", 6)
           || !strncmp(comp_ctx->target_arch, "i386", 4);
}

LLVMValueRef
simd_pop_v128_and_bitcast(const AOTCompContext *comp_ctx,
                          const AOTFuncContext *func_ctx, LLVMTypeRef vec_type,
                          const char *name);

bool
simd_bitcast_and_push_v128(const AOTCompContext *comp_ctx,
                           const AOTFuncContext *func_ctx, LLVMValueRef vector,
                           const char *name);

LLVMValueRef
simd_lane_id_to_llvm_value(AOTCompContext *comp_ctx, uint8 lane_id);

LLVMValueRef
simd_build_const_integer_vector(const AOTCompContext *comp_ctx,
                                const LLVMTypeRef element_type,
                                const int *element_value, uint32 length);

LLVMValueRef
simd_build_splat_const_integer_vector(const AOTCompContext *comp_ctx,
                                      const LLVMTypeRef element_type,
                                      const int64 element_value, uint32 length);

LLVMValueRef
simd_build_splat_const_float_vector(const AOTCompContext *comp_ctx,
                                    const LLVMTypeRef element_type,
                                    const float element_value, uint32 length);
#endif /* _SIMD_COMMON_H_ */