/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SIMD_LOAD_STORE_H_
#define _SIMD_LOAD_STORE_H_

#include "../aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_simd_v128_load(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           uint32 align, mem_offset_t offset);

bool
aot_compile_simd_load_extend(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             uint8 opcode, uint32 align, mem_offset_t offset);

bool
aot_compile_simd_load_splat(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            uint8 opcode, uint32 align, mem_offset_t offset);

bool
aot_compile_simd_load_lane(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           uint8 opcode, uint32 align, mem_offset_t offset,
                           uint8 lane_id);

bool
aot_compile_simd_load_zero(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           uint8 opcode, uint32 align, mem_offset_t offset);

bool
aot_compile_simd_v128_store(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            uint32 align, mem_offset_t offset);

bool
aot_compile_simd_store_lane(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            uint8 opcode, uint32 align, mem_offset_t offset,
                            uint8 lane_id);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _SIMD_LOAD_STORE_H_ */
