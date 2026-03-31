/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SIMD_ACCESS_LANES_H_
#define _SIMD_ACCESS_LANES_H_

#include "../aot_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
aot_compile_simd_shuffle(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         const uint8 *frame_ip);

bool
aot_compile_simd_swizzle(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_simd_extract_i8x16(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id,
                               bool is_signed);

bool
aot_compile_simd_extract_i16x8(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id,
                               bool is_signed);

bool
aot_compile_simd_extract_i32x4(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id);

bool
aot_compile_simd_extract_i64x2(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id);

bool
aot_compile_simd_extract_f32x4(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id);

bool
aot_compile_simd_extract_f64x2(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id);

bool
aot_compile_simd_replace_i8x16(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id);

bool
aot_compile_simd_replace_i16x8(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id);

bool
aot_compile_simd_replace_i32x4(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id);

bool
aot_compile_simd_replace_i64x2(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id);

bool
aot_compile_simd_replace_f32x4(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id);

bool
aot_compile_simd_replace_f64x2(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx, uint8 lane_id);

bool
aot_compile_simd_load8_lane(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            uint8 lane_id);

bool
aot_compile_simd_load16_lane(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             uint8 lane_id);

bool
aot_compile_simd_load32_lane(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             uint8 lane_id);

bool
aot_compile_simd_load64_lane(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             uint8 lane_id);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _SIMD_ACCESS_LANES_H_ */
