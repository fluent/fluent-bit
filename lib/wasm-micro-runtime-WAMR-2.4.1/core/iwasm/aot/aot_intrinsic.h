/*
 * Copyright (C) 2021 XiaoMi Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_INTRINSIC_H
#define _AOT_INTRINSIC_H

#include "aot_runtime.h"
#if WASM_ENABLE_WAMR_COMPILER != 0 || WASM_ENABLE_JIT != 0
#include "aot_llvm.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AOT_INTRINSIC_GROUPS 2

/* Use uint64 as flag container:
 *   - The upper 16 bits are the intrinsic group number
 *   - The lower 48 bits are the intrinsic capability mask
 */

#define AOT_INTRINSIC_FLAG(group, number) \
    ((((uint64)(group & 0xffffLL)) << 48) | ((uint64)1 << number))

#define AOT_INTRINSIC_FLAG_MASK (0x0000ffffffffffffLL)

#define AOT_INTRINSIC_GET_GROUP_FROM_FLAG(flag) \
    ((((uint64)flag) >> 48) & 0xffffLL)

/* clang-format off */
#define AOT_INTRINSIC_FLAG_F32_FADD     AOT_INTRINSIC_FLAG(0, 0)
#define AOT_INTRINSIC_FLAG_F32_FSUB     AOT_INTRINSIC_FLAG(0, 1)
#define AOT_INTRINSIC_FLAG_F32_FMUL     AOT_INTRINSIC_FLAG(0, 2)
#define AOT_INTRINSIC_FLAG_F32_FDIV     AOT_INTRINSIC_FLAG(0, 3)
#define AOT_INTRINSIC_FLAG_F32_FABS     AOT_INTRINSIC_FLAG(0, 4)
#define AOT_INTRINSIC_FLAG_F32_CEIL     AOT_INTRINSIC_FLAG(0, 5)
#define AOT_INTRINSIC_FLAG_F32_FLOOR    AOT_INTRINSIC_FLAG(0, 6)
#define AOT_INTRINSIC_FLAG_F32_TRUNC    AOT_INTRINSIC_FLAG(0, 7)
#define AOT_INTRINSIC_FLAG_F32_RINT     AOT_INTRINSIC_FLAG(0, 8)
#define AOT_INTRINSIC_FLAG_F32_SQRT     AOT_INTRINSIC_FLAG(0, 9)
#define AOT_INTRINSIC_FLAG_F32_COPYSIGN AOT_INTRINSIC_FLAG(0, 10)
#define AOT_INTRINSIC_FLAG_F32_MIN      AOT_INTRINSIC_FLAG(0, 11)
#define AOT_INTRINSIC_FLAG_F32_MAX      AOT_INTRINSIC_FLAG(0, 12)
#define AOT_INTRINSIC_FLAG_I32_CLZ      AOT_INTRINSIC_FLAG(0, 13)
#define AOT_INTRINSIC_FLAG_I32_CTZ      AOT_INTRINSIC_FLAG(0, 14)
#define AOT_INTRINSIC_FLAG_I32_POPCNT   AOT_INTRINSIC_FLAG(0, 15)
#define AOT_INTRINSIC_FLAG_I32_TO_F32   AOT_INTRINSIC_FLAG(0, 16)
#define AOT_INTRINSIC_FLAG_U32_TO_F32   AOT_INTRINSIC_FLAG(0, 17)
#define AOT_INTRINSIC_FLAG_I32_TO_F64   AOT_INTRINSIC_FLAG(0, 18)
#define AOT_INTRINSIC_FLAG_U32_TO_F64   AOT_INTRINSIC_FLAG(0, 19)
#define AOT_INTRINSIC_FLAG_F32_TO_I32   AOT_INTRINSIC_FLAG(0, 20)
#define AOT_INTRINSIC_FLAG_F32_TO_U32   AOT_INTRINSIC_FLAG(0, 21)
#define AOT_INTRINSIC_FLAG_F32_TO_I64   AOT_INTRINSIC_FLAG(0, 22)
#define AOT_INTRINSIC_FLAG_F32_TO_U64   AOT_INTRINSIC_FLAG(0, 23)
#define AOT_INTRINSIC_FLAG_F32_TO_F64   AOT_INTRINSIC_FLAG(0, 24)
#define AOT_INTRINSIC_FLAG_F32_CMP      AOT_INTRINSIC_FLAG(0, 25)
#define AOT_INTRINSIC_FLAG_F32_CONST    AOT_INTRINSIC_FLAG(0, 26)
#define AOT_INTRINSIC_FLAG_I32_CONST    AOT_INTRINSIC_FLAG(0, 27)
#define AOT_INTRINSIC_FLAG_I32_DIV_U    AOT_INTRINSIC_FLAG(0, 28)
#define AOT_INTRINSIC_FLAG_I32_REM_S    AOT_INTRINSIC_FLAG(0, 29)
#define AOT_INTRINSIC_FLAG_I32_REM_U    AOT_INTRINSIC_FLAG(0, 30)
#define AOT_INTRINSIC_FLAG_I32_DIV_S    AOT_INTRINSIC_FLAG(0, 31)

#define AOT_INTRINSIC_FLAG_F64_FADD     AOT_INTRINSIC_FLAG(1, 0)
#define AOT_INTRINSIC_FLAG_F64_FSUB     AOT_INTRINSIC_FLAG(1, 1)
#define AOT_INTRINSIC_FLAG_F64_FMUL     AOT_INTRINSIC_FLAG(1, 2)
#define AOT_INTRINSIC_FLAG_F64_FDIV     AOT_INTRINSIC_FLAG(1, 3)
#define AOT_INTRINSIC_FLAG_F64_FABS     AOT_INTRINSIC_FLAG(1, 4)
#define AOT_INTRINSIC_FLAG_F64_CEIL     AOT_INTRINSIC_FLAG(1, 5)
#define AOT_INTRINSIC_FLAG_F64_FLOOR    AOT_INTRINSIC_FLAG(1, 6)
#define AOT_INTRINSIC_FLAG_F64_TRUNC    AOT_INTRINSIC_FLAG(1, 7)
#define AOT_INTRINSIC_FLAG_F64_RINT     AOT_INTRINSIC_FLAG(1, 8)
#define AOT_INTRINSIC_FLAG_F64_SQRT     AOT_INTRINSIC_FLAG(1, 9)
#define AOT_INTRINSIC_FLAG_F64_COPYSIGN AOT_INTRINSIC_FLAG(1, 10)
#define AOT_INTRINSIC_FLAG_F64_MIN      AOT_INTRINSIC_FLAG(1, 11)
#define AOT_INTRINSIC_FLAG_F64_MAX      AOT_INTRINSIC_FLAG(1, 12)
#define AOT_INTRINSIC_FLAG_I64_CLZ      AOT_INTRINSIC_FLAG(1, 13)
#define AOT_INTRINSIC_FLAG_I64_CTZ      AOT_INTRINSIC_FLAG(1, 14)
#define AOT_INTRINSIC_FLAG_I64_POPCNT   AOT_INTRINSIC_FLAG(1, 15)
#define AOT_INTRINSIC_FLAG_I64_TO_F32   AOT_INTRINSIC_FLAG(1, 16)
#define AOT_INTRINSIC_FLAG_U64_TO_F32   AOT_INTRINSIC_FLAG(1, 17)
#define AOT_INTRINSIC_FLAG_I64_TO_F64   AOT_INTRINSIC_FLAG(1, 18)
#define AOT_INTRINSIC_FLAG_U64_TO_F64   AOT_INTRINSIC_FLAG(1, 19)
#define AOT_INTRINSIC_FLAG_F64_TO_I32   AOT_INTRINSIC_FLAG(1, 20)
#define AOT_INTRINSIC_FLAG_F64_TO_U32   AOT_INTRINSIC_FLAG(1, 21)
#define AOT_INTRINSIC_FLAG_F64_TO_I64   AOT_INTRINSIC_FLAG(1, 22)
#define AOT_INTRINSIC_FLAG_F64_TO_U64   AOT_INTRINSIC_FLAG(1, 23)
#define AOT_INTRINSIC_FLAG_F64_TO_F32   AOT_INTRINSIC_FLAG(1, 24)
#define AOT_INTRINSIC_FLAG_F64_CMP      AOT_INTRINSIC_FLAG(1, 25)
#define AOT_INTRINSIC_FLAG_F64_CONST    AOT_INTRINSIC_FLAG(1, 26)
#define AOT_INTRINSIC_FLAG_I64_CONST    AOT_INTRINSIC_FLAG(1, 27)
#define AOT_INTRINSIC_FLAG_I64_DIV_S    AOT_INTRINSIC_FLAG(1, 28)
#define AOT_INTRINSIC_FLAG_I64_DIV_U    AOT_INTRINSIC_FLAG(1, 29)
#define AOT_INTRINSIC_FLAG_I64_REM_S    AOT_INTRINSIC_FLAG(1, 30)
#define AOT_INTRINSIC_FLAG_I64_REM_U    AOT_INTRINSIC_FLAG(1, 31)
#define AOT_INTRINSIC_FLAG_I64_BIT_OR   AOT_INTRINSIC_FLAG(1, 32)
#define AOT_INTRINSIC_FLAG_I64_BIT_AND  AOT_INTRINSIC_FLAG(1, 33)
#define AOT_INTRINSIC_FLAG_I64_MUL      AOT_INTRINSIC_FLAG(1, 34)
#define AOT_INTRINSIC_FLAG_I64_SHL      AOT_INTRINSIC_FLAG(1, 35)
#define AOT_INTRINSIC_FLAG_I64_SHR_S    AOT_INTRINSIC_FLAG(1, 36)
#define AOT_INTRINSIC_FLAG_I64_SHR_U    AOT_INTRINSIC_FLAG(1, 37)

/* clang-format on */

float32
aot_intrinsic_fadd_f32(float32 a, float32 b);

float64
aot_intrinsic_fadd_f64(float64 a, float64 b);

float32
aot_intrinsic_fsub_f32(float32 a, float32 b);

float64
aot_intrinsic_fsub_f64(float64 a, float64 b);

float32
aot_intrinsic_fmul_f32(float32 a, float32 b);

float64
aot_intrinsic_fmul_f64(float64 a, float64 b);

float32
aot_intrinsic_fdiv_f32(float32 a, float32 b);

float64
aot_intrinsic_fdiv_f64(float64 a, float64 b);

float32
aot_intrinsic_fabs_f32(float32 a);

float64
aot_intrinsic_fabs_f64(float64 a);

float32
aot_intrinsic_ceil_f32(float32 a);

float64
aot_intrinsic_ceil_f64(float64 a);

float32
aot_intrinsic_floor_f32(float32 a);

float64
aot_intrinsic_floor_f64(float64 a);

float32
aot_intrinsic_trunc_f32(float32 a);

float64
aot_intrinsic_trunc_f64(float64 a);

float32
aot_intrinsic_rint_f32(float32 a);

float64
aot_intrinsic_rint_f64(float64 a);

float32
aot_intrinsic_sqrt_f32(float32 a);

float64
aot_intrinsic_sqrt_f64(float64 a);

float32
aot_intrinsic_copysign_f32(float32 a, float32 b);

float64
aot_intrinsic_copysign_f64(float64 a, float64 b);

float32
aot_intrinsic_fmin_f32(float32 a, float32 b);

float64
aot_intrinsic_fmin_f64(float64 a, float64 b);

float32
aot_intrinsic_fmax_f32(float32 a, float32 b);

float64
aot_intrinsic_fmax_f64(float64 a, float64 b);

uint32
aot_intrinsic_clz_i32(uint32 type);

uint64
aot_intrinsic_clz_i64(uint64 type);

uint32
aot_intrinsic_ctz_i32(uint32 type);

uint64
aot_intrinsic_ctz_i64(uint64 type);

uint32
aot_intrinsic_popcnt_i32(uint32 u);

uint64
aot_intrinsic_popcnt_i64(uint64 u);

float32
aot_intrinsic_i32_to_f32(int32 i);

float32
aot_intrinsic_u32_to_f32(uint32 u);

float64
aot_intrinsic_i32_to_f64(int32 i);

float64
aot_intrinsic_u32_to_f64(uint32 u);

float32
aot_intrinsic_i64_to_f32(int64 i);

float32
aot_intrinsic_u64_to_f32(uint64 u);

float64
aot_intrinsic_i64_to_f64(int64 i);

float64
aot_intrinsic_u64_to_f64(uint64 u);

int32
aot_intrinsic_f32_to_i32(float32 f);

uint32
aot_intrinsic_f32_to_u32(float32 f);

int64
aot_intrinsic_f32_to_i64(float32 f);

uint64
aot_intrinsic_f32_to_u64(float32 f);

int32
aot_intrinsic_f64_to_i32(float64 f);

uint32
aot_intrinsic_f64_to_u32(float64 f);

int64
aot_intrinsic_f64_to_i64(float64 f);

uint64
aot_intrinsic_f64_to_u64(float64 f);

float64
aot_intrinsic_f32_to_f64(float32 f);

float32
aot_intrinsic_f64_to_f32(float64 f);

int32
aot_intrinsic_f32_cmp(AOTFloatCond cond, float32 lhs, float32 rhs);

int32
aot_intrinsic_f64_cmp(AOTFloatCond cond, float64 lhs, float64 rhs);

int64
aot_intrinsic_i64_div_s(int64 l, int64 r);

int32
aot_intrinsic_i32_div_s(int32 l, int32 r);

uint32
aot_intrinsic_i32_div_u(uint32 l, uint32 r);

int32
aot_intrinsic_i32_rem_s(int32 l, int32 r);

uint32
aot_intrinsic_i32_rem_u(uint32 l, uint32 r);

uint64
aot_intrinsic_i64_div_u(uint64 l, uint64 r);

int64
aot_intrinsic_i64_rem_s(int64 l, int64 r);

uint64
aot_intrinsic_i64_rem_u(uint64 l, uint64 r);

uint64
aot_intrinsic_i64_bit_or(uint64 l, uint64 r);

uint64
aot_intrinsic_i64_bit_and(uint64 l, uint64 r);

uint64
aot_intrinsic_i64_mul(uint64 l, uint64 r);

uint64
aot_intrinsic_i64_shl(uint64 l, uint64 r);

uint64
aot_intrinsic_i64_shr_s(uint64 l, uint64 r);

uint64
aot_intrinsic_i64_shr_u(uint64 l, uint64 r);

#if WASM_ENABLE_WAMR_COMPILER != 0 || WASM_ENABLE_JIT != 0
const char *
aot_intrinsic_get_symbol(const char *llvm_intrinsic);

bool
aot_intrinsic_check_capability(const AOTCompContext *comp_ctx,
                               const char *llvm_intrinsic);

void
aot_intrinsic_fill_capability_flags(AOTCompContext *comp_ctx);
#endif

#ifdef __cplusplus
}
#endif

#endif /* end of _AOT_INTRINSIC_H */
