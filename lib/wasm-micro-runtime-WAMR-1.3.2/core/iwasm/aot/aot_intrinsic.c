/*
 * Copyright (C) 2021 XiaoMi Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_intrinsic.h"

typedef struct {
    const char *llvm_intrinsic;
    const char *native_intrinsic;
    uint64 flag;
} aot_intrinsic;

/* clang-format off */
static const aot_intrinsic g_intrinsic_mapping[] = {
    { "llvm.experimental.constrained.fadd.f32", "aot_intrinsic_fadd_f32", AOT_INTRINSIC_FLAG_F32_FADD },
    { "llvm.experimental.constrained.fadd.f64", "aot_intrinsic_fadd_f64", AOT_INTRINSIC_FLAG_F64_FADD },
    { "llvm.experimental.constrained.fsub.f32", "aot_intrinsic_fsub_f32", AOT_INTRINSIC_FLAG_F32_FSUB },
    { "llvm.experimental.constrained.fsub.f64", "aot_intrinsic_fsub_f64", AOT_INTRINSIC_FLAG_F64_FSUB },
    { "llvm.experimental.constrained.fmul.f32", "aot_intrinsic_fmul_f32", AOT_INTRINSIC_FLAG_F32_FMUL },
    { "llvm.experimental.constrained.fmul.f64", "aot_intrinsic_fmul_f64", AOT_INTRINSIC_FLAG_F64_FMUL },
    { "llvm.experimental.constrained.fdiv.f32", "aot_intrinsic_fdiv_f32", AOT_INTRINSIC_FLAG_F32_FDIV },
    { "llvm.experimental.constrained.fdiv.f64", "aot_intrinsic_fdiv_f64", AOT_INTRINSIC_FLAG_F64_FDIV },
    { "llvm.fabs.f32", "aot_intrinsic_fabs_f32", AOT_INTRINSIC_FLAG_F32_FABS },
    { "llvm.fabs.f64", "aot_intrinsic_fabs_f64", AOT_INTRINSIC_FLAG_F64_FABS },
    { "llvm.ceil.f32", "aot_intrinsic_ceil_f32", AOT_INTRINSIC_FLAG_F32_CEIL },
    { "llvm.ceil.f64", "aot_intrinsic_ceil_f64", AOT_INTRINSIC_FLAG_F64_CEIL },
    { "llvm.floor.f32", "aot_intrinsic_floor_f32", AOT_INTRINSIC_FLAG_F32_FLOOR },
    { "llvm.floor.f64", "aot_intrinsic_floor_f64", AOT_INTRINSIC_FLAG_F64_FLOOR },
    { "llvm.trunc.f32", "aot_intrinsic_trunc_f32", AOT_INTRINSIC_FLAG_F32_TRUNC },
    { "llvm.trunc.f64", "aot_intrinsic_trunc_f64", AOT_INTRINSIC_FLAG_F64_TRUNC },
    { "llvm.rint.f32", "aot_intrinsic_rint_f32", AOT_INTRINSIC_FLAG_F32_RINT },
    { "llvm.rint.f64", "aot_intrinsic_rint_f64", AOT_INTRINSIC_FLAG_F64_RINT },
    { "llvm.sqrt.f32", "aot_intrinsic_sqrt_f32", AOT_INTRINSIC_FLAG_F32_SQRT },
    { "llvm.sqrt.f64", "aot_intrinsic_sqrt_f64", AOT_INTRINSIC_FLAG_F64_SQRT },
    { "llvm.copysign.f32", "aot_intrinsic_copysign_f32", AOT_INTRINSIC_FLAG_F32_COPYSIGN },
    { "llvm.copysign.f64", "aot_intrinsic_copysign_f64", AOT_INTRINSIC_FLAG_F64_COPYSIGN },
    { "llvm.minnum.f32", "aot_intrinsic_fmin_f32", AOT_INTRINSIC_FLAG_F32_MIN },
    { "llvm.minnum.f64", "aot_intrinsic_fmin_f64", AOT_INTRINSIC_FLAG_F64_MIN },
    { "llvm.maxnum.f32", "aot_intrinsic_fmax_f32", AOT_INTRINSIC_FLAG_F32_MAX },
    { "llvm.maxnum.f64", "aot_intrinsic_fmax_f64", AOT_INTRINSIC_FLAG_F64_MAX },
    { "llvm.ctlz.i32", "aot_intrinsic_clz_i32", AOT_INTRINSIC_FLAG_I32_CLZ },
    { "llvm.ctlz.i64", "aot_intrinsic_clz_i64", AOT_INTRINSIC_FLAG_I64_CLZ },
    { "llvm.cttz.i32", "aot_intrinsic_ctz_i32", AOT_INTRINSIC_FLAG_I32_CTZ },
    { "llvm.cttz.i64", "aot_intrinsic_ctz_i64", AOT_INTRINSIC_FLAG_I64_CTZ },
    { "llvm.ctpop.i32", "aot_intrinsic_popcnt_i32", AOT_INTRINSIC_FLAG_I32_POPCNT },
    { "llvm.ctpop.i64", "aot_intrinsic_popcnt_i64", AOT_INTRINSIC_FLAG_I64_POPCNT },
    { "f64_convert_i32_s", "aot_intrinsic_i32_to_f64", AOT_INTRINSIC_FLAG_I32_TO_F64 },
    { "f64_convert_i32_u", "aot_intrinsic_u32_to_f64", AOT_INTRINSIC_FLAG_U32_TO_F64 },
    { "f32_convert_i32_s", "aot_intrinsic_i32_to_f32", AOT_INTRINSIC_FLAG_I32_TO_F32 },
    { "f32_convert_i32_u", "aot_intrinsic_u32_to_f32", AOT_INTRINSIC_FLAG_U32_TO_F32 },
    { "f64_convert_i64_s", "aot_intrinsic_i64_to_f64", AOT_INTRINSIC_FLAG_I32_TO_F64 },
    { "f64_convert_i64_u", "aot_intrinsic_u64_to_f64", AOT_INTRINSIC_FLAG_U64_TO_F64 },
    { "f32_convert_i64_s", "aot_intrinsic_i64_to_f32", AOT_INTRINSIC_FLAG_I64_TO_F32 },
    { "f32_convert_i64_u", "aot_intrinsic_u64_to_f32", AOT_INTRINSIC_FLAG_U64_TO_F32 },
    { "i32_trunc_f32_u", "aot_intrinsic_f32_to_u32", AOT_INTRINSIC_FLAG_F32_TO_U32 },
    { "i32_trunc_f32_s", "aot_intrinsic_f32_to_i32", AOT_INTRINSIC_FLAG_F32_TO_I32 },
    { "i32_trunc_f64_u", "aot_intrinsic_f64_to_u32", AOT_INTRINSIC_FLAG_F64_TO_U32 },
    { "i32_trunc_f64_s", "aot_intrinsic_f64_to_i32", AOT_INTRINSIC_FLAG_F64_TO_I32 },
    { "i64_trunc_f64_u", "aot_intrinsic_f64_to_u64", AOT_INTRINSIC_FLAG_F64_TO_U64 },
    { "i64_trunc_f32_s", "aot_intrinsic_f32_to_i64", AOT_INTRINSIC_FLAG_F32_TO_I64 },
    { "i64_trunc_f32_u", "aot_intrinsic_f32_to_u64", AOT_INTRINSIC_FLAG_F32_TO_U64 },
    { "i64_trunc_f64_s", "aot_intrinsic_f64_to_i64", AOT_INTRINSIC_FLAG_F64_TO_I64 },
    { "f32_demote_f64", "aot_intrinsic_f64_to_f32", AOT_INTRINSIC_FLAG_F64_TO_F32 },
    { "f64_promote_f32", "aot_intrinsic_f32_to_f64", AOT_INTRINSIC_FLAG_F32_TO_F64 },
    { "f32_cmp", "aot_intrinsic_f32_cmp", AOT_INTRINSIC_FLAG_F32_CMP },
    { "f64_cmp", "aot_intrinsic_f64_cmp", AOT_INTRINSIC_FLAG_F64_CMP },
    { "i32.const", NULL, AOT_INTRINSIC_FLAG_I32_CONST },
    { "i64.const", NULL, AOT_INTRINSIC_FLAG_I64_CONST },
    { "f32.const", NULL, AOT_INTRINSIC_FLAG_F32_CONST },
    { "f64.const", NULL, AOT_INTRINSIC_FLAG_F64_CONST },
    { "i64.div_s", "aot_intrinsic_i64_div_s", AOT_INTRINSIC_FLAG_I64_DIV_S},
    { "i32.div_s", "aot_intrinsic_i32_div_s", AOT_INTRINSIC_FLAG_I32_DIV_S},
    { "i32.div_u", "aot_intrinsic_i32_div_u", AOT_INTRINSIC_FLAG_I32_DIV_U},
    { "i32.rem_s", "aot_intrinsic_i32_rem_s", AOT_INTRINSIC_FLAG_I32_REM_S},
    { "i32.rem_u", "aot_intrinsic_i32_rem_u", AOT_INTRINSIC_FLAG_I32_REM_U},
    { "i64.div_u", "aot_intrinsic_i64_div_u", AOT_INTRINSIC_FLAG_I64_DIV_U},
    { "i64.rem_s", "aot_intrinsic_i64_rem_s", AOT_INTRINSIC_FLAG_I64_REM_S},
    { "i64.rem_u", "aot_intrinsic_i64_rem_u", AOT_INTRINSIC_FLAG_I64_REM_U},
    { "i64.or", "aot_intrinsic_i64_bit_or", AOT_INTRINSIC_FLAG_I64_BIT_OR},
    { "i64.and", "aot_intrinsic_i64_bit_and", AOT_INTRINSIC_FLAG_I64_BIT_AND},
};
/* clang-format on */

static const uint32 g_intrinsic_count =
    sizeof(g_intrinsic_mapping) / sizeof(aot_intrinsic);

float32
aot_intrinsic_fadd_f32(float32 a, float32 b)
{
    return a + b;
}

float64
aot_intrinsic_fadd_f64(float64 a, float64 b)
{
    return a + b;
}

float32
aot_intrinsic_fsub_f32(float32 a, float32 b)
{
    return a - b;
}

float64
aot_intrinsic_fsub_f64(float64 a, float64 b)
{
    return a - b;
}

float32
aot_intrinsic_fmul_f32(float32 a, float32 b)
{
    return a * b;
}

float64
aot_intrinsic_fmul_f64(float64 a, float64 b)
{
    return a * b;
}

float32
aot_intrinsic_fdiv_f32(float32 a, float32 b)
{
    return a / b;
}

float64
aot_intrinsic_fdiv_f64(float64 a, float64 b)
{
    return a / b;
}

float32
aot_intrinsic_fabs_f32(float32 a)
{
    return fabsf(a);
}

float64
aot_intrinsic_fabs_f64(float64 a)
{
    return fabs(a);
}

float32
aot_intrinsic_ceil_f32(float32 a)
{
    return ceilf(a);
}

float64
aot_intrinsic_ceil_f64(float64 a)
{
    return ceil(a);
}

float32
aot_intrinsic_floor_f32(float32 a)
{
    return floorf(a);
}

float64
aot_intrinsic_floor_f64(float64 a)
{
    return floor(a);
}

float32
aot_intrinsic_trunc_f32(float32 a)
{
    return truncf(a);
}

float64
aot_intrinsic_trunc_f64(float64 a)
{
    return trunc(a);
}

float32
aot_intrinsic_rint_f32(float32 a)
{
    return rintf(a);
}

float64
aot_intrinsic_rint_f64(float64 a)
{
    return rint(a);
}

float32
aot_intrinsic_sqrt_f32(float32 a)
{
    return sqrtf(a);
}

float64
aot_intrinsic_sqrt_f64(float64 a)
{
    return sqrt(a);
}

float32
aot_intrinsic_copysign_f32(float32 a, float32 b)
{
    return signbit(b) ? -fabsf(a) : fabsf(a);
}

float64
aot_intrinsic_copysign_f64(float64 a, float64 b)
{
    return signbit(b) ? -fabs(a) : fabs(a);
}

float32
aot_intrinsic_fmin_f32(float32 a, float32 b)
{
    if (isnan(a) || isnan(b))
        return NAN;
    else if (a == 0 && a == b)
        return signbit(a) ? a : b;
    else
        return a > b ? b : a;
}

float64
aot_intrinsic_fmin_f64(float64 a, float64 b)
{
    if (isnan(a) || isnan(b))
        return NAN;
    else if (a == 0 && a == b)
        return signbit(a) ? a : b;
    else
        return a > b ? b : a;
}

float32
aot_intrinsic_fmax_f32(float32 a, float32 b)
{
    if (isnan(a) || isnan(b))
        return NAN;
    else if (a == 0 && a == b)
        return signbit(a) ? b : a;
    else
        return a > b ? a : b;
}

float64
aot_intrinsic_fmax_f64(float64 a, float64 b)
{
    if (isnan(a) || isnan(b))
        return NAN;
    else if (a == 0 && a == b)
        return signbit(a) ? b : a;
    else
        return a > b ? a : b;
}

uint32
aot_intrinsic_clz_i32(uint32 type)
{
    uint32 num = 0;
    if (type == 0)
        return 32;
    while (!(type & 0x80000000)) {
        num++;
        type <<= 1;
    }
    return num;
}

uint32
aot_intrinsic_clz_i64(uint64 type)
{
    uint32 num = 0;
    if (type == 0)
        return 64;
    while (!(type & 0x8000000000000000LL)) {
        num++;
        type <<= 1;
    }
    return num;
}

uint32
aot_intrinsic_ctz_i32(uint32 type)
{
    uint32 num = 0;
    if (type == 0)
        return 32;
    while (!(type & 1)) {
        num++;
        type >>= 1;
    }
    return num;
}

uint32
aot_intrinsic_ctz_i64(uint64 type)
{
    uint32 num = 0;
    if (type == 0)
        return 64;
    while (!(type & 1)) {
        num++;
        type >>= 1;
    }
    return num;
}

uint32
aot_intrinsic_popcnt_i32(uint32 u)
{
    uint32 ret = 0;
    while (u) {
        u = (u & (u - 1));
        ret++;
    }
    return ret;
}

uint32
aot_intrinsic_popcnt_i64(uint64 u)
{
    uint32 ret = 0;
    while (u) {
        u = (u & (u - 1));
        ret++;
    }
    return ret;
}

float32
aot_intrinsic_i32_to_f32(int32 i)
{
    return (float32)i;
}

float32
aot_intrinsic_u32_to_f32(uint32 u)
{
    return (float32)u;
}

float64
aot_intrinsic_i32_to_f64(int32 i)
{
    return (float64)i;
}

float64
aot_intrinsic_u32_to_f64(uint32 u)
{
    return (float64)u;
}

float32
aot_intrinsic_i64_to_f32(int64 i)
{
    return (float32)i;
}

float32
aot_intrinsic_u64_to_f32(uint64 u)
{
    return (float32)u;
}

float64
aot_intrinsic_i64_to_f64(int64 i)
{
    return (float64)i;
}

float64
aot_intrinsic_u64_to_f64(uint64 u)
{
    return (float64)u;
}

int32
aot_intrinsic_f32_to_i32(float32 f)
{
    return (int32)f;
}

uint32
aot_intrinsic_f32_to_u32(float32 f)
{
    return (uint32)f;
}

int64
aot_intrinsic_f32_to_i64(float32 f)
{
    return (int64)f;
}

uint64
aot_intrinsic_f32_to_u64(float32 f)
{
    return (uint64)f;
}

int32
aot_intrinsic_f64_to_i32(float64 f)
{
    return (int32)f;
}

uint32
aot_intrinsic_f64_to_u32(float64 f)
{
    return (uint32)f;
}

int64
aot_intrinsic_f64_to_i64(float64 f)
{
    return (int64)f;
}

uint64
aot_intrinsic_f64_to_u64(float64 f)
{
    return (uint64)f;
}

float64
aot_intrinsic_f32_to_f64(float32 f)
{
    return (float64)f;
}

float32
aot_intrinsic_f64_to_f32(float64 f)
{
    return (float32)f;
}

int32
aot_intrinsic_f32_cmp(AOTFloatCond cond, float32 lhs, float32 rhs)
{
    switch (cond) {
        case FLOAT_EQ:
            return lhs == rhs ? 1 : 0;

        case FLOAT_LT:
            return lhs < rhs ? 1 : 0;

        case FLOAT_GT:
            return lhs > rhs ? 1 : 0;

        case FLOAT_LE:
            return lhs <= rhs ? 1 : 0;

        case FLOAT_GE:
            return lhs >= rhs ? 1 : 0;

        case FLOAT_NE:
            return (isnan(lhs) || isnan(rhs) || lhs != rhs) ? 1 : 0;

        case FLOAT_UNO:
            return (isnan(lhs) || isnan(rhs)) ? 1 : 0;

        default:
            break;
    }
    return 0;
}

int32
aot_intrinsic_f64_cmp(AOTFloatCond cond, float64 lhs, float64 rhs)
{
    switch (cond) {
        case FLOAT_EQ:
            return lhs == rhs ? 1 : 0;

        case FLOAT_LT:
            return lhs < rhs ? 1 : 0;

        case FLOAT_GT:
            return lhs > rhs ? 1 : 0;

        case FLOAT_LE:
            return lhs <= rhs ? 1 : 0;

        case FLOAT_GE:
            return lhs >= rhs ? 1 : 0;

        case FLOAT_NE:
            return (isnan(lhs) || isnan(rhs) || lhs != rhs) ? 1 : 0;

        case FLOAT_UNO:
            return (isnan(lhs) || isnan(rhs)) ? 1 : 0;

        default:
            break;
    }
    return 0;
}

int64
aot_intrinsic_i64_div_s(int64 l, int64 r)
{
    return l / r;
}

int32
aot_intrinsic_i32_div_s(int32 l, int32 r)
{
    return l / r;
}

uint32
aot_intrinsic_i32_div_u(uint32 l, uint32 r)
{
    return l / r;
}

int32
aot_intrinsic_i32_rem_s(int32 l, int32 r)
{
    return l % r;
}

uint32
aot_intrinsic_i32_rem_u(uint32 l, uint32 r)
{
    return l % r;
}

uint64
aot_intrinsic_i64_div_u(uint64 l, uint64 r)
{
    return l / r;
}

int64
aot_intrinsic_i64_rem_s(int64 l, int64 r)
{
    return l % r;
}

uint64
aot_intrinsic_i64_rem_u(uint64 l, uint64 r)
{
    return l % r;
}

uint64
aot_intrinsic_i64_bit_or(uint64 l, uint64 r)
{
    return l | r;
}

uint64
aot_intrinsic_i64_bit_and(uint64 l, uint64 r)
{
    return l & r;
}

const char *
aot_intrinsic_get_symbol(const char *llvm_intrinsic)
{
    uint32 cnt;
    for (cnt = 0; cnt < g_intrinsic_count; cnt++) {
        if (!strcmp(llvm_intrinsic, g_intrinsic_mapping[cnt].llvm_intrinsic)) {
            return g_intrinsic_mapping[cnt].native_intrinsic;
        }
    }
    return NULL;
}

#if WASM_ENABLE_WAMR_COMPILER != 0 || WASM_ENABLE_JIT != 0

static void
add_intrinsic_capability(AOTCompContext *comp_ctx, uint64 flag)
{
    uint64 group = AOT_INTRINSIC_GET_GROUP_FROM_FLAG(flag);
    if (group < sizeof(comp_ctx->flags) / sizeof(uint64)) {
        comp_ctx->flags[group] |= flag;
    }
    else {
        bh_log(BH_LOG_LEVEL_WARNING, __FILE__, __LINE__,
               "intrinsic exceeds max limit.");
    }
}

static void
add_i64_common_intrinsics(AOTCompContext *comp_ctx)
{
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_DIV_S);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_DIV_U);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_REM_S);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_REM_U);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_BIT_OR);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_BIT_AND);
}

static void
add_i32_common_intrinsics(AOTCompContext *comp_ctx)
{
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_DIV_S);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_DIV_U);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_REM_S);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_REM_U);
}

static void
add_f32_common_intrinsics(AOTCompContext *comp_ctx)
{
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_FABS);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_FADD);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_FSUB);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_FMUL);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_FDIV);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_SQRT);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_CMP);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_MIN);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_MAX);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_CEIL);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_FLOOR);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_TRUNC);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_RINT);
}

static void
add_f64_common_intrinsics(AOTCompContext *comp_ctx)
{
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_FABS);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_FADD);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_FSUB);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_FMUL);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_MIN);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_MAX);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_CEIL);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_FLOOR);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_TRUNC);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_RINT);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_FDIV);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_SQRT);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_CMP);
}

static void
add_f32xi32_intrinsics(AOTCompContext *comp_ctx)
{
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_TO_I32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_TO_U32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_TO_F32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_U32_TO_F32);
}

static void
add_f64xi32_intrinsics(AOTCompContext *comp_ctx)
{
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_TO_I32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_TO_U32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_TO_F64);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_U32_TO_F64);
}

static void
add_f32xi64_intrinsics(AOTCompContext *comp_ctx)
{
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_TO_I64);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_TO_U64);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_TO_F32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_U64_TO_F32);
}

static void
add_f64xi64_intrinsics(AOTCompContext *comp_ctx)
{
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_TO_I64);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_TO_U64);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_TO_F64);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_U64_TO_F64);
}

static void
add_common_float_integer_convertion(AOTCompContext *comp_ctx)
{
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_TO_F32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_U32_TO_F32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_TO_F64);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_U32_TO_F64);

    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_TO_F32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_U64_TO_F32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_TO_F64);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_U64_TO_F64);

    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_TO_I32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_TO_U32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_TO_I64);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_TO_U64);

    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_TO_I32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_TO_U32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_TO_I64);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_TO_U64);

    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_TO_F32);
    add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_TO_F64);
}

bool
aot_intrinsic_check_capability(const AOTCompContext *comp_ctx,
                               const char *llvm_intrinsic)
{
    uint32 cnt;
    uint64 flag;
    uint64 group;

    for (cnt = 0; cnt < g_intrinsic_count; cnt++) {
        if (!strcmp(llvm_intrinsic, g_intrinsic_mapping[cnt].llvm_intrinsic)) {
            flag = g_intrinsic_mapping[cnt].flag;
            group = AOT_INTRINSIC_GET_GROUP_FROM_FLAG(flag);
            flag &= AOT_INTRINSIC_FLAG_MASK;
            if (group < sizeof(comp_ctx->flags) / sizeof(uint64)) {
                if (comp_ctx->flags[group] & flag) {
                    return true;
                }
            }
            else {
                bh_log(BH_LOG_LEVEL_WARNING, __FILE__, __LINE__,
                       "intrinsic exceeds max limit.");
            }
        }
    }
    return false;
}

void
aot_intrinsic_fill_capability_flags(AOTCompContext *comp_ctx)
{
    uint32 i;

    memset(comp_ctx->flags, 0, sizeof(comp_ctx->flags));

    /* Intrinsics from command line have highest priority */

    if (comp_ctx->builtin_intrinsics) {

        /* Handle 'all' group */
        if (strstr(comp_ctx->builtin_intrinsics, "all")) {
            for (i = 0; i < g_intrinsic_count; i++) {
                add_intrinsic_capability(comp_ctx, g_intrinsic_mapping[i].flag);
            }
            return;
        }

        /* Handle 'i32.common' group */
        if (strstr(comp_ctx->builtin_intrinsics, "i32.common")) {
            add_i32_common_intrinsics(comp_ctx);
        }

        /* Handle 'i64.common' group */
        if (strstr(comp_ctx->builtin_intrinsics, "i64.common")) {
            add_i64_common_intrinsics(comp_ctx);
        }

        /* Handle 'fp.common' group */
        if (strstr(comp_ctx->builtin_intrinsics, "fp.common")) {
            add_f32_common_intrinsics(comp_ctx);
            add_f64_common_intrinsics(comp_ctx);
        }

        /* Handle 'f32.common' group */
        if (strstr(comp_ctx->builtin_intrinsics, "f32.common")) {
            add_f32_common_intrinsics(comp_ctx);
        }

        /* Handle 'f64.common' group */
        if (strstr(comp_ctx->builtin_intrinsics, "f64.common")) {
            add_f64_common_intrinsics(comp_ctx);
        }

        /* Handle 'f32xi32' group */
        if (strstr(comp_ctx->builtin_intrinsics, "f32xi32")) {
            add_f32xi32_intrinsics(comp_ctx);
        }

        /* Handle 'f64xi32' group */
        if (strstr(comp_ctx->builtin_intrinsics, "f64xi32")) {
            add_f64xi32_intrinsics(comp_ctx);
        }

        /* Handle 'f32xi64' group */
        if (strstr(comp_ctx->builtin_intrinsics, "f32xi64")) {
            add_f32xi64_intrinsics(comp_ctx);
        }

        /* Handle 'f64xi64' group */
        if (strstr(comp_ctx->builtin_intrinsics, "f64xi64")) {
            add_f64xi64_intrinsics(comp_ctx);
        }

        /* Handle 'fpxint' group */
        if (strstr(comp_ctx->builtin_intrinsics, "fpxint")) {
            add_f32xi32_intrinsics(comp_ctx);
            add_f64xi32_intrinsics(comp_ctx);
            add_f32xi64_intrinsics(comp_ctx);
            add_f64xi64_intrinsics(comp_ctx);
        }

        /* Handle 'constop' group */
        if (strstr(comp_ctx->builtin_intrinsics, "constop")) {
            add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_CONST);
            add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_CONST);
            add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_CONST);
            add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_CONST);
        }

        /* Handle 'fp.common' group */
        if (strstr(comp_ctx->builtin_intrinsics, "fp.common")) {
            add_f32_common_intrinsics(comp_ctx);
            add_f64_common_intrinsics(comp_ctx);
        }

        /* Handle other single items */
        for (i = 0; i < g_intrinsic_count; i++) {
            if (strstr(comp_ctx->builtin_intrinsics,
                       g_intrinsic_mapping[i].llvm_intrinsic)) {
                add_intrinsic_capability(comp_ctx, g_intrinsic_mapping[i].flag);
            }
        }

        return;
    }

    if (!comp_ctx->target_cpu)
        return;

    if (!strncmp(comp_ctx->target_arch, "thumb", 5)) {
        add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_CONST);
        add_i32_common_intrinsics(comp_ctx);
        if (!strcmp(comp_ctx->target_cpu, "cortex-m7")) {
        }
        else if (!strcmp(comp_ctx->target_cpu, "cortex-m4")) {
            add_f64_common_intrinsics(comp_ctx);
        }
        else {
            add_f32_common_intrinsics(comp_ctx);
            add_f64_common_intrinsics(comp_ctx);
            add_i64_common_intrinsics(comp_ctx);
            add_common_float_integer_convertion(comp_ctx);
        }
    }
    else if (!strncmp(comp_ctx->target_arch, "riscv", 5)) {
        add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_CONST);
        /*
         * Note: Use builtin intrinsics since hardware float operation
         * will cause rodata relocation
         */
        add_f32_common_intrinsics(comp_ctx);
        add_f64_common_intrinsics(comp_ctx);
        add_common_float_integer_convertion(comp_ctx);
        if (!strncmp(comp_ctx->target_arch, "riscv32", 7)) {
            add_i64_common_intrinsics(comp_ctx);
        }
    }
    else if (!strncmp(comp_ctx->target_arch, "xtensa", 6)) {
        /*
         * Note: Use builtin intrinsics since hardware float operation
         * will cause rodata relocation
         */
        add_f32_common_intrinsics(comp_ctx);
        add_i32_common_intrinsics(comp_ctx);
        add_f64_common_intrinsics(comp_ctx);
        add_i64_common_intrinsics(comp_ctx);
        add_common_float_integer_convertion(comp_ctx);
        add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_CONST);
        add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_CONST);
        add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I32_CONST);
        add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_I64_CONST);
    }
    else {
        /*
         * Use constant value table by default
         */
        add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F32_CONST);
        add_intrinsic_capability(comp_ctx, AOT_INTRINSIC_FLAG_F64_CONST);
    }
}

#endif /* WASM_ENABLE_WAMR_COMPILER != 0 || WASM_ENABLE_JIT != 0 */
