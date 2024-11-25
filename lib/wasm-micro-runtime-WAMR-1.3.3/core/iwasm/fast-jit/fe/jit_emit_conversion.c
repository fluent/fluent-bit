/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_emit_conversion.h"
#include "jit_emit_exception.h"
#include "jit_emit_function.h"
#include "../jit_codegen.h"
#include "../jit_frontend.h"

#define F32_I32_S_MIN (-2147483904.0f)
#define F32_I32_S_MAX (2147483648.0f)
#define F32_I32_U_MIN (-1.0f)
#define F32_I32_U_MAX (4294967296.0f)
#define F32_I64_S_MIN (-9223373136366403584.0f)
#define F32_I64_S_MAX (9223372036854775808.0f)
#define F32_I64_U_MIN (-1.0f)
#define F32_I64_U_MAX (18446744073709551616.0f)

#define F64_I32_S_MIN (-2147483649.0)
#define F64_I32_S_MAX (2147483648.0)
#define F64_I32_U_MIN (-1.0)
#define F64_I32_U_MAX (4294967296.0)
#define F64_I64_S_MIN (-9223372036854777856.0)
#define F64_I64_S_MAX (9223372036854775808.0)
#define F64_I64_U_MIN (-1.0)
#define F64_I64_U_MAX (18446744073709551616.0)

#define FP_TO_INT(f_ty, i_ty, f_nm, i_nm) \
    static i_ty i_nm##_trunc_##f_nm(f_ty fp)

#define INT_TO_FP(i_ty, f_ty, i_nm, f_nm) \
    static f_ty f_nm##_convert_##i_nm(i_ty i)

#define FP_TO_INT_SAT(f_ty, i_ty, f_nm, i_nm) \
    static i_ty i_nm##_trunc_##f_nm##_sat(f_ty fp)

static int
local_isnan(double x)
{
    return isnan(x);
}

static int
local_isnanf(float x)
{
    return isnan(x);
}

#define RETURN_IF_NANF(fp)  \
    if (local_isnanf(fp)) { \
        return 0;           \
    }

#define RETURN_IF_NAN(fp)  \
    if (local_isnan(fp)) { \
        return 0;          \
    }

#define RETURN_IF_INF(fp, i_min, i_max) \
    if (isinf(fp)) {                    \
        return fp < 0 ? i_min : i_max;  \
    }

#define RETURN_IF_MIN(fp, f_min, i_min) \
    if (fp <= f_min) {                  \
        return i_min;                   \
    }

#define RETURN_IF_MAX(fp, f_max, i_max) \
    if (fp >= f_max) {                  \
        return i_max;                   \
    }

FP_TO_INT_SAT(float, int32, f32, i32)
{
    RETURN_IF_NANF(fp)
    RETURN_IF_INF(fp, INT32_MIN, INT32_MAX)
    RETURN_IF_MIN(fp, F32_I32_S_MIN, INT32_MIN)
    RETURN_IF_MAX(fp, F32_I32_S_MAX, INT32_MAX)
    return (int32)fp;
}

FP_TO_INT_SAT(float, uint32, f32, u32)
{
    RETURN_IF_NANF(fp)
    RETURN_IF_INF(fp, 0, UINT32_MAX)
    RETURN_IF_MIN(fp, F32_I32_U_MIN, 0)
    RETURN_IF_MAX(fp, F32_I32_U_MAX, UINT32_MAX)
    return (uint32)fp;
}

FP_TO_INT_SAT(double, int32, f64, i32)
{
    RETURN_IF_NAN(fp)
    RETURN_IF_INF(fp, INT32_MIN, INT32_MAX)
    RETURN_IF_MIN(fp, F64_I32_S_MIN, INT32_MIN)
    RETURN_IF_MAX(fp, F64_I32_S_MAX, INT32_MAX)
    return (int32)fp;
}

FP_TO_INT_SAT(double, uint32, f64, u32)
{
    RETURN_IF_NAN(fp)
    RETURN_IF_INF(fp, 0, UINT32_MAX)
    RETURN_IF_MIN(fp, F64_I32_U_MIN, 0)
    RETURN_IF_MAX(fp, F64_I32_U_MAX, UINT32_MAX)
    return (uint32)fp;
}

FP_TO_INT_SAT(float, int64, f32, i64)
{
    RETURN_IF_NANF(fp)
    RETURN_IF_INF(fp, INT64_MIN, INT64_MAX)
    RETURN_IF_MIN(fp, F32_I64_S_MIN, INT64_MIN)
    RETURN_IF_MAX(fp, F32_I64_S_MAX, INT64_MAX)
    return (int64)fp;
}

FP_TO_INT(float, uint64, f32, u64)
{
    return (uint64)fp;
}

FP_TO_INT_SAT(float, uint64, f32, u64)
{
    RETURN_IF_NANF(fp)
    RETURN_IF_INF(fp, 0, UINT64_MAX)
    RETURN_IF_MIN(fp, F32_I64_U_MIN, 0)
    RETURN_IF_MAX(fp, F32_I64_U_MAX, UINT64_MAX)
    return (uint64)fp;
}

FP_TO_INT_SAT(double, int64, f64, i64)
{
    RETURN_IF_NANF(fp)
    RETURN_IF_INF(fp, INT64_MIN, INT64_MAX)
    RETURN_IF_MIN(fp, F64_I64_S_MIN, INT64_MIN)
    RETURN_IF_MAX(fp, F64_I64_S_MAX, INT64_MAX)
    return (int64)fp;
}

FP_TO_INT(double, uint64, f64, u64)
{
    return (uint64)fp;
}

FP_TO_INT_SAT(double, uint64, f64, u64)
{
    RETURN_IF_NANF(fp)
    RETURN_IF_INF(fp, 0, UINT64_MAX)
    RETURN_IF_MIN(fp, F64_I64_U_MIN, 0)
    RETURN_IF_MAX(fp, F64_I64_U_MAX, UINT64_MAX)
    return (uint64)fp;
}

INT_TO_FP(uint64, float, u64, f32)
{
    return (float)i;
}

INT_TO_FP(uint64, double, u64, f64)
{
    return (double)i;
}

bool
jit_compile_op_i32_wrap_i64(JitCompContext *cc)
{
    JitReg num, res;

    POP_I64(num);

    res = jit_cc_new_reg_I32(cc);
    GEN_INSN(I64TOI32, res, num);

    PUSH_I32(res);

    return true;
fail:
    return false;
}

static bool
jit_compile_check_value_range(JitCompContext *cc, JitReg value, JitReg min_fp,
                              JitReg max_fp)
{
    JitReg nan_ret = jit_cc_new_reg_I32(cc);
    JitRegKind kind = jit_reg_kind(value);
    bool emit_ret = false;

    bh_assert(JIT_REG_KIND_F32 == kind || JIT_REG_KIND_F64 == kind);

    if (JIT_REG_KIND_F32 == kind && jit_reg_is_const(value)) {
        /* value is an f32 const */
        float value_f32_const = jit_cc_get_const_F32(cc, value);
        float min_fp_f32_const = jit_cc_get_const_F32(cc, min_fp);
        float max_fp_f32_const = jit_cc_get_const_F32(cc, max_fp);

        if (isnan(value_f32_const)) {
            /* throw exception if value is nan */
            if (!jit_emit_exception(cc, EXCE_INVALID_CONVERSION_TO_INTEGER,
                                    JIT_OP_JMP, 0, NULL))
                goto fail;
        }

        if (value_f32_const <= min_fp_f32_const
            || value_f32_const >= max_fp_f32_const) {
            /* throw exception if value is out of range */
            if (!jit_emit_exception(cc, EXCE_INTEGER_OVERFLOW, JIT_OP_JMP, 0,
                                    NULL))
                goto fail;
        }

        /* value is in range, do nothing */
        return true;
    }
    else if (JIT_REG_KIND_F64 == kind && jit_reg_is_const(value)) {
        /* value is an f64 const */
        double value_f64_const = jit_cc_get_const_F64(cc, value);
        double min_fp_f64_const = jit_cc_get_const_F64(cc, min_fp);
        double max_fp_f64_const = jit_cc_get_const_F64(cc, max_fp);

        if (isnan(value_f64_const)) {
            /* throw exception if value is nan */
            if (!jit_emit_exception(cc, EXCE_INVALID_CONVERSION_TO_INTEGER,
                                    JIT_OP_JMP, 0, NULL))
                goto fail;
        }

        if (value_f64_const <= min_fp_f64_const
            || value_f64_const >= max_fp_f64_const) {
            /* throw exception if value is out of range */
            if (!jit_emit_exception(cc, EXCE_INTEGER_OVERFLOW, JIT_OP_JMP, 0,
                                    NULL))
                goto fail;
        }

        /* value is in range, do nothing */
        return true;
    }

    /* If value is NaN, throw exception */
    if (JIT_REG_KIND_F32 == kind)
        emit_ret = jit_emit_callnative(cc, local_isnanf, nan_ret, &value, 1);
    else
        emit_ret = jit_emit_callnative(cc, local_isnan, nan_ret, &value, 1);
    if (!emit_ret)
        goto fail;

    GEN_INSN(CMP, cc->cmp_reg, nan_ret, NEW_CONST(I32, 1));
    if (!jit_emit_exception(cc, EXCE_INVALID_CONVERSION_TO_INTEGER, JIT_OP_BEQ,
                            cc->cmp_reg, NULL))
        goto fail;

    /* If value is out of integer range, throw exception */
    GEN_INSN(CMP, cc->cmp_reg, min_fp, value);
    if (!jit_emit_exception(cc, EXCE_INTEGER_OVERFLOW, JIT_OP_BGES, cc->cmp_reg,
                            NULL))
        goto fail;

    GEN_INSN(CMP, cc->cmp_reg, value, max_fp);
    if (!jit_emit_exception(cc, EXCE_INTEGER_OVERFLOW, JIT_OP_BGES, cc->cmp_reg,
                            NULL))
        goto fail;

    return true;
fail:
    return false;
}

bool
jit_compile_op_i32_trunc_f32(JitCompContext *cc, bool sign, bool sat)
{
    JitReg value, res;

    POP_F32(value);

    res = jit_cc_new_reg_I32(cc);
    if (!sat) {
        JitReg min_fp = NEW_CONST(F32, sign ? F32_I32_S_MIN : F32_I32_U_MIN);
        JitReg max_fp = NEW_CONST(F32, sign ? F32_I32_S_MAX : F32_I32_U_MAX);

        if (!jit_compile_check_value_range(cc, value, min_fp, max_fp))
            goto fail;

        if (sign)
            GEN_INSN(F32TOI32, res, value);
        else
            GEN_INSN(F32TOU32, res, value);
    }
    else {
        if (!jit_emit_callnative(cc,
                                 sign ? (void *)i32_trunc_f32_sat
                                      : (void *)u32_trunc_f32_sat,
                                 res, &value, 1))
            goto fail;
    }

    PUSH_I32(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_i32_trunc_f64(JitCompContext *cc, bool sign, bool sat)
{
    JitReg value, res;

    POP_F64(value);

    res = jit_cc_new_reg_I32(cc);
    if (!sat) {
        JitReg min_fp = NEW_CONST(F64, sign ? F64_I32_S_MIN : F64_I32_U_MIN);
        JitReg max_fp = NEW_CONST(F64, sign ? F64_I32_S_MAX : F64_I32_U_MAX);

        if (!jit_compile_check_value_range(cc, value, min_fp, max_fp))
            goto fail;

        if (sign)
            GEN_INSN(F64TOI32, res, value);
        else
            GEN_INSN(F64TOU32, res, value);
    }
    else {
        if (!jit_emit_callnative(cc,
                                 sign ? (void *)i32_trunc_f64_sat
                                      : (void *)u32_trunc_f64_sat,
                                 res, &value, 1))
            goto fail;
    }

    PUSH_I32(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_i64_extend_i32(JitCompContext *cc, bool sign)
{
    JitReg num, res;

    POP_I32(num);

    res = jit_cc_new_reg_I64(cc);
    if (sign)
        GEN_INSN(I32TOI64, res, num);
    else
        GEN_INSN(U32TOI64, res, num);

    PUSH_I64(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_i64_extend_i64(JitCompContext *cc, int8 bitwidth)
{
    JitReg value, tmp, res;

    POP_I64(value);

    tmp = jit_cc_new_reg_I32(cc);
    res = jit_cc_new_reg_I64(cc);

    switch (bitwidth) {
        case 8:
        {
            GEN_INSN(I64TOI8, tmp, value);
            GEN_INSN(I8TOI64, res, tmp);
            break;
        }
        case 16:
        {
            GEN_INSN(I64TOI16, tmp, value);
            GEN_INSN(I16TOI64, res, tmp);
            break;
        }
        case 32:
        {
            GEN_INSN(I64TOI32, tmp, value);
            GEN_INSN(I32TOI64, res, tmp);
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

    PUSH_I64(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_i32_extend_i32(JitCompContext *cc, int8 bitwidth)
{
    JitReg value, tmp, res;

    POP_I32(value);

    tmp = jit_cc_new_reg_I32(cc);
    res = jit_cc_new_reg_I32(cc);

    switch (bitwidth) {
        case 8:
        {
            GEN_INSN(I32TOI8, tmp, value);
            GEN_INSN(I8TOI32, res, tmp);
            break;
        }
        case 16:
        {
            GEN_INSN(I32TOI16, tmp, value);
            GEN_INSN(I16TOI32, res, tmp);
            break;
        }
        default:
        {
            bh_assert(0);
            goto fail;
        }
    }

    PUSH_I32(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_i64_trunc_f32(JitCompContext *cc, bool sign, bool sat)
{
    JitReg value, res;

    POP_F32(value);

    res = jit_cc_new_reg_I64(cc);
    if (!sat) {
        JitReg min_fp = NEW_CONST(F32, sign ? F32_I64_S_MIN : F32_I64_U_MIN);
        JitReg max_fp = NEW_CONST(F32, sign ? F32_I64_S_MAX : F32_I64_U_MAX);

        if (!jit_compile_check_value_range(cc, value, min_fp, max_fp))
            goto fail;

        if (sign) {
            GEN_INSN(F32TOI64, res, value);
        }
        else {
            if (!jit_emit_callnative(cc, u64_trunc_f32, res, &value, 1))
                goto fail;
        }
    }
    else {
        if (!jit_emit_callnative(cc,
                                 sign ? (void *)i64_trunc_f32_sat
                                      : (void *)u64_trunc_f32_sat,
                                 res, &value, 1))
            goto fail;
    }

    PUSH_I64(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_i64_trunc_f64(JitCompContext *cc, bool sign, bool sat)
{
    JitReg value, res;

    POP_F64(value);

    res = jit_cc_new_reg_I64(cc);
    if (!sat) {
        JitReg min_fp = NEW_CONST(F64, sign ? F64_I64_S_MIN : F64_I64_U_MIN);
        JitReg max_fp = NEW_CONST(F64, sign ? F64_I64_S_MAX : F64_I64_U_MAX);

        if (!jit_compile_check_value_range(cc, value, min_fp, max_fp))
            goto fail;

        if (sign) {
            GEN_INSN(F64TOI64, res, value);
        }
        else {
            if (!jit_emit_callnative(cc, u64_trunc_f64, res, &value, 1))
                goto fail;
        }
    }
    else {
        if (!jit_emit_callnative(cc,
                                 sign ? (void *)i64_trunc_f64_sat
                                      : (void *)u64_trunc_f64_sat,
                                 res, &value, 1))
            goto fail;
    }

    PUSH_I64(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_f32_convert_i32(JitCompContext *cc, bool sign)
{
    JitReg value, res;

    POP_I32(value);

    res = jit_cc_new_reg_F32(cc);
    if (sign) {
        GEN_INSN(I32TOF32, res, value);
    }
    else {
        GEN_INSN(U32TOF32, res, value);
    }

    PUSH_F32(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_f32_convert_i64(JitCompContext *cc, bool sign)
{
    JitReg value, res;

    POP_I64(value);

    res = jit_cc_new_reg_F32(cc);
    if (sign) {
        GEN_INSN(I64TOF32, res, value);
    }
    else {
        if (!jit_emit_callnative(cc, f32_convert_u64, res, &value, 1)) {
            goto fail;
        }
    }

    PUSH_F32(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_f32_demote_f64(JitCompContext *cc)
{
    JitReg value, res;

    POP_F64(value);

    res = jit_cc_new_reg_F32(cc);
    GEN_INSN(F64TOF32, res, value);

    PUSH_F32(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_f64_convert_i32(JitCompContext *cc, bool sign)
{
    JitReg value, res;

    POP_I32(value);

    res = jit_cc_new_reg_F64(cc);
    if (sign)
        GEN_INSN(I32TOF64, res, value);
    else
        GEN_INSN(U32TOF64, res, value);

    PUSH_F64(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_f64_convert_i64(JitCompContext *cc, bool sign)
{
    JitReg value, res;

    POP_I64(value);

    res = jit_cc_new_reg_F64(cc);
    if (sign) {
        GEN_INSN(I64TOF64, res, value);
    }
    else {
        if (!jit_emit_callnative(cc, f64_convert_u64, res, &value, 1)) {
            goto fail;
        }
    }

    PUSH_F64(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_f64_promote_f32(JitCompContext *cc)
{
    JitReg value, res;

    POP_F32(value);

    res = jit_cc_new_reg_F64(cc);
    GEN_INSN(F32TOF64, res, value);

    PUSH_F64(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_i64_reinterpret_f64(JitCompContext *cc)
{
    JitReg value, res;

    POP_F64(value);

    res = jit_cc_new_reg_I64(cc);
    GEN_INSN(F64CASTI64, res, value);

    PUSH_I64(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_i32_reinterpret_f32(JitCompContext *cc)
{
    JitReg value, res;

    POP_F32(value);

    res = jit_cc_new_reg_I32(cc);
    GEN_INSN(F32CASTI32, res, value);

    PUSH_I32(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_f64_reinterpret_i64(JitCompContext *cc)
{
    JitReg value, res;

    POP_I64(value);

    res = jit_cc_new_reg_F64(cc);
    GEN_INSN(I64CASTF64, res, value);

    PUSH_F64(res);

    return true;
fail:
    return false;
}

bool
jit_compile_op_f32_reinterpret_i32(JitCompContext *cc)
{
    JitReg value, res;

    POP_I32(value);

    res = jit_cc_new_reg_F32(cc);
    GEN_INSN(I32CASTF32, res, value);

    PUSH_F32(res);

    return true;
fail:
    return false;
}
