/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_emit_const.h"
#include "../jit_frontend.h"

bool
jit_compile_op_i32_const(JitCompContext *cc, int32 i32_const)
{
    JitReg value = NEW_CONST(I32, i32_const);
    PUSH_I32(value);
    return true;
fail:
    return false;
}

bool
jit_compile_op_i64_const(JitCompContext *cc, int64 i64_const)
{
    JitReg value = NEW_CONST(I64, i64_const);
    PUSH_I64(value);
    return true;
fail:
    return false;
}

bool
jit_compile_op_f32_const(JitCompContext *cc, float32 f32_const)
{
    JitReg value = NEW_CONST(F32, f32_const);
    PUSH_F32(value);
    return true;
fail:
    return false;
}

bool
jit_compile_op_f64_const(JitCompContext *cc, float64 f64_const)
{
    JitReg value = NEW_CONST(F64, f64_const);
    PUSH_F64(value);
    return true;
fail:
    return false;
}
