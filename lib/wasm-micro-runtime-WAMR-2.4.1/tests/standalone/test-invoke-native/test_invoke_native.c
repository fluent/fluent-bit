/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_runtime.h"

static void
test_native_args1(WASMModuleInstance *module_inst, int arg0, uint64_t arg1,
                  float arg2, double arg3, int arg4, int64_t arg5, int64_t arg6,
                  int arg7, double arg8, float arg9, int arg10, double arg11,
                  float arg12, int64_t arg13, uint64_t arg14, float arg15,
                  double arg16, int64_t arg17, uint64_t arg18, float arg19)
{
    printf("##test_native_args1 result:\n");
    printf("arg0: 0x%X, arg1: 0x%X%08X, arg2: %f, arg3: %f\n", arg0,
           (int32)(arg1 >> 32), (int32)arg1, arg2, arg3);
    printf("arg4: 0x%X, arg5: 0x%X%08X, arg6: 0x%X%08X, arg7: 0x%X\n", arg4,
           (int32)(arg5 >> 32), (int32)arg5, (int32)(arg6 >> 32), (int32)arg6,
           arg7);
    printf("arg8: %f, arg9: %f, arg10: 0x%X, arg11: %f\n", arg8, arg9, arg10,
           arg11);
    printf("arg12: %f, arg13: 0x%X%08X, arg14: 0x%X%08X, arg15: %f\n", arg12,
           (int32)(arg13 >> 32), (int32)arg13, (int32)(arg14 >> 32),
           (int32)arg14, arg15);
    printf("arg16: %f, arg17: 0x%X%08X, arg18: 0x%X%08X, arg19: %f\n", arg16,
           (int32)(arg17 >> 32), (int32)arg17, (int32)(arg18 >> 32),
           (int32)arg18, arg19);
}

static void
test_native_args2(WASMModuleInstance *module_inst, uint64_t arg1, float arg2,
                  double arg3, int arg4, int64_t arg5, int64_t arg6, int arg7,
                  double arg8, float arg9, int arg10, double arg11, float arg12,
                  int64_t arg13, uint64_t arg14, float arg15, double arg16,
                  int64_t arg17, uint64_t arg18, float arg19)
{
    printf("##test_native_args2 result:\n");
    printf("arg1: 0x%X%08X, arg2: %f, arg3: %f\n", (int32)(arg1 >> 32),
           (int32)arg1, arg2, arg3);
    printf("arg4: 0x%X, arg5: 0x%X%08X, arg6: 0x%X%08X, arg7: 0x%X\n", arg4,
           (int32)(arg5 >> 32), (int32)arg5, (int32)(arg6 >> 32), (int32)arg6,
           arg7);
    printf("arg8: %f, arg9: %f, arg10: 0x%X, arg11: %f\n", arg8, arg9, arg10,
           arg11);
    printf("arg12: %f, arg13: 0x%X%08X, arg14: 0x%X%08X, arg15: %f\n", arg12,
           (int32)(arg13 >> 32), (int32)arg13, (int32)(arg14 >> 32),
           (int32)arg14, arg15);
    printf("arg16: %f, arg17: 0x%X%08X, arg18: 0x%X%08X, arg19: %f\n", arg16,
           (int32)(arg17 >> 32), (int32)arg17, (int32)(arg18 >> 32),
           (int32)arg18, arg19);
}

static int32
test_return_i32(WASMModuleInstance *module_inst)
{
    return 0x12345678;
}

static int64
test_return_i64(WASMModuleInstance *module_inst)
{
    return 0x12345678ABCDEFFFll;
}

static float32
test_return_f32(WASMModuleInstance *module_inst)
{
    return 1234.5678f;
}

static float64
test_return_f64(WASMModuleInstance *module_inst)
{
    return 87654321.12345678;
}

#define STORE_I64(addr, value)  \
    do {                        \
        union {                 \
            int64 val;          \
            uint32 parts[2];    \
        } u;                    \
        u.val = (int64)(value); \
        (addr)[0] = u.parts[0]; \
        (addr)[1] = u.parts[1]; \
    } while (0)

#define STORE_F64(addr, value)  \
    do {                        \
        union {                 \
            float64 val;        \
            uint32 parts[2];    \
        } u;                    \
        u.val = (value);        \
        (addr)[0] = u.parts[0]; \
        (addr)[1] = u.parts[1]; \
    } while (0)

#define I32 VALUE_TYPE_I32
#define I64 VALUE_TYPE_I64
#define F32 VALUE_TYPE_F32
#define F64 VALUE_TYPE_F64

typedef struct WASMTypeTest {
    uint16 param_count;
    /* only one result is supported currently */
    uint16 result_count;
    uint16 param_cell_num;
    uint16 ret_cell_num;
    /* types of params and results */
    uint8 types[128];
} WASMTypeTest;

void
test_invoke_native()
{
    uint32 argv[128], *p = argv;
    WASMTypeTest func_type1 = { 20, 0, 0, 0, { I32, I64, F32, F64, I32,
                                               I64, I64, I32, F64, F32,
                                               I32, F64, F32, I64, I64,
                                               F32, F64, I64, I64, F32 } };
    WASMTypeTest func_type2 = { 19,
                                0,
                                0,
                                0,
                                { I64, F32, F64, I32, I64, I64, I32, F64, F32,
                                  I32, F64, F32, I64, I64, F32, F64, I64, I64,
                                  F32 } };
    WASMTypeTest func_type_i32 = { 0, 1, 0, 0, { I32 } };
    WASMTypeTest func_type_i64 = { 0, 1, 0, 0, { I64 } };
    WASMTypeTest func_type_f32 = { 0, 1, 0, 0, { F32 } };
    WASMTypeTest func_type_f64 = { 0, 1, 0, 0, { F64 } };
    WASMModuleInstance module_inst = { 0 };
    WASMExecEnv exec_env = { 0 };

    module_inst.module_type = Wasm_Module_Bytecode;
    exec_env.module_inst = (WASMModuleInstanceCommon *)&module_inst;

    *p++ = 0x12345678;
    STORE_I64(p, 0xFFFFFFFF87654321ll);
    p += 2;
    *(float32 *)p++ = 1234.5678f;
    STORE_F64(p, 567890.1234);
    p += 2;

    *p++ = 0x11111111;
    STORE_I64(p, 0xAAAAAAAABBBBBBBBll);
    p += 2;
    STORE_I64(p, 0x7788888899ll);
    p += 2;
    *p++ = 0x3456;

    STORE_F64(p, 8888.7777);
    p += 2;
    *(float32 *)p++ = 7777.8888f;
    *p++ = 0x66666;
    STORE_F64(p, 999999.88888);
    p += 2;

    *(float32 *)p++ = 555555.22f;
    STORE_I64(p, 0xBBBBBAAAAAAAAll);
    p += 2;
    STORE_I64(p, 0x3333AAAABBBBll);
    p += 2;
    *(float32 *)p++ = 88.77f;

    STORE_F64(p, 9999.01234);
    p += 2;
    STORE_I64(p, 0x1111122222222ll);
    p += 2;
    STORE_I64(p, 0x444455555555ll);
    p += 2;
    *(float32 *)p++ = 77.88f;

    wasm_runtime_invoke_native(&exec_env, test_native_args1,
                               (WASMType *)&func_type1, NULL, NULL, argv,
                               p - argv, argv);
    printf("\n");

    wasm_runtime_invoke_native(&exec_env, test_native_args2,
                               (WASMType *)&func_type2, NULL, NULL, argv + 1,
                               p - argv - 1, argv);
    printf("\n");

    wasm_runtime_invoke_native(&exec_env, test_return_i32,
                               (WASMType *)&func_type_i32, NULL, NULL, NULL, 0,
                               argv);
    printf("test_return_i32: 0x%X\n\n", argv[0]);

    wasm_runtime_invoke_native(&exec_env, test_return_i64,
                               (WASMType *)&func_type_i64, NULL, NULL, NULL, 0,
                               argv);
    printf("test_return_i64: 0x%X%08X\n\n", (int32)((*(int64 *)argv) >> 32),
           (int32)(*(int64 *)argv));

    wasm_runtime_invoke_native(&exec_env, test_return_f32,
                               (WASMType *)&func_type_f32, NULL, NULL, NULL, 0,
                               argv);
    printf("test_return_f32: %f\n\n", *(float32 *)argv);

    wasm_runtime_invoke_native(&exec_env, test_return_f64,
                               (WASMType *)&func_type_f64, NULL, NULL, NULL, 0,
                               argv);
    printf("test_return_f64: %f\n\n", *(float64 *)argv);
}
