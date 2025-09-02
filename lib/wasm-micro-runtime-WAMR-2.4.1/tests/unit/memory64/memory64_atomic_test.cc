/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "memory64_common.h"

// To use a test fixture and Value Parameterized Tests,
// derive a class from testing::TestWithParam.
class memory64_atomic_test_suite : public testing::TestWithParam<RunningMode>
{
  protected:
    bool load_wasm_file(const char *wasm_file)
    {
        const char *file;
        unsigned char *wasm_file_buf;
        uint32 wasm_file_size;

        file = wasm_file;

        wasm_file_buf =
            (unsigned char *)bh_read_file_to_buffer(file, &wasm_file_size);
        if (!wasm_file_buf)
            goto fail;

        if (!(module = wasm_runtime_load(wasm_file_buf, wasm_file_size,
                                         error_buf, sizeof(error_buf)))) {
            printf("Load wasm module failed. error: %s\n", error_buf);
            goto fail;
        }
        return true;

    fail:
        if (module)
            wasm_runtime_unload(module);

        return false;
    }

    bool init_exec_env()
    {
        if (!(module_inst =
                  wasm_runtime_instantiate(module, stack_size, heap_size,
                                           error_buf, sizeof(error_buf)))) {
            printf("Instantiate wasm module failed. error: %s\n", error_buf);
            goto fail;
        }
        if (!(exec_env =
                  wasm_runtime_create_exec_env(module_inst, stack_size))) {
            printf("Create wasm execution environment failed.\n");
            goto fail;
        }
        return true;

    fail:
        if (exec_env)
            wasm_runtime_destroy_exec_env(exec_env);
        if (module_inst)
            wasm_runtime_deinstantiate(module_inst);
        if (module)
            wasm_runtime_unload(module);
        return false;
    }

    void destroy_exec_env()
    {
        wasm_runtime_destroy_exec_env(exec_env);
        wasm_runtime_deinstantiate(module_inst);
        wasm_runtime_unload(module);
    }

  public:
    //  If your test fixture defines SetUpTestSuite() or TearDownTestSuite()
    //  they must be declared public rather than protected in order to use
    //  TEST_P.

    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    virtual void SetUp()
    {
        memset(&init_args, 0, sizeof(RuntimeInitArgs));

        init_args.mem_alloc_type = Alloc_With_Pool;
        init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
        init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

        ASSERT_EQ(wasm_runtime_full_init(&init_args), true);
        ASSERT_TRUE(load_wasm_file("atomic_opcodes.wasm"));
        ASSERT_TRUE(init_exec_env());

        running_mode = GetParam();
        ASSERT_TRUE(wasm_runtime_set_running_mode(module_inst, running_mode));
        ASSERT_EQ(running_mode, wasm_runtime_get_running_mode(module_inst));

        for (auto &iter : func_map) {
            iter.second =
                wasm_runtime_lookup_function(module_inst, iter.first.c_str());
            ASSERT_TRUE(iter.second != NULL);
        }

        cleanup = true;
    }

    static void SetUpTestCase() {}

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    virtual void TearDown()
    {
        if (cleanup) {
            destroy_exec_env();
            wasm_runtime_destroy();
            cleanup = false;
        }
    }

    static void TearDownTestCase() {}

    RuntimeInitArgs init_args;
    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    RunningMode running_mode;
    char error_buf[128];
    char global_heap_buf[512 * 1024];
    uint32_t stack_size = 8092, heap_size = 8092;
    bool cleanup = true;
    std::unordered_map<std::string, wasm_function_inst_t> func_map = {
        { "i32_atomic_store", nullptr },
        { "i32_atomic_store8", nullptr },
        { "i32_atomic_store16", nullptr },
        { "i64_atomic_store", nullptr },
        { "i64_atomic_store8", nullptr },
        { "i64_atomic_store16", nullptr },
        { "i64_atomic_store32", nullptr },
        { "i32_atomic_load", nullptr },
        { "i32_atomic_load8_u", nullptr },
        { "i32_atomic_load16_u", nullptr },
        { "i64_atomic_load", nullptr },
        { "i64_atomic_load8_u", nullptr },
        { "i64_atomic_load16_u", nullptr },
        { "i64_atomic_load32_u", nullptr },
        { "i32_atomic_rmw_add", nullptr },
        { "i32_atomic_rmw8_add_u", nullptr },
        { "i32_atomic_rmw16_add_u", nullptr },
        { "i64_atomic_rmw_add", nullptr },
        { "i64_atomic_rmw8_add_u", nullptr },
        { "i64_atomic_rmw16_add_u", nullptr },
        { "i64_atomic_rmw32_add_u", nullptr },
        { "i64_atomic_rmw_cmpxchg", nullptr },
    };
    uint32_t wasm_argv[6], i32;
    uint64_t i64;
};

TEST_P(memory64_atomic_test_suite, atomic_opcodes_i64_st)
{
    // store at 0x2000, with value 0xbeefdead
    PUT_I64_TO_ADDR(wasm_argv, 0x2000);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0xcafedeadbeefdead);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_store"],
                                       4, wasm_argv));
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_load"], 2,
                                       wasm_argv));
    // check return value: 0xcafedeadbeefdead:i64
    i64 = 0xcafedeadbeefdead;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    // store at 0x2000, with value 0xbeefbeef
    PUT_I64_TO_ADDR(wasm_argv, 0x2000);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0xdeadbeef);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_store32"],
                                       4, wasm_argv));
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_load"], 2,
                                       wasm_argv));
    // check return value: 0xcafedeaddeadbeef:i64
    i64 = 0xcafedeaddeadbeef;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    // store at 0x2000, with value 0xcafe
    PUT_I64_TO_ADDR(wasm_argv, 0x2000);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0xcafe);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_store16"],
                                       4, wasm_argv));
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_load"], 2,
                                       wasm_argv));
    // check return value: 0xcafedeaddeadcafe:i64
    i64 = 0xcafedeaddeadcafe;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    // store at 0x2000, with value 0xcafe
    PUT_I64_TO_ADDR(wasm_argv, 0x2000);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0xaa);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_store8"],
                                       4, wasm_argv));
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_load"], 2,
                                       wasm_argv));
    // check return value: 0xcafedeaddeadcaaa:i64
    i64 = 0xcafedeaddeadcaaa;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));
}

TEST_P(memory64_atomic_test_suite, atomic_opcodes_i32_st)
{
    // store at 0x1000, with value 0xbeefbeef
    PUT_I64_TO_ADDR(wasm_argv, 0x2000);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0xaabbccdd);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i32_atomic_store"],
                                       4, wasm_argv));
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i32_atomic_load"], 2,
                                       wasm_argv));
    // check return value: 0xaabbccdd:i32
    i32 = 0xaabbccdd;
    ASSERT_EQ(i32, wasm_argv[0]);

    // store at 0x1000, with value 0xcafe
    PUT_I64_TO_ADDR(wasm_argv, 0x2000);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0xcafe);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i32_atomic_store16"],
                                       4, wasm_argv));
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i32_atomic_load"], 2,
                                       wasm_argv));
    // check return value: 0xaabbcafe:i32
    i32 = 0xaabbcafe;
    ASSERT_EQ(i32, wasm_argv[0]);

    PUT_I64_TO_ADDR(wasm_argv, 0x2000);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0xaa);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i32_atomic_store8"],
                                       4, wasm_argv));
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i32_atomic_load"], 2,
                                       wasm_argv));
    // check return value: 0xaabbcaaa:i32
    i32 = 0xaabbcaaa;
    ASSERT_EQ(i32, wasm_argv[0]);
}

TEST_P(memory64_atomic_test_suite, atomic_opcodes_i64_ld)
{
    // from address 0, it's \01\02\03\04\05\06\07\08\09\0A\0B\0C\0D\0E\0F\10
    PUT_I64_TO_ADDR(wasm_argv, 0x0);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_load"], 2,
                                       wasm_argv));
    // check return value: 0x0807060504030201:i64
    i64 = 0x0807060504030201;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    PUT_I64_TO_ADDR(wasm_argv, 0x8);
    ASSERT_TRUE(wasm_runtime_call_wasm(
        exec_env, func_map["i64_atomic_load32_u"], 2, wasm_argv));
    // check return value: 0x0C0B0A09:i64
    i64 = 0x0C0B0A09;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    PUT_I64_TO_ADDR(wasm_argv, 0x8);
    ASSERT_TRUE(wasm_runtime_call_wasm(
        exec_env, func_map["i64_atomic_load16_u"], 2, wasm_argv));
    // check return value: 0x0A09:i64
    i64 = 0x0A09;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    PUT_I64_TO_ADDR(wasm_argv, 0x0A);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_load8_u"],
                                       2, wasm_argv));
    // check return value: 0x0B:i64
    i64 = 0x0B;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));
}

TEST_P(memory64_atomic_test_suite, atomic_opcodes_i32_ld)
{
    // from address 0, it's \01\02\03\04\05\06\07\08\09\0A\0B\0C\0D\0E\0F\10
    PUT_I64_TO_ADDR(wasm_argv, 0x0);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i32_atomic_load"], 2,
                                       wasm_argv));
    // check return value: 0x04030201:i32
    i32 = 0x04030201;
    ASSERT_EQ(i32, wasm_argv[0]);

    PUT_I64_TO_ADDR(wasm_argv, 0x8);
    ASSERT_TRUE(wasm_runtime_call_wasm(
        exec_env, func_map["i32_atomic_load16_u"], 2, wasm_argv));
    // check return value: 0x0A09:i32
    i32 = 0x0A09;
    ASSERT_EQ(i32, wasm_argv[0]);

    PUT_I64_TO_ADDR(wasm_argv, 0xA);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i32_atomic_load8_u"],
                                       2, wasm_argv));
    // check return value: 0x0B:i32
    i32 = 0x0B;
    ASSERT_EQ(i32, wasm_argv[0]);
}

TEST_P(memory64_atomic_test_suite, atomic_opcodes_i64_rmw_add)
{
    // from address 0, it's \01\02\03\04\05\06\07\08\09\0A\0B\0C\0D\0E\0F\10
    PUT_I64_TO_ADDR(wasm_argv, 0x8);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0x1010101020202020);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_rmw_add"],
                                       4, wasm_argv));
    i64 = 0x100F0E0D0C0B0A09;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    PUT_I64_TO_ADDR(wasm_argv, 0x8);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0x10103030);
    ASSERT_TRUE(wasm_runtime_call_wasm(
        exec_env, func_map["i64_atomic_rmw32_add_u"], 4, wasm_argv));
    i64 = 0x2C2B2A29;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    PUT_I64_TO_ADDR(wasm_argv, 0x8);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0x1020);
    ASSERT_TRUE(wasm_runtime_call_wasm(
        exec_env, func_map["i64_atomic_rmw16_add_u"], 4, wasm_argv));
    i64 = 0x5A59;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    PUT_I64_TO_ADDR(wasm_argv, 0x8);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0x30);
    ASSERT_TRUE(wasm_runtime_call_wasm(
        exec_env, func_map["i64_atomic_rmw8_add_u"], 4, wasm_argv));
    i64 = 0x79;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    PUT_I64_TO_ADDR(wasm_argv, 0x8);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_load"], 2,
                                       wasm_argv));
    i64 = 0x201F1E1D3C3B6AA9;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));
}

TEST_P(memory64_atomic_test_suite, atomic_opcodes_i64_rmw_cmpxchg)
{
    // from address 0, it's \01\02\03\04\05\06\07\08\09\0A\0B\0C\0D\0E\0F\10
    PUT_I64_TO_ADDR(wasm_argv, 0x8);
    // old
    PUT_I64_TO_ADDR(wasm_argv + 2, 0x100F0E0D0C0B0A09);
    // new
    PUT_I64_TO_ADDR(wasm_argv + 4, 0xdeadcafebeefdead);
    ASSERT_TRUE(wasm_runtime_call_wasm(
        exec_env, func_map["i64_atomic_rmw_cmpxchg"], 6, wasm_argv));
    i64 = 0x100F0E0D0C0B0A09;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    PUT_I64_TO_ADDR(wasm_argv, 0x8);
    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_map["i64_atomic_load"], 2,
                                       wasm_argv));
    i64 = 0xdeadcafebeefdead;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));
}

INSTANTIATE_TEST_CASE_P(RunningMode, memory64_atomic_test_suite,
                        testing::ValuesIn(running_mode_supported));
