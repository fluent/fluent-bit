/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "memory64_common.h"

// To use a test fixture and Value Parameterized Tests,
// derive a class from testing::TestWithParam.
class memory64_test_suite : public testing::TestWithParam<RunningMode>
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
            wasm_runtime_destroy();
            cleanup = false;
        }
    }

    static void TearDownTestCase() {}

    RuntimeInitArgs init_args;
    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    char error_buf[128];
    char global_heap_buf[512 * 1024];
    uint32_t stack_size = 8092, heap_size = 8092;
    bool cleanup = true;
};

TEST_F(memory64_test_suite, wasm_runtime_is_running_mode_supported)
{
    // TODO: make sure the chosen running mode option is compiled, for memory64,
    // currently only support classic interp mode
    ASSERT_EQ(true, wasm_runtime_is_running_mode_supported(
                        static_cast<RunningMode>(Mode_Default)));
    for (auto running_mode : running_mode_supported) {
        ASSERT_EQ(true, wasm_runtime_is_running_mode_supported(running_mode));
    }
}

TEST_F(memory64_test_suite, page_exceed_u32_1)
{
    bool ret;
    ret = load_wasm_file("page_exceed_u32.wasm");
    ASSERT_FALSE(ret);
    ASSERT_TRUE(strcmp("WASM module load failed: integer too large", error_buf)
                == 0);
}

TEST_F(memory64_test_suite, page_exceed_u32_2)
{
    bool ret;
    ret = load_wasm_file("page_exceed_u32_2.wasm");
    ASSERT_FALSE(ret);
    ASSERT_TRUE(strcmp("WASM module load failed: integer too large", error_buf)
                == 0);
}

TEST_F(memory64_test_suite, page_u32_max)
{
    bool ret;
    ret = load_wasm_file("page_u32_max.wasm");
    ASSERT_TRUE(ret);
}

TEST_P(memory64_test_suite, memory_8GB)
{
    RunningMode running_mode = GetParam();
    wasm_function_inst_t touch_every_page_func, i64_store_offset_4GB,
        i64_load_offset_4GB;
    uint32_t wasm_argv[6], i32;
    uint64_t i64;
    bool ret;

    ret = load_wasm_file("8GB_memory.wasm");
    ASSERT_TRUE(ret);
    ret = init_exec_env();
    ASSERT_TRUE(ret);

    ret = wasm_runtime_set_running_mode(module_inst, running_mode);
    ASSERT_TRUE(ret);
    ASSERT_EQ(running_mode, wasm_runtime_get_running_mode(module_inst));

    touch_every_page_func =
        wasm_runtime_lookup_function(module_inst, "touch_every_page");
    ASSERT_TRUE(touch_every_page_func != NULL);
    ret = wasm_runtime_call_wasm(exec_env, touch_every_page_func, 0, wasm_argv);
    ASSERT_TRUE(ret);
    // check return value: 0xfff8:i64,0x10000fff8:i64,0x1fff8:i32,0x1:i32
    i64 = 0xfff8;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));
    i64 = 0x10000fff8;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv + 2));
    i32 = 0x1fff8;
    ASSERT_EQ(i32, wasm_argv[4]);
    i32 = 0x1;
    ASSERT_EQ(i32, wasm_argv[5]);

    // store at 0x100001000, with value 0xbeefdead
    PUT_I64_TO_ADDR(wasm_argv, 0x1000);
    PUT_I64_TO_ADDR(wasm_argv + 2, 0xbeefdead);
    i64_store_offset_4GB =
        wasm_runtime_lookup_function(module_inst, "i64_store_offset_4GB");
    ASSERT_TRUE(i64_store_offset_4GB != NULL);
    ret = wasm_runtime_call_wasm(exec_env, i64_store_offset_4GB, 4, wasm_argv);
    ASSERT_TRUE(ret);

    i64_load_offset_4GB =
        wasm_runtime_lookup_function(module_inst, "i64_load_offset_4GB");
    ASSERT_TRUE(i64_load_offset_4GB != NULL);
    ret = wasm_runtime_call_wasm(exec_env, i64_load_offset_4GB, 2, wasm_argv);
    ASSERT_TRUE(ret);
    // check return value: 0xbeefdead:i64
    i64 = 0xbeefdead;
    ASSERT_EQ(i64, GET_U64_FROM_ADDR(wasm_argv));

    destroy_exec_env();
}

TEST_P(memory64_test_suite, mem64_from_clang)
{
    RunningMode running_mode = GetParam();
    wasm_function_inst_t test_func;
    uint32_t wasm_argv[1], i32;
    bool ret;

    ret = load_wasm_file("mem64.wasm");
    ASSERT_TRUE(ret);
    ret = init_exec_env();
    ASSERT_TRUE(ret);

    ret = wasm_runtime_set_running_mode(module_inst, running_mode);
    ASSERT_TRUE(ret);
    ASSERT_EQ(running_mode, wasm_runtime_get_running_mode(module_inst));

    test_func =
        wasm_runtime_lookup_function(module_inst, "test");
    ASSERT_TRUE(test_func != NULL);
    ret = wasm_runtime_call_wasm(exec_env, test_func, 0, wasm_argv);
    ASSERT_TRUE(ret);
    i32 = 0x109;
    ASSERT_EQ(i32, wasm_argv[0]);

    destroy_exec_env();
}

INSTANTIATE_TEST_CASE_P(RunningMode, memory64_test_suite,
                        testing::ValuesIn(running_mode_supported));