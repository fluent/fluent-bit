/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "test_helper.h"
#include "gtest/gtest.h"

#include "platform_common.h"
#include "wasm_runtime_common.h"
#include "bh_read_file.h"
#include "wasm_runtime.h"
#include "bh_platform.h"
#include "wasm_export.h"
#include "aot_runtime.h"

namespace {

std::string CWD;
std::string TEST_WASM1 = "/hello.wasm";
std::string TEST_WASM2 = "/mytest.wasm";
char *WASM_FILE_1;
char *WASM_FILE_2;
std::vector<RunningMode> running_mode_supported = { Mode_Interp,
#if WASM_ENABLE_FAST_JIT != 0
                                                     Mode_Fast_JIT,
#endif
#if WASM_ENABLE_JIT != 0
                                                     Mode_LLVM_JIT,
#endif
#if WASM_ENABLE_JIT != 0 && WASM_ENABLE_FAST_JIT != 0 \
    && WASM_ENABLE_LAZY_JIT != 0
                                                     Mode_Multi_Tier_JIT
#endif
};

// To use a test fixture and Value Parameterized Tests,
// derive a class from testing::TestWithParam.
class wasm_running_modes_test_suite : public testing::TestWithParam<RunningMode>
{
  private:
    std::string get_binary_path()
    {
        char cwd[1024];
        memset(cwd, 0, 1024);

        if (readlink("/proc/self/exe", cwd, 1024) <= 0) {
        }

        char *path_end = strrchr(cwd, '/');
        if (path_end != NULL) {
            *path_end = '\0';
        }

        return std::string(cwd);
    }

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

  protected:
    void run_wasm_basic(
        char *filename, bool in_default_running_mode,
        RunningMode running_mode = static_cast<RunningMode>(Mode_Default))
    {
        bool ret;
        uint32_t wasm_argv[2];
        ret = load_wasm_file(filename);
        ASSERT_TRUE(ret);
        ret = init_exec_env();
        ASSERT_TRUE(ret);

        if (!in_default_running_mode) {
            ret = wasm_runtime_set_running_mode(module_inst, running_mode);
            ASSERT_TRUE(ret);
            ASSERT_EQ(running_mode, wasm_runtime_get_running_mode(module_inst));
        }

        wasm_function_inst_t echo2xback_func =
            wasm_runtime_lookup_function(module_inst, "echo");
        ASSERT_TRUE(echo2xback_func != NULL);

        wasm_argv[0] = 5;
        ret = wasm_runtime_call_wasm(exec_env, echo2xback_func, 1, wasm_argv);
        ASSERT_TRUE(ret);
        ASSERT_EQ(10, wasm_argv[0]);

        destroy_exec_env();
    }

    void run_wasm_complex(char *filename1, char *filename2,
                          RunningMode default_running_mode,
                          RunningMode running_mode)
    {
        bool ret;
        uint32_t wasm_argv[2];

        /* run wasm file 1 in default running mode */
        wasm_runtime_set_default_running_mode(default_running_mode);
        ret = load_wasm_file(filename1);
        ASSERT_TRUE(ret);
        ret = init_exec_env();
        ASSERT_TRUE(ret);

        uint8_t *buffer, *buffer2;
        wasm_function_inst_t echo2xback_func, main;

        ASSERT_EQ(default_running_mode,
                  wasm_runtime_get_running_mode(module_inst));
        echo2xback_func = wasm_runtime_lookup_function(module_inst, "echo");
        ASSERT_TRUE(echo2xback_func != NULL);
        wasm_argv[0] = 5;
        ret = wasm_runtime_call_wasm(exec_env, echo2xback_func, 1, wasm_argv);
        ASSERT_TRUE(ret);
        ASSERT_EQ(10, wasm_argv[0]);

        destroy_exec_env();

        /* run wasm file 2 in running_mode */
        ret = load_wasm_file(filename2);
        ASSERT_TRUE(ret);
        ret = init_exec_env();
        ASSERT_TRUE(ret);

        ret = wasm_runtime_set_running_mode(module_inst, running_mode);
        ASSERT_TRUE(ret);
        ASSERT_EQ(running_mode, wasm_runtime_get_running_mode(module_inst));
        main = wasm_runtime_lookup_function(module_inst, "__main_argc_argv");
        ASSERT_TRUE(main != NULL);
        ret = wasm_runtime_call_wasm(exec_env, main, 2, wasm_argv);
        ASSERT_TRUE(ret);

        destroy_exec_env();
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
        CWD = get_binary_path();
        WASM_FILE_1 = strdup((CWD + TEST_WASM1).c_str());
        WASM_FILE_2 = strdup((CWD + TEST_WASM2).c_str());

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
        free(WASM_FILE_1);
        free(WASM_FILE_2);
    }

    static void TearDownTestCase() {}

    std::string CWD;
    RuntimeInitArgs init_args;
    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    char error_buf[128];
    char global_heap_buf[512 * 1024];
    uint32_t stack_size = 8092, heap_size = 8092;
    bool cleanup = true;
};

TEST_F(wasm_running_modes_test_suite, wasm_runtime_is_running_mode_supported)
{
    // normal situation
    ASSERT_EQ(true, wasm_runtime_is_running_mode_supported(
                        static_cast<RunningMode>(Mode_Default)));
    for (auto running_mode : running_mode_supported) {
        ASSERT_EQ(true, wasm_runtime_is_running_mode_supported(running_mode));
    }

    // abnormal situation
    ASSERT_EQ(false, wasm_runtime_is_running_mode_supported(
                         static_cast<RunningMode>(-1)));
    ASSERT_EQ(false, wasm_runtime_is_running_mode_supported(
                         static_cast<RunningMode>(5)));
    ASSERT_EQ(false, wasm_runtime_is_running_mode_supported(
                         static_cast<RunningMode>(0xFF)));
}

TEST_F(wasm_running_modes_test_suite, wasm_runtime_set_default_running_mode)
{
    // normal situation: only set up
    ASSERT_EQ(true, wasm_runtime_set_default_running_mode(
                        static_cast<RunningMode>(Mode_Default)));
    for (auto running_mode : running_mode_supported) {
        ASSERT_EQ(true, wasm_runtime_set_default_running_mode(running_mode));
    }

    // abnormal situation
    ASSERT_EQ(false, wasm_runtime_set_default_running_mode(
                         static_cast<RunningMode>(-1)));
    ASSERT_EQ(false, wasm_runtime_set_default_running_mode(
                         static_cast<RunningMode>(5)));
    ASSERT_EQ(false, wasm_runtime_set_default_running_mode(
                         static_cast<RunningMode>(0xFF)));
}

TEST_P(wasm_running_modes_test_suite,
       wasm_runtime_set_default_running_mode_basic)
{
    RunningMode running_mode = GetParam();
    ASSERT_EQ(true, wasm_runtime_set_default_running_mode(running_mode));
    run_wasm_basic(WASM_FILE_1, true);
}

TEST_P(wasm_running_modes_test_suite,
       wasm_runtime_set_and_get_running_mode_basic)
{
    RunningMode running_mode = GetParam();
    run_wasm_basic(WASM_FILE_1, false, running_mode);
}

TEST_P(wasm_running_modes_test_suite,
       wasm_runtime_set_and_get_running_mode_complex)
{
    RunningMode default_running_mode = GetParam();
    for (auto running_mode : running_mode_supported) {
        run_wasm_complex(WASM_FILE_1, WASM_FILE_2, default_running_mode,
                         running_mode);
    }
}

INSTANTIATE_TEST_CASE_P(RunningMode, wasm_running_modes_test_suite,
                        testing::ValuesIn(running_mode_supported));

}
