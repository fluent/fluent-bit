/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "test_helper.h"
#include "gtest/gtest.h"

#include "bh_read_file.h"
#include "wasm_runtime_common.h"

static std::string CWD;

static std::string
get_binary_path()
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

#if WASM_DISABLE_HW_BOUND_CHECK != 0
#define TEST_SUITE_NAME linear_memory_test_suite_wasm_no_hw_bound
#else
#define TEST_SUITE_NAME linear_memory_test_suite_wasm
#endif

class TEST_SUITE_NAME : public testing::Test
{
  protected:
    // You should make the members protected s.t. they can be
    // accessed from sub-classes.

    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    virtual void SetUp() {}

    static void SetUpTestCase() { CWD = get_binary_path(); }

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    virtual void TearDown() {}

    WAMRRuntimeRAII<512 * 1024> runtime;
};

struct ret_env {
    wasm_exec_env_t exec_env;
    wasm_module_t wasm_module;
    wasm_module_inst_t wasm_module_inst;
    unsigned char *wasm_file_buf;
    char error_buf[128];
};

struct ret_env
load_wasm(char *wasm_file_tested, unsigned int app_heap_size)
{
    std::string wasm_mem_page = wasm_file_tested;
    const char *wasm_file = strdup((CWD + wasm_mem_page).c_str());
    wasm_module_inst_t wasm_module_inst = nullptr;
    wasm_module_t wasm_module = nullptr;
    wasm_exec_env_t exec_env = nullptr;
    unsigned char *wasm_file_buf = nullptr;
    unsigned int wasm_file_size = 0;
    unsigned int stack_size = 16 * 1024, heap_size = app_heap_size;
    char error_buf[128] = { 0 };
    struct ret_env ret_module_env;

    memset(ret_module_env.error_buf, 0, 128);
    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
    if (!wasm_file_buf) {
        goto fail;
    }

    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    if (!wasm_module) {
        memcpy(ret_module_env.error_buf, error_buf, 128);
        goto fail;
    }

    wasm_module_inst = wasm_runtime_instantiate(
        wasm_module, stack_size, heap_size, error_buf, sizeof(error_buf));
    if (!wasm_module_inst) {
        memcpy(ret_module_env.error_buf, error_buf, 128);
        goto fail;
    }

    exec_env = wasm_runtime_create_exec_env(wasm_module_inst, stack_size);

fail:
    ret_module_env.exec_env = exec_env;
    ret_module_env.wasm_module = wasm_module;
    ret_module_env.wasm_module_inst = wasm_module_inst;
    ret_module_env.wasm_file_buf = wasm_file_buf;

    return ret_module_env;
}

void
destroy_module_env(struct ret_env module_env)
{
    if (module_env.exec_env) {
        wasm_runtime_destroy_exec_env(module_env.exec_env);
    }

    if (module_env.wasm_module_inst) {
        wasm_runtime_deinstantiate(module_env.wasm_module_inst);
    }

    if (module_env.wasm_module) {
        wasm_runtime_unload(module_env.wasm_module);
    }

    if (module_env.wasm_file_buf) {
        wasm_runtime_free(module_env.wasm_file_buf);
    }
}

TEST_F(TEST_SUITE_NAME, test_wasm_mem_page_count)
{
    struct ret_env tmp_module_env;
    unsigned int num_normal_wasm = 9;
    unsigned int num_error_wasm = 10;
    const char *wasm_file_normal[num_normal_wasm] = {
        "/wasm_mem_page_01.wasm", "/wasm_mem_page_02.wasm",
        "/wasm_mem_page_05.wasm", "/wasm_mem_page_07.wasm",
        "/wasm_mem_page_08.wasm", "/wasm_mem_page_09.wasm",
        "/wasm_mem_page_10.wasm", "/wasm_mem_page_12.wasm",
        "/wasm_mem_page_14.wasm"
    };

    const char *wasm_file_error[num_error_wasm] = {
        "/wasm_mem_page_03.wasm", "/wasm_mem_page_04.wasm",
        "/wasm_mem_page_06.wasm", "/wasm_mem_page_11.wasm",
        "/wasm_mem_page_13.wasm", "/wasm_mem_page_15.wasm",
        "/wasm_mem_page_16.wasm", "/wasm_mem_page_17.wasm",
        "/wasm_mem_page_18.wasm", "/wasm_mem_page_19.wasm"
    };

    // Test normal wasm file.
    for (int i = 0; i < num_normal_wasm; i++) {
#if UINTPTR_MAX != UINT64_MAX
        // 32 bit do not load this wasm.
        if ((0 == strcmp("/wasm_mem_page_12.wasm", wasm_file_normal[i]))
            || (0 == strcmp("/wasm_mem_page_14.wasm", wasm_file_normal[i]))) {
            continue;
        }
#endif
        tmp_module_env = load_wasm((char *)wasm_file_normal[i], 16 * 1024);
        EXPECT_NE(nullptr, tmp_module_env.wasm_module);
        EXPECT_NE(nullptr, tmp_module_env.wasm_file_buf);

#if WASM_DISABLE_HW_BOUND_CHECK == 0
        EXPECT_NE(nullptr, tmp_module_env.exec_env);
        EXPECT_NE(nullptr, tmp_module_env.wasm_module_inst);
#endif
        destroy_module_env(tmp_module_env);
    }

    // Test error wasm file.
    for (int i = 0; i < num_error_wasm; i++) {
        tmp_module_env = load_wasm((char *)wasm_file_error[i], 16 * 1024);

        if (0 != strlen(tmp_module_env.error_buf)) {
            EXPECT_EQ(0, strncmp("WASM module",
                                 (const char *)tmp_module_env.error_buf, 11));
        }

        destroy_module_env(tmp_module_env);
    }
}

TEST_F(TEST_SUITE_NAME, test_wasm_about_app_heap)
{
    struct ret_env tmp_module_env;

    // Test case: init_page_count = 65536, app heap size = 1.
    tmp_module_env = load_wasm((char *)"/wasm_mem_page_03.wasm", 1);
    EXPECT_EQ(0, strncmp("WASM module instantiate failed",
                         (const char *)tmp_module_env.error_buf, 30));
    destroy_module_env(tmp_module_env);

    // Test case: init_page_count = 65535, app heap size = 65537.
    tmp_module_env = load_wasm((char *)"/wasm_mem_page_20.wasm", 65537);
    EXPECT_EQ(0, strncmp("WASM module instantiate failed",
                         (const char *)tmp_module_env.error_buf, 30));
    destroy_module_env(tmp_module_env);
}

TEST_F(TEST_SUITE_NAME, test_throw_exception_out_of_bounds)
{
    struct ret_env tmp_module_env;
    WASMFunctionInstanceCommon *func = nullptr;
    bool ret = false;
    uint32 argv[1] = { 9999 * 64 * 1024 };
    const char *exception = nullptr;

    tmp_module_env = load_wasm((char *)"/out_of_bounds.wasm", 16 * 1024);
    func =
        wasm_runtime_lookup_function(tmp_module_env.wasm_module_inst, "load");
    if (!func) {
        printf("\nFailed to wasm_runtime_lookup_function!\n");
        goto failed_out_of_bounds;
    }

    ret = wasm_runtime_call_wasm(tmp_module_env.exec_env, func, 1, argv);
    if (!ret) {
        printf("\nFailed to wasm_runtime_call_wasm!\n");
    }

    exception = wasm_runtime_get_exception(tmp_module_env.wasm_module_inst);
    EXPECT_EQ(0,
              strncmp("Exception: out of bounds memory access", exception, 38));

failed_out_of_bounds:
    destroy_module_env(tmp_module_env);
}

TEST_F(TEST_SUITE_NAME, test_mem_grow_out_of_bounds)
{
    struct ret_env tmp_module_env;
    WASMFunctionInstanceCommon *func_mem_grow = nullptr;
    WASMFunctionInstanceCommon *func_mem_size = nullptr;
    bool ret = false;
    // after refactor, the 65536 pages to one 4G page optimization is removed
    // the size can be 65536 now, so use 2 + 65535 to test OOB
    uint32 argv[1] = { 65535 };
    const char *exception = nullptr;

    // Test case: module((memory 2)), memory.grow 65535, then memory.size.
    tmp_module_env = load_wasm((char *)"/mem_grow_out_of_bounds_01.wasm", 0);
    func_mem_grow = wasm_runtime_lookup_function(
        tmp_module_env.wasm_module_inst, "mem_grow");
    if (!func_mem_grow) {
        printf("\nFailed to wasm_runtime_lookup_function!\n");
        goto failed_out_of_bounds;
    }

    func_mem_size = wasm_runtime_lookup_function(
        tmp_module_env.wasm_module_inst, "mem_size");
    if (!func_mem_size) {
        printf("\nFailed to wasm_runtime_lookup_function!\n");
        goto failed_out_of_bounds;
    }

    ret =
        wasm_runtime_call_wasm(tmp_module_env.exec_env, func_mem_grow, 1, argv);
    if (!ret) {
        printf("\nFailed to wasm_runtime_call_wasm!\n");
        goto failed_out_of_bounds;
    }

    EXPECT_EQ(-1, argv[0]);

    ret =
        wasm_runtime_call_wasm(tmp_module_env.exec_env, func_mem_size, 0, argv);
    if (!ret) {
        printf("\nFailed to wasm_runtime_call_wasm!\n");
        goto failed_out_of_bounds;
    }

    EXPECT_EQ(2, argv[0]);

    // Test case: wasm_runtime_instantiate(heap_size=32768), memory.grow 65535,
    // memory.grow 1.
    destroy_module_env(tmp_module_env);
    tmp_module_env =
        load_wasm((char *)"/mem_grow_out_of_bounds_02.wasm", 32768);
    func_mem_grow = wasm_runtime_lookup_function(
        tmp_module_env.wasm_module_inst, "mem_grow");
    if (!func_mem_grow) {
        printf("\nFailed to wasm_runtime_lookup_function!\n");
        goto failed_out_of_bounds;
    }

    func_mem_size = wasm_runtime_lookup_function(
        tmp_module_env.wasm_module_inst, "mem_size");
    if (!func_mem_size) {
        printf("\nFailed to wasm_runtime_lookup_function!\n");
        goto failed_out_of_bounds;
    }

    ret =
        wasm_runtime_call_wasm(tmp_module_env.exec_env, func_mem_size, 0, argv);
    if (!ret) {
        printf("\nFailed to wasm_runtime_call_wasm!\n");
        goto failed_out_of_bounds;
    }
    EXPECT_EQ(2, argv[0]);

    argv[0] = 65535;
    ret =
        wasm_runtime_call_wasm(tmp_module_env.exec_env, func_mem_grow, 1, argv);
    if (!ret) {
        printf("\nFailed to wasm_runtime_call_wasm!\n");
        goto failed_out_of_bounds;
    }

    EXPECT_NE(2, argv[0]);

    argv[0] = 1;
    ret =
        wasm_runtime_call_wasm(tmp_module_env.exec_env, func_mem_grow, 1, argv);
    if (!ret) {
        printf("\nFailed to wasm_runtime_call_wasm!\n");
        goto failed_out_of_bounds;
    }

    EXPECT_EQ(2, argv[0]);

failed_out_of_bounds:
    destroy_module_env(tmp_module_env);
}
