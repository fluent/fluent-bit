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
#define TEST_SUITE_NAME linear_memory_test_suite_aot_no_hw_bound
#else
#define TEST_SUITE_NAME linear_memory_test_suite_aot
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
    wasm_module_t aot_module;
    wasm_module_inst_t aot_module_inst;
    unsigned char *aot_file_buf;
    char error_buf[128];
};

struct ret_env
load_aot(char *aot_file_tested, unsigned int app_heap_size)
{
    std::string aot_mem_page = aot_file_tested;
    const char *aot_file = strdup((CWD + aot_mem_page).c_str());
    wasm_module_inst_t aot_module_inst = nullptr;
    wasm_module_t aot_module = nullptr;
    wasm_exec_env_t exec_env = nullptr;
    unsigned char *aot_file_buf = nullptr;
    unsigned int aot_file_size = 0;
    unsigned int stack_size = 16 * 1024, heap_size = app_heap_size;
    char error_buf[128] = { 0 };
    struct ret_env ret_module_env;

    memset(ret_module_env.error_buf, 0, 128);
    aot_file_buf =
        (unsigned char *)bh_read_file_to_buffer(aot_file, &aot_file_size);
    if (!aot_file_buf) {
        goto fail;
    }

    aot_module = wasm_runtime_load(aot_file_buf, aot_file_size, error_buf,
                                   sizeof(error_buf));
    if (!aot_module) {
        memcpy(ret_module_env.error_buf, error_buf, 128);
        goto fail;
    }

    aot_module_inst = wasm_runtime_instantiate(
        aot_module, stack_size, heap_size, error_buf, sizeof(error_buf));
    if (!aot_module_inst) {
        memcpy(ret_module_env.error_buf, error_buf, 128);
        goto fail;
    }

    exec_env = wasm_runtime_create_exec_env(aot_module_inst, stack_size);

fail:
    ret_module_env.exec_env = exec_env;
    ret_module_env.aot_module = aot_module;
    ret_module_env.aot_module_inst = aot_module_inst;
    ret_module_env.aot_file_buf = aot_file_buf;

    return ret_module_env;
}

void
destroy_module_env(struct ret_env module_env)
{
    if (module_env.exec_env) {
        wasm_runtime_destroy_exec_env(module_env.exec_env);
    }

    if (module_env.aot_module_inst) {
        wasm_runtime_deinstantiate(module_env.aot_module_inst);
    }

    if (module_env.aot_module) {
        wasm_runtime_unload(module_env.aot_module);
    }

    if (module_env.aot_file_buf) {
        wasm_runtime_free(module_env.aot_file_buf);
    }
}

TEST_F(TEST_SUITE_NAME, test_aot_mem_page_count)
{
    struct ret_env tmp_module_env;
    const unsigned int num_normal_aot = 9;
    const unsigned int num_error_aot = 2;

#if UINTPTR_MAX == UINT64_MAX
    const char *aot_file_normal[num_normal_aot] = {
        "/mem_page_01.aot", "/mem_page_02.aot", "/mem_page_05.aot",
        "/mem_page_07.aot", "/mem_page_08.aot", "/mem_page_09.aot",
        "/mem_page_10.aot", "/mem_page_12.aot", "/mem_page_14.aot"
    };

    const char *aot_file_error[num_error_aot] = { "/mem_page_03.aot",
                                                  "/mem_page_16.aot" };
#else
    const char *aot_file_normal[num_normal_aot] = {
        "/mem_page_01_32.aot", "/mem_page_02_32.aot", "/mem_page_05_32.aot",
        "/mem_page_07_32.aot", "/mem_page_08_32.aot", "/mem_page_09_32.aot",
        "/mem_page_10_32.aot", "/mem_page_12_32.aot", "/mem_page_14_32.aot"
    };

    const char *aot_file_error[num_error_aot] = { "/mem_page_03_32.aot",
                                                  "/mem_page_16_32.aot" };
#endif

    // Test normal wasm file.
    for (int i = 0; i < num_normal_aot; i++) {
#if UINTPTR_MAX != UINT64_MAX
        // 32 bit do not load this wasm.
        if ((0 == strcmp("/mem_page_14_32.aot", aot_file_normal[i]))) {
            continue;
        }
#endif

        tmp_module_env = load_aot((char *)aot_file_normal[i], 16 * 1024);
        EXPECT_NE(nullptr, tmp_module_env.aot_module);
        EXPECT_NE(nullptr, tmp_module_env.aot_file_buf);

        destroy_module_env(tmp_module_env);
    }

    // Test error wasm file.
    for (int i = 0; i < num_error_aot; i++) {
        tmp_module_env = load_aot((char *)aot_file_error[i], 16 * 1024);
        if (0 != strlen(tmp_module_env.error_buf)) {
            /* 3 and 16 are for legit for loader, the init and max page count
             * can be 65536, but they can't allocate any host managed heap, so
             * instantiating errors  */
            EXPECT_EQ(0, strncmp("AOT module instantiate failed",
                                 (const char *)tmp_module_env.error_buf, 29));
            printf("%s\n", tmp_module_env.error_buf);
        }

        destroy_module_env(tmp_module_env);
    }
}

TEST_F(TEST_SUITE_NAME, test_aot_about_app_heap)
{
    struct ret_env tmp_module_env;

    // Test case: init_page_count = 65536, app heap size = 1.
#if UINTPTR_MAX == UINT64_MAX
    tmp_module_env = load_aot((char *)"/mem_page_03.aot", 1);
#else
    tmp_module_env = load_aot((char *)"/mem_page_03_32.aot", 1);
#endif
    EXPECT_EQ(
        0, strncmp("AOT module", (const char *)tmp_module_env.error_buf, 10));
    destroy_module_env(tmp_module_env);

    // Test case: init_page_count = 65535, app heap size = 65537.
#if UINTPTR_MAX == UINT64_MAX
    tmp_module_env = load_aot((char *)"/mem_page_20.aot", 65537);
#else
    tmp_module_env = load_aot((char *)"/mem_page_20_32.aot", 65537);
#endif
    EXPECT_EQ(
        0, strncmp("AOT module", (const char *)tmp_module_env.error_buf, 10));
    destroy_module_env(tmp_module_env);
}

TEST_F(TEST_SUITE_NAME, test_throw_exception_out_of_bounds)
{
    struct ret_env tmp_module_env;
    WASMFunctionInstanceCommon *func = nullptr;
    bool ret = false;
    uint32 argv[1] = { 9999 * 64 * 1024 };
    const char *exception = nullptr;

    /* TODO: use no_hw_bounds version when disable */
#if UINTPTR_MAX == UINT64_MAX
    tmp_module_env = load_aot((char *)"/out_of_bounds.aot", 16 * 1024);
#else
    tmp_module_env = load_aot((char *)"/out_of_bounds_32.aot", 16 * 1024);
#endif
    func = wasm_runtime_lookup_function(tmp_module_env.aot_module_inst, "load");
    if (!func) {
        printf("\nFailed to wasm_runtime_lookup_function!\n");
        goto failed_out_of_bounds;
    }

    ret = wasm_runtime_call_wasm(tmp_module_env.exec_env, func, 1, argv);
    if (!ret) {
        printf("\nFailed to wasm_runtime_call_wasm!\n");
    }

    exception = wasm_runtime_get_exception(tmp_module_env.aot_module_inst);
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
    uint32 argv[1] = { 65535 };
    const char *exception = nullptr;

    /* TODO: use no_hw_bounds version when disable */
    // Test case: module((memory 2)), memory.grow 65535, then memory.size.
#if UINTPTR_MAX == UINT64_MAX
    tmp_module_env = load_aot((char *)"/mem_grow_out_of_bounds_01.aot", 0);
#else
    tmp_module_env = load_aot((char *)"/mem_grow_out_of_bounds_01_32.aot", 0);
#endif

    func_mem_grow = wasm_runtime_lookup_function(tmp_module_env.aot_module_inst,
                                                 "mem_grow");
    if (!func_mem_grow) {
        printf("\nFailed to wasm_runtime_lookup_function!\n");
        goto failed_out_of_bounds;
    }

    func_mem_size = wasm_runtime_lookup_function(tmp_module_env.aot_module_inst,
                                                 "mem_size");
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

    // Test case: wasm_runtime_instantiate(heap_size=32768), memory.grow 65534,
    // memory.grow 1.
    destroy_module_env(tmp_module_env);

#if UINTPTR_MAX == UINT64_MAX
    tmp_module_env = load_aot((char *)"/mem_grow_out_of_bounds_02.aot", 32768);
#else
    tmp_module_env =
        load_aot((char *)"/mem_grow_out_of_bounds_02_32.aot", 32768);
#endif

    func_mem_grow = wasm_runtime_lookup_function(tmp_module_env.aot_module_inst,
                                                 "mem_grow");
    if (!func_mem_grow) {
        printf("\nFailed to wasm_runtime_lookup_function!\n");
        goto failed_out_of_bounds;
    }

    func_mem_size = wasm_runtime_lookup_function(tmp_module_env.aot_module_inst,
                                                 "mem_size");
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

    argv[0] = 65534;
    ret =
        wasm_runtime_call_wasm(tmp_module_env.exec_env, func_mem_grow, 1, argv);
    if (!ret) {
        printf("\nFailed to wasm_runtime_call_wasm!\n");
        goto failed_out_of_bounds;
    }

#if UINTPTR_MAX == UINT64_MAX
    EXPECT_EQ(2, argv[0]);
#else
    EXPECT_EQ(-1, argv[0]);
#endif

    argv[0] = 1;
    ret =
        wasm_runtime_call_wasm(tmp_module_env.exec_env, func_mem_grow, 1, argv);
    if (!ret) {
        printf("\nFailed to wasm_runtime_call_wasm!\n");
        goto failed_out_of_bounds;
    }

#if UINTPTR_MAX == UINT64_MAX
    EXPECT_EQ(-1, argv[0]);
#else
    EXPECT_EQ(2, argv[0]);
#endif

failed_out_of_bounds:
    destroy_module_env(tmp_module_env);
}
