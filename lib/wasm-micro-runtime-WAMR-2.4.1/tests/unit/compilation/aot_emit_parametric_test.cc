/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "test_helper.h"
#include "gtest/gtest.h"

#include "bh_read_file.h"
#include "aot_llvm.h"
#include "aot_emit_parametric.h"

static std::string CWD;
static std::string MAIN_WASM = "/main.wasm";
static char *WASM_FILE;

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

class aot_emit_parametric_test_suite : public testing::Test
{
  protected:
    // You should make the members protected s.t. they can be
    // accessed from sub-classes.

    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    virtual void SetUp() {}

    static void SetUpTestCase()
    {
        CWD = get_binary_path();
        WASM_FILE = strdup((CWD + MAIN_WASM).c_str());
    }

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    virtual void TearDown() {}

    static void TearDownTestCase() { free(WASM_FILE); }

    WAMRRuntimeRAII<512 * 1024> runtime;
};

TEST_F(aot_emit_parametric_test_suite, aot_compile_op_select)
{
    const char *wasm_file = WASM_FILE;
    unsigned int wasm_file_size = 0;
    unsigned char *wasm_file_buf = nullptr;
    char error_buf[128] = { 0 };
    wasm_module_t wasm_module = nullptr;

    struct AOTCompData *comp_data = nullptr;
    struct AOTCompContext *comp_ctx = nullptr;
    AOTFuncContext *func_ctx = nullptr;
    AOTCompOption option = { 0 };

    option.opt_level = 3;
    option.size_level = 3;
    option.output_format = AOT_FORMAT_FILE;
    /* default value, enable or disable depends on the platform */
    option.bounds_checks = 2;
    option.enable_simd = true;
    option.enable_aux_stack_check = true;
    option.enable_bulk_memory = true;
    option.enable_ref_types = true;

    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
    EXPECT_NE(wasm_file_buf, nullptr);
    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    EXPECT_NE(wasm_module, nullptr);

    comp_data = aot_create_comp_data((WASMModule *)wasm_module, NULL, false);
    EXPECT_NE(nullptr, comp_data);
    comp_ctx = aot_create_comp_context(comp_data, &option);
    EXPECT_NE(comp_ctx, nullptr);
    EXPECT_TRUE(aot_compile_wasm(comp_ctx));
    func_ctx = comp_ctx->func_ctxes[1];

    EXPECT_FALSE(aot_compile_op_select(comp_ctx, func_ctx, true));
    EXPECT_FALSE(aot_compile_op_select(comp_ctx, func_ctx, false));
}

TEST_F(aot_emit_parametric_test_suite, aot_compile_op_drop)
{
    const char *wasm_file = WASM_FILE;
    unsigned int wasm_file_size = 0;
    unsigned char *wasm_file_buf = nullptr;
    char error_buf[128] = { 0 };
    wasm_module_t wasm_module = nullptr;

    struct AOTCompData *comp_data = nullptr;
    struct AOTCompContext *comp_ctx = nullptr;
    AOTFuncContext *func_ctx = nullptr;
    AOTCompOption option = { 0 };

    option.opt_level = 3;
    option.size_level = 3;
    option.output_format = AOT_FORMAT_FILE;
    /* default value, enable or disable depends on the platform */
    option.bounds_checks = 2;
    option.enable_simd = true;
    option.enable_aux_stack_check = true;
    option.enable_bulk_memory = true;
    option.enable_ref_types = true;

    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
    EXPECT_NE(wasm_file_buf, nullptr);
    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    EXPECT_NE(wasm_module, nullptr);

    comp_data = aot_create_comp_data((WASMModule *)wasm_module, NULL, false);
    EXPECT_NE(nullptr, comp_data);
    comp_ctx = aot_create_comp_context(comp_data, &option);
    EXPECT_NE(comp_ctx, nullptr);
    EXPECT_TRUE(aot_compile_wasm(comp_ctx));
    func_ctx = comp_ctx->func_ctxes[1];
    func_ctx->block_stack.block_list_end = nullptr;

    EXPECT_FALSE(aot_compile_op_drop(comp_ctx, func_ctx, true));
    EXPECT_FALSE(aot_compile_op_drop(comp_ctx, func_ctx, false));
}
