/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "test_helper.h"
#include "gtest/gtest.h"

#include "wasm_export.h"
#include "aot_export.h"
#include "bh_read_file.h"

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

extern "C" {
uint8 *
aot_emit_aot_file_buf(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                      uint32 *p_aot_file_size);
}

class aot_emit_aot_file_test_suite : public testing::Test
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

TEST_F(aot_emit_aot_file_test_suite, aot_emit_aot_file)
{
    const char *wasm_file = WASM_FILE;
    unsigned int wasm_file_size = 0;
    unsigned char *wasm_file_buf = nullptr;
    char error_buf[128] = { 0 };
    wasm_module_t wasm_module = nullptr;
    aot_comp_data_t comp_data = nullptr;
    aot_comp_context_t comp_ctx = nullptr;
    AOTCompOption option = { 0 };
    char out_file_name[] = "test.aot";

    option.opt_level = 3;
    option.size_level = 3;
    option.output_format = AOT_FORMAT_FILE;
    /* default value, enable or disable depends on the platform */
    option.bounds_checks = 2;
    option.enable_simd = false;
    option.enable_aux_stack_check = false;
    option.enable_bulk_memory = false;
    option.enable_ref_types = false;

    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
    EXPECT_NE(wasm_file_buf, nullptr);
    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    EXPECT_NE(wasm_module, nullptr);

    comp_data = aot_create_comp_data(wasm_module, NULL, false);
    EXPECT_NE(nullptr, comp_data);
    comp_ctx = aot_create_comp_context(comp_data, &option);
    EXPECT_NE(comp_ctx, nullptr);
    EXPECT_TRUE(aot_compile_wasm(comp_ctx));

    EXPECT_EQ(false, aot_emit_aot_file(comp_ctx, comp_data, nullptr));
}
