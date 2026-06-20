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
char *
aot_generate_tempfile_name(const char *prefix, const char *extension,
                           char *buffer, uint32 len);
}

class aot_compiler_test_suit : public testing::Test
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

void
test_aot_emit_object_file_with_option(AOTCompOption *option_ptr)
{
    const char *wasm_file = WASM_FILE;
    unsigned int wasm_file_size = 0;
    unsigned char *wasm_file_buf = nullptr;
    char error_buf[128] = { 0 };
    wasm_module_t wasm_module = nullptr;
    aot_comp_data_t comp_data = nullptr;
    aot_comp_context_t comp_ctx = nullptr;
    char out_file_name[] = "test.aot";

    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
    EXPECT_NE(wasm_file_buf, nullptr);
    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    EXPECT_NE(wasm_module, nullptr);

    comp_data = aot_create_comp_data(wasm_module, NULL, false);
    EXPECT_NE(nullptr, comp_data);

    comp_ctx = aot_create_comp_context(comp_data, option_ptr);
    EXPECT_NE(comp_ctx, nullptr);
    EXPECT_STREQ(aot_get_last_error(), "");
    EXPECT_TRUE(aot_compile_wasm(comp_ctx));

    EXPECT_TRUE(aot_emit_object_file(comp_ctx, out_file_name));
}

TEST_F(aot_compiler_test_suit, aot_emit_object_file)
{
    AOTCompOption option = { 0 };
    uint32_t i = 0;

    option.opt_level = 3;
    option.size_level = 3;
    option.output_format = AOT_FORMAT_FILE;
    option.bounds_checks = 2;
    option.enable_simd = true;
    option.enable_aux_stack_check = true;
    option.enable_bulk_memory = true;
    option.enable_ref_types = true;

    // Test opt_level in range from 0 to 3.
    for (i = 0; i <= 3; i++) {
        option.opt_level = i;
        test_aot_emit_object_file_with_option(&option);
    }

    // Test size_level in range from 0 to 3.
    option.opt_level = 3;
    for (i = 0; i <= 3; i++) {
        option.size_level = i;
        test_aot_emit_object_file_with_option(&option);
    }

    // Test output_format in range from AOT_FORMAT_FILE to AOT_LLVMIR_OPT_FILE.
    option.size_level = 3;
    for (i = AOT_FORMAT_FILE; i <= AOT_LLVMIR_OPT_FILE; i++) {
        option.output_format = i;
        test_aot_emit_object_file_with_option(&option);
    }

    // Test bounds_checks in range 0 to 2.
    option.output_format = AOT_FORMAT_FILE;
    for (i = 0; i <= 2; i++) {
        option.bounds_checks = i;
        test_aot_emit_object_file_with_option(&option);
    }

    // Test all enable option is false.
    option.bounds_checks = 2;
    option.enable_simd = false;
    option.enable_aux_stack_check = false;
    option.enable_bulk_memory = false;
    option.enable_ref_types = false;
    test_aot_emit_object_file_with_option(&option);
}

TEST_F(aot_compiler_test_suit, aot_emit_llvm_file)
{
    const char *wasm_file = WASM_FILE;
    unsigned int wasm_file_size = 0;
    unsigned char *wasm_file_buf = nullptr;
    char error_buf[128] = { 0 };
    wasm_module_t wasm_module = nullptr;
    aot_comp_data_t comp_data = nullptr;
    aot_comp_context_t comp_ctx = nullptr;
    AOTCompOption option = { 0 };
    char out_file_name[] = "out_file_name_test";

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

    comp_data = aot_create_comp_data(wasm_module, NULL, false);
    EXPECT_NE(nullptr, comp_data);
    comp_ctx = aot_create_comp_context(comp_data, &option);
    EXPECT_NE(comp_ctx, nullptr);
    EXPECT_STREQ(aot_get_last_error(), "");
    EXPECT_TRUE(aot_compile_wasm(comp_ctx));

    EXPECT_EQ(true, aot_emit_llvm_file(comp_ctx, out_file_name));
}

TEST_F(aot_compiler_test_suit, aot_generate_tempfile_name)
{
    char obj_file_name[64];

    // Test common case.
    aot_generate_tempfile_name("wamrc-obj", "o", obj_file_name,
                               sizeof(obj_file_name));
    EXPECT_NE(nullptr, strstr(obj_file_name, ".o"));

    // Test abnormal cases.
    EXPECT_EQ(nullptr,
              aot_generate_tempfile_name("wamrc-obj", "o", obj_file_name, 0));
    char obj_file_name_1[20];
    EXPECT_EQ(nullptr, aot_generate_tempfile_name(
                           "wamrc-obj", "12345678901234567890", obj_file_name_1,
                           sizeof(obj_file_name_1)));
}
