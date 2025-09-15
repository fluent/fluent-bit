/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "test_helper.h"
#include "gtest/gtest.h"

#include "bh_read_file.h"
#include "aot_llvm.h"
#include "aot_compiler.h"

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

class aot_llvm_test_suite : public testing::Test
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

TEST_F(aot_llvm_test_suite, aot_functions)
{
    const char *wasm_file = WASM_FILE;
    unsigned int wasm_file_size = 0;
    unsigned char *wasm_file_buf = nullptr;
    char error_buf[128] = { 0 };
    wasm_module_t wasm_module = nullptr;

    struct AOTCompData *comp_data = nullptr;
    struct AOTCompContext *comp_ctx = nullptr;
    AOTCompOption option = { 0 };
    AOTFuncContext *func_ctx = nullptr;
    WASMValue wasm_value;
    LLVMTypeRef param_types[1];

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

    param_types[0] = F64_TYPE;
    EXPECT_TRUE(aot_call_llvm_intrinsic(comp_ctx, func_ctx, "f32_demote_f64",
                                        F32_TYPE, param_types, 0));

    /* Test function aot_get_native_symbol_index. */
    AOTNativeSymbol elem_insert_1;
    elem_insert_1.index = -1;
    bh_list_insert(&comp_ctx->native_symbols, &elem_insert_1);

    AOTNativeSymbol elem_insert_2;
    strcpy(elem_insert_2.symbol, "f64#_test");
    elem_insert_2.index = -1;
    bh_list_insert(&comp_ctx->native_symbols, &elem_insert_2);
    comp_ctx->pointer_size = sizeof(uint32);
    strcpy(comp_ctx->target_arch, "i386");
    EXPECT_NE(-1, aot_get_native_symbol_index(comp_ctx, "f64#_test"));
}

TEST_F(aot_llvm_test_suite, wasm_type_to_llvm_type) {}

TEST_F(aot_llvm_test_suite, aot_build_zero_function_ret)
{
    const char *wasm_file = WASM_FILE;
    unsigned int wasm_file_size = 0;
    unsigned char *wasm_file_buf = nullptr;
    char error_buf[128] = { 0 };
    wasm_module_t wasm_module = nullptr;

    struct AOTCompData *comp_data = nullptr;
    struct AOTCompContext *comp_ctx = nullptr;
    AOTCompOption option = { 0 };
    AOTFuncContext *func_ctx = nullptr;
    AOTFuncType func_type;

    option.opt_level = 3;
    option.size_level = 3;
    option.output_format = AOT_FORMAT_FILE;
    /* default value, enable or disable depends on the platform */
    option.bounds_checks = 2;
    option.enable_simd = true;
    option.enable_aux_stack_check = true;
    option.enable_bulk_memory = true;
    option.enable_ref_types = false;

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

    func_type.result_count = 1;
    func_type.param_count = 0;
    func_type.types[func_type.param_count] = VALUE_TYPE_I32;
    EXPECT_NE(0, aot_build_zero_function_ret(comp_ctx, func_ctx, &func_type));
    func_type.types[func_type.param_count] = VALUE_TYPE_I64;
    EXPECT_NE(0, aot_build_zero_function_ret(comp_ctx, func_ctx, &func_type));
    func_type.types[func_type.param_count] = VALUE_TYPE_F32;
    EXPECT_NE(0, aot_build_zero_function_ret(comp_ctx, func_ctx, &func_type));
    func_type.types[func_type.param_count] = VALUE_TYPE_F64;
    EXPECT_NE(0, aot_build_zero_function_ret(comp_ctx, func_ctx, &func_type));
    func_type.types[func_type.param_count] = VALUE_TYPE_V128;
    EXPECT_NE(0, aot_build_zero_function_ret(comp_ctx, func_ctx, &func_type));
    /* THe current optimization, if not actually use ref_types in wasm module,
     * it will set to false, so test false condition */
    func_type.types[func_type.param_count] = VALUE_TYPE_FUNCREF;
    EXPECT_DEATH(aot_build_zero_function_ret(comp_ctx, func_ctx, &func_type),
                 ".*");
    func_type.types[func_type.param_count] = VALUE_TYPE_EXTERNREF;
    EXPECT_DEATH(aot_build_zero_function_ret(comp_ctx, func_ctx, &func_type),
                 ".*");
    func_type.types[func_type.param_count] = 0xFF;
    EXPECT_DEATH(aot_build_zero_function_ret(comp_ctx, func_ctx, &func_type),
                 ".*");
}

TEST_F(aot_llvm_test_suite, aot_destroy_comp_context)
{
    const char *wasm_file = WASM_FILE;
    unsigned int wasm_file_size = 0;
    unsigned char *wasm_file_buf = nullptr;
    char error_buf[128] = { 0 };
    wasm_module_t wasm_module = nullptr;

    struct AOTCompData *comp_data = nullptr;
    struct AOTCompContext *comp_ctx = nullptr;
    AOTCompOption option = { 0 };
    AOTFuncContext *func_ctx = nullptr;
    AOTFuncType func_type;

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

    AOTNativeSymbol elem_insert_1;
    elem_insert_1.index = -1;
    bh_list_insert(&comp_ctx->native_symbols, &elem_insert_1);
    aot_destroy_comp_context(comp_ctx);

    aot_destroy_comp_context(nullptr);
}

TEST_F(aot_llvm_test_suite, aot_create_comp_context)
{
    const char *wasm_file = WASM_FILE;
    unsigned int wasm_file_size = 0;
    unsigned char *wasm_file_buf = nullptr;
    char error_buf[128] = { 0 };
    wasm_module_t wasm_module = nullptr;

    struct AOTCompData *comp_data = nullptr;
    struct AOTCompContext *comp_ctx = nullptr;
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

    option.enable_thread_mgr = true;
    option.enable_tail_call = true;
    option.is_indirect_mode = true;
    option.disable_llvm_intrinsics = true;
    option.disable_llvm_lto = true;
    option.is_jit_mode = true;

    option.target_arch = (char *)"arm";
    comp_ctx = aot_create_comp_context(comp_data, &option);
    EXPECT_NE(comp_ctx, nullptr);
    option.output_format = 100;
    comp_ctx = aot_create_comp_context(comp_data, &option);

    // Test every target_arch.
    option.is_jit_mode = false;
    option.target_arch = (char *)"arm";
    comp_ctx = aot_create_comp_context(comp_data, &option);
    option.target_arch = (char *)"armeb";
    comp_ctx = aot_create_comp_context(comp_data, &option);
    option.target_arch = (char *)"thumb";
    comp_ctx = aot_create_comp_context(comp_data, &option);
    option.target_arch = (char *)"thumbeb";
    comp_ctx = aot_create_comp_context(comp_data, &option);
    option.target_arch = (char *)"aarch64";
    comp_ctx = aot_create_comp_context(comp_data, &option);
    option.target_arch = (char *)"aarch64_be";
    comp_ctx = aot_create_comp_context(comp_data, &option);
    option.target_arch = (char *)"help";
    comp_ctx = aot_create_comp_context(comp_data, &option);

    // Test every target_abi.
    option.target_arch = (char *)"arm";
    option.target_abi = (char *)"test";
    comp_ctx = aot_create_comp_context(comp_data, &option);
    option.target_abi = (char *)"help";
    comp_ctx = aot_create_comp_context(comp_data, &option);
    option.target_abi = (char *)"msvc";
    option.target_arch = (char *)"i386";
    comp_ctx = aot_create_comp_context(comp_data, &option);

    option.cpu_features = (char *)"test";
    comp_ctx = aot_create_comp_context(comp_data, &option);
    option.is_sgx_platform = true;
    comp_ctx = aot_create_comp_context(comp_data, &option);
    comp_data->func_count = 0;
    comp_ctx = aot_create_comp_context(comp_data, &option);
}
