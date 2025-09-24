/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "gtest/gtest.h"
#include "bh_platform.h"
#include "bh_read_file.h"
#include "aot_emit_memory.h"
#include "test_helper.h"

#define DEFAULT_CYCLE_TIMES 0xFFFF
#define DEFAULT_MAX_RAND_NUM 0xFFFFFFFF

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

class compilation_aot_emit_memory_test : public testing::Test
{
  protected:
    void SetUp() override
    {
        CWD = get_binary_path();
        WASM_FILE = strdup((CWD + MAIN_WASM).c_str());
        AOTCompOption option = { 0 };

        option.opt_level = 3;
        option.size_level = 3;
        option.output_format = AOT_FORMAT_FILE;
        /* default value, enable or disable depends on the platform */
        option.bounds_checks = 2;
        /* default value, enable or disable depends on the platform */
        option.stack_bounds_checks = 2;
        option.enable_simd = true;
        option.enable_aux_stack_check = true;
        option.enable_bulk_memory = true;
        option.enable_ref_types = true;

        const char *wasm_file = WASM_FILE;
        unsigned int wasm_file_size = 0;
        unsigned char *wasm_file_buf = nullptr;
        char error_buf[128] = { 0 };

        wasm_file_buf =
            (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
        EXPECT_NE(wasm_file_buf, nullptr);
        wasm_module = reinterpret_cast<WASMModule *>(wasm_runtime_load(
            wasm_file_buf, wasm_file_size, error_buf, sizeof(error_buf)));
        EXPECT_NE(wasm_module, nullptr);
        comp_data = aot_create_comp_data(wasm_module, NULL, false);
        EXPECT_NE(comp_data, nullptr);

        // properly init compilation and function context, to do that,
        // use as a dummy module(instead of compile the function in it, simply
        // test the APIs)
        comp_ctx = aot_create_comp_context(comp_data, &option);
        EXPECT_NE(comp_ctx, nullptr);
        func_ctx = comp_ctx->func_ctxes[0];
        EXPECT_NE(func_ctx, nullptr);
    }

    void TearDown() override
    {
        aot_destroy_comp_context(comp_ctx);
        aot_destroy_comp_data(comp_data);
        wasm_runtime_unload(reinterpret_cast<WASMModuleCommon *>(wasm_module));
    }

  public:
    WASMModule *wasm_module = nullptr;
    AOTCompData *comp_data = nullptr;
    AOTCompContext *comp_ctx = nullptr;
    AOTFuncContext *func_ctx = nullptr;

    WAMRRuntimeRAII<512 * 1024> runtime;
};

TEST_F(compilation_aot_emit_memory_test, aot_check_memory_overflow)
{
    uint32 offset = 64;
    uint32 bytes = 4;

    for (uint32 i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
        offset = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
        aot_check_memory_overflow(comp_ctx, func_ctx, offset, bytes, false,
                                  NULL);
    }
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_i32_load)
{
    uint32 align = 0;
    uint32 offset = 1024;
    uint32 bytes = 0;
    bool sign = false;
    bool atomic = false;

    for (uint32 i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
        align = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
        offset = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
        bytes = (1 + (rand() % (4 - 1 + 1)));
        printf("---%d", aot_compile_op_i32_load(comp_ctx, func_ctx, align,
                                                offset, bytes, sign, atomic));
    }
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_i64_load)
{
    uint32 align = 0;
    uint32 offset = 1024;
    uint32 bytes = 0;
    bool sign = false;
    bool atomic = false;

    for (uint32 i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
        align = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
        offset = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
        bytes = (1 + (rand() % (4 - 1 + 1)));
        sign = !sign;
        atomic = !atomic;
        aot_compile_op_i64_load(comp_ctx, func_ctx, align, offset, bytes, sign,
                                atomic);
    }
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_f32_load)
{
    uint32 align = 10;
    uint32 offset = 10;

    for (uint32 i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
        align = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
        offset = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
        aot_compile_op_f32_load(comp_ctx, func_ctx, align, offset);
    }
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_f64_load)
{
    uint32 align = 10;
    uint32 offset = 10;

    for (uint32 i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
        align = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
        offset = (1 + (rand() % (DEFAULT_MAX_RAND_NUM - 1 + 1)));
        aot_compile_op_f64_load(comp_ctx, func_ctx, align, offset);
    }
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_i32_store)
{
    uint32 align = 0;
    uint32 offset = 0;
    uint32 bytes = 0;
    bool atomic = false;

    EXPECT_FALSE(aot_compile_op_i32_store(comp_ctx, func_ctx, align, offset,
                                          bytes, atomic));

    /* Generate random number range：[m,n] int a=m+rand()%(n-m+1); */
    for (uint32 i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
        bytes = (1 + (rand() % (4 - 1 + 1)));
        offset = (1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        align = (1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        atomic = !atomic;

        EXPECT_FALSE(aot_compile_op_i32_store(comp_ctx, func_ctx, align, offset,
                                              bytes, atomic));
    }
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_i64_store)
{
    uint32 align = 0;
    uint32 offset = 0;
    uint32 bytes = 0;
    bool atomic = false;

    EXPECT_FALSE(aot_compile_op_i64_store(comp_ctx, func_ctx, align, offset,
                                          bytes, atomic));

    /* Generate random number range：[m,n] int a=m+rand()%(n-m+1); */
    for (uint32 i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
        bytes = (1 + (rand() % (8 - 1 + 1)));
        offset = (1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        align = (1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        atomic = !atomic;

        EXPECT_FALSE(aot_compile_op_i64_store(comp_ctx, func_ctx, align, offset,
                                              bytes, atomic));
    }
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_f32_store)
{
    uint32 align = 0;
    uint32 offset = 0;

    EXPECT_FALSE(aot_compile_op_f32_store(comp_ctx, func_ctx, align, offset));

    /* Generate random number range：[m,n] int a=m+rand()%(n-m+1); */
    for (uint32 i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
        offset = (1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        align = (1 + (rand() % (0xFFFFFFFF - 1 + 1)));

        EXPECT_FALSE(
            aot_compile_op_f32_store(comp_ctx, func_ctx, align, offset));
    }
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_f64_store)
{
    uint32 align = 0;
    uint32 offset = 0;

    EXPECT_FALSE(aot_compile_op_f64_store(comp_ctx, func_ctx, align, offset));

    /* Generate random number range：[m,n] int a=m+rand()%(n-m+1); */
    for (uint32 i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
        offset = (1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        align = (1 + (rand() % (0xFFFFFFFF - 1 + 1)));

        EXPECT_FALSE(
            aot_compile_op_f64_store(comp_ctx, func_ctx, align, offset));
    }
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_memory_size)
{
    aot_compile_op_memory_size(comp_ctx, func_ctx);
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_memory_grow)
{
    aot_compile_op_memory_grow(comp_ctx, func_ctx);
}

#if WASM_ENABLE_BULK_MEMORY != 0
TEST_F(compilation_aot_emit_memory_test, aot_compile_op_memory_init)
{
    uint32 seg_index = 0;

    /* Generate random number range：[m,n] int a=m+rand()%(n-m+1); */
    for (uint32 i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
        seg_index = (1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        aot_compile_op_memory_init(comp_ctx, func_ctx, seg_index);
    }
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_data_drop)
{
    uint32 seg_index = 0;

    /* Generate random number range：[m,n] int a=m+rand()%(n-m+1); */
    for (uint32 i = 0; i < DEFAULT_CYCLE_TIMES; i++) {
        seg_index = (1 + (rand() % (0xFFFFFFFF - 1 + 1)));
        aot_compile_op_data_drop(comp_ctx, func_ctx, seg_index);
    }
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_memory_copy)
{
    aot_compile_op_memory_copy(comp_ctx, func_ctx);
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_memory_fill)
{
    aot_compile_op_memory_fill(comp_ctx, func_ctx);
}
#endif

#if WASM_ENABLE_SHARED_MEMORY != 0
TEST_F(compilation_aot_emit_memory_test, aot_compile_op_atomic_rmw)
{
    uint8 atomic_op = LLVMAtomicRMWBinOpAdd;
    uint8 op_type = VALUE_TYPE_I32;
    uint32 align = 4;
    uint32 offset = 64;
    uint32 bytes = 4;

    aot_compile_op_atomic_rmw(comp_ctx, func_ctx, atomic_op, op_type, align,
                              offset, bytes);
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_atomic_cmpxchg)
{

    uint8 op_type = VALUE_TYPE_I32;
    uint32 align = 4;
    uint32 offset = 64;
    uint32 bytes = 4;

    aot_compile_op_atomic_cmpxchg(comp_ctx, func_ctx, op_type, align, offset,
                                  bytes);
}

TEST_F(compilation_aot_emit_memory_test, aot_compile_op_atomic_wait)
{

    uint8 op_type = VALUE_TYPE_I32;
    uint32 align = 4;
    uint32 offset = 64;
    uint32 bytes = 4;

    aot_compile_op_atomic_wait(comp_ctx, func_ctx, op_type, align, offset,
                               bytes);
}

TEST_F(compilation_aot_emit_memory_test, aot_compiler_op_atomic_notify)
{

    uint32 align = 4;
    uint32 offset = 64;
    uint32 bytes = 4;

    aot_compiler_op_atomic_notify(comp_ctx, func_ctx, align, offset, bytes);
}
#endif
