/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "gtest/gtest.h"
#include "bh_platform.h"
#include "bh_read_file.h"
#include "wasm_export.h"
#if WASM_ENABLE_MULTI_MODULE != 0
#include "wasm.h"
#include "wasm_runtime.h"
#endif
#include "wasm-apps/app1_wasm.h"
#include "wasm-apps/app2_wasm.h"
#include "wasm-apps/app3_wasm.h"

#define EightK (8 * 1024)
// To use a test fixture, derive a class from testing::Test.
class WasmVMTest : public testing::Test
{
  protected:
    // You should make the members protected s.t. they can be
    // accessed from sub-classes.

    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    void SetUp()
    {
        memset(&init_args, 0, sizeof(RuntimeInitArgs));

        init_args.mem_alloc_type = Alloc_With_Pool;
        init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
        init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

        ASSERT_EQ(wasm_runtime_full_init(&init_args), true);

        // bh_log_set_verbose_level(5);

        clean = true;
    }

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    void TearDown()
    {
        if (clean) {
            wasm_runtime_destroy();
        }
    }

  public:
    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_function_inst_t func_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    char error_buf[128];
    char global_heap_buf[512 * 1024];
    RuntimeInitArgs init_args;
    bool clean = true;
};

TEST_F(WasmVMTest, Test_app1)
{
    uint32 argv[10];

    ASSERT_TRUE(app1_wasm != NULL);

    /* Load module */
    module = wasm_runtime_load(app1_wasm, sizeof(app1_wasm), error_buf,
                               sizeof(error_buf));
    if (module == nullptr) {
        printf("error: %s\n", error_buf);
    }

    ASSERT_TRUE(module != NULL);

    /* Initiate module */
    module_inst = wasm_runtime_instantiate(module, 8 * 1024, 8 * 1024,
                                           error_buf, sizeof(error_buf));
    ASSERT_TRUE(module_inst != NULL);

    exec_env = wasm_runtime_create_exec_env(module_inst, 8 * 1024);
    ASSERT_TRUE(exec_env != NULL);

    /* _on_init() function doesn't exist */
    func_inst = wasm_runtime_lookup_function(module_inst, "_on_init");
    ASSERT_TRUE(func_inst == NULL);

    /* on_init() function exists */
    func_inst = wasm_runtime_lookup_function(module_inst, "on_init");
    ASSERT_TRUE(func_inst != NULL);

    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_inst, 0, NULL) == true);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);

    /* call my_malloc */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_malloc");
    ASSERT_TRUE(func_inst != NULL);

    /* malloc with very large size */
    argv[0] = 10 * 1024;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);
    wasm_runtime_clear_exception(module_inst);
    ASSERT_EQ(argv[0], 0);

    /* malloc 1K, should success */
    argv[0] = 1024;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);

    /* convert to native address */
    ASSERT_TRUE(wasm_runtime_validate_app_addr(module_inst, argv[0], 1));
    char *buf = (char *)wasm_runtime_addr_app_to_native(module_inst, argv[0]);
    ASSERT_TRUE(buf != NULL);

    ASSERT_EQ(wasm_runtime_addr_native_to_app(module_inst, buf), argv[0]);
    int32 buf_offset = argv[0];

    /* call memcpy */
    char *buf1 = buf + 100;
    memcpy(buf1, "123456", 7);
    func_inst = wasm_runtime_lookup_function(module_inst, "my_memcpy");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset;
    argv[1] = buf_offset + 100;
    argv[2] = 7;
    wasm_runtime_call_wasm(exec_env, func_inst, 3, argv);
    ASSERT_TRUE(strcmp(buf, buf1) == 0);

    /* call strdup */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_strdup");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);

    int32 buf_offset1 = argv[0];
    ASSERT_NE(buf_offset, buf_offset1);

    buf1 = (char *)wasm_runtime_addr_app_to_native(module_inst, buf_offset1);
    ASSERT_TRUE(strcmp(buf, buf1) == 0);

    wasm_runtime_deinstantiate(module_inst);
    wasm_runtime_unload(module);
    wasm_runtime_destroy_exec_env(exec_env);
}

TEST_F(WasmVMTest, Test_app2)
{
    uint32 argv[10];

    /* Load module */
    module = wasm_runtime_load(app2_wasm, sizeof(app2_wasm), error_buf,
                               sizeof(error_buf));

    ASSERT_TRUE(module != NULL);

    /* Initiate module */
    module_inst = wasm_runtime_instantiate(module, 8 * 1024, 8 * 1024,
                                           error_buf, sizeof(error_buf));
    ASSERT_TRUE(module_inst != NULL);

    exec_env = wasm_runtime_create_exec_env(module_inst, 8 * 1024);
    ASSERT_TRUE(exec_env != NULL);

    /* _on_init() function doesn't exist */
    func_inst = wasm_runtime_lookup_function(module_inst, "_on_init");
    ASSERT_TRUE(func_inst == NULL);

    /* on_init() function exists */
    func_inst = wasm_runtime_lookup_function(module_inst, "on_init");
    ASSERT_TRUE(func_inst != NULL);

    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_inst, 0, NULL) == true);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);

    /* call my_malloc */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_malloc");
    ASSERT_TRUE(func_inst != NULL);

    /* malloc 1K, should success */
    argv[0] = 1024;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);

    /* convert to native address */
    ASSERT_TRUE(wasm_runtime_validate_app_addr(module_inst, argv[0], 1));
    char *buf = (char *)wasm_runtime_addr_app_to_native(module_inst, argv[0]);
    ASSERT_TRUE(buf != NULL);

    ASSERT_EQ(wasm_runtime_addr_native_to_app(module_inst, buf), argv[0]);
    int32 buf_offset = argv[0];

    /* call memcpy */
    char *buf1 = buf + 100;
    memcpy(buf1, "123456", 7);
    func_inst = wasm_runtime_lookup_function(module_inst, "my_memcpy");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset;
    argv[1] = buf_offset + 100;
    argv[2] = 7;
    wasm_runtime_call_wasm(exec_env, func_inst, 3, argv);
    ASSERT_TRUE(strcmp(buf, buf1) == 0);

    /* call memcmp */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_memcmp");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset;
    argv[1] = buf_offset + 100;
    argv[2] = 7;
    wasm_runtime_call_wasm(exec_env, func_inst, 3, argv);

    ASSERT_TRUE(argv[0] == 0);

    /* call printf */
    char *format = buf + 200;
    memcpy(format, "string0 is %s", 13);
    func_inst = wasm_runtime_lookup_function(module_inst, "my_printf");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = wasm_runtime_addr_native_to_app(module_inst, format);
    argv[1] = buf_offset;
    wasm_runtime_call_wasm(exec_env, func_inst, 2, argv);
    ASSERT_TRUE(argv[0] == 17);

    /* call sprintf */
    memcpy(format, "string1 is %s", 13);
    func_inst = wasm_runtime_lookup_function(module_inst, "my_sprintf");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset + 300;
    int32 argv0_tmp = argv[0];
    argv[1] = wasm_runtime_addr_native_to_app(module_inst, format);
    argv[2] = buf_offset;
    wasm_runtime_call_wasm(exec_env, func_inst, 3, argv);

    ASSERT_TRUE(
        memcmp((char *)wasm_runtime_addr_app_to_native(module_inst, argv0_tmp),
               "string1 is 123456", 17)
        == 0);
    ASSERT_TRUE(argv[0] == 17);

    /* call snprintf */
    memcpy(format, "string2 is %s", 13);
    func_inst = wasm_runtime_lookup_function(module_inst, "my_snprintf");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset + 400;
    argv0_tmp = argv[0];
    argv[1] = 3;
    argv[2] = wasm_runtime_addr_native_to_app(module_inst, format);
    argv[3] = buf_offset;
    wasm_runtime_call_wasm(exec_env, func_inst, 4, argv);

    ASSERT_TRUE(
        memcmp((char *)wasm_runtime_addr_app_to_native(module_inst, argv0_tmp),
               "st\0", 3)
        == 0);
    ASSERT_TRUE(argv[0] == 17);

    /* call puts */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_puts");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);

    ASSERT_TRUE(argv[0] != EOF);

    /* call putchar */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_putchar");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);

    ASSERT_TRUE(argv[0] != EOF);

    /* call memmove without memory coverage*/
    func_inst = wasm_runtime_lookup_function(module_inst, "my_memmove");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset + 10;
    argv[1] = buf_offset + 100;
    argv[2] = 6;
    wasm_runtime_call_wasm(exec_env, func_inst, 3, argv);

    buf1 = (char *)wasm_runtime_addr_app_to_native(module_inst, argv[0]);
    ASSERT_TRUE(strcmp(buf + 100, buf1) == 0);
    ASSERT_TRUE(memcmp(buf1, "123456", 6) == 0);

    /* call memmove with memory coverage*/
    func_inst = wasm_runtime_lookup_function(module_inst, "my_memmove");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset + 95;
    argv[1] = buf_offset + 100;
    argv[2] = 6;
    wasm_runtime_call_wasm(exec_env, func_inst, 3, argv);

    buf1 = (char *)wasm_runtime_addr_app_to_native(module_inst, argv[0]);
    ASSERT_TRUE(strcmp(buf + 100, buf1) != 0);
    ASSERT_TRUE(memcmp(buf1, "123456", 6) == 0);
    ASSERT_TRUE(memcmp(buf + 100, "623456", 6) == 0);

    /* call memset*/
    func_inst = wasm_runtime_lookup_function(module_inst, "my_memset");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset + 100;
    argv[1] = 48;
    argv[2] = 4;
    wasm_runtime_call_wasm(exec_env, func_inst, 3, argv);
    ASSERT_TRUE(memcmp(buf + 100, "000056", 6) == 0);

    /* call strchr*/
    func_inst = wasm_runtime_lookup_function(module_inst, "my_strchr");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset;
    argv[1] = 49; // asc2 for char "1"
    wasm_runtime_call_wasm(exec_env, func_inst, 2, argv);

    buf1 = (char *)wasm_runtime_addr_app_to_native(module_inst, argv[0]);
    ASSERT_TRUE(buf1 - buf == 0);

    /* call strcmp */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_strcmp");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset;
    argv[1] = buf_offset;
    wasm_runtime_call_wasm(exec_env, func_inst, 2, argv);

    ASSERT_TRUE(argv[0] == 0);

    argv[0] = buf_offset;
    argv[1] = buf_offset + 1;
    wasm_runtime_call_wasm(exec_env, func_inst, 2, argv);

    ASSERT_TRUE(argv[0] != 0);

    /* call strcpy */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_strcpy");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset + 110;
    argv[1] = buf_offset;
    wasm_runtime_call_wasm(exec_env, func_inst, 2, argv);
    ASSERT_TRUE(memcmp(buf + 110, "123456", 6) == 0);

    /* call strlen */
    buf1 = buf + 110;
    memcpy(buf1, "123456\0", 7);
    func_inst = wasm_runtime_lookup_function(module_inst, "my_strlen");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset + 110;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);

    ASSERT_TRUE(argv[0] == 6);

    /* call strncmp */
    buf1 = buf + 110;
    memcpy(buf1, "123457", 6);
    func_inst = wasm_runtime_lookup_function(module_inst, "my_strncmp");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset;
    argv[1] = buf_offset + 110;
    argv[2] = 5;
    wasm_runtime_call_wasm(exec_env, func_inst, 3, argv);

    ASSERT_TRUE(argv[0] == 0);

    argv[0] = buf_offset;
    argv[1] = buf_offset + 110;
    argv[2] = 6;
    wasm_runtime_call_wasm(exec_env, func_inst, 3, argv);

    ASSERT_TRUE(argv[0] != 0);

    /* call strncpy */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_strncpy");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset + 130;
    argv[1] = buf_offset;
    argv[2] = 5;
    wasm_runtime_call_wasm(exec_env, func_inst, 3, argv);

    buf1 = (char *)wasm_runtime_addr_app_to_native(module_inst, argv[0]);
    ASSERT_TRUE(memcmp(buf, buf1, 5) == 0);
    ASSERT_TRUE(memcmp(buf, buf1, 6) != 0);

    /* call _my_calloc */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_calloc");
    ASSERT_TRUE(func_inst != NULL);
    /* calloc, should success */
    argv[0] = 10;
    argv[1] = 4;
    wasm_runtime_call_wasm(exec_env, func_inst, 2, argv);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);

    /* convert to native address */
    ASSERT_TRUE(wasm_runtime_validate_app_addr(module_inst, argv[0], 40));
    char *buf2 = (char *)wasm_runtime_addr_app_to_native(module_inst, argv[0]);
    ASSERT_TRUE(buf2 != NULL);

    ASSERT_EQ(wasm_runtime_addr_native_to_app(module_inst, buf2), argv[0]);
    int32 buf_offset1 = argv[0];

    /* call _my_free */
    memcpy(buf2, "123456", 6);
    func_inst = wasm_runtime_lookup_function(module_inst, "my_free");
    ASSERT_TRUE(func_inst != NULL);
    argv[0] = buf_offset1;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);

    ASSERT_TRUE(memcmp(buf2, "123456", 6) != 0);

    wasm_runtime_deinstantiate(module_inst);
    wasm_runtime_unload(module);
    wasm_runtime_destroy_exec_env(exec_env);
}

TEST_F(WasmVMTest, Test_app3)
{
    uint32 argv[10];

    /* Load module */
    module = wasm_runtime_load(app3_wasm, sizeof(app3_wasm), error_buf,
                               sizeof(error_buf));

    ASSERT_TRUE(module != NULL);

    /* Initiate module */
    module_inst = wasm_runtime_instantiate(module, 8 * 1024, 8 * 1024,
                                           error_buf, sizeof(error_buf));
    ASSERT_TRUE(module_inst != NULL);

    exec_env = wasm_runtime_create_exec_env(module_inst, 8 * 1024);
    ASSERT_TRUE(exec_env != NULL);

    /* _on_init() function doesn't exist */
    func_inst = wasm_runtime_lookup_function(module_inst, "_on_init");
    ASSERT_TRUE(func_inst == NULL);

    /* on_init() function exists */
    func_inst = wasm_runtime_lookup_function(module_inst, "on_init");
    ASSERT_TRUE(func_inst != NULL);

    ASSERT_TRUE(wasm_runtime_call_wasm(exec_env, func_inst, 0, NULL) == true);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);

    /* call my_malloc */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_malloc");
    ASSERT_TRUE(func_inst != NULL);

    /* malloc with very large size */
    argv[0] = 10 * 1024;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);
    wasm_runtime_clear_exception(module_inst);
    ASSERT_EQ(argv[0], 0);

    /* malloc 1K, should success */
    argv[0] = 1024;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);

    /* convert to native address */
    ASSERT_TRUE(wasm_runtime_validate_app_addr(module_inst, argv[0], 1));
    char *buf = (char *)wasm_runtime_addr_app_to_native(module_inst, argv[0]);
    ASSERT_TRUE(buf != NULL);

    ASSERT_EQ(wasm_runtime_addr_native_to_app(module_inst, buf), argv[0]);

    /* call my_malloc */
    func_inst = wasm_runtime_lookup_function(module_inst, "my_malloc");
    ASSERT_TRUE(func_inst != NULL);

    /* malloc, should success */
    argv[0] = 10;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);

    /* convert to native address */
    ASSERT_TRUE(wasm_runtime_validate_app_addr(module_inst, argv[0], 1));
    char *buf1 = (char *)wasm_runtime_addr_app_to_native(module_inst, argv[0]);
    ASSERT_TRUE(buf1 != NULL);

    ASSERT_EQ(wasm_runtime_addr_native_to_app(module_inst, buf1), argv[0]);

    wasm_runtime_deinstantiate(module_inst);
    wasm_runtime_unload(module);
    wasm_runtime_destroy_exec_env(exec_env);
}

#if WASM_ENABLE_MULTI_MODULE != 0
static const char *module_search_path = ".";
static bool call_destroyer = false;
static bool
module_reader_callback(package_type_t module_type, const char *module_name,
                       uint8 **p_buffer, uint32 *p_size)
{
    const char *format = "%s/%s.wasm";
    int sz = strlen(module_search_path) + strlen("/") + strlen(module_name)
             + strlen(".wasm") + 1;
    char *wasm_file_name = (char *)BH_MALLOC(sz);
    if (!wasm_file_name) {
        return false;
    }

    snprintf(wasm_file_name, sz, format, module_search_path, module_name);
    printf("going to open %s\n", wasm_file_name);

    call_destroyer = false;
    *p_buffer = (uint8_t *)bh_read_file_to_buffer(wasm_file_name, p_size);

    BH_FREE(wasm_file_name);
    return *p_buffer != NULL;
}

static void
module_destroyer_callback(uint8 *buffer, uint32 size)
{
    wasm_runtime_free(buffer);
    call_destroyer = true;
}

TEST_F(WasmVMTest, Test_app4_single)
{
    uint8 *buffer = NULL;
    uint32 buffer_size = 0;
    bool ret = false;
    uint32 argv[10];

    wasm_runtime_set_module_reader(&module_reader_callback,
                                   &module_destroyer_callback);

    /* m1 only  */
    ret = module_reader_callback(Wasm_Module_Bytecode, "m1", &buffer,
                                 &buffer_size);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(buffer_size > 0);
    ASSERT_TRUE(buffer != NULL);

    module =
        wasm_runtime_load(buffer, buffer_size, error_buf, sizeof(error_buf));
    ASSERT_TRUE(module != NULL);

    ASSERT_FALSE(wasm_runtime_find_module_registered("m1"));

    wasm_runtime_register_module("m1", module, error_buf, sizeof(error_buf));

    ASSERT_TRUE(wasm_runtime_find_module_registered("m1"));

    module_inst = wasm_runtime_instantiate(module, EightK, EightK, error_buf,
                                           sizeof(error_buf));
    ASSERT_TRUE(module_inst != NULL);

    exec_env = wasm_runtime_create_exec_env(module_inst, EightK);
    ASSERT_TRUE(exec_env != NULL);

    func_inst = wasm_runtime_lookup_function(module_inst, "f1");
    ASSERT_TRUE(func_inst != NULL);
    ASSERT_FALSE(((WASMFunctionInstance *)func_inst)->is_import_func);
    ASSERT_TRUE(((WASMFunctionInstance *)func_inst)->param_cell_num == 0);
    ASSERT_TRUE(((WASMFunctionInstance *)func_inst)->ret_cell_num == 1);

    wasm_runtime_call_wasm(exec_env, func_inst, 0, argv);
    printf("exception is %s", wasm_runtime_get_exception(module_inst));

    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);
    ASSERT_TRUE(argv[0] == 1);

    wasm_runtime_destroy_exec_env(exec_env);
    wasm_runtime_deinstantiate(module_inst);
    wasm_runtime_unload(module);

    // call destroyer and without exception
    ASSERT_FALSE(call_destroyer);
    module_destroyer_callback(buffer, buffer_size);

    clean = false;
    wasm_runtime_destroy();
}

TEST_F(WasmVMTest, Test_app4_plus_one)
{
    uint8 *buffer = NULL;
    uint32 buffer_size = 0;
    bool ret = false;
    uint32 argv[10] = { 0 };

    wasm_runtime_set_module_reader(&module_reader_callback,
                                   &module_destroyer_callback);

    /* m2 -> m1 */
    ret = module_reader_callback(Wasm_Module_Bytecode, "m2", &buffer,
                                 &buffer_size);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(buffer_size > 0);
    ASSERT_TRUE(buffer != NULL);

    module =
        wasm_runtime_load(buffer, buffer_size, error_buf, sizeof(error_buf));
    ASSERT_TRUE(module != NULL);

    module_inst = wasm_runtime_instantiate(module, EightK, EightK, error_buf,
                                           sizeof(error_buf));
    ASSERT_TRUE(module_inst != NULL);

    exec_env = wasm_runtime_create_exec_env(module_inst, EightK);
    ASSERT_TRUE(exec_env != NULL);

    printf("------------------- m1-f1 ---------------------\n");
    func_inst = wasm_runtime_lookup_function(module_inst, "m1-f1");
    ASSERT_TRUE(func_inst != NULL);
    ASSERT_TRUE(((WASMFunctionInstance *)func_inst)->is_import_func);
    ASSERT_TRUE(((WASMFunctionInstance *)func_inst)->param_cell_num == 0);
    ASSERT_TRUE(((WASMFunctionInstance *)func_inst)->ret_cell_num == 1);

    wasm_runtime_call_wasm(exec_env, func_inst, 0, argv);
    printf("exception is %s\n", wasm_runtime_get_exception(module_inst));

    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);
    ASSERT_TRUE(argv[0] == 1);

    printf("------------------- f2 ---------------------\n");
    func_inst = wasm_runtime_lookup_function(module_inst, "f2");
    ASSERT_TRUE(func_inst != NULL);
    ASSERT_FALSE(((WASMFunctionInstance *)func_inst)->is_import_func);
    ASSERT_TRUE(((WASMFunctionInstance *)func_inst)->param_cell_num == 1);
    ASSERT_TRUE(((WASMFunctionInstance *)func_inst)->ret_cell_num == 1);

    argv[0] = 2;
    wasm_runtime_call_wasm(exec_env, func_inst, 1, argv);
    printf("exception is %s\n", wasm_runtime_get_exception(module_inst));

    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);
    ASSERT_TRUE(argv[0] == 3);

    printf("------------------- f3 ---------------------\n");
    func_inst = wasm_runtime_lookup_function(module_inst, "f3");
    ASSERT_TRUE(func_inst != NULL);
    ASSERT_FALSE(((WASMFunctionInstance *)func_inst)->is_import_func);
    ASSERT_TRUE(((WASMFunctionInstance *)func_inst)->param_cell_num == 2);
    ASSERT_TRUE(((WASMFunctionInstance *)func_inst)->ret_cell_num == 1);

    argv[0] = 4;
    argv[1] = 9;
    wasm_runtime_call_wasm(exec_env, func_inst, 2, argv);
    printf("exception is %s\n", wasm_runtime_get_exception(module_inst));

    ASSERT_TRUE(wasm_runtime_get_exception(module_inst) == NULL);
    ASSERT_TRUE(argv[0] == 9);

    wasm_runtime_destroy_exec_env(exec_env);
    wasm_runtime_deinstantiate(module_inst);

    wasm_runtime_unload(module);
    ASSERT_FALSE(call_destroyer);
}

TEST_F(WasmVMTest, Test_app4_family)
{
    uint8 *buffer = NULL;
    uint32 buffer_size = 0;
    bool ret = false;

    wasm_runtime_set_module_reader(&module_reader_callback,
                                   &module_destroyer_callback);

    /* m3 -> m2[->m1], m1 */
    ret = module_reader_callback(Wasm_Module_Bytecode, "m3", &buffer,
                                 &buffer_size);
    ASSERT_TRUE(ret);
    ASSERT_TRUE(buffer_size > 0);
    ASSERT_TRUE(buffer != NULL);
    module =
        wasm_runtime_load(buffer, buffer_size, error_buf, sizeof(error_buf));
    ASSERT_TRUE(module != NULL);

    wasm_runtime_unload(module);
    ASSERT_FALSE(call_destroyer);
}

static const WASMModule *
search_sub_module(const WASMModule *parent_module, const char *sub_module_name)
{
    WASMRegisteredModule *node = (WASMRegisteredModule *)bh_list_first_elem(
        parent_module->import_module_list);
    while (node && strcmp(node->module_name, sub_module_name)) {
        node = (WASMRegisteredModule *)bh_list_elem_next(node);
    }
    return node ? (WASMModule *)node->module : NULL;
}

TEST_F(WasmVMTest, Test_app4_reuse)
{
    uint8 *buffer = NULL;
    uint32 buffer_size = 0;
    bool ret = false;

    wasm_runtime_set_module_reader(&module_reader_callback,
                                   &module_destroyer_callback);

    /* m3 -> m2[->m1], m1 */
    ret = module_reader_callback(Wasm_Module_Bytecode, "m3", &buffer,
                                 &buffer_size);
    ASSERT_TRUE(buffer != NULL);

    WASMModule *m3 = (WASMModule *)wasm_runtime_load(
        buffer, buffer_size, error_buf, sizeof(error_buf));
    ASSERT_TRUE(m3 != NULL);

    const WASMModule *m2 = search_sub_module(m3, "m2");
    const WASMModule *m1_in_m2 = search_sub_module(m2, "m1");
    const WASMModule *m1_in_m3 = search_sub_module(m3, "m1");
    ASSERT_EQ(m1_in_m2, m1_in_m3);
}
#endif /* WASM_ENABLE_MULTI_MODULE */
