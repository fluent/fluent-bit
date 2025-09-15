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

using namespace std;

extern "C" {
uint32
wasm_runtime_module_realloc(WASMModuleInstanceCommon *module_inst, uint32 ptr,
                            uint32 size, void **p_native_addr);
bool
wasm_runtime_create_exec_env_and_call_wasm(
    WASMModuleInstanceCommon *module_inst, WASMFunctionInstanceCommon *function,
    uint32 argc, uint32 argv[]);
}

static bh_list loading_module_list_head;
static bh_list *const loading_module_list = &loading_module_list_head;
static korp_mutex loading_module_list_lock;

static std::string CWD;
static std::string MAIN_WASM = "/main.wasm";
static std::string MAIN_AOT = "/main.aot";
static char *WASM_FILE_1;
static char *AOT_FILE_1;

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

class wasm_runtime_common_test_suite : public testing::Test
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
        WASM_FILE_1 = strdup((CWD + MAIN_WASM).c_str());
        AOT_FILE_1 = strdup((CWD + MAIN_AOT).c_str());
    }

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    virtual void TearDown() {}

    static void TearDownTestCase()
    {
        free(WASM_FILE_1);
        free(AOT_FILE_1);
    }

    WAMRRuntimeRAII<512 * 1024> runtime;
};

TEST_F(wasm_runtime_common_test_suite, wasm_runtime_destroy)
{
    wasm_runtime_init();
    wasm_runtime_destroy();
}

static bool
reader_test(package_type_t module_type, const char *module_name,
            uint8 **p_buffer, uint32 *p_size)
{
    return true;
}

static void
destroyer_test(uint8 *buffer, uint32 size)
{}

TEST_F(wasm_runtime_common_test_suite,
       set_module_reader_get_module_reader_get_module_destroyer)
{
    wasm_runtime_set_module_reader(reader_test, destroyer_test);
    EXPECT_EQ((module_reader)reader_test, wasm_runtime_get_module_reader());
    EXPECT_EQ((module_destroyer)destroyer_test,
              wasm_runtime_get_module_destroyer());
}

TEST_F(wasm_runtime_common_test_suite, wasm_runtime_register_module)
{
    const char *wasm_file = WASM_FILE_1;
    wasm_module_t wasm_module = nullptr;
    unsigned char *wasm_file_buf = nullptr;
    unsigned int wasm_file_size = 0;
    char error_buf[128] = { 0 };
    char module_name[] = "module_test";
    char module_name_1[] = "module_test_1";

    // Normal situation.
    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
    EXPECT_NE(wasm_file_buf, nullptr);
    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    EXPECT_NE(wasm_module, nullptr);
    EXPECT_NE(false,
              wasm_runtime_register_module("module_test", wasm_module,
                                           error_buf, sizeof(error_buf)));

    // Abnormal situation.
    EXPECT_EQ(false,
              wasm_runtime_register_module(nullptr, nullptr, nullptr, 0));
    EXPECT_EQ(false, wasm_runtime_register_module(
                         "module_test", nullptr, error_buf, sizeof(error_buf)));
    EXPECT_EQ(false, wasm_runtime_register_module("module_test", wasm_module,
                                                  nullptr, sizeof(error_buf)));
    EXPECT_EQ(false, wasm_runtime_register_module("module_test", wasm_module,
                                                  error_buf, 0));
    EXPECT_EQ(false, wasm_runtime_register_module(
                         nullptr, wasm_module, error_buf, sizeof(error_buf)));
    EXPECT_EQ(false, wasm_runtime_register_module(nullptr, nullptr, error_buf,
                                                  sizeof(error_buf)));

    EXPECT_EQ(true, wasm_runtime_register_module(module_name, wasm_module,
                                                 error_buf, sizeof(error_buf)));
    EXPECT_EQ(false, wasm_runtime_register_module_internal(nullptr, wasm_module,
                                                           NULL, 0, error_buf,
                                                           sizeof(error_buf)));
    EXPECT_EQ(false, wasm_runtime_register_module_internal(
                         module_name_1, wasm_module, NULL, 0, error_buf,
                         sizeof(error_buf)));
}

TEST_F(wasm_runtime_common_test_suite, wasm_runtime_unregister_module)
{
    wasm_runtime_unregister_module(nullptr);
}

TEST_F(wasm_runtime_common_test_suite, wasm_runtime_find_module_registered)
{
    EXPECT_EQ(nullptr, wasm_runtime_find_module_registered("module_test"));
}

TEST_F(wasm_runtime_common_test_suite, wasm_runtime_is_module_registered)
{
    EXPECT_EQ(nullptr, wasm_runtime_find_module_registered(""));
}

/* TODO: add thread safety test. */
TEST_F(wasm_runtime_common_test_suite, wasm_runtime_add_loading_module)
{
    EXPECT_EQ(true, wasm_runtime_add_loading_module(nullptr, nullptr, 0));
}

TEST_F(wasm_runtime_common_test_suite, wasm_runtime_destroy_loading_module_list)
{
    os_mutex_init(&loading_module_list_lock);
    wasm_runtime_destroy_loading_module_list();
    os_mutex_destroy(&loading_module_list_lock);
}

TEST_F(wasm_runtime_common_test_suite, wasm_runtime_is_built_in_module)
{
    EXPECT_EQ(true, wasm_runtime_is_built_in_module("env"));
    EXPECT_EQ(true, wasm_runtime_is_built_in_module("wasi_unstable"));
    EXPECT_EQ(true, wasm_runtime_is_built_in_module("wasi_snapshot_preview1"));
    EXPECT_EQ(true, wasm_runtime_is_built_in_module(""));
    EXPECT_EQ(false, wasm_runtime_is_built_in_module("test"));
}

TEST_F(wasm_runtime_common_test_suite, wasm_runtime_read_v128)
{
    unsigned char buf[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    unsigned char ret1[8] = { 0 };
    unsigned char ret2[8] = { 0 };

    wasm_runtime_read_v128((const uint8 *)buf, (uint64 *)ret1, (uint64 *)ret2);
    EXPECT_EQ(0, strncmp("01234567", (const char *)ret1, 8));
    EXPECT_EQ(0, strncmp("89ABCDEF", (const char *)ret2, 8));
}

TEST_F(wasm_runtime_common_test_suite,
       wasm_runtime_show_app_heap_corrupted_prompt)
{
    wasm_runtime_show_app_heap_corrupted_prompt();
}

TEST_F(wasm_runtime_common_test_suite, wasm_runtime_is_xip_file)
{
    // WASM file.
    const char *wasm_file = WASM_FILE_1;
    unsigned int wasm_file_size = 0;
    unsigned char *wasm_file_buf = nullptr;

    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
    EXPECT_NE(wasm_file_buf, nullptr);
    EXPECT_EQ(false, wasm_runtime_is_xip_file(wasm_file_buf, wasm_file_size));

    // AoT file.
    const char *aot_file = AOT_FILE_1;
    unsigned int aot_file_size = 0;
    unsigned char *aot_file_buf = nullptr;

    aot_file_buf =
        (unsigned char *)bh_read_file_to_buffer(aot_file, &aot_file_size);
    EXPECT_NE(aot_file_buf, nullptr);
    EXPECT_EQ(false, wasm_runtime_is_xip_file(aot_file_buf, aot_file_size));
}

TEST_F(wasm_runtime_common_test_suite, get_package_type)
{
    const char *wasm_file = WASM_FILE_1;
    unsigned int wasm_file_size = 0;
    unsigned char *wasm_file_buf = nullptr;

    // WASM file.
    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
    EXPECT_NE(wasm_file_buf, nullptr);
    EXPECT_EQ(Wasm_Module_Bytecode,
              get_package_type(wasm_file_buf, wasm_file_size));

    // WASM file. Abnormally.
    wasm_file_buf[3] = -1;
    EXPECT_EQ(Package_Type_Unknown,
              get_package_type(wasm_file_buf, wasm_file_size));
    wasm_file_buf[2] = -1;
    EXPECT_EQ(Package_Type_Unknown,
              get_package_type(wasm_file_buf, wasm_file_size));
    wasm_file_buf[1] = -1;
    EXPECT_EQ(Package_Type_Unknown,
              get_package_type(wasm_file_buf, wasm_file_size));
    wasm_file_buf[0] = -1;
    EXPECT_EQ(Package_Type_Unknown,
              get_package_type(wasm_file_buf, wasm_file_size));

    EXPECT_EQ(Package_Type_Unknown, get_package_type(wasm_file_buf, 0));
    EXPECT_EQ(Package_Type_Unknown, get_package_type(nullptr, 0));

    // AoT file.
    const char *wasm_file_aot = AOT_FILE_1;
    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file_aot, &wasm_file_size);
    EXPECT_NE(wasm_file_buf, nullptr);
    EXPECT_EQ(Wasm_Module_AoT, get_package_type(wasm_file_buf, wasm_file_size));

    // AoT file. Abnormally.
    wasm_file_buf[3] = -1;
    EXPECT_EQ(Package_Type_Unknown,
              get_package_type(wasm_file_buf, wasm_file_size));
    wasm_file_buf[2] = -1;
    EXPECT_EQ(Package_Type_Unknown,
              get_package_type(wasm_file_buf, wasm_file_size));
    wasm_file_buf[1] = -1;
    EXPECT_EQ(Package_Type_Unknown,
              get_package_type(wasm_file_buf, wasm_file_size));
    wasm_file_buf[0] = -1;
    EXPECT_EQ(Package_Type_Unknown,
              get_package_type(wasm_file_buf, wasm_file_size));

    EXPECT_EQ(Package_Type_Unknown, get_package_type(wasm_file_buf, 0));
    EXPECT_EQ(Package_Type_Unknown, get_package_type(nullptr, 0));
}

TEST_F(wasm_runtime_common_test_suite, functions_on_wasm_module)
{
    const char *wasm_file = WASM_FILE_1;
    wasm_module_inst_t wasm_module_inst = nullptr;
    wasm_module_t wasm_module = nullptr;
    wasm_exec_env_t exec_env = nullptr;
    wasm_exec_env_t exec_env_1 = nullptr;
    unsigned char *wasm_file_buf = nullptr;
    WASMFunctionInstanceCommon *func = nullptr;
    const char *user_data = "test";
    unsigned int wasm_file_size = 0;
    unsigned int stack_size = 16 * 1024, heap_size = 16 * 1024;
    char error_buf[128] = { 0 };
    unsigned int argv[2] = { 0 };
    WASMType *func_type = nullptr;
    wasm_val_t arguments[1];
    char str_test[] = "This is a test.";
    char str_exception[] = "Exception: ";
    char str_tmp[60] = { 0 };
    void *ptr_tmp = nullptr;
    unsigned int offset_tmp = 0;
    unsigned int tmp = 0;
    unsigned char *p_native_start_addr = nullptr;
    unsigned char *p_native_end_addr = nullptr;
    NativeSymbol *native_symbols;
    uint32 n_native_symbols;
    const char *exception_test = nullptr;

    arguments[0].kind = WASM_I32;
    arguments[0].of.i32 = 0;

    // Create exec_env.
    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
    EXPECT_NE(wasm_file_buf, nullptr);
    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    EXPECT_NE(wasm_module, nullptr);
    wasm_module_inst = wasm_runtime_instantiate(
        wasm_module, stack_size, heap_size, error_buf, sizeof(error_buf));
    EXPECT_NE(wasm_module_inst, nullptr);
    exec_env = wasm_runtime_create_exec_env(wasm_module_inst, stack_size);
    EXPECT_NE(exec_env, nullptr);

    // Operations on exec_env.
    EXPECT_EQ(true, wasm_runtime_register_module_internal("test", wasm_module,
                                                          nullptr, 0, error_buf,
                                                          sizeof(error_buf)));
    EXPECT_NE(nullptr, wasm_runtime_find_module_registered("test"));
    EXPECT_EQ(wasm_module_inst, wasm_runtime_get_module_inst(exec_env));
    EXPECT_EQ(exec_env->attachment,
              wasm_runtime_get_function_attachment(exec_env));
    EXPECT_EQ(wasm_module, wasm_exec_env_get_module(exec_env));

    wasm_runtime_set_user_data(exec_env, (void *)user_data);
    EXPECT_EQ((void *)user_data, wasm_runtime_get_user_data(exec_env));

    func = wasm_runtime_lookup_function(wasm_module_inst, "on_timer_event");
    func_type =
        wasm_runtime_get_function_type(func, wasm_module_inst->module_type);
    EXPECT_NE(func_type, nullptr);
    EXPECT_EQ(false, wasm_runtime_call_wasm(exec_env, func, 0, argv));
    exception_test = wasm_runtime_get_exception(wasm_module_inst);
    EXPECT_NE(nullptr, exception_test);

    EXPECT_EQ(false, wasm_runtime_call_wasm_a(exec_env, func, 0, nullptr, 1,
                                              arguments));
    exception_test = wasm_runtime_get_exception(wasm_module_inst);
    EXPECT_NE(nullptr, exception_test);

    WASMFunctionInstance func_test_1;
    WASMFunction wasm_func_test;
    WASMType wasm_type_test;
    wasm_func_test.func_type = &wasm_type_test;
    func_test_1.u.func = &wasm_func_test;
    func_test_1.u.func->func_type->param_count = 1;
    func_test_1.u.func->func_type->param_cell_num = 2;
    func_test_1.u.func->func_type->types[0] = VALUE_TYPE_I64;
    func_test_1.u.func->max_stack_cell_num = 10;
    EXPECT_EQ(false, wasm_runtime_call_wasm_v(
                         exec_env, (WASMFunctionInstanceCommon *)(&func_test_1),
                         0, nullptr, 1, arguments));
    func_test_1.u.func->func_type->types[0] = VALUE_TYPE_F32;
    EXPECT_EQ(false, wasm_runtime_call_wasm_v(
                         exec_env, (WASMFunctionInstanceCommon *)(&func_test_1),
                         0, nullptr, 1, arguments));
    func_test_1.u.func->func_type->types[0] = VALUE_TYPE_F64;
    EXPECT_EQ(false, wasm_runtime_call_wasm_v(
                         exec_env, (WASMFunctionInstanceCommon *)(&func_test_1),
                         0, nullptr, 1, arguments));

#if 0
    WASMFunctionInstance func_test;
    WASMFunctionImport func_import_test;
    WASMType *func_type_1 = nullptr;
    func_import_test.func_type = func_type;
    func_test.u.func_import = &func_import_test;
    func_test.is_import_func = true;
    func_type_1 = wasm_runtime_get_function_type(&func_test,
                                                 wasm_module_inst->module_type);
    EXPECT_NE(func_type_1, nullptr);
#endif

    EXPECT_EQ(true, wasm_runtime_create_exec_env_singleton(wasm_module_inst));
    EXPECT_NE(nullptr, wasm_runtime_get_exec_env_singleton(wasm_module_inst));

    wasm_runtime_set_exception(wasm_module_inst, str_test);
    sprintf(str_tmp, "%s%s", str_exception, str_test);
    EXPECT_EQ(0, strcmp(str_tmp, wasm_runtime_get_exception(wasm_module_inst)));
    wasm_runtime_clear_exception(wasm_module_inst);
    EXPECT_EQ(nullptr, wasm_runtime_get_exception(wasm_module_inst));

    wasm_runtime_set_custom_data(wasm_module_inst, (void *)user_data);
    EXPECT_EQ((void *)user_data,
              wasm_runtime_get_custom_data(wasm_module_inst));

    offset_tmp = wasm_runtime_module_malloc(wasm_module_inst, 10, &ptr_tmp);
    EXPECT_NE(0, offset_tmp);
    EXPECT_EQ(true,
              wasm_runtime_validate_app_addr(wasm_module_inst, offset_tmp, 10));
    EXPECT_EQ(ptr_tmp,
              wasm_runtime_addr_app_to_native(wasm_module_inst, offset_tmp));
    EXPECT_EQ(true,
              wasm_runtime_validate_native_addr(wasm_module_inst, ptr_tmp, 10));
    EXPECT_EQ(offset_tmp,
              wasm_runtime_addr_native_to_app(wasm_module_inst, ptr_tmp));
    EXPECT_EQ(true, wasm_runtime_get_native_addr_range(
                        wasm_module_inst, (unsigned char *)ptr_tmp,
                        &p_native_start_addr, &p_native_end_addr));
    EXPECT_NE(0, wasm_runtime_module_realloc(wasm_module_inst, offset_tmp, 100,
                                             &ptr_tmp));
    /* can't test like that since shrink size optimization will be applied */
    /* EXPECT_EQ(false,
              wasm_enlarge_memory((WASMModuleInstance *)wasm_module_inst, 1));
     */
    EXPECT_EQ(offset_tmp,
              wasm_runtime_addr_native_to_app(wasm_module_inst, ptr_tmp));
    EXPECT_EQ(true, wasm_runtime_get_native_addr_range(
                        wasm_module_inst, (unsigned char *)ptr_tmp,
                        &p_native_start_addr, &p_native_end_addr));

    offset_tmp = wasm_runtime_module_dup_data(wasm_module_inst, str_test,
                                              sizeof(str_test));
    EXPECT_EQ(0, strcmp(str_test, (char *)wasm_runtime_addr_app_to_native(
                                      wasm_module_inst, offset_tmp)));
    EXPECT_EQ(true,
              wasm_runtime_validate_app_str_addr(wasm_module_inst, offset_tmp));

    ((WASMModuleInstance *)wasm_module_inst)->exec_env_singleton = nullptr;
    EXPECT_NE(nullptr, wasm_runtime_get_exec_env_singleton(wasm_module_inst));

    EXPECT_EQ(false, wasm_runtime_call_wasm(nullptr, func, 0, argv));
    wasm_runtime_set_exception(wasm_module_inst, str_test);
    EXPECT_EQ(false, wasm_runtime_call_wasm(exec_env, func, 0, argv));
    wasm_runtime_clear_exception(wasm_module_inst);

    EXPECT_EQ(false, wasm_runtime_call_wasm_a(exec_env, func, 0, nullptr, 2,
                                              arguments));
    WASMFunctionInstance *func_test_call_wasm_a_ptr =
        (WASMFunctionInstance *)func;
    func_test_call_wasm_a_ptr->u.func->func_type->ret_cell_num = 10;
    EXPECT_EQ(true, wasm_runtime_call_wasm_a(exec_env, func, 0, nullptr, 1,
                                             arguments));

    // Destroy.
    wasm_runtime_module_free(wasm_module_inst, offset_tmp);
    wasm_runtime_destroy_exec_env(exec_env);
    wasm_runtime_deinstantiate(wasm_module_inst);
    wasm_runtime_unload(wasm_module);
    if (wasm_file_buf) {
        wasm_runtime_free(wasm_file_buf);
    }
}

TEST_F(wasm_runtime_common_test_suite, functions_on_aot_module)
{
    const char *wasm_file = AOT_FILE_1;
    wasm_module_inst_t wasm_module_inst = nullptr;
    wasm_module_t wasm_module = nullptr;
    wasm_exec_env_t exec_env = nullptr;
    wasm_exec_env_t exec_env_1 = nullptr;
    unsigned char *wasm_file_buf = nullptr;
    WASMFunctionInstanceCommon *func = nullptr;
    const char *user_data = "test";
    unsigned int wasm_file_size = 0;
    unsigned int stack_size = 16 * 1024, heap_size = 16 * 1024;
    char error_buf[128] = { 0 };
    unsigned int argv[2] = { 0 };
    WASMType *func_type = nullptr;
    wasm_val_t arguments[1];
    char str_test[] = "This is a test.";
    char str_exception[] = "Exception: ";
    char str_tmp[60] = { 0 };
    void *ptr_tmp = nullptr;
    unsigned int offset_tmp = 0;
    unsigned int tmp = 0;
    unsigned char *p_native_start_addr = nullptr;
    unsigned char *p_native_end_addr = nullptr;
    NativeSymbol *native_symbols;
    uint32 n_native_symbols;
    const char *exception_test = nullptr;

    arguments[0].kind = WASM_I32;
    arguments[0].of.i32 = 0;

    // Create exec_env.
    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
    EXPECT_NE(wasm_file_buf, nullptr);
    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    EXPECT_NE(wasm_module, nullptr);
    wasm_module_inst = wasm_runtime_instantiate(
        wasm_module, stack_size, heap_size, error_buf, sizeof(error_buf));
    EXPECT_NE(wasm_module_inst, nullptr);
    exec_env = wasm_runtime_create_exec_env(wasm_module_inst, stack_size);
    EXPECT_NE(exec_env, nullptr);

    // Operations on exec_env.
    EXPECT_EQ(true, wasm_runtime_register_module_internal("test", wasm_module,
                                                          nullptr, 0, error_buf,
                                                          sizeof(error_buf)));
    EXPECT_NE(nullptr, wasm_runtime_find_module_registered("test"));
    EXPECT_EQ(wasm_module_inst, wasm_runtime_get_module_inst(exec_env));
    EXPECT_EQ(exec_env->attachment,
              wasm_runtime_get_function_attachment(exec_env));
    EXPECT_EQ(wasm_module, wasm_exec_env_get_module(exec_env));

    wasm_runtime_set_user_data(exec_env, (void *)user_data);
    EXPECT_EQ((void *)user_data, wasm_runtime_get_user_data(exec_env));

    func = wasm_runtime_lookup_function(wasm_module_inst, "on_timer_event");
    func_type =
        wasm_runtime_get_function_type(func, wasm_module_inst->module_type);
    EXPECT_NE(func_type, nullptr);

    EXPECT_EQ(false, wasm_runtime_call_wasm(exec_env, func, 0, argv));
    exception_test = wasm_runtime_get_exception(wasm_module_inst);
    EXPECT_NE(nullptr, exception_test);

    EXPECT_EQ(false, wasm_runtime_call_wasm_a(exec_env, func, 0, nullptr, 1,
                                              arguments));
    exception_test = wasm_runtime_get_exception(wasm_module_inst);
    EXPECT_NE(nullptr, exception_test);
    EXPECT_EQ(false, wasm_runtime_call_wasm_v(exec_env, func, 0, nullptr, 1,
                                              arguments));
    exception_test = wasm_runtime_get_exception(wasm_module_inst);
    EXPECT_NE(nullptr, exception_test);

    AOTFunctionInstance func_test;
    AOTImportFunc func_import_test;
    func_test.u.func_import = &func_import_test;
    func_import_test.func_type = (AOTFuncType *)func_type;
    func_test.is_import_func = true;
    EXPECT_NE(nullptr, wasm_runtime_get_function_type(
                           &func_test, wasm_module_inst->module_type));

    EXPECT_EQ(true, wasm_runtime_create_exec_env_singleton(wasm_module_inst));
    EXPECT_NE(nullptr, wasm_runtime_get_exec_env_singleton(wasm_module_inst));

    wasm_runtime_set_exception(wasm_module_inst, str_test);
    sprintf(str_tmp, "%s%s", str_exception, str_test);
    EXPECT_EQ(0, strcmp(str_tmp, wasm_runtime_get_exception(wasm_module_inst)));
    wasm_runtime_clear_exception(wasm_module_inst);
    EXPECT_EQ(nullptr, wasm_runtime_get_exception(wasm_module_inst));

    wasm_runtime_set_custom_data(wasm_module_inst, (void *)user_data);
    EXPECT_EQ((void *)user_data,
              wasm_runtime_get_custom_data(wasm_module_inst));

    offset_tmp = wasm_runtime_module_malloc(wasm_module_inst, 10, &ptr_tmp);
    EXPECT_NE(0, offset_tmp);
    EXPECT_EQ(true,
              wasm_runtime_validate_app_addr(wasm_module_inst, offset_tmp, 10));
    EXPECT_EQ(ptr_tmp,
              wasm_runtime_addr_app_to_native(wasm_module_inst, offset_tmp));
    EXPECT_EQ(true,
              wasm_runtime_validate_native_addr(wasm_module_inst, ptr_tmp, 10));
    EXPECT_EQ(offset_tmp,
              wasm_runtime_addr_native_to_app(wasm_module_inst, ptr_tmp));
    EXPECT_EQ(true, wasm_runtime_get_native_addr_range(
                        wasm_module_inst, (unsigned char *)ptr_tmp,
                        &p_native_start_addr, &p_native_end_addr));
    EXPECT_NE(0, wasm_runtime_module_realloc(wasm_module_inst, offset_tmp, 100,
                                             &ptr_tmp));

    /* can't test like that since shrink size optimization will be applied */
    /* EXPECT_EQ(false,
              wasm_enlarge_memory((WASMModuleInstance *)wasm_module_inst, 1));
     */

    offset_tmp = wasm_runtime_module_dup_data(wasm_module_inst, str_test,
                                              sizeof(str_test));
    EXPECT_EQ(0, strcmp(str_test, (char *)wasm_runtime_addr_app_to_native(
                                      wasm_module_inst, offset_tmp)));
    EXPECT_EQ(true,
              wasm_runtime_validate_app_str_addr(wasm_module_inst, offset_tmp));

    ((WASMModuleInstance *)wasm_module_inst)->exec_env_singleton = nullptr;
    EXPECT_NE(nullptr, wasm_runtime_get_exec_env_singleton(wasm_module_inst));

    // Destroy.
    wasm_runtime_module_free(wasm_module_inst, offset_tmp);
    wasm_runtime_destroy_exec_env(exec_env);
    wasm_runtime_deinstantiate(wasm_module_inst);
    wasm_runtime_unload(wasm_module);
    if (wasm_file_buf) {
        wasm_runtime_free(wasm_file_buf);
    }
}

TEST_F(wasm_runtime_common_test_suite, functions_on_module_type_unknown)
{
    const char *wasm_file = AOT_FILE_1;
    wasm_module_inst_t wasm_module_inst = nullptr;
    wasm_module_t wasm_module = nullptr;
    wasm_exec_env_t exec_env = nullptr;
    wasm_exec_env_t exec_env_1 = nullptr;
    unsigned char *wasm_file_buf = nullptr;
    WASMFunctionInstanceCommon *func = nullptr;
    const char *user_data = "test";
    unsigned int wasm_file_size = 0;
    unsigned int stack_size = 16 * 1024, heap_size = 16 * 1024;
    char error_buf[128] = { 0 };
    unsigned int argv[2] = { 0 };
    WASMType *func_type = nullptr;
    wasm_val_t arguments[1];
    char str_test[] = "This is a test.";
    char str_exception[] = "Exception: ";
    char str_tmp[60] = { 0 };
    void *ptr_tmp = nullptr;
    unsigned int offset_tmp = 0;
    unsigned int tmp = 0;
    unsigned char *p_native_start_addr = nullptr;
    unsigned char *p_native_end_addr = nullptr;
    const char *exception_test = nullptr;

    arguments[0].kind = WASM_I32;
    arguments[0].of.i32 = 0;

    // Create exec_env.
    wasm_runtime_unregister_module(wasm_module);
    wasm_file_buf =
        (unsigned char *)bh_read_file_to_buffer(wasm_file, &wasm_file_size);
    EXPECT_NE(wasm_file_buf, nullptr);
    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    EXPECT_NE(wasm_module, nullptr);
    wasm_module_inst = wasm_runtime_instantiate(
        wasm_module, stack_size, heap_size, error_buf, sizeof(error_buf));
    EXPECT_NE(wasm_module_inst, nullptr);
    exec_env = wasm_runtime_create_exec_env(wasm_module_inst, stack_size);
    EXPECT_NE(exec_env, nullptr);

    // wasm_module_inst->module_type = Package_Type_Unknown.
    wasm_module_inst->module_type = Package_Type_Unknown;
    EXPECT_DEATH(wasm_exec_env_get_module(exec_env), "");
    EXPECT_DEATH(
        wasm_runtime_validate_app_str_addr(wasm_module_inst, offset_tmp), "");

    // wasm_module->module_type = Package_Type_Unknown.
    wasm_module->module_type = Package_Type_Unknown;
    EXPECT_EQ(nullptr,
              wasm_runtime_instantiate(wasm_module, stack_size, heap_size,
                                       error_buf, sizeof(error_buf)));

    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    /* Reload unmodified buffer should be valid now */
    EXPECT_NE(wasm_module, nullptr);
    wasm_file_buf[3] = -1;
    wasm_file_buf[2] = -1;
    wasm_file_buf[1] = -1;
    wasm_file_buf[0] = -1;
    wasm_module =
        wasm_runtime_load(wasm_file_buf, 0, error_buf, sizeof(error_buf));
    EXPECT_EQ(wasm_module, nullptr);
    wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size, error_buf,
                                    sizeof(error_buf));
    EXPECT_EQ(wasm_module, nullptr);

    // Destroy.
    wasm_runtime_module_free(wasm_module_inst, offset_tmp);
    wasm_runtime_destroy_exec_env(exec_env);
    wasm_runtime_deinstantiate(wasm_module_inst);
    wasm_runtime_unload(wasm_module);
    if (wasm_file_buf) {
        wasm_runtime_free(wasm_file_buf);
    }
}
