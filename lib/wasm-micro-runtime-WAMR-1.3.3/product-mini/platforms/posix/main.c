/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bh_platform.h"
#include "bh_read_file.h"
#include "wasm_export.h"

#if WASM_ENABLE_LIBC_WASI != 0
#include "../common/libc_wasi.c"
#endif

#if BH_HAS_DLFCN
#include <dlfcn.h>
#endif

static int app_argc;
static char **app_argv;

/* clang-format off */
static int
print_help()
{
    printf("Usage: iwasm [-options] wasm_file [args...]\n");
    printf("options:\n");
    printf("  -f|--function name       Specify a function name of the module to run rather\n"
           "                           than main\n");
#if WASM_ENABLE_LOG != 0
    printf("  -v=n                     Set log verbose level (0 to 5, default is 2) larger\n"
           "                           level with more log\n");
#endif
#if WASM_ENABLE_INTERP != 0
    printf("  --interp                 Run the wasm app with interpreter mode\n");
#endif
#if WASM_ENABLE_FAST_JIT != 0
    printf("  --fast-jit               Run the wasm app with fast jit mode\n");
#endif
#if WASM_ENABLE_JIT != 0
    printf("  --llvm-jit               Run the wasm app with llvm jit mode\n");
#endif
#if WASM_ENABLE_JIT != 0 && WASM_ENABLE_FAST_JIT != 0 && WASM_ENABLE_LAZY_JIT != 0
    printf("  --multi-tier-jit         Run the wasm app with multi-tier jit mode\n");
#endif
    printf("  --stack-size=n           Set maximum stack size in bytes, default is 64 KB\n");
    printf("  --heap-size=n            Set maximum heap size in bytes, default is 16 KB\n");
#if WASM_ENABLE_FAST_JIT != 0
    printf("  --jit-codecache-size=n   Set fast jit maximum code cache size in bytes,\n");
    printf("                           default is %u KB\n", FAST_JIT_DEFAULT_CODE_CACHE_SIZE / 1024);
#endif
#if WASM_ENABLE_JIT != 0
    printf("  --llvm-jit-size-level=n  Set LLVM JIT size level, default is 3\n");
    printf("  --llvm-jit-opt-level=n   Set LLVM JIT optimization level, default is 3\n");
#if defined(os_writegsbase)
    printf("  --enable-segue[=<flags>] Enable using segment register GS as the base address of\n");
    printf("                           linear memory, which may improve performance, flags can be:\n");
    printf("                              i32.load, i64.load, f32.load, f64.load, v128.load,\n");
    printf("                              i32.store, i64.store, f32.store, f64.store, v128.store\n");
    printf("                           Use comma to separate, e.g. --enable-segue=i32.load,i64.store\n");
    printf("                           and --enable-segue means all flags are added.\n");
#endif
#endif /* WASM_ENABLE_JIT != 0*/
#if WASM_ENABLE_LINUX_PERF != 0
    printf("  --enable-linux-perf      Enable linux perf support. It works in aot and llvm-jit.\n");
#endif
    printf("  --repl                   Start a very simple REPL (read-eval-print-loop) mode\n"
           "                           that runs commands in the form of \"FUNC ARG...\"\n");
#if WASM_CONFIGURABLE_BOUNDS_CHECKS != 0
    printf("  --disable-bounds-checks  Disable bounds checks for memory accesses\n");
#endif
#if WASM_ENABLE_LIBC_WASI != 0
    libc_wasi_print_help();
#endif
#if BH_HAS_DLFCN
    printf("  --native-lib=<lib>       Register native libraries to the WASM module, which\n");
    printf("                           are shared object (.so) files, for example:\n");
    printf("                             --native-lib=test1.so --native-lib=test2.so\n");
#endif
#if WASM_ENABLE_MULTI_MODULE != 0
    printf("  --module-path=<path>     Indicate a module search path. default is current\n"
           "                           directory('./')\n");
#endif
#if WASM_ENABLE_LIB_PTHREAD != 0 || WASM_ENABLE_LIB_WASI_THREADS != 0
    printf("  --max-threads=n          Set maximum thread number per cluster, default is 4\n");
#endif
#if WASM_ENABLE_THREAD_MGR != 0
    printf("  --timeout=ms             Set the maximum execution time in ms.\n");
    printf("                           If it expires, the runtime aborts the execution\n");
    printf("                           with a trap.\n");
#endif
#if WASM_ENABLE_DEBUG_INTERP != 0
    printf("  -g=ip:port               Set the debug sever address, default is debug disabled\n");
    printf("                             if port is 0, then a random port will be used\n");
#endif
#if WASM_ENABLE_STATIC_PGO != 0
    printf("  --gen-prof-file=<path>   Generate LLVM PGO (Profile-Guided Optimization) profile file\n");
#endif
    printf("  --version                Show version information\n");
    return 1;
}
/* clang-format on */

static const void *
app_instance_main(wasm_module_inst_t module_inst)
{
    const char *exception;

    wasm_application_execute_main(module_inst, app_argc, app_argv);
    exception = wasm_runtime_get_exception(module_inst);
    return exception;
}

static const void *
app_instance_func(wasm_module_inst_t module_inst, const char *func_name)
{
    wasm_application_execute_func(module_inst, func_name, app_argc - 1,
                                  app_argv + 1);
    /* The result of wasm function or exception info was output inside
       wasm_application_execute_func(), here we don't output them again. */
    return wasm_runtime_get_exception(module_inst);
}

/**
 * Split a string into an array of strings
 * Returns NULL on failure
 * Memory must be freed by caller
 * Based on: http://stackoverflow.com/a/11198630/471795
 */
static char **
split_string(char *str, int *count, const char *delimer)
{
    char **res = NULL, **res1;
    char *p;
    int idx = 0;

    /* split string and append tokens to 'res' */
    do {
        p = strtok(str, delimer);
        str = NULL;
        res1 = res;
        res = (char **)realloc(res1, sizeof(char *) * (uint32)(idx + 1));
        if (res == NULL) {
            free(res1);
            return NULL;
        }
        res[idx++] = p;
    } while (p);

    /**
     * Due to the function name,
     * res[0] might contain a '\' to indicate a space
     * func\name -> func name
     */
    p = strchr(res[0], '\\');
    while (p) {
        *p = ' ';
        p = strchr(p, '\\');
    }

    if (count) {
        *count = idx - 1;
    }
    return res;
}

static void *
app_instance_repl(wasm_module_inst_t module_inst)
{
    char *cmd = NULL;
    size_t len = 0;
    ssize_t n;

    while ((printf("webassembly> "), fflush(stdout),
            n = getline(&cmd, &len, stdin))
           != -1) {
        bh_assert(n > 0);
        if (cmd[n - 1] == '\n') {
            if (n == 1)
                continue;
            else
                cmd[n - 1] = '\0';
        }
        if (!strcmp(cmd, "__exit__")) {
            printf("exit repl mode\n");
            break;
        }
        app_argv = split_string(cmd, &app_argc, " ");
        if (app_argv == NULL) {
            LOG_ERROR("Wasm prepare param failed: split string failed.\n");
            break;
        }
        if (app_argc != 0) {
            const char *exception;
            wasm_application_execute_func(module_inst, app_argv[0],
                                          app_argc - 1, app_argv + 1);
            if ((exception = wasm_runtime_get_exception(module_inst)))
                printf("%s\n", exception);
        }
        free(app_argv);
    }
    free(cmd);
    return NULL;
}

#if WASM_ENABLE_JIT != 0
static uint32
resolve_segue_flags(char *str_flags)
{
    uint32 segue_flags = 0;
    int32 flag_count, i;
    char **flag_list;

    flag_list = split_string(str_flags, &flag_count, ",");
    if (flag_list) {
        for (i = 0; i < flag_count; i++) {
            if (!strcmp(flag_list[i], "i32.load")) {
                segue_flags |= 1 << 0;
            }
            else if (!strcmp(flag_list[i], "i64.load")) {
                segue_flags |= 1 << 1;
            }
            else if (!strcmp(flag_list[i], "f32.load")) {
                segue_flags |= 1 << 2;
            }
            else if (!strcmp(flag_list[i], "f64.load")) {
                segue_flags |= 1 << 3;
            }
            else if (!strcmp(flag_list[i], "v128.load")) {
                segue_flags |= 1 << 4;
            }
            else if (!strcmp(flag_list[i], "i32.store")) {
                segue_flags |= 1 << 8;
            }
            else if (!strcmp(flag_list[i], "i64.store")) {
                segue_flags |= 1 << 9;
            }
            else if (!strcmp(flag_list[i], "f32.store")) {
                segue_flags |= 1 << 10;
            }
            else if (!strcmp(flag_list[i], "f64.store")) {
                segue_flags |= 1 << 11;
            }
            else if (!strcmp(flag_list[i], "v128.store")) {
                segue_flags |= 1 << 12;
            }
            else {
                /* invalid flag */
                segue_flags = (uint32)-1;
                break;
            }
        }
        free(flag_list);
    }
    return segue_flags;
}
#endif /* end of WASM_ENABLE_JIT != 0 */

#if BH_HAS_DLFCN
struct native_lib {
    void *handle;

    uint32 (*get_native_lib)(char **p_module_name,
                             NativeSymbol **p_native_symbols);
    int (*init_native_lib)(void);
    void (*deinit_native_lib)(void);

    char *module_name;
    NativeSymbol *native_symbols;
    uint32 n_native_symbols;
};

struct native_lib *
load_native_lib(const char *name)
{
    struct native_lib *lib = wasm_runtime_malloc(sizeof(*lib));
    if (lib == NULL) {
        LOG_WARNING("warning: failed to load native library %s because of "
                    "allocation failure",
                    name);
        goto fail;
    }
    memset(lib, 0, sizeof(*lib));

    /* open the native library */
    if (!(lib->handle = dlopen(name, RTLD_NOW | RTLD_GLOBAL))
        && !(lib->handle = dlopen(name, RTLD_LAZY))) {
        LOG_WARNING("warning: failed to load native library %s", name);
        goto fail;
    }

    lib->init_native_lib = dlsym(lib->handle, "init_native_lib");
    lib->get_native_lib = dlsym(lib->handle, "get_native_lib");
    lib->deinit_native_lib = dlsym(lib->handle, "deinit_native_lib");

    if (!lib->get_native_lib) {
        LOG_WARNING("warning: failed to lookup `get_native_lib` function "
                    "from native lib %s",
                    name);
        goto fail;
    }

    if (lib->init_native_lib) {
        int ret = lib->init_native_lib();
        if (ret != 0) {
            LOG_WARNING("warning: `init_native_lib` function from native "
                        "lib %s failed with %d",
                        name, ret);
            goto fail;
        }
    }

    lib->n_native_symbols =
        lib->get_native_lib(&lib->module_name, &lib->native_symbols);

    /* register native symbols */
    if (!(lib->n_native_symbols > 0 && lib->module_name && lib->native_symbols
          && wasm_runtime_register_natives(
              lib->module_name, lib->native_symbols, lib->n_native_symbols))) {
        LOG_WARNING("warning: failed to register native lib %s", name);
        if (lib->deinit_native_lib) {
            lib->deinit_native_lib();
        }
        goto fail;
    }
    return lib;
fail:
    if (lib != NULL) {
        if (lib->handle != NULL) {
            dlclose(lib->handle);
        }
        wasm_runtime_free(lib);
    }
    return NULL;
}

static uint32
load_and_register_native_libs(const char **native_lib_list,
                              uint32 native_lib_count,
                              struct native_lib **native_lib_loaded_list)
{
    uint32 i, native_lib_loaded_count = 0;

    for (i = 0; i < native_lib_count; i++) {
        struct native_lib *lib = load_native_lib(native_lib_list[i]);
        if (lib == NULL) {
            continue;
        }
        native_lib_loaded_list[native_lib_loaded_count++] = lib;
    }

    return native_lib_loaded_count;
}

static void
unregister_and_unload_native_libs(uint32 native_lib_count,
                                  struct native_lib **native_lib_loaded_list)
{
    uint32 i;

    for (i = 0; i < native_lib_count; i++) {
        struct native_lib *lib = native_lib_loaded_list[i];

        /* unregister native symbols */
        if (!wasm_runtime_unregister_natives(lib->module_name,
                                             lib->native_symbols)) {
            LOG_WARNING("warning: failed to unregister native lib %p",
                        lib->handle);
            continue;
        }

        if (lib->deinit_native_lib) {
            lib->deinit_native_lib();
        }

        dlclose(lib->handle);
        wasm_runtime_free(lib);
    }
}
#endif /* BH_HAS_DLFCN */

#if WASM_ENABLE_MULTI_MODULE != 0
static char *
handle_module_path(const char *module_path)
{
    /* next character after = */
    return (strchr(module_path, '=')) + 1;
}

static char *module_search_path = ".";

static bool
module_reader_callback(package_type_t module_type, const char *module_name,
                       uint8 **p_buffer, uint32 *p_size)
{
    char *file_format = NULL;
#if WASM_ENABLE_INTERP != 0
    if (module_type == Wasm_Module_Bytecode)
        file_format = ".wasm";
#endif
#if WASM_ENABLE_AOT != 0
    if (module_type == Wasm_Module_AoT)
        file_format = ".aot";
#endif
    bh_assert(file_format);
    const char *format = "%s/%s%s";
    int sz = strlen(module_search_path) + strlen("/") + strlen(module_name)
             + strlen(file_format) + 1;
    char *wasm_file_name = wasm_runtime_malloc(sz);
    if (!wasm_file_name) {
        return false;
    }
    snprintf(wasm_file_name, sz, format, module_search_path, module_name,
             file_format);
    *p_buffer = (uint8_t *)bh_read_file_to_buffer(wasm_file_name, p_size);

    wasm_runtime_free(wasm_file_name);
    return *p_buffer != NULL;
}

static void
moudle_destroyer(uint8 *buffer, uint32 size)
{
    if (!buffer) {
        return;
    }

    wasm_runtime_free(buffer);
    buffer = NULL;
}
#endif /* WASM_ENABLE_MULTI_MODULE */

#if WASM_ENABLE_GLOBAL_HEAP_POOL != 0
static char global_heap_buf[WASM_GLOBAL_HEAP_SIZE] = { 0 };
#else
static void *
malloc_func(
#if WASM_MEM_ALLOC_WITH_USER_DATA != 0
    void *user_data,
#endif
    unsigned int size)
{
    return malloc(size);
}

static void *
realloc_func(
#if WASM_MEM_ALLOC_WITH_USER_DATA != 0
    void *user_data,
#endif
    void *ptr, unsigned int size)
{
    return realloc(ptr, size);
}

static void
free_func(
#if WASM_MEM_ALLOC_WITH_USER_DATA != 0
    void *user_data,
#endif
    void *ptr)
{
    free(ptr);
}
#endif /* end of WASM_ENABLE_GLOBAL_HEAP_POOL */

#if WASM_ENABLE_STATIC_PGO != 0
static void
dump_pgo_prof_data(wasm_module_inst_t module_inst, const char *path)
{
    char *buf;
    uint32 len;
    FILE *file;

    if (!(len = wasm_runtime_get_pgo_prof_data_size(module_inst))) {
        printf("failed to get LLVM PGO profile data size\n");
        return;
    }

    if (!(buf = wasm_runtime_malloc(len))) {
        printf("allocate memory failed\n");
        return;
    }

    if (len != wasm_runtime_dump_pgo_prof_data_to_buf(module_inst, buf, len)) {
        printf("failed to dump LLVM PGO profile data\n");
        wasm_runtime_free(buf);
        return;
    }

    if (!(file = fopen(path, "wb"))) {
        printf("failed to create file %s", path);
        wasm_runtime_free(buf);
        return;
    }
    fwrite(buf, len, 1, file);
    fclose(file);

    wasm_runtime_free(buf);

    printf("LLVM raw profile file %s was generated.\n", path);
}
#endif

#if WASM_ENABLE_THREAD_MGR != 0
struct timeout_arg {
    uint32 timeout_ms;
    wasm_module_inst_t inst;
#if defined(BH_HAS_STD_ATOMIC)
    _Atomic
#endif
        bool cancel;
};

void *
timeout_thread(void *vp)
{
    const struct timeout_arg *arg = vp;
    uint32 left = arg->timeout_ms;
    while (!arg->cancel) {
        uint32 ms;
        if (left >= 100) {
            ms = 100;
        }
        else {
            ms = left;
        }
        os_usleep((uint64)ms * 1000);
        left -= ms;
        if (left == 0) {
            wasm_runtime_terminate(arg->inst);
            break;
        }
    }
    return NULL;
}
#endif

int
main(int argc, char *argv[])
{
    int32 ret = -1;
    char *wasm_file = NULL;
    const char *func_name = NULL;
    uint8 *wasm_file_buf = NULL;
    uint32 wasm_file_size;
    uint32 stack_size = 64 * 1024;
#if WASM_ENABLE_LIBC_WASI != 0
    uint32 heap_size = 0;
#else
    uint32 heap_size = 16 * 1024;
#endif
#if WASM_ENABLE_FAST_JIT != 0
    uint32 jit_code_cache_size = FAST_JIT_DEFAULT_CODE_CACHE_SIZE;
#endif
#if WASM_ENABLE_JIT != 0
    uint32 llvm_jit_size_level = 3;
    uint32 llvm_jit_opt_level = 3;
    uint32 segue_flags = 0;
#endif
#if WASM_ENABLE_LINUX_PERF != 0
    bool enable_linux_perf = false;
#endif
    wasm_module_t wasm_module = NULL;
    wasm_module_inst_t wasm_module_inst = NULL;
    RunningMode running_mode = 0;
    RuntimeInitArgs init_args;
    char error_buf[128] = { 0 };
#if WASM_ENABLE_LOG != 0
    int log_verbose_level = 2;
#endif
    bool is_repl_mode = false;
    bool is_xip_file = false;
#if WASM_CONFIGURABLE_BOUNDS_CHECKS != 0
    bool disable_bounds_checks = false;
#endif
#if WASM_ENABLE_LIBC_WASI != 0
    libc_wasi_parse_context_t wasi_parse_ctx;
#endif
#if BH_HAS_DLFCN
    const char *native_lib_list[8] = { NULL };
    uint32 native_lib_count = 0;
    struct native_lib *native_lib_loaded_list[8];
    uint32 native_lib_loaded_count = 0;
#endif
#if WASM_ENABLE_DEBUG_INTERP != 0
    char *ip_addr = NULL;
    int instance_port = 0;
#endif
#if WASM_ENABLE_STATIC_PGO != 0
    const char *gen_prof_file = NULL;
#endif
#if WASM_ENABLE_THREAD_MGR != 0
    int timeout_ms = -1;
#endif

#if WASM_ENABLE_LIBC_WASI != 0
    memset(&wasi_parse_ctx, 0, sizeof(wasi_parse_ctx));
#endif

    /* Process options. */
    for (argc--, argv++; argc > 0 && argv[0][0] == '-'; argc--, argv++) {
        if (!strcmp(argv[0], "-f") || !strcmp(argv[0], "--function")) {
            argc--, argv++;
            if (argc < 2) {
                return print_help();
            }
            func_name = argv[0];
        }
#if WASM_ENABLE_INTERP != 0
        else if (!strcmp(argv[0], "--interp")) {
            running_mode = Mode_Interp;
        }
#endif
#if WASM_ENABLE_FAST_JIT != 0
        else if (!strcmp(argv[0], "--fast-jit")) {
            running_mode = Mode_Fast_JIT;
        }
#endif
#if WASM_ENABLE_JIT != 0
        else if (!strcmp(argv[0], "--llvm-jit")) {
            running_mode = Mode_LLVM_JIT;
        }
#endif
#if WASM_ENABLE_JIT != 0 && WASM_ENABLE_FAST_JIT != 0 \
    && WASM_ENABLE_LAZY_JIT != 0
        else if (!strcmp(argv[0], "--multi-tier-jit")) {
            running_mode = Mode_Multi_Tier_JIT;
        }
#endif
#if WASM_ENABLE_LOG != 0
        else if (!strncmp(argv[0], "-v=", 3)) {
            log_verbose_level = atoi(argv[0] + 3);
            if (log_verbose_level < 0 || log_verbose_level > 5)
                return print_help();
        }
#endif
        else if (!strcmp(argv[0], "--repl")) {
            is_repl_mode = true;
        }
#if WASM_CONFIGURABLE_BOUNDS_CHECKS != 0
        else if (!strcmp(argv[0], "--disable-bounds-checks")) {
            disable_bounds_checks = true;
        }
#endif
        else if (!strncmp(argv[0], "--stack-size=", 13)) {
            if (argv[0][13] == '\0')
                return print_help();
            stack_size = atoi(argv[0] + 13);
        }
        else if (!strncmp(argv[0], "--heap-size=", 12)) {
            if (argv[0][12] == '\0')
                return print_help();
            heap_size = atoi(argv[0] + 12);
        }
#if WASM_ENABLE_FAST_JIT != 0
        else if (!strncmp(argv[0], "--jit-codecache-size=", 21)) {
            if (argv[0][21] == '\0')
                return print_help();
            jit_code_cache_size = atoi(argv[0] + 21);
        }
#endif
#if WASM_ENABLE_JIT != 0
        else if (!strncmp(argv[0], "--llvm-jit-size-level=", 22)) {
            if (argv[0][22] == '\0')
                return print_help();
            llvm_jit_size_level = atoi(argv[0] + 22);
            if (llvm_jit_size_level < 1) {
                printf("LLVM JIT size level shouldn't be smaller than 1, "
                       "setting it to 1\n");
                llvm_jit_size_level = 1;
            }
            else if (llvm_jit_size_level > 3) {
                printf("LLVM JIT size level shouldn't be greater than 3, "
                       "setting it to 3\n");
                llvm_jit_size_level = 3;
            }
        }
        else if (!strncmp(argv[0], "--llvm-jit-opt-level=", 21)) {
            if (argv[0][21] == '\0')
                return print_help();
            llvm_jit_opt_level = atoi(argv[0] + 21);
            if (llvm_jit_opt_level < 1) {
                printf("LLVM JIT opt level shouldn't be smaller than 1, "
                       "setting it to 1\n");
                llvm_jit_opt_level = 1;
            }
            else if (llvm_jit_opt_level > 3) {
                printf("LLVM JIT opt level shouldn't be greater than 3, "
                       "setting it to 3\n");
                llvm_jit_opt_level = 3;
            }
        }
        else if (!strcmp(argv[0], "--enable-segue")) {
            /* all flags are enabled */
            segue_flags = 0x1F1F;
        }
        else if (!strncmp(argv[0], "--enable-segue=", 15)) {
            segue_flags = resolve_segue_flags(argv[0] + 15);
            if (segue_flags == (uint32)-1)
                return print_help();
        }
#endif /* end of WASM_ENABLE_JIT != 0 */
#if BH_HAS_DLFCN
        else if (!strncmp(argv[0], "--native-lib=", 13)) {
            if (argv[0][13] == '\0')
                return print_help();
            if (native_lib_count >= sizeof(native_lib_list) / sizeof(char *)) {
                printf("Only allow max native lib number %d\n",
                       (int)(sizeof(native_lib_list) / sizeof(char *)));
                return 1;
            }
            native_lib_list[native_lib_count++] = argv[0] + 13;
        }
#endif
#if WASM_ENABLE_LINUX_PERF != 0
        else if (!strncmp(argv[0], "--enable-linux-perf", 19)) {
            enable_linux_perf = true;
        }
#endif
#if WASM_ENABLE_MULTI_MODULE != 0
        else if (!strncmp(argv[0],
                          "--module-path=", strlen("--module-path="))) {
            module_search_path = handle_module_path(argv[0]);
            if (!strlen(module_search_path)) {
                return print_help();
            }
        }
#endif
#if WASM_ENABLE_LIB_PTHREAD != 0 || WASM_ENABLE_LIB_WASI_THREADS != 0
        else if (!strncmp(argv[0], "--max-threads=", 14)) {
            if (argv[0][14] == '\0')
                return print_help();
            wasm_runtime_set_max_thread_num(atoi(argv[0] + 14));
        }
#endif
#if WASM_ENABLE_THREAD_MGR != 0
        else if (!strncmp(argv[0], "--timeout=", 10)) {
            if (argv[0][10] == '\0')
                return print_help();
            timeout_ms = atoi(argv[0] + 10);
        }
#endif
#if WASM_ENABLE_DEBUG_INTERP != 0
        else if (!strncmp(argv[0], "-g=", 3)) {
            char *port_str = strchr(argv[0] + 3, ':');
            char *port_end;
            if (port_str == NULL)
                return print_help();
            *port_str = '\0';
            instance_port = strtoul(port_str + 1, &port_end, 10);
            if (port_str[1] == '\0' || *port_end != '\0')
                return print_help();
            ip_addr = argv[0] + 3;
        }
#endif
#if WASM_ENABLE_STATIC_PGO != 0
        else if (!strncmp(argv[0], "--gen-prof-file=", 16)) {
            if (argv[0][16] == '\0')
                return print_help();
            gen_prof_file = argv[0] + 16;
        }
#endif
        else if (!strcmp(argv[0], "--version")) {
            uint32 major, minor, patch;
            wasm_runtime_get_version(&major, &minor, &patch);
            printf("iwasm %" PRIu32 ".%" PRIu32 ".%" PRIu32 "\n", major, minor,
                   patch);
            return 0;
        }
        else {
#if WASM_ENABLE_LIBC_WASI != 0
            libc_wasi_parse_result_t result =
                libc_wasi_parse(argv[0], &wasi_parse_ctx);
            switch (result) {
                case LIBC_WASI_PARSE_RESULT_OK:
                    continue;
                case LIBC_WASI_PARSE_RESULT_NEED_HELP:
                    return print_help();
                case LIBC_WASI_PARSE_RESULT_BAD_PARAM:
                    return 1;
            }
#else
            return print_help();
#endif
        }
    }

    if (argc == 0)
        return print_help();

    wasm_file = argv[0];
    app_argc = argc;
    app_argv = argv;

    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    init_args.running_mode = running_mode;
#if WASM_ENABLE_GLOBAL_HEAP_POOL != 0
    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);
#else
    init_args.mem_alloc_type = Alloc_With_Allocator;
#if WASM_MEM_ALLOC_WITH_USER_DATA != 0
    /* Set user data for the allocator is needed */
    /* init_args.mem_alloc_option.allocator.user_data = user_data; */
#endif
    init_args.mem_alloc_option.allocator.malloc_func = malloc_func;
    init_args.mem_alloc_option.allocator.realloc_func = realloc_func;
    init_args.mem_alloc_option.allocator.free_func = free_func;
#endif

#if WASM_ENABLE_FAST_JIT != 0
    init_args.fast_jit_code_cache_size = jit_code_cache_size;
#endif

#if WASM_ENABLE_JIT != 0
    init_args.llvm_jit_size_level = llvm_jit_size_level;
    init_args.llvm_jit_opt_level = llvm_jit_opt_level;
    init_args.segue_flags = segue_flags;
#endif
#if WASM_ENABLE_LINUX_PERF != 0
    init_args.enable_linux_perf = enable_linux_perf;
#endif

#if WASM_ENABLE_DEBUG_INTERP != 0
    init_args.instance_port = instance_port;
    if (ip_addr)
        /* ensure that init_args.ip_addr is null terminated */
        strncpy(init_args.ip_addr, ip_addr, sizeof(init_args.ip_addr) - 1);
#endif

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

#if WASM_ENABLE_LOG != 0
    bh_log_set_verbose_level(log_verbose_level);
#endif

#if BH_HAS_DLFCN
    native_lib_loaded_count = load_and_register_native_libs(
        native_lib_list, native_lib_count, native_lib_loaded_list);
#endif

    /* load WASM byte buffer from WASM bin file */
    if (!(wasm_file_buf =
              (uint8 *)bh_read_file_to_buffer(wasm_file, &wasm_file_size)))
        goto fail1;

#if WASM_ENABLE_AOT != 0
    if (wasm_runtime_is_xip_file(wasm_file_buf, wasm_file_size)) {
        uint8 *wasm_file_mapped;
        int map_prot = MMAP_PROT_READ | MMAP_PROT_WRITE | MMAP_PROT_EXEC;
        int map_flags = MMAP_MAP_32BIT;

        if (!(wasm_file_mapped = os_mmap(NULL, (uint32)wasm_file_size, map_prot,
                                         map_flags, os_get_invalid_handle()))) {
            printf("mmap memory failed\n");
            wasm_runtime_free(wasm_file_buf);
            goto fail1;
        }

        bh_memcpy_s(wasm_file_mapped, wasm_file_size, wasm_file_buf,
                    wasm_file_size);
        wasm_runtime_free(wasm_file_buf);
        wasm_file_buf = wasm_file_mapped;
        is_xip_file = true;
    }
#endif

#if WASM_ENABLE_MULTI_MODULE != 0
    wasm_runtime_set_module_reader(module_reader_callback, moudle_destroyer);
#endif

    /* load WASM module */
    if (!(wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size,
                                          error_buf, sizeof(error_buf)))) {
        printf("%s\n", error_buf);
        goto fail2;
    }

#if WASM_ENABLE_LIBC_WASI != 0
    libc_wasi_init(wasm_module, argc, argv, &wasi_parse_ctx);
#endif

    /* instantiate the module */
    if (!(wasm_module_inst =
              wasm_runtime_instantiate(wasm_module, stack_size, heap_size,
                                       error_buf, sizeof(error_buf)))) {
        printf("%s\n", error_buf);
        goto fail3;
    }

#if WASM_CONFIGURABLE_BOUNDS_CHECKS != 0
    if (disable_bounds_checks) {
        wasm_runtime_set_bounds_checks(wasm_module_inst, false);
    }
#endif

#if WASM_ENABLE_DEBUG_INTERP != 0
    if (ip_addr != NULL) {
        wasm_exec_env_t exec_env =
            wasm_runtime_get_exec_env_singleton(wasm_module_inst);
        uint32_t debug_port;
        if (exec_env == NULL) {
            printf("%s\n", wasm_runtime_get_exception(wasm_module_inst));
            goto fail4;
        }
        debug_port = wasm_runtime_start_debug_instance(exec_env);
        if (debug_port == 0) {
            printf("Failed to start debug instance\n");
            goto fail4;
        }
    }
#endif

#if WASM_ENABLE_THREAD_MGR != 0
    struct timeout_arg timeout_arg;
    korp_tid timeout_tid;
    if (timeout_ms >= 0) {
        timeout_arg.timeout_ms = timeout_ms;
        timeout_arg.inst = wasm_module_inst;
        timeout_arg.cancel = false;
        ret = os_thread_create(&timeout_tid, timeout_thread, &timeout_arg,
                               APP_THREAD_STACK_SIZE_DEFAULT);
        if (ret != 0) {
            printf("Failed to start timeout\n");
            goto fail5;
        }
    }
#endif

    ret = 0;
    const char *exception = NULL;
    if (is_repl_mode) {
        app_instance_repl(wasm_module_inst);
    }
    else if (func_name) {
        exception = app_instance_func(wasm_module_inst, func_name);
        if (exception) {
            /* got an exception */
            ret = 1;
        }
    }
    else {
        exception = app_instance_main(wasm_module_inst);
        if (exception) {
            /* got an exception */
            ret = 1;
        }
    }

#if WASM_ENABLE_LIBC_WASI != 0
    if (ret == 0) {
        /* propagate wasi exit code. */
        ret = wasm_runtime_get_wasi_exit_code(wasm_module_inst);
    }
#endif

    if (exception)
        printf("%s\n", exception);

#if WASM_ENABLE_STATIC_PGO != 0 && WASM_ENABLE_AOT != 0
    if (get_package_type(wasm_file_buf, wasm_file_size) == Wasm_Module_AoT
        && gen_prof_file)
        dump_pgo_prof_data(wasm_module_inst, gen_prof_file);
#endif

#if WASM_ENABLE_THREAD_MGR != 0
    if (timeout_ms >= 0) {
        timeout_arg.cancel = true;
        os_thread_join(timeout_tid, NULL);
    }
#endif

#if WASM_ENABLE_THREAD_MGR != 0
fail5:
#endif
#if WASM_ENABLE_DEBUG_INTERP != 0
fail4:
#endif
    /* destroy the module instance */
    wasm_runtime_deinstantiate(wasm_module_inst);

fail3:
    /* unload the module */
    wasm_runtime_unload(wasm_module);

fail2:
    /* free the file buffer */
    if (!is_xip_file)
        wasm_runtime_free(wasm_file_buf);
    else
        os_munmap(wasm_file_buf, wasm_file_size);

fail1:
#if BH_HAS_DLFCN
    /* unload the native libraries */
    unregister_and_unload_native_libs(native_lib_loaded_count,
                                      native_lib_loaded_list);
#endif

    /* destroy runtime environment */
    wasm_runtime_destroy();

    return ret;
}
