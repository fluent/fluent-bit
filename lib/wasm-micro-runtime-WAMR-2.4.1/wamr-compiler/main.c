/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdlib.h>
#include "bh_platform.h"
#include "bh_read_file.h"
#include "wasm_export.h"
#include "aot_export.h"

#include <llvm-c/Support.h>

#if BH_HAS_DLFCN
#include <dlfcn.h>

typedef uint32 (*get_native_lib_func)(char **p_module_name,
                                      NativeSymbol **p_native_symbols);

static uint32
load_and_register_native_libs(const char **native_lib_list,
                              uint32 native_lib_count,
                              void **native_handle_list)
{
    uint32 i, native_handle_count = 0, n_native_symbols;
    NativeSymbol *native_symbols;
    char *module_name;
    void *handle;

    for (i = 0; i < native_lib_count; i++) {
        /* open the native library */
        if (!(handle = dlopen(native_lib_list[i], RTLD_NOW | RTLD_GLOBAL))
            && !(handle = dlopen(native_lib_list[i], RTLD_LAZY))) {
            LOG_WARNING("warning: failed to load native library %s",
                        native_lib_list[i]);
            continue;
        }

        /* lookup get_native_lib func */
        get_native_lib_func get_native_lib = dlsym(handle, "get_native_lib");
        if (!get_native_lib) {
            LOG_WARNING("warning: failed to lookup `get_native_lib` function "
                        "from native lib %s",
                        native_lib_list[i]);
            dlclose(handle);
            continue;
        }

        n_native_symbols = get_native_lib(&module_name, &native_symbols);

        /* register native symbols */
        if (!(n_native_symbols > 0 && module_name && native_symbols
              && wasm_runtime_register_natives(module_name, native_symbols,
                                               n_native_symbols))) {
            LOG_WARNING("warning: failed to register native lib %s",
                        native_lib_list[i]);
            dlclose(handle);
            continue;
        }

        native_handle_list[native_handle_count++] = handle;
    }

    return native_handle_count;
}

static void
unregister_and_unload_native_libs(uint32 native_lib_count,
                                  void **native_handle_list)
{
    uint32 i, n_native_symbols;
    NativeSymbol *native_symbols;
    char *module_name;
    void *handle;

    for (i = 0; i < native_lib_count; i++) {
        handle = native_handle_list[i];

        /* lookup get_native_lib func */
        get_native_lib_func get_native_lib = dlsym(handle, "get_native_lib");
        if (!get_native_lib) {
            LOG_WARNING("warning: failed to lookup `get_native_lib` function "
                        "from native lib %p",
                        handle);
            continue;
        }

        n_native_symbols = get_native_lib(&module_name, &native_symbols);
        if (n_native_symbols == 0 || module_name == NULL
            || native_symbols == NULL) {
            LOG_WARNING("warning: get_native_lib returned different values for "
                        "native lib %p",
                        handle);
            continue;
        }

        /* unregister native symbols */
        if (!wasm_runtime_unregister_natives(module_name, native_symbols)) {
            LOG_WARNING("warning: failed to unregister native lib %p", handle);
            continue;
        }

        dlclose(handle);
    }
}
#endif

/* clang-format off */
static void
print_help()
{
    printf("Usage: wamrc [options] -o output_file wasm_file\n");
    printf("  --target=<arch-name>      Set the target arch, which has the general format: <arch><sub>\n");
    printf("                            <arch> = x86_64, i386, aarch64, arm, thumb, xtensa, mips,\n");
    printf("                                     riscv64, riscv32.\n");
    printf("                              Default is host arch, e.g. x86_64\n");
    printf("                            <sub> = for ex. on arm or thumb: v5, v6m, v7a, v7m, etc.\n");
    printf("                            Use --target=help to list supported targets\n");
    printf("                            Or, provide a triple in the format of <arch>-<vendor>-<os>-<abi>.\n");
    printf("                            By doing this, --target-abi, --cpu, and --cpu-features will be ignored.\n");
    printf("                            The triple will only be normalized without any further verification.\n");
    printf("  --target-abi=<abi>        Set the target ABI, e.g. gnu, eabi, gnueabihf, msvc, etc.\n");
    printf("                              Default is gnu if target isn't riscv64 or riscv32\n");
    printf("                              For target riscv64 and riscv32, default is lp64d and ilp32d\n");
    printf("                            Use --target-abi=help to list all the ABI supported\n");
    printf("  --cpu=<cpu>               Set the target CPU (default: host CPU, e.g. skylake)\n");
    printf("                            Use --cpu=help to list all the CPU supported\n");
    printf("  --cpu-features=<features> Enable or disable the CPU features\n");
    printf("                            Use +feature to enable a feature, or -feature to disable it\n");
    printf("                            For example, --cpu-features=+feature1,-feature2\n");
    printf("                            Use --cpu-features=+help to list all the features supported\n");
    printf("  --opt-level=n             Set the optimization level (0 to 3, default is 3)\n");
    printf("  --size-level=n            Set the code size level (0 to 3, default is 3)\n");
    printf("                              0 - Large code model\n");
    printf("                              1 - Medium code model\n");
    printf("                              2 - Kernel code model\n");
    printf("                              3 - Small code model\n");
    printf("  -sgx                      Generate code for SGX platform (Intel Software Guard Extensions)\n");
    printf("  --bounds-checks=1/0       Enable or disable the bounds checks for memory access:\n");
    printf("                              This flag controls bounds checking with a software check. \n"); 
    printf("                              On 64-bit platforms, it is disabled by default, using a hardware \n"); 
    printf("                              trap if supported, except when SGX or memory64 is enabled,\n"); 
    printf("                              which defaults to a software check.\n"); 
    printf("                              On 32-bit platforms, the flag is enabled by default, using a software check\n");
    printf("                              due to the lack of hardware support.\n"); 
    printf("                            CAVEAT: --bounds-checks=0 enables some optimizations\n");
    printf("                              which make the compiled AOT module incompatible\n");
    printf("                              with a runtime without the hardware bounds checks.\n");
    printf("  --stack-bounds-checks=1/0 Enable or disable the bounds checks for native stack:\n");
    printf("                              if the option isn't set, the status is same as `--bounds-check`,\n");
    printf("                              if the option is set, the status is same as the option value\n");
    printf("  --stack-usage=<file>      Generate a stack-usage file.\n");
    printf("                              Similarly to `clang -fstack-usage`.\n");
    printf("  --format=<format>         Specifies the format of the output file\n");
    printf("                            The format supported:\n");
    printf("                              aot (default)  AoT file\n");
    printf("                              object         Native object file\n");
    printf("                              llvmir-unopt   Unoptimized LLVM IR\n");
    printf("                              llvmir-opt     Optimized LLVM IR\n");
    printf("  --disable-bulk-memory     Disable the MVP bulk memory feature\n");
    printf("  --enable-multi-thread     Enable multi-thread feature, the dependent features bulk-memory and\n");
    printf("                            thread-mgr will be enabled automatically\n");
    printf("  --enable-tail-call        Enable the post-MVP tail call feature\n");
    printf("  --disable-simd            Disable the post-MVP 128-bit SIMD feature:\n");
    printf("                              currently 128-bit SIMD is supported for x86-64 and aarch64 targets,\n");
    printf("                              and by default it is enabled in them and disabled in other targets\n");
    printf("  --disable-ref-types       Disable the MVP reference types feature, it will be disabled forcibly if\n");
    printf("                              GC is enabled\n");
    printf("  --disable-aux-stack-check Disable auxiliary stack overflow/underflow check\n");
    printf("  --enable-dump-call-stack  Enable stack trace feature\n");
    printf("  --call-stack-features=<features>\n");
    printf("                            A comma-separated list of features when generating call stacks.\n");
    printf("                            By default, all features are enabled. To disable all features,\n");
    printf("                            provide an empty list (i.e. --call-stack-features=). This flag\n");
    printf("                            only only takes effect when --enable-dump-call-stack is set.\n");
    printf("                            Available features: bounds-checks, ip, func-idx, trap-ip, values.\n");
    printf("  --enable-perf-profiling   Enable function performance profiling\n");
    printf("  --enable-memory-profiling Enable memory usage profiling\n");
    printf("  --xip                     A shorthand of --enable-indirect-mode --disable-llvm-intrinsics\n");
    printf("  --enable-indirect-mode    Enable call function through symbol table but not direct call\n");
    printf("  --enable-gc               Enable GC (Garbage Collection) feature\n");
    printf("  --disable-llvm-intrinsics Disable the LLVM built-in intrinsics\n");
    printf("  --enable-builtin-intrinsics=<flags>\n");
    printf("                            Enable the specified built-in intrinsics, it will override the default\n");
    printf("                              settings. It only takes effect when --disable-llvm-intrinsics is set.\n");
    printf("                            Available flags: all, i32.common, i64.common, f32.common, f64.common,\n");
    printf("                              i32.clz, i32.ctz, etc, refer to doc/xip.md for full list\n");
    printf("                            Use comma to separate, please refer to doc/xip.md for full list.\n");
    printf("  --disable-llvm-jump-tables Disable the LLVM jump tables similarly to clang's -fno-jump-tables\n");
    printf("  --disable-llvm-lto        Disable the LLVM link time optimization\n");
    printf("  --enable-llvm-pgo         Enable LLVM PGO (Profile-Guided Optimization)\n");
    printf("  --enable-llvm-passes=<passes>\n");
    printf("                            Enable the specified LLVM passes, using comma to separate\n");
    printf("  --use-prof-file=<file>    Use profile file collected by LLVM PGO (Profile-Guided Optimization)\n");
    printf("  --enable-segue[=<flags>]  Enable using segment register GS as the base address of linear memory,\n");
    printf("                            only available on linux x86-64, which may improve performance,\n");
    printf("                            flags can be: i32.load, i64.load, f32.load, f64.load, v128.load,\n");
    printf("                                          i32.store, i64.store, f32.store, f64.store, v128.store\n");
    printf("                            Use comma to separate, e.g. --enable-segue=i32.load,i64.store\n");
    printf("                            and --enable-segue means all flags are added.\n");
    printf("  --emit-custom-sections=<section names>\n");
    printf("                            Emit the specified custom sections to AoT file, using comma to separate\n");
    printf("                            multiple names, e.g.\n");
    printf("                                --emit-custom-sections=section1,section2,sectionN\n");
#if BH_HAS_DLFCN
    printf("  --native-lib=<lib>        Register native libraries to the WASM module, which\n");
    printf("                            are shared object (.so) files, for example:\n");
    printf("                              --native-lib=test1.so --native-lib=test2.so\n");
#endif
    printf("  --invoke-c-api-import     Treat unknown import function as wasm-c-api import function and\n");
    printf("                            quick call it from AOT code\n");
#if WASM_ENABLE_LINUX_PERF != 0
    printf("  --enable-linux-perf       Enable linux perf support\n");
#endif
    printf("  --mllvm=<option>          Add the LLVM command line option\n");
    printf("  --enable-shared-heap      Enable shared heap feature, assuming only one shared heap will be attached\n");
    printf("  --enable-shared-chain     Enable shared heap chain feature, works for more than one shared heap\n");
    printf("                            WARNING: enable this feature will largely increase code size\n");
    printf("  -v=n                      Set log verbose level (0 to 5, default is 2), larger with more log\n");
    printf("  --version                 Show version information\n");
    printf("Examples: wamrc -o test.aot test.wasm\n");
    printf("          wamrc --target=i386 -o test.aot test.wasm\n");
    printf("          wamrc --target=i386 --format=object -o test.o test.wasm\n");
    printf("          wamrc --target-abi=help\n");
    printf("          wamrc --target=x86_64 --cpu=help\n");
}
/* clang-format on */

#define PRINT_HELP_AND_EXIT() \
    do {                      \
        print_help();         \
        goto fail0;           \
    } while (0)

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
     * Due to the section name,
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

static bool
parse_call_stack_features(char *features_str,
                          AOTCallStackFeatures *out_features)
{
    int size = 0;
    char **features;
    bool ret = true;

    bh_assert(features_str);
    bh_assert(out_features);

    /* non-empty feature list */
    features = split_string(features_str, &size, ",");
    if (!features) {
        return false;
    }

    while (size--) {
        if (!strcmp(features[size], "bounds-checks")) {
            out_features->bounds_checks = true;
        }
        else if (!strcmp(features[size], "ip")) {
            out_features->ip = true;
        }
        else if (!strcmp(features[size], "trap-ip")) {
            out_features->trap_ip = true;
        }
        else if (!strcmp(features[size], "values")) {
            out_features->values = true;
        }
        else if (!strcmp(features[size], "func-idx")) {
            out_features->func_idx = true;
        }
        else {
            ret = false;
            printf("Unsupported feature %s\n", features[size]);
            goto finish;
        }
    }

finish:
    free(features);
    return ret;
}

static bool
can_enable_tiny_frame(const AOTCompOption *opt)
{
    return !opt->call_stack_features.values && !opt->enable_gc
           && !opt->enable_perf_profiling;
}

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

/* When print help info for target/cpu/target-abi/cpu-features, load this dummy
 * wasm file content rather than from an input file, the dummy wasm file content
 * is: magic header + version number */
static unsigned char dummy_wasm_file[8] = { 0x00, 0x61, 0x73, 0x6D,
                                            0x01, 0x00, 0x00, 0x00 };

int
main(int argc, char *argv[])
{
    char *wasm_file_name = NULL, *out_file_name = NULL;
    char **llvm_options = NULL;
    size_t llvm_options_count = 0;
    uint8 *wasm_file = NULL;
    uint32 wasm_file_size;
    wasm_module_t wasm_module = NULL;
    aot_comp_data_t comp_data = NULL;
    aot_comp_context_t comp_ctx = NULL;
    RuntimeInitArgs init_args;
    AOTCompOption option = { 0 };
    char error_buf[128];
    int log_verbose_level = 2;
    bool sgx_mode = false, size_level_set = false, use_dummy_wasm = false;
    int exit_status = EXIT_FAILURE;
#if BH_HAS_DLFCN
    const char *native_lib_list[8] = { NULL };
    uint32 native_lib_count = 0;
    void *native_handle_list[8] = { NULL };
    uint32 native_handle_count = 0;
#endif
#if WASM_ENABLE_LINUX_PERF != 0
    bool enable_linux_perf = false;
#endif

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
    option.enable_gc = false;
    option.enable_extended_const = false;
    aot_call_stack_features_init_default(&option.call_stack_features);

    /* Process options */
    for (argc--, argv++; argc > 0 && argv[0][0] == '-'; argc--, argv++) {
        if (!strcmp(argv[0], "-o")) {
            argc--, argv++;
            if (argc < 2)
                PRINT_HELP_AND_EXIT();
            out_file_name = argv[0];
        }
        else if (!strncmp(argv[0], "--target=", 9)) {
            if (argv[0][9] == '\0')
                PRINT_HELP_AND_EXIT();
            option.target_arch = argv[0] + 9;
            if (!strcmp(option.target_arch, "help")) {
                use_dummy_wasm = true;
            }
        }
        else if (!strncmp(argv[0], "--target-abi=", 13)) {
            if (argv[0][13] == '\0')
                PRINT_HELP_AND_EXIT();
            option.target_abi = argv[0] + 13;
            if (!strcmp(option.target_abi, "help")) {
                use_dummy_wasm = true;
            }
        }
        else if (!strncmp(argv[0], "--cpu=", 6)) {
            if (argv[0][6] == '\0')
                PRINT_HELP_AND_EXIT();
            option.target_cpu = argv[0] + 6;
            if (!strcmp(option.target_cpu, "help")) {
                use_dummy_wasm = true;
            }
        }
        else if (!strncmp(argv[0], "--cpu-features=", 15)) {
            if (argv[0][15] == '\0')
                PRINT_HELP_AND_EXIT();
            option.cpu_features = argv[0] + 15;
            if (!strcmp(option.cpu_features, "+help")) {
                use_dummy_wasm = true;
            }
        }
        else if (!strncmp(argv[0], "--opt-level=", 12)) {
            if (argv[0][12] == '\0')
                PRINT_HELP_AND_EXIT();
            option.opt_level = (uint32)atoi(argv[0] + 12);
            if (option.opt_level > 3)
                option.opt_level = 3;
        }
        else if (!strncmp(argv[0], "--size-level=", 13)) {
            if (argv[0][13] == '\0')
                PRINT_HELP_AND_EXIT();
            option.size_level = (uint32)atoi(argv[0] + 13);
            if (option.size_level > 3)
                option.size_level = 3;
            size_level_set = true;
        }
        else if (!strcmp(argv[0], "-sgx")) {
            sgx_mode = true;
        }
        else if (!strncmp(argv[0], "--bounds-checks=", 16)) {
            option.bounds_checks = (atoi(argv[0] + 16) == 1) ? 1 : 0;
        }
        else if (!strncmp(argv[0], "--stack-bounds-checks=", 22)) {
            option.stack_bounds_checks = (atoi(argv[0] + 22) == 1) ? 1 : 0;
        }
        else if (!strncmp(argv[0], "--stack-usage=", 14)) {
            option.stack_usage_file = argv[0] + 14;
        }
        else if (!strncmp(argv[0], "--format=", 9)) {
            if (argv[0][9] == '\0')
                PRINT_HELP_AND_EXIT();
            if (!strcmp(argv[0] + 9, "aot"))
                option.output_format = AOT_FORMAT_FILE;
            else if (!strcmp(argv[0] + 9, "object"))
                option.output_format = AOT_OBJECT_FILE;
            else if (!strcmp(argv[0] + 9, "llvmir-unopt"))
                option.output_format = AOT_LLVMIR_UNOPT_FILE;
            else if (!strcmp(argv[0] + 9, "llvmir-opt"))
                option.output_format = AOT_LLVMIR_OPT_FILE;
            else {
                printf("Invalid format %s.\n", argv[0] + 9);
                PRINT_HELP_AND_EXIT();
            }
        }
        else if (!strncmp(argv[0], "-v=", 3)) {
            log_verbose_level = atoi(argv[0] + 3);
            if (log_verbose_level < 0 || log_verbose_level > 5)
                PRINT_HELP_AND_EXIT();
        }
        else if (!strcmp(argv[0], "--disable-bulk-memory")) {
            option.enable_bulk_memory = false;
        }
        else if (!strcmp(argv[0], "--enable-multi-thread")) {
            option.enable_bulk_memory = true;
            option.enable_thread_mgr = true;
        }
        else if (!strcmp(argv[0], "--enable-tail-call")) {
            option.enable_tail_call = true;
        }
        else if (!strcmp(argv[0], "--enable-simd")) {
            /* obsolete option, kept for compatibility */
            option.enable_simd = true;
        }
        else if (!strcmp(argv[0], "--disable-simd")) {
            option.enable_simd = false;
        }
        else if (!strcmp(argv[0], "--disable-ref-types")) {
            option.enable_ref_types = false;
        }
        else if (!strcmp(argv[0], "--disable-aux-stack-check")) {
            option.enable_aux_stack_check = false;
        }
        else if (!strcmp(argv[0], "--enable-extended-const")) {
            option.enable_extended_const = true;
        }
        else if (!strcmp(argv[0], "--enable-dump-call-stack")) {
            option.aux_stack_frame_type = AOT_STACK_FRAME_TYPE_STANDARD;
        }
        else if (!strncmp(argv[0], "--call-stack-features=", 22)) {
            /* Reset all the features, only enable the user-defined ones */
            memset(&option.call_stack_features, 0,
                   sizeof(AOTCallStackFeatures));

            if (argv[0][22] != '\0') {
                if (!parse_call_stack_features(argv[0] + 22,
                                               &option.call_stack_features)) {
                    printf("Failed to parse call-stack-features\n");
                    PRINT_HELP_AND_EXIT();
                }
            }
        }
        else if (!strcmp(argv[0], "--enable-perf-profiling")) {
            option.aux_stack_frame_type = AOT_STACK_FRAME_TYPE_STANDARD;
            option.enable_perf_profiling = true;
        }
        else if (!strcmp(argv[0], "--enable-memory-profiling")) {
            option.enable_memory_profiling = true;
            option.enable_stack_estimation = true;
        }
        else if (!strcmp(argv[0], "--xip")) {
            option.is_indirect_mode = true;
            option.disable_llvm_intrinsics = true;
        }
        else if (!strcmp(argv[0], "--enable-indirect-mode")) {
            option.is_indirect_mode = true;
        }
        else if (!strcmp(argv[0], "--enable-gc")) {
            option.aux_stack_frame_type = AOT_STACK_FRAME_TYPE_STANDARD;
            option.enable_gc = true;
        }
        else if (!strcmp(argv[0], "--disable-llvm-intrinsics")) {
            option.disable_llvm_intrinsics = true;
        }
        else if (!strncmp(argv[0], "--enable-builtin-intrinsics=", 28)) {
            if (argv[0][28] == '\0')
                PRINT_HELP_AND_EXIT();
            option.builtin_intrinsics = argv[0] + 28;
        }
        else if (!strcmp(argv[0], "--disable-llvm-jump-tables")) {
            option.disable_llvm_jump_tables = true;
        }
        else if (!strcmp(argv[0], "--disable-llvm-lto")) {
            option.disable_llvm_lto = true;
        }
        else if (!strcmp(argv[0], "--enable-llvm-pgo")) {
            option.enable_llvm_pgo = true;
        }
        else if (!strncmp(argv[0], "--enable-llvm-passes=", 21)) {
            if (argv[0][21] == '\0')
                PRINT_HELP_AND_EXIT();
            option.llvm_passes = argv[0] + 21;
        }
        else if (!strncmp(argv[0], "--use-prof-file=", 16)) {
            if (argv[0][16] == '\0')
                PRINT_HELP_AND_EXIT();
            option.use_prof_file = argv[0] + 16;
        }
        else if (!strcmp(argv[0], "--enable-segue")) {
            /* all flags are enabled */
            option.segue_flags = 0x1F1F;
        }
        else if (!strncmp(argv[0], "--enable-segue=", 15)) {
            option.segue_flags = resolve_segue_flags(argv[0] + 15);
            if (option.segue_flags == (uint32)-1)
                PRINT_HELP_AND_EXIT();
        }
        else if (!strncmp(argv[0], "--emit-custom-sections=", 23)) {
            int len = 0;
            if (option.custom_sections) {
                free(option.custom_sections);
            }

            option.custom_sections = split_string(argv[0] + 23, &len, ",");
            if (!option.custom_sections) {
                printf("Failed to process emit-custom-sections: alloc "
                       "memory failed\n");
                PRINT_HELP_AND_EXIT();
            }

            option.custom_sections_count = len;
        }
#if BH_HAS_DLFCN
        else if (!strncmp(argv[0], "--native-lib=", 13)) {
            if (argv[0][13] == '\0')
                PRINT_HELP_AND_EXIT();
            if (native_lib_count >= sizeof(native_lib_list) / sizeof(char *)) {
                printf("Only allow max native lib number %d\n",
                       (int)(sizeof(native_lib_list) / sizeof(char *)));
                goto fail0;
            }
            native_lib_list[native_lib_count++] = argv[0] + 13;
        }
#endif
        else if (!strcmp(argv[0], "--invoke-c-api-import")) {
            option.quick_invoke_c_api_import = true;
        }
#if WASM_ENABLE_LINUX_PERF != 0
        else if (!strcmp(argv[0], "--enable-linux-perf")) {
            enable_linux_perf = true;
        }
#endif
        else if (!strncmp(argv[0], "--mllvm=", 8)) {
            void *np;
            if (argv[0][8] == '\0')
                PRINT_HELP_AND_EXIT();
            if (llvm_options_count == 0)
                llvm_options_count += 2;
            else
                llvm_options_count++;
            np = realloc(llvm_options, llvm_options_count * sizeof(char *));
            if (np == NULL) {
                printf("Memory allocation failure\n");
                goto fail0;
            }
            llvm_options = np;
            if (llvm_options_count == 2)
                llvm_options[llvm_options_count - 2] = "wamrc";
            llvm_options[llvm_options_count - 1] = argv[0] + 8;
        }
        else if (!strcmp(argv[0], "--enable-shared-heap")) {
            option.enable_shared_heap = true;
        }
        else if (!strcmp(argv[0], "--enable-shared-chain")) {
            option.enable_shared_chain = true;
        }
        else if (!strcmp(argv[0], "--version")) {
            uint32 major, minor, patch;
            wasm_runtime_get_version(&major, &minor, &patch);
            printf("wamrc %u.%u.%u\n", major, minor, patch);
            return 0;
        }
        else
            PRINT_HELP_AND_EXIT();
    }

    if (!use_dummy_wasm && (argc == 0 || !out_file_name))
        PRINT_HELP_AND_EXIT();

    if (option.aux_stack_frame_type == AOT_STACK_FRAME_TYPE_STANDARD
        && can_enable_tiny_frame(&option)) {
        LOG_VERBOSE("Use tiny frame mode for stack frames");
        option.aux_stack_frame_type = AOT_STACK_FRAME_TYPE_TINY;
        /* for now we only enable frame per function for a TINY frame mode */
        option.call_stack_features.frame_per_function = true;
    }
    if (!option.call_stack_features.func_idx
        && (option.enable_gc || option.enable_perf_profiling)) {
        LOG_WARNING("'func-idx' call stack feature will be automatically "
                    "enabled for GC and perf profiling mode");
        option.call_stack_features.func_idx = true;
    }

    if (!size_level_set) {
        /**
         * Set opt level to 1 by default for Windows and MacOS as
         * they can not memory map out 0-2GB memory and might not
         * be able to meet the requirements of some AOT relocation
         * operations.
         */
        if (option.target_abi && !strcmp(option.target_abi, "msvc")) {
            LOG_VERBOSE("Set size level to 1 for Windows AOT file");
            option.size_level = 1;
        }
#if defined(_WIN32) || defined(_WIN32_) \
    || ((defined(__APPLE__) || defined(__MACH__)) && !defined(__arm64__))
        if (!option.target_arch && !option.target_abi) {
            LOG_VERBOSE("Set size level to 1 for Windows or MacOS AOT file");
            option.size_level = 1;
        }
#endif
    }

    if (option.enable_gc && !option.call_stack_features.values) {
        LOG_WARNING("Call stack feature 'values' must be enabled for GC. The "
                    "feature will be enabled automatically.");
        option.call_stack_features.values = true;
    }

    if (sgx_mode) {
        option.size_level = 0;
        option.is_sgx_platform = true;
    }

    if (option.enable_gc) {
        option.enable_ref_types = false;
    }

    if (option.enable_shared_chain) {
        LOG_VERBOSE("Enable shared chain will overwrite shared heap and sw "
                    "bounds control");
        option.enable_shared_heap = false;
        option.bounds_checks = true;
    }

    if (!use_dummy_wasm) {
        wasm_file_name = argv[0];

        if (!strcmp(wasm_file_name, out_file_name)) {
            printf("Error: input file and output file are the same");
            return -1;
        }
    }

    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    init_args.mem_alloc_type = Alloc_With_Allocator;
    init_args.mem_alloc_option.allocator.malloc_func = malloc;
    init_args.mem_alloc_option.allocator.realloc_func = realloc;
    init_args.mem_alloc_option.allocator.free_func = free;
#if WASM_ENABLE_LINUX_PERF != 0
    init_args.enable_linux_perf = enable_linux_perf;
#endif

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

    bh_log_set_verbose_level(log_verbose_level);

#if BH_HAS_DLFCN
    bh_print_time("Begin to load native libs");
    native_handle_count = load_and_register_native_libs(
        native_lib_list, native_lib_count, native_handle_list);
#endif

    if (llvm_options_count > 0)
        LLVMParseCommandLineOptions(llvm_options_count,
                                    (const char **)llvm_options, "wamrc");

    bh_print_time("Begin to load wasm file");

    if (use_dummy_wasm) {
        /* load WASM byte buffer from dummy buffer */
        wasm_file_size = sizeof(dummy_wasm_file);
        wasm_file = dummy_wasm_file;
    }
    else {
        /* load WASM byte buffer from WASM bin file */
        if (!(wasm_file = (uint8 *)bh_read_file_to_buffer(wasm_file_name,
                                                          &wasm_file_size)))
            goto fail1;
    }

    if (wasm_file_size >= 4 /* length of MAGIC NUMBER */
        && get_package_type(wasm_file, wasm_file_size)
               != Wasm_Module_Bytecode) {
        printf("Invalid wasm file: magic header not detected\n");
        goto fail2;
    }

    /* load WASM module */
    if (!(wasm_module = wasm_runtime_load(wasm_file, wasm_file_size, error_buf,
                                          sizeof(error_buf)))) {
        printf("%s\n", error_buf);
        goto fail2;
    }

    if (!(comp_data = aot_create_comp_data(wasm_module, option.target_arch,
                                           option.enable_gc))) {
        printf("%s\n", aot_get_last_error());
        goto fail3;
    }

#if WASM_ENABLE_DEBUG_AOT != 0
    if (!create_dwarf_extractor(comp_data, wasm_file_name)) {
        printf("%s:create dwarf extractor failed\n", wasm_file_name);
    }
#endif

    bh_print_time("Begin to create compile context");

    if (!(comp_ctx = aot_create_comp_context(comp_data, &option))) {
        printf("%s\n", aot_get_last_error());
        goto fail4;
    }

    bh_print_time("Begin to compile");

    if (!aot_compile_wasm(comp_ctx)) {
        printf("%s\n", aot_get_last_error());
        goto fail5;
    }

    switch (option.output_format) {
        case AOT_LLVMIR_UNOPT_FILE:
        case AOT_LLVMIR_OPT_FILE:
            if (!aot_emit_llvm_file(comp_ctx, out_file_name)) {
                printf("%s\n", aot_get_last_error());
                goto fail5;
            }
            break;
        case AOT_OBJECT_FILE:
            if (!aot_emit_object_file(comp_ctx, out_file_name)) {
                printf("%s\n", aot_get_last_error());
                goto fail5;
            }
            break;
        case AOT_FORMAT_FILE:
            if (!aot_emit_aot_file(comp_ctx, comp_data, out_file_name)) {
                printf("%s\n", aot_get_last_error());
                goto fail5;
            }
            break;
        default:
            break;
    }

    bh_print_time("Compile end");

    printf("Compile success, file %s was generated.\n", out_file_name);
    exit_status = EXIT_SUCCESS;

fail5:
    /* Destroy compiler context */
    aot_destroy_comp_context(comp_ctx);

fail4:
    /* Destroy compile data */
    aot_destroy_comp_data(comp_data);

fail3:
    /* Unload WASM module */
    wasm_runtime_unload(wasm_module);

fail2:
    /* free the file buffer */
    if (!use_dummy_wasm) {
        wasm_runtime_free(wasm_file);
    }

fail1:
#if BH_HAS_DLFCN
    unregister_and_unload_native_libs(native_handle_count, native_handle_list);
#endif
    /* Destroy runtime environment */
    wasm_runtime_destroy();

fail0:
    /* free option.custom_sections */
    if (option.custom_sections) {
        free(option.custom_sections);
    }
    free(llvm_options);

    bh_print_time("wamrc return");
    return exit_status;
}
