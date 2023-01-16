/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdlib.h>
#include "bh_platform.h"
#include "bh_read_file.h"
#include "wasm_export.h"
#include "aot_export.h"

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
    printf("  -sgx                      Generate code for SGX platform (Intel Software Guard Extention)\n");
    printf("  --bounds-checks=1/0       Enable or disable the bounds checks for memory access:\n");
    printf("                              by default it is disabled in all 64-bit platforms except SGX and\n");
    printf("                              in these platforms runtime does bounds checks with hardware trap,\n");
    printf("                              and by default it is enabled in all 32-bit platforms\n");
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
    printf("  --disable-ref-types       Disable the MVP reference types feature\n");
    printf("  --disable-aux-stack-check Disable auxiliary stack overflow/underflow check\n");
    printf("  --enable-dump-call-stack  Enable stack trace feature\n");
    printf("  --enable-perf-profiling   Enable function performance profiling\n");
    printf("  --enable-indirect-mode    Enalbe call function through symbol table but not direct call\n");
    printf("  --disable-llvm-intrinsics Disable the LLVM built-in intrinsics\n");
    printf("  --disable-llvm-lto        Disable the LLVM link time optimization\n");
    printf("  --emit-custom-sections=<section names>\n");
    printf("                            Emit the specified custom sections to AoT file, using comma to separate\n");
    printf("                            multiple names, e.g.\n");
    printf("                                --emit-custom-sections=section1,section2,sectionN\n");
    printf("  -v=n                      Set log verbose level (0 to 5, default is 2), larger with more log\n");
    printf("  --version                 Show version information\n");
    printf("Examples: wamrc -o test.aot test.wasm\n");
    printf("          wamrc --target=i386 -o test.aot test.wasm\n");
    printf("          wamrc --target=i386 --format=object -o test.o test.wasm\n");
}
/* clang-format on */

#define PRINT_HELP_AND_EXIT() \
    do {                      \
        print_help();         \
        goto fail0;           \
    } while (0)

/**
 * Split a strings into an array of strings
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

int
main(int argc, char *argv[])
{
    char *wasm_file_name = NULL, *out_file_name = NULL;
    uint8 *wasm_file = NULL;
    uint32 wasm_file_size;
    wasm_module_t wasm_module = NULL;
    aot_comp_data_t comp_data = NULL;
    aot_comp_context_t comp_ctx = NULL;
    RuntimeInitArgs init_args;
    AOTCompOption option = { 0 };
    char error_buf[128];
    int log_verbose_level = 2;
    bool sgx_mode = false, size_level_set = false;
    int exit_status = EXIT_FAILURE;

    option.opt_level = 3;
    option.size_level = 3;
    option.output_format = AOT_FORMAT_FILE;
    /* default value, enable or disable depends on the platform */
    option.bounds_checks = 2;
    option.enable_simd = true;
    option.enable_aux_stack_check = true;
    option.enable_bulk_memory = true;
    option.enable_ref_types = true;

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
        }
        else if (!strncmp(argv[0], "--target-abi=", 13)) {
            if (argv[0][13] == '\0')
                PRINT_HELP_AND_EXIT();
            option.target_abi = argv[0] + 13;
        }
        else if (!strncmp(argv[0], "--cpu=", 6)) {
            if (argv[0][6] == '\0')
                PRINT_HELP_AND_EXIT();
            option.target_cpu = argv[0] + 6;
        }
        else if (!strncmp(argv[0], "--cpu-features=", 15)) {
            if (argv[0][15] == '\0')
                PRINT_HELP_AND_EXIT();
            option.cpu_features = argv[0] + 15;
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
            option.enable_ref_types = false;
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
        else if (!strcmp(argv[0], "--enable-dump-call-stack")) {
            option.enable_aux_stack_frame = true;
        }
        else if (!strcmp(argv[0], "--enable-perf-profiling")) {
            option.enable_aux_stack_frame = true;
        }
        else if (!strcmp(argv[0], "--enable-indirect-mode")) {
            option.is_indirect_mode = true;
        }
        else if (!strcmp(argv[0], "--disable-llvm-intrinsics")) {
            option.disable_llvm_intrinsics = true;
        }
        else if (!strcmp(argv[0], "--disable-llvm-lto")) {
            option.disable_llvm_lto = true;
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
        else if (!strncmp(argv[0], "--version", 9)) {
            uint32 major, minor, patch;
            wasm_runtime_get_version(&major, &minor, &patch);
            printf("wamrc %u.%u.%u\n", major, minor, patch);
            return 0;
        }
        else
            PRINT_HELP_AND_EXIT();
    }

    if (argc == 0 || !out_file_name)
        PRINT_HELP_AND_EXIT();

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
#if defined(_WIN32) || defined(_WIN32_) || defined(__APPLE__) \
    || defined(__MACH__)
        if (!option.target_abi) {
            LOG_VERBOSE("Set size level to 1 for Windows or MacOS AOT file");
            option.size_level = 1;
        }
#endif
    }

    if (sgx_mode) {
        option.size_level = 1;
        option.is_sgx_platform = true;
    }

    wasm_file_name = argv[0];

    if (!strcmp(wasm_file_name, out_file_name)) {
        printf("Error: input file and output file are the same");
        return -1;
    }

    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    init_args.mem_alloc_type = Alloc_With_Allocator;
    init_args.mem_alloc_option.allocator.malloc_func = malloc;
    init_args.mem_alloc_option.allocator.realloc_func = realloc;
    init_args.mem_alloc_option.allocator.free_func = free;

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

    bh_log_set_verbose_level(log_verbose_level);

    bh_print_time("Begin to load wasm file");

    /* load WASM byte buffer from WASM bin file */
    if (!(wasm_file =
              (uint8 *)bh_read_file_to_buffer(wasm_file_name, &wasm_file_size)))
        goto fail1;

    if (get_package_type(wasm_file, wasm_file_size) != Wasm_Module_Bytecode) {
        printf("Invalid file type: expected wasm file but got other\n");
        goto fail2;
    }

    /* load WASM module */
    if (!(wasm_module = wasm_runtime_load(wasm_file, wasm_file_size, error_buf,
                                          sizeof(error_buf)))) {
        printf("%s\n", error_buf);
        goto fail2;
    }

    if (!(comp_data = aot_create_comp_data(wasm_module))) {
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
    wasm_runtime_free(wasm_file);

fail1:
    /* Destroy runtime environment */
    wasm_runtime_destroy();

fail0:
    /* free option.custom_sections */
    if (option.custom_sections) {
        free(option.custom_sections);
    }

    bh_print_time("wamrc return");
    return exit_status;
}
