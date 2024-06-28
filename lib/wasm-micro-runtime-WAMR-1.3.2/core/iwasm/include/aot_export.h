/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EXPORT_H
#define _AOT_EXPORT_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct AOTCompData;
typedef struct AOTCompData *aot_comp_data_t;

struct AOTCompContext;
typedef struct AOTCompContext *aot_comp_context_t;

aot_comp_data_t
aot_create_comp_data(void *wasm_module);

void
aot_destroy_comp_data(aot_comp_data_t comp_data);

#if WASM_ENABLE_DEBUG_AOT != 0
typedef void *dwarf_extractor_handle_t;
dwarf_extractor_handle_t
create_dwarf_extractor(aot_comp_data_t comp_data, char *file_name);
#endif

enum {
    AOT_FORMAT_FILE,
    AOT_OBJECT_FILE,
    AOT_LLVMIR_UNOPT_FILE,
    AOT_LLVMIR_OPT_FILE,
};

/* always sync it with AOTCompOption in compilation/aot_llvm.h */
typedef struct AOTCompOption {
    bool is_jit_mode;
    bool is_indirect_mode;
    char *target_arch;
    char *target_abi;
    char *target_cpu;
    char *cpu_features;
    bool is_sgx_platform;
    bool enable_bulk_memory;
    bool enable_thread_mgr;
    bool enable_tail_call;
    bool enable_simd;
    bool enable_ref_types;
    bool enable_aux_stack_check;
    bool enable_aux_stack_frame;
    bool disable_llvm_intrinsics;
    bool disable_llvm_lto;
    bool enable_llvm_pgo;
    bool enable_stack_estimation;
    bool quick_invoke_c_api_import;
    char *use_prof_file;
    uint32_t opt_level;
    uint32_t size_level;
    uint32_t output_format;
    uint32_t bounds_checks;
    uint32_t stack_bounds_checks;
    uint32_t segue_flags;
    char **custom_sections;
    uint32_t custom_sections_count;
    const char *stack_usage_file;
    const char *llvm_passes;
    const char *builtin_intrinsics;
} AOTCompOption, *aot_comp_option_t;

bool
aot_compiler_init(void);

void
aot_compiler_destroy(void);

aot_comp_context_t
aot_create_comp_context(aot_comp_data_t comp_data, aot_comp_option_t option);

void
aot_destroy_comp_context(aot_comp_context_t comp_ctx);

bool
aot_compile_wasm(aot_comp_context_t comp_ctx);

bool
aot_emit_llvm_file(aot_comp_context_t comp_ctx, const char *file_name);

bool
aot_emit_object_file(aot_comp_context_t comp_ctx, const char *file_name);

bool
aot_emit_aot_file(aot_comp_context_t comp_ctx, aot_comp_data_t comp_data,
                  const char *file_name);

void
aot_destroy_aot_file(uint8_t *aot_file);

char *
aot_get_last_error();

uint32_t
aot_get_plt_table_size();

#ifdef __cplusplus
}
#endif

#endif /* end of _AOT_EXPORT_H */
