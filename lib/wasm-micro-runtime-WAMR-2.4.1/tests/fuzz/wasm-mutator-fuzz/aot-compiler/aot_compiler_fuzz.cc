// Copyright (C) 2025 Intel Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <iostream>
#include <vector>

#include "aot_export.h"
#include "wasm_export.h"
#include "bh_read_file.h"

static void
handle_aot_recent_error(const char *tag)
{
    const char *error = aot_get_last_error();
    if (strlen(error) == 0) {
        error = "UNKNOWN ERROR";
    }

    std::cout << tag << " " << error << std::endl;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    wasm_module_t module = NULL;
    char error_buf[128] = { 0 };
    AOTCompOption option = { 0 };
    aot_comp_data_t comp_data = NULL;
    aot_comp_context_t comp_ctx = NULL;

    /* libfuzzer don't allow to modify the given Data, so make a copy here */
    std::vector<uint8_t> myData(Data, Data + Size);

    if (Size >= 4
        && get_package_type(myData.data(), Size) != Wasm_Module_Bytecode) {
        printf("Invalid wasm file: magic header not detected\n");
        return 0;
    }

    wasm_runtime_init();

    module = wasm_runtime_load((uint8_t *)myData.data(), Size, error_buf, 120);
    if (!module) {
        std::cout << "[LOADING] " << error_buf << std::endl;
        goto DESTROY_RUNTIME;
    }

    // TODO: target_arch and other fields
    option.target_arch = "x86_64";
    option.target_abi = "gnu";
    option.enable_bulk_memory = true;
    option.enable_thread_mgr = true;
    option.enable_tail_call = true;
    option.enable_simd = true;
    option.enable_ref_types = true;
    option.enable_gc = true;
    option.aux_stack_frame_type = AOT_STACK_FRAME_TYPE_STANDARD;

    comp_data =
        aot_create_comp_data(module, option.target_arch, option.enable_gc);
    if (!comp_data) {
        handle_aot_recent_error("[CREATING comp_data]");
        goto UNLOAD_MODULE;
    }

    comp_ctx = aot_create_comp_context(comp_data, &option);
    if (!comp_ctx) {
        handle_aot_recent_error("[CREATING comp_context]");
        goto DESTROY_COMP_DATA;
    }

    if (!aot_compile_wasm(comp_ctx)) {
        handle_aot_recent_error("[COMPILING]");
        goto DESTROY_COMP_CTX;
    }

DESTROY_COMP_CTX:
    aot_destroy_comp_context(comp_ctx);
DESTROY_COMP_DATA:
    aot_destroy_comp_data(comp_data);
UNLOAD_MODULE:
    wasm_runtime_unload(module);
DESTROY_RUNTIME:
    wasm_runtime_destroy();

    /* Values other than 0 and -1 are reserved for future use. */
    return 0;
}
