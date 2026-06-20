/*
 * Copyright (C) 2025 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_validator.h"

static void
set_error_buf(char *error_buf, uint32 error_buf_size, const char *string)
{
    if (error_buf != NULL) {
        snprintf(error_buf, error_buf_size,
                 "AOT module load failed: from validator. %s", string);
    }
}

static bool
aot_memory_info_validate(const AOTModule *module, char *error_buf,
                         uint32 error_buf_size)
{
    if (module->import_memory_count > 0) {
        set_error_buf(error_buf, error_buf_size,
                      "import memory is not supported");
        return false;
    }

    if (module->memory_count < 1) {
        set_error_buf(error_buf, error_buf_size,
                      "there should be >=1 memory in one aot module");
        return false;
    }

    return true;
}

bool
aot_module_validate(const AOTModule *module, char *error_buf,
                    uint32 error_buf_size)
{
    if (!aot_memory_info_validate(module, error_buf, error_buf_size)) {
        return false;
    }

    return true;
}
