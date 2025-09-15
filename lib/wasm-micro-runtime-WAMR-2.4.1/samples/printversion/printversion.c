/*
 * Copyright (C) 2025 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include <wasm_export.h>

int
main(int argc, char **argv)
{
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    wasm_runtime_get_version(&major, &minor, &patch);
    printf("wasm-micro-runtime %" PRIu32 ".%" PRIu32 ".%" PRIu32 "\n", major,
           minor, patch);
}
