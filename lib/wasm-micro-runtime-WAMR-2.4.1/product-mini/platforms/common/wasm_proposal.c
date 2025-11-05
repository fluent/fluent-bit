/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>

#include "bh_platform.h"

void
wasm_proposal_print_status(void)
{
    printf("About Wasm Proposals:\n");
    printf("  Always-on:\n");
    printf("    - Multi-value\n");
    printf("    - Non-trapping float-to-int conversions\n");
    printf("    - Sign-extension operators\n");
    printf("    - WebAssembly C and C++ API\n");
    printf("  Compilation Configurable. 0 is OFF. 1 is ON:\n");
    printf("    - Bulk Memory Operation via WASM_ENABLE_BULK_MEMORY: %u\n",
           WASM_ENABLE_BULK_MEMORY);
    printf("    - Fixed-Width SIMD via WASM_ENABLE_SIMD: %u\n",
           WASM_ENABLE_SIMD);
    printf("    - Garbage Collection via WASM_ENABLE_GC: %u\n", WASM_ENABLE_GC);
    printf(
        "    - Legacy Exception Handling via WASM_ENABLE_EXCE_HANDLING: %u\n",
        WASM_ENABLE_EXCE_HANDLING);
    printf("    - Memory64 via WASM_ENABLE_MEMORY64: %u\n",
           WASM_ENABLE_MEMORY64);
    printf("    - Multiple Memory via WASM_ENABLE_MULTI_MEMORY: %u\n",
           WASM_ENABLE_MULTI_MEMORY);
    printf("    - Reference Types via WASM_ENABLE_REF_TYPES: %u\n",
           WASM_ENABLE_REF_TYPES);
    printf("    - Reference-Typed Strings via WASM_ENABLE_REF_TYPES: %u\n",
           WASM_ENABLE_REF_TYPES);
    printf("    - Tail Call via WASM_ENABLE_TAIL_CALL: %u\n",
           WASM_ENABLE_TAIL_CALL);
    printf("    - Threads via WASM_ENABLE_SHARED_MEMORY: %u\n",
           WASM_ENABLE_SHARED_MEMORY);
    printf("    - Typed Function References via WASM_ENABLE_GC: %u\n",
           WASM_ENABLE_GC);
    printf("  Unsupported (>= Phase4):\n");
    printf("    - Branch Hinting\n");
    printf("    - Custom Annotation Syntax in the Text Format\n");
    printf("    - Exception handling\n");
    printf("    - Extended Constant Expressions\n");
    printf("    - Import/Export of Mutable Globals\n");
    printf("    - JS String Builtins\n");
    printf("    - Relaxed SIMD\n");
}
