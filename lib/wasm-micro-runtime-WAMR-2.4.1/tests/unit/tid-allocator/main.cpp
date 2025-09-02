/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <gtest/gtest.h>
#include "wasm_runtime_common.h"

int
main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    if (!wasm_runtime_init()) {
        return -1;
    }

    int ret = RUN_ALL_TESTS();
    wasm_runtime_destroy();

    return ret;
}