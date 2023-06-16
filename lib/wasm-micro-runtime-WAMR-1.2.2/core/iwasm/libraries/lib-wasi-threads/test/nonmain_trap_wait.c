/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef __wasi__
#error This example only compiles to WASM/WASI target
#endif

#include "common.h"

int
main(int argc, char **argv)
{
    test_termination(true, false, BLOCKING_TASK_ATOMIC_WAIT);
}