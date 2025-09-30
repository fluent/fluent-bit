/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int32_t
add_native(int32_t n);

int32_t
calculate(int32_t n)
{
    printf("calling into WASM function: %s\n", __FUNCTION__);
    return add_native(n);
}
