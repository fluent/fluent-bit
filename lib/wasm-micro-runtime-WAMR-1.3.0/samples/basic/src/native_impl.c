/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_platform.h"
#include "wasm_export.h"
#include "math.h"

// The first parameter is not exec_env because it is invoked by native funtions
void
reverse(char *str, int len)
{
    int i = 0, j = len - 1, temp;
    while (i < j) {
        temp = str[i];
        str[i] = str[j];
        str[j] = temp;
        i++;
        j--;
    }
}

// The first parameter exec_env must be defined using type wasm_exec_env_t
// which is the calling convention for exporting native API by WAMR.
//
// Converts a given integer x to string str[].
// digit is the number of digits required in the output.
// If digit is more than the number of digits in x,
// then 0s are added at the beginning.
int
intToStr(wasm_exec_env_t exec_env, int x, char *str, int str_len, int digit)
{
    int i = 0;

    printf("calling into native function: %s\n", __FUNCTION__);

    while (x) {
        // native is responsible for checking the str_len overflow
        if (i >= str_len) {
            return -1;
        }
        str[i++] = (x % 10) + '0';
        x = x / 10;
    }

    // If number of digits required is more, then
    // add 0s at the beginning
    while (i < digit) {
        if (i >= str_len) {
            return -1;
        }
        str[i++] = '0';
    }

    reverse(str, i);

    if (i >= str_len)
        return -1;
    str[i] = '\0';
    return i;
}

int
get_pow(wasm_exec_env_t exec_env, int x, int y)
{
    printf("calling into native function: %s\n", __FUNCTION__);
    return (int)pow(x, y);
}

int32_t
calculate_native(wasm_exec_env_t exec_env, int32_t n, int32_t func1,
                 int32_t func2)
{
    printf("calling into native function: %s, n=%d, func1=%d, func2=%d\n",
           __FUNCTION__, n, func1, func2);

    uint32_t argv[] = { n };
    if (!wasm_runtime_call_indirect(exec_env, func1, 1, argv)) {
        printf("call func1 failed\n");
        return 0xDEAD;
    }

    uint32_t n1 = argv[0];
    printf("call func1 and return n1=%d\n", n1);

    if (!wasm_runtime_call_indirect(exec_env, func2, 1, argv)) {
        printf("call func2 failed\n");
        return 0xDEAD;
    }

    uint32_t n2 = argv[0];
    printf("call func2 and return n2=%d\n", n2);
    return n1 + n2;
}
