/*
 * Copyright (C) 2024 Midokura Japan KK.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#define __STDC_WANT_LIB_EXT1__ 1

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "wasm_export.h"
#include "bh_platform.h"

/*
 * this "nest" var has two purposes:
 * - prevent tail-call optimization
 * - detect possible resource leak
 */
unsigned int nest = 0;
ptrdiff_t prev_diff = 0;

uint32_t
call_indirect(wasm_exec_env_t exec_env, uint32_t funcidx, uint32_t x)
{
    uint32_t argv[1] = {
        x,
    };
    uint32_t argc = 1;
    if (!wasm_runtime_call_indirect(exec_env, funcidx, argc, argv)) {
        /* failed */
        return 0;
    }
    return argv[0];
}

uint32_t
host_consume_stack_and_call_indirect(wasm_exec_env_t exec_env, uint32_t funcidx,
                                     uint32_t x, uint32_t stack)
{
    void *boundary = os_thread_get_stack_boundary();
    void *fp = __builtin_frame_address(0);
    ptrdiff_t diff = fp - boundary;
    /*
     * because this function performs recursive calls depending on
     * the user input, we don't have an apriori knowledge how much stack
     * we need. perform the overflow check on each iteration.
     */
    if (!wasm_runtime_detect_native_stack_overflow(exec_env)) {
        return 0;
    }
    if (diff > stack) {
        prev_diff = diff;
        nest++;
        uint32_t ret =
            host_consume_stack_and_call_indirect(exec_env, funcidx, x, stack);
        nest--;
        return ret;
    }
    return call_indirect(exec_env, funcidx, x);
}

__attribute__((noinline)) static uint32_t
consume_stack1(wasm_exec_env_t exec_env, void *base, uint32_t stack)
#if defined(__clang__)
    __attribute__((disable_tail_calls))
#endif
{
    void *fp = __builtin_frame_address(0);
    ptrdiff_t diff = (unsigned char *)base - (unsigned char *)fp;
    assert(diff > 0);
    if (diff > stack) {
        return diff;
    }
    return consume_stack1(exec_env, base, stack);
}

uint32_t
host_consume_stack(wasm_exec_env_t exec_env, uint32_t stack)
{
    /*
     * this function consumes a bit more than "stack" bytes.
     */
    if (!wasm_runtime_detect_native_stack_overflow_size(exec_env, 64 + stack)) {
        return 0;
    }
    void *base = __builtin_frame_address(0);
    return consume_stack1(exec_env, base, stack);
}
