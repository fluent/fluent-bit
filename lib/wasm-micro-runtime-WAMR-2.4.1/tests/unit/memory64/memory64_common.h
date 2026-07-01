/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef UNIT_TEST_MEMORY64_COMMON_H
#define UNIT_TEST_MEMORY64_COMMON_H

#include "test_helper.h"
#include "gtest/gtest.h"

#include "platform_common.h"
#include "wasm_runtime_common.h"
#include "bh_read_file.h"
#include "wasm_runtime.h"
#include "bh_platform.h"
#include "wasm_export.h"
#include <unordered_map>
// #include "aot_runtime.h"

namespace {

std::vector<RunningMode> running_mode_supported = { Mode_Interp,
#if WASM_ENABLE_FAST_JIT != 0
                                                    Mode_Fast_JIT,
#endif
#if WASM_ENABLE_JIT != 0
                                                    Mode_LLVM_JIT,
#endif
#if WASM_ENABLE_JIT != 0 && WASM_ENABLE_FAST_JIT != 0 \
    && WASM_ENABLE_LAZY_JIT != 0
                                                    Mode_Multi_Tier_JIT
#endif
};

static inline uint64
GET_U64_FROM_ADDR(uint32 *addr)
{
    union {
        uint64 val;
        uint32 parts[2];
    } u;
    u.parts[0] = addr[0];
    u.parts[1] = addr[1];
    return u.val;
}

static inline void
PUT_U64_TO_ADDR(uint32 *addr, uint64 value)
{
    uint32 *addr_u32 = (uint32 *)(addr);
    union {
        float64 val;
        uint32 parts[2];
    } u;
    u.val = (value);
    addr_u32[0] = u.parts[0];
    addr_u32[1] = u.parts[1];
}

}

#endif // UNIT_TEST_MEMORY64_COMMON_H
