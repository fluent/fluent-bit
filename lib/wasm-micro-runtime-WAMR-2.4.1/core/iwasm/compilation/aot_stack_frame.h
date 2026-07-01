/*
 * Copyright (C) 2024 Amazon Inc.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_STACK_FRAME_H_
#define _AOT_STACK_FRAME_H_

#include "platform_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* The non-imported function index of current function */
    uint32 func_index;

    /* Instruction pointer: offset to the bytecode array */
    uint32 ip_offset;
} AOTTinyFrame;

#ifdef __cplusplus
}
#endif

#endif
