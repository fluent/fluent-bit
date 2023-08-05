/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _JIT_EMIT_MEMORY_H_
#define _JIT_EMIT_MEMORY_H_

#include "../jit_compiler.h"
#if WASM_ENABLE_SHARED_MEMORY != 0
#include "../../common/wasm_shared_memory.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

bool
jit_compile_op_i32_load(JitCompContext *cc, uint32 align, uint32 offset,
                        uint32 bytes, bool sign, bool atomic);

bool
jit_compile_op_i64_load(JitCompContext *cc, uint32 align, uint32 offset,
                        uint32 bytes, bool sign, bool atomic);

bool
jit_compile_op_f32_load(JitCompContext *cc, uint32 align, uint32 offset);

bool
jit_compile_op_f64_load(JitCompContext *cc, uint32 align, uint32 offset);

bool
jit_compile_op_i32_store(JitCompContext *cc, uint32 align, uint32 offset,
                         uint32 bytes, bool atomic);

bool
jit_compile_op_i64_store(JitCompContext *cc, uint32 align, uint32 offset,
                         uint32 bytes, bool atomic);

bool
jit_compile_op_f32_store(JitCompContext *cc, uint32 align, uint32 offset);

bool
jit_compile_op_f64_store(JitCompContext *cc, uint32 align, uint32 offset);

bool
jit_compile_op_memory_size(JitCompContext *cc, uint32 mem_idx);

bool
jit_compile_op_memory_grow(JitCompContext *cc, uint32 mem_idx);

#if WASM_ENABLE_BULK_MEMORY != 0
bool
jit_compile_op_memory_init(JitCompContext *cc, uint32 mem_idx, uint32 seg_idx);

bool
jit_compile_op_data_drop(JitCompContext *cc, uint32 seg_idx);

bool
jit_compile_op_memory_copy(JitCompContext *cc, uint32 src_mem_idx,
                           uint32 dst_mem_idx);

bool
jit_compile_op_memory_fill(JitCompContext *cc, uint32 mem_idx);
#endif

#if WASM_ENABLE_SHARED_MEMORY != 0
bool
jit_compile_op_atomic_rmw(JitCompContext *cc, uint8 atomic_op, uint8 op_type,
                          uint32 align, uint32 offset, uint32 bytes);

bool
jit_compile_op_atomic_cmpxchg(JitCompContext *cc, uint8 op_type, uint32 align,
                              uint32 offset, uint32 bytes);

bool
jit_compile_op_atomic_wait(JitCompContext *cc, uint8 op_type, uint32 align,
                           uint32 offset, uint32 bytes);

bool
jit_compiler_op_atomic_notify(JitCompContext *cc, uint32 align, uint32 offset,
                              uint32 bytes);

bool
jit_compiler_op_atomic_fence(JitCompContext *cc);
#endif

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _JIT_EMIT_MEMORY_H_ */
