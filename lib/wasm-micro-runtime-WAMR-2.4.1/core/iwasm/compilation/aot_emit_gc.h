/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_EMIT_GC_H_
#define _AOT_EMIT_GC_H_

#include "aot_compiler.h"
#include "aot_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

#if WASM_ENABLE_GC != 0

bool
aot_call_aot_create_func_obj(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef func_idx, LLVMValueRef *p_gc_obj);

bool
aot_call_aot_obj_is_instance_of(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx, LLVMValueRef gc_obj,
                                LLVMValueRef heap_type, LLVMValueRef *castable);

bool
aot_call_wasm_obj_is_type_of(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                             LLVMValueRef gc_obj, LLVMValueRef heap_type,
                             LLVMValueRef *castable);

bool
aot_call_aot_rtt_type_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          LLVMValueRef type_index, LLVMValueRef *rtt_type);

bool
aot_compile_op_ref_as_non_null(AOTCompContext *comp_ctx,
                               AOTFuncContext *func_ctx);

bool
aot_compile_op_struct_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 type_index, bool init_with_default);

bool
aot_compile_op_struct_get(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 type_index, uint32 field_idx, bool sign);

bool
aot_compile_op_struct_set(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 type_index, uint32 field_idx);

bool
aot_compile_op_array_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 type_index, bool init_with_default,
                         bool fixed_size, uint32 array_len);

bool
aot_compile_op_array_new_data(AOTCompContext *comp_ctx,
                              AOTFuncContext *func_ctx, uint32 type_index,
                              uint32 data_seg_index);

bool
aot_array_obj_length(AOTCompContext *comp_ctx, LLVMValueRef array_obj,
                     LLVMValueRef *p_array_len);

bool
aot_array_obj_elem_addr(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        LLVMValueRef array_obj, LLVMValueRef elem_idx,
                        LLVMValueRef *p_elem_data, uint8 array_elem_type);

bool
aot_compile_op_array_get(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 type_index, bool sign);

bool
aot_compile_op_array_set(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                         uint32 type_index);

bool
aot_compile_op_array_fill(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 type_index);

bool
aot_compile_op_array_copy(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                          uint32 type_index, uint32 src_type_index);

bool
aot_compile_op_array_len(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_op_i31_new(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);

bool
aot_compile_op_i31_get(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                       bool sign);

bool
aot_compile_op_ref_test(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        int32 heap_type, bool nullable);

bool
aot_compile_op_ref_cast(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        int32 heap_type, bool nullable);

bool
aot_compile_op_extern_internalize(AOTCompContext *comp_ctx,
                                  AOTFuncContext *func_ctx);

bool
aot_compile_op_extern_externalize(AOTCompContext *comp_ctx,
                                  AOTFuncContext *func_ctx);

#endif

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_EMIT_GC_H_ */
