/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_LLVM_H_
#define _AOT_LLVM_H_

#include "aot.h"
#include "llvm/Config/llvm-config.h"
#include "llvm-c/Types.h"
#include "llvm-c/Target.h"
#include "llvm-c/Core.h"
#include "llvm-c/Object.h"
#include "llvm-c/OrcEE.h"
#include "llvm-c/ExecutionEngine.h"
#include "llvm-c/Analysis.h"
#include "llvm-c/BitWriter.h"
#if LLVM_VERSION_MAJOR < 17
#include "llvm-c/Transforms/Utils.h"
#include "llvm-c/Transforms/Scalar.h"
#include "llvm-c/Transforms/Vectorize.h"
#include "llvm-c/Transforms/PassManagerBuilder.h"
#include "llvm-c/Initialization.h"
#endif

#include "llvm-c/Orc.h"
#include "llvm-c/Error.h"
#include "llvm-c/Support.h"

#include "llvm-c/TargetMachine.h"
#include "llvm-c/LLJIT.h"
#if WASM_ENABLE_DEBUG_AOT != 0
#include "llvm-c/DebugInfo.h"
#endif

#include "aot_orc_extra.h"
#include "aot_comp_option.h"

#if defined(_WIN32) || defined(_WIN32_)
#include <io.h>
#define access _access
/* On windows there is no X_OK flag to check for executablity, only check for
 * existence */
#ifdef X_OK
#undef X_OK
#endif
#define X_OK 00
#define unlink _unlink
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if LLVM_VERSION_MAJOR < 14
#define LLVMBuildLoad2(builder, type, value, name) \
    LLVMBuildLoad(builder, value, name)

#define LLVMBuildCall2(builder, type, func, args, num_args, name) \
    LLVMBuildCall(builder, func, args, num_args, name)

#define LLVMBuildInBoundsGEP2(builder, type, ptr, indices, num_indices, name) \
    LLVMBuildInBoundsGEP(builder, ptr, indices, num_indices, name)
#else
/* Opaque pointer type */
#define OPQ_PTR_TYPE INT8_PTR_TYPE
#endif

#ifndef NDEBUG
#undef DEBUG_PASS
#undef DUMP_MODULE
// #define DEBUG_PASS
// #define DUMP_MODULE
#else
#undef DEBUG_PASS
#undef DUMP_MODULE
#endif

struct AOTValueSlot;

/**
 * Value in the WASM operation stack, each stack element
 * is an LLVM value
 */
typedef struct AOTValue {
    struct AOTValue *next;
    struct AOTValue *prev;
    LLVMValueRef value;
    uint64 const_value; /* valid if is_const is true */
    uint32 local_idx;
    /* VALUE_TYPE_I32/I64/F32/F64/VOID */
    uint8 type;
    bool is_local;
    bool is_const;
} AOTValue;

/**
 * Value stack, represents stack elements in a WASM block
 */
typedef struct AOTValueStack {
    AOTValue *value_list_head;
    AOTValue *value_list_end;
} AOTValueStack;

/* Record information of a value slot of local variable or stack
   during translation */
typedef struct AOTValueSlot {
    /* The LLVM value of this slot */
    LLVMValueRef value;

    /* The value type of this slot */
    uint8 type;

    /* The dirty bit of the value slot. It's set if the value in
       register is newer than the value in memory. */
    uint32 dirty : 1;

    /* Whether the new value in register is a reference, which is valid
       only when the dirty bit is set. */
    uint32 ref : 1;

    /* Committed reference flag:
         0: uncommitted, 1: not-reference, 2: reference */
    uint32 committed_ref : 2;
} AOTValueSlot;

/* Frame information for translation */
typedef struct AOTCompFrame {
    /* The current compilation context */
    struct AOTCompContext *comp_ctx;
    /* The current function context */
    struct AOTFuncContext *func_ctx;
    /* The current instruction pointer which is being compiled */
    const uint8 *frame_ip;

    /* Max local slot number */
    uint32 max_local_cell_num;

    /* Max operand stack slot number */
    uint32 max_stack_cell_num;

    /* Size of current AOTFrame/WASMInterpFrame */
    uint32 cur_frame_size;

    /* Stack top pointer */
    AOTValueSlot *sp;

    /* Local variables + stack operands */
    AOTValueSlot lp[1];
} AOTCompFrame;

typedef struct AOTBlock {
    struct AOTBlock *next;
    struct AOTBlock *prev;

    /* Block index */
    uint32 block_index;
    /* LABEL_TYPE_BLOCK/LOOP/IF/FUNCTION */
    uint32 label_type;
    /* Whether it is reachable */
    bool is_reachable;
    /* Whether skip translation of wasm else branch */
    bool skip_wasm_code_else;

    /* code of else opcode of this block, if it is a IF block  */
    uint8 *wasm_code_else;
    /* code end of this block */
    uint8 *wasm_code_end;

    /* LLVM label points to code begin */
    LLVMBasicBlockRef llvm_entry_block;
    /* LLVM label points to code else */
    LLVMBasicBlockRef llvm_else_block;
    /* LLVM label points to code end */
    LLVMBasicBlockRef llvm_end_block;

    /* WASM operation stack */
    AOTValueStack value_stack;

    /* Param count/types/PHIs of this block */
    uint32 param_count;
    uint8 *param_types;
    LLVMValueRef *param_phis;
    LLVMValueRef *else_param_phis;

    /* Result count/types/PHIs of this block */
    uint32 result_count;
    uint8 *result_types;
    LLVMValueRef *result_phis;

    /* The begin frame stack pointer of this block */
    AOTValueSlot *frame_sp_begin;
    /* The max frame stack pointer that br/br_if/br_table/br_on_xxx
       opcodes ever reached when they jumped to the end this block */
    AOTValueSlot *frame_sp_max_reached;
} AOTBlock;

/**
 * Block stack, represents WASM block stack elements
 */
typedef struct AOTBlockStack {
    AOTBlock *block_list_head;
    AOTBlock *block_list_end;
    /* Current block index of each block type */
    uint32 block_index[3];
} AOTBlockStack;

typedef struct AOTCheckedAddr {
    struct AOTCheckedAddr *next;
    uint32 local_idx;
    uint64 offset;
    uint32 bytes;
} AOTCheckedAddr, *AOTCheckedAddrList;

typedef struct AOTMemInfo {
    LLVMValueRef mem_base_addr;
    LLVMValueRef mem_data_size_addr;
    LLVMValueRef mem_cur_page_count_addr;
    LLVMValueRef mem_bound_check_1byte;
    LLVMValueRef mem_bound_check_2bytes;
    LLVMValueRef mem_bound_check_4bytes;
    LLVMValueRef mem_bound_check_8bytes;
    LLVMValueRef mem_bound_check_16bytes;
} AOTMemInfo;

typedef struct AOTFuncContext {
    AOTFunc *aot_func;
    LLVMValueRef func;
    LLVMValueRef precheck_func;
    LLVMTypeRef func_type;
    LLVMModuleRef module;
    AOTBlockStack block_stack;

    LLVMValueRef exec_env;
    LLVMValueRef aot_inst;
    LLVMValueRef argv_buf;
    LLVMValueRef native_stack_bound;
    LLVMValueRef native_stack_top_min_addr;
    LLVMValueRef aux_stack_bound;
    LLVMValueRef aux_stack_bottom;
    LLVMValueRef native_symbol;
    LLVMValueRef func_ptrs;

    AOTMemInfo *mem_info;

    LLVMValueRef cur_exception;

    LLVMValueRef cur_frame;
    LLVMValueRef cur_frame_ptr;
    LLVMValueRef wasm_stack_top_bound;
    LLVMValueRef wasm_stack_top_ptr;

    bool mem_space_unchanged;
    AOTCheckedAddrList checked_addr_list;

    /* The last accessed shared heap info */
    LLVMValueRef shared_heap_base_addr_adj;
    LLVMValueRef shared_heap_start_off;
    LLVMValueRef shared_heap_end_off;
    /* The start offset of the head of shared heap chain */
    LLVMValueRef shared_heap_head_start_off;

    LLVMBasicBlockRef got_exception_block;
    LLVMBasicBlockRef func_return_block;
    LLVMValueRef exception_id_phi;
    /* current ip when exception is thrown */
    LLVMValueRef exception_ip_phi;
    LLVMValueRef func_type_indexes;
#if WASM_ENABLE_DEBUG_AOT != 0
    LLVMMetadataRef debug_func;
#endif

    unsigned int stack_consumption_for_func_call;

    LLVMValueRef locals[1];
} AOTFuncContext;

typedef struct AOTLLVMTypes {
    LLVMTypeRef int1_type;
    LLVMTypeRef int8_type;
    LLVMTypeRef int16_type;
    LLVMTypeRef int32_type;
    LLVMTypeRef int64_type;
    LLVMTypeRef intptr_t_type;
    LLVMTypeRef size_t_type;
    LLVMTypeRef float32_type;
    LLVMTypeRef float64_type;
    LLVMTypeRef void_type;

    LLVMTypeRef int8_ptr_type;
    LLVMTypeRef int8_pptr_type;
    LLVMTypeRef int16_ptr_type;
    LLVMTypeRef int32_ptr_type;
    LLVMTypeRef int64_ptr_type;
    LLVMTypeRef intptr_t_ptr_type;
    LLVMTypeRef float32_ptr_type;
    LLVMTypeRef float64_ptr_type;

    LLVMTypeRef v128_type;
    LLVMTypeRef v128_ptr_type;
    LLVMTypeRef i8x16_vec_type;
    LLVMTypeRef i16x8_vec_type;
    LLVMTypeRef i32x4_vec_type;
    LLVMTypeRef i64x2_vec_type;
    LLVMTypeRef f32x4_vec_type;
    LLVMTypeRef f64x2_vec_type;

    LLVMTypeRef int8_ptr_type_gs;
    LLVMTypeRef int16_ptr_type_gs;
    LLVMTypeRef int32_ptr_type_gs;
    LLVMTypeRef int64_ptr_type_gs;
    LLVMTypeRef float32_ptr_type_gs;
    LLVMTypeRef float64_ptr_type_gs;
    LLVMTypeRef v128_ptr_type_gs;

    LLVMTypeRef i1x2_vec_type;

    LLVMTypeRef meta_data_type;

    LLVMTypeRef funcref_type;
    LLVMTypeRef externref_type;
    LLVMTypeRef gc_ref_type;
    LLVMTypeRef gc_ref_ptr_type;
} AOTLLVMTypes;

typedef struct AOTLLVMConsts {
    LLVMValueRef i1_zero;
    LLVMValueRef i1_one;
    LLVMValueRef i8_zero;
    LLVMValueRef i8_one;
    LLVMValueRef i32_zero;
    LLVMValueRef i64_zero;
    LLVMValueRef f32_zero;
    LLVMValueRef f64_zero;
    LLVMValueRef i32_one;
    LLVMValueRef i32_two;
    LLVMValueRef i32_three;
    LLVMValueRef i32_four;
    LLVMValueRef i32_five;
    LLVMValueRef i32_six;
    LLVMValueRef i32_seven;
    LLVMValueRef i32_eight;
    LLVMValueRef i32_nine;
    LLVMValueRef i32_ten;
    LLVMValueRef i32_eleven;
    LLVMValueRef i32_twelve;
    LLVMValueRef i32_thirteen;
    LLVMValueRef i32_fourteen;
    LLVMValueRef i32_fifteen;
    LLVMValueRef i32_neg_one;
    LLVMValueRef i64_neg_one;
    LLVMValueRef i32_min;
    LLVMValueRef i64_min;
    LLVMValueRef i32_31;
    LLVMValueRef i32_32;
    LLVMValueRef i64_63;
    LLVMValueRef i64_64;
    LLVMValueRef i8x16_vec_zero;
    LLVMValueRef i16x8_vec_zero;
    LLVMValueRef i32x4_vec_zero;
    LLVMValueRef i64x2_vec_zero;
    LLVMValueRef f32x4_vec_zero;
    LLVMValueRef f64x2_vec_zero;
    LLVMValueRef i8x16_undef;
    LLVMValueRef i16x8_undef;
    LLVMValueRef i32x4_undef;
    LLVMValueRef i64x2_undef;
    LLVMValueRef f32x4_undef;
    LLVMValueRef f64x2_undef;
    LLVMValueRef i32x16_zero;
    LLVMValueRef i32x8_zero;
    LLVMValueRef i32x4_zero;
    LLVMValueRef i32x2_zero;
    LLVMValueRef gc_ref_null;
    LLVMValueRef i8_ptr_null;
} AOTLLVMConsts;

/**
 * Compiler context
 */
typedef struct AOTCompContext {
    const AOTCompData *comp_data;

    /* LLVM variables required to emit LLVM IR */
    LLVMContextRef context;
    LLVMBuilderRef builder;
#if WASM_ENABLE_DEBUG_AOT
    LLVMDIBuilderRef debug_builder;
    LLVMMetadataRef debug_file;
    LLVMMetadataRef debug_comp_unit;
#endif
    LLVMTargetMachineRef target_machine;
    char *target_cpu;
    char target_arch[16];
    unsigned pointer_size;

    /* Hardware intrinsic compatibility flags */
    uint64 flags[8];

    /* required by JIT */
    LLVMOrcLLLazyJITRef orc_jit;
    LLVMOrcThreadSafeContextRef orc_thread_safe_context;

    LLVMModuleRef module;

    bool is_jit_mode;

    /* AOT indirect mode flag & symbol list */
    bool is_indirect_mode;
    bh_list native_symbols;

    /* Bulk memory feature */
    bool enable_bulk_memory;

    /* Boundary Check */
    bool enable_bound_check;

    /* Native stack boundary Check */
    bool enable_stack_bound_check;

    /* Native stack usage estimation */
    bool enable_stack_estimation;

    /* 128-bit SIMD */
    bool enable_simd;

    /* Auxiliary stack overflow/underflow check */
    bool enable_aux_stack_check;

    /* Generate auxiliary stack frame */
    AOTStackFrameType aux_stack_frame_type;

    /* Auxiliary call stack features */
    AOTCallStackFeatures call_stack_features;

    /* Function performance profiling */
    bool enable_perf_profiling;

    /* Memory usage profiling */
    bool enable_memory_profiling;

    /* Thread Manager */
    bool enable_thread_mgr;

    /* Tail Call */
    bool enable_tail_call;

    /* Reference Types */
    bool enable_ref_types;

    /* Disable LLVM built-in intrinsics */
    bool disable_llvm_intrinsics;

    /* Disable LLVM jump tables */
    bool disable_llvm_jump_tables;

    /* Disable LLVM link time optimization */
    bool disable_llvm_lto;

    /* Enable LLVM PGO (Profile-Guided Optimization) */
    bool enable_llvm_pgo;

    /* Enable extended constant expression */
    bool enable_extended_const;

    /* Treat unknown import function as wasm-c-api import function
       and allow to directly invoke it from AOT/JIT code */
    bool quick_invoke_c_api_import;

    /* Use profile file collected by LLVM PGO */
    char *use_prof_file;

    /* Enable to use segment register as the base addr
       of linear memory for load/store operations */
    bool enable_segue_i32_load;
    bool enable_segue_i64_load;
    bool enable_segue_f32_load;
    bool enable_segue_f64_load;
    bool enable_segue_v128_load;
    bool enable_segue_i32_store;
    bool enable_segue_i64_store;
    bool enable_segue_f32_store;
    bool enable_segue_f64_store;
    bool enable_segue_v128_store;

    /* Whether optimize the JITed code */
    bool optimize;

    bool emit_frame_pointer;

    /* Enable GC */
    bool enable_gc;

    bool enable_shared_heap;
    bool enable_shared_chain;

    uint32 opt_level;
    uint32 size_level;

    /* LLVM floating-point rounding mode metadata */
    LLVMValueRef fp_rounding_mode;

    /* LLVM floating-point exception behavior metadata */
    LLVMValueRef fp_exception_behavior;

    /* a global array to store stack sizes */
    LLVMTypeRef stack_sizes_type;
    LLVMValueRef stack_sizes;
    uint32 *jit_stack_sizes; /* for JIT */

    /* LLVM data types */
    AOTLLVMTypes basic_types;
    LLVMTypeRef exec_env_type;
    LLVMTypeRef aot_inst_type;

    /* LLVM const values */
    AOTLLVMConsts llvm_consts;

    /* Function contexts */
    AOTFuncContext **func_ctxes;
    uint32 func_ctx_count;
    char **custom_sections_wp;
    uint32 custom_sections_count;

    /* 3rd-party toolchains */
    /* External llc compiler, if specified, wamrc will emit the llvm-ir file and
     * invoke the llc compiler to generate object file.
     * This can be used when we want to benefit from the optimization of other
     * LLVM based toolchains */
    const char *external_llc_compiler;
    const char *llc_compiler_flags;
    /* External asm compiler, if specified, wamrc will emit the text-based
     * assembly file (.s) and invoke the llc compiler to generate object file.
     * This will be useful when the upstream LLVM doesn't support to emit object
     * file for some architecture (such as arc) */
    const char *external_asm_compiler;
    const char *asm_compiler_flags;

    const char *stack_usage_file;
    char stack_usage_temp_file[64];
    const char *llvm_passes;
    const char *builtin_intrinsics;

    /* Current frame information for translation */
    AOTCompFrame *aot_frame;
} AOTCompContext;

enum {
    AOT_FORMAT_FILE,
    AOT_OBJECT_FILE,
    AOT_LLVMIR_UNOPT_FILE,
    AOT_LLVMIR_OPT_FILE,
};

bool
aot_compiler_init(void);

void
aot_compiler_destroy(void);

AOTCompContext *
aot_create_comp_context(const AOTCompData *comp_data, aot_comp_option_t option);

void
aot_destroy_comp_context(AOTCompContext *comp_ctx);

int32
aot_get_native_symbol_index(AOTCompContext *comp_ctx, const char *symbol);

bool
aot_compile_wasm(AOTCompContext *comp_ctx);

uint8 *
aot_emit_elf_file(AOTCompContext *comp_ctx, uint32 *p_elf_file_size);

void
aot_destroy_elf_file(uint8 *elf_file);

void
aot_value_stack_push(const AOTCompContext *comp_ctx, AOTValueStack *stack,
                     AOTValue *value);

AOTValue *
aot_value_stack_pop(const AOTCompContext *comp_ctx, AOTValueStack *stack);

void
aot_value_stack_destroy(AOTCompContext *comp_ctx, AOTValueStack *stack);

void
aot_block_stack_push(AOTBlockStack *stack, AOTBlock *block);

AOTBlock *
aot_block_stack_pop(AOTBlockStack *stack);

void
aot_block_stack_destroy(AOTCompContext *comp_ctx, AOTBlockStack *stack);

void
aot_block_destroy(AOTCompContext *comp_ctx, AOTBlock *block);

LLVMTypeRef
wasm_type_to_llvm_type(const AOTCompContext *comp_ctx,
                       const AOTLLVMTypes *llvm_types, uint8 wasm_type);

bool
aot_checked_addr_list_add(AOTFuncContext *func_ctx, uint32 local_idx,
                          uint64 offset, uint32 bytes);

void
aot_checked_addr_list_del(AOTFuncContext *func_ctx, uint32 local_idx);

bool
aot_checked_addr_list_find(AOTFuncContext *func_ctx, uint32 local_idx,
                           uint64 offset, uint32 bytes);

void
aot_checked_addr_list_destroy(AOTFuncContext *func_ctx);

bool
aot_build_zero_function_ret(const AOTCompContext *comp_ctx,
                            AOTFuncContext *func_ctx, AOTFuncType *func_type);

LLVMValueRef
aot_call_llvm_intrinsic(const AOTCompContext *comp_ctx,
                        const AOTFuncContext *func_ctx, const char *intrinsic,
                        LLVMTypeRef ret_type, LLVMTypeRef *param_types,
                        int param_count, ...);

LLVMValueRef
aot_call_llvm_intrinsic_v(const AOTCompContext *comp_ctx,
                          const AOTFuncContext *func_ctx, const char *intrinsic,
                          LLVMTypeRef ret_type, LLVMTypeRef *param_types,
                          int param_count, va_list param_value_list);

LLVMValueRef
aot_get_func_from_table(const AOTCompContext *comp_ctx, LLVMValueRef base,
                        LLVMTypeRef func_type, int32 index);

LLVMValueRef
aot_load_const_from_table(AOTCompContext *comp_ctx, LLVMValueRef base,
                          const WASMValue *value, uint8 value_type);

bool
aot_check_simd_compatibility(const char *arch_c_str, const char *cpu_c_str);

void
aot_apply_llvm_new_pass_manager(AOTCompContext *comp_ctx, LLVMModuleRef module);

void
aot_handle_llvm_errmsg(const char *string, LLVMErrorRef err);

char *
aot_compress_aot_func_names(AOTCompContext *comp_ctx, uint32 *p_size);

bool
aot_set_cond_br_weights(AOTCompContext *comp_ctx, LLVMValueRef cond_br,
                        int32 weights_true, int32 weights_false);

bool
aot_target_precheck_can_use_musttail(const AOTCompContext *comp_ctx);

unsigned int
aot_estimate_stack_usage_for_function_call(const AOTCompContext *comp_ctx,
                                           const AOTFuncType *callee_func_type);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_LLVM_H_ */
