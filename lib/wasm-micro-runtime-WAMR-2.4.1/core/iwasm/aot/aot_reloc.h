/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_RELOC_H_
#define _AOT_RELOC_H_

#include "aot_runtime.h"
#include "aot_intrinsic.h"

#if WASM_ENABLE_STRINGREF != 0
#include "string_object.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *symbol_name;
    void *symbol_addr;
} SymbolMap;

/* clang-format off */
#define REG_SYM(symbol) { #symbol, (void *)symbol }

#if WASM_ENABLE_BULK_MEMORY != 0
#define REG_BULK_MEMORY_SYM()             \
    REG_SYM(aot_memory_init),             \
    REG_SYM(aot_data_drop),
#else
#define REG_BULK_MEMORY_SYM()
#endif

#if WASM_ENABLE_SHARED_MEMORY != 0
#include "wasm_shared_memory.h"
#define REG_ATOMIC_WAIT_SYM()             \
    REG_SYM(wasm_runtime_atomic_wait),    \
    REG_SYM(wasm_runtime_atomic_notify),
#else
#define REG_ATOMIC_WAIT_SYM()
#endif

#if WASM_ENABLE_REF_TYPES != 0
#define REG_REF_TYPES_SYM()               \
    REG_SYM(aot_drop_table_seg),          \
    REG_SYM(aot_table_init),              \
    REG_SYM(aot_table_copy),              \
    REG_SYM(aot_table_fill),              \
    REG_SYM(aot_table_grow),
#else
#define REG_REF_TYPES_SYM()
#endif

#if WASM_ENABLE_AOT_STACK_FRAME != 0
#define REG_AOT_TRACE_SYM()               \
    REG_SYM(aot_alloc_frame),             \
    REG_SYM(aot_free_frame),              \
    REG_SYM(aot_frame_update_profile_info),
#else
#define REG_AOT_TRACE_SYM()
#endif

#if WASM_ENABLE_AOT_INTRINSICS != 0
#define REG_INTRINSIC_SYM()               \
    REG_SYM(aot_intrinsic_fabs_f32),      \
    REG_SYM(aot_intrinsic_fabs_f64),      \
    REG_SYM(aot_intrinsic_floor_f32),     \
    REG_SYM(aot_intrinsic_floor_f64),     \
    REG_SYM(aot_intrinsic_ceil_f32),      \
    REG_SYM(aot_intrinsic_ceil_f64),      \
    REG_SYM(aot_intrinsic_trunc_f32),     \
    REG_SYM(aot_intrinsic_trunc_f64),     \
    REG_SYM(aot_intrinsic_rint_f32),      \
    REG_SYM(aot_intrinsic_rint_f64),      \
    REG_SYM(aot_intrinsic_sqrt_f32),      \
    REG_SYM(aot_intrinsic_sqrt_f64),      \
    REG_SYM(aot_intrinsic_copysign_f32),  \
    REG_SYM(aot_intrinsic_copysign_f64),  \
    REG_SYM(aot_intrinsic_fadd_f32),      \
    REG_SYM(aot_intrinsic_fadd_f64),      \
    REG_SYM(aot_intrinsic_fsub_f32),      \
    REG_SYM(aot_intrinsic_fsub_f64),      \
    REG_SYM(aot_intrinsic_fmul_f32),      \
    REG_SYM(aot_intrinsic_fmul_f64),      \
    REG_SYM(aot_intrinsic_fdiv_f32),      \
    REG_SYM(aot_intrinsic_fdiv_f64),      \
    REG_SYM(aot_intrinsic_fmin_f32),      \
    REG_SYM(aot_intrinsic_fmin_f64),      \
    REG_SYM(aot_intrinsic_fmax_f32),      \
    REG_SYM(aot_intrinsic_fmax_f64),      \
    REG_SYM(aot_intrinsic_clz_i32),       \
    REG_SYM(aot_intrinsic_clz_i64),       \
    REG_SYM(aot_intrinsic_ctz_i32),       \
    REG_SYM(aot_intrinsic_ctz_i64),       \
    REG_SYM(aot_intrinsic_popcnt_i32),    \
    REG_SYM(aot_intrinsic_popcnt_i64),    \
    REG_SYM(aot_intrinsic_i32_to_f32),    \
    REG_SYM(aot_intrinsic_u32_to_f32),    \
    REG_SYM(aot_intrinsic_i32_to_f64),    \
    REG_SYM(aot_intrinsic_u32_to_f64),    \
    REG_SYM(aot_intrinsic_i64_to_f32),    \
    REG_SYM(aot_intrinsic_u64_to_f32),    \
    REG_SYM(aot_intrinsic_i64_to_f64),    \
    REG_SYM(aot_intrinsic_u64_to_f64),    \
    REG_SYM(aot_intrinsic_f64_to_f32),    \
    REG_SYM(aot_intrinsic_f32_to_i32),    \
    REG_SYM(aot_intrinsic_f32_to_u32),    \
    REG_SYM(aot_intrinsic_f32_to_i64),    \
    REG_SYM(aot_intrinsic_f32_to_u64),    \
    REG_SYM(aot_intrinsic_f64_to_i32),    \
    REG_SYM(aot_intrinsic_f64_to_u32),    \
    REG_SYM(aot_intrinsic_f64_to_i64),    \
    REG_SYM(aot_intrinsic_f64_to_u64),    \
    REG_SYM(aot_intrinsic_f32_to_f64),    \
    REG_SYM(aot_intrinsic_f32_cmp),       \
    REG_SYM(aot_intrinsic_f64_cmp),       \
    REG_SYM(aot_intrinsic_i64_div_s),     \
    REG_SYM(aot_intrinsic_i64_div_u),     \
    REG_SYM(aot_intrinsic_i64_rem_s),     \
    REG_SYM(aot_intrinsic_i64_rem_u),     \
    REG_SYM(aot_intrinsic_i64_bit_or),    \
    REG_SYM(aot_intrinsic_i64_bit_and),   \
    REG_SYM(aot_intrinsic_i64_mul),       \
    REG_SYM(aot_intrinsic_i64_shl),       \
    REG_SYM(aot_intrinsic_i64_shr_s),     \
    REG_SYM(aot_intrinsic_i64_shr_u),     \
    REG_SYM(aot_intrinsic_i32_div_s),     \
    REG_SYM(aot_intrinsic_i32_div_u),     \
    REG_SYM(aot_intrinsic_i32_rem_s),     \
    REG_SYM(aot_intrinsic_i32_rem_u),
#else
#define REG_INTRINSIC_SYM()
#endif

#if WASM_ENABLE_STATIC_PGO != 0
#define REG_LLVM_PGO_SYM()               \
    { "__llvm_profile_instrument_target", llvm_profile_instrument_target }, \
    { "__llvm_profile_instrument_memop", llvm_profile_instrument_memop },
#else
#define REG_LLVM_PGO_SYM()
#endif

#if WASM_ENABLE_GC != 0
#define REG_GC_SYM()                       \
    REG_SYM(aot_array_init_with_data),     \
    REG_SYM(aot_create_func_obj),          \
    REG_SYM(aot_obj_is_instance_of),       \
    REG_SYM(aot_func_type_is_super_of),    \
    REG_SYM(aot_rtt_type_new),             \
    REG_SYM(wasm_array_obj_copy),          \
    REG_SYM(wasm_array_obj_new),           \
    REG_SYM(wasm_externref_obj_to_internal_obj), \
    REG_SYM(wasm_internal_obj_to_externref_obj), \
    REG_SYM(wasm_obj_is_type_of),          \
    REG_SYM(wasm_struct_obj_new),
#else
#define REG_GC_SYM()
#endif

#if WASM_ENABLE_STRINGREF != 0
#define REG_STRINGREF_SYM()                 \
    REG_SYM(wasm_stringref_obj_new),        \
    REG_SYM(wasm_stringview_wtf8_obj_new),  \
    REG_SYM(wasm_stringview_wtf16_obj_new), \
    REG_SYM(wasm_stringview_iter_obj_new),  \
    REG_SYM(wasm_string_destroy),           \
    REG_SYM(wasm_string_new_const),         \
    REG_SYM(wasm_string_new_with_encoding), \
    REG_SYM(wasm_string_measure),           \
    REG_SYM(wasm_string_wtf16_get_length),  \
    REG_SYM(wasm_string_encode),            \
    REG_SYM(wasm_string_concat),            \
    REG_SYM(wasm_string_eq),                \
    REG_SYM(wasm_string_is_usv_sequence),   \
    REG_SYM(wasm_string_create_view),       \
    REG_SYM(wasm_string_advance),           \
    REG_SYM(wasm_string_slice),             \
    REG_SYM(wasm_string_get_wtf16_codeunit),\
    REG_SYM(wasm_string_next_codepoint),    \
    REG_SYM(wasm_string_rewind),            \
    REG_SYM(wasm_string_dump),
#else
#define REG_STRINGREF_SYM()
#endif

#if WASM_ENABLE_SHARED_HEAP != 0
#define REG_SHARED_HEAP_SYM()                 \
    REG_SYM(wasm_runtime_check_and_update_last_used_shared_heap),
#else
#define REG_SHARED_HEAP_SYM()
#endif

#define REG_COMMON_SYMBOLS                \
    REG_SYM(aot_set_exception_with_id),   \
    REG_SYM(aot_invoke_native),           \
    REG_SYM(aot_call_indirect),           \
    REG_SYM(aot_enlarge_memory),          \
    REG_SYM(aot_set_exception),           \
    REG_SYM(aot_check_app_addr_and_convert),\
    REG_SYM(wasm_runtime_quick_invoke_c_api_native),\
    { "memset", (void*)aot_memset },      \
    { "memmove", (void*)aot_memmove },    \
    { "memcpy", (void*)aot_memmove },     \
    { "sqrt", (void*)aot_sqrt },          \
    { "sqrtf", (void*)aot_sqrtf },        \
    REG_SYM(fmin),                        \
    REG_SYM(fminf),                       \
    REG_SYM(fmax),                        \
    REG_SYM(fmaxf),                       \
    REG_SYM(ceil),                        \
    REG_SYM(ceilf),                       \
    REG_SYM(floor),                       \
    REG_SYM(floorf),                      \
    REG_SYM(trunc),                       \
    REG_SYM(truncf),                      \
    REG_SYM(rint),                        \
    REG_SYM(rintf),                       \
    REG_BULK_MEMORY_SYM()                 \
    REG_ATOMIC_WAIT_SYM()                 \
    REG_REF_TYPES_SYM()                   \
    REG_AOT_TRACE_SYM()                   \
    REG_INTRINSIC_SYM()                   \
    REG_LLVM_PGO_SYM()                    \
    REG_GC_SYM()                          \
    REG_STRINGREF_SYM()                   \
    REG_SHARED_HEAP_SYM()                 \

#define CHECK_RELOC_OFFSET(data_size) do {              \
    if (!check_reloc_offset(target_section_size,        \
                            reloc_offset, data_size,    \
                            error_buf, error_buf_size)) \
        return false;                                   \
  } while (0)

SymbolMap *
get_target_symbol_map(uint32 *sym_num);

uint32
get_plt_table_size(void);

void
init_plt_table(uint8 *plt);

void
get_current_target(char *target_buf, uint32 target_buf_size);

bool
apply_relocation(AOTModule *module,
                 uint8 *target_section_addr, uint32 target_section_size,
                 uint64 reloc_offset, int64 reloc_addend,
                 uint32 reloc_type, void *symbol_addr, int32 symbol_index,
                 char *error_buf, uint32 error_buf_size);
/* clang-format off */

#ifdef __cplusplus
}
#endif

#endif /* end of _AOT_RELOC_H_ */
