/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WASM_H_
#define _WASM_H_

#include "bh_platform.h"
#include "bh_hashmap.h"
#include "bh_assert.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Value Type */
#define VALUE_TYPE_I32 0x7F
#define VALUE_TYPE_I64 0X7E
#define VALUE_TYPE_F32 0x7D
#define VALUE_TYPE_F64 0x7C
#define VALUE_TYPE_V128 0x7B
#define VALUE_TYPE_FUNCREF 0x70
#define VALUE_TYPE_EXTERNREF 0x6F
#define VALUE_TYPE_VOID 0x40
/* Used by AOT */
#define VALUE_TYPE_I1 0x41
/*  Used by loader to represent any type of i32/i64/f32/f64 */
#define VALUE_TYPE_ANY 0x42

#define DEFAULT_NUM_BYTES_PER_PAGE 65536
#define DEFAULT_MAX_PAGES 65536

#define NULL_REF (0xFFFFFFFF)

#define TABLE_MAX_SIZE (1024)

#define INIT_EXPR_TYPE_I32_CONST 0x41
#define INIT_EXPR_TYPE_I64_CONST 0x42
#define INIT_EXPR_TYPE_F32_CONST 0x43
#define INIT_EXPR_TYPE_F64_CONST 0x44
#define INIT_EXPR_TYPE_V128_CONST 0xFD
/* = WASM_OP_REF_FUNC */
#define INIT_EXPR_TYPE_FUNCREF_CONST 0xD2
/* = WASM_OP_REF_NULL */
#define INIT_EXPR_TYPE_REFNULL_CONST 0xD0
#define INIT_EXPR_TYPE_GET_GLOBAL 0x23
#define INIT_EXPR_TYPE_ERROR 0xff

#define WASM_MAGIC_NUMBER 0x6d736100
#define WASM_CURRENT_VERSION 1

#define SECTION_TYPE_USER 0
#define SECTION_TYPE_TYPE 1
#define SECTION_TYPE_IMPORT 2
#define SECTION_TYPE_FUNC 3
#define SECTION_TYPE_TABLE 4
#define SECTION_TYPE_MEMORY 5
#define SECTION_TYPE_GLOBAL 6
#define SECTION_TYPE_EXPORT 7
#define SECTION_TYPE_START 8
#define SECTION_TYPE_ELEM 9
#define SECTION_TYPE_CODE 10
#define SECTION_TYPE_DATA 11
#if WASM_ENABLE_BULK_MEMORY != 0
#define SECTION_TYPE_DATACOUNT 12
#endif

#define SUB_SECTION_TYPE_MODULE 0
#define SUB_SECTION_TYPE_FUNC 1
#define SUB_SECTION_TYPE_LOCAL 2

#define IMPORT_KIND_FUNC 0
#define IMPORT_KIND_TABLE 1
#define IMPORT_KIND_MEMORY 2
#define IMPORT_KIND_GLOBAL 3

#define EXPORT_KIND_FUNC 0
#define EXPORT_KIND_TABLE 1
#define EXPORT_KIND_MEMORY 2
#define EXPORT_KIND_GLOBAL 3

#define LABEL_TYPE_BLOCK 0
#define LABEL_TYPE_LOOP 1
#define LABEL_TYPE_IF 2
#define LABEL_TYPE_FUNCTION 3

typedef struct WASMModule WASMModule;
typedef struct WASMFunction WASMFunction;
typedef struct WASMGlobal WASMGlobal;

typedef union V128 {
    int8 i8x16[16];
    int16 i16x8[8];
    int32 i32x8[4];
    int64 i64x2[2];
    float32 f32x4[4];
    float64 f64x2[2];
} V128;

typedef union WASMValue {
    int32 i32;
    uint32 u32;
    uint32 global_index;
    uint32 ref_index;
    int64 i64;
    uint64 u64;
    float32 f32;
    float64 f64;
    uintptr_t addr;
    V128 v128;
} WASMValue;

typedef struct InitializerExpression {
    /* type of INIT_EXPR_TYPE_XXX */
    /* it actually is instr, in some places, requires constant only */
    uint8 init_expr_type;
    WASMValue u;
} InitializerExpression;

typedef struct WASMType {
    uint16 param_count;
    uint16 result_count;
    uint16 param_cell_num;
    uint16 ret_cell_num;
    uint16 ref_count;
    /* types of params and results */
    uint8 types[1];
} WASMType;

typedef struct WASMTable {
    uint8 elem_type;
    uint32 flags;
    uint32 init_size;
    /* specified if (flags & 1), else it is 0x10000 */
    uint32 max_size;
    bool possible_grow;
} WASMTable;

typedef struct WASMMemory {
    uint32 flags;
    uint32 num_bytes_per_page;
    uint32 init_page_count;
    uint32 max_page_count;
} WASMMemory;

typedef struct WASMTableImport {
    char *module_name;
    char *field_name;
    uint8 elem_type;
    uint32 flags;
    uint32 init_size;
    /* specified if (flags & 1), else it is 0x10000 */
    uint32 max_size;
    bool possible_grow;
#if WASM_ENABLE_MULTI_MODULE != 0
    WASMModule *import_module;
    WASMTable *import_table_linked;
#endif
} WASMTableImport;

typedef struct WASMMemoryImport {
    char *module_name;
    char *field_name;
    uint32 flags;
    uint32 num_bytes_per_page;
    uint32 init_page_count;
    uint32 max_page_count;
#if WASM_ENABLE_MULTI_MODULE != 0
    WASMModule *import_module;
    WASMMemory *import_memory_linked;
#endif
} WASMMemoryImport;

typedef struct WASMFunctionImport {
    char *module_name;
    char *field_name;
    /* function type */
    WASMType *func_type;
    /* native function pointer after linked */
    void *func_ptr_linked;
    /* signature from registered native symbols */
    const char *signature;
    /* attachment */
    void *attachment;
    bool call_conv_raw;
#if WASM_ENABLE_MULTI_MODULE != 0
    WASMModule *import_module;
    WASMFunction *import_func_linked;
#endif
    bool call_conv_wasm_c_api;
    bool wasm_c_api_with_env;
} WASMFunctionImport;

typedef struct WASMGlobalImport {
    char *module_name;
    char *field_name;
    uint8 type;
    bool is_mutable;
    /* global data after linked */
    WASMValue global_data_linked;
    bool is_linked;
#if WASM_ENABLE_MULTI_MODULE != 0
    /* imported function pointer after linked */
    /* TODO: remove if not needed */
    WASMModule *import_module;
    WASMGlobal *import_global_linked;
#endif
#if WASM_ENABLE_FAST_JIT != 0
    /* The data offset of current global in global data */
    uint32 data_offset;
#endif
} WASMGlobalImport;

typedef struct WASMImport {
    uint8 kind;
    union {
        WASMFunctionImport function;
        WASMTableImport table;
        WASMMemoryImport memory;
        WASMGlobalImport global;
        struct {
            char *module_name;
            char *field_name;
        } names;
    } u;
} WASMImport;

struct WASMFunction {
#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
    char *field_name;
#endif
    /* the type of function */
    WASMType *func_type;
    uint32 local_count;
    uint8 *local_types;

    /* cell num of parameters */
    uint16 param_cell_num;
    /* cell num of return type */
    uint16 ret_cell_num;
    /* cell num of local variables */
    uint16 local_cell_num;
    /* offset of each local, including function parameters
       and local variables */
    uint16 *local_offsets;

    uint32 max_stack_cell_num;
    uint32 max_block_num;
    /* Whether function has opcode memory.grow */
    bool has_op_memory_grow;
    /* Whether function has opcode call or
       call_indirect */
    bool has_op_func_call;
    uint32 code_size;
    uint8 *code;
#if WASM_ENABLE_FAST_INTERP != 0
    uint32 code_compiled_size;
    uint8 *code_compiled;
    uint8 *consts;
    uint32 const_cell_num;
#endif
#if WASM_ENABLE_FAST_JIT != 0
    void *fast_jit_jitted_code;
#endif
};

struct WASMGlobal {
    uint8 type;
    bool is_mutable;
    InitializerExpression init_expr;
#if WASM_ENABLE_FAST_JIT != 0
    /* The data offset of current global in global data */
    uint32 data_offset;
#endif
};

typedef struct WASMExport {
    char *name;
    uint8 kind;
    uint32 index;
} WASMExport;

typedef struct WASMTableSeg {
    /* 0 to 7 */
    uint32 mode;
    /* funcref or externref, elemkind will be considered as funcref */
    uint32 elem_type;
    bool is_dropped;
    /* optional, only for active */
    uint32 table_index;
    InitializerExpression base_offset;
    uint32 function_count;
    uint32 *func_indexes;
} WASMTableSeg;

typedef struct WASMDataSeg {
    uint32 memory_index;
    InitializerExpression base_offset;
    uint32 data_length;
#if WASM_ENABLE_BULK_MEMORY != 0
    bool is_passive;
#endif
    uint8 *data;
} WASMDataSeg;

typedef struct BlockAddr {
    const uint8 *start_addr;
    uint8 *else_addr;
    uint8 *end_addr;
} BlockAddr;

#if WASM_ENABLE_LIBC_WASI != 0
typedef struct WASIArguments {
    const char **dir_list;
    uint32 dir_count;
    const char **map_dir_list;
    uint32 map_dir_count;
    const char **env;
    uint32 env_count;
    /* in CIDR noation */
    const char **addr_pool;
    uint32 addr_count;
    const char **ns_lookup_pool;
    uint32 ns_lookup_count;
    char **argv;
    uint32 argc;
    int stdio[3];
} WASIArguments;
#endif

typedef struct StringNode {
    struct StringNode *next;
    char *str;
} StringNode, *StringList;

typedef struct BrTableCache {
    struct BrTableCache *next;
    /* Address of br_table opcode */
    uint8 *br_table_op_addr;
    uint32 br_count;
    uint32 br_depths[1];
} BrTableCache;

#if WASM_ENABLE_DEBUG_INTERP != 0
typedef struct WASMFastOPCodeNode {
    struct WASMFastOPCodeNode *next;
    uint64 offset;
    uint8 orig_op;
} WASMFastOPCodeNode;
#endif

#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
typedef struct WASMCustomSection {
    struct WASMCustomSection *next;
    /* Start address of the section name */
    char *name_addr;
    /* Length of the section name decoded from leb */
    uint32 name_len;
    /* Start address of the content (name len and name skipped) */
    uint8 *content_addr;
    uint32 content_len;
} WASMCustomSection;
#endif

struct WASMModule {
    /* Module type, for module loaded from WASM bytecode binary,
       this field is Wasm_Module_Bytecode;
       for module loaded from AOT file, this field is
       Wasm_Module_AoT, and this structure should be treated as
       AOTModule structure. */
    uint32 module_type;

    uint32 type_count;
    uint32 import_count;
    uint32 function_count;
    uint32 table_count;
    uint32 memory_count;
    uint32 global_count;
    uint32 export_count;
    uint32 table_seg_count;
    /* data seg count read from data segment section */
    uint32 data_seg_count;
#if WASM_ENABLE_BULK_MEMORY != 0
    /* data count read from datacount section */
    uint32 data_seg_count1;
#endif

    uint32 import_function_count;
    uint32 import_table_count;
    uint32 import_memory_count;
    uint32 import_global_count;

    WASMImport *import_functions;
    WASMImport *import_tables;
    WASMImport *import_memories;
    WASMImport *import_globals;

    WASMType **types;
    WASMImport *imports;
    WASMFunction **functions;
    WASMTable *tables;
    WASMMemory *memories;
    WASMGlobal *globals;
    WASMExport *exports;
    WASMTableSeg *table_segments;
    WASMDataSeg **data_segments;
    uint32 start_function;

    /* the index of auxiliary __data_end global,
       -1 means unexported */
    uint32 aux_data_end_global_index;
    /* auxiliary __data_end exported by wasm app */
    uint32 aux_data_end;

    /* the index of auxiliary __heap_base global,
       -1 means unexported */
    uint32 aux_heap_base_global_index;
    /* auxiliary __heap_base exported by wasm app */
    uint32 aux_heap_base;

    /* the index of auxiliary stack top global,
       -1 means unexported */
    uint32 aux_stack_top_global_index;
    /* auxiliary stack bottom resolved */
    uint32 aux_stack_bottom;
    /* auxiliary stack size resolved */
    uint32 aux_stack_size;

    /* the index of malloc/free function,
       -1 means unexported */
    uint32 malloc_function;
    uint32 free_function;

    /* the index of __retain function,
       -1 means unexported */
    uint32 retain_function;

    /* Whether there is possible memory grow, e.g. memory.grow opcode */
    bool possible_memory_grow;

    StringList const_str_list;
#if WASM_ENABLE_FAST_INTERP == 0
    bh_list br_table_cache_list_head;
    bh_list *br_table_cache_list;
#endif

#if WASM_ENABLE_LIBC_WASI != 0
    WASIArguments wasi_args;
    bool import_wasi_api;
#endif

#if WASM_ENABLE_MULTI_MODULE != 0
    /* TODO: add mutex for mutli-thread? */
    bh_list import_module_list_head;
    bh_list *import_module_list;
#endif
#if WASM_ENABLE_DEBUG_INTERP != 0 || WASM_ENABLE_DEBUG_AOT != 0
    bh_list fast_opcode_list;
    uint8 *buf_code;
    uint64 buf_code_size;
#endif
#if WASM_ENABLE_DEBUG_INTERP != 0 || WASM_ENABLE_DEBUG_AOT != 0 \
    || WASM_ENABLE_FAST_JIT != 0
    uint8 *load_addr;
    uint64 load_size;
#endif

#if WASM_ENABLE_DEBUG_INTERP != 0
    /**
     * Count how many instances reference this module. When source
     * debugging feature enabled, the debugger may modify the code
     * section of the module, so we need to report a warning if user
     * create several instances based on the same module
     *
     * Sub_instances created by lib-pthread or spawn API will not
     * influence or check the ref count
     */
    uint32 ref_count;
    korp_mutex ref_count_lock;
#endif

#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
    const uint8 *name_section_buf;
    const uint8 *name_section_buf_end;
#endif

#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
    WASMCustomSection *custom_section_list;
#endif

#if WASM_ENABLE_FAST_JIT != 0
    /* point to JITed functions */
    void **fast_jit_func_ptrs;
#endif
};

typedef struct BlockType {
    /* Block type may be expressed in one of two forms:
     * either by the type of the single return value or
     * by a type index of module.
     */
    union {
        uint8 value_type;
        WASMType *type;
    } u;
    bool is_value_type;
} BlockType;

typedef struct WASMBranchBlock {
    uint8 *begin_addr;
    uint8 *target_addr;
    uint32 *frame_sp;
    uint32 cell_num;
} WASMBranchBlock;

/* Execution environment, e.g. stack info */
/**
 * Align an unsigned value on a alignment boundary.
 *
 * @param v the value to be aligned
 * @param b the alignment boundary (2, 4, 8, ...)
 *
 * @return the aligned value
 */
inline static unsigned
align_uint(unsigned v, unsigned b)
{
    unsigned m = b - 1;
    return (v + m) & ~m;
}

/**
 * Return the hash value of c string.
 */
inline static uint32
wasm_string_hash(const char *str)
{
    unsigned h = (unsigned)strlen(str);
    const uint8 *p = (uint8 *)str;
    const uint8 *end = p + h;

    while (p != end)
        h = ((h << 5) - h) + *p++;
    return h;
}

/**
 * Whether two c strings are equal.
 */
inline static bool
wasm_string_equal(const char *s1, const char *s2)
{
    return strcmp(s1, s2) == 0 ? true : false;
}

/**
 * Return the byte size of value type.
 *
 */
inline static uint32
wasm_value_type_size(uint8 value_type)
{
    switch (value_type) {
        case VALUE_TYPE_I32:
        case VALUE_TYPE_F32:
#if WASM_ENABLE_REF_TYPES != 0
        case VALUE_TYPE_FUNCREF:
        case VALUE_TYPE_EXTERNREF:
#endif
            return sizeof(int32);
        case VALUE_TYPE_I64:
        case VALUE_TYPE_F64:
            return sizeof(int64);
#if WASM_ENABLE_SIMD != 0
        case VALUE_TYPE_V128:
            return sizeof(int64) * 2;
#endif
        case VALUE_TYPE_VOID:
            return 0;
        default:
            bh_assert(0);
    }
    return 0;
}

inline static uint16
wasm_value_type_cell_num(uint8 value_type)
{
    return wasm_value_type_size(value_type) / 4;
}

inline static uint32
wasm_get_cell_num(const uint8 *types, uint32 type_count)
{
    uint32 cell_num = 0;
    uint32 i;
    for (i = 0; i < type_count; i++)
        cell_num += wasm_value_type_cell_num(types[i]);
    return cell_num;
}

#if WASM_ENABLE_REF_TYPES != 0
inline static uint16
wasm_value_type_cell_num_outside(uint8 value_type)
{
    if (VALUE_TYPE_EXTERNREF == value_type) {
        return sizeof(uintptr_t) / sizeof(uint32);
    }
    else {
        return wasm_value_type_cell_num(value_type);
    }
}
#endif

inline static bool
wasm_type_equal(const WASMType *type1, const WASMType *type2)
{
    if (type1 == type2) {
        return true;
    }
    return (type1->param_count == type2->param_count
            && type1->result_count == type2->result_count
            && memcmp(type1->types, type2->types,
                      (uint32)(type1->param_count + type1->result_count))
                   == 0)
               ? true
               : false;
}

inline static uint32
wasm_get_smallest_type_idx(WASMType **types, uint32 type_count,
                           uint32 cur_type_idx)
{
    uint32 i;

    for (i = 0; i < cur_type_idx; i++) {
        if (wasm_type_equal(types[cur_type_idx], types[i]))
            return i;
    }
    (void)type_count;
    return cur_type_idx;
}

static inline uint32
block_type_get_param_types(BlockType *block_type, uint8 **p_param_types)
{
    uint32 param_count = 0;
    if (!block_type->is_value_type) {
        WASMType *wasm_type = block_type->u.type;
        *p_param_types = wasm_type->types;
        param_count = wasm_type->param_count;
    }
    else {
        *p_param_types = NULL;
        param_count = 0;
    }

    return param_count;
}

static inline uint32
block_type_get_result_types(BlockType *block_type, uint8 **p_result_types)
{
    uint32 result_count = 0;
    if (block_type->is_value_type) {
        if (block_type->u.value_type != VALUE_TYPE_VOID) {
            *p_result_types = &block_type->u.value_type;
            result_count = 1;
        }
    }
    else {
        WASMType *wasm_type = block_type->u.type;
        *p_result_types = wasm_type->types + wasm_type->param_count;
        result_count = wasm_type->result_count;
    }
    return result_count;
}

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _WASM_H_ */
