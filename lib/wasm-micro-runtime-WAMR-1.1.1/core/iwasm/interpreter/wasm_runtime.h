/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WASM_RUNTIME_H
#define _WASM_RUNTIME_H

#include "wasm.h"
#include "bh_hashmap.h"
#include "../common/wasm_runtime_common.h"
#include "../common/wasm_exec_env.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WASMModuleInstance WASMModuleInstance;
typedef struct WASMFunctionInstance WASMFunctionInstance;
typedef struct WASMMemoryInstance WASMMemoryInstance;
typedef struct WASMTableInstance WASMTableInstance;
typedef struct WASMGlobalInstance WASMGlobalInstance;

struct WASMMemoryInstance {
    /* Module type */
    uint32 module_type;
    /* Shared memory flag */
    bool is_shared;

    /* Number bytes per page */
    uint32 num_bytes_per_page;
    /* Current page count */
    uint32 cur_page_count;
    /* Maximum page count */
    uint32 max_page_count;
    /* Memory data size */
    uint32 memory_data_size;

    /**
     * Memory data begin address, Note:
     *   the app-heap might be inserted in to the linear memory,
     *   when memory is re-allocated, the heap data and memory data
     *   must be copied to new memory also
     */
    uint8 *memory_data;
    /* Memory data end address */
    uint8 *memory_data_end;

    /* Heap data base address */
    uint8 *heap_data;
    /* Heap data end address */
    uint8 *heap_data_end;
    /* The heap created */
    void *heap_handle;

#if WASM_ENABLE_SHARED_MEMORY != 0
    /* mutex lock for the memory, used in atomic operation */
    korp_mutex mem_lock;
#endif

#if WASM_ENABLE_FAST_JIT != 0
#if UINTPTR_MAX == UINT64_MAX
    uint64 mem_bound_check_1byte;
    uint64 mem_bound_check_2bytes;
    uint64 mem_bound_check_4bytes;
    uint64 mem_bound_check_8bytes;
    uint64 mem_bound_check_16bytes;
#else
    uint32 mem_bound_check_1byte;
    uint32 mem_bound_check_2bytes;
    uint32 mem_bound_check_4bytes;
    uint32 mem_bound_check_8bytes;
    uint32 mem_bound_check_16bytes;
#endif
#endif
};

struct WASMTableInstance {
    /* The element type, VALUE_TYPE_FUNCREF/EXTERNREF currently */
    uint8 elem_type;
    /* Current size */
    uint32 cur_size;
    /* Maximum size */
    uint32 max_size;
#if WASM_ENABLE_MULTI_MODULE != 0
    /* just for import, keep the reference here */
    WASMTableInstance *table_inst_linked;
#endif
    /* Base address */
    uint8 base_addr[1];
};

struct WASMGlobalInstance {
    /* value type, VALUE_TYPE_I32/I64/F32/F64 */
    uint8 type;
    /* mutable or constant */
    bool is_mutable;
    /* data offset to base_addr of WASMMemoryInstance */
    uint32 data_offset;
    /* initial value */
    WASMValue initial_value;
#if WASM_ENABLE_MULTI_MODULE != 0
    /* just for import, keep the reference here */
    WASMModuleInstance *import_module_inst;
    WASMGlobalInstance *import_global_inst;
#endif
};

struct WASMFunctionInstance {
    /* whether it is import function or WASM function */
    bool is_import_func;
    /* parameter count */
    uint16 param_count;
    /* local variable count, 0 for import function */
    uint16 local_count;
    /* cell num of parameters */
    uint16 param_cell_num;
    /* cell num of return type */
    uint16 ret_cell_num;
    /* cell num of local variables, 0 for import function */
    uint16 local_cell_num;
#if WASM_ENABLE_FAST_INTERP != 0
    /* cell num of consts */
    uint16 const_cell_num;
#endif
    uint16 *local_offsets;
    /* parameter types */
    uint8 *param_types;
    /* local types, NULL for import function */
    uint8 *local_types;
    union {
        WASMFunctionImport *func_import;
        WASMFunction *func;
    } u;
#if WASM_ENABLE_MULTI_MODULE != 0
    WASMModuleInstance *import_module_inst;
    WASMFunctionInstance *import_func_inst;
#endif
#if WASM_ENABLE_PERF_PROFILING != 0
    /* total execution time */
    uint64 total_exec_time;
    /* total execution count */
    uint32 total_exec_cnt;
#endif
};

typedef struct WASMExportFuncInstance {
    char *name;
    WASMFunctionInstance *function;
} WASMExportFuncInstance;

#if WASM_ENABLE_MULTI_MODULE != 0
typedef struct WASMExportGlobInstance {
    char *name;
    WASMGlobalInstance *global;
} WASMExportGlobInstance;

typedef struct WASMExportTabInstance {
    char *name;
    WASMTableInstance *table;
} WASMExportTabInstance;

typedef struct WASMExportMemInstance {
    char *name;
    WASMMemoryInstance *memory;
} WASMExportMemInstance;
#endif

struct WASMModuleInstance {
    /* Module instance type, for module instance loaded from
       WASM bytecode binary, this field is Wasm_Module_Bytecode;
       for module instance loaded from AOT file, this field is
       Wasm_Module_AoT, and this structure should be treated as
       AOTModuleInstance structure. */
    uint32 module_type;

    uint32 memory_count;
    uint32 table_count;
    uint32 global_count;
    uint32 function_count;

    uint32 export_func_count;
#if WASM_ENABLE_MULTI_MODULE != 0
    uint32 export_glob_count;
    uint32 export_mem_count;
    uint32 export_tab_count;
#endif

    /* Array of function pointers to import functions */
    void **import_func_ptrs;
#if WASM_ENABLE_FAST_JIT != 0
    /* point to JITed functions */
    void **fast_jit_func_ptrs;
    uint32 *func_type_indexes;
#endif

    WASMMemoryInstance **memories;
    WASMTableInstance **tables;
    WASMGlobalInstance *globals;
    WASMFunctionInstance *functions;

    WASMExportFuncInstance *export_functions;
#if WASM_ENABLE_MULTI_MODULE != 0
    WASMExportGlobInstance *export_globals;
    WASMExportMemInstance *export_memories;
    WASMExportTabInstance *export_tables;
#endif

    WASMMemoryInstance *default_memory;
    WASMTableInstance *default_table;
    /* Global data of global instances */
    uint8 *global_data;

    WASMFunctionInstance *start_function;
    WASMFunctionInstance *malloc_function;
    WASMFunctionInstance *free_function;
    WASMFunctionInstance *retain_function;

    WASMModule *module;

#if WASM_ENABLE_LIBC_WASI != 0
    WASIContext *wasi_ctx;
#endif

    WASMExecEnv *exec_env_singleton;

    /* Default WASM stack size of threads of this Module instance. */
    uint32 default_wasm_stack_size;

    /* The exception buffer of wasm interpreter for current thread. */
    char cur_exception[128];

#if WASM_ENABLE_DUMP_CALL_STACK != 0
    Vector *frames;
#endif

    /* The custom data that can be set/get by
     * wasm_set_custom_data/wasm_get_custom_data */
    void *custom_data;

#if WASM_ENABLE_MULTI_MODULE != 0
    /* TODO: add mutex for mutli-threads? */
    bh_list sub_module_inst_list_head;
    bh_list *sub_module_inst_list;
#endif

#if WASM_ENABLE_MEMORY_PROFILING != 0
    uint32 max_aux_stack_used;
#endif
};

struct WASMInterpFrame;
typedef struct WASMInterpFrame WASMRuntimeFrame;

#if WASM_ENABLE_MULTI_MODULE != 0
typedef struct WASMSubModInstNode {
    bh_list_link l;
    /* point to a string pool */
    const char *module_name;
    WASMModuleInstance *module_inst;
} WASMSubModInstNode;
#endif

/**
 * Return the code block of a function.
 *
 * @param func the WASM function instance
 *
 * @return the code block of the function
 */
static inline uint8 *
wasm_get_func_code(WASMFunctionInstance *func)
{
#if WASM_ENABLE_FAST_INTERP == 0
    return func->is_import_func ? NULL : func->u.func->code;
#else
    return func->is_import_func ? NULL : func->u.func->code_compiled;
#endif
}

/**
 * Return the code block end of a function.
 *
 * @param func the WASM function instance
 *
 * @return the code block end of the function
 */
static inline uint8 *
wasm_get_func_code_end(WASMFunctionInstance *func)
{
#if WASM_ENABLE_FAST_INTERP == 0
    return func->is_import_func ? NULL
                                : func->u.func->code + func->u.func->code_size;
#else
    return func->is_import_func
               ? NULL
               : func->u.func->code_compiled + func->u.func->code_compiled_size;
#endif
}

WASMModule *
wasm_load(uint8 *buf, uint32 size, char *error_buf, uint32 error_buf_size);

WASMModule *
wasm_load_from_sections(WASMSection *section_list, char *error_buf,
                        uint32 error_buf_size);

void
wasm_unload(WASMModule *module);

WASMModuleInstance *
wasm_instantiate(WASMModule *module, bool is_sub_inst, uint32 stack_size,
                 uint32 heap_size, char *error_buf, uint32 error_buf_size);

void
wasm_dump_perf_profiling(const WASMModuleInstance *module_inst);

void
wasm_deinstantiate(WASMModuleInstance *module_inst, bool is_sub_inst);

WASMFunctionInstance *
wasm_lookup_function(const WASMModuleInstance *module_inst, const char *name,
                     const char *signature);

#if WASM_ENABLE_MULTI_MODULE != 0
WASMGlobalInstance *
wasm_lookup_global(const WASMModuleInstance *module_inst, const char *name);

WASMMemoryInstance *
wasm_lookup_memory(const WASMModuleInstance *module_inst, const char *name);

WASMTableInstance *
wasm_lookup_table(const WASMModuleInstance *module_inst, const char *name);
#endif

bool
wasm_call_function(WASMExecEnv *exec_env, WASMFunctionInstance *function,
                   unsigned argc, uint32 argv[]);

bool
wasm_create_exec_env_and_call_function(WASMModuleInstance *module_inst,
                                       WASMFunctionInstance *function,
                                       unsigned argc, uint32 argv[]);

bool
wasm_create_exec_env_singleton(WASMModuleInstance *module_inst);

void
wasm_set_exception(WASMModuleInstance *module, const char *exception);

const char *
wasm_get_exception(WASMModuleInstance *module);

uint32
wasm_module_malloc(WASMModuleInstance *module_inst, uint32 size,
                   void **p_native_addr);

uint32
wasm_module_realloc(WASMModuleInstance *module_inst, uint32 ptr, uint32 size,
                    void **p_native_addr);

void
wasm_module_free(WASMModuleInstance *module_inst, uint32 ptr);

uint32
wasm_module_dup_data(WASMModuleInstance *module_inst, const char *src,
                     uint32 size);

bool
wasm_validate_app_addr(WASMModuleInstance *module_inst, uint32 app_offset,
                       uint32 size);

bool
wasm_validate_app_str_addr(WASMModuleInstance *module_inst, uint32 app_offset);

bool
wasm_validate_native_addr(WASMModuleInstance *module_inst, void *native_ptr,
                          uint32 size);

void *
wasm_addr_app_to_native(WASMModuleInstance *module_inst, uint32 app_offset);

uint32
wasm_addr_native_to_app(WASMModuleInstance *module_inst, void *native_ptr);

bool
wasm_get_app_addr_range(WASMModuleInstance *module_inst, uint32 app_offset,
                        uint32 *p_app_start_offset, uint32 *p_app_end_offset);

bool
wasm_get_native_addr_range(WASMModuleInstance *module_inst, uint8 *native_ptr,
                           uint8 **p_native_start_addr,
                           uint8 **p_native_end_addr);

bool
wasm_enlarge_memory(WASMModuleInstance *module, uint32 inc_page_count);

bool
wasm_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 elem_idx,
                   uint32 argc, uint32 argv[]);

#if WASM_ENABLE_FAST_JIT != 0
bool
jit_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 elem_idx,
                  uint32 type_idx, uint32 argc, uint32 argv[]);
#endif

#if WASM_ENABLE_THREAD_MGR != 0
bool
wasm_set_aux_stack(WASMExecEnv *exec_env, uint32 start_offset, uint32 size);

bool
wasm_get_aux_stack(WASMExecEnv *exec_env, uint32 *start_offset, uint32 *size);
#endif

#ifdef OS_ENABLE_HW_BOUND_CHECK
#ifndef BH_PLATFORM_WINDOWS
void
wasm_signal_handler(WASMSignalInfo *sig_info);
#else
LONG
wasm_exception_handler(WASMSignalInfo *sig_info);
#endif
#endif

void
wasm_get_module_mem_consumption(const WASMModule *module,
                                WASMModuleMemConsumption *mem_conspn);

void
wasm_get_module_inst_mem_consumption(const WASMModuleInstance *module,
                                     WASMModuleInstMemConsumption *mem_conspn);

#if WASM_ENABLE_REF_TYPES != 0
static inline bool
wasm_elem_is_active(uint32 mode)
{
    return (mode & 0x1) == 0x0;
}

static inline bool
wasm_elem_is_passive(uint32 mode)
{
    return (mode & 0x1) == 0x1;
}

static inline bool
wasm_elem_is_declarative(uint32 mode)
{
    return (mode & 0x3) == 0x3;
}

bool
wasm_enlarge_table(WASMModuleInstance *module_inst, uint32 table_idx,
                   uint32 inc_entries, uint32 init_val);
#endif /* WASM_ENABLE_REF_TYPES != 0 */

static inline WASMTableInstance *
wasm_get_table_inst(const WASMModuleInstance *module_inst, const uint32 tbl_idx)
{
    /* careful, it might be a table in another module */
    WASMTableInstance *tbl_inst = module_inst->tables[tbl_idx];
#if WASM_ENABLE_MULTI_MODULE != 0
    if (tbl_inst->table_inst_linked) {
        tbl_inst = tbl_inst->table_inst_linked;
    }
#endif
    bh_assert(tbl_inst);
    return tbl_inst;
}

#if WASM_ENABLE_DUMP_CALL_STACK != 0
bool
wasm_interp_create_call_stack(struct WASMExecEnv *exec_env);

/**
 * @brief Dump wasm call stack or get the size
 *
 * @param exec_env the execution environment
 * @param print whether to print to stdout or not
 * @param buf buffer to store the dumped content
 * @param len length of the buffer
 *
 * @return when print is true, return the bytes printed out to stdout; when
 * print is false and buf is NULL, return the size required to store the
 * callstack content; when print is false and buf is not NULL, return the size
 * dumped to the buffer, 0 means error and data in buf may be invalid
 */
uint32
wasm_interp_dump_call_stack(struct WASMExecEnv *exec_env, bool print, char *buf,
                            uint32 len);
#endif

const uint8 *
wasm_loader_get_custom_section(WASMModule *module, const char *name,
                               uint32 *len);

#ifdef __cplusplus
}
#endif

#endif /* end of _WASM_RUNTIME_H */
