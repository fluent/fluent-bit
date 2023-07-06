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

#if WASM_ENABLE_WASI_NN != 0
#include "../libraries/wasi-nn/src/wasi_nn_private.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define EXCEPTION_BUF_LEN 128

typedef struct WASMModuleInstance WASMModuleInstance;
typedef struct WASMFunctionInstance WASMFunctionInstance;
typedef struct WASMMemoryInstance WASMMemoryInstance;
typedef struct WASMTableInstance WASMTableInstance;
typedef struct WASMGlobalInstance WASMGlobalInstance;

/**
 * When LLVM JIT, WAMR compiler or AOT is enabled, we should ensure that
 * some offsets of the same field in the interpreter module instance and
 * aot module instance are the same, so that the LLVM JITed/AOTed code
 * can smoothly access the interpreter module instance.
 * Same for the memory instance and table instance.
 * We use the macro DefPointer to define some related pointer fields.
 */
#if (WASM_ENABLE_JIT != 0 || WASM_ENABLE_WAMR_COMPILER != 0 \
     || WASM_ENABLE_AOT != 0)                               \
    && UINTPTR_MAX == UINT32_MAX
/* Add u32 padding if LLVM JIT, WAMR compiler or AOT is enabled on
   32-bit platform */
#define DefPointer(type, field) \
    type field;                 \
    uint32 field##_padding
#else
#define DefPointer(type, field) type field
#endif

typedef enum WASMExceptionID {
    EXCE_UNREACHABLE = 0,
    EXCE_OUT_OF_MEMORY,
    EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS,
    EXCE_INTEGER_OVERFLOW,
    EXCE_INTEGER_DIVIDE_BY_ZERO,
    EXCE_INVALID_CONVERSION_TO_INTEGER,
    EXCE_INVALID_FUNCTION_TYPE_INDEX,
    EXCE_INVALID_FUNCTION_INDEX,
    EXCE_UNDEFINED_ELEMENT,
    EXCE_UNINITIALIZED_ELEMENT,
    EXCE_CALL_UNLINKED_IMPORT_FUNC,
    EXCE_NATIVE_STACK_OVERFLOW,
    EXCE_UNALIGNED_ATOMIC,
    EXCE_AUX_STACK_OVERFLOW,
    EXCE_AUX_STACK_UNDERFLOW,
    EXCE_OUT_OF_BOUNDS_TABLE_ACCESS,
    EXCE_OPERAND_STACK_OVERFLOW,
    EXCE_FAILED_TO_COMPILE_FAST_JIT_FUNC,
    EXCE_ALREADY_THROWN,
    EXCE_NUM,
} WASMExceptionID;

typedef union {
    uint64 u64;
    uint32 u32[2];
} MemBound;

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
    DefPointer(uint8 *, memory_data);
    /* Memory data end address */
    DefPointer(uint8 *, memory_data_end);

    /* Heap data base address */
    DefPointer(uint8 *, heap_data);
    /* Heap data end address */
    DefPointer(uint8 *, heap_data_end);
    /* The heap created */
    DefPointer(void *, heap_handle);

#if WASM_ENABLE_FAST_JIT != 0 || WASM_ENABLE_JIT != 0 \
    || WASM_ENABLE_WAMR_COMPILER != 0 || WASM_ENABLE_AOT != 0
    MemBound mem_bound_check_1byte;
    MemBound mem_bound_check_2bytes;
    MemBound mem_bound_check_4bytes;
    MemBound mem_bound_check_8bytes;
    MemBound mem_bound_check_16bytes;
#endif
};

struct WASMTableInstance {
    /* Current size */
    uint32 cur_size;
    /* Maximum size */
    uint32 max_size;
    /* Table elements */
    uint32 elems[1];
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

/* wasm-c-api import function info */
typedef struct CApiFuncImport {
    /* host func pointer after linked */
    void *func_ptr_linked;
    /* whether the host func has env argument */
    bool with_env_arg;
    /* the env argument of the host func */
    void *env_arg;
} CApiFuncImport;

/* Extra info of WASM module instance for interpreter/jit mode */
typedef struct WASMModuleInstanceExtra {
    WASMGlobalInstance *globals;
    WASMFunctionInstance *functions;

    uint32 global_count;
    uint32 function_count;

    WASMFunctionInstance *start_function;
    WASMFunctionInstance *malloc_function;
    WASMFunctionInstance *free_function;
    WASMFunctionInstance *retain_function;

    CApiFuncImport *c_api_func_imports;
    RunningMode running_mode;

#if WASM_ENABLE_MULTI_MODULE != 0
    bh_list sub_module_inst_list_head;
    bh_list *sub_module_inst_list;
    /* linked table instances of import table instances */
    WASMTableInstance **table_insts_linked;
#endif

#if WASM_ENABLE_MEMORY_PROFILING != 0
    uint32 max_aux_stack_used;
#endif

#if WASM_ENABLE_DEBUG_INTERP != 0                         \
    || (WASM_ENABLE_FAST_JIT != 0 && WASM_ENABLE_JIT != 0 \
        && WASM_ENABLE_LAZY_JIT != 0)
    WASMModuleInstance *next;
#endif

#if WASM_ENABLE_WASI_NN != 0
    WASINNContext *wasi_nn_ctx;
#endif
} WASMModuleInstanceExtra;

struct AOTFuncPerfProfInfo;

struct WASMModuleInstance {
    /* Module instance type, for module instance loaded from
       WASM bytecode binary, this field is Wasm_Module_Bytecode;
       for module instance loaded from AOT file, this field is
       Wasm_Module_AoT, and this structure should be treated as
       AOTModuleInstance structure. */
    uint32 module_type;

    uint32 memory_count;
    DefPointer(WASMMemoryInstance **, memories);

    /* global and table info */
    uint32 global_data_size;
    uint32 table_count;
    DefPointer(uint8 *, global_data);
    /* For AOTModuleInstance, it denotes `AOTTableInstance *` */
    DefPointer(WASMTableInstance **, tables);

    /* import func ptrs + llvm jit func ptrs */
    DefPointer(void **, func_ptrs);

    /* function type indexes */
    DefPointer(uint32 *, func_type_indexes);

    uint32 export_func_count;
    uint32 export_global_count;
    uint32 export_memory_count;
    uint32 export_table_count;
    /* For AOTModuleInstance, it denotes `AOTFunctionInstance *` */
    DefPointer(WASMExportFuncInstance *, export_functions);
    DefPointer(WASMExportGlobInstance *, export_globals);
    DefPointer(WASMExportMemInstance *, export_memories);
    DefPointer(WASMExportTabInstance *, export_tables);

    /* The exception buffer of wasm interpreter for current thread. */
    char cur_exception[EXCEPTION_BUF_LEN];

    /* The WASM module or AOT module, for AOTModuleInstance,
       it denotes `AOTModule *` */
    DefPointer(WASMModule *, module);

#if WASM_ENABLE_LIBC_WASI
    /* WASI context */
    DefPointer(WASIContext *, wasi_ctx);
#else
    DefPointer(void *, wasi_ctx);
#endif
    DefPointer(WASMExecEnv *, exec_env_singleton);
    /* Array of function pointers to import functions,
       not available in AOTModuleInstance */
    DefPointer(void **, import_func_ptrs);
    /* Array of function pointers to fast jit functions,
       not available in AOTModuleInstance:
       Only when the multi-tier JIT macros are all enabled and the running
       mode of current module instance is set to Mode_Fast_JIT, runtime
       will allocate new memory for it, otherwise it always points to the
       module->fast_jit_func_ptrs */
    DefPointer(void **, fast_jit_func_ptrs);
    /* The custom data that can be set/get by wasm_{get|set}_custom_data */
    DefPointer(void *, custom_data);
    /* Stack frames, used in call stack dump and perf profiling */
    DefPointer(Vector *, frames);
    /* Function performance profiling info list, only available
       in AOTModuleInstance */
    DefPointer(struct AOTFuncPerfProfInfo *, func_perf_profilings);
    /* WASM/AOT module extra info, for AOTModuleInstance,
       it denotes `AOTModuleInstanceExtra *` */
    DefPointer(WASMModuleInstanceExtra *, e);

    /* Default WASM operand stack size */
    uint32 default_wasm_stack_size;
    uint32 reserved[3];

    /*
     * +------------------------------+ <-- memories
     * | WASMMemoryInstance[mem_count], mem_count is always 1 for LLVM JIT/AOT
     * +------------------------------+ <-- global_data
     * | global data
     * +------------------------------+ <-- tables
     * | WASMTableInstance[table_count]
     * +------------------------------+ <-- e
     * | WASMModuleInstanceExtra
     * +------------------------------+
     */
    union {
        uint64 _make_it_8_byte_aligned_;
        WASMMemoryInstance memory_instances[1];
        uint8 bytes[1];
    } global_table_data;
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
wasm_instantiate(WASMModule *module, bool is_sub_inst,
                 WASMExecEnv *exec_env_main, uint32 stack_size,
                 uint32 heap_size, char *error_buf, uint32 error_buf_size);

void
wasm_dump_perf_profiling(const WASMModuleInstance *module_inst);

void
wasm_deinstantiate(WASMModuleInstance *module_inst, bool is_sub_inst);

bool
wasm_set_running_mode(WASMModuleInstance *module_inst,
                      RunningMode running_mode);

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

void
wasm_set_exception(WASMModuleInstance *module, const char *exception);

void
wasm_set_exception_with_id(WASMModuleInstance *module_inst, uint32 id);

const char *
wasm_get_exception(WASMModuleInstance *module);

/**
 * @brief Copy exception in buffer passed as parameter. Thread-safe version of
 * `wasm_get_exception()`
 * @note Buffer size must be no smaller than EXCEPTION_BUF_LEN
 * @return true if exception found
 */
bool
wasm_copy_exception(WASMModuleInstance *module_inst, char *exception_buf);

uint32
wasm_module_malloc_internal(WASMModuleInstance *module_inst,
                            WASMExecEnv *exec_env, uint32 size,
                            void **p_native_addr);

uint32
wasm_module_realloc_internal(WASMModuleInstance *module_inst,
                             WASMExecEnv *exec_env, uint32 ptr, uint32 size,
                             void **p_native_addr);

void
wasm_module_free_internal(WASMModuleInstance *module_inst,
                          WASMExecEnv *exec_env, uint32 ptr);

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

/**
 * Check whether the app address and the buf is inside the linear memory,
 * and convert the app address into native address
 */
bool
wasm_check_app_addr_and_convert(WASMModuleInstance *module_inst, bool is_str,
                                uint32 app_buf_addr, uint32 app_buf_size,
                                void **p_native_addr);

WASMMemoryInstance *
wasm_get_default_memory(WASMModuleInstance *module_inst);

bool
wasm_enlarge_memory(WASMModuleInstance *module_inst, uint32 inc_page_count);

bool
wasm_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 elem_idx,
                   uint32 argc, uint32 argv[]);

#if WASM_ENABLE_THREAD_MGR != 0
bool
wasm_set_aux_stack(WASMExecEnv *exec_env, uint32 start_offset, uint32 size);

bool
wasm_get_aux_stack(WASMExecEnv *exec_env, uint32 *start_offset, uint32 *size);
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
wasm_get_table_inst(const WASMModuleInstance *module_inst, uint32 tbl_idx)
{
    /* careful, it might be a table in another module */
    WASMTableInstance *tbl_inst = module_inst->tables[tbl_idx];
#if WASM_ENABLE_MULTI_MODULE != 0
    if (tbl_idx < module_inst->module->import_table_count
        && module_inst->e->table_insts_linked[tbl_idx]) {
        tbl_inst = module_inst->e->table_insts_linked[tbl_idx];
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

#if WASM_ENABLE_FAST_JIT != 0 || WASM_ENABLE_JIT != 0 \
    || WASM_ENABLE_WAMR_COMPILER != 0
void
jit_set_exception_with_id(WASMModuleInstance *module_inst, uint32 id);

/**
 * Check whether the app address and the buf is inside the linear memory,
 * and convert the app address into native address
 */
bool
jit_check_app_addr_and_convert(WASMModuleInstance *module_inst, bool is_str,
                               uint32 app_buf_addr, uint32 app_buf_size,
                               void **p_native_addr);
#endif /* end of WASM_ENABLE_FAST_JIT != 0 || WASM_ENABLE_JIT != 0 \
          || WASM_ENABLE_WAMR_COMPILER != 0 */

#if WASM_ENABLE_FAST_JIT != 0
bool
fast_jit_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 elem_idx,
                       uint32 type_idx, uint32 argc, uint32 *argv);

bool
fast_jit_invoke_native(WASMExecEnv *exec_env, uint32 func_idx,
                       struct WASMInterpFrame *prev_frame);
#endif

#if WASM_ENABLE_JIT != 0 || WASM_ENABLE_WAMR_COMPILER != 0
bool
llvm_jit_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 elem_idx,
                       uint32 argc, uint32 *argv);

bool
llvm_jit_invoke_native(WASMExecEnv *exec_env, uint32 func_idx, uint32 argc,
                       uint32 *argv);

#if WASM_ENABLE_BULK_MEMORY != 0
bool
llvm_jit_memory_init(WASMModuleInstance *module_inst, uint32 seg_index,
                     uint32 offset, uint32 len, uint32 dst);

bool
llvm_jit_data_drop(WASMModuleInstance *module_inst, uint32 seg_index);
#endif

#if WASM_ENABLE_REF_TYPES != 0
void
llvm_jit_drop_table_seg(WASMModuleInstance *module_inst, uint32 tbl_seg_idx);

void
llvm_jit_table_init(WASMModuleInstance *module_inst, uint32 tbl_idx,
                    uint32 tbl_seg_idx, uint32 length, uint32 src_offset,
                    uint32 dst_offset);

void
llvm_jit_table_copy(WASMModuleInstance *module_inst, uint32 src_tbl_idx,
                    uint32 dst_tbl_idx, uint32 length, uint32 src_offset,
                    uint32 dst_offset);

void
llvm_jit_table_fill(WASMModuleInstance *module_inst, uint32 tbl_idx,
                    uint32 length, uint32 val, uint32 data_offset);

uint32
llvm_jit_table_grow(WASMModuleInstance *module_inst, uint32 tbl_idx,
                    uint32 inc_entries, uint32 init_val);
#endif

#if WASM_ENABLE_DUMP_CALL_STACK != 0 || WASM_ENABLE_PERF_PROFILING != 0
bool
llvm_jit_alloc_frame(WASMExecEnv *exec_env, uint32 func_index);

void
llvm_jit_free_frame(WASMExecEnv *exec_env);
#endif
#endif /* end of WASM_ENABLE_JIT != 0 || WASM_ENABLE_WAMR_COMPILER != 0 */

#if WASM_ENABLE_LIBC_WASI != 0 && WASM_ENABLE_MULTI_MODULE != 0
void
wasm_propagate_wasi_args(WASMModule *module);
#endif

#ifdef __cplusplus
}
#endif

#endif /* end of _WASM_RUNTIME_H */
