/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _AOT_RUNTIME_H_
#define _AOT_RUNTIME_H_

#include "bh_platform.h"
#include "../common/wasm_runtime_common.h"
#include "../interpreter/wasm_runtime.h"
#include "../compilation/aot.h"
#if WASM_ENABLE_JIT != 0
#include "../compilation/aot_llvm.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum AOTExceptionID {
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
    EXCE_NUM,
} AOTExceptionID;

typedef enum AOTSectionType {
    AOT_SECTION_TYPE_TARGET_INFO = 0,
    AOT_SECTION_TYPE_INIT_DATA = 1,
    AOT_SECTION_TYPE_TEXT = 2,
    AOT_SECTION_TYPE_FUNCTION = 3,
    AOT_SECTION_TYPE_EXPORT = 4,
    AOT_SECTION_TYPE_RELOCATION = 5,
    AOT_SECTION_TYPE_SIGANATURE = 6,
    AOT_SECTION_TYPE_CUSTOM = 100,
} AOTSectionType;

typedef enum AOTCustomSectionType {
    AOT_CUSTOM_SECTION_RAW = 0,
    AOT_CUSTOM_SECTION_NATIVE_SYMBOL = 1,
    AOT_CUSTOM_SECTION_ACCESS_CONTROL = 2,
    AOT_CUSTOM_SECTION_NAME = 3,
} AOTCustomSectionType;

typedef struct AOTObjectDataSection {
    char *name;
    uint8 *data;
    uint32 size;
} AOTObjectDataSection;

/* Relocation info */
typedef struct AOTRelocation {
    uint64 relocation_offset;
    int64 relocation_addend;
    uint32 relocation_type;
    char *symbol_name;
    /* index in the symbol offset field */
    uint32 symbol_index;
} AOTRelocation;

/* Relocation Group */
typedef struct AOTRelocationGroup {
    char *section_name;
    /* index in the symbol offset field */
    uint32 name_index;
    uint32 relocation_count;
    AOTRelocation *relocations;
} AOTRelocationGroup;

/* AOT function instance */
typedef struct AOTFunctionInstance {
    char *func_name;
    uint32 func_index;
    bool is_import_func;
    union {
        struct {
            AOTFuncType *func_type;
            /* function pointer linked */
            void *func_ptr;
        } func;
        AOTImportFunc *func_import;
    } u;
} AOTFunctionInstance;

#if defined(OS_ENABLE_HW_BOUND_CHECK) && defined(BH_PLATFORM_WINDOWS)
/* clang-format off */
typedef struct AOTUnwindInfo {
    uint8 Version       : 3;
    uint8 Flags         : 5;
    uint8 SizeOfProlog;
    uint8 CountOfCodes;
    uint8 FrameRegister : 4;
    uint8 FrameOffset   : 4;
    struct {
        struct {
            uint8 CodeOffset;
            uint8 UnwindOp : 4;
            uint8 OpInfo   : 4;
        };
        uint16 FrameOffset;
    } UnwindCode[1];
} AOTUnwindInfo;
/* clang-format on */

/* size of mov instruction and jmp instruction */
#define PLT_ITEM_SIZE 12
#endif

typedef struct AOTModule {
    uint32 module_type;

    /* import memories */
    uint32 import_memory_count;
    AOTImportMemory *import_memories;

    /* memory info */
    uint32 memory_count;
    AOTMemory *memories;

    /* init data */
    uint32 mem_init_data_count;
    AOTMemInitData **mem_init_data_list;

    /* native symbol */
    void **native_symbol_list;

    /* import tables */
    uint32 import_table_count;
    AOTImportTable *import_tables;

    /* tables */
    uint32 table_count;
    AOTTable *tables;

    /* table init data info */
    uint32 table_init_data_count;
    AOTTableInitData **table_init_data_list;

    /* function type info */
    uint32 func_type_count;
    AOTFuncType **func_types;

    /* import global variable info */
    uint32 import_global_count;
    AOTImportGlobal *import_globals;

    /* global variable info */
    uint32 global_count;
    AOTGlobal *globals;

    /* total global variable size */
    uint32 global_data_size;

    /* import function info */
    uint32 import_func_count;
    AOTImportFunc *import_funcs;

    /* function info */
    uint32 func_count;
    /* point to AOTed/JITed functions */
    void **func_ptrs;
    /* function type indexes */
    uint32 *func_type_indexes;

    /* export info */
    uint32 export_count;
    AOTExport *exports;

    /* start function index, -1 denotes no start function */
    uint32 start_func_index;
    /* start function, point to AOTed/JITed function */
    void *start_function;

    uint32 malloc_func_index;
    uint32 free_func_index;
    uint32 retain_func_index;

    /* AOTed code, NULL for JIT mode */
    void *code;
    uint32 code_size;

    /* literal for AOTed code, NULL for JIT mode */
    uint8 *literal;
    uint32 literal_size;

#if defined(BH_PLATFORM_WINDOWS)
    /* extra plt data area for __ymm, __xmm and __real constants
       in Windows platform, NULL for JIT mode */
    uint8 *extra_plt_data;
    uint32 extra_plt_data_size;
    uint32 ymm_plt_count;
    uint32 xmm_plt_count;
    uint32 real_plt_count;
    uint32 float_plt_count;
#endif

#if defined(OS_ENABLE_HW_BOUND_CHECK) && defined(BH_PLATFORM_WINDOWS)
    /* dynamic function table to be added by RtlAddFunctionTable(),
       used to unwind the call stack and register exception handler
       for AOT functions */
    RUNTIME_FUNCTION *rtl_func_table;
    bool rtl_func_table_registered;
#endif

    /* data sections in AOT object file, including .data, .rodata
     * and .rodata.cstN. NULL for JIT mode. */
    AOTObjectDataSection *data_sections;
    uint32 data_section_count;

    /* constant string set */
    HashMap *const_str_set;

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

    /* is jit mode or not */
    bool is_jit_mode;

    /* is indirect mode or not */
    bool is_indirect_mode;

#if WASM_ENABLE_JIT != 0
    WASMModule *wasm_module;
    AOTCompContext *comp_ctx;
    AOTCompData *comp_data;
#endif

#if WASM_ENABLE_LIBC_WASI != 0
    WASIArguments wasi_args;
    bool import_wasi_api;
#endif
#if WASM_ENABLE_DEBUG_AOT != 0
    void *elf_hdr;
    uint32 elf_size;
#endif
#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
    const char **aux_func_names;
    uint32 *aux_func_indexes;
    uint32 aux_func_name_count;
#endif
#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
    WASMCustomSection *custom_section_list;
#endif
} AOTModule;

typedef union {
    uint64 _make_it_8_bytes_;
    void *ptr;
} AOTPointer;

typedef union {
    uint64 u64;
    uint32 u32[2];
} MemBound;

typedef struct AOTMemoryInstance {
    uint32 module_type;
    /* shared memory flag */
    bool is_shared;

    /* memory space info */
    uint32 num_bytes_per_page;
    uint32 cur_page_count;
    uint32 max_page_count;
    uint32 memory_data_size;
    AOTPointer memory_data;
    AOTPointer memory_data_end;

    /* heap space info */
    AOTPointer heap_data;
    AOTPointer heap_data_end;
    AOTPointer heap_handle;

    /* boundary check constants for aot code */
    MemBound mem_bound_check_1byte;
    MemBound mem_bound_check_2bytes;
    MemBound mem_bound_check_4bytes;
    MemBound mem_bound_check_8bytes;
    MemBound mem_bound_check_16bytes;
} AOTMemoryInstance;

typedef struct AOTTableInstance {
    uint32 cur_size;
    /*
     * only grow in the range of [:max_size)
     * if the table is growable, max_size equals to its declared maximum size
     * otherwise, max_size equals to its declared minimum size
     */
    uint32 max_size;
    /*
     * +------------------------------+  <--- data
     * | ref.func[] or ref.extern[]
     * +------------------------------+
     */
    uint32 data[1];
} AOTTableInstance;

typedef struct AOTModuleInstance {
    uint32 module_type;

    /* memories */
    uint32 memory_count;
    AOTPointer memories;

    /* global and table info */
    uint32 global_data_size;
    /*
     * the count of AOTTableInstance.
     * it includes imported tables and local tables.
     *
     * TODO: for now we treate imported table like a local table
     */
    uint32 table_count;
    /* points to global_data */
    AOTPointer global_data;
    /* points to AOTTableInstance[] */
    AOTPointer tables;

    /* function pointer array */
    AOTPointer func_ptrs;
    /* function type indexes */
    AOTPointer func_type_indexes;

    /* export info */
    uint32 export_func_count;
    uint32 export_global_count;
    uint32 export_mem_count;
    uint32 export_tab_count;
    AOTPointer export_funcs;
    AOTPointer export_globals;
    AOTPointer export_memories;
    AOTPointer export_tables;

    /* The exception buffer for current thread. */
    char cur_exception[128];
    /* The custom data that can be set/get by
     * wasm_runtime_set_custom_data/wasm_runtime_get_custom_data */
    AOTPointer custom_data;
    /* The AOT module */
    AOTPointer aot_module;
    /* WASI context */
    AOTPointer wasi_ctx;
    /* function performance profiling info list */
    AOTPointer func_perf_profilings;
    /* stack frames, used in call stack dump and perf profiling */
    AOTPointer frames;

    AOTPointer exec_env_singleton;

    uint32 default_wasm_stack_size;

    /* reserved */
    uint32 reserved[9];

    /*
     * +------------------------------+ <-- memories.ptr
     * | #0 AOTMemoryInstance
     * +------------------------------+ <-- global_data.ptr
     * | global data
     * +------------------------------+ <-- tables.ptr
     * | AOTTableInstance[table_count]
     * +------------------------------+
     */
    union {
        uint64 _make_it_8_byte_aligned_;
        AOTMemoryInstance memory_instances[1];
        uint8 bytes[1];
    } global_table_data;
} AOTModuleInstance;

/* Target info, read from ELF header of object file */
typedef struct AOTTargetInfo {
    /* Binary type, elf32l/elf32b/elf64l/elf64b */
    uint16 bin_type;
    /* ABI type */
    uint16 abi_type;
    /* Object file type */
    uint16 e_type;
    /* Architecture */
    uint16 e_machine;
    /* Object file version */
    uint32 e_version;
    /* Processor-specific flags */
    uint32 e_flags;
    /* Reserved */
    uint32 reserved;
    /* Arch name */
    char arch[16];
} AOTTargetInfo;

typedef struct AOTFuncPerfProfInfo {
    /* total execution time */
    uint64 total_exec_time;
    /* total execution count */
    uint32 total_exec_cnt;
} AOTFuncPerfProfInfo;

/* AOT auxiliary call stack */
typedef struct AOTFrame {
    struct AOTFrame *prev_frame;
    uint32 func_index;
#if WASM_ENABLE_PERF_PROFILING != 0
    uint64 time_started;
    AOTFuncPerfProfInfo *func_perf_prof_info;
#endif
} AOTFrame;

/**
 * Load a AOT module from aot file buffer
 * @param buf the byte buffer which contains the AOT file data
 * @param size the size of the buffer
 * @param error_buf output of the error info
 * @param error_buf_size the size of the error string
 *
 * @return return AOT module loaded, NULL if failed
 */
AOTModule *
aot_load_from_aot_file(const uint8 *buf, uint32 size, char *error_buf,
                       uint32 error_buf_size);

/**
 * Load a AOT module from a specified AOT section list.
 *
 * @param section_list the section list which contains each section data
 * @param error_buf output of the error info
 * @param error_buf_size the size of the error string
 *
 * @return return AOT module loaded, NULL if failed
 */
AOTModule *
aot_load_from_sections(AOTSection *section_list, char *error_buf,
                       uint32 error_buf_size);

#if WASM_ENABLE_JIT != 0
/**
 * Convert WASM module to AOT module
 *
 * @param wasm_module the WASM module to convert
 * @param error_buf output of the error info
 * @param error_buf_size the size of the error string
 *
 * @return return AOT module loaded, NULL if failed
 */
AOTModule *
aot_convert_wasm_module(WASMModule *wasm_module, char *error_buf,
                        uint32 error_buf_size);
#endif

/**
 * Unload a AOT module.
 *
 * @param module the module to be unloaded
 */
void
aot_unload(AOTModule *module);

/**
 * Instantiate a AOT module.
 *
 * @param module the AOT module to instantiate
 * @param is_sub_inst the flag of sub instance
 * @param heap_size the default heap size of the module instance, a heap will
 *        be created besides the app memory space. Both wasm app and native
 *        function can allocate memory from the heap. If heap_size is 0, the
 *        default heap size will be used.
 * @param error_buf buffer to output the error info if failed
 * @param error_buf_size the size of the error buffer
 *
 * @return return the instantiated AOT module instance, NULL if failed
 */
AOTModuleInstance *
aot_instantiate(AOTModule *module, bool is_sub_inst, uint32 stack_size,
                uint32 heap_size, char *error_buf, uint32 error_buf_size);

/**
 * Deinstantiate a AOT module instance, destroy the resources.
 *
 * @param module_inst the AOT module instance to destroy
 * @param is_sub_inst the flag of sub instance
 */
void
aot_deinstantiate(AOTModuleInstance *module_inst, bool is_sub_inst);

/**
 * Lookup an exported function in the AOT module instance.
 *
 * @param module_inst the module instance
 * @param name the name of the function
 * @param signature the signature of the function, use "i32"/"i64"/"f32"/"f64"
 *        to represent the type of i32/i64/f32/f64, e.g. "(i32i64)" "(i32)f32"
 *
 * @return the function instance found
 */
AOTFunctionInstance *
aot_lookup_function(const AOTModuleInstance *module_inst, const char *name,
                    const char *signature);
/**
 * Call the given AOT function of a AOT module instance with
 * arguments.
 *
 * @param exec_env the execution environment
 * @param function the function to be called
 * @param argc the number of arguments
 * @param argv the arguments.  If the function method has return value,
 *   the first (or first two in case 64-bit return value) element of
 *   argv stores the return value of the called AOT function after this
 *   function returns.
 *
 * @return true if success, false otherwise and exception will be thrown,
 *   the caller can call aot_get_exception to get exception info.
 */
bool
aot_call_function(WASMExecEnv *exec_env, AOTFunctionInstance *function,
                  unsigned argc, uint32 argv[]);

bool
aot_create_exec_env_and_call_function(AOTModuleInstance *module_inst,
                                      AOTFunctionInstance *function,
                                      unsigned argc, uint32 argv[]);

bool
aot_create_exec_env_singleton(AOTModuleInstance *module_inst);

/**
 * Set AOT module instance exception with exception string
 *
 * @param module the AOT module instance
 *
 * @param exception current exception string
 */
void
aot_set_exception(AOTModuleInstance *module_inst, const char *exception);

void
aot_set_exception_with_id(AOTModuleInstance *module_inst, uint32 id);

/**
 * Get exception info of the AOT module instance.
 *
 * @param module_inst the AOT module instance
 *
 * @return the exception string
 */
const char *
aot_get_exception(AOTModuleInstance *module_inst);

/**
 * Clear exception info of the AOT module instance.
 *
 * @param module_inst the AOT module instance
 */
void
aot_clear_exception(AOTModuleInstance *module_inst);

uint32
aot_module_malloc(AOTModuleInstance *module_inst, uint32 size,
                  void **p_native_addr);

uint32
aot_module_realloc(AOTModuleInstance *module_inst, uint32 ptr, uint32 size,
                   void **p_native_addr);

void
aot_module_free(AOTModuleInstance *module_inst, uint32 ptr);

uint32
aot_module_dup_data(AOTModuleInstance *module_inst, const char *src,
                    uint32 size);

bool
aot_validate_app_addr(AOTModuleInstance *module_inst, uint32 app_offset,
                      uint32 size);

bool
aot_validate_native_addr(AOTModuleInstance *module_inst, void *native_ptr,
                         uint32 size);

void *
aot_addr_app_to_native(AOTModuleInstance *module_inst, uint32 app_offset);

uint32
aot_addr_native_to_app(AOTModuleInstance *module_inst, void *native_ptr);

bool
aot_get_app_addr_range(AOTModuleInstance *module_inst, uint32 app_offset,
                       uint32 *p_app_start_offset, uint32 *p_app_end_offset);

bool
aot_get_native_addr_range(AOTModuleInstance *module_inst, uint8 *native_ptr,
                          uint8 **p_native_start_addr,
                          uint8 **p_native_end_addr);

bool
aot_enlarge_memory(AOTModuleInstance *module_inst, uint32 inc_page_count);

/**
 * Invoke native function from aot code
 */
bool
aot_invoke_native(WASMExecEnv *exec_env, uint32 func_idx, uint32 argc,
                  uint32 *argv);

bool
aot_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 table_elem_idx,
                  uint32 argc, uint32 *argv);

bool
aot_check_app_addr_and_convert(AOTModuleInstance *module_inst, bool is_str,
                               uint32 app_buf_addr, uint32 app_buf_size,
                               void **p_native_addr);

uint32
aot_get_plt_table_size();

void *
aot_memmove(void *dest, const void *src, size_t n);

void *
aot_memset(void *s, int c, size_t n);

#if WASM_ENABLE_BULK_MEMORY != 0
bool
aot_memory_init(AOTModuleInstance *module_inst, uint32 seg_index, uint32 offset,
                uint32 len, uint32 dst);

bool
aot_data_drop(AOTModuleInstance *module_inst, uint32 seg_index);
#endif

#if WASM_ENABLE_THREAD_MGR != 0
bool
aot_set_aux_stack(WASMExecEnv *exec_env, uint32 start_offset, uint32 size);

bool
aot_get_aux_stack(WASMExecEnv *exec_env, uint32 *start_offset, uint32 *size);
#endif

#ifdef OS_ENABLE_HW_BOUND_CHECK
#ifndef BH_PLATFORM_WINDOWS
void
aot_signal_handler(WASMSignalInfo *sig_info);
#else
LONG
aot_exception_handler(WASMSignalInfo *sig_info);
#endif
#endif

void
aot_get_module_mem_consumption(const AOTModule *module,
                               WASMModuleMemConsumption *mem_conspn);

void
aot_get_module_inst_mem_consumption(const AOTModuleInstance *module_inst,
                                    WASMModuleInstMemConsumption *mem_conspn);

#if WASM_ENABLE_REF_TYPES != 0
void
aot_drop_table_seg(AOTModuleInstance *module_inst, uint32 tbl_seg_idx);

void
aot_table_init(AOTModuleInstance *module_inst, uint32 tbl_idx,
               uint32 tbl_seg_idx, uint32 length, uint32 src_offset,
               uint32 dst_offset);

void
aot_table_copy(AOTModuleInstance *module_inst, uint32 src_tbl_idx,
               uint32 dst_tbl_idx, uint32 length, uint32 src_offset,
               uint32 dst_offset);

void
aot_table_fill(AOTModuleInstance *module_inst, uint32 tbl_idx, uint32 length,
               uint32 val, uint32 data_offset);

uint32
aot_table_grow(AOTModuleInstance *module_inst, uint32 tbl_idx,
               uint32 inc_entries, uint32 init_val);
#endif

AOTTableInstance *
aot_next_tbl_inst(const AOTTableInstance *tbl_inst);

bool
aot_alloc_frame(WASMExecEnv *exec_env, uint32 func_index);

void
aot_free_frame(WASMExecEnv *exec_env);

bool
aot_create_call_stack(struct WASMExecEnv *exec_env);

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
aot_dump_call_stack(WASMExecEnv *exec_env, bool print, char *buf, uint32 len);

void
aot_dump_perf_profiling(const AOTModuleInstance *module_inst);

const uint8 *
aot_get_custom_section(const AOTModule *module, const char *name, uint32 *len);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* end of _AOT_RUNTIME_H_ */
