/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WASM_EXPORT_H
#define _WASM_EXPORT_H

#include <stdint.h>
#include <stdbool.h>
#include "lib_export.h"

#ifndef WASM_RUNTIME_API_EXTERN
#if defined(_MSC_BUILD)
#if defined(COMPILING_WASM_RUNTIME_API)
#define WASM_RUNTIME_API_EXTERN __declspec(dllexport)
#else
#define WASM_RUNTIME_API_EXTERN __declspec(dllimport)
#endif
#else
#define WASM_RUNTIME_API_EXTERN
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* clang-format off */

#define get_module_inst(exec_env) \
    wasm_runtime_get_module_inst(exec_env)

#define validate_app_addr(offset, size) \
    wasm_runtime_validate_app_addr(module_inst, offset, size)

#define validate_app_str_addr(offset) \
    wasm_runtime_validate_app_str_addr(module_inst, offset)

#define addr_app_to_native(offset) \
    wasm_runtime_addr_app_to_native(module_inst, offset)

#define addr_native_to_app(ptr) \
    wasm_runtime_addr_native_to_app(module_inst, ptr)

#define module_malloc(size, p_native_addr) \
    wasm_runtime_module_malloc(module_inst, size, p_native_addr)

#define module_free(offset) \
    wasm_runtime_module_free(module_inst, offset)

#define native_raw_return_type(type, args) type *raw_ret = (type *)(args)

#define native_raw_get_arg(type, name, args) type name = *((type *)(args++))

#define native_raw_set_return(val) *raw_ret = (val)

#ifndef WASM_MODULE_T_DEFINED
#define WASM_MODULE_T_DEFINED
/* Uninstantiated WASM module loaded from WASM binary file
   or AoT binary file*/
struct WASMModuleCommon;
typedef struct WASMModuleCommon *wasm_module_t;
#endif

/* Instantiated WASM module */
struct WASMModuleInstanceCommon;
typedef struct WASMModuleInstanceCommon *wasm_module_inst_t;

/* Function instance */
typedef void WASMFunctionInstanceCommon;
typedef WASMFunctionInstanceCommon *wasm_function_inst_t;

/* WASM section */
typedef struct wasm_section_t {
    struct wasm_section_t *next;
    /* section type */
    int section_type;
    /* section body, not include type and size */
    uint8_t *section_body;
    /* section body size */
    uint32_t section_body_size;
} wasm_section_t, aot_section_t, *wasm_section_list_t, *aot_section_list_t;

/* Execution environment, e.g. stack info */
struct WASMExecEnv;
typedef struct WASMExecEnv *wasm_exec_env_t;

/* Package Type */
typedef enum {
    Wasm_Module_Bytecode = 0,
    Wasm_Module_AoT,
    Package_Type_Unknown = 0xFFFF
} package_type_t;

#ifndef MEM_ALLOC_OPTION_DEFINED
#define MEM_ALLOC_OPTION_DEFINED
/* Memory allocator type */
typedef enum {
    /* pool mode, allocate memory from user defined heap buffer */
    Alloc_With_Pool = 0,
    /* user allocator mode, allocate memory from user defined
       malloc function */
    Alloc_With_Allocator,
    /* system allocator mode, allocate memory from system allocator,
       or, platform's os_malloc function */
    Alloc_With_System_Allocator,
} mem_alloc_type_t;

/* Memory allocator option */
typedef union MemAllocOption {
    struct {
        void *heap_buf;
        uint32_t heap_size;
    } pool;
    struct {
        void *malloc_func;
        void *realloc_func;
        void *free_func;
    } allocator;
} MemAllocOption;
#endif

/* Memory pool info  */
typedef struct mem_alloc_info_t {
    uint32_t total_size;
    uint32_t total_free_size;
    uint32_t highmark_size;
} mem_alloc_info_t;

/* WASM runtime initialize arguments */
typedef struct RuntimeInitArgs {
    mem_alloc_type_t mem_alloc_type;
    MemAllocOption mem_alloc_option;

    const char *native_module_name;
    NativeSymbol *native_symbols;
    uint32_t n_native_symbols;

    /* maximum thread number, only used when
        WASM_ENABLE_THREAD_MGR is defined */
    uint32_t max_thread_num;

    /* Debug settings, only used when
       WASM_ENABLE_DEBUG_INTERP != 0 */
    char ip_addr[128];
    int unused; /* was platform_port */
    int instance_port;

    /* Fast JIT code cache size */
    uint32_t fast_jit_code_cache_size;
} RuntimeInitArgs;

#ifndef WASM_VALKIND_T_DEFINED
#define WASM_VALKIND_T_DEFINED
typedef uint8_t wasm_valkind_t;
enum wasm_valkind_enum {
    WASM_I32,
    WASM_I64,
    WASM_F32,
    WASM_F64,
    WASM_ANYREF = 128,
    WASM_FUNCREF,
};
#endif

#ifndef WASM_VAL_T_DEFINED
#define WASM_VAL_T_DEFINED

typedef struct wasm_val_t {
    wasm_valkind_t kind;
    union {
        /* also represent a function index */
        int32_t i32;
        int64_t i64;
        float f32;
        double f64;
        /* represent a foreign object, aka externref in .wat */
        uintptr_t foreign;
    } of;
} wasm_val_t;
#endif

/**
 * Initialize the WASM runtime environment, and also initialize
 * the memory allocator with system allocator, which calls os_malloc
 * to allocate memory
 *
 * @return true if success, false otherwise
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_init(void);

/**
 * Initialize the WASM runtime environment, and also initialize
 * the memory allocator and register native symbols, which are specified
 * with init arguments
 *
 * @param init_args specifies the init arguments
 *
 * @return return true if success, false otherwise
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_full_init(RuntimeInitArgs *init_args);

/**
 * Destroy the WASM runtime environment.
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_destroy(void);

/**
 * Allocate memory from runtime memory environment.
 *
 * @param size bytes need to allocate
 *
 * @return the pointer to memory allocated
 */
WASM_RUNTIME_API_EXTERN void *
wasm_runtime_malloc(unsigned int size);

/**
 * Reallocate memory from runtime memory environment
 *
 * @param ptr the original memory
 * @param size bytes need to reallocate
 *
 * @return the pointer to memory reallocated
 */
WASM_RUNTIME_API_EXTERN void *
wasm_runtime_realloc(void *ptr, unsigned int size);

/*
 * Free memory to runtime memory environment.
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_free(void *ptr);

/*
 * Get memory info, only pool mode is supported now.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_get_mem_alloc_info(mem_alloc_info_t *mem_alloc_info);

/**
 * Get the package type of a buffer.
 *
 * @param buf the package buffer
 * @param size the package buffer size
 *
 * @return the package type, return Package_Type_Unknown if the type is unknown
 */
WASM_RUNTIME_API_EXTERN package_type_t
get_package_type(const uint8_t *buf, uint32_t size);

/**
 * Check whether a file is an AOT XIP (Execution In Place) file
 *
 * @param buf the package buffer
 * @param size the package buffer size
 *
 * @return true if success, false otherwise
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_is_xip_file(const uint8_t *buf, uint32_t size);

/**
 * Callback to load a module file into a buffer in multi-module feature
 */
typedef bool (*module_reader)(const char *module_name,
                              uint8_t **p_buffer, uint32_t *p_size);

/**
 * Callback to release the buffer loaded by module_reader callback
 */
typedef void (*module_destroyer)(uint8_t *buffer, uint32_t size);

/**
 * Setup callbacks for reading and releasing a buffer about a module file
 *
 * @param reader a callback to read a module file into a buffer
 * @param destroyer a callback to release above buffer
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_module_reader(const module_reader reader,
                               const module_destroyer destroyer);
/**
 * Give the "module" a name "module_name".
 * Can not assign a new name to a module if it already has a name
 *
 * @param module_name indicate a name
 * @param module the target module
 * @param error_buf output of the exception info
 * @param error_buf_size the size of the exception string
 *
 * @return true means success, false means failed
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_register_module(const char *module_name, wasm_module_t module,
                             char *error_buf, uint32_t error_buf_size);

/**
 * Check if there is already a loaded module named module_name in the
 * runtime. Repeately loading a module with the same name is not allowed.
 *
 * @param module_name indicate a name
 *
 * @return return WASM module loaded, NULL if failed
 */
WASM_RUNTIME_API_EXTERN wasm_module_t
wasm_runtime_find_module_registered(const char *module_name);

/**
 * Load a WASM module from a specified byte buffer. The byte buffer can be
 * WASM binary data when interpreter or JIT is enabled, or AOT binary data
 * when AOT is enabled. If it is AOT binary data, it must be 4-byte aligned.
 *
 * Note: In case of AOT XIP modules, the runtime doesn't make modifications
 * to the buffer. (Except the "Known issues" mentioned in doc/xip.md.)
 * Otherwise, the runtime can make modifications to the buffer for its
 * internal purposes. Thus, in general, it isn't safe to create multiple
 * modules from a single buffer.
 *
 * @param buf the byte buffer which contains the WASM/AOT binary data,
 *        note that the byte buffer must be writable since runtime may
 *        change its content for footprint and performance purpose, and
 *        it must be referencable until wasm_runtime_unload is called
 * @param size the size of the buffer
 * @param error_buf output of the exception info
 * @param error_buf_size the size of the exception string
 *
 * @return return WASM module loaded, NULL if failed
 */
WASM_RUNTIME_API_EXTERN wasm_module_t
wasm_runtime_load(uint8_t *buf, uint32_t size,
                  char *error_buf, uint32_t error_buf_size);

/**
 * Load a WASM module from a specified WASM or AOT section list.
 *
 * @param section_list the section list which contains each section data
 * @param is_aot whether the section list is AOT section list
 * @param error_buf output of the exception info
 * @param error_buf_size the size of the exception string
 *
 * @return return WASM module loaded, NULL if failed
 */
WASM_RUNTIME_API_EXTERN wasm_module_t
wasm_runtime_load_from_sections(wasm_section_list_t section_list, bool is_aot,
                                char *error_buf, uint32_t error_buf_size);

/**
 * Unload a WASM module.
 *
 * @param module the module to be unloaded
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_unload(wasm_module_t module);

WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_wasi_args_ex(wasm_module_t module,
                           const char *dir_list[], uint32_t dir_count,
                           const char *map_dir_list[], uint32_t map_dir_count,
                           const char *env[], uint32_t env_count,
                           char *argv[], int argc,
                           int stdinfd, int stdoutfd, int stderrfd);

WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_wasi_args(wasm_module_t module,
                           const char *dir_list[], uint32_t dir_count,
                           const char *map_dir_list[], uint32_t map_dir_count,
                           const char *env[], uint32_t env_count,
                           char *argv[], int argc);

WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_wasi_addr_pool(wasm_module_t module, const char *addr_pool[],
                                uint32_t addr_pool_size);

WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_wasi_ns_lookup_pool(wasm_module_t module, const char *ns_lookup_pool[],
                                     uint32_t ns_lookup_pool_size);

/**
 * Instantiate a WASM module.
 *
 * @param module the WASM module to instantiate
 * @param stack_size the default stack size of the module instance when the
 *        exec env's operation stack isn't created by user, e.g. API
 *        wasm_application_execute_main() and wasm_application_execute_func()
 *        create the operation stack internally with the stack size specified
 *        here. And API wasm_runtime_create_exec_env() creates the operation
 *        stack with stack size specified by its parameter, the stack size
 *        specified here is ignored.
 * @param heap_size the default heap size of the module instance, a heap will
 *        be created besides the app memory space. Both wasm app and native
 *        function can allocate memory from the heap.
 * @param error_buf buffer to output the error info if failed
 * @param error_buf_size the size of the error buffer
 *
 * @return return the instantiated WASM module instance, NULL if failed
 */
WASM_RUNTIME_API_EXTERN wasm_module_inst_t
wasm_runtime_instantiate(const wasm_module_t module,
                         uint32_t stack_size, uint32_t heap_size,
                         char *error_buf, uint32_t error_buf_size);

/**
 * Deinstantiate a WASM module instance, destroy the resources.
 *
 * @param module_inst the WASM module instance to destroy
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_deinstantiate(wasm_module_inst_t module_inst);

WASM_RUNTIME_API_EXTERN bool
wasm_runtime_is_wasi_mode(wasm_module_inst_t module_inst);

WASM_RUNTIME_API_EXTERN wasm_function_inst_t
wasm_runtime_lookup_wasi_start_function(wasm_module_inst_t module_inst);

/**
 * Lookup an exported function in the WASM module instance.
 *
 * @param module_inst the module instance
 * @param name the name of the function
 * @param signature the signature of the function, ignored currently
 *
 * @return the function instance found, NULL if not found
 */
WASM_RUNTIME_API_EXTERN wasm_function_inst_t
wasm_runtime_lookup_function(wasm_module_inst_t const module_inst,
                             const char *name, const char *signature);

/**
 * Get parameter count of the function instance
 *
 * @param func_inst the function instance
 * @param module_inst the module instance the function instance belongs to
 *
 * @return the parameter count of the function instance
 */
WASM_RUNTIME_API_EXTERN uint32_t
wasm_func_get_param_count(wasm_function_inst_t const func_inst,
                          wasm_module_inst_t const module_inst);

/**
 * Get result count of the function instance
 *
 * @param func_inst the function instance
 * @param module_inst the module instance the function instance belongs to
 *
 * @return the result count of the function instance
 */
WASM_RUNTIME_API_EXTERN uint32_t
wasm_func_get_result_count(wasm_function_inst_t const func_inst,
                           wasm_module_inst_t const module_inst);

/**
 * Get parameter types of the function instance
 *
 * @param func_inst the function instance
 * @param module_inst the module instance the function instance belongs to
 * @param param_types the parameter types returned
 */
WASM_RUNTIME_API_EXTERN void
wasm_func_get_param_types(wasm_function_inst_t const func_inst,
                          wasm_module_inst_t const module_inst,
                          wasm_valkind_t *param_types);

/**
 * Get result types of the function instance
 *
 * @param func_inst the function instance
 * @param module_inst the module instance the function instance belongs to
 * @param result_types the result types returned
 */
WASM_RUNTIME_API_EXTERN void
wasm_func_get_result_types(wasm_function_inst_t const func_inst,
                           wasm_module_inst_t const module_inst,
                           wasm_valkind_t *result_types);

/**
 * Create execution environment for a WASM module instance.
 *
 * @param module_inst the module instance
 * @param stack_size the stack size to execute a WASM function
 *
 * @return the execution environment, NULL if failed, e.g. invalid
 *         stack size is passed
 */
WASM_RUNTIME_API_EXTERN wasm_exec_env_t
wasm_runtime_create_exec_env(wasm_module_inst_t module_inst,
                             uint32_t stack_size);

/**
 * Destroy the execution environment.
 *
 * @param exec_env the execution environment to destroy
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_destroy_exec_env(wasm_exec_env_t exec_env);

/**
 * Get the singleton execution environment for the instance.
 *
 * Note: The singleton execution environment is the execution
 * environment used internally by the runtime for the API functions
 * like wasm_application_execute_main, which don't take explicit
 * execution environment. It's associated to the corresponding
 * module instance and managed by the runtime. The API user should
 * not destroy it with wasm_runtime_destroy_exec_env.
 *
 * @param module_inst the module instance
 *
 * @return exec_env the execution environment to destroy
 */
WASM_RUNTIME_API_EXTERN wasm_exec_env_t
wasm_runtime_get_exec_env_singleton(wasm_module_inst_t module_inst);

/**
 * Start debug instance based on given execution environment.
 * Note:
 *   The debug instance will be destroyed during destroying the
 *   execution environment, developers don't need to destroy it
 *   manually.
 *   If the cluster of this execution environment has already
 *   been bound to a debug instance, this function will return true
 *   directly.
 *   If developer spawns some exec_env by wasm_runtime_spawn_exec_env,
 *   don't need to call this function for every spawned exec_env as
 *   they are sharing the same cluster with the main exec_env.
 *
 * @param exec_env the execution environment to start debug instance
 * @param port     the port for the debug server to listen on.
 *                 0 means automatic assignment.
 *                 -1 means to use the global setting in RuntimeInitArgs.
 *
 * @return debug port if success, 0 otherwise.
 */
WASM_RUNTIME_API_EXTERN uint32_t
wasm_runtime_start_debug_instance_with_port(wasm_exec_env_t exec_env, int32_t port);

/**
 * Same as wasm_runtime_start_debug_instance_with_port(env, -1).
 */
WASM_RUNTIME_API_EXTERN uint32_t
wasm_runtime_start_debug_instance(wasm_exec_env_t exec_env);

/**
 * Initialize the thread environment.
 * Note:
 *   If developer creates a child thread by himself to call the
 *   the wasm function in that thread, he should call this API
 *   firstly before calling the wasm function and then call
 *   wasm_runtime_destroy_thread_env() after calling the wasm
 *   function. If the thread is created from the runtime API,
 *   it is unnecessary to call these two APIs.
 *
 * @return true if success, false otherwise
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_init_thread_env(void);

/**
 * Destroy the thread environment
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_destroy_thread_env(void);

/**
 * Whether the thread environment is initialized
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_thread_env_inited(void);

/**
 * Get WASM module instance from execution environment
 *
 * @param exec_env the execution environment to retrieve
 *
 * @return the WASM module instance
 */
WASM_RUNTIME_API_EXTERN wasm_module_inst_t
wasm_runtime_get_module_inst(wasm_exec_env_t exec_env);

/**
 * Set WASM module instance of execution environment
 * Caution:
 *   normally the module instance is bound with the execution
 *   environment one by one, if multiple module instances want
 *   to share to the same execution environment, developer should
 *   be responsible for the backup and restore of module instance
 *
 * @param exec_env the execution environment
 * @param module_inst the WASM module instance to set
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_module_inst(wasm_exec_env_t exec_env,
                             const wasm_module_inst_t module_inst);

/**
 * Call the given WASM function of a WASM module instance with
 * arguments (bytecode and AoT).
 *
 * @param exec_env the execution environment to call the function,
 *   which must be created from wasm_create_exec_env()
 * @param function the function to call
 * @param argc total cell number that the function parameters occupy,
 *   a cell is a slot of the uint32 array argv[], e.g. i32/f32 argument
 *   occupies one cell, i64/f64 argument occupies two cells, note that
 *   it might be different from the parameter number of the function
 * @param argv the arguments. If the function has return value,
 *   the first (or first two in case 64-bit return value) element of
 *   argv stores the return value of the called WASM function after this
 *   function returns.
 *
 * @return true if success, false otherwise and exception will be thrown,
 *   the caller can call wasm_runtime_get_exception to get the exception
 *   info.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_call_wasm(wasm_exec_env_t exec_env,
                       wasm_function_inst_t function,
                       uint32_t argc, uint32_t argv[]);

/**
 * Call the given WASM function of a WASM module instance with
 * provided results space and arguments (bytecode and AoT).
 *
 * @param exec_env the execution environment to call the function,
 *   which must be created from wasm_create_exec_env()
 * @param function the function to call
 * @param num_results the number of results
 * @param results the pre-alloced pointer to get the results
 * @param num_args the number of arguments
 * @param args the arguments
 *
 * @return true if success, false otherwise and exception will be thrown,
 *   the caller can call wasm_runtime_get_exception to get the exception
 *   info.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_call_wasm_a(wasm_exec_env_t exec_env,
                         wasm_function_inst_t function,
                         uint32_t num_results, wasm_val_t results[],
                         uint32_t num_args, wasm_val_t *args);

/**
 * Call the given WASM function of a WASM module instance with
 * provided results space and variant arguments (bytecode and AoT).
 *
 * @param exec_env the execution environment to call the function,
 *   which must be created from wasm_create_exec_env()
 * @param function the function to call
 * @param num_results the number of results
 * @param results the pre-alloced pointer to get the results
 * @param num_args the number of arguments
 * @param ... the variant arguments
 *
 * @return true if success, false otherwise and exception will be thrown,
 *   the caller can call wasm_runtime_get_exception to get the exception
 *   info.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_call_wasm_v(wasm_exec_env_t exec_env,
                         wasm_function_inst_t function,
                         uint32_t num_results, wasm_val_t results[],
                         uint32_t num_args, ...);

/**
 * Find the unique main function from a WASM module instance
 * and execute that function.
 *
 * @param module_inst the WASM module instance
 * @param argc the number of arguments
 * @param argv the arguments array, if the main function has return value,
 *   *(int*)argv stores the return value of the called main function after
 *   this function returns.
 *
 * @return true if the main function is called, false otherwise and exception
 *   will be thrown, the caller can call wasm_runtime_get_exception to get
 *   the exception info.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_application_execute_main(wasm_module_inst_t module_inst,
                              int32_t argc, char *argv[]);

/**
 * Find the specified function in argv[0] from a WASM module instance
 * and execute that function.
 *
 * @param module_inst the WASM module instance
 * @param name the name of the function to execute.
 *  to indicate the module name via: $module_name$function_name
 *  or just a function name: function_name
 * @param argc the number of arguments
 * @param argv the arguments array
 *
 * @return true if the specified function is called, false otherwise and
 *   exception will be thrown, the caller can call wasm_runtime_get_exception
 *   to get the exception info.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_application_execute_func(wasm_module_inst_t module_inst,
                              const char *name, int32_t argc, char *argv[]);
/**
 * Get exception info of the WASM module instance.
 *
 * @param module_inst the WASM module instance
 *
 * @return the exception string
 */
WASM_RUNTIME_API_EXTERN const char *
wasm_runtime_get_exception(wasm_module_inst_t module_inst);

/**
 * Set exception info of the WASM module instance.
 *
 * @param module_inst the WASM module instance
 *
 * @param exception the exception string
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_exception(wasm_module_inst_t module_inst,
                           const char *exception);

/**
 * Clear exception info of the WASM module instance.
 *
 * @param module_inst the WASM module instance
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_clear_exception(wasm_module_inst_t module_inst);

/**
 * Set custom data to WASM module instance.
 * Note:
 *  If WAMR_BUILD_LIB_PTHREAD is enabled, this API
 *  will spread the custom data to all threads
 *
 * @param module_inst the WASM module instance
 * @param custom_data the custom data to be set
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_custom_data(wasm_module_inst_t module_inst,
                             void *custom_data);
/**
 * Get the custom data within a WASM module instance.
 *
 * @param module_inst the WASM module instance
 *
 * @return the custom data (NULL if not set yet)
 */
WASM_RUNTIME_API_EXTERN void *
wasm_runtime_get_custom_data(wasm_module_inst_t module_inst);

/**
 * Allocate memory from the heap of WASM module instance
 *
 * Note: wasm_runtime_module_malloc can call heap functions inside
 * the module instance and thus cause a memory growth.
 * This API needs to be used very carefully when you have a native
 * pointers to the module instance memory obtained with
 * wasm_runtime_addr_app_to_native or similar APIs.
 *
 * @param module_inst the WASM module instance which contains heap
 * @param size the size bytes to allocate
 * @param p_native_addr return native address of the allocated memory
 *        if it is not NULL, and return NULL if memory malloc failed
 *
 * @return the allocated memory address, which is a relative offset to the
 *         base address of the module instance's memory space. Note that
 *         it is not an absolute address.
 *         Return non-zero if success, zero if failed.
 */
WASM_RUNTIME_API_EXTERN uint32_t
wasm_runtime_module_malloc(wasm_module_inst_t module_inst, uint32_t size,
                           void **p_native_addr);

/**
 * Free memory to the heap of WASM module instance
 *
 * @param module_inst the WASM module instance which contains heap
 * @param ptr the pointer to free
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_module_free(wasm_module_inst_t module_inst, uint32_t ptr);

/**
 * Allocate memory from the heap of WASM module instance and initialize
 * the memory with src
 *
 * @param module_inst the WASM module instance which contains heap
 * @param src the source data to copy
 * @param size the size of the source data
 *
 * @return the allocated memory address, which is a relative offset to the
 *         base address of the module instance's memory space. Note that
 *         it is not an absolute address.
 *         Return non-zero if success, zero if failed.
 */
WASM_RUNTIME_API_EXTERN uint32_t
wasm_runtime_module_dup_data(wasm_module_inst_t module_inst,
                             const char *src, uint32_t size);

/**
 * Validate the app address, check whether it belongs to WASM module
 * instance's address space, or in its heap space or memory space.
 *
 * @param module_inst the WASM module instance
 * @param app_offset the app address to validate, which is a relative address
 * @param size the size bytes of the app address
 *
 * @return true if success, false otherwise. If failed, an exception will
 *         be thrown.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_validate_app_addr(wasm_module_inst_t module_inst,
                               uint32_t app_offset, uint32_t size);

/**
 * Similar to wasm_runtime_validate_app_addr(), except that the size parameter
 * is not provided. This function validates the app string address, check
 * whether it belongs to WASM module instance's address space, or in its heap
 * space or memory space. Moreover, it checks whether it is the offset of a
 * string that is end with '\0'.
 *
 * Note: The validation result, especially the NUL termination check,
 * is not reliable for a module instance with multiple threads because
 * other threads can modify the heap behind us.
 *
 * @param module_inst the WASM module instance
 * @param app_str_offset the app address of the string to validate, which is a
 *        relative address
 *
 * @return true if success, false otherwise. If failed, an exception will
 *         be thrown.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_validate_app_str_addr(wasm_module_inst_t module_inst,
                                   uint32_t app_str_offset);

/**
 * Validate the native address, check whether it belongs to WASM module
 * instance's address space, or in its heap space or memory space.
 *
 * @param module_inst the WASM module instance
 * @param native_ptr the native address to validate, which is an absolute
 *        address
 * @param size the size bytes of the app address
 *
 * @return true if success, false otherwise. If failed, an exception will
 *         be thrown.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_validate_native_addr(wasm_module_inst_t module_inst,
                                  void *native_ptr, uint32_t size);

/**
 * Convert app address(relative address) to native address(absolute address)
 *
 * Note that native addresses to module instance memory can be invalidated
 * on a memory growth. (Except shared memory, whose native addresses are
 * stable.)
 *
 * @param module_inst the WASM module instance
 * @param app_offset the app adress
 *
 * @return the native address converted
 */
WASM_RUNTIME_API_EXTERN void *
wasm_runtime_addr_app_to_native(wasm_module_inst_t module_inst,
                                uint32_t app_offset);

/**
 * Convert native address(absolute address) to app address(relative address)
 *
 * @param module_inst the WASM module instance
 * @param native_ptr the native address
 *
 * @return the app address converted
 */
WASM_RUNTIME_API_EXTERN uint32_t
wasm_runtime_addr_native_to_app(wasm_module_inst_t module_inst,
                                void *native_ptr);

/**
 * Get the app address range (relative address) that a app address belongs to
 *
 * @param module_inst the WASM module instance
 * @param app_offset the app address to retrieve
 * @param p_app_start_offset buffer to output the app start offset if not NULL
 * @param p_app_end_offset buffer to output the app end offset if not NULL
 *
 * @return true if success, false otherwise.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_get_app_addr_range(wasm_module_inst_t module_inst,
                                uint32_t app_offset,
                                uint32_t *p_app_start_offset,
                                uint32_t *p_app_end_offset);

/**
 * Get the native address range (absolute address) that a native address
 * belongs to
 *
 * @param module_inst the WASM module instance
 * @param native_ptr the native address to retrieve
 * @param p_native_start_addr buffer to output the native start address
 *        if not NULL
 * @param p_native_end_addr buffer to output the native end address
 *        if not NULL
 *
 * @return true if success, false otherwise.
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_get_native_addr_range(wasm_module_inst_t module_inst,
                                   uint8_t *native_ptr,
                                   uint8_t **p_native_start_addr,
                                   uint8_t **p_native_end_addr);

/**
 * Register native functions with same module name
 *
 * Note: The array `native_symbols` should not be read-only because the
 * library can modify it in-place.
 *
 * Note: After successful call of this function, the array `native_symbols`
 * is owned by the library.
 *
 * @param module_name the module name of the native functions
 * @param native_symbols specifies an array of NativeSymbol structures which
 *        contain the names, function pointers and signatures
 *        Note: WASM runtime will not allocate memory to clone the data, so
 *              user must ensure the array can be used forever
 *        Meanings of letters in function signature:
 *          'i': the parameter is i32 type
 *          'I': the parameter is i64 type
 *          'f': the parameter is f32 type
 *          'F': the parameter is f64 type
 *          'r': the parameter is externref type, it should be a uintptr_t in host
 *          '*': the parameter is a pointer (i32 in WASM), and runtime will
 *               auto check its boundary before calling the native function.
 *               If it is followed by '~', the checked length of the pointer
 *               is gotten from the following parameter, if not, the checked
 *               length of the pointer is 1.
 *          '~': the parameter is the pointer's length with i32 type, and must
 *               follow after '*'
 *          '$': the parameter is a string (i32 in WASM), and runtime will
 *               auto check its boundary before calling the native function
 * @param n_native_symbols specifies the number of native symbols in the array
 *
 * @return true if success, false otherwise
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_register_natives(const char *module_name,
                              NativeSymbol *native_symbols,
                              uint32_t n_native_symbols);

/**
 * Register native functions with same module name, similar to
 *   wasm_runtime_register_natives, the difference is that runtime passes raw
 * arguments to native API, which means that the native API should be defined as
 *   void foo(wasm_exec_env_t exec_env, uint64 *args);
 * and native API should extract arguments one by one from args array with macro
 *   native_raw_get_arg
 * and write the return value back to args[0] with macro
 *   native_raw_return_type and native_raw_set_return
 */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_register_natives_raw(const char *module_name,
                                  NativeSymbol *native_symbols,
                                  uint32_t n_native_symbols);

/**
 * Get attachment of native function from execution environment
 *
 * @param exec_env the execution environment to retrieve
 *
 * @return the attachment of native function
 */
WASM_RUNTIME_API_EXTERN void *
wasm_runtime_get_function_attachment(wasm_exec_env_t exec_env);

/**
 * Set user data to execution environment.
 *
 * @param exec_env the execution environment
 * @param user_data the user data to be set
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_user_data(wasm_exec_env_t exec_env, void *user_data);

/**
 * Get the user data within execution environment.
 *
 * @param exec_env the execution environment
 *
 * @return the user data (NULL if not set yet)
 */
WASM_RUNTIME_API_EXTERN void *
wasm_runtime_get_user_data(wasm_exec_env_t exec_env);

/**
 * Dump runtime memory consumption, including:
 *     Exec env memory consumption
 *     WASM module memory consumption
 *     WASM module instance memory consumption
 *     stack and app heap used info
 *
 * @param exec_env the execution environment
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_dump_mem_consumption(wasm_exec_env_t exec_env);

/**
 * Dump runtime performance profiler data of each function
 *
 * @param module_inst the WASM module instance to profile
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_dump_perf_profiling(wasm_module_inst_t module_inst);

/* wasm thread callback function type */
typedef void *(*wasm_thread_callback_t)(wasm_exec_env_t, void *);
/* wasm thread type */
typedef uintptr_t wasm_thread_t;

/**
 * Set the max thread num per cluster.
 *
 * @param num maximum thread num
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_max_thread_num(uint32_t num);

/**
 * Spawn a new exec_env, the spawned exec_env
 *   can be used in other threads
 *
 * @param num the original exec_env
 *
 * @return the spawned exec_env if success, NULL otherwise
 */
WASM_RUNTIME_API_EXTERN wasm_exec_env_t
wasm_runtime_spawn_exec_env(wasm_exec_env_t exec_env);

/**
 * Destroy the spawned exec_env
 *
 * @param exec_env the spawned exec_env
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_destroy_spawned_exec_env(wasm_exec_env_t exec_env);

/**
 * Spawn a thread from the given exec_env
 *
 * @param exec_env the original exec_env
 * @param tid thread id to be returned to the caller
 * @param callback the callback function provided by the user
 * @param arg the arguments passed to the callback
 *
 * @return 0 if success, -1 otherwise
 */
WASM_RUNTIME_API_EXTERN int32_t
wasm_runtime_spawn_thread(wasm_exec_env_t exec_env, wasm_thread_t *tid,
                          wasm_thread_callback_t callback, void *arg);

/**
 * Wait a spawned thread to terminate
 *
 * @param tid thread id
 * @param retval if not NULL, output the return value of the thread
 *
 * @return 0 if success, error number otherwise
 */
WASM_RUNTIME_API_EXTERN int32_t
wasm_runtime_join_thread(wasm_thread_t tid, void **retval);

/**
 * Map external object to an internal externref index: if the index
 *   has been created, return it, otherwise create the index.
 *
 * @param module_inst the WASM module instance that the extern object
 *        belongs to
 * @param extern_obj the external object to be mapped
 * @param p_externref_idx return externref index of the external object
 *
 * @return true if success, false otherwise
 */
WASM_RUNTIME_API_EXTERN bool
wasm_externref_obj2ref(wasm_module_inst_t module_inst,
                       void *extern_obj, uint32_t *p_externref_idx);

/**
 * Retrieve the external object from an internal externref index
 *
 * @param externref_idx the externref index to retrieve
 * @param p_extern_obj return the mapped external object of
 *        the externref index
 *
 * @return true if success, false otherwise
 */
WASM_RUNTIME_API_EXTERN bool
wasm_externref_ref2obj(uint32_t externref_idx, void **p_extern_obj);

/**
 * Retain an extern object which is mapped to the internal externref
 *   so that the object won't be cleaned during extern object reclaim
 *   if it isn't used.
 *
 * @param externref_idx the externref index of an external object
 *        to retain
 * @return true if success, false otherwise
 */
WASM_RUNTIME_API_EXTERN bool
wasm_externref_retain(uint32_t externref_idx);

/**
 * Dump the call stack to stdout
 *
 * @param exec_env the execution environment
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_dump_call_stack(wasm_exec_env_t exec_env);

/**
 * Get the size required to store the call stack contents, including
 * the space for terminating null byte ('\0')
 *
 * @param exec_env the execution environment
 *
 * @return size required to store the contents, 0 means error
 */
WASM_RUNTIME_API_EXTERN uint32_t
wasm_runtime_get_call_stack_buf_size(wasm_exec_env_t exec_env);

/**
 * Dump the call stack to buffer.
 *
 * @note this function is not thread-safe, please only use this API
 *       when the exec_env is not executing
 *
 * @param exec_env the execution environment
 * @param buf buffer to store the dumped content
 * @param len length of the buffer
 *
 * @return bytes dumped to the buffer, including the terminating null
 *         byte ('\0'), 0 means error and data in buf may be invalid
 */
WASM_RUNTIME_API_EXTERN uint32_t
wasm_runtime_dump_call_stack_to_buf(wasm_exec_env_t exec_env, char *buf,
                                    uint32_t len);

/**
 * Get a custom section by name
 *
 * @param module_comm the module to find
 * @param name name of the custom section
 * @param len return the length of the content if found
 *
 * @return Custom section content (not including the name length
 *         and name string) if found, NULL otherwise
 */
WASM_RUNTIME_API_EXTERN const uint8_t *
wasm_runtime_get_custom_section(wasm_module_t const module_comm,
                                const char *name, uint32_t *len);


/**
 * Get WAMR semantic version
 */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_get_version(uint32_t *major, uint32_t *minor, uint32_t *patch);
/* clang-format on */

#ifdef __cplusplus
}
#endif

#endif /* end of _WASM_EXPORT_H */
