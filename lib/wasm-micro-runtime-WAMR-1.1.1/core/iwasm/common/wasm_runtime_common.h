/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WASM_COMMON_H
#define _WASM_COMMON_H

#include "bh_platform.h"
#include "bh_common.h"
#include "wasm_exec_env.h"
#include "wasm_native.h"
#include "../include/wasm_export.h"
#include "../interpreter/wasm.h"
#if WASM_ENABLE_LIBC_WASI != 0
#if WASM_ENABLE_UVWASI == 0
#include "wasmtime_ssp.h"
#include "posix.h"
#else
#include "uvwasi.h"
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS != 0

#define PUT_I64_TO_ADDR(addr, value)       \
    do {                                   \
        *(int64 *)(addr) = (int64)(value); \
    } while (0)
#define PUT_F64_TO_ADDR(addr, value)           \
    do {                                       \
        *(float64 *)(addr) = (float64)(value); \
    } while (0)

#define GET_I64_FROM_ADDR(addr) (*(int64 *)(addr))
#define GET_F64_FROM_ADDR(addr) (*(float64 *)(addr))

/* For STORE opcodes */
#define STORE_I64 PUT_I64_TO_ADDR
#define STORE_U32(addr, value)               \
    do {                                     \
        *(uint32 *)(addr) = (uint32)(value); \
    } while (0)
#define STORE_U16(addr, value)               \
    do {                                     \
        *(uint16 *)(addr) = (uint16)(value); \
    } while (0)

/* For LOAD opcodes */
#define LOAD_I64(addr) (*(int64 *)(addr))
#define LOAD_F64(addr) (*(float64 *)(addr))
#define LOAD_I32(addr) (*(int32 *)(addr))
#define LOAD_U32(addr) (*(uint32 *)(addr))
#define LOAD_I16(addr) (*(int16 *)(addr))
#define LOAD_U16(addr) (*(uint16 *)(addr))

#define STORE_PTR(addr, ptr)          \
    do {                              \
        *(void **)addr = (void *)ptr; \
    } while (0)

#else /* WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS != 0 */

#define PUT_I64_TO_ADDR(addr, value)         \
    do {                                     \
        uint32 *addr_u32 = (uint32 *)(addr); \
        union {                              \
            int64 val;                       \
            uint32 parts[2];                 \
        } u;                                 \
        u.val = (int64)(value);              \
        addr_u32[0] = u.parts[0];            \
        addr_u32[1] = u.parts[1];            \
    } while (0)
#define PUT_F64_TO_ADDR(addr, value)         \
    do {                                     \
        uint32 *addr_u32 = (uint32 *)(addr); \
        union {                              \
            float64 val;                     \
            uint32 parts[2];                 \
        } u;                                 \
        u.val = (value);                     \
        addr_u32[0] = u.parts[0];            \
        addr_u32[1] = u.parts[1];            \
    } while (0)

static inline int64
GET_I64_FROM_ADDR(uint32 *addr)
{
    union {
        int64 val;
        uint32 parts[2];
    } u;
    u.parts[0] = addr[0];
    u.parts[1] = addr[1];
    return u.val;
}

static inline float64
GET_F64_FROM_ADDR(uint32 *addr)
{
    union {
        float64 val;
        uint32 parts[2];
    } u;
    u.parts[0] = addr[0];
    u.parts[1] = addr[1];
    return u.val;
}

/* For STORE opcodes */
#define STORE_I64(addr, value)                      \
    do {                                            \
        uintptr_t addr_ = (uintptr_t)(addr);        \
        union {                                     \
            int64 val;                              \
            uint32 u32[2];                          \
            uint16 u16[4];                          \
            uint8 u8[8];                            \
        } u;                                        \
        if ((addr_ & (uintptr_t)7) == 0)            \
            *(int64 *)(addr) = (int64)(value);      \
        else {                                      \
            u.val = (int64)(value);                 \
            if ((addr_ & (uintptr_t)3) == 0) {      \
                ((uint32 *)(addr))[0] = u.u32[0];   \
                ((uint32 *)(addr))[1] = u.u32[1];   \
            }                                       \
            else if ((addr_ & (uintptr_t)1) == 0) { \
                ((uint16 *)(addr))[0] = u.u16[0];   \
                ((uint16 *)(addr))[1] = u.u16[1];   \
                ((uint16 *)(addr))[2] = u.u16[2];   \
                ((uint16 *)(addr))[3] = u.u16[3];   \
            }                                       \
            else {                                  \
                int32 t;                            \
                for (t = 0; t < 8; t++)             \
                    ((uint8 *)(addr))[t] = u.u8[t]; \
            }                                       \
        }                                           \
    } while (0)

#define STORE_U32(addr, value)                    \
    do {                                          \
        uintptr_t addr_ = (uintptr_t)(addr);      \
        union {                                   \
            uint32 val;                           \
            uint16 u16[2];                        \
            uint8 u8[4];                          \
        } u;                                      \
        if ((addr_ & (uintptr_t)3) == 0)          \
            *(uint32 *)(addr) = (uint32)(value);  \
        else {                                    \
            u.val = (uint32)(value);              \
            if ((addr_ & (uintptr_t)1) == 0) {    \
                ((uint16 *)(addr))[0] = u.u16[0]; \
                ((uint16 *)(addr))[1] = u.u16[1]; \
            }                                     \
            else {                                \
                ((uint8 *)(addr))[0] = u.u8[0];   \
                ((uint8 *)(addr))[1] = u.u8[1];   \
                ((uint8 *)(addr))[2] = u.u8[2];   \
                ((uint8 *)(addr))[3] = u.u8[3];   \
            }                                     \
        }                                         \
    } while (0)

#define STORE_U16(addr, value)          \
    do {                                \
        union {                         \
            uint16 val;                 \
            uint8 u8[2];                \
        } u;                            \
        u.val = (uint16)(value);        \
        ((uint8 *)(addr))[0] = u.u8[0]; \
        ((uint8 *)(addr))[1] = u.u8[1]; \
    } while (0)

/* For LOAD opcodes */
static inline int64
LOAD_I64(void *addr)
{
    uintptr_t addr1 = (uintptr_t)addr;
    union {
        int64 val;
        uint32 u32[2];
        uint16 u16[4];
        uint8 u8[8];
    } u;
    if ((addr1 & (uintptr_t)7) == 0)
        return *(int64 *)addr;

    if ((addr1 & (uintptr_t)3) == 0) {
        u.u32[0] = ((uint32 *)addr)[0];
        u.u32[1] = ((uint32 *)addr)[1];
    }
    else if ((addr1 & (uintptr_t)1) == 0) {
        u.u16[0] = ((uint16 *)addr)[0];
        u.u16[1] = ((uint16 *)addr)[1];
        u.u16[2] = ((uint16 *)addr)[2];
        u.u16[3] = ((uint16 *)addr)[3];
    }
    else {
        int32 t;
        for (t = 0; t < 8; t++)
            u.u8[t] = ((uint8 *)addr)[t];
    }
    return u.val;
}

static inline float64
LOAD_F64(void *addr)
{
    uintptr_t addr1 = (uintptr_t)addr;
    union {
        float64 val;
        uint32 u32[2];
        uint16 u16[4];
        uint8 u8[8];
    } u;
    if ((addr1 & (uintptr_t)7) == 0)
        return *(float64 *)addr;

    if ((addr1 & (uintptr_t)3) == 0) {
        u.u32[0] = ((uint32 *)addr)[0];
        u.u32[1] = ((uint32 *)addr)[1];
    }
    else if ((addr1 & (uintptr_t)1) == 0) {
        u.u16[0] = ((uint16 *)addr)[0];
        u.u16[1] = ((uint16 *)addr)[1];
        u.u16[2] = ((uint16 *)addr)[2];
        u.u16[3] = ((uint16 *)addr)[3];
    }
    else {
        int32 t;
        for (t = 0; t < 8; t++)
            u.u8[t] = ((uint8 *)addr)[t];
    }
    return u.val;
}

static inline int32
LOAD_I32(void *addr)
{
    uintptr_t addr1 = (uintptr_t)addr;
    union {
        int32 val;
        uint16 u16[2];
        uint8 u8[4];
    } u;
    if ((addr1 & (uintptr_t)3) == 0)
        return *(int32 *)addr;

    if ((addr1 & (uintptr_t)1) == 0) {
        u.u16[0] = ((uint16 *)addr)[0];
        u.u16[1] = ((uint16 *)addr)[1];
    }
    else {
        u.u8[0] = ((uint8 *)addr)[0];
        u.u8[1] = ((uint8 *)addr)[1];
        u.u8[2] = ((uint8 *)addr)[2];
        u.u8[3] = ((uint8 *)addr)[3];
    }
    return u.val;
}

static inline int16
LOAD_I16(void *addr)
{
    uintptr_t addr1 = (uintptr_t)addr;
    union {
        int16 val;
        uint8 u8[2];
    } u;
    if ((addr1 & (uintptr_t)1)) {
        u.u8[0] = ((uint8 *)addr)[0];
        u.u8[1] = ((uint8 *)addr)[1];
        return u.val;
    }
    return *(int16 *)addr;
}

#define LOAD_U32(addr) ((uint32)LOAD_I32(addr))
#define LOAD_U16(addr) ((uint16)LOAD_I16(addr))

#if UINTPTR_MAX == UINT32_MAX
#define STORE_PTR(addr, ptr) STORE_U32(addr, (uintptr_t)ptr)
#elif UINTPTR_MAX == UINT64_MAX
#define STORE_PTR(addr, ptr) STORE_I64(addr, (uintptr_t)ptr)
#endif

#endif /* WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS != 0 */

typedef struct WASMModuleCommon {
    /* Module type, for module loaded from WASM bytecode binary,
       this field is Wasm_Module_Bytecode, and this structure should
       be treated as WASMModule structure;
       for module loaded from AOT binary, this field is
       Wasm_Module_AoT, and this structure should be treated as
       AOTModule structure. */
    uint32 module_type;

    /* The following uint8[1] member is a dummy just to indicate
       some module_type dependent members follow.
       Typically it should be accessed by casting to the corresponding
       actual module_type dependent structure, not via this member. */
    uint8 module_data[1];
} WASMModuleCommon;

typedef struct WASMModuleInstanceCommon {
    /* Module instance type, for module instance loaded from WASM
       bytecode binary, this field is Wasm_Module_Bytecode, and this
       structure should be treated as WASMModuleInstance structure;
       for module instance loaded from AOT binary, this field is
       Wasm_Module_AoT, and this structure should be treated as
       AOTModuleInstance structure. */
    uint32 module_type;

    /* The following uint8[1] member is a dummy just to indicate
       some module_type dependent members follow.
       Typically it should be accessed by casting to the corresponding
       actual module_type dependent structure, not via this member. */
    uint8 module_inst_data[1];
} WASMModuleInstanceCommon;

typedef struct WASMModuleMemConsumption {
    uint32 total_size;
    uint32 module_struct_size;
    uint32 types_size;
    uint32 imports_size;
    uint32 functions_size;
    uint32 tables_size;
    uint32 memories_size;
    uint32 globals_size;
    uint32 exports_size;
    uint32 table_segs_size;
    uint32 data_segs_size;
    uint32 const_strs_size;
#if WASM_ENABLE_AOT != 0
    uint32 aot_code_size;
#endif
} WASMModuleMemConsumption;

typedef struct WASMModuleInstMemConsumption {
    uint32 total_size;
    uint32 module_inst_struct_size;
    uint32 memories_size;
    uint32 app_heap_size;
    uint32 tables_size;
    uint32 globals_size;
    uint32 functions_size;
    uint32 exports_size;
} WASMModuleInstMemConsumption;

#if WASM_ENABLE_LIBC_WASI != 0
#if WASM_ENABLE_UVWASI == 0
typedef struct WASIContext {
    struct fd_table *curfds;
    struct fd_prestats *prestats;
    struct argv_environ_values *argv_environ;
    struct addr_pool *addr_pool;
    char *ns_lookup_buf;
    char **ns_lookup_list;
    char *argv_buf;
    char **argv_list;
    char *env_buf;
    char **env_list;
} WASIContext;
#else
typedef uvwasi_t WASIContext;
#endif
#endif

#if WASM_ENABLE_MULTI_MODULE != 0
typedef struct WASMRegisteredModule {
    bh_list_link l;
    /* point to a string pool */
    const char *module_name;
    WASMModuleCommon *module;
    /* to store the original module file buffer address */
    uint8 *orig_file_buf;
    uint32 orig_file_buf_size;
} WASMRegisteredModule;
#endif

typedef struct WASMMemoryInstanceCommon {
    uint32 module_type;

    /* The following uint8[1] member is a dummy just to indicate
       some module_type dependent members follow.
       Typically it should be accessed by casting to the corresponding
       actual module_type dependent structure, not via this member. */
    uint8 memory_inst_data[1];
} WASMMemoryInstanceCommon;

typedef package_type_t PackageType;
typedef wasm_section_t WASMSection, AOTSection;

typedef struct wasm_frame_t {
    /*  wasm_instance_t */
    void *instance;
    uint32 module_offset;
    uint32 func_index;
    uint32 func_offset;
    const char *func_name_wp;
} WASMCApiFrame;

#ifdef OS_ENABLE_HW_BOUND_CHECK
/* Signal info passing to interp/aot signal handler */
typedef struct WASMSignalInfo {
    WASMExecEnv *exec_env_tls;
#ifndef BH_PLATFORM_WINDOWS
    void *sig_addr;
#else
    EXCEPTION_POINTERS *exce_info;
#endif
} WASMSignalInfo;

/* Set exec_env of thread local storage */
void
wasm_runtime_set_exec_env_tls(WASMExecEnv *exec_env);

/* Get exec_env of thread local storage */
WASMExecEnv *
wasm_runtime_get_exec_env_tls(void);
#endif

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_init(void);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_full_init(RuntimeInitArgs *init_args);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_destroy(void);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN PackageType
get_package_type(const uint8 *buf, uint32 size);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_is_xip_file(const uint8 *buf, uint32 size);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN WASMModuleCommon *
wasm_runtime_load(uint8 *buf, uint32 size, char *error_buf,
                  uint32 error_buf_size);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN WASMModuleCommon *
wasm_runtime_load_from_sections(WASMSection *section_list, bool is_aot,
                                char *error_buf, uint32 error_buf_size);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_unload(WASMModuleCommon *module);

/* Internal API */
WASMModuleInstanceCommon *
wasm_runtime_instantiate_internal(WASMModuleCommon *module, bool is_sub_inst,
                                  uint32 stack_size, uint32 heap_size,
                                  char *error_buf, uint32 error_buf_size);

/* Internal API */
void
wasm_runtime_deinstantiate_internal(WASMModuleInstanceCommon *module_inst,
                                    bool is_sub_inst);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN WASMModuleInstanceCommon *
wasm_runtime_instantiate(WASMModuleCommon *module, uint32 stack_size,
                         uint32 heap_size, char *error_buf,
                         uint32 error_buf_size);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_deinstantiate(WASMModuleInstanceCommon *module_inst);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN WASMFunctionInstanceCommon *
wasm_runtime_lookup_function(WASMModuleInstanceCommon *const module_inst,
                             const char *name, const char *signature);

/* Internal API */
WASMType *
wasm_runtime_get_function_type(const WASMFunctionInstanceCommon *function,
                               uint32 module_type);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN uint32
wasm_func_get_param_count(WASMFunctionInstanceCommon *const func_inst,
                          WASMModuleInstanceCommon *const module_inst);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN uint32
wasm_func_get_result_count(WASMFunctionInstanceCommon *const func_inst,
                           WASMModuleInstanceCommon *const module_inst);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_func_get_param_types(WASMFunctionInstanceCommon *const func_inst,
                          WASMModuleInstanceCommon *const module_inst,
                          wasm_valkind_t *param_types);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_func_get_result_types(WASMFunctionInstanceCommon *const func_inst,
                           WASMModuleInstanceCommon *const module_inst,
                           wasm_valkind_t *result_types);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN WASMExecEnv *
wasm_runtime_create_exec_env(WASMModuleInstanceCommon *module_inst,
                             uint32 stack_size);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_destroy_exec_env(WASMExecEnv *exec_env);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN WASMModuleInstanceCommon *
wasm_runtime_get_module_inst(WASMExecEnv *exec_env);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_module_inst(WASMExecEnv *exec_env,
                             WASMModuleInstanceCommon *const module_inst);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void *
wasm_runtime_get_function_attachment(WASMExecEnv *exec_env);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_user_data(WASMExecEnv *exec_env, void *user_data);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void *
wasm_runtime_get_user_data(WASMExecEnv *exec_env);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_call_wasm(WASMExecEnv *exec_env,
                       WASMFunctionInstanceCommon *function, uint32 argc,
                       uint32 argv[]);

WASM_RUNTIME_API_EXTERN bool
wasm_runtime_call_wasm_a(WASMExecEnv *exec_env,
                         WASMFunctionInstanceCommon *function,
                         uint32 num_results, wasm_val_t *results,
                         uint32 num_args, wasm_val_t *args);

WASM_RUNTIME_API_EXTERN bool
wasm_runtime_call_wasm_v(WASMExecEnv *exec_env,
                         WASMFunctionInstanceCommon *function,
                         uint32 num_results, wasm_val_t *results,
                         uint32 num_args, ...);

#if WASM_ENABLE_DEBUG_INTERP != 0
/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN uint32
wasm_runtime_start_debug_instance_with_port(WASMExecEnv *exec_env,
                                            int32_t port);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN uint32
wasm_runtime_start_debug_instance(WASMExecEnv *exec_env);
#endif

/**
 * Call a function reference of a given WASM runtime instance with
 * arguments.
 *
 * @param exec_env the execution environment to call the function
 *   which must be created from wasm_create_exec_env()
 * @param element_indices the function ference indicies, usually
 *   prvovided by the caller of a registed native function
 * @param argc the number of arguments
 * @param argv the arguments.  If the function method has return value,
 *   the first (or first two in case 64-bit return value) element of
 *   argv stores the return value of the called WASM function after this
 *   function returns.
 *
 * @return true if success, false otherwise and exception will be thrown,
 *   the caller can call wasm_runtime_get_exception to get exception info.
 */
bool
wasm_runtime_call_indirect(WASMExecEnv *exec_env, uint32 element_indices,
                           uint32 argc, uint32 argv[]);

bool
wasm_runtime_create_exec_env_singleton(WASMModuleInstanceCommon *module_inst);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN WASMExecEnv *
wasm_runtime_get_exec_env_singleton(WASMModuleInstanceCommon *module_inst);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_application_execute_main(WASMModuleInstanceCommon *module_inst, int32 argc,
                              char *argv[]);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_application_execute_func(WASMModuleInstanceCommon *module_inst,
                              const char *name, int32 argc, char *argv[]);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_exception(WASMModuleInstanceCommon *module,
                           const char *exception);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN const char *
wasm_runtime_get_exception(WASMModuleInstanceCommon *module);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_clear_exception(WASMModuleInstanceCommon *module_inst);

/* Internal API */
void
wasm_runtime_set_custom_data_internal(WASMModuleInstanceCommon *module_inst,
                                      void *custom_data);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_custom_data(WASMModuleInstanceCommon *module_inst,
                             void *custom_data);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void *
wasm_runtime_get_custom_data(WASMModuleInstanceCommon *module_inst);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN uint32
wasm_runtime_module_malloc(WASMModuleInstanceCommon *module_inst, uint32 size,
                           void **p_native_addr);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_module_free(WASMModuleInstanceCommon *module_inst, uint32 ptr);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN uint32
wasm_runtime_module_dup_data(WASMModuleInstanceCommon *module_inst,
                             const char *src, uint32 size);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_validate_app_addr(WASMModuleInstanceCommon *module_inst,
                               uint32 app_offset, uint32 size);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_validate_app_str_addr(WASMModuleInstanceCommon *module_inst,
                                   uint32 app_str_offset);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_validate_native_addr(WASMModuleInstanceCommon *module_inst,
                                  void *native_ptr, uint32 size);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void *
wasm_runtime_addr_app_to_native(WASMModuleInstanceCommon *module_inst,
                                uint32 app_offset);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN uint32
wasm_runtime_addr_native_to_app(WASMModuleInstanceCommon *module_inst,
                                void *native_ptr);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_get_app_addr_range(WASMModuleInstanceCommon *module_inst,
                                uint32 app_offset, uint32 *p_app_start_offset,
                                uint32 *p_app_end_offset);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_get_native_addr_range(WASMModuleInstanceCommon *module_inst,
                                   uint8 *native_ptr,
                                   uint8 **p_native_start_addr,
                                   uint8 **p_native_end_addr);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN const uint8 *
wasm_runtime_get_custom_section(WASMModuleCommon *const module_comm,
                                const char *name, uint32 *len);

#if WASM_ENABLE_MULTI_MODULE != 0
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_module_reader(const module_reader reader,
                               const module_destroyer destroyer);

module_reader
wasm_runtime_get_module_reader();

module_destroyer
wasm_runtime_get_module_destroyer();

bool
wasm_runtime_register_module_internal(const char *module_name,
                                      WASMModuleCommon *module,
                                      uint8 *orig_file_buf,
                                      uint32 orig_file_buf_size,
                                      char *error_buf, uint32 error_buf_size);

void
wasm_runtime_unregister_module(const WASMModuleCommon *module);

bool
wasm_runtime_add_loading_module(const char *module_name, char *error_buf,
                                uint32 error_buf_size);

void
wasm_runtime_delete_loading_module(const char *module_name);

bool
wasm_runtime_is_loading_module(const char *module_name);

void
wasm_runtime_destroy_loading_module_list();
#endif /* WASM_ENALBE_MULTI_MODULE */

bool
wasm_runtime_is_built_in_module(const char *module_name);

#if WASM_ENABLE_THREAD_MGR != 0
bool
wasm_exec_env_get_aux_stack(WASMExecEnv *exec_env, uint32 *start_offset,
                            uint32 *size);

bool
wasm_exec_env_set_aux_stack(WASMExecEnv *exec_env, uint32 start_offset,
                            uint32 size);
#endif

#if WASM_ENABLE_LIBC_WASI != 0
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_wasi_args_ex(WASMModuleCommon *module, const char *dir_list[],
                              uint32 dir_count, const char *map_dir_list[],
                              uint32 map_dir_count, const char *env_list[],
                              uint32 env_count, char *argv[], int argc,
                              int stdinfd, int stdoutfd, int stderrfd);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_wasi_args(WASMModuleCommon *module, const char *dir_list[],
                           uint32 dir_count, const char *map_dir_list[],
                           uint32 map_dir_count, const char *env_list[],
                           uint32 env_count, char *argv[], int argc);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_is_wasi_mode(WASMModuleInstanceCommon *module_inst);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN WASMFunctionInstanceCommon *
wasm_runtime_lookup_wasi_start_function(WASMModuleInstanceCommon *module_inst);

bool
wasm_runtime_init_wasi(WASMModuleInstanceCommon *module_inst,
                       const char *dir_list[], uint32 dir_count,
                       const char *map_dir_list[], uint32 map_dir_count,
                       const char *env[], uint32 env_count,
                       const char *addr_pool[], uint32 addr_pool_size,
                       const char *ns_lookup_pool[], uint32 ns_lookup_pool_size,
                       char *argv[], uint32 argc, int stdinfd, int stdoutfd,
                       int stderrfd, char *error_buf, uint32 error_buf_size);

void
wasm_runtime_destroy_wasi(WASMModuleInstanceCommon *module_inst);

void
wasm_runtime_set_wasi_ctx(WASMModuleInstanceCommon *module_inst,
                          WASIContext *wasi_ctx);

WASIContext *
wasm_runtime_get_wasi_ctx(WASMModuleInstanceCommon *module_inst);

WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_wasi_addr_pool(wasm_module_t module, const char *addr_pool[],
                                uint32 addr_pool_size);

WASM_RUNTIME_API_EXTERN void
wasm_runtime_set_wasi_ns_lookup_pool(wasm_module_t module,
                                     const char *ns_lookup_pool[],
                                     uint32 ns_lookup_pool_size);
#endif /* end of WASM_ENABLE_LIBC_WASI */

#if WASM_ENABLE_REF_TYPES != 0
/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_externref_obj2ref(WASMModuleInstanceCommon *module_inst, void *extern_obj,
                       uint32 *p_externref_idx);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_externref_ref2obj(uint32 externref_idx, void **p_extern_obj);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_externref_retain(uint32 externref_idx);

/**
 * Reclaim the externref objects/indexes which are not used by
 * module instance
 */
void
wasm_externref_reclaim(WASMModuleInstanceCommon *module_inst);

/**
 * Cleanup the externref objects/indexes of the module instance
 */
void
wasm_externref_cleanup(WASMModuleInstanceCommon *module_inst);
#endif /* end of WASM_ENABLE_REF_TYPES */

#if WASM_ENABLE_DUMP_CALL_STACK != 0
/**
 * @brief Internal implementation for dumping or printing callstack line
 *
 * @note if dump_or_print is true, then print to stdout directly;
 * if dump_or_print is false, but *buf is NULL, then return the length of the
 * line;
 * if dump_or_print is false, and *buf is not NULL, then dump content to
 * the memory pointed by *buf, and adjust *buf and *len according to actual
 * bytes dumped, and return the actual dumped length
 *
 * @param line_buf current line to dump or print
 * @param dump_or_print whether to print to stdout or dump to buf
 * @param buf [INOUT] pointer to the buffer
 * @param len [INOUT] pointer to remaining length
 * @return bytes printed to stdout or dumped to buf
 */
uint32
wasm_runtime_dump_line_buf_impl(const char *line_buf, bool dump_or_print,
                                char **buf, uint32 *len);
#endif /* end of WASM_ENABLE_DUMP_CALL_STACK != 0 */

/* Get module of the current exec_env */
WASMModuleCommon *
wasm_exec_env_get_module(WASMExecEnv *exec_env);

/**
 * Enlarge wasm memory data space.
 *
 * @param module the wasm module instance
 * @param inc_page_count denote the page number to increase
 * @return return true if enlarge successfully, false otherwise
 */
bool
wasm_runtime_enlarge_memory(WASMModuleInstanceCommon *module,
                            uint32 inc_page_count);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_register_natives(const char *module_name,
                              NativeSymbol *native_symbols,
                              uint32 n_native_symbols);

/* See wasm_export.h for description */
WASM_RUNTIME_API_EXTERN bool
wasm_runtime_register_natives_raw(const char *module_name,
                                  NativeSymbol *native_symbols,
                                  uint32 n_native_symbols);

bool
wasm_runtime_invoke_native(WASMExecEnv *exec_env, void *func_ptr,
                           const WASMType *func_type, const char *signature,
                           void *attachment, uint32 *argv, uint32 argc,
                           uint32 *ret);

bool
wasm_runtime_invoke_native_raw(WASMExecEnv *exec_env, void *func_ptr,
                               const WASMType *func_type, const char *signature,
                               void *attachment, uint32 *argv, uint32 argc,
                               uint32 *ret);

void
wasm_runtime_read_v128(const uint8 *bytes, uint64 *ret1, uint64 *ret2);

void
wasm_runtime_dump_module_mem_consumption(const WASMModuleCommon *module);

void
wasm_runtime_dump_module_inst_mem_consumption(
    const WASMModuleInstanceCommon *module_inst);

void
wasm_runtime_dump_exec_env_mem_consumption(const WASMExecEnv *exec_env);

bool
wasm_runtime_get_export_func_type(const WASMModuleCommon *module_comm,
                                  const WASMExport *export_, WASMType **out);

bool
wasm_runtime_get_export_global_type(const WASMModuleCommon *module_comm,
                                    const WASMExport *export_,
                                    uint8 *out_val_type, bool *out_mutability);

bool
wasm_runtime_get_export_memory_type(const WASMModuleCommon *module_comm,
                                    const WASMExport *export_,
                                    uint32 *out_min_page, uint32 *out_max_page);

bool
wasm_runtime_get_export_table_type(const WASMModuleCommon *module_comm,
                                   const WASMExport *export_,
                                   uint8 *out_elem_type, uint32 *out_min_size,
                                   uint32 *out_max_size);

bool
wasm_runtime_invoke_c_api_native(WASMModuleInstanceCommon *module_inst,
                                 void *func_ptr, WASMType *func_type,
                                 uint32 argc, uint32 *argv, bool with_env,
                                 void *wasm_c_api_env);

void
wasm_runtime_show_app_heap_corrupted_prompt();

#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
void
wasm_runtime_destroy_custom_sections(WASMCustomSection *section_list);
#endif

#ifdef __cplusplus
}
#endif

#endif /* end of _WASM_COMMON_H */
