/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_runtime_common.h"
#include "../interpreter/wasm_runtime.h"
#include "../aot/aot_runtime.h"
#include "mem_alloc.h"
#include "wasm_memory.h"

#if WASM_ENABLE_SHARED_MEMORY != 0
#include "../common/wasm_shared_memory.h"
#endif

typedef enum Memory_Mode {
    MEMORY_MODE_UNKNOWN = 0,
    MEMORY_MODE_POOL,
    MEMORY_MODE_ALLOCATOR,
    MEMORY_MODE_SYSTEM_ALLOCATOR
} Memory_Mode;

static Memory_Mode memory_mode = MEMORY_MODE_UNKNOWN;

static mem_allocator_t pool_allocator = NULL;

static enlarge_memory_error_callback_t enlarge_memory_error_cb;
static void *enlarge_memory_error_user_data;

#if WASM_MEM_ALLOC_WITH_USER_DATA != 0
static void *allocator_user_data = NULL;
static void *(*malloc_func)(void *user_data, unsigned int size) = NULL;
static void *(*realloc_func)(void *user_data, void *ptr,
                             unsigned int size) = NULL;
static void (*free_func)(void *user_data, void *ptr) = NULL;
#else
static void *(*malloc_func)(unsigned int size) = NULL;
static void *(*realloc_func)(void *ptr, unsigned int size) = NULL;
static void (*free_func)(void *ptr) = NULL;
#endif

static unsigned int global_pool_size;

static bool
wasm_memory_init_with_pool(void *mem, unsigned int bytes)
{
    mem_allocator_t allocator = mem_allocator_create(mem, bytes);

    if (allocator) {
        memory_mode = MEMORY_MODE_POOL;
        pool_allocator = allocator;
        global_pool_size = bytes;
        return true;
    }
    LOG_ERROR("Init memory with pool (%p, %u) failed.\n", mem, bytes);
    return false;
}

#if WASM_MEM_ALLOC_WITH_USER_DATA != 0
static bool
wasm_memory_init_with_allocator(void *_user_data, void *_malloc_func,
                                void *_realloc_func, void *_free_func)
{
    if (_malloc_func && _free_func && _malloc_func != _free_func) {
        memory_mode = MEMORY_MODE_ALLOCATOR;
        allocator_user_data = _user_data;
        malloc_func = _malloc_func;
        realloc_func = _realloc_func;
        free_func = _free_func;
        return true;
    }
    LOG_ERROR("Init memory with allocator (%p, %p, %p, %p) failed.\n",
              _user_data, _malloc_func, _realloc_func, _free_func);
    return false;
}
#else
static bool
wasm_memory_init_with_allocator(void *malloc_func_ptr, void *realloc_func_ptr,
                                void *free_func_ptr)
{
    if (malloc_func_ptr && free_func_ptr && malloc_func_ptr != free_func_ptr) {
        memory_mode = MEMORY_MODE_ALLOCATOR;
        malloc_func = malloc_func_ptr;
        realloc_func = realloc_func_ptr;
        free_func = free_func_ptr;
        return true;
    }
    LOG_ERROR("Init memory with allocator (%p, %p, %p) failed.\n",
              malloc_func_ptr, realloc_func_ptr, free_func_ptr);
    return false;
}
#endif

static inline bool
is_bounds_checks_enabled(WASMModuleInstanceCommon *module_inst)
{
#if WASM_CONFIGURABLE_BOUNDS_CHECKS != 0
    if (!module_inst) {
        return true;
    }

    return wasm_runtime_is_bounds_checks_enabled(module_inst);
#else
    return true;
#endif
}

bool
wasm_runtime_memory_init(mem_alloc_type_t mem_alloc_type,
                         const MemAllocOption *alloc_option)
{
    if (mem_alloc_type == Alloc_With_Pool) {
        return wasm_memory_init_with_pool(alloc_option->pool.heap_buf,
                                          alloc_option->pool.heap_size);
    }
    else if (mem_alloc_type == Alloc_With_Allocator) {
        return wasm_memory_init_with_allocator(
#if WASM_MEM_ALLOC_WITH_USER_DATA != 0
            alloc_option->allocator.user_data,
#endif
            alloc_option->allocator.malloc_func,
            alloc_option->allocator.realloc_func,
            alloc_option->allocator.free_func);
    }
    else if (mem_alloc_type == Alloc_With_System_Allocator) {
        memory_mode = MEMORY_MODE_SYSTEM_ALLOCATOR;
        return true;
    }
    else {
        return false;
    }
}

void
wasm_runtime_memory_destroy()
{
    if (memory_mode == MEMORY_MODE_POOL) {
#if BH_ENABLE_GC_VERIFY == 0
        (void)mem_allocator_destroy(pool_allocator);
#else
        int ret = mem_allocator_destroy(pool_allocator);
        if (ret != 0) {
            /* Memory leak detected */
            exit(-1);
        }
#endif
    }
    memory_mode = MEMORY_MODE_UNKNOWN;
}

unsigned
wasm_runtime_memory_pool_size()
{
    if (memory_mode == MEMORY_MODE_POOL)
        return global_pool_size;
    else
        return UINT32_MAX;
}

static inline void *
wasm_runtime_malloc_internal(unsigned int size)
{
    if (memory_mode == MEMORY_MODE_UNKNOWN) {
        LOG_WARNING(
            "wasm_runtime_malloc failed: memory hasn't been initialize.\n");
        return NULL;
    }
    else if (memory_mode == MEMORY_MODE_POOL) {
        return mem_allocator_malloc(pool_allocator, size);
    }
    else if (memory_mode == MEMORY_MODE_ALLOCATOR) {
#if WASM_MEM_ALLOC_WITH_USER_DATA != 0
        return malloc_func(allocator_user_data, size);
#else
        return malloc_func(size);
#endif
    }
    else {
        return os_malloc(size);
    }
}

static inline void *
wasm_runtime_realloc_internal(void *ptr, unsigned int size)
{
    if (memory_mode == MEMORY_MODE_UNKNOWN) {
        LOG_WARNING(
            "wasm_runtime_realloc failed: memory hasn't been initialize.\n");
        return NULL;
    }
    else if (memory_mode == MEMORY_MODE_POOL) {
        return mem_allocator_realloc(pool_allocator, ptr, size);
    }
    else if (memory_mode == MEMORY_MODE_ALLOCATOR) {
        if (realloc_func)
#if WASM_MEM_ALLOC_WITH_USER_DATA != 0
            return realloc_func(allocator_user_data, ptr, size);
#else
            return realloc_func(ptr, size);
#endif
        else
            return NULL;
    }
    else {
        return os_realloc(ptr, size);
    }
}

static inline void
wasm_runtime_free_internal(void *ptr)
{
    if (!ptr) {
        LOG_WARNING("warning: wasm_runtime_free with NULL pointer\n");
#if BH_ENABLE_GC_VERIFY != 0
        exit(-1);
#endif
        return;
    }

    if (memory_mode == MEMORY_MODE_UNKNOWN) {
        LOG_WARNING("warning: wasm_runtime_free failed: "
                    "memory hasn't been initialize.\n");
    }
    else if (memory_mode == MEMORY_MODE_POOL) {
        mem_allocator_free(pool_allocator, ptr);
    }
    else if (memory_mode == MEMORY_MODE_ALLOCATOR) {
#if WASM_MEM_ALLOC_WITH_USER_DATA != 0
        free_func(allocator_user_data, ptr);
#else
        free_func(ptr);
#endif
    }
    else {
        os_free(ptr);
    }
}

void *
wasm_runtime_malloc(unsigned int size)
{
    if (size == 0) {
        LOG_WARNING("warning: wasm_runtime_malloc with size zero\n");
        /* At lease alloc 1 byte to avoid malloc failed */
        size = 1;
#if BH_ENABLE_GC_VERIFY != 0
        exit(-1);
#endif
    }

    return wasm_runtime_malloc_internal(size);
}

void *
wasm_runtime_realloc(void *ptr, unsigned int size)
{
    return wasm_runtime_realloc_internal(ptr, size);
}

void
wasm_runtime_free(void *ptr)
{
    wasm_runtime_free_internal(ptr);
}

bool
wasm_runtime_get_mem_alloc_info(mem_alloc_info_t *mem_alloc_info)
{
    if (memory_mode == MEMORY_MODE_POOL) {
        return mem_allocator_get_alloc_info(pool_allocator, mem_alloc_info);
    }
    return false;
}

bool
wasm_runtime_validate_app_addr(WASMModuleInstanceCommon *module_inst_comm,
                               uint32 app_offset, uint32 size)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;
    WASMMemoryInstance *memory_inst;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);

    if (!is_bounds_checks_enabled(module_inst_comm)) {
        return true;
    }

    memory_inst = wasm_get_default_memory(module_inst);
    if (!memory_inst) {
        goto fail;
    }

    /* integer overflow check */
    if (app_offset > UINT32_MAX - size) {
        goto fail;
    }

    SHARED_MEMORY_LOCK(memory_inst);

    if (app_offset + size <= memory_inst->memory_data_size) {
        SHARED_MEMORY_UNLOCK(memory_inst);
        return true;
    }

    SHARED_MEMORY_UNLOCK(memory_inst);

fail:
    wasm_set_exception(module_inst, "out of bounds memory access");
    return false;
}

bool
wasm_runtime_validate_app_str_addr(WASMModuleInstanceCommon *module_inst_comm,
                                   uint32 app_str_offset)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;
    uint32 app_end_offset;
    char *str, *str_end;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);

    if (!is_bounds_checks_enabled(module_inst_comm)) {
        return true;
    }

    if (!wasm_runtime_get_app_addr_range(module_inst_comm, app_str_offset, NULL,
                                         &app_end_offset))
        goto fail;

    str = wasm_runtime_addr_app_to_native(module_inst_comm, app_str_offset);
    str_end = str + (app_end_offset - app_str_offset);
    while (str < str_end && *str != '\0')
        str++;
    if (str == str_end)
        goto fail;

    return true;
fail:
    wasm_set_exception(module_inst, "out of bounds memory access");
    return false;
}

bool
wasm_runtime_validate_native_addr(WASMModuleInstanceCommon *module_inst_comm,
                                  void *native_ptr, uint32 size)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;
    WASMMemoryInstance *memory_inst;
    uint8 *addr = (uint8 *)native_ptr;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);

    if (!is_bounds_checks_enabled(module_inst_comm)) {
        return true;
    }

    memory_inst = wasm_get_default_memory(module_inst);
    if (!memory_inst) {
        goto fail;
    }

    /* integer overflow check */
    if ((uintptr_t)addr > UINTPTR_MAX - size) {
        goto fail;
    }

    SHARED_MEMORY_LOCK(memory_inst);

    if (memory_inst->memory_data <= addr
        && addr + size <= memory_inst->memory_data_end) {
        SHARED_MEMORY_UNLOCK(memory_inst);
        return true;
    }

    SHARED_MEMORY_UNLOCK(memory_inst);

fail:
    wasm_set_exception(module_inst, "out of bounds memory access");
    return false;
}

void *
wasm_runtime_addr_app_to_native(WASMModuleInstanceCommon *module_inst_comm,
                                uint32 app_offset)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;
    WASMMemoryInstance *memory_inst;
    uint8 *addr;
    bool bounds_checks;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);

    bounds_checks = is_bounds_checks_enabled(module_inst_comm);

    memory_inst = wasm_get_default_memory(module_inst);
    if (!memory_inst) {
        return NULL;
    }

    SHARED_MEMORY_LOCK(memory_inst);

    addr = memory_inst->memory_data + app_offset;

    if (bounds_checks) {
        if (memory_inst->memory_data <= addr
            && addr < memory_inst->memory_data_end) {
            SHARED_MEMORY_UNLOCK(memory_inst);
            return addr;
        }
    }
    /* If bounds checks is disabled, return the address directly */
    else if (app_offset != 0) {
        SHARED_MEMORY_UNLOCK(memory_inst);
        return addr;
    }

    SHARED_MEMORY_UNLOCK(memory_inst);
    return NULL;
}

uint32
wasm_runtime_addr_native_to_app(WASMModuleInstanceCommon *module_inst_comm,
                                void *native_ptr)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;
    WASMMemoryInstance *memory_inst;
    uint8 *addr = (uint8 *)native_ptr;
    bool bounds_checks;
    uint32 ret;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);

    bounds_checks = is_bounds_checks_enabled(module_inst_comm);

    memory_inst = wasm_get_default_memory(module_inst);
    if (!memory_inst) {
        return 0;
    }

    SHARED_MEMORY_LOCK(memory_inst);

    if (bounds_checks) {
        if (memory_inst->memory_data <= addr
            && addr < memory_inst->memory_data_end) {
            ret = (uint32)(addr - memory_inst->memory_data);
            SHARED_MEMORY_UNLOCK(memory_inst);
            return ret;
        }
    }
    /* If bounds checks is disabled, return the offset directly */
    else if (addr != NULL) {
        ret = (uint32)(addr - memory_inst->memory_data);
        SHARED_MEMORY_UNLOCK(memory_inst);
        return ret;
    }

    SHARED_MEMORY_UNLOCK(memory_inst);
    return 0;
}

bool
wasm_runtime_get_app_addr_range(WASMModuleInstanceCommon *module_inst_comm,
                                uint32 app_offset, uint32 *p_app_start_offset,
                                uint32 *p_app_end_offset)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;
    WASMMemoryInstance *memory_inst;
    uint32 memory_data_size;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);

    memory_inst = wasm_get_default_memory(module_inst);
    if (!memory_inst) {
        return false;
    }

    SHARED_MEMORY_LOCK(memory_inst);

    memory_data_size = memory_inst->memory_data_size;

    if (app_offset < memory_data_size) {
        if (p_app_start_offset)
            *p_app_start_offset = 0;
        if (p_app_end_offset)
            *p_app_end_offset = memory_data_size;
        SHARED_MEMORY_UNLOCK(memory_inst);
        return true;
    }

    SHARED_MEMORY_UNLOCK(memory_inst);
    return false;
}

bool
wasm_runtime_get_native_addr_range(WASMModuleInstanceCommon *module_inst_comm,
                                   uint8 *native_ptr,
                                   uint8 **p_native_start_addr,
                                   uint8 **p_native_end_addr)
{
    WASMModuleInstance *module_inst = (WASMModuleInstance *)module_inst_comm;
    WASMMemoryInstance *memory_inst;
    uint8 *addr = (uint8 *)native_ptr;

    bh_assert(module_inst_comm->module_type == Wasm_Module_Bytecode
              || module_inst_comm->module_type == Wasm_Module_AoT);

    memory_inst = wasm_get_default_memory(module_inst);
    if (!memory_inst) {
        return false;
    }

    SHARED_MEMORY_LOCK(memory_inst);

    if (memory_inst->memory_data <= addr
        && addr < memory_inst->memory_data_end) {
        if (p_native_start_addr)
            *p_native_start_addr = memory_inst->memory_data;
        if (p_native_end_addr)
            *p_native_end_addr = memory_inst->memory_data_end;
        SHARED_MEMORY_UNLOCK(memory_inst);
        return true;
    }

    SHARED_MEMORY_UNLOCK(memory_inst);
    return false;
}

bool
wasm_check_app_addr_and_convert(WASMModuleInstance *module_inst, bool is_str,
                                uint32 app_buf_addr, uint32 app_buf_size,
                                void **p_native_addr)
{
    WASMMemoryInstance *memory_inst = wasm_get_default_memory(module_inst);
    uint8 *native_addr;
    bool bounds_checks;

    if (!memory_inst) {
        wasm_set_exception(module_inst, "out of bounds memory access");
        return false;
    }

    native_addr = memory_inst->memory_data + app_buf_addr;

    bounds_checks = is_bounds_checks_enabled((wasm_module_inst_t)module_inst);

    if (!bounds_checks) {
        if (app_buf_addr == 0) {
            native_addr = NULL;
        }
        goto success;
    }

    /* No need to check the app_offset and buf_size if memory access
       boundary check with hardware trap is enabled */
#ifndef OS_ENABLE_HW_BOUND_CHECK
    SHARED_MEMORY_LOCK(memory_inst);

    if (app_buf_addr >= memory_inst->memory_data_size) {
        goto fail;
    }

    if (!is_str) {
        if (app_buf_size > memory_inst->memory_data_size - app_buf_addr) {
            goto fail;
        }
    }
    else {
        const char *str, *str_end;

        /* The whole string must be in the linear memory */
        str = (const char *)native_addr;
        str_end = (const char *)memory_inst->memory_data_end;
        while (str < str_end && *str != '\0')
            str++;
        if (str == str_end)
            goto fail;
    }

    SHARED_MEMORY_UNLOCK(memory_inst);
#endif

success:
    *p_native_addr = (void *)native_addr;
    return true;

#ifndef OS_ENABLE_HW_BOUND_CHECK
fail:
    SHARED_MEMORY_UNLOCK(memory_inst);
    wasm_set_exception(module_inst, "out of bounds memory access");
    return false;
#endif
}

WASMMemoryInstance *
wasm_get_default_memory(WASMModuleInstance *module_inst)
{
    if (module_inst->memories)
        return module_inst->memories[0];
    else
        return NULL;
}

void
wasm_runtime_set_mem_bound_check_bytes(WASMMemoryInstance *memory,
                                       uint64 memory_data_size)
{
#if WASM_ENABLE_FAST_JIT != 0 || WASM_ENABLE_JIT != 0 || WASM_ENABLE_AOT != 0
#if UINTPTR_MAX == UINT64_MAX
    memory->mem_bound_check_1byte.u64 = memory_data_size - 1;
    memory->mem_bound_check_2bytes.u64 = memory_data_size - 2;
    memory->mem_bound_check_4bytes.u64 = memory_data_size - 4;
    memory->mem_bound_check_8bytes.u64 = memory_data_size - 8;
    memory->mem_bound_check_16bytes.u64 = memory_data_size - 16;
#else
    memory->mem_bound_check_1byte.u32[0] = (uint32)memory_data_size - 1;
    memory->mem_bound_check_2bytes.u32[0] = (uint32)memory_data_size - 2;
    memory->mem_bound_check_4bytes.u32[0] = (uint32)memory_data_size - 4;
    memory->mem_bound_check_8bytes.u32[0] = (uint32)memory_data_size - 8;
    memory->mem_bound_check_16bytes.u32[0] = (uint32)memory_data_size - 16;
#endif
#endif
}

#ifndef OS_ENABLE_HW_BOUND_CHECK
bool
wasm_enlarge_memory_internal(WASMModuleInstance *module, uint32 inc_page_count)
{
    WASMMemoryInstance *memory = wasm_get_default_memory(module);
    uint8 *memory_data_old, *memory_data_new, *heap_data_old;
    uint32 num_bytes_per_page, heap_size, total_size_old = 0;
    uint32 cur_page_count, max_page_count, total_page_count;
    uint64 total_size_new;
    bool ret = true;
    enlarge_memory_error_reason_t failure_reason = INTERNAL_ERROR;

    if (!memory) {
        ret = false;
        goto return_func;
    }

    heap_data_old = memory->heap_data;
    heap_size = (uint32)(memory->heap_data_end - memory->heap_data);

    memory_data_old = memory->memory_data;
    total_size_old = memory->memory_data_size;

    num_bytes_per_page = memory->num_bytes_per_page;
    cur_page_count = memory->cur_page_count;
    max_page_count = memory->max_page_count;
    total_page_count = inc_page_count + cur_page_count;
    total_size_new = num_bytes_per_page * (uint64)total_page_count;

    if (inc_page_count <= 0)
        /* No need to enlarge memory */
        return true;

    if (total_page_count < cur_page_count) { /* integer overflow */
        ret = false;
        goto return_func;
    }

    if (total_page_count > max_page_count) {
        failure_reason = MAX_SIZE_REACHED;
        ret = false;
        goto return_func;
    }

    bh_assert(total_size_new <= 4 * (uint64)BH_GB);
    if (total_size_new > UINT32_MAX) {
        /* Resize to 1 page with size 4G-1 */
        num_bytes_per_page = UINT32_MAX;
        total_page_count = max_page_count = 1;
        total_size_new = UINT32_MAX;
    }

#if WASM_ENABLE_SHARED_MEMORY != 0
    if (shared_memory_is_shared(memory)) {
        memory->num_bytes_per_page = num_bytes_per_page;
        memory->cur_page_count = total_page_count;
        memory->max_page_count = max_page_count;
        SET_LINEAR_MEMORY_SIZE(memory, (uint32)total_size_new);
        memory->memory_data_end = memory->memory_data + (uint32)total_size_new;

        wasm_runtime_set_mem_bound_check_bytes(memory, total_size_new);
        return true;
    }
#endif

    if (heap_size > 0) {
        if (mem_allocator_is_heap_corrupted(memory->heap_handle)) {
            wasm_runtime_show_app_heap_corrupted_prompt();
            ret = false;
            goto return_func;
        }
    }

    if (!(memory_data_new =
              wasm_runtime_realloc(memory_data_old, (uint32)total_size_new))) {
        if (!(memory_data_new = wasm_runtime_malloc((uint32)total_size_new))) {
            ret = false;
            goto return_func;
        }
        if (memory_data_old) {
            bh_memcpy_s(memory_data_new, (uint32)total_size_new,
                        memory_data_old, total_size_old);
            wasm_runtime_free(memory_data_old);
        }
    }

    memset(memory_data_new + total_size_old, 0,
           (uint32)total_size_new - total_size_old);

    if (heap_size > 0) {
        if (mem_allocator_migrate(memory->heap_handle,
                                  (char *)heap_data_old
                                      + (memory_data_new - memory_data_old),
                                  heap_size)
            != 0) {
            /* Don't return here as memory->memory_data is obsolete and
               must be updated to be correctly used later. */
            ret = false;
        }
    }

    memory->heap_data = memory_data_new + (heap_data_old - memory_data_old);
    memory->heap_data_end = memory->heap_data + heap_size;

    memory->num_bytes_per_page = num_bytes_per_page;
    memory->cur_page_count = total_page_count;
    memory->max_page_count = max_page_count;
    memory->memory_data_size = (uint32)total_size_new;

    memory->memory_data = memory_data_new;
    memory->memory_data_end = memory_data_new + (uint32)total_size_new;

    wasm_runtime_set_mem_bound_check_bytes(memory, total_size_new);

#if defined(os_writegsbase)
    /* write base addr of linear memory to GS segment register */
    os_writegsbase(memory_data_new);
#endif

return_func:
    if (!ret && enlarge_memory_error_cb) {
        WASMExecEnv *exec_env = NULL;

#if WASM_ENABLE_INTERP != 0
        if (module->module_type == Wasm_Module_Bytecode)
            exec_env =
                ((WASMModuleInstanceExtra *)module->e)->common.cur_exec_env;
#endif
#if WASM_ENABLE_AOT != 0
        if (module->module_type == Wasm_Module_AoT)
            exec_env =
                ((AOTModuleInstanceExtra *)module->e)->common.cur_exec_env;
#endif

        enlarge_memory_error_cb(inc_page_count, total_size_old, 0,
                                failure_reason,
                                (WASMModuleInstanceCommon *)module, exec_env,
                                enlarge_memory_error_user_data);
    }

    return ret;
}
#else
bool
wasm_enlarge_memory_internal(WASMModuleInstance *module, uint32 inc_page_count)
{
    WASMMemoryInstance *memory = wasm_get_default_memory(module);
    uint32 num_bytes_per_page, total_size_old = 0;
    uint32 cur_page_count, max_page_count, total_page_count;
    uint64 total_size_new;
    bool ret = true;
    enlarge_memory_error_reason_t failure_reason = INTERNAL_ERROR;

    if (!memory) {
        ret = false;
        goto return_func;
    }

    num_bytes_per_page = memory->num_bytes_per_page;
    cur_page_count = memory->cur_page_count;
    max_page_count = memory->max_page_count;
    total_size_old = num_bytes_per_page * cur_page_count;
    total_page_count = inc_page_count + cur_page_count;
    total_size_new = num_bytes_per_page * (uint64)total_page_count;

    if (inc_page_count <= 0)
        /* No need to enlarge memory */
        return true;

    if (total_page_count < cur_page_count) { /* integer overflow */
        ret = false;
        goto return_func;
    }

    if (total_page_count > max_page_count) {
        failure_reason = MAX_SIZE_REACHED;
        ret = false;
        goto return_func;
    }

    bh_assert(total_size_new <= 4 * (uint64)BH_GB);
    if (total_size_new > UINT32_MAX) {
        /* Resize to 1 page with size 4G-1 */
        num_bytes_per_page = UINT32_MAX;
        total_page_count = max_page_count = 1;
        total_size_new = UINT32_MAX;
    }

#ifdef BH_PLATFORM_WINDOWS
    if (!os_mem_commit(memory->memory_data_end,
                       (uint32)total_size_new - total_size_old,
                       MMAP_PROT_READ | MMAP_PROT_WRITE)) {
        ret = false;
        goto return_func;
    }
#endif

    if (os_mprotect(memory->memory_data_end,
                    (uint32)total_size_new - total_size_old,
                    MMAP_PROT_READ | MMAP_PROT_WRITE)
        != 0) {
#ifdef BH_PLATFORM_WINDOWS
        os_mem_decommit(memory->memory_data_end,
                        (uint32)total_size_new - total_size_old);
#endif
        ret = false;
        goto return_func;
    }

    /* The increased pages are filled with zero by the OS when os_mmap,
       no need to memset it again here */

    memory->num_bytes_per_page = num_bytes_per_page;
    memory->cur_page_count = total_page_count;
    memory->max_page_count = max_page_count;
    SET_LINEAR_MEMORY_SIZE(memory, (uint32)total_size_new);
    memory->memory_data_end = memory->memory_data + (uint32)total_size_new;

    wasm_runtime_set_mem_bound_check_bytes(memory, total_size_new);

return_func:
    if (!ret && enlarge_memory_error_cb) {
        WASMExecEnv *exec_env = NULL;

#if WASM_ENABLE_INTERP != 0
        if (module->module_type == Wasm_Module_Bytecode)
            exec_env =
                ((WASMModuleInstanceExtra *)module->e)->common.cur_exec_env;
#endif
#if WASM_ENABLE_AOT != 0
        if (module->module_type == Wasm_Module_AoT)
            exec_env =
                ((AOTModuleInstanceExtra *)module->e)->common.cur_exec_env;
#endif

        enlarge_memory_error_cb(inc_page_count, total_size_old, 0,
                                failure_reason,
                                (WASMModuleInstanceCommon *)module, exec_env,
                                enlarge_memory_error_user_data);
    }

    return ret;
}
#endif /* end of OS_ENABLE_HW_BOUND_CHECK */

void
wasm_runtime_set_enlarge_mem_error_callback(
    const enlarge_memory_error_callback_t callback, void *user_data)
{
    enlarge_memory_error_cb = callback;
    enlarge_memory_error_user_data = user_data;
}

bool
wasm_enlarge_memory(WASMModuleInstance *module, uint32 inc_page_count)
{
    bool ret = false;

#if WASM_ENABLE_SHARED_MEMORY != 0
    if (module->memory_count > 0)
        shared_memory_lock(module->memories[0]);
#endif
    ret = wasm_enlarge_memory_internal(module, inc_page_count);
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (module->memory_count > 0)
        shared_memory_unlock(module->memories[0]);
#endif

    return ret;
}
