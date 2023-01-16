/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_runtime.h"
#include "bh_log.h"
#include "mem_alloc.h"
#include "../common/wasm_runtime_common.h"
#if WASM_ENABLE_SHARED_MEMORY != 0
#include "../common/wasm_shared_memory.h"
#endif
#if WASM_ENABLE_THREAD_MGR != 0
#include "../libraries/thread-mgr/thread_manager.h"
#endif

/*
 * Note: These offsets need to match the values hardcoded in
 * AoT compilation code: aot_create_func_context, check_suspend_flags.
 */

bh_static_assert(offsetof(WASMExecEnv, module_inst) == 2 * sizeof(uintptr_t));
bh_static_assert(offsetof(WASMExecEnv, argv_buf) == 3 * sizeof(uintptr_t));
bh_static_assert(offsetof(WASMExecEnv, native_stack_boundary)
                 == 4 * sizeof(uintptr_t));
bh_static_assert(offsetof(WASMExecEnv, suspend_flags) == 5 * sizeof(uintptr_t));
bh_static_assert(offsetof(WASMExecEnv, aux_stack_boundary)
                 == 6 * sizeof(uintptr_t));
bh_static_assert(offsetof(WASMExecEnv, aux_stack_bottom)
                 == 7 * sizeof(uintptr_t));
bh_static_assert(offsetof(WASMExecEnv, native_symbol) == 8 * sizeof(uintptr_t));

static void
set_error_buf(char *error_buf, uint32 error_buf_size, const char *string)
{
    if (error_buf != NULL) {
        snprintf(error_buf, error_buf_size, "AOT module instantiate failed: %s",
                 string);
    }
}

static void
set_error_buf_v(char *error_buf, uint32 error_buf_size, const char *format, ...)
{
    va_list args;
    char buf[128];

    if (error_buf != NULL) {
        va_start(args, format);
        vsnprintf(buf, sizeof(buf), format, args);
        va_end(args);
        snprintf(error_buf, error_buf_size, "AOT module instantiate failed: %s",
                 buf);
    }
}

static void *
runtime_malloc(uint64 size, char *error_buf, uint32 error_buf_size)
{
    void *mem;

    if (size >= UINT32_MAX || !(mem = wasm_runtime_malloc((uint32)size))) {
        set_error_buf(error_buf, error_buf_size, "allocate memory failed");
        return NULL;
    }

    memset(mem, 0, (uint32)size);
    return mem;
}

static bool
check_global_init_expr(const AOTModule *module, uint32 global_index,
                       char *error_buf, uint32 error_buf_size)
{
    if (global_index >= module->import_global_count + module->global_count) {
        set_error_buf_v(error_buf, error_buf_size, "unknown global %d",
                        global_index);
        return false;
    }

    /**
     * Currently, constant expressions occurring as initializers of
     * globals are further constrained in that contained global.get
     * instructions are only allowed to refer to imported globals.
     *
     * And initializer expression cannot reference a mutable global.
     */
    if (global_index >= module->import_global_count
        || module->import_globals->is_mutable) {
        set_error_buf(error_buf, error_buf_size,
                      "constant expression required");
        return false;
    }

    return true;
}

static void
init_global_data(uint8 *global_data, uint8 type, WASMValue *initial_value)
{
    switch (type) {
        case VALUE_TYPE_I32:
        case VALUE_TYPE_F32:
#if WASM_ENABLE_REF_TYPES != 0
        case VALUE_TYPE_FUNCREF:
        case VALUE_TYPE_EXTERNREF:
#endif
            *(int32 *)global_data = initial_value->i32;
            break;
        case VALUE_TYPE_I64:
        case VALUE_TYPE_F64:
            bh_memcpy_s(global_data, sizeof(int64), &initial_value->i64,
                        sizeof(int64));
            break;
#if WASM_ENABLE_SIMD != 0
        case VALUE_TYPE_V128:
            bh_memcpy_s(global_data, sizeof(V128), &initial_value->i64,
                        sizeof(V128));
            break;
#endif
        default:
            bh_assert(0);
    }
}

static bool
global_instantiate(AOTModuleInstance *module_inst, AOTModule *module,
                   char *error_buf, uint32 error_buf_size)
{
    uint32 i;
    InitializerExpression *init_expr;
    uint8 *p = (uint8 *)module_inst->global_data.ptr;
    AOTImportGlobal *import_global = module->import_globals;
    AOTGlobal *global = module->globals;

    /* Initialize import global data */
    for (i = 0; i < module->import_global_count; i++, import_global++) {
        bh_assert(import_global->data_offset
                  == (uint32)(p - (uint8 *)module_inst->global_data.ptr));
        init_global_data(p, import_global->type,
                         &import_global->global_data_linked);
        p += import_global->size;
    }

    /* Initialize defined global data */
    for (i = 0; i < module->global_count; i++, global++) {
        bh_assert(global->data_offset
                  == (uint32)(p - (uint8 *)module_inst->global_data.ptr));
        init_expr = &global->init_expr;
        switch (init_expr->init_expr_type) {
            case INIT_EXPR_TYPE_GET_GLOBAL:
            {
                if (!check_global_init_expr(module, init_expr->u.global_index,
                                            error_buf, error_buf_size)) {
                    return false;
                }
                init_global_data(
                    p, global->type,
                    &module->import_globals[init_expr->u.global_index]
                         .global_data_linked);
                break;
            }
#if WASM_ENABLE_REF_TYPES != 0
            case INIT_EXPR_TYPE_REFNULL_CONST:
            {
                *(uint32 *)p = NULL_REF;
                break;
            }
#endif
            default:
            {
                init_global_data(p, global->type, &init_expr->u);
                break;
            }
        }
        p += global->size;
    }

    bh_assert(module_inst->global_data_size
              == (uint32)(p - (uint8 *)module_inst->global_data.ptr));
    return true;
}

AOTTableInstance *
aot_next_tbl_inst(const AOTTableInstance *tbl_inst)
{
    uint32 offset = offsetof(AOTTableInstance, data);
    offset += tbl_inst->max_size * sizeof(uint32);
    return (AOTTableInstance *)((uint8 *)tbl_inst + offset);
}

static inline AOTTableInstance *
aot_get_table_inst(const AOTModuleInstance *module_inst, uint32 tbl_idx)
{
    uint32 i = 0;
    AOTTableInstance *tbl_inst = (AOTTableInstance *)module_inst->tables.ptr;

    while (i != tbl_idx) {
        tbl_inst = aot_next_tbl_inst(tbl_inst);
        ++i;
    }

    return tbl_inst;
}

static bool
table_instantiate(AOTModuleInstance *module_inst, AOTModule *module,
                  char *error_buf, uint32 error_buf_size)
{
    uint32 i, global_index, global_data_offset, base_offset, length;
    AOTTableInitData *table_seg;
    AOTTableInstance *tbl_inst = (AOTTableInstance *)module_inst->tables.ptr;

    /*
     * treat import table like a local one until we enable module linking
     * in AOT mode
     */
    for (i = 0; i != module_inst->table_count; ++i) {
        if (i < module->import_table_count) {
            AOTImportTable *import_table = module->import_tables + i;
            tbl_inst->cur_size = import_table->table_init_size;
            tbl_inst->max_size = aot_get_imp_tbl_data_slots(import_table);
        }
        else {
            AOTTable *table = module->tables + (i - module->import_table_count);
            tbl_inst->cur_size = table->table_init_size;
            tbl_inst->max_size = aot_get_tbl_data_slots(table);
        }

        tbl_inst = aot_next_tbl_inst(tbl_inst);
    }

    /* fill table with element segment content */
    for (i = 0; i < module->table_init_data_count; i++) {
        table_seg = module->table_init_data_list[i];

#if WASM_ENABLE_REF_TYPES != 0
        if (!wasm_elem_is_active(table_seg->mode))
            continue;
#endif

        bh_assert(table_seg->table_index < module_inst->table_count);

        tbl_inst = aot_get_table_inst(module_inst, table_seg->table_index);
        bh_assert(tbl_inst);

#if WASM_ENABLE_REF_TYPES != 0
        bh_assert(
            table_seg->offset.init_expr_type == INIT_EXPR_TYPE_I32_CONST
            || table_seg->offset.init_expr_type == INIT_EXPR_TYPE_GET_GLOBAL
            || table_seg->offset.init_expr_type == INIT_EXPR_TYPE_FUNCREF_CONST
            || table_seg->offset.init_expr_type
                   == INIT_EXPR_TYPE_REFNULL_CONST);
#else
        bh_assert(table_seg->offset.init_expr_type == INIT_EXPR_TYPE_I32_CONST
                  || table_seg->offset.init_expr_type
                         == INIT_EXPR_TYPE_GET_GLOBAL);
#endif

        /* Resolve table data base offset */
        if (table_seg->offset.init_expr_type == INIT_EXPR_TYPE_GET_GLOBAL) {
            global_index = table_seg->offset.u.global_index;

            if (!check_global_init_expr(module, global_index, error_buf,
                                        error_buf_size)) {
                return false;
            }

            if (global_index < module->import_global_count)
                global_data_offset =
                    module->import_globals[global_index].data_offset;
            else
                global_data_offset =
                    module->globals[global_index - module->import_global_count]
                        .data_offset;

            base_offset = *(uint32 *)((uint8 *)module_inst->global_data.ptr
                                      + global_data_offset);
        }
        else
            base_offset = (uint32)table_seg->offset.u.i32;

        /* Copy table data */
        /* base_offset only since length might negative */
        if (base_offset > tbl_inst->cur_size) {
#if WASM_ENABLE_REF_TYPES != 0
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds table access");
#else
            set_error_buf(error_buf, error_buf_size,
                          "elements segment does not fit");
#endif
            return false;
        }

        /* base_offset + length(could be zero) */
        length = table_seg->func_index_count;
        if (base_offset + length > tbl_inst->cur_size) {
#if WASM_ENABLE_REF_TYPES != 0
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds table access");
#else
            set_error_buf(error_buf, error_buf_size,
                          "elements segment does not fit");
#endif
            return false;
        }

        /**
         * Check function index in the current module inst for now.
         * will check the linked table inst owner in future
         */
        bh_memcpy_s((uint32 *)tbl_inst->data + base_offset,
                    (tbl_inst->max_size - base_offset) * sizeof(uint32),
                    table_seg->func_indexes, length * sizeof(uint32));
    }

    return true;
}

static void
memories_deinstantiate(AOTModuleInstance *module_inst)
{
    uint32 i;
    AOTMemoryInstance *memory_inst;

    for (i = 0; i < module_inst->memory_count; i++) {
        memory_inst = ((AOTMemoryInstance **)module_inst->memories.ptr)[i];
        if (memory_inst) {
#if WASM_ENABLE_SHARED_MEMORY != 0
            if (memory_inst->is_shared) {
                int32 ref_count = shared_memory_dec_reference(
                    (WASMModuleCommon *)module_inst->aot_module.ptr);
                bh_assert(ref_count >= 0);

                /* if the reference count is not zero,
                    don't free the memory */
                if (ref_count > 0)
                    continue;
            }
#endif
            if (memory_inst->heap_handle.ptr) {
                mem_allocator_destroy(memory_inst->heap_handle.ptr);
                wasm_runtime_free(memory_inst->heap_handle.ptr);
            }

            if (memory_inst->memory_data.ptr) {
#ifndef OS_ENABLE_HW_BOUND_CHECK
                wasm_runtime_free(memory_inst->memory_data.ptr);
#else
#ifdef BH_PLATFORM_WINDOWS
                os_mem_decommit(memory_inst->memory_data.ptr,
                                memory_inst->num_bytes_per_page
                                    * memory_inst->cur_page_count);
#endif
                os_munmap((uint8 *)memory_inst->memory_data.ptr,
                          8 * (uint64)BH_GB);
#endif
            }
        }
    }
    wasm_runtime_free(module_inst->memories.ptr);
}

static AOTMemoryInstance *
memory_instantiate(AOTModuleInstance *module_inst, AOTModule *module,
                   AOTMemoryInstance *memory_inst, AOTMemory *memory,
                   uint32 heap_size, char *error_buf, uint32 error_buf_size)
{
    void *heap_handle;
    uint32 num_bytes_per_page = memory->num_bytes_per_page;
    uint32 init_page_count = memory->mem_init_page_count;
    uint32 max_page_count = memory->mem_max_page_count;
    uint32 inc_page_count, aux_heap_base, global_idx;
    uint32 bytes_of_last_page, bytes_to_page_end;
    uint32 heap_offset = num_bytes_per_page * init_page_count;
    uint64 total_size;
    uint8 *p = NULL, *global_addr;
#ifdef OS_ENABLE_HW_BOUND_CHECK
    uint8 *mapped_mem;
    uint64 map_size = 8 * (uint64)BH_GB;
    uint64 page_size = os_getpagesize();
#endif

#if WASM_ENABLE_SHARED_MEMORY != 0
    bool is_shared_memory = memory->memory_flags & 0x02 ? true : false;

    /* Shared memory */
    if (is_shared_memory) {
        AOTMemoryInstance *shared_memory_instance;
        WASMSharedMemNode *node =
            wasm_module_get_shared_memory((WASMModuleCommon *)module);
        /* If the memory of this module has been instantiated,
            return the memory instance directly */
        if (node) {
            uint32 ref_count;
            ref_count = shared_memory_inc_reference((WASMModuleCommon *)module);
            bh_assert(ref_count > 0);
            shared_memory_instance =
                (AOTMemoryInstance *)shared_memory_get_memory_inst(node);
            bh_assert(shared_memory_instance);

            (void)ref_count;
            return shared_memory_instance;
        }
    }
#endif

    if (heap_size > 0 && module->malloc_func_index != (uint32)-1
        && module->free_func_index != (uint32)-1) {
        /* Disable app heap, use malloc/free function exported
           by wasm app to allocate/free memory instead */
        heap_size = 0;
    }

    if (init_page_count == max_page_count && init_page_count == 1) {
        /* If only one page and at most one page, we just append
           the app heap to the end of linear memory, enlarge the
           num_bytes_per_page, and don't change the page count */
        heap_offset = num_bytes_per_page;
        num_bytes_per_page += heap_size;
        if (num_bytes_per_page < heap_size) {
            set_error_buf(error_buf, error_buf_size,
                          "failed to insert app heap into linear memory, "
                          "try using `--heap_size=0` option");
            return NULL;
        }
    }
    else if (heap_size > 0) {
        if (init_page_count == max_page_count && init_page_count == 0) {
            /* If the memory data size is always 0, we resize it to
               one page for app heap */
            num_bytes_per_page = heap_size;
            heap_offset = 0;
            inc_page_count = 1;
        }
        else if (module->aux_heap_base_global_index != (uint32)-1
                 && module->aux_heap_base
                        < num_bytes_per_page * init_page_count) {
            /* Insert app heap before __heap_base */
            aux_heap_base = module->aux_heap_base;
            bytes_of_last_page = aux_heap_base % num_bytes_per_page;
            if (bytes_of_last_page == 0)
                bytes_of_last_page = num_bytes_per_page;
            bytes_to_page_end = num_bytes_per_page - bytes_of_last_page;
            inc_page_count =
                (heap_size - bytes_to_page_end + num_bytes_per_page - 1)
                / num_bytes_per_page;
            heap_offset = aux_heap_base;
            aux_heap_base += heap_size;

            bytes_of_last_page = aux_heap_base % num_bytes_per_page;
            if (bytes_of_last_page == 0)
                bytes_of_last_page = num_bytes_per_page;
            bytes_to_page_end = num_bytes_per_page - bytes_of_last_page;
            if (bytes_to_page_end < 1 * BH_KB) {
                aux_heap_base += 1 * BH_KB;
                inc_page_count++;
            }

            /* Adjust __heap_base global value */
            global_idx = module->aux_heap_base_global_index
                         - module->import_global_count;
            global_addr = (uint8 *)module_inst->global_data.ptr
                          + module->globals[global_idx].data_offset;
            *(uint32 *)global_addr = aux_heap_base;
            LOG_VERBOSE("Reset __heap_base global to %u", aux_heap_base);
        }
        else {
            /* Insert app heap before new page */
            inc_page_count =
                (heap_size + num_bytes_per_page - 1) / num_bytes_per_page;
            heap_offset = num_bytes_per_page * init_page_count;
            heap_size = num_bytes_per_page * inc_page_count;
            if (heap_size > 0)
                heap_size -= 1 * BH_KB;
        }
        init_page_count += inc_page_count;
        max_page_count += inc_page_count;
        if (init_page_count > DEFAULT_MAX_PAGES) {
            set_error_buf(error_buf, error_buf_size,
                          "failed to insert app heap into linear memory, "
                          "try using `--heap_size=0` option");
            return NULL;
        }
        else if (init_page_count == DEFAULT_MAX_PAGES) {
            num_bytes_per_page = UINT32_MAX;
            init_page_count = max_page_count = 1;
        }
        if (max_page_count > DEFAULT_MAX_PAGES)
            max_page_count = DEFAULT_MAX_PAGES;
    }

    LOG_VERBOSE("Memory instantiate:");
    LOG_VERBOSE("  page bytes: %u, init pages: %u, max pages: %u",
                num_bytes_per_page, init_page_count, max_page_count);
    LOG_VERBOSE("  data offset: %u, stack size: %d", module->aux_data_end,
                module->aux_stack_size);
    LOG_VERBOSE("  heap offset: %u, heap size: %d\n", heap_offset, heap_size);

    total_size = (uint64)num_bytes_per_page * init_page_count;
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (is_shared_memory) {
        /* Allocate max page for shared memory */
        total_size = (uint64)num_bytes_per_page * max_page_count;
    }
#endif
    bh_assert(total_size <= UINT32_MAX);

#ifndef OS_ENABLE_HW_BOUND_CHECK
    /* Allocate memory */
    if (total_size > 0
        && !(p = runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }
#else
    total_size = (total_size + page_size - 1) & ~(page_size - 1);

    /* Totally 8G is mapped, the opcode load/store address range is 0 to 8G:
     *   ea = i + memarg.offset
     * both i and memarg.offset are u32 in range 0 to 4G
     * so the range of ea is 0 to 8G
     */
    if (!(p = mapped_mem =
              os_mmap(NULL, map_size, MMAP_PROT_NONE, MMAP_MAP_NONE))) {
        set_error_buf(error_buf, error_buf_size, "mmap memory failed");
        return NULL;
    }

#ifdef BH_PLATFORM_WINDOWS
    if (!os_mem_commit(p, total_size, MMAP_PROT_READ | MMAP_PROT_WRITE)) {
        set_error_buf(error_buf, error_buf_size, "commit memory failed");
        os_munmap(mapped_mem, map_size);
        return NULL;
    }
#endif

    if (os_mprotect(p, total_size, MMAP_PROT_READ | MMAP_PROT_WRITE) != 0) {
        set_error_buf(error_buf, error_buf_size, "mprotect memory failed");
#ifdef BH_PLATFORM_WINDOWS
        os_mem_decommit(p, total_size);
#endif
        os_munmap(mapped_mem, map_size);
        return NULL;
    }
    /* Newly allocated pages are filled with zero by the OS, we don't fill it
     * again here */
#endif /* end of OS_ENABLE_HW_BOUND_CHECK */

    if (total_size > UINT32_MAX)
        total_size = UINT32_MAX;

    memory_inst->module_type = Wasm_Module_AoT;
    memory_inst->num_bytes_per_page = num_bytes_per_page;
    memory_inst->cur_page_count = init_page_count;
    memory_inst->max_page_count = max_page_count;
    memory_inst->memory_data_size = (uint32)total_size;

    /* Init memory info */
    memory_inst->memory_data.ptr = p;
    memory_inst->memory_data_end.ptr = p + (uint32)total_size;

    /* Initialize heap info */
    memory_inst->heap_data.ptr = p + heap_offset;
    memory_inst->heap_data_end.ptr = p + heap_offset + heap_size;
    if (heap_size > 0) {
        uint32 heap_struct_size = mem_allocator_get_heap_struct_size();

        if (!(heap_handle = runtime_malloc((uint64)heap_struct_size, error_buf,
                                           error_buf_size))) {
            goto fail1;
        }

        memory_inst->heap_handle.ptr = heap_handle;

        if (!mem_allocator_create_with_struct_and_pool(
                heap_handle, heap_struct_size, memory_inst->heap_data.ptr,
                heap_size)) {
            set_error_buf(error_buf, error_buf_size, "init app heap failed");
            goto fail2;
        }
    }

    if (total_size > 0) {
#if UINTPTR_MAX == UINT64_MAX
        memory_inst->mem_bound_check_1byte.u64 = total_size - 1;
        memory_inst->mem_bound_check_2bytes.u64 = total_size - 2;
        memory_inst->mem_bound_check_4bytes.u64 = total_size - 4;
        memory_inst->mem_bound_check_8bytes.u64 = total_size - 8;
        memory_inst->mem_bound_check_16bytes.u64 = total_size - 16;
#else
        memory_inst->mem_bound_check_1byte.u32[0] = (uint32)total_size - 1;
        memory_inst->mem_bound_check_2bytes.u32[0] = (uint32)total_size - 2;
        memory_inst->mem_bound_check_4bytes.u32[0] = (uint32)total_size - 4;
        memory_inst->mem_bound_check_8bytes.u32[0] = (uint32)total_size - 8;
        memory_inst->mem_bound_check_16bytes.u32[0] = (uint32)total_size - 16;
#endif
    }

#if WASM_ENABLE_SHARED_MEMORY != 0
    if (is_shared_memory) {
        memory_inst->is_shared = true;
        if (!shared_memory_set_memory_inst(
                (WASMModuleCommon *)module,
                (WASMMemoryInstanceCommon *)memory_inst)) {
            set_error_buf(error_buf, error_buf_size, "allocate memory failed");
            goto fail3;
        }
    }
#endif

    return memory_inst;

#if WASM_ENABLE_SHARED_MEMORY != 0
fail3:
    if (heap_size > 0)
        mem_allocator_destroy(memory_inst->heap_handle.ptr);
#endif
fail2:
    if (heap_size > 0)
        wasm_runtime_free(memory_inst->heap_handle.ptr);
fail1:
#ifndef OS_ENABLE_HW_BOUND_CHECK
    if (memory_inst->memory_data.ptr)
        wasm_runtime_free(memory_inst->memory_data.ptr);
#else
#ifdef BH_PLATFORM_WINDOWS
    if (memory_inst->memory_data.ptr)
        os_mem_decommit(p, total_size);
#endif
    os_munmap(mapped_mem, map_size);
#endif
    memory_inst->memory_data.ptr = NULL;
    return NULL;
}

static AOTMemoryInstance *
aot_get_default_memory(AOTModuleInstance *module_inst)
{
    if (module_inst->memories.ptr)
        return ((AOTMemoryInstance **)module_inst->memories.ptr)[0];
    else
        return NULL;
}

static bool
memories_instantiate(AOTModuleInstance *module_inst, AOTModule *module,
                     uint32 heap_size, char *error_buf, uint32 error_buf_size)
{
    uint32 global_index, global_data_offset, base_offset, length;
    uint32 i, memory_count = module->memory_count;
    AOTMemoryInstance *memories, *memory_inst;
    AOTMemInitData *data_seg;
    uint64 total_size;

    module_inst->memory_count = memory_count;
    total_size = sizeof(AOTPointer) * (uint64)memory_count;
    if (!(module_inst->memories.ptr =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    memories = module_inst->global_table_data.memory_instances;
    for (i = 0; i < memory_count; i++, memories++) {
        memory_inst = memory_instantiate(module_inst, module, memories,
                                         &module->memories[i], heap_size,
                                         error_buf, error_buf_size);
        if (!memory_inst) {
            return false;
        }

        ((AOTMemoryInstance **)module_inst->memories.ptr)[i] = memory_inst;
    }

    /* Get default memory instance */
    memory_inst = aot_get_default_memory(module_inst);
    if (!memory_inst) {
        /* Ignore setting memory init data if no memory inst is created */
        return true;
    }

    for (i = 0; i < module->mem_init_data_count; i++) {
        data_seg = module->mem_init_data_list[i];
#if WASM_ENABLE_BULK_MEMORY != 0
        if (data_seg->is_passive)
            continue;
#endif

        bh_assert(data_seg->offset.init_expr_type == INIT_EXPR_TYPE_I32_CONST
                  || data_seg->offset.init_expr_type
                         == INIT_EXPR_TYPE_GET_GLOBAL);

        /* Resolve memory data base offset */
        if (data_seg->offset.init_expr_type == INIT_EXPR_TYPE_GET_GLOBAL) {
            global_index = data_seg->offset.u.global_index;

            if (!check_global_init_expr(module, global_index, error_buf,
                                        error_buf_size)) {
                return false;
            }

            if (global_index < module->import_global_count)
                global_data_offset =
                    module->import_globals[global_index].data_offset;
            else
                global_data_offset =
                    module->globals[global_index - module->import_global_count]
                        .data_offset;

            base_offset = *(uint32 *)((uint8 *)module_inst->global_data.ptr
                                      + global_data_offset);
        }
        else {
            base_offset = (uint32)data_seg->offset.u.i32;
        }

        /* Copy memory data */
        bh_assert(memory_inst->memory_data.ptr
                  || memory_inst->memory_data_size == 0);

        /* Check memory data */
        /* check offset since length might negative */
        if (base_offset > memory_inst->memory_data_size) {
            LOG_DEBUG("base_offset(%d) > memory_data_size(%d)", base_offset,
                      memory_inst->memory_data_size);
#if WASM_ENABLE_REF_TYPES != 0
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds memory access");
#else
            set_error_buf(error_buf, error_buf_size,
                          "data segment does not fit");
#endif
            return false;
        }

        /* check offset + length(could be zero) */
        length = data_seg->byte_count;
        if (base_offset + length > memory_inst->memory_data_size) {
            LOG_DEBUG("base_offset(%d) + length(%d) > memory_data_size(%d)",
                      base_offset, length, memory_inst->memory_data_size);
#if WASM_ENABLE_REF_TYPES != 0
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds memory access");
#else
            set_error_buf(error_buf, error_buf_size,
                          "data segment does not fit");
#endif
            return false;
        }

        if (memory_inst->memory_data.ptr) {
            bh_memcpy_s((uint8 *)memory_inst->memory_data.ptr + base_offset,
                        memory_inst->memory_data_size - base_offset,
                        data_seg->bytes, length);
        }
    }

    return true;
}

static bool
init_func_ptrs(AOTModuleInstance *module_inst, AOTModule *module,
               char *error_buf, uint32 error_buf_size)
{
    uint32 i;
    void **func_ptrs;
    uint64 total_size = ((uint64)module->import_func_count + module->func_count)
                        * sizeof(void *);

    if (module->import_func_count + module->func_count == 0)
        return true;

    /* Allocate memory */
    if (!(module_inst->func_ptrs.ptr =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    /* Set import function pointers */
    func_ptrs = (void **)module_inst->func_ptrs.ptr;
    for (i = 0; i < module->import_func_count; i++, func_ptrs++) {
        *func_ptrs = (void *)module->import_funcs[i].func_ptr_linked;
        if (!*func_ptrs) {
            const char *module_name = module->import_funcs[i].module_name;
            const char *field_name = module->import_funcs[i].func_name;
            LOG_WARNING("warning: failed to link import function (%s, %s)",
                        module_name, field_name);
        }
    }

    /* Set defined function pointers */
    bh_memcpy_s(func_ptrs, sizeof(void *) * module->func_count,
                module->func_ptrs, sizeof(void *) * module->func_count);
    return true;
}

static bool
init_func_type_indexes(AOTModuleInstance *module_inst, AOTModule *module,
                       char *error_buf, uint32 error_buf_size)
{
    uint32 i;
    uint32 *func_type_index;
    uint64 total_size = ((uint64)module->import_func_count + module->func_count)
                        * sizeof(uint32);

    if (module->import_func_count + module->func_count == 0)
        return true;

    /* Allocate memory */
    if (!(module_inst->func_type_indexes.ptr =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    /* Set import function type indexes */
    func_type_index = (uint32 *)module_inst->func_type_indexes.ptr;
    for (i = 0; i < module->import_func_count; i++, func_type_index++)
        *func_type_index = module->import_funcs[i].func_type_index;

    bh_memcpy_s(func_type_index, sizeof(uint32) * module->func_count,
                module->func_type_indexes, sizeof(uint32) * module->func_count);
    return true;
}

static bool
create_export_funcs(AOTModuleInstance *module_inst, AOTModule *module,
                    char *error_buf, uint32 error_buf_size)
{
    AOTExport *exports = module->exports;
    AOTFunctionInstance *export_func;
    uint64 size;
    uint32 i, func_index, ftype_index;

    if (module_inst->export_func_count > 0) {
        /* Allocate memory */
        size = sizeof(AOTFunctionInstance)
               * (uint64)module_inst->export_func_count;
        if (!(module_inst->export_funcs.ptr = export_func =
                  runtime_malloc(size, error_buf, error_buf_size))) {
            return false;
        }

        for (i = 0; i < module->export_count; i++) {
            if (exports[i].kind == EXPORT_KIND_FUNC) {
                export_func->func_name = exports[i].name;
                export_func->func_index = exports[i].index;
                if (export_func->func_index < module->import_func_count) {
                    export_func->is_import_func = true;
                    export_func->u.func_import =
                        &module->import_funcs[export_func->func_index];
                }
                else {
                    export_func->is_import_func = false;
                    func_index =
                        export_func->func_index - module->import_func_count;
                    ftype_index = module->func_type_indexes[func_index];
                    export_func->u.func.func_type =
                        module->func_types[ftype_index];
                    export_func->u.func.func_ptr =
                        module->func_ptrs[func_index];
                }
                export_func++;
            }
        }
    }

    return true;
}

static bool
create_exports(AOTModuleInstance *module_inst, AOTModule *module,
               char *error_buf, uint32 error_buf_size)
{
    AOTExport *exports = module->exports;
    uint32 i;

    for (i = 0; i < module->export_count; i++) {
        switch (exports[i].kind) {
            case EXPORT_KIND_FUNC:
                module_inst->export_func_count++;
                break;
            case EXPORT_KIND_GLOBAL:
                module_inst->export_global_count++;
                break;
            case EXPORT_KIND_TABLE:
                module_inst->export_tab_count++;
                break;
            case EXPORT_KIND_MEMORY:
                module_inst->export_mem_count++;
                break;
            default:
                return false;
        }
    }

    return create_export_funcs(module_inst, module, error_buf, error_buf_size);
}

static bool
clear_wasi_proc_exit_exception(AOTModuleInstance *module_inst)
{
#if WASM_ENABLE_LIBC_WASI != 0
    const char *exception = aot_get_exception(module_inst);
    if (exception && !strcmp(exception, "Exception: wasi proc exit")) {
        /* The "wasi proc exit" exception is thrown by native lib to
           let wasm app exit, which is a normal behavior, we clear
           the exception here. */
        aot_set_exception(module_inst, NULL);
        return true;
    }
    return false;
#else
    return false;
#endif
}

static bool
execute_post_inst_function(AOTModuleInstance *module_inst)
{
    AOTFunctionInstance *post_inst_func =
        aot_lookup_function(module_inst, "__post_instantiate", "()");

    if (!post_inst_func)
        /* Not found */
        return true;

    return aot_create_exec_env_and_call_function(module_inst, post_inst_func, 0,
                                                 NULL);
}

static bool
execute_start_function(AOTModuleInstance *module_inst)
{
    AOTModule *module = (AOTModule *)module_inst->aot_module.ptr;
    WASMExecEnv *exec_env;
    typedef void (*F)(WASMExecEnv *);
    union {
        F f;
        void *v;
    } u;

    if (!module->start_function)
        return true;

    if (!(exec_env =
              wasm_exec_env_create((WASMModuleInstanceCommon *)module_inst,
                                   module_inst->default_wasm_stack_size))) {
        aot_set_exception(module_inst, "allocate memory failed");
        return false;
    }

    u.v = module->start_function;
    u.f(exec_env);

    wasm_exec_env_destroy(exec_env);
    (void)clear_wasi_proc_exit_exception(module_inst);
    return !aot_get_exception(module_inst);
}

#if WASM_ENABLE_BULK_MEMORY != 0
static bool
execute_memory_init_function(AOTModuleInstance *module_inst)
{
    AOTFunctionInstance *memory_init_func =
        aot_lookup_function(module_inst, "__wasm_call_ctors", "()");

    if (!memory_init_func)
        /* Not found */
        return true;

    return aot_create_exec_env_and_call_function(module_inst, memory_init_func,
                                                 0, NULL);
}
#endif

AOTModuleInstance *
aot_instantiate(AOTModule *module, bool is_sub_inst, uint32 stack_size,
                uint32 heap_size, char *error_buf, uint32 error_buf_size)
{
    AOTModuleInstance *module_inst;
    const uint32 module_inst_struct_size =
        offsetof(AOTModuleInstance, global_table_data.bytes);
    const uint64 module_inst_mem_inst_size =
        (uint64)module->memory_count * sizeof(AOTMemoryInstance);
    uint64 total_size, table_size = 0;
    uint8 *p;
    uint32 i;

    /* Check heap size */
    heap_size = align_uint(heap_size, 8);
    if (heap_size > APP_HEAP_SIZE_MAX)
        heap_size = APP_HEAP_SIZE_MAX;

    total_size = (uint64)module_inst_struct_size + module_inst_mem_inst_size
                 + module->global_data_size;

    /*
     * calculate size of table data
     */
    for (i = 0; i != module->import_table_count; ++i) {
        table_size += offsetof(AOTTableInstance, data);
        table_size +=
            (uint64)sizeof(uint32)
            * (uint64)aot_get_imp_tbl_data_slots(module->import_tables + i);
    }

    for (i = 0; i != module->table_count; ++i) {
        table_size += offsetof(AOTTableInstance, data);
        table_size += (uint64)sizeof(uint32)
                      * (uint64)aot_get_tbl_data_slots(module->tables + i);
    }
    total_size += table_size;

    /* Allocate module instance, global data, table data and heap data */
    if (!(module_inst =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    module_inst->module_type = Wasm_Module_AoT;
    module_inst->aot_module.ptr = module;

    /* Initialize global info */
    p = (uint8 *)module_inst + module_inst_struct_size
        + module_inst_mem_inst_size;
    module_inst->global_data.ptr = p;
    module_inst->global_data_size = module->global_data_size;
    if (!global_instantiate(module_inst, module, error_buf, error_buf_size))
        goto fail;

    /* Initialize table info */
    p += module->global_data_size;
    module_inst->tables.ptr = p;
    module_inst->table_count = module->table_count + module->import_table_count;
    /* Set all elements to -1 to mark them as uninitialized elements */
    memset(module_inst->tables.ptr, 0xff, (uint32)table_size);
    if (!table_instantiate(module_inst, module, error_buf, error_buf_size))
        goto fail;

    /* Initialize memory space */
    if (!memories_instantiate(module_inst, module, heap_size, error_buf,
                              error_buf_size))
        goto fail;

    /* Initialize function pointers */
    if (!init_func_ptrs(module_inst, module, error_buf, error_buf_size))
        goto fail;

    /* Initialize function type indexes */
    if (!init_func_type_indexes(module_inst, module, error_buf, error_buf_size))
        goto fail;

    if (!create_exports(module_inst, module, error_buf, error_buf_size))
        goto fail;

#if WASM_ENABLE_LIBC_WASI != 0
    if (!is_sub_inst) {
        if (!wasm_runtime_init_wasi(
                (WASMModuleInstanceCommon *)module_inst,
                module->wasi_args.dir_list, module->wasi_args.dir_count,
                module->wasi_args.map_dir_list, module->wasi_args.map_dir_count,
                module->wasi_args.env, module->wasi_args.env_count,
                module->wasi_args.addr_pool, module->wasi_args.addr_count,
                module->wasi_args.ns_lookup_pool,
                module->wasi_args.ns_lookup_count, module->wasi_args.argv,
                module->wasi_args.argc, module->wasi_args.stdio[0],
                module->wasi_args.stdio[1], module->wasi_args.stdio[2],
                error_buf, error_buf_size))
            goto fail;
    }
#endif

    /* Initialize the thread related data */
    if (stack_size == 0)
        stack_size = DEFAULT_WASM_STACK_SIZE;
#if WASM_ENABLE_SPEC_TEST != 0
    if (stack_size < 48 * 1024)
        stack_size = 48 * 1024;
#endif
    module_inst->default_wasm_stack_size = stack_size;

#if WASM_ENABLE_PERF_PROFILING != 0
    total_size = (uint64)sizeof(AOTFuncPerfProfInfo)
                 * (module->import_func_count + module->func_count);
    if (!(module_inst->func_perf_profilings.ptr =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        goto fail;
    }
#endif

#if WASM_ENABLE_DUMP_CALL_STACK != 0
    if (!(module_inst->frames.ptr =
              runtime_malloc(sizeof(Vector), error_buf, error_buf_size))) {
        goto fail;
    }
#endif

    /* Execute __post_instantiate function and start function*/
    if (!execute_post_inst_function(module_inst)
        || !execute_start_function(module_inst)) {
        set_error_buf(error_buf, error_buf_size, module_inst->cur_exception);
        goto fail;
    }

#if WASM_ENABLE_BULK_MEMORY != 0
#if WASM_ENABLE_LIBC_WASI != 0
    if (!module->import_wasi_api) {
#endif
        /* Only execute the memory init function for main instance because
            the data segments will be dropped once initialized.
        */
        if (!is_sub_inst) {
            if (!execute_memory_init_function(module_inst)) {
                set_error_buf(error_buf, error_buf_size,
                              module_inst->cur_exception);
                goto fail;
            }
        }
#if WASM_ENABLE_LIBC_WASI != 0
    }
#endif
#endif

#if WASM_ENABLE_MEMORY_TRACING != 0
    wasm_runtime_dump_module_inst_mem_consumption(
        (WASMModuleInstanceCommon *)module_inst);
#endif

    return module_inst;

fail:
    aot_deinstantiate(module_inst, is_sub_inst);
    return NULL;
}

bool
aot_create_exec_env_singleton(AOTModuleInstance *module_inst)
{
    WASMExecEnv *exec_env =
        wasm_exec_env_create((WASMModuleInstanceCommon *)module_inst,
                             module_inst->default_wasm_stack_size);
    if (exec_env)
        module_inst->exec_env_singleton.ptr = exec_env;

    return exec_env ? true : false;
}

void
aot_deinstantiate(AOTModuleInstance *module_inst, bool is_sub_inst)
{
#if WASM_ENABLE_LIBC_WASI != 0
    /* Destroy wasi resource before freeing app heap, since some fields of
       wasi contex are allocated from app heap, and if app heap is freed,
       these fields will be set to NULL, we cannot free their internal data
       which may allocated from global heap. */
    /* Only destroy wasi ctx in the main module instance */
    if (!is_sub_inst)
        wasm_runtime_destroy_wasi((WASMModuleInstanceCommon *)module_inst);
#endif

#if WASM_ENABLE_PERF_PROFILING != 0
    if (module_inst->func_perf_profilings.ptr)
        wasm_runtime_free(module_inst->func_perf_profilings.ptr);
#endif

#if WASM_ENABLE_DUMP_CALL_STACK != 0
    if (module_inst->frames.ptr) {
        bh_vector_destroy(module_inst->frames.ptr);
        wasm_runtime_free(module_inst->frames.ptr);
        module_inst->frames.ptr = NULL;
    }
#endif

    if (module_inst->memories.ptr)
        memories_deinstantiate(module_inst);

    if (module_inst->export_funcs.ptr)
        wasm_runtime_free(module_inst->export_funcs.ptr);

    if (module_inst->func_ptrs.ptr)
        wasm_runtime_free(module_inst->func_ptrs.ptr);

    if (module_inst->func_type_indexes.ptr)
        wasm_runtime_free(module_inst->func_type_indexes.ptr);

    if (module_inst->exec_env_singleton.ptr)
        wasm_exec_env_destroy(
            (WASMExecEnv *)module_inst->exec_env_singleton.ptr);

    wasm_runtime_free(module_inst);
}

AOTFunctionInstance *
aot_lookup_function(const AOTModuleInstance *module_inst, const char *name,
                    const char *signature)
{
    uint32 i;
    AOTFunctionInstance *export_funcs =
        (AOTFunctionInstance *)module_inst->export_funcs.ptr;

    for (i = 0; i < module_inst->export_func_count; i++)
        if (!strcmp(export_funcs[i].func_name, name))
            return &export_funcs[i];
    (void)signature;
    return NULL;
}

#ifdef OS_ENABLE_HW_BOUND_CHECK

#ifndef BH_PLATFORM_WINDOWS
void
aot_signal_handler(WASMSignalInfo *sig_info)
{
    WASMExecEnv *exec_env_tls = sig_info->exec_env_tls;
    void *sig_addr = sig_info->sig_addr;
    AOTModuleInstance *module_inst;
    AOTMemoryInstance *memory_inst;
    WASMJmpBuf *jmpbuf_node;
    uint8 *mapped_mem_start_addr = NULL;
    uint8 *mapped_mem_end_addr = NULL;
    uint8 *stack_min_addr;
    uint32 page_size;
    uint32 guard_page_count = STACK_OVERFLOW_CHECK_GUARD_PAGE_COUNT;

    /* Check whether current thread is running aot function */
    if (exec_env_tls && exec_env_tls->handle == os_self_thread()
        && (jmpbuf_node = exec_env_tls->jmpbuf_stack_top)) {
        /* Get mapped mem info of current instance */
        module_inst = (AOTModuleInstance *)exec_env_tls->module_inst;
        /* Get the default memory instance */
        memory_inst = aot_get_default_memory(module_inst);
        if (memory_inst) {
            mapped_mem_start_addr = (uint8 *)memory_inst->memory_data.ptr;
            mapped_mem_end_addr =
                (uint8 *)memory_inst->memory_data.ptr + 8 * (uint64)BH_GB;
        }

        /* Get stack info of current thread */
        page_size = os_getpagesize();
        stack_min_addr = os_thread_get_stack_boundary();

        if (memory_inst
            && (mapped_mem_start_addr <= (uint8 *)sig_addr
                && (uint8 *)sig_addr < mapped_mem_end_addr)) {
            /* The address which causes segmentation fault is inside
               the memory instance's guard regions */
            aot_set_exception_with_id(module_inst,
                                      EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS);
            os_longjmp(jmpbuf_node->jmpbuf, 1);
        }
        else if (stack_min_addr - page_size <= (uint8 *)sig_addr
                 && (uint8 *)sig_addr
                        < stack_min_addr + page_size * guard_page_count) {
            /* The address which causes segmentation fault is inside
               native thread's guard page */
            aot_set_exception_with_id(module_inst, EXCE_NATIVE_STACK_OVERFLOW);
            os_longjmp(jmpbuf_node->jmpbuf, 1);
        }
    }
}
#else  /* else of BH_PLATFORM_WINDOWS */
LONG
aot_exception_handler(WASMSignalInfo *sig_info)
{
    WASMExecEnv *exec_env_tls = sig_info->exec_env_tls;
    EXCEPTION_POINTERS *exce_info = sig_info->exce_info;
    PEXCEPTION_RECORD ExceptionRecord = exce_info->ExceptionRecord;
    uint8 *sig_addr = (uint8 *)ExceptionRecord->ExceptionInformation[1];
    AOTModuleInstance *module_inst;
    AOTMemoryInstance *memory_inst;
    WASMJmpBuf *jmpbuf_node;
    uint8 *mapped_mem_start_addr = NULL;
    uint8 *mapped_mem_end_addr = NULL;
    uint32 page_size = os_getpagesize();

    if (exec_env_tls && exec_env_tls->handle == os_self_thread()
        && (jmpbuf_node = exec_env_tls->jmpbuf_stack_top)) {
        module_inst = (AOTModuleInstance *)exec_env_tls->module_inst;
        if (ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            /* Get the default memory instance */
            memory_inst = aot_get_default_memory(module_inst);
            if (memory_inst) {
                mapped_mem_start_addr = (uint8 *)memory_inst->memory_data.ptr;
                mapped_mem_end_addr =
                    (uint8 *)memory_inst->memory_data.ptr + 8 * (uint64)BH_GB;
                if (mapped_mem_start_addr <= (uint8 *)sig_addr
                    && (uint8 *)sig_addr < mapped_mem_end_addr) {
                    /* The address which causes segmentation fault is inside
                       aot instance's guard regions.
                       Set exception and let the aot func continue to run, when
                       the aot func returns, the caller will check whether the
                       exception is thrown and return to runtime. */
                    aot_set_exception_with_id(module_inst,
                                              EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS);
                    /* Skip current instruction */
                    exce_info->ContextRecord->Rip++;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
        else if (ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW) {
            /* Set stack overflow exception and let the aot func continue
               to run, when the aot func returns, the caller will check
               whether the exception is thrown and return to runtime, and
               the damaged stack will be recovered by _resetstkoflw(). */
            aot_set_exception_with_id(module_inst, EXCE_NATIVE_STACK_OVERFLOW);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    os_printf("Unhandled exception thrown:  exception code: 0x%lx, "
              "exception address: %p, exception information: %p\n",
              ExceptionRecord->ExceptionCode, ExceptionRecord->ExceptionAddress,
              sig_addr);
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif /* end of BH_PLATFORM_WINDOWS */

static bool
invoke_native_with_hw_bound_check(WASMExecEnv *exec_env, void *func_ptr,
                                  const WASMType *func_type,
                                  const char *signature, void *attachment,
                                  uint32 *argv, uint32 argc, uint32 *argv_ret)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    WASMExecEnv *exec_env_tls = wasm_runtime_get_exec_env_tls();
    WASMJmpBuf jmpbuf_node = { 0 }, *jmpbuf_node_pop;
    uint32 page_size = os_getpagesize();
    uint32 guard_page_count = STACK_OVERFLOW_CHECK_GUARD_PAGE_COUNT;
    uint16 param_count = func_type->param_count;
    uint16 result_count = func_type->result_count;
    const uint8 *types = func_type->types;
#ifdef BH_PLATFORM_WINDOWS
    const char *exce;
    int result;
#endif
    bool ret;

    /* Check native stack overflow firstly to ensure we have enough
       native stack to run the following codes before actually calling
       the aot function in invokeNative function. */
    if ((uint8 *)&module_inst < exec_env->native_stack_boundary
                                    + page_size * (guard_page_count + 1)) {
        aot_set_exception_with_id(module_inst, EXCE_NATIVE_STACK_OVERFLOW);
        return false;
    }

    if (exec_env_tls && (exec_env_tls != exec_env)) {
        aot_set_exception(module_inst, "invalid exec env");
        return false;
    }

    if (!os_thread_signal_inited()) {
        aot_set_exception(module_inst, "thread signal env not inited");
        return false;
    }

    wasm_exec_env_push_jmpbuf(exec_env, &jmpbuf_node);

    wasm_runtime_set_exec_env_tls(exec_env);
    if (os_setjmp(jmpbuf_node.jmpbuf) == 0) {
        /* Quick call with func_ptr if the function signature is simple */
        if (!signature && param_count == 1 && types[0] == VALUE_TYPE_I32) {
            if (result_count == 0) {
                void (*NativeFunc)(WASMExecEnv *, uint32) =
                    (void (*)(WASMExecEnv *, uint32))func_ptr;
                NativeFunc(exec_env, argv[0]);
                ret = aot_get_exception(module_inst) ? false : true;
            }
            else if (result_count == 1
                     && types[param_count] == VALUE_TYPE_I32) {
                uint32 (*NativeFunc)(WASMExecEnv *, uint32) =
                    (uint32(*)(WASMExecEnv *, uint32))func_ptr;
                argv_ret[0] = NativeFunc(exec_env, argv[0]);
                ret = aot_get_exception(module_inst) ? false : true;
            }
            else {
                ret = wasm_runtime_invoke_native(exec_env, func_ptr, func_type,
                                                 signature, attachment, argv,
                                                 argc, argv_ret);
            }
        }
        else {
            ret = wasm_runtime_invoke_native(exec_env, func_ptr, func_type,
                                             signature, attachment, argv, argc,
                                             argv_ret);
        }
#ifdef BH_PLATFORM_WINDOWS
        if ((exce = aot_get_exception(module_inst))
            && strstr(exce, "native stack overflow")) {
            /* After a stack overflow, the stack was left
               in a damaged state, let the CRT repair it */
            result = _resetstkoflw();
            bh_assert(result != 0);
        }
#endif
    }
    else {
        /* Exception has been set in signal handler before calling longjmp */
        ret = false;
    }

    jmpbuf_node_pop = wasm_exec_env_pop_jmpbuf(exec_env);
    bh_assert(&jmpbuf_node == jmpbuf_node_pop);
    if (!exec_env->jmpbuf_stack_top) {
        wasm_runtime_set_exec_env_tls(NULL);
    }
    if (!ret) {
        os_sigreturn();
        os_signal_unmask();
    }
    (void)jmpbuf_node_pop;
    return ret;
}

#define invoke_native_internal invoke_native_with_hw_bound_check
#else /* else of OS_ENABLE_HW_BOUND_CHECK */
#define invoke_native_internal wasm_runtime_invoke_native
#endif /* end of OS_ENABLE_HW_BOUND_CHECK */

bool
aot_call_function(WASMExecEnv *exec_env, AOTFunctionInstance *function,
                  unsigned argc, uint32 argv[])
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTFuncType *func_type = function->u.func.func_type;
    uint32 result_count = func_type->result_count;
    uint32 ext_ret_count = result_count > 1 ? result_count - 1 : 0;
    bool ret;

    if (argc < func_type->param_cell_num) {
        char buf[108];
        snprintf(buf, sizeof(buf),
                 "invalid argument count %u, must be no smaller than %u", argc,
                 func_type->param_cell_num);
        aot_set_exception(module_inst, buf);
        return false;
    }
    argc = func_type->param_cell_num;

#if WASM_ENABLE_LAZY_JIT != 0
    if (!function->u.func.func_ptr) {
        AOTModule *aot_module = (AOTModule *)module_inst->aot_module.ptr;
        if (!(function->u.func.func_ptr =
                  aot_lookup_orcjit_func(aot_module->comp_ctx->orc_lazyjit,
                                         module_inst, function->func_index))) {
            return false;
        }
    }
#endif

    /* set thread handle and stack boundary */
    wasm_exec_env_set_thread_info(exec_env);

    if (ext_ret_count > 0) {
        uint32 cell_num = 0, i;
        uint8 *ext_ret_types = func_type->types + func_type->param_count + 1;
        uint32 argv1_buf[32], *argv1 = argv1_buf, *ext_rets = NULL;
        uint32 *argv_ret = argv;
        uint32 ext_ret_cell = wasm_get_cell_num(ext_ret_types, ext_ret_count);
        uint64 size;

        /* Allocate memory all arguments */
        size =
            sizeof(uint32) * (uint64)argc /* original arguments */
            + sizeof(void *)
                  * (uint64)ext_ret_count /* extra result values' addr */
            + sizeof(uint32) * (uint64)ext_ret_cell; /* extra result values */
        if (size > sizeof(argv1_buf)
            && !(argv1 = runtime_malloc(size, module_inst->cur_exception,
                                        sizeof(module_inst->cur_exception)))) {
            aot_set_exception_with_id(module_inst, EXCE_OUT_OF_MEMORY);
            return false;
        }

        /* Copy original arguments */
        bh_memcpy_s(argv1, (uint32)size, argv, sizeof(uint32) * argc);

        /* Get the extra result value's address */
        ext_rets =
            argv1 + argc + sizeof(void *) / sizeof(uint32) * ext_ret_count;

        /* Append each extra result value's address to original arguments */
        for (i = 0; i < ext_ret_count; i++) {
            *(uintptr_t *)(argv1 + argc + sizeof(void *) / sizeof(uint32) * i) =
                (uintptr_t)(ext_rets + cell_num);
            cell_num += wasm_value_type_cell_num(ext_ret_types[i]);
        }

#if (WASM_ENABLE_DUMP_CALL_STACK != 0) || (WASM_ENABLE_PERF_PROFILING != 0)
        if (!aot_alloc_frame(exec_env, function->func_index)) {
            if (argv1 != argv1_buf)
                wasm_runtime_free(argv1);
            return false;
        }
#endif

        ret = invoke_native_internal(exec_env, function->u.func.func_ptr,
                                     func_type, NULL, NULL, argv1, argc, argv);

        if (!ret || aot_get_exception(module_inst)) {
            if (clear_wasi_proc_exit_exception(module_inst))
                ret = true;
            else
                ret = false;
        }

#if WASM_ENABLE_DUMP_CALL_STACK != 0
        if (!ret) {
            if (aot_create_call_stack(exec_env)) {
                aot_dump_call_stack(exec_env, true, NULL, 0);
            }
        }
#endif

#if (WASM_ENABLE_DUMP_CALL_STACK != 0) || (WASM_ENABLE_PERF_PROFILING != 0)
        aot_free_frame(exec_env);
#endif
        if (!ret) {
            if (argv1 != argv1_buf)
                wasm_runtime_free(argv1);
            return ret;
        }

        /* Get extra result values */
        switch (func_type->types[func_type->param_count]) {
            case VALUE_TYPE_I32:
            case VALUE_TYPE_F32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
#endif
                argv_ret++;
                break;
            case VALUE_TYPE_I64:
            case VALUE_TYPE_F64:
                argv_ret += 2;
                break;
#if WASM_ENABLE_SIMD != 0
            case VALUE_TYPE_V128:
                argv_ret += 4;
                break;
#endif
            default:
                bh_assert(0);
                break;
        }
        ext_rets =
            argv1 + argc + sizeof(void *) / sizeof(uint32) * ext_ret_count;
        bh_memcpy_s(argv_ret, sizeof(uint32) * cell_num, ext_rets,
                    sizeof(uint32) * cell_num);

        if (argv1 != argv1_buf)
            wasm_runtime_free(argv1);
        return true;
    }
    else {
#if (WASM_ENABLE_DUMP_CALL_STACK != 0) || (WASM_ENABLE_PERF_PROFILING != 0)
        if (!aot_alloc_frame(exec_env, function->func_index)) {
            return false;
        }
#endif

        ret = invoke_native_internal(exec_env, function->u.func.func_ptr,
                                     func_type, NULL, NULL, argv, argc, argv);

        if (clear_wasi_proc_exit_exception(module_inst))
            ret = true;

#if WASM_ENABLE_DUMP_CALL_STACK != 0
        if (aot_get_exception(module_inst)) {
            if (aot_create_call_stack(exec_env)) {
                aot_dump_call_stack(exec_env, true, NULL, 0);
            }
        }
#endif

#if (WASM_ENABLE_DUMP_CALL_STACK != 0) || (WASM_ENABLE_PERF_PROFILING != 0)
        aot_free_frame(exec_env);
#endif

        return ret && !aot_get_exception(module_inst) ? true : false;
    }
}

bool
aot_create_exec_env_and_call_function(AOTModuleInstance *module_inst,
                                      AOTFunctionInstance *func, unsigned argc,
                                      uint32 argv[])
{
    WASMExecEnv *exec_env = NULL, *existing_exec_env = NULL;
    bool ret;

#if defined(OS_ENABLE_HW_BOUND_CHECK)
    existing_exec_env = exec_env = wasm_runtime_get_exec_env_tls();
#elif WASM_ENABLE_THREAD_MGR != 0
    existing_exec_env = exec_env =
        wasm_clusters_search_exec_env((WASMModuleInstanceCommon *)module_inst);
#endif

    if (!existing_exec_env) {
        if (!(exec_env =
                  wasm_exec_env_create((WASMModuleInstanceCommon *)module_inst,
                                       module_inst->default_wasm_stack_size))) {
            aot_set_exception(module_inst, "allocate memory failed");
            return false;
        }
    }

    ret = aot_call_function(exec_env, func, argc, argv);

    /* don't destroy the exec_env if it isn't created in this function */
    if (!existing_exec_env)
        wasm_exec_env_destroy(exec_env);

    return ret;
}

void
aot_set_exception(AOTModuleInstance *module_inst, const char *exception)
{
    if (exception)
        snprintf(module_inst->cur_exception, sizeof(module_inst->cur_exception),
                 "Exception: %s", exception);
    else
        module_inst->cur_exception[0] = '\0';
}

void
aot_set_exception_with_id(AOTModuleInstance *module_inst, uint32 id)
{
    switch (id) {
        case EXCE_UNREACHABLE:
            aot_set_exception(module_inst, "unreachable");
            break;
        case EXCE_OUT_OF_MEMORY:
            aot_set_exception(module_inst, "allocate memory failed");
            break;
        case EXCE_OUT_OF_BOUNDS_MEMORY_ACCESS:
            aot_set_exception(module_inst, "out of bounds memory access");
            break;
        case EXCE_INTEGER_OVERFLOW:
            aot_set_exception(module_inst, "integer overflow");
            break;
        case EXCE_INTEGER_DIVIDE_BY_ZERO:
            aot_set_exception(module_inst, "integer divide by zero");
            break;
        case EXCE_INVALID_CONVERSION_TO_INTEGER:
            aot_set_exception(module_inst, "invalid conversion to integer");
            break;
        case EXCE_INVALID_FUNCTION_TYPE_INDEX:
            aot_set_exception(module_inst, "indirect call type mismatch");
            break;
        case EXCE_INVALID_FUNCTION_INDEX:
            aot_set_exception(module_inst, "invalid function index");
            break;
        case EXCE_UNDEFINED_ELEMENT:
            aot_set_exception(module_inst, "undefined element");
            break;
        case EXCE_UNINITIALIZED_ELEMENT:
            aot_set_exception(module_inst, "uninitialized element");
            break;
        case EXCE_CALL_UNLINKED_IMPORT_FUNC:
            aot_set_exception(module_inst,
                              "failed to call unlinked import function");
            break;
        case EXCE_NATIVE_STACK_OVERFLOW:
            aot_set_exception(module_inst, "native stack overflow");
            break;
        case EXCE_UNALIGNED_ATOMIC:
            aot_set_exception(module_inst, "unaligned atomic");
            break;
        case EXCE_AUX_STACK_OVERFLOW:
            aot_set_exception(module_inst, "wasm auxiliary stack overflow");
            break;
        case EXCE_AUX_STACK_UNDERFLOW:
            aot_set_exception(module_inst, "wasm auxiliary stack underflow");
            break;
        case EXCE_OUT_OF_BOUNDS_TABLE_ACCESS:
            aot_set_exception(module_inst, "out of bounds table access");
            break;
        default:
            break;
    }
}

const char *
aot_get_exception(AOTModuleInstance *module_inst)
{
    if (module_inst->cur_exception[0] == '\0')
        return NULL;
    else
        return module_inst->cur_exception;
}

void
aot_clear_exception(AOTModuleInstance *module_inst)
{
    module_inst->cur_exception[0] = '\0';
}

static bool
execute_malloc_function(AOTModuleInstance *module_inst,
                        AOTFunctionInstance *malloc_func,
                        AOTFunctionInstance *retain_func, uint32 size,
                        uint32 *p_result)
{
#ifdef OS_ENABLE_HW_BOUND_CHECK
    WASMExecEnv *exec_env_tls = wasm_runtime_get_exec_env_tls();
#endif
    uint32 argv[2], argc;
    bool ret;

    argv[0] = size;
    argc = 1;
    if (retain_func) {
        argv[1] = 0;
        argc = 2;
    }

#ifdef OS_ENABLE_HW_BOUND_CHECK
    if (exec_env_tls != NULL) {
        bh_assert(exec_env_tls->module_inst
                  == (WASMModuleInstanceCommon *)module_inst);
        ret = aot_call_function(exec_env_tls, malloc_func, argc, argv);

        if (retain_func && ret) {
            ret = aot_call_function(exec_env_tls, retain_func, 1, argv);
        }
    }
    else
#endif
    {
        ret = aot_create_exec_env_and_call_function(module_inst, malloc_func,
                                                    argc, argv);

        if (retain_func && ret) {
            ret = aot_create_exec_env_and_call_function(module_inst,
                                                        retain_func, 1, argv);
        }
    }

    if (ret)
        *p_result = argv[0];
    return ret;
}

static bool
execute_free_function(AOTModuleInstance *module_inst,
                      AOTFunctionInstance *free_func, uint32 offset)
{
#ifdef OS_ENABLE_HW_BOUND_CHECK
    WASMExecEnv *exec_env_tls = wasm_runtime_get_exec_env_tls();
#endif
    uint32 argv[2];

    argv[0] = offset;
#ifdef OS_ENABLE_HW_BOUND_CHECK
    if (exec_env_tls != NULL) {
        bh_assert(exec_env_tls->module_inst
                  == (WASMModuleInstanceCommon *)module_inst);
        return aot_call_function(exec_env_tls, free_func, 1, argv);
    }
    else
#endif
    {
        return aot_create_exec_env_and_call_function(module_inst, free_func, 1,
                                                     argv);
    }
}

uint32
aot_module_malloc(AOTModuleInstance *module_inst, uint32 size,
                  void **p_native_addr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    AOTModule *module = (AOTModule *)module_inst->aot_module.ptr;
    uint8 *addr = NULL;
    uint32 offset = 0;

    if (!memory_inst) {
        aot_set_exception(module_inst, "uninitialized memory");
        return 0;
    }

    if (memory_inst->heap_handle.ptr) {
        addr = mem_allocator_malloc(memory_inst->heap_handle.ptr, size);
    }
    else if (module->malloc_func_index != (uint32)-1
             && module->free_func_index != (uint32)-1) {
        AOTFunctionInstance *malloc_func, *retain_func = NULL;
        char *malloc_func_name;
        char *malloc_func_sig;

        if (module->retain_func_index != (uint32)-1) {
            malloc_func_name = "__new";
            malloc_func_sig = "(ii)i";
            retain_func = aot_lookup_function(module_inst, "__retain", "(i)i");
            if (!retain_func)
                retain_func = aot_lookup_function(module_inst, "__pin", "(i)i");
            bh_assert(retain_func);
        }
        else {
            malloc_func_name = "malloc";
            malloc_func_sig = "(i)i";
        }
        malloc_func =
            aot_lookup_function(module_inst, malloc_func_name, malloc_func_sig);

        if (!malloc_func
            || !execute_malloc_function(module_inst, malloc_func, retain_func,
                                        size, &offset)) {
            return 0;
        }
        addr = offset ? (uint8 *)memory_inst->memory_data.ptr + offset : NULL;
    }

    if (!addr) {
        if (memory_inst->heap_handle.ptr
            && mem_allocator_is_heap_corrupted(memory_inst->heap_handle.ptr)) {
            wasm_runtime_show_app_heap_corrupted_prompt();
            aot_set_exception(module_inst, "app heap corrupted");
        }
        else {
            LOG_WARNING("warning: allocate %u bytes memory failed", size);
        }
        return 0;
    }
    if (p_native_addr)
        *p_native_addr = addr;
    return (uint32)(addr - (uint8 *)memory_inst->memory_data.ptr);
}

uint32
aot_module_realloc(AOTModuleInstance *module_inst, uint32 ptr, uint32 size,
                   void **p_native_addr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    uint8 *addr = NULL;

    if (!memory_inst) {
        aot_set_exception(module_inst, "uninitialized memory");
        return 0;
    }

    if (memory_inst->heap_handle.ptr) {
        addr = mem_allocator_realloc(
            memory_inst->heap_handle.ptr,
            ptr ? (uint8 *)memory_inst->memory_data.ptr + ptr : NULL, size);
    }

    /* Only support realloc in WAMR's app heap */

    if (!addr) {
        if (memory_inst->heap_handle.ptr
            && mem_allocator_is_heap_corrupted(memory_inst->heap_handle.ptr)) {
            aot_set_exception(module_inst, "app heap corrupted");
        }
        else {
            aot_set_exception(module_inst, "out of memory");
        }
        return 0;
    }

    if (p_native_addr)
        *p_native_addr = addr;
    return (uint32)(addr - (uint8 *)memory_inst->memory_data.ptr);
}

void
aot_module_free(AOTModuleInstance *module_inst, uint32 ptr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    AOTModule *module = (AOTModule *)module_inst->aot_module.ptr;

    if (!memory_inst) {
        return;
    }

    if (ptr) {
        uint8 *addr = (uint8 *)memory_inst->memory_data.ptr + ptr;
        if (memory_inst->heap_handle.ptr
            && (uint8 *)memory_inst->heap_data.ptr < addr
            && addr < (uint8 *)memory_inst->heap_data_end.ptr) {
            mem_allocator_free(memory_inst->heap_handle.ptr, addr);
        }
        else if (module->malloc_func_index != (uint32)-1
                 && module->free_func_index != (uint32)-1
                 && (uint8 *)memory_inst->memory_data.ptr <= addr
                 && addr < (uint8 *)memory_inst->memory_data_end.ptr) {
            AOTFunctionInstance *free_func;
            char *free_func_name;

            if (module->retain_func_index != (uint32)-1) {
                free_func_name = "__release";
            }
            else {
                free_func_name = "free";
            }
            free_func =
                aot_lookup_function(module_inst, free_func_name, "(i)i");
            if (!free_func && module->retain_func_index != (uint32)-1)
                free_func = aot_lookup_function(module_inst, "__unpin", "(i)i");

            if (free_func)
                execute_free_function(module_inst, free_func, ptr);
        }
    }
}

uint32
aot_module_dup_data(AOTModuleInstance *module_inst, const char *src,
                    uint32 size)
{
    char *buffer;
    uint32 buffer_offset =
        aot_module_malloc(module_inst, size, (void **)&buffer);

    if (buffer_offset != 0) {
        buffer = aot_addr_app_to_native(module_inst, buffer_offset);
        bh_memcpy_s(buffer, size, src, size);
    }
    return buffer_offset;
}

bool
aot_validate_app_addr(AOTModuleInstance *module_inst, uint32 app_offset,
                      uint32 size)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);

    if (!memory_inst) {
        goto fail;
    }

    /* integer overflow check */
    if (app_offset > UINT32_MAX - size) {
        goto fail;
    }

    if (app_offset + size <= memory_inst->memory_data_size) {
        return true;
    }
fail:
    aot_set_exception(module_inst, "out of bounds memory access");
    return false;
}

bool
aot_validate_native_addr(AOTModuleInstance *module_inst, void *native_ptr,
                         uint32 size)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    uint8 *addr = (uint8 *)native_ptr;

    if (!memory_inst) {
        goto fail;
    }

    /* integer overflow check */
    if ((uintptr_t)addr > UINTPTR_MAX - size) {
        goto fail;
    }

    if ((uint8 *)memory_inst->memory_data.ptr <= addr
        && addr + size <= (uint8 *)memory_inst->memory_data_end.ptr)
        return true;
fail:
    aot_set_exception(module_inst, "out of bounds memory access");
    return false;
}

void *
aot_addr_app_to_native(AOTModuleInstance *module_inst, uint32 app_offset)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    uint8 *addr;

    if (!memory_inst) {
        return NULL;
    }

    addr = (uint8 *)memory_inst->memory_data.ptr + app_offset;

    if ((uint8 *)memory_inst->memory_data.ptr <= addr
        && addr < (uint8 *)memory_inst->memory_data_end.ptr)
        return addr;
    return NULL;
}

uint32
aot_addr_native_to_app(AOTModuleInstance *module_inst, void *native_ptr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    uint8 *addr = (uint8 *)native_ptr;

    if (!memory_inst) {
        return 0;
    }

    if ((uint8 *)memory_inst->memory_data.ptr <= addr
        && addr < (uint8 *)memory_inst->memory_data_end.ptr)
        return (uint32)(addr - (uint8 *)memory_inst->memory_data.ptr);
    return 0;
}

bool
aot_get_app_addr_range(AOTModuleInstance *module_inst, uint32 app_offset,
                       uint32 *p_app_start_offset, uint32 *p_app_end_offset)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    uint32 memory_data_size;

    if (!memory_inst) {
        return false;
    }

    memory_data_size = memory_inst->memory_data_size;

    if (app_offset < memory_data_size) {
        if (p_app_start_offset)
            *p_app_start_offset = 0;
        if (p_app_end_offset)
            *p_app_end_offset = memory_data_size;
        return true;
    }
    return false;
}

bool
aot_get_native_addr_range(AOTModuleInstance *module_inst, uint8 *native_ptr,
                          uint8 **p_native_start_addr,
                          uint8 **p_native_end_addr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    uint8 *addr = (uint8 *)native_ptr;

    if (!memory_inst) {
        return false;
    }

    if ((uint8 *)memory_inst->memory_data.ptr <= addr
        && addr < (uint8 *)memory_inst->memory_data_end.ptr) {
        if (p_native_start_addr)
            *p_native_start_addr = (uint8 *)memory_inst->memory_data.ptr;
        if (p_native_end_addr)
            *p_native_end_addr = (uint8 *)memory_inst->memory_data_end.ptr;
        return true;
    }
    return false;
}

#ifndef OS_ENABLE_HW_BOUND_CHECK
bool
aot_enlarge_memory(AOTModuleInstance *module_inst, uint32 inc_page_count)
{
    AOTMemoryInstance *memory = aot_get_default_memory(module_inst);
    uint8 *memory_data_old, *memory_data_new, *heap_data_old;
    uint32 num_bytes_per_page, heap_size, total_size_old;
    uint32 cur_page_count, max_page_count, total_page_count;
    uint64 total_size_new;
    bool ret = true;

    if (!memory)
        return false;

    heap_data_old = (uint8 *)memory->heap_data.ptr;
    heap_size = (uint32)((uint8 *)memory->heap_data_end.ptr
                         - (uint8 *)memory->heap_data.ptr);

    memory_data_old = (uint8 *)memory->memory_data.ptr;
    total_size_old =
        (uint32)((uint8 *)memory->memory_data_end.ptr - memory_data_old);

    num_bytes_per_page = memory->num_bytes_per_page;
    cur_page_count = memory->cur_page_count;
    max_page_count = memory->max_page_count;
    total_page_count = inc_page_count + cur_page_count;
    total_size_new = num_bytes_per_page * (uint64)total_page_count;

    if (inc_page_count <= 0)
        /* No need to enlarge memory */
        return true;

    if (total_page_count < cur_page_count /* integer overflow */
        || total_page_count > max_page_count) {
        return false;
    }

    bh_assert(total_size_new <= 4 * (uint64)BH_GB);
    if (total_size_new > UINT32_MAX) {
        /* Resize to 1 page with size 4G-1 */
        num_bytes_per_page = UINT32_MAX;
        total_page_count = max_page_count = 1;
        total_size_new = UINT32_MAX;
    }

#if WASM_ENABLE_SHARED_MEMORY != 0
    if (memory->is_shared) {
        memory->num_bytes_per_page = num_bytes_per_page;
        memory->cur_page_count = total_page_count;
        memory->max_page_count = max_page_count;
        /* No need to update memory->memory_data_size as it is
           initialized with the maximum memory data size for
           shared memory */
        return true;
    }
#endif

    if (heap_size > 0) {
        if (mem_allocator_is_heap_corrupted(memory->heap_handle.ptr)) {
            wasm_runtime_show_app_heap_corrupted_prompt();
            return false;
        }
    }

    if (!(memory_data_new =
              wasm_runtime_realloc(memory_data_old, (uint32)total_size_new))) {
        if (!(memory_data_new = wasm_runtime_malloc((uint32)total_size_new))) {
            return false;
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
        if (mem_allocator_migrate(memory->heap_handle.ptr,
                                  (char *)heap_data_old
                                      + (memory_data_new - memory_data_old),
                                  heap_size)
            != 0) {
            /* Don't return here as memory->memory_data is obsolete and
               must be updated to be correctly used later. */
            ret = false;
        }
    }

    memory->heap_data.ptr = memory_data_new + (heap_data_old - memory_data_old);
    memory->heap_data_end.ptr = (uint8 *)memory->heap_data.ptr + heap_size;

    memory->num_bytes_per_page = num_bytes_per_page;
    memory->cur_page_count = total_page_count;
    memory->max_page_count = max_page_count;

    memory->memory_data.ptr = memory_data_new;
    memory->memory_data_end.ptr = memory_data_new + (uint32)total_size_new;
    memory->memory_data_size = (uint32)total_size_new;

#if UINTPTR_MAX == UINT64_MAX
    memory->mem_bound_check_1byte.u64 = total_size_new - 1;
    memory->mem_bound_check_2bytes.u64 = total_size_new - 2;
    memory->mem_bound_check_4bytes.u64 = total_size_new - 4;
    memory->mem_bound_check_8bytes.u64 = total_size_new - 8;
    memory->mem_bound_check_16bytes.u64 = total_size_new - 16;
#else
    memory->mem_bound_check_1byte.u32[0] = (uint32)total_size_new - 1;
    memory->mem_bound_check_2bytes.u32[0] = (uint32)total_size_new - 2;
    memory->mem_bound_check_4bytes.u32[0] = (uint32)total_size_new - 4;
    memory->mem_bound_check_8bytes.u32[0] = (uint32)total_size_new - 8;
    memory->mem_bound_check_16bytes.u32[0] = (uint32)total_size_new - 16;
#endif

    return ret;
}
#else /* else of OS_ENABLE_HW_BOUND_CHECK */
bool
aot_enlarge_memory(AOTModuleInstance *module_inst, uint32 inc_page_count)
{
    AOTMemoryInstance *memory = aot_get_default_memory(module_inst);
    uint32 num_bytes_per_page, total_size_old;
    uint32 cur_page_count, max_page_count, total_page_count;
    uint64 total_size_new;

    if (!memory)
        return false;

    num_bytes_per_page = memory->num_bytes_per_page;
    cur_page_count = memory->cur_page_count;
    max_page_count = memory->max_page_count;
    total_size_old = num_bytes_per_page * cur_page_count;
    total_page_count = inc_page_count + cur_page_count;
    total_size_new = num_bytes_per_page * (uint64)total_page_count;

    if (inc_page_count <= 0)
        /* No need to enlarge memory */
        return true;

    if (total_page_count < cur_page_count /* integer overflow */
        || total_page_count > max_page_count) {
        return false;
    }

    bh_assert(total_size_new <= 4 * (uint64)BH_GB);
    if (total_size_new > UINT32_MAX) {
        /* Resize to 1 page with size 4G-1 */
        num_bytes_per_page = UINT32_MAX;
        total_page_count = max_page_count = 1;
        total_size_new = UINT32_MAX;
    }

#ifdef BH_PLATFORM_WINDOWS
    if (!os_mem_commit(memory->memory_data_end.ptr,
                       (uint32)total_size_new - total_size_old,
                       MMAP_PROT_READ | MMAP_PROT_WRITE)) {
        return false;
    }
#endif

    if (os_mprotect(memory->memory_data_end.ptr,
                    (uint32)total_size_new - total_size_old,
                    MMAP_PROT_READ | MMAP_PROT_WRITE)
        != 0) {
#ifdef BH_PLATFORM_WINDOWS
        os_mem_decommit(memory->memory_data_end.ptr,
                        (uint32)total_size_new - total_size_old);
#endif
        return false;
    }

    /* The increased pages are filled with zero by the OS when os_mmap,
       no need to memset it again here */

    memory->num_bytes_per_page = num_bytes_per_page;
    memory->cur_page_count = total_page_count;
    memory->max_page_count = max_page_count;
    memory->memory_data_size = (uint32)total_size_new;
    memory->memory_data_end.ptr =
        (uint8 *)memory->memory_data.ptr + (uint32)total_size_new;

    memory->mem_bound_check_1byte.u64 = total_size_new - 1;
    memory->mem_bound_check_2bytes.u64 = total_size_new - 2;
    memory->mem_bound_check_4bytes.u64 = total_size_new - 4;
    memory->mem_bound_check_8bytes.u64 = total_size_new - 8;
    memory->mem_bound_check_16bytes.u64 = total_size_new - 16;

    return true;
}
#endif /* end of OS_ENABLE_HW_BOUND_CHECK */

bool
aot_invoke_native(WASMExecEnv *exec_env, uint32 func_idx, uint32 argc,
                  uint32 *argv)
{
    AOTModuleInstance *module_inst =
        (AOTModuleInstance *)wasm_runtime_get_module_inst(exec_env);
    AOTModule *aot_module = (AOTModule *)module_inst->aot_module.ptr;
    uint32 *func_type_indexes = (uint32 *)module_inst->func_type_indexes.ptr;
    uint32 func_type_idx = func_type_indexes[func_idx];
    AOTFuncType *func_type = aot_module->func_types[func_type_idx];
    void **func_ptrs = (void **)module_inst->func_ptrs.ptr;
    void *func_ptr = func_ptrs[func_idx];
    AOTImportFunc *import_func;
    const char *signature;
    void *attachment;
    char buf[96];

    bh_assert(func_idx < aot_module->import_func_count);

    import_func = aot_module->import_funcs + func_idx;
    if (!func_ptr) {
        snprintf(buf, sizeof(buf),
                 "failed to call unlinked import function (%s, %s)",
                 import_func->module_name, import_func->func_name);
        aot_set_exception(module_inst, buf);
        return false;
    }

    attachment = import_func->attachment;
    if (import_func->call_conv_wasm_c_api) {
        return wasm_runtime_invoke_c_api_native(
            (WASMModuleInstanceCommon *)module_inst, func_ptr, func_type, argc,
            argv, import_func->wasm_c_api_with_env, attachment);
    }
    else if (!import_func->call_conv_raw) {
        signature = import_func->signature;
        return wasm_runtime_invoke_native(exec_env, func_ptr, func_type,
                                          signature, attachment, argv, argc,
                                          argv);
    }
    else {
        signature = import_func->signature;
        return wasm_runtime_invoke_native_raw(exec_env, func_ptr, func_type,
                                              signature, attachment, argv, argc,
                                              argv);
    }
}

bool
aot_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 table_elem_idx,
                  uint32 argc, uint32 *argv)
{
    AOTModuleInstance *module_inst =
        (AOTModuleInstance *)wasm_runtime_get_module_inst(exec_env);
    AOTModule *aot_module = (AOTModule *)module_inst->aot_module.ptr;
    uint32 *func_type_indexes = (uint32 *)module_inst->func_type_indexes.ptr;
    AOTTableInstance *tbl_inst;
    AOTFuncType *func_type;
    void **func_ptrs = (void **)module_inst->func_ptrs.ptr, *func_ptr;
    uint32 func_type_idx, func_idx, ext_ret_count;
    AOTImportFunc *import_func;
    const char *signature = NULL;
    void *attachment = NULL;
    char buf[96];
    bool ret;

    /* this function is called from native code, so exec_env->handle and
       exec_env->native_stack_boundary must have been set, we don't set
       it again */

    if ((uint8 *)&module_inst < exec_env->native_stack_boundary) {
        aot_set_exception_with_id(module_inst, EXCE_NATIVE_STACK_OVERFLOW);
        return false;
    }

    tbl_inst = aot_get_table_inst(module_inst, tbl_idx);
    bh_assert(tbl_inst);

    if (table_elem_idx >= tbl_inst->cur_size) {
        aot_set_exception_with_id(module_inst, EXCE_UNDEFINED_ELEMENT);
        return false;
    }

    func_idx = ((uint32 *)tbl_inst->data)[table_elem_idx];
    if (func_idx == (uint32)-1) {
        aot_set_exception_with_id(module_inst, EXCE_UNINITIALIZED_ELEMENT);
        return false;
    }

    func_type_idx = func_type_indexes[func_idx];
    func_type = aot_module->func_types[func_type_idx];

#if WASM_ENABLE_LAZY_JIT != 0
    if (func_idx >= aot_module->import_func_count && !func_ptrs[func_idx]) {
        if (!(func_ptr = aot_lookup_orcjit_func(
                  aot_module->comp_ctx->orc_lazyjit, module_inst, func_idx))) {
            return false;
        }
    }
#endif

    if (!(func_ptr = func_ptrs[func_idx])) {
        bh_assert(func_idx < aot_module->import_func_count);
        import_func = aot_module->import_funcs + func_idx;
        snprintf(buf, sizeof(buf),
                 "failed to call unlinked import function (%s, %s)",
                 import_func->module_name, import_func->func_name);
        aot_set_exception(module_inst, buf);
        return false;
    }

    if (func_idx < aot_module->import_func_count) {
        /* Call native function */
        import_func = aot_module->import_funcs + func_idx;
        signature = import_func->signature;
        if (import_func->call_conv_raw) {
            attachment = import_func->attachment;
            return wasm_runtime_invoke_native_raw(exec_env, func_ptr, func_type,
                                                  signature, attachment, argv,
                                                  argc, argv);
        }
    }

    ext_ret_count =
        func_type->result_count > 1 ? func_type->result_count - 1 : 0;
    if (ext_ret_count > 0) {
        uint32 argv1_buf[32], *argv1 = argv1_buf;
        uint32 *ext_rets = NULL, *argv_ret = argv;
        uint32 cell_num = 0, i;
        uint8 *ext_ret_types = func_type->types + func_type->param_count + 1;
        uint32 ext_ret_cell = wasm_get_cell_num(ext_ret_types, ext_ret_count);
        uint64 size;

        /* Allocate memory all arguments */
        size =
            sizeof(uint32) * (uint64)argc /* original arguments */
            + sizeof(void *)
                  * (uint64)ext_ret_count /* extra result values' addr */
            + sizeof(uint32) * (uint64)ext_ret_cell; /* extra result values */
        if (size > sizeof(argv1_buf)
            && !(argv1 = runtime_malloc(size, module_inst->cur_exception,
                                        sizeof(module_inst->cur_exception)))) {
            aot_set_exception_with_id(module_inst, EXCE_OUT_OF_MEMORY);
            return false;
        }

        /* Copy original arguments */
        bh_memcpy_s(argv1, (uint32)size, argv, sizeof(uint32) * argc);

        /* Get the extra result value's address */
        ext_rets =
            argv1 + argc + sizeof(void *) / sizeof(uint32) * ext_ret_count;

        /* Append each extra result value's address to original arguments */
        for (i = 0; i < ext_ret_count; i++) {
            *(uintptr_t *)(argv1 + argc + sizeof(void *) / sizeof(uint32) * i) =
                (uintptr_t)(ext_rets + cell_num);
            cell_num += wasm_value_type_cell_num(ext_ret_types[i]);
        }

        ret = invoke_native_internal(exec_env, func_ptr, func_type, signature,
                                     attachment, argv1, argc, argv);
        if (!ret || aot_get_exception(module_inst)) {
            if (argv1 != argv1_buf)
                wasm_runtime_free(argv1);
            if (clear_wasi_proc_exit_exception(module_inst))
                return true;
            return false;
        }

        /* Get extra result values */
        switch (func_type->types[func_type->param_count]) {
            case VALUE_TYPE_I32:
            case VALUE_TYPE_F32:
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
#endif
                argv_ret++;
                break;
            case VALUE_TYPE_I64:
            case VALUE_TYPE_F64:
                argv_ret += 2;
                break;
#if WASM_ENABLE_SIMD != 0
            case VALUE_TYPE_V128:
                argv_ret += 4;
                break;
#endif
            default:
                bh_assert(0);
                break;
        }
        ext_rets =
            argv1 + argc + sizeof(void *) / sizeof(uint32) * ext_ret_count;
        bh_memcpy_s(argv_ret, sizeof(uint32) * cell_num, ext_rets,
                    sizeof(uint32) * cell_num);

        if (argv1 != argv1_buf)
            wasm_runtime_free(argv1);

        return true;
    }
    else {
        ret = invoke_native_internal(exec_env, func_ptr, func_type, signature,
                                     attachment, argv, argc, argv);
        if (clear_wasi_proc_exit_exception(module_inst))
            return true;
        return ret;
    }
}

/**
 * Check whether the app address and the buf is inside the linear memory,
 * and convert the app address into native address
 */
bool
aot_check_app_addr_and_convert(AOTModuleInstance *module_inst, bool is_str,
                               uint32 app_buf_addr, uint32 app_buf_size,
                               void **p_native_addr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    uint8 *native_addr;

    if (!memory_inst) {
        goto fail;
    }

    native_addr = (uint8 *)memory_inst->memory_data.ptr + app_buf_addr;

    /* No need to check the app_offset and buf_size if memory access
       boundary check with hardware trap is enabled */
#ifndef OS_ENABLE_HW_BOUND_CHECK
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
        str_end = (const char *)memory_inst->memory_data_end.ptr;
        while (str < str_end && *str != '\0')
            str++;
        if (str == str_end)
            goto fail;
    }
#endif

    *p_native_addr = (void *)native_addr;
    return true;
fail:
    aot_set_exception(module_inst, "out of bounds memory access");
    return false;
}

void *
aot_memmove(void *dest, const void *src, size_t n)
{
    return memmove(dest, src, n);
}

void *
aot_memset(void *s, int c, size_t n)
{
    return memset(s, c, n);
}

#if WASM_ENABLE_BULK_MEMORY != 0
bool
aot_memory_init(AOTModuleInstance *module_inst, uint32 seg_index, uint32 offset,
                uint32 len, uint32 dst)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    AOTModule *aot_module;
    uint8 *data = NULL;
    uint8 *maddr;
    uint64 seg_len = 0;

    aot_module = (AOTModule *)module_inst->aot_module.ptr;
    if (aot_module->is_jit_mode) {
#if WASM_ENABLE_JIT != 0
        seg_len =
            aot_module->wasm_module->data_segments[seg_index]->data_length;
        data = aot_module->wasm_module->data_segments[seg_index]->data;
#endif
    }
    else {
        seg_len = aot_module->mem_init_data_list[seg_index]->byte_count;
        data = aot_module->mem_init_data_list[seg_index]->bytes;
    }

    if (!aot_validate_app_addr(module_inst, dst, len))
        return false;

    if ((uint64)offset + (uint64)len > seg_len) {
        aot_set_exception(module_inst, "out of bounds memory access");
        return false;
    }

    maddr = aot_addr_app_to_native(module_inst, dst);

    bh_memcpy_s(maddr, memory_inst->memory_data_size - dst, data + offset, len);
    return true;
}

bool
aot_data_drop(AOTModuleInstance *module_inst, uint32 seg_index)
{
    AOTModule *aot_module = (AOTModule *)(module_inst->aot_module.ptr);

    if (aot_module->is_jit_mode) {
#if WASM_ENABLE_JIT != 0
        aot_module->wasm_module->data_segments[seg_index]->data_length = 0;
        /* Currently we can't free the dropped data segment
            as they are stored in wasm bytecode */
#endif
    }
    else {
        aot_module->mem_init_data_list[seg_index]->byte_count = 0;
        /* Currently we can't free the dropped data segment
            as the mem_init_data_count is a continuous array */
    }
    return true;
}
#endif /* WASM_ENABLE_BULK_MEMORY */

#if WASM_ENABLE_THREAD_MGR != 0
bool
aot_set_aux_stack(WASMExecEnv *exec_env, uint32 start_offset, uint32 size)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTModule *module = (AOTModule *)module_inst->aot_module.ptr;

    uint32 stack_top_idx = module->aux_stack_top_global_index;
    uint32 data_end = module->aux_data_end;
    uint32 stack_bottom = module->aux_stack_bottom;
    bool is_stack_before_data = stack_bottom < data_end ? true : false;

    /* Check the aux stack space, currently we don't allocate space in heap */
    if ((is_stack_before_data && (size > start_offset))
        || ((!is_stack_before_data) && (start_offset - data_end < size)))
        return false;

    if (stack_top_idx != (uint32)-1) {
        /* The aux stack top is a wasm global,
            set the initial value for the global */
        uint32 global_offset = module->globals[stack_top_idx].data_offset;
        uint8 *global_addr =
            (uint8 *)module_inst->global_data.ptr + global_offset;
        *(int32 *)global_addr = start_offset;

        /* The aux stack boundary is a constant value,
            set the value to exec_env */
        exec_env->aux_stack_boundary.boundary = start_offset - size;
        exec_env->aux_stack_bottom.bottom = start_offset;
        return true;
    }

    return false;
}

bool
aot_get_aux_stack(WASMExecEnv *exec_env, uint32 *start_offset, uint32 *size)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTModule *module = (AOTModule *)module_inst->aot_module.ptr;

    /* The aux stack information is resolved in loader
        and store in module */
    uint32 stack_bottom = module->aux_stack_bottom;
    uint32 total_aux_stack_size = module->aux_stack_size;

    if (stack_bottom != 0 && total_aux_stack_size != 0) {
        if (start_offset)
            *start_offset = stack_bottom;
        if (size)
            *size = total_aux_stack_size;
        return true;
    }
    return false;
}
#endif

#if (WASM_ENABLE_MEMORY_PROFILING != 0) || (WASM_ENABLE_MEMORY_TRACING != 0)
static void
const_string_node_size_cb(void *key, void *value, void *p_const_string_size)
{
    uint32 const_string_size = 0;
    const_string_size += bh_hash_map_get_elem_struct_size();
    const_string_size += strlen((const char *)value) + 1;
    *(uint32 *)p_const_string_size += const_string_size;
}

void
aot_get_module_mem_consumption(const AOTModule *module,
                               WASMModuleMemConsumption *mem_conspn)
{
    uint32 i, size;

    memset(mem_conspn, 0, sizeof(*mem_conspn));

    mem_conspn->module_struct_size = sizeof(AOTModule);

    mem_conspn->types_size = sizeof(AOTFuncType *) * module->func_type_count;
    for (i = 0; i < module->func_type_count; i++) {
        AOTFuncType *type = module->func_types[i];
        size = offsetof(AOTFuncType, types)
               + sizeof(uint8) * (type->param_count + type->result_count);
        mem_conspn->types_size += size;
    }

    mem_conspn->imports_size =
        sizeof(AOTImportMemory) * module->import_memory_count
        + sizeof(AOTImportTable) * module->import_table_count
        + sizeof(AOTImportGlobal) * module->import_global_count
        + sizeof(AOTImportFunc) * module->import_func_count;

    /* func_ptrs and func_type_indexes */
    mem_conspn->functions_size =
        (sizeof(void *) + sizeof(uint32)) * module->func_count;

    mem_conspn->tables_size = sizeof(AOTTable) * module->table_count;

    mem_conspn->memories_size = sizeof(AOTMemory) * module->memory_count;
    mem_conspn->globals_size = sizeof(AOTGlobal) * module->global_count;
    mem_conspn->exports_size = sizeof(AOTExport) * module->export_count;

    mem_conspn->table_segs_size =
        sizeof(AOTTableInitData *) * module->table_init_data_count;
    for (i = 0; i < module->table_init_data_count; i++) {
        AOTTableInitData *init_data = module->table_init_data_list[i];
        size = offsetof(AOTTableInitData, func_indexes)
               + sizeof(uint32) * init_data->func_index_count;
        mem_conspn->table_segs_size += size;
    }

    mem_conspn->data_segs_size =
        sizeof(AOTMemInitData *) * module->mem_init_data_count;
    for (i = 0; i < module->mem_init_data_count; i++) {
        mem_conspn->data_segs_size += sizeof(AOTMemInitData);
    }

    if (module->const_str_set) {
        uint32 const_string_size = 0;

        mem_conspn->const_strs_size =
            bh_hash_map_get_struct_size(module->const_str_set);

        bh_hash_map_traverse(module->const_str_set, const_string_node_size_cb,
                             (void *)&const_string_size);
        mem_conspn->const_strs_size += const_string_size;
    }

    /* code size + literal size + object data section size */
    mem_conspn->aot_code_size =
        module->code_size + module->literal_size
        + sizeof(AOTObjectDataSection) * module->data_section_count;
    for (i = 0; i < module->data_section_count; i++) {
        AOTObjectDataSection *obj_data = module->data_sections + i;
        mem_conspn->aot_code_size += sizeof(uint8) * obj_data->size;
    }

    mem_conspn->total_size += mem_conspn->module_struct_size;
    mem_conspn->total_size += mem_conspn->types_size;
    mem_conspn->total_size += mem_conspn->imports_size;
    mem_conspn->total_size += mem_conspn->functions_size;
    mem_conspn->total_size += mem_conspn->tables_size;
    mem_conspn->total_size += mem_conspn->memories_size;
    mem_conspn->total_size += mem_conspn->globals_size;
    mem_conspn->total_size += mem_conspn->exports_size;
    mem_conspn->total_size += mem_conspn->table_segs_size;
    mem_conspn->total_size += mem_conspn->data_segs_size;
    mem_conspn->total_size += mem_conspn->const_strs_size;
    mem_conspn->total_size += mem_conspn->aot_code_size;
}

void
aot_get_module_inst_mem_consumption(const AOTModuleInstance *module_inst,
                                    WASMModuleInstMemConsumption *mem_conspn)
{
    AOTTableInstance *tbl_inst;
    uint32 i;

    memset(mem_conspn, 0, sizeof(*mem_conspn));

    mem_conspn->module_inst_struct_size = sizeof(AOTModuleInstance);

    mem_conspn->memories_size =
        sizeof(AOTPointer) * module_inst->memory_count
        + sizeof(AOTMemoryInstance) * module_inst->memory_count;
    for (i = 0; i < module_inst->memory_count; i++) {
        AOTMemoryInstance *mem_inst =
            ((AOTMemoryInstance **)module_inst->memories.ptr)[i];
        mem_conspn->memories_size +=
            mem_inst->num_bytes_per_page * mem_inst->cur_page_count;
        mem_conspn->app_heap_size = (uint8 *)mem_inst->heap_data_end.ptr
                                    - (uint8 *)mem_inst->heap_data.ptr;
        /* size of app heap structure */
        mem_conspn->memories_size += mem_allocator_get_heap_struct_size();
    }

    tbl_inst = module_inst->tables.ptr;
    for (i = 0; i < module_inst->table_count; i++) {
        mem_conspn->tables_size += offsetof(AOTTableInstance, data);
        mem_conspn->tables_size += sizeof(uint32) * tbl_inst->max_size;
        tbl_inst = aot_next_tbl_inst(tbl_inst);
    }

    /* func_ptrs and func_type_indexes */
    mem_conspn->functions_size =
        (sizeof(void *) + sizeof(uint32))
        * (((AOTModule *)module_inst->aot_module.ptr)->import_func_count
           + ((AOTModule *)module_inst->aot_module.ptr)->func_count);

    mem_conspn->globals_size = module_inst->global_data_size;

    mem_conspn->exports_size =
        sizeof(AOTFunctionInstance) * (uint64)module_inst->export_func_count;

    mem_conspn->total_size += mem_conspn->module_inst_struct_size;
    mem_conspn->total_size += mem_conspn->memories_size;
    mem_conspn->total_size += mem_conspn->functions_size;
    mem_conspn->total_size += mem_conspn->tables_size;
    mem_conspn->total_size += mem_conspn->globals_size;
    mem_conspn->total_size += mem_conspn->exports_size;
}
#endif /* end of (WASM_ENABLE_MEMORY_PROFILING != 0) \
                 || (WASM_ENABLE_MEMORY_TRACING != 0) */

#if WASM_ENABLE_REF_TYPES != 0
void
aot_drop_table_seg(AOTModuleInstance *module_inst, uint32 tbl_seg_idx)
{
    AOTModule *module = (AOTModule *)module_inst->aot_module.ptr;
    AOTTableInitData *tbl_seg = module->table_init_data_list[tbl_seg_idx];
    tbl_seg->is_dropped = true;
}

void
aot_table_init(AOTModuleInstance *module_inst, uint32 tbl_idx,
               uint32 tbl_seg_idx, uint32 length, uint32 src_offset,
               uint32 dst_offset)
{
    AOTTableInstance *tbl_inst;
    AOTTableInitData *tbl_seg;
    const AOTModule *module = module_inst->aot_module.ptr;

    tbl_inst = aot_get_table_inst(module_inst, tbl_idx);
    bh_assert(tbl_inst);

    tbl_seg = module->table_init_data_list[tbl_seg_idx];
    bh_assert(tbl_seg);

    if (!length) {
        return;
    }

    if (length + src_offset > tbl_seg->func_index_count
        || dst_offset + length > tbl_inst->cur_size) {
        aot_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    if (tbl_seg->is_dropped) {
        aot_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    if (!wasm_elem_is_passive(tbl_seg->mode)) {
        aot_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    bh_memcpy_s((uint8 *)tbl_inst + offsetof(AOTTableInstance, data)
                    + dst_offset * sizeof(uint32),
                (tbl_inst->cur_size - dst_offset) * sizeof(uint32),
                tbl_seg->func_indexes + src_offset, length * sizeof(uint32));
}

void
aot_table_copy(AOTModuleInstance *module_inst, uint32 src_tbl_idx,
               uint32 dst_tbl_idx, uint32 length, uint32 src_offset,
               uint32 dst_offset)
{
    AOTTableInstance *src_tbl_inst, *dst_tbl_inst;

    src_tbl_inst = aot_get_table_inst(module_inst, src_tbl_idx);
    bh_assert(src_tbl_inst);

    dst_tbl_inst = aot_get_table_inst(module_inst, dst_tbl_idx);
    bh_assert(dst_tbl_inst);

    if ((uint64)dst_offset + length > dst_tbl_inst->cur_size
        || (uint64)src_offset + length > src_tbl_inst->cur_size) {
        aot_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    /* if src_offset >= dst_offset, copy from front to back */
    /* if src_offset < dst_offset, copy from back to front */
    /* merge all together */
    bh_memmove_s((uint8 *)(dst_tbl_inst) + offsetof(AOTTableInstance, data)
                     + dst_offset * sizeof(uint32),
                 (dst_tbl_inst->cur_size - dst_offset) * sizeof(uint32),
                 (uint8 *)(src_tbl_inst) + offsetof(AOTTableInstance, data)
                     + src_offset * sizeof(uint32),
                 length * sizeof(uint32));
}

void
aot_table_fill(AOTModuleInstance *module_inst, uint32 tbl_idx, uint32 length,
               uint32 val, uint32 data_offset)
{
    AOTTableInstance *tbl_inst;

    tbl_inst = aot_get_table_inst(module_inst, tbl_idx);
    bh_assert(tbl_inst);

    if (data_offset + length > tbl_inst->cur_size) {
        aot_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    for (; length != 0; data_offset++, length--) {
        tbl_inst->data[data_offset] = val;
    }
}

uint32
aot_table_grow(AOTModuleInstance *module_inst, uint32 tbl_idx,
               uint32 inc_entries, uint32 init_val)
{
    uint32 entry_count, i, orig_tbl_sz;
    AOTTableInstance *tbl_inst;

    tbl_inst = aot_get_table_inst(module_inst, tbl_idx);
    if (!tbl_inst) {
        return (uint32)-1;
    }

    orig_tbl_sz = tbl_inst->cur_size;

    if (!inc_entries) {
        return orig_tbl_sz;
    }

    if (tbl_inst->cur_size > UINT32_MAX - inc_entries) {
        return (uint32)-1;
    }

    entry_count = tbl_inst->cur_size + inc_entries;
    if (entry_count > tbl_inst->max_size) {
        return (uint32)-1;
    }

    /* fill in */
    for (i = 0; i < inc_entries; ++i) {
        tbl_inst->data[tbl_inst->cur_size + i] = init_val;
    }

    tbl_inst->cur_size = entry_count;
    return orig_tbl_sz;
}
#endif /* WASM_ENABLE_REF_TYPES != 0 */

#if (WASM_ENABLE_DUMP_CALL_STACK != 0) || (WASM_ENABLE_PERF_PROFILING != 0)
#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
static const char *
lookup_func_name(const char **func_names, uint32 *func_indexes,
                 uint32 func_index_count, uint32 func_index)
{
    int64 low = 0, mid;
    int64 high = func_index_count - 1;

    if (!func_names || !func_indexes || func_index_count == 0)
        return NULL;

    while (low <= high) {
        mid = (low + high) / 2;
        if (func_index == func_indexes[mid]) {
            return func_names[mid];
        }
        else if (func_index < func_indexes[mid])
            high = mid - 1;
        else
            low = mid + 1;
    }

    return NULL;
}
#endif /* WASM_ENABLE_CUSTOM_NAME_SECTION != 0 */

static const char *
get_func_name_from_index(const AOTModuleInstance *module_inst,
                         uint32 func_index)
{
    const char *func_name = NULL;
    AOTModule *module = module_inst->aot_module.ptr;

#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
    if ((func_name =
             lookup_func_name(module->aux_func_names, module->aux_func_indexes,
                              module->aux_func_name_count, func_index))) {
        return func_name;
    }
#endif

    if (func_index < module->import_func_count) {
        func_name = module->import_funcs[func_index].func_name;
    }
    else {
        uint32 i;

        for (i = 0; i < module->export_count; i++) {
            AOTExport export = module->exports[i];
            if (export.index == func_index && export.kind == EXPORT_KIND_FUNC) {
                func_name = export.name;
                break;
            }
        }
    }

    return func_name;
}

bool
aot_alloc_frame(WASMExecEnv *exec_env, uint32 func_index)
{
    AOTFrame *frame =
        wasm_exec_env_alloc_wasm_frame(exec_env, sizeof(AOTFrame));
#if WASM_ENABLE_PERF_PROFILING != 0
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTFuncPerfProfInfo *func_perf_prof =
        (AOTFuncPerfProfInfo *)module_inst->func_perf_profilings.ptr
        + func_index;
#endif

    if (!frame) {
        aot_set_exception((AOTModuleInstance *)exec_env->module_inst,
                          "auxiliary call stack overflow");
        return false;
    }

#if WASM_ENABLE_PERF_PROFILING != 0
    frame->time_started = os_time_get_boot_microsecond();
    frame->func_perf_prof_info = func_perf_prof;
#endif

    frame->prev_frame = (AOTFrame *)exec_env->cur_frame;
    exec_env->cur_frame = (struct WASMInterpFrame *)frame;

    frame->func_index = func_index;
    return true;
}

void
aot_free_frame(WASMExecEnv *exec_env)
{
    AOTFrame *cur_frame = (AOTFrame *)exec_env->cur_frame;
    AOTFrame *prev_frame = cur_frame->prev_frame;

#if WASM_ENABLE_PERF_PROFILING != 0
    cur_frame->func_perf_prof_info->total_exec_time +=
        os_time_get_boot_microsecond() - cur_frame->time_started;
    cur_frame->func_perf_prof_info->total_exec_cnt++;
#endif

    wasm_exec_env_free_wasm_frame(exec_env, cur_frame);
    exec_env->cur_frame = (struct WASMInterpFrame *)prev_frame;
}
#endif /* end of (WASM_ENABLE_DUMP_CALL_STACK != 0) \
                 || (WASM_ENABLE_PERF_PROFILING != 0) */

#if WASM_ENABLE_DUMP_CALL_STACK != 0
bool
aot_create_call_stack(struct WASMExecEnv *exec_env)
{
    AOTFrame *cur_frame = (AOTFrame *)exec_env->cur_frame,
             *first_frame = cur_frame;
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    uint32 n = 0;

    while (cur_frame) {
        cur_frame = cur_frame->prev_frame;
        n++;
    }

    /* release previous stack frames and create new ones */
    if (!bh_vector_destroy(module_inst->frames.ptr)
        || !bh_vector_init(module_inst->frames.ptr, n, sizeof(WASMCApiFrame),
                           false)) {
        return false;
    }

    cur_frame = first_frame;
    while (cur_frame) {
        WASMCApiFrame frame = { 0 };
        frame.instance = module_inst;
        frame.module_offset = 0;
        frame.func_index = cur_frame->func_index;
        frame.func_offset = 0;
        frame.func_name_wp =
            get_func_name_from_index(module_inst, cur_frame->func_index);

        if (!bh_vector_append(module_inst->frames.ptr, &frame)) {
            bh_vector_destroy(module_inst->frames.ptr);
            return false;
        }

        cur_frame = cur_frame->prev_frame;
    }

    return true;
}

#define PRINT_OR_DUMP()                                                   \
    do {                                                                  \
        total_len +=                                                      \
            wasm_runtime_dump_line_buf_impl(line_buf, print, &buf, &len); \
        if ((!print) && buf && (len == 0)) {                              \
            return total_len;                                             \
        }                                                                 \
    } while (0)

uint32
aot_dump_call_stack(WASMExecEnv *exec_env, bool print, char *buf, uint32 len)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    uint32 n = 0, total_len = 0, total_frames;
    /* reserve 256 bytes for line buffer, any line longer than 256 bytes
     * will be truncated */
    char line_buf[256];

    if (!module_inst->frames.ptr) {
        return 0;
    }

    total_frames = (uint32)bh_vector_size(module_inst->frames.ptr);
    if (total_frames == 0) {
        return 0;
    }

    snprintf(line_buf, sizeof(line_buf), "\n");
    PRINT_OR_DUMP();

    while (n < total_frames) {
        WASMCApiFrame frame = { 0 };
        uint32 line_length, i;

        if (!bh_vector_get(module_inst->frames.ptr, n, &frame)) {
            return 0;
        }

        /* function name not exported, print number instead */
        if (frame.func_name_wp == NULL) {
            line_length = snprintf(line_buf, sizeof(line_buf), "#%02d $f%d\n",
                                   n, frame.func_index);
        }
        else {
            line_length = snprintf(line_buf, sizeof(line_buf), "#%02d %s\n", n,
                                   frame.func_name_wp);
        }

        if (line_length >= sizeof(line_buf)) {
            uint32 line_buffer_len = sizeof(line_buf);
            /* If line too long, ensure the last character is '\n' */
            for (i = line_buffer_len - 5; i < line_buffer_len - 2; i++) {
                line_buf[i] = '.';
            }
            line_buf[line_buffer_len - 2] = '\n';
        }

        PRINT_OR_DUMP();

        n++;
    }
    snprintf(line_buf, sizeof(line_buf), "\n");
    PRINT_OR_DUMP();

    return total_len + 1;
}
#endif /* end of WASM_ENABLE_DUMP_CALL_STACK */

#if WASM_ENABLE_PERF_PROFILING != 0
void
aot_dump_perf_profiling(const AOTModuleInstance *module_inst)
{
    AOTFuncPerfProfInfo *perf_prof =
        (AOTFuncPerfProfInfo *)module_inst->func_perf_profilings.ptr;
    AOTModule *module = (AOTModule *)module_inst->aot_module.ptr;
    uint32 total_func_count = module->import_func_count + module->func_count, i;
    const char *func_name;

    os_printf("Performance profiler data:\n");
    for (i = 0; i < total_func_count; i++, perf_prof++) {
        func_name = get_func_name_from_index(module_inst, i);

        if (func_name)
            os_printf("  func %s, execution time: %.3f ms, execution count: %d "
                      "times\n",
                      func_name, perf_prof->total_exec_time / 1000.0f,
                      perf_prof->total_exec_cnt);
        else
            os_printf("  func %d, execution time: %.3f ms, execution count: %d "
                      "times\n",
                      i, perf_prof->total_exec_time / 1000.0f,
                      perf_prof->total_exec_cnt);
    }
}
#endif /* end of WASM_ENABLE_PERF_PROFILING */
