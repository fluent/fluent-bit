/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_runtime.h"
#include "bh_log.h"
#include "mem_alloc.h"
#include "../common/wasm_runtime_common.h"
#include "../common/wasm_memory.h"
#include "../interpreter/wasm_runtime.h"
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
bh_static_assert(offsetof(WASMExecEnv, native_stack_top_min)
                 == 9 * sizeof(uintptr_t));

bh_static_assert(offsetof(AOTModuleInstance, memories) == 1 * sizeof(uint64));
bh_static_assert(offsetof(AOTModuleInstance, func_ptrs) == 5 * sizeof(uint64));
bh_static_assert(offsetof(AOTModuleInstance, func_type_indexes)
                 == 6 * sizeof(uint64));
bh_static_assert(offsetof(AOTModuleInstance, cur_exception)
                 == 13 * sizeof(uint64));
bh_static_assert(offsetof(AOTModuleInstance, global_table_data)
                 == 13 * sizeof(uint64) + 128 + 11 * sizeof(uint64));

bh_static_assert(sizeof(AOTMemoryInstance) == 104);
bh_static_assert(offsetof(AOTTableInstance, elems) == 8);

bh_static_assert(offsetof(AOTModuleInstanceExtra, stack_sizes) == 0);
bh_static_assert(offsetof(AOTModuleInstanceExtra, common.c_api_func_imports)
                 == sizeof(uint64));

bh_static_assert(sizeof(CApiFuncImport) == sizeof(uintptr_t) * 3);

bh_static_assert(sizeof(wasm_val_t) == 16);
bh_static_assert(offsetof(wasm_val_t, of) == 8);

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
            bh_memcpy_s(global_data, sizeof(V128), &initial_value->v128,
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
    uint8 *p = module_inst->global_data;
    AOTImportGlobal *import_global = module->import_globals;
    AOTGlobal *global = module->globals;

    /* Initialize import global data */
    for (i = 0; i < module->import_global_count; i++, import_global++) {
        bh_assert(import_global->data_offset
                  == (uint32)(p - module_inst->global_data));
        init_global_data(p, import_global->type,
                         &import_global->global_data_linked);
        p += import_global->size;
    }

    /* Initialize defined global data */
    for (i = 0; i < module->global_count; i++, global++) {
        bh_assert(global->data_offset
                  == (uint32)(p - module_inst->global_data));
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
              == (uint32)(p - module_inst->global_data));
    return true;
}

static bool
tables_instantiate(AOTModuleInstance *module_inst, AOTModule *module,
                   AOTTableInstance *first_tbl_inst, char *error_buf,
                   uint32 error_buf_size)
{
    uint32 i, global_index, global_data_offset, base_offset, length;
    uint64 total_size;
    AOTTableInitData *table_seg;
    AOTTableInstance *tbl_inst = first_tbl_inst;

    total_size = (uint64)sizeof(WASMTableInstance *) * module_inst->table_count;
    if (total_size > 0
        && !(module_inst->tables =
                 runtime_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    /*
     * treat import table like a local one until we enable module linking
     * in AOT mode
     */
    for (i = 0; i != module_inst->table_count; ++i) {
        if (i < module->import_table_count) {
            AOTImportTable *import_table = module->import_tables + i;
            tbl_inst->cur_size = import_table->table_init_size;
            tbl_inst->max_size =
                aot_get_imp_tbl_data_slots(import_table, false);
        }
        else {
            AOTTable *table = module->tables + (i - module->import_table_count);
            tbl_inst->cur_size = table->table_init_size;
            tbl_inst->max_size = aot_get_tbl_data_slots(table, false);
        }

        /* Set all elements to -1 to mark them as uninitialized elements */
        memset(tbl_inst->elems, 0xff, sizeof(uint32) * tbl_inst->max_size);

        module_inst->tables[i] = tbl_inst;
        tbl_inst = (AOTTableInstance *)((uint8 *)tbl_inst
                                        + offsetof(AOTTableInstance, elems)
                                        + sizeof(uint32) * tbl_inst->max_size);
    }

    /* fill table with element segment content */
    for (i = 0; i < module->table_init_data_count; i++) {
        table_seg = module->table_init_data_list[i];

#if WASM_ENABLE_REF_TYPES != 0
        if (!wasm_elem_is_active(table_seg->mode))
            continue;
#endif

        bh_assert(table_seg->table_index < module_inst->table_count);

        tbl_inst = module_inst->tables[table_seg->table_index];
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

            base_offset =
                *(uint32 *)(module_inst->global_data + global_data_offset);
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
        bh_memcpy_s(tbl_inst->elems + base_offset,
                    (tbl_inst->max_size - base_offset) * sizeof(uint32),
                    table_seg->func_indexes, length * sizeof(uint32));
    }

    return true;
}

static void
memories_deinstantiate(AOTModuleInstance *module_inst)
{
#ifdef WASM_LINEAR_MEMORY_MMAP
    uint64 map_size;
#endif
    uint32 i;
    AOTMemoryInstance *memory_inst;

    for (i = 0; i < module_inst->memory_count; i++) {
        memory_inst = module_inst->memories[i];
        if (memory_inst) {
#if WASM_ENABLE_SHARED_MEMORY != 0
            if (shared_memory_is_shared(memory_inst)) {
                uint32 ref_count = shared_memory_dec_reference(memory_inst);
                /* if the reference count is not zero,
                    don't free the memory */
                if (ref_count > 0)
                    continue;
            }
#endif
            if (memory_inst->heap_handle) {
                mem_allocator_destroy(memory_inst->heap_handle);
                wasm_runtime_free(memory_inst->heap_handle);
            }

            if (memory_inst->memory_data) {
#ifndef OS_ENABLE_HW_BOUND_CHECK
#ifdef WASM_LINEAR_MEMORY_MMAP
                if (shared_memory_is_shared(memory_inst)) {
                    map_size = (uint64)memory_inst->num_bytes_per_page
                               * memory_inst->max_page_count;
                    wasm_munmap_linear_memory(memory_inst->memory_data,
                                              map_size, map_size);
                }
                else
#endif
                    wasm_runtime_free(memory_inst->memory_data);
#else
                map_size = (uint64)memory_inst->num_bytes_per_page
                           * memory_inst->cur_page_count;
                wasm_munmap_linear_memory(memory_inst->memory_data, map_size,
                                          8 * (uint64)BH_GB);
#endif
            }
        }
    }
    wasm_runtime_free(module_inst->memories);
}

static AOTMemoryInstance *
memory_instantiate(AOTModuleInstance *module_inst, AOTModuleInstance *parent,
                   AOTModule *module, AOTMemoryInstance *memory_inst,
                   AOTMemory *memory, uint32 memory_idx, uint32 heap_size,
                   char *error_buf, uint32 error_buf_size)
{
    void *heap_handle;
    uint32 num_bytes_per_page = memory->num_bytes_per_page;
    uint32 init_page_count = memory->mem_init_page_count;
    uint32 max_page_count = memory->mem_max_page_count;
    uint32 inc_page_count, aux_heap_base, global_idx;
    uint32 bytes_of_last_page, bytes_to_page_end;
    uint32 heap_offset = num_bytes_per_page * init_page_count;
    uint64 memory_data_size, max_memory_data_size;
    uint8 *p = NULL, *global_addr;
#ifdef WASM_LINEAR_MEMORY_MMAP
    uint8 *mapped_mem = NULL;
    uint64 map_size;
#endif

#if WASM_ENABLE_SHARED_MEMORY != 0
    bool is_shared_memory = memory->memory_flags & 0x02 ? true : false;

    /* Shared memory */
    if (is_shared_memory && parent != NULL) {
        AOTMemoryInstance *shared_memory_instance;
        bh_assert(memory_idx == 0);
        bh_assert(parent->memory_count > memory_idx);
        shared_memory_instance = parent->memories[memory_idx];
        shared_memory_inc_reference(shared_memory_instance);
        return shared_memory_instance;
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
                          "try using `--heap-size=0` option");
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
            global_addr = module_inst->global_data
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
                          "try using `--heap-size=0` option");
            return NULL;
        }
        else if (init_page_count == DEFAULT_MAX_PAGES) {
            num_bytes_per_page = UINT32_MAX;
            init_page_count = max_page_count = 1;
        }
        if (max_page_count > DEFAULT_MAX_PAGES)
            max_page_count = DEFAULT_MAX_PAGES;
    }
    else { /* heap_size == 0 */
        if (init_page_count == DEFAULT_MAX_PAGES) {
            num_bytes_per_page = UINT32_MAX;
            init_page_count = max_page_count = 1;
        }
    }

    LOG_VERBOSE("Memory instantiate:");
    LOG_VERBOSE("  page bytes: %u, init pages: %u, max pages: %u",
                num_bytes_per_page, init_page_count, max_page_count);
    LOG_VERBOSE("  data offset: %u, stack size: %d", module->aux_data_end,
                module->aux_stack_size);
    LOG_VERBOSE("  heap offset: %u, heap size: %d\n", heap_offset, heap_size);

    memory_data_size = (uint64)num_bytes_per_page * init_page_count;
    max_memory_data_size = (uint64)num_bytes_per_page * max_page_count;
    bh_assert(memory_data_size <= UINT32_MAX);
    bh_assert(max_memory_data_size <= 4 * (uint64)BH_GB);
    (void)max_memory_data_size;

#ifndef OS_ENABLE_HW_BOUND_CHECK
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (is_shared_memory) {
#if WASM_ENABLE_SHARED_MEMORY_MMAP != 0
        map_size = max_memory_data_size;
        if (max_memory_data_size > 0
            && !(p = mapped_mem =
                     wasm_mmap_linear_memory(map_size, &max_memory_data_size,
                                             error_buf, error_buf_size))) {
            return NULL;
        }
#else
        /* Allocate maximum memory size when memory is shared */
        if (max_memory_data_size > 0
            && !(p = runtime_malloc(max_memory_data_size, error_buf,
                                    error_buf_size))) {
            return NULL;
        }
#endif
    }
    else
#endif /* end of WASM_ENABLE_SHARED_MEMORY != 0 */
    {
        /* Allocate initial memory size when memory is not shared */
        if (memory_data_size > 0
            && !(p = runtime_malloc(memory_data_size, error_buf,
                                    error_buf_size))) {
            return NULL;
        }
    }
#else  /* else of OS_ENABLE_HW_BOUND_CHECK */
    /* Totally 8G is mapped, the opcode load/store address range is 0 to 8G:
     *   ea = i + memarg.offset
     * both i and memarg.offset are u32 in range 0 to 4G
     * so the range of ea is 0 to 8G
     */
    map_size = 8 * (uint64)BH_GB;
    if (!(p = mapped_mem = wasm_mmap_linear_memory(
              map_size, &memory_data_size, error_buf, error_buf_size))) {
        set_error_buf(error_buf, error_buf_size, "mmap memory failed");
        return NULL;
    }
#endif /* end of OS_ENABLE_HW_BOUND_CHECK */

    memory_inst->module_type = Wasm_Module_AoT;
    memory_inst->num_bytes_per_page = num_bytes_per_page;
    memory_inst->cur_page_count = init_page_count;
    memory_inst->max_page_count = max_page_count;
    memory_inst->memory_data_size = (uint32)memory_data_size;

    /* Init memory info */
    memory_inst->memory_data = p;
    memory_inst->memory_data_end = p + (uint32)memory_data_size;

    /* Initialize heap info */
    memory_inst->heap_data = p + heap_offset;
    memory_inst->heap_data_end = p + heap_offset + heap_size;
    if (heap_size > 0) {
        uint32 heap_struct_size = mem_allocator_get_heap_struct_size();

        if (!(heap_handle = runtime_malloc((uint64)heap_struct_size, error_buf,
                                           error_buf_size))) {
            goto fail1;
        }

        memory_inst->heap_handle = heap_handle;

        if (!mem_allocator_create_with_struct_and_pool(
                heap_handle, heap_struct_size, memory_inst->heap_data,
                heap_size)) {
            set_error_buf(error_buf, error_buf_size, "init app heap failed");
            goto fail2;
        }
    }

    if (memory_data_size > 0) {
        wasm_runtime_set_mem_bound_check_bytes(memory_inst, memory_data_size);
    }

#if WASM_ENABLE_SHARED_MEMORY != 0
    if (is_shared_memory) {
        memory_inst->is_shared_memory = 1;
        memory_inst->ref_count = 1;
    }
#endif

    return memory_inst;

fail2:
    if (heap_size > 0)
        wasm_runtime_free(memory_inst->heap_handle);
fail1:
#ifdef WASM_LINEAR_MEMORY_MMAP
    if (mapped_mem)
        wasm_munmap_linear_memory(mapped_mem, memory_data_size, map_size);
    else
#endif
    {
        if (memory_inst->memory_data)
            wasm_runtime_free(memory_inst->memory_data);
    }
    memory_inst->memory_data = NULL;
    return NULL;
}

static AOTMemoryInstance *
aot_get_default_memory(AOTModuleInstance *module_inst)
{
    if (module_inst->memories)
        return module_inst->memories[0];
    else
        return NULL;
}

static bool
memories_instantiate(AOTModuleInstance *module_inst, AOTModuleInstance *parent,
                     AOTModule *module, uint32 heap_size, char *error_buf,
                     uint32 error_buf_size)
{
    uint32 global_index, global_data_offset, base_offset, length;
    uint32 i, memory_count = module->memory_count;
    AOTMemoryInstance *memories, *memory_inst;
    AOTMemInitData *data_seg;
    uint64 total_size;

    module_inst->memory_count = memory_count;
    total_size = sizeof(AOTMemoryInstance *) * (uint64)memory_count;
    if (!(module_inst->memories =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    memories = module_inst->global_table_data.memory_instances;
    for (i = 0; i < memory_count; i++, memories++) {
        memory_inst = memory_instantiate(module_inst, parent, module, memories,
                                         &module->memories[i], i, heap_size,
                                         error_buf, error_buf_size);
        if (!memory_inst) {
            return false;
        }

        module_inst->memories[i] = memory_inst;
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
        if (parent != NULL)
            /* Ignore setting memory init data if the memory has been
               initialized */
            continue;

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

            base_offset =
                *(uint32 *)(module_inst->global_data + global_data_offset);
        }
        else {
            base_offset = (uint32)data_seg->offset.u.i32;
        }

        /* Copy memory data */
        bh_assert(memory_inst->memory_data
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

        if (memory_inst->memory_data) {
            bh_memcpy_s((uint8 *)memory_inst->memory_data + base_offset,
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
    if (!(module_inst->func_ptrs =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    /* Set import function pointers */
    func_ptrs = (void **)module_inst->func_ptrs;
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
    if (!(module_inst->func_type_indexes =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    /* Set import function type indexes */
    func_type_index = module_inst->func_type_indexes;
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
        if (!(export_func = runtime_malloc(size, error_buf, error_buf_size))) {
            return false;
        }
        module_inst->export_functions = (void *)export_func;

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
                module_inst->export_table_count++;
                break;
            case EXPORT_KIND_MEMORY:
                module_inst->export_memory_count++;
                break;
            default:
                return false;
        }
    }

    return create_export_funcs(module_inst, module, error_buf, error_buf_size);
}

static AOTFunctionInstance *
lookup_post_instantiate_func(AOTModuleInstance *module_inst,
                             const char *func_name)
{
    AOTFunctionInstance *func;
    AOTFuncType *func_type;

    if (!(func = aot_lookup_function(module_inst, func_name, NULL)))
        /* Not found */
        return NULL;

    func_type = func->u.func.func_type;
    if (!(func_type->param_count == 0 && func_type->result_count == 0))
        /* Not a valid function type, ignore it */
        return NULL;

    return func;
}

static bool
execute_post_instantiate_functions(AOTModuleInstance *module_inst,
                                   bool is_sub_inst, WASMExecEnv *exec_env_main)
{
    AOTModule *module = (AOTModule *)module_inst->module;
    AOTFunctionInstance *initialize_func = NULL;
    AOTFunctionInstance *post_inst_func = NULL;
    AOTFunctionInstance *call_ctors_func = NULL;
    WASMModuleInstanceCommon *module_inst_main = NULL;
#ifdef OS_ENABLE_HW_BOUND_CHECK
    WASMExecEnv *exec_env_tls = wasm_runtime_get_exec_env_tls();
#endif
    WASMExecEnv *exec_env = NULL, *exec_env_created = NULL;
    bool ret = false;

#if WASM_ENABLE_LIBC_WASI != 0
    /*
     * WASI reactor instances may assume that _initialize will be called by
     * the environment at most once, and that none of their other exports
     * are accessed before that call.
     */
    if (!is_sub_inst && module->import_wasi_api) {
        initialize_func =
            lookup_post_instantiate_func(module_inst, "_initialize");
    }
#endif

    /* Execute possible "__post_instantiate" function if wasm app is
       compiled by emsdk's early version */
    if (!is_sub_inst) {
        post_inst_func =
            lookup_post_instantiate_func(module_inst, "__post_instantiate");
    }

#if WASM_ENABLE_BULK_MEMORY != 0
    /* Only execute the memory init function for main instance since
       the data segments will be dropped once initialized */
    if (!is_sub_inst
#if WASM_ENABLE_LIBC_WASI != 0
        && !module->import_wasi_api
#endif
    ) {
        call_ctors_func =
            lookup_post_instantiate_func(module_inst, "__wasm_call_ctors");
    }
#endif

    if (!module->start_function && !initialize_func && !post_inst_func
        && !call_ctors_func) {
        /* No post instantiation functions to call */
        return true;
    }

    if (is_sub_inst) {
        bh_assert(exec_env_main);
#ifdef OS_ENABLE_HW_BOUND_CHECK
        bh_assert(exec_env_tls == exec_env_main);
        (void)exec_env_tls;
#endif
        exec_env = exec_env_main;

        /* Temporarily replace parent exec_env's module inst to current
           module inst to avoid checking failure when calling the
           wasm functions, and ensure that the exec_env's module inst
           is the correct one. */
        module_inst_main = exec_env_main->module_inst;
        wasm_exec_env_set_module_inst(exec_env,
                                      (WASMModuleInstanceCommon *)module_inst);
    }
    else {
        /* Try using the existing exec_env */
#ifdef OS_ENABLE_HW_BOUND_CHECK
        exec_env = exec_env_tls;
#endif
#if WASM_ENABLE_THREAD_MGR != 0
        if (!exec_env)
            exec_env = wasm_clusters_search_exec_env(
                (WASMModuleInstanceCommon *)module_inst);
#endif
        if (!exec_env) {
            if (!(exec_env = exec_env_created = wasm_exec_env_create(
                      (WASMModuleInstanceCommon *)module_inst,
                      module_inst->default_wasm_stack_size))) {
                aot_set_exception(module_inst, "allocate memory failed");
                return false;
            }
        }
        else {
            /* Temporarily replace exec_env's module inst with current
               module inst to ensure that the exec_env's module inst
               is the correct one. */
            module_inst_main = exec_env->module_inst;
            wasm_exec_env_set_module_inst(
                exec_env, (WASMModuleInstanceCommon *)module_inst);
        }
    }

#if defined(os_writegsbase)
    {
        AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
        if (memory_inst)
            /* write base addr of linear memory to GS segment register */
            os_writegsbase(memory_inst->memory_data);
    }
#endif

    /* Execute start function for both main insance and sub instance */
    if (module->start_function) {
        AOTFunctionInstance start_func = { 0 };
        uint32 func_type_idx;

        start_func.func_name = "";
        start_func.func_index = module->start_func_index;
        start_func.is_import_func = false;
        func_type_idx = module->func_type_indexes[module->start_func_index
                                                  - module->import_func_count];
        start_func.u.func.func_type = module->func_types[func_type_idx];
        start_func.u.func.func_ptr = module->start_function;
        if (!aot_call_function(exec_env, &start_func, 0, NULL)) {
            goto fail;
        }
    }

    if (initialize_func
        && !aot_call_function(exec_env, initialize_func, 0, NULL)) {
        goto fail;
    }

    if (post_inst_func
        && !aot_call_function(exec_env, post_inst_func, 0, NULL)) {
        goto fail;
    }

    if (call_ctors_func
        && !aot_call_function(exec_env, call_ctors_func, 0, NULL)) {
        goto fail;
    }

    ret = true;

fail:
    if (is_sub_inst) {
        /* Restore the parent exec_env's module inst */
        wasm_exec_env_restore_module_inst(exec_env_main, module_inst_main);
    }
    else {
        if (module_inst_main)
            /* Restore the existing exec_env's module inst */
            wasm_exec_env_restore_module_inst(exec_env, module_inst_main);
        if (exec_env_created)
            wasm_exec_env_destroy(exec_env_created);
    }

    return ret;
}

static bool
check_linked_symbol(AOTModule *module, char *error_buf, uint32 error_buf_size)
{
    uint32 i;

    /* init_func_ptrs() will go through import functions */

    for (i = 0; i < module->import_global_count; i++) {
        AOTImportGlobal *global = module->import_globals + i;
        if (!global->is_linked) {
            set_error_buf_v(error_buf, error_buf_size,
                            "failed to link import global (%s, %s)",
                            global->module_name, global->global_name);
            return false;
        }
    }

    return true;
}

AOTModuleInstance *
aot_instantiate(AOTModule *module, AOTModuleInstance *parent,
                WASMExecEnv *exec_env_main, uint32 stack_size, uint32 heap_size,
                char *error_buf, uint32 error_buf_size)
{
    AOTModuleInstance *module_inst;
#if WASM_ENABLE_BULK_MEMORY != 0 || WASM_ENABLE_REF_TYPES != 0
    WASMModuleInstanceExtraCommon *common;
#endif
    const uint32 module_inst_struct_size =
        offsetof(AOTModuleInstance, global_table_data.bytes);
    const uint64 module_inst_mem_inst_size =
        (uint64)module->memory_count * sizeof(AOTMemoryInstance);
    uint64 total_size, table_size = 0;
    uint8 *p;
    uint32 i, extra_info_offset;
    const bool is_sub_inst = parent != NULL;
#if WASM_ENABLE_MULTI_MODULE != 0
    bool ret = false;
#endif

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
        table_size += offsetof(AOTTableInstance, elems);
        table_size += (uint64)sizeof(uint32)
                      * (uint64)aot_get_imp_tbl_data_slots(
                          module->import_tables + i, false);
    }

    for (i = 0; i != module->table_count; ++i) {
        table_size += offsetof(AOTTableInstance, elems);
        table_size +=
            (uint64)sizeof(uint32)
            * (uint64)aot_get_tbl_data_slots(module->tables + i, false);
    }
    total_size += table_size;

    /* The offset of AOTModuleInstanceExtra, make it 8-byte aligned */
    total_size = (total_size + 7LL) & ~7LL;
    extra_info_offset = (uint32)total_size;
    total_size += sizeof(AOTModuleInstanceExtra);

    /* Allocate module instance, global data, table data and heap data */
    if (!(module_inst =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    module_inst->module_type = Wasm_Module_AoT;
    module_inst->module = (void *)module;
    module_inst->e =
        (WASMModuleInstanceExtra *)((uint8 *)module_inst + extra_info_offset);

#if WASM_ENABLE_MULTI_MODULE != 0
    ((AOTModuleInstanceExtra *)module_inst->e)->sub_module_inst_list =
        &((AOTModuleInstanceExtra *)module_inst->e)->sub_module_inst_list_head;
    ret = wasm_runtime_sub_module_instantiate(
        (WASMModuleCommon *)module, (WASMModuleInstanceCommon *)module_inst,
        stack_size, heap_size, error_buf, error_buf_size);
    if (!ret) {
        LOG_DEBUG("build a sub module list failed");
        goto fail;
    }
#endif

#if WASM_ENABLE_BULK_MEMORY != 0 || WASM_ENABLE_REF_TYPES != 0
    common = &((AOTModuleInstanceExtra *)module_inst->e)->common;
#endif
#if WASM_ENABLE_BULK_MEMORY != 0
    if (module->mem_init_data_count > 0) {
        common->data_dropped = bh_bitmap_new(0, module->mem_init_data_count);
        if (common->data_dropped == NULL) {
            LOG_DEBUG("failed to allocate bitmaps");
            set_error_buf(error_buf, error_buf_size,
                          "failed to allocate bitmaps");
            goto fail;
        }
        for (i = 0; i < module->mem_init_data_count; i++) {
            if (!module->mem_init_data_list[i]->is_passive)
                bh_bitmap_set_bit(common->data_dropped, i);
        }
    }
#endif
#if WASM_ENABLE_REF_TYPES != 0
    if (module->table_init_data_count > 0) {
        common->elem_dropped = bh_bitmap_new(0, module->table_init_data_count);
        if (common->elem_dropped == NULL) {
            LOG_DEBUG("failed to allocate bitmaps");
            set_error_buf(error_buf, error_buf_size,
                          "failed to allocate bitmaps");
            goto fail;
        }
        for (i = 0; i < module->table_init_data_count; i++) {
            if (wasm_elem_is_active(module->table_init_data_list[i]->mode))
                bh_bitmap_set_bit(common->elem_dropped, i);
        }
    }
#endif

    /* Initialize global info */
    p = (uint8 *)module_inst + module_inst_struct_size
        + module_inst_mem_inst_size;
    module_inst->global_data = p;
    module_inst->global_data_size = module->global_data_size;
    if (!global_instantiate(module_inst, module, error_buf, error_buf_size))
        goto fail;

    /* Initialize table info */
    p += module->global_data_size;
    module_inst->table_count = module->table_count + module->import_table_count;
    if (!tables_instantiate(module_inst, module, (AOTTableInstance *)p,
                            error_buf, error_buf_size))
        goto fail;

    /* Initialize memory space */
    if (!memories_instantiate(module_inst, parent, module, heap_size, error_buf,
                              error_buf_size))
        goto fail;

    /* Initialize function pointers */
    if (!init_func_ptrs(module_inst, module, error_buf, error_buf_size))
        goto fail;

    /* Initialize function type indexes */
    if (!init_func_type_indexes(module_inst, module, error_buf, error_buf_size))
        goto fail;

    if (!check_linked_symbol(module, error_buf, error_buf_size))
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

    ((AOTModuleInstanceExtra *)module_inst->e)->stack_sizes =
        aot_get_data_section_addr(module, AOT_STACK_SIZES_SECTION_NAME, NULL);

#if WASM_ENABLE_PERF_PROFILING != 0
    total_size = (uint64)sizeof(AOTFuncPerfProfInfo)
                 * (module->import_func_count + module->func_count);
    if (!(module_inst->func_perf_profilings =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        goto fail;
    }
#endif

#if WASM_ENABLE_DUMP_CALL_STACK != 0
    if (!(module_inst->frames =
              runtime_malloc(sizeof(Vector), error_buf, error_buf_size))) {
        goto fail;
    }
#endif

    if (!execute_post_instantiate_functions(module_inst, is_sub_inst,
                                            exec_env_main)) {
        set_error_buf(error_buf, error_buf_size, module_inst->cur_exception);
        goto fail;
    }

#if WASM_ENABLE_MEMORY_TRACING != 0
    wasm_runtime_dump_module_inst_mem_consumption(
        (WASMModuleInstanceCommon *)module_inst);
#endif

    return module_inst;

fail:
    aot_deinstantiate(module_inst, is_sub_inst);
    return NULL;
}

void
aot_deinstantiate(AOTModuleInstance *module_inst, bool is_sub_inst)
{
    WASMModuleInstanceExtraCommon *common =
        &((AOTModuleInstanceExtra *)module_inst->e)->common;
    if (module_inst->exec_env_singleton) {
        /* wasm_exec_env_destroy will call
           wasm_cluster_wait_for_all_except_self to wait for other
           threads, so as to destroy their exec_envs and module
           instances first, and avoid accessing the shared resources
           of current module instance after it is deinstantiated. */
        wasm_exec_env_destroy((WASMExecEnv *)module_inst->exec_env_singleton);
    }

#if WASM_ENABLE_PERF_PROFILING != 0
    if (module_inst->func_perf_profilings)
        wasm_runtime_free(module_inst->func_perf_profilings);
#endif

#if WASM_ENABLE_DUMP_CALL_STACK != 0
    if (module_inst->frames) {
        bh_vector_destroy(module_inst->frames);
        wasm_runtime_free(module_inst->frames);
        module_inst->frames = NULL;
    }
#endif

#if WASM_ENABLE_MULTI_MODULE != 0
    wasm_runtime_sub_module_deinstantiate(
        (WASMModuleInstanceCommon *)module_inst);
#endif

    if (module_inst->tables)
        wasm_runtime_free(module_inst->tables);

    if (module_inst->memories)
        memories_deinstantiate(module_inst);

    if (module_inst->export_functions)
        wasm_runtime_free(module_inst->export_functions);

    if (module_inst->func_ptrs)
        wasm_runtime_free(module_inst->func_ptrs);

    if (module_inst->func_type_indexes)
        wasm_runtime_free(module_inst->func_type_indexes);

    if (common->c_api_func_imports)
        wasm_runtime_free(((AOTModuleInstanceExtra *)module_inst->e)
                              ->common.c_api_func_imports);

    if (!is_sub_inst) {
#if WASM_ENABLE_WASI_NN != 0
        wasi_nn_destroy(module_inst);
#endif
        wasm_native_call_context_dtors((WASMModuleInstanceCommon *)module_inst);
    }

#if WASM_ENABLE_BULK_MEMORY != 0
    bh_bitmap_delete(common->data_dropped);
#endif
#if WASM_ENABLE_REF_TYPES != 0
    bh_bitmap_delete(common->elem_dropped);
#endif

    wasm_runtime_free(module_inst);
}

AOTFunctionInstance *
aot_lookup_function(const AOTModuleInstance *module_inst, const char *name,
                    const char *signature)
{
    uint32 i;
    AOTFunctionInstance *export_funcs =
        (AOTFunctionInstance *)module_inst->export_functions;

    for (i = 0; i < module_inst->export_func_count; i++)
        if (!strcmp(export_funcs[i].func_name, name))
            return &export_funcs[i];
    (void)signature;
    return NULL;
}

#ifdef OS_ENABLE_HW_BOUND_CHECK
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
#ifdef BH_PLATFORM_WINDOWS
    int result;
    bool has_exception;
    char exception[EXCEPTION_BUF_LEN];
#endif
    bool ret;

    /* Check native stack overflow firstly to ensure we have enough
       native stack to run the following codes before actually calling
       the aot function in invokeNative function. */
    RECORD_STACK_USAGE(exec_env, (uint8 *)&module_inst);
    if ((uint8 *)&module_inst < exec_env->native_stack_boundary
                                    + page_size * (guard_page_count + 1)) {
        aot_set_exception_with_id(module_inst, EXCE_NATIVE_STACK_OVERFLOW);
        return false;
    }

    if (!exec_env_tls) {
        if (!os_thread_signal_inited()) {
            aot_set_exception(module_inst, "thread signal env not inited");
            return false;
        }

        /* Set thread handle and stack boundary if they haven't been set */
        wasm_exec_env_set_thread_info(exec_env);

        wasm_runtime_set_exec_env_tls(exec_env);
    }
    else {
        if (exec_env_tls != exec_env) {
            aot_set_exception(module_inst, "invalid exec env");
            return false;
        }
    }

    wasm_exec_env_push_jmpbuf(exec_env, &jmpbuf_node);

    if (os_setjmp(jmpbuf_node.jmpbuf) == 0) {
#if WASM_ENABLE_QUICK_AOT_ENTRY != 0
        /* Quick call if the quick aot entry is registered */
        if (!signature && func_type->quick_aot_entry) {
            void (*invoke_native)(void *func_ptr, void *exec_env, uint32 *argv,
                                  uint32 *argv_ret) =
                func_type->quick_aot_entry;
            invoke_native(func_ptr, exec_env, argv, argv_ret);
            ret = !aot_copy_exception(module_inst, NULL);
        }
        else
#endif
        {
            ret = wasm_runtime_invoke_native(exec_env, func_ptr, func_type,
                                             signature, attachment, argv, argc,
                                             argv_ret);
        }
#ifdef BH_PLATFORM_WINDOWS
        has_exception = aot_copy_exception(module_inst, exception);
        if (has_exception && strstr(exception, "native stack overflow")) {
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
#define invoke_native_internal invoke_native_with_hw_bound_check /* NOLINT */
#else /* else of OS_ENABLE_HW_BOUND_CHECK */
static inline bool
invoke_native_internal(WASMExecEnv *exec_env, void *func_ptr,
                       const WASMType *func_type, const char *signature,
                       void *attachment, uint32 *argv, uint32 argc,
                       uint32 *argv_ret)
{
#if WASM_ENABLE_QUICK_AOT_ENTRY != 0
    /* Quick call if the quick aot entry is registered */
    if (!signature && func_type->quick_aot_entry) {
        AOTModuleInstance *module_inst =
            (AOTModuleInstance *)exec_env->module_inst;
        void (*invoke_native)(void *func_ptr, void *exec_env, uint32 *argv,
                              uint32 *argv_ret) = func_type->quick_aot_entry;
        invoke_native(func_ptr, exec_env, argv, argv_ret);
        return !aot_copy_exception(module_inst, NULL);
    }
#endif
    return wasm_runtime_invoke_native(exec_env, func_ptr, func_type, signature,
                                      attachment, argv, argc, argv_ret);
}
#endif /* end of OS_ENABLE_HW_BOUND_CHECK */

bool
aot_call_function(WASMExecEnv *exec_env, AOTFunctionInstance *function,
                  unsigned argc, uint32 argv[])
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTFuncType *func_type = function->is_import_func
                                 ? function->u.func_import->func_type
                                 : function->u.func.func_type;
    uint32 result_count = func_type->result_count;
    uint32 ext_ret_count = result_count > 1 ? result_count - 1 : 0;
    bool ret;
    void *func_ptr = function->is_import_func
                         ? function->u.func_import->func_ptr_linked
                         : function->u.func.func_ptr;
#if WASM_ENABLE_MULTI_MODULE != 0
    bh_list *sub_module_list_node = NULL;
    const char *sub_inst_name = NULL;
    const char *func_name = function->u.func_import->module_name;
    if (function->is_import_func) {
        sub_module_list_node =
            ((AOTModuleInstanceExtra *)module_inst->e)->sub_module_inst_list;
        sub_module_list_node = bh_list_first_elem(sub_module_list_node);
        while (sub_module_list_node) {
            sub_inst_name =
                ((AOTSubModInstNode *)sub_module_list_node)->module_name;
            if (strcmp(sub_inst_name, func_name) == 0) {
                exec_env = wasm_runtime_get_exec_env_singleton(
                    (WASMModuleInstanceCommon *)((AOTSubModInstNode *)
                                                     sub_module_list_node)
                        ->module_inst);
                module_inst = (AOTModuleInstance *)exec_env->module_inst;
                break;
            }
            sub_module_list_node = bh_list_elem_next(sub_module_list_node);
        }
        if (exec_env == NULL) {
            wasm_runtime_set_exception((WASMModuleInstanceCommon *)module_inst,
                                       "create singleton exec_env failed");
            return false;
        }
    }
#endif

    if (argc < func_type->param_cell_num) {
        char buf[108];
        snprintf(buf, sizeof(buf),
                 "invalid argument count %u, must be no smaller than %u", argc,
                 func_type->param_cell_num);
        aot_set_exception(module_inst, buf);
        return false;
    }
    argc = func_type->param_cell_num;

#if defined(os_writegsbase)
    {
        AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
        if (memory_inst)
            /* write base addr of linear memory to GS segment register */
            os_writegsbase(memory_inst->memory_data);
    }
#endif

    /* func pointer was looked up previously */
    bh_assert(func_ptr != NULL);

#ifndef OS_ENABLE_HW_BOUND_CHECK
    /* Set thread handle and stack boundary */
    wasm_exec_env_set_thread_info(exec_env);
#else
    /* Set thread info in invoke_native_with_hw_bound_check when
       hw bound check is enabled */
#endif

    /* Set exec env so it can be later retrieved from instance */
    ((AOTModuleInstanceExtra *)module_inst->e)->common.cur_exec_env = exec_env;

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

        ret = invoke_native_internal(exec_env, func_ptr, func_type, NULL, NULL,
                                     argv, argc, argv);

#if WASM_ENABLE_DUMP_CALL_STACK != 0
        if (aot_copy_exception(module_inst, NULL)) {
            if (aot_create_call_stack(exec_env)) {
                aot_dump_call_stack(exec_env, true, NULL, 0);
            }
        }
#endif

#if (WASM_ENABLE_DUMP_CALL_STACK != 0) || (WASM_ENABLE_PERF_PROFILING != 0)
        aot_free_frame(exec_env);
#endif

        return ret && !aot_copy_exception(module_inst, NULL) ? true : false;
    }
}

void
aot_set_exception(AOTModuleInstance *module_inst, const char *exception)
{
    wasm_set_exception(module_inst, exception);
}

void
aot_set_exception_with_id(AOTModuleInstance *module_inst, uint32 id)
{
    if (id != EXCE_ALREADY_THROWN)
        wasm_set_exception_with_id(module_inst, id);
#ifdef OS_ENABLE_HW_BOUND_CHECK
    wasm_runtime_access_exce_check_guard_page();
#endif
}

const char *
aot_get_exception(AOTModuleInstance *module_inst)
{
    return wasm_get_exception(module_inst);
}

bool
aot_copy_exception(AOTModuleInstance *module_inst, char *exception_buf)
{
    /* The field offsets of cur_exception in AOTModuleInstance and
       WASMModuleInstance are the same */
    return wasm_copy_exception(module_inst, exception_buf);
}

static bool
execute_malloc_function(AOTModuleInstance *module_inst, WASMExecEnv *exec_env,
                        AOTFunctionInstance *malloc_func,
                        AOTFunctionInstance *retain_func, uint32 size,
                        uint32 *p_result)
{
#ifdef OS_ENABLE_HW_BOUND_CHECK
    WASMExecEnv *exec_env_tls = wasm_runtime_get_exec_env_tls();
#endif
    WASMExecEnv *exec_env_created = NULL;
    WASMModuleInstanceCommon *module_inst_old = NULL;
    uint32 argv[2], argc;
    bool ret;

    argv[0] = size;
    argc = 1;
    if (retain_func) {
        argv[1] = 0;
        argc = 2;
    }

    if (exec_env) {
#ifdef OS_ENABLE_HW_BOUND_CHECK
        if (exec_env_tls) {
            bh_assert(exec_env_tls == exec_env);
        }
#endif
        bh_assert(exec_env->module_inst
                  == (WASMModuleInstanceCommon *)module_inst);
    }
    else {
        /* Try using the existing exec_env */
#ifdef OS_ENABLE_HW_BOUND_CHECK
        exec_env = exec_env_tls;
#endif
#if WASM_ENABLE_THREAD_MGR != 0
        if (!exec_env)
            exec_env = wasm_clusters_search_exec_env(
                (WASMModuleInstanceCommon *)module_inst);
#endif
        if (!exec_env) {
            if (!(exec_env = exec_env_created = wasm_exec_env_create(
                      (WASMModuleInstanceCommon *)module_inst,
                      module_inst->default_wasm_stack_size))) {
                wasm_set_exception(module_inst, "allocate memory failed");
                return false;
            }
        }
        else {
            /* Temporarily replace exec_env's module inst with current
               module inst to ensure that the exec_env's module inst
               is the correct one. */
            module_inst_old = exec_env->module_inst;
            wasm_exec_env_set_module_inst(
                exec_env, (WASMModuleInstanceCommon *)module_inst);
        }
    }

    ret = aot_call_function(exec_env, malloc_func, argc, argv);

    if (retain_func && ret)
        ret = aot_call_function(exec_env, retain_func, 1, argv);

    if (module_inst_old)
        /* Restore the existing exec_env's module inst */
        wasm_exec_env_restore_module_inst(exec_env, module_inst_old);

    if (exec_env_created)
        wasm_exec_env_destroy(exec_env_created);

    if (ret)
        *p_result = argv[0];
    return ret;
}

static bool
execute_free_function(AOTModuleInstance *module_inst, WASMExecEnv *exec_env,
                      AOTFunctionInstance *free_func, uint32 offset)
{
#ifdef OS_ENABLE_HW_BOUND_CHECK
    WASMExecEnv *exec_env_tls = wasm_runtime_get_exec_env_tls();
#endif
    WASMExecEnv *exec_env_created = NULL;
    WASMModuleInstanceCommon *module_inst_old = NULL;
    uint32 argv[2];
    bool ret;

    argv[0] = offset;

    if (exec_env) {
#ifdef OS_ENABLE_HW_BOUND_CHECK
        if (exec_env_tls) {
            bh_assert(exec_env_tls == exec_env);
        }
#endif
        bh_assert(exec_env->module_inst
                  == (WASMModuleInstanceCommon *)module_inst);
    }
    else {
        /* Try using the existing exec_env */
#ifdef OS_ENABLE_HW_BOUND_CHECK
        exec_env = exec_env_tls;
#endif
#if WASM_ENABLE_THREAD_MGR != 0
        if (!exec_env)
            exec_env = wasm_clusters_search_exec_env(
                (WASMModuleInstanceCommon *)module_inst);
#endif
        if (!exec_env) {
            if (!(exec_env = exec_env_created = wasm_exec_env_create(
                      (WASMModuleInstanceCommon *)module_inst,
                      module_inst->default_wasm_stack_size))) {
                wasm_set_exception(module_inst, "allocate memory failed");
                return false;
            }
        }
        else {
            /* Temporarily replace exec_env's module inst with current
               module inst to ensure that the exec_env's module inst
               is the correct one. */
            module_inst_old = exec_env->module_inst;
            wasm_exec_env_set_module_inst(
                exec_env, (WASMModuleInstanceCommon *)module_inst);
        }
    }

    ret = aot_call_function(exec_env, free_func, 1, argv);

    if (module_inst_old)
        /* Restore the existing exec_env's module inst */
        wasm_exec_env_restore_module_inst(exec_env, module_inst_old);

    if (exec_env_created)
        wasm_exec_env_destroy(exec_env_created);

    return ret;
}

uint32
aot_module_malloc_internal(AOTModuleInstance *module_inst,
                           WASMExecEnv *exec_env, uint32 size,
                           void **p_native_addr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    AOTModule *module = (AOTModule *)module_inst->module;
    uint8 *addr = NULL;
    uint32 offset = 0;

    if (!memory_inst) {
        aot_set_exception(module_inst, "uninitialized memory");
        return 0;
    }

    if (memory_inst->heap_handle) {
        addr = mem_allocator_malloc(memory_inst->heap_handle, size);
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
            || !execute_malloc_function(module_inst, exec_env, malloc_func,
                                        retain_func, size, &offset)) {
            return 0;
        }
        addr = offset ? (uint8 *)memory_inst->memory_data + offset : NULL;
    }

    if (!addr) {
        if (memory_inst->heap_handle
            && mem_allocator_is_heap_corrupted(memory_inst->heap_handle)) {
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
    return (uint32)(addr - memory_inst->memory_data);
}

uint32
aot_module_realloc_internal(AOTModuleInstance *module_inst,
                            WASMExecEnv *exec_env, uint32 ptr, uint32 size,
                            void **p_native_addr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    uint8 *addr = NULL;

    if (!memory_inst) {
        aot_set_exception(module_inst, "uninitialized memory");
        return 0;
    }

    if (memory_inst->heap_handle) {
        addr = mem_allocator_realloc(
            memory_inst->heap_handle,
            ptr ? memory_inst->memory_data + ptr : NULL, size);
    }

    /* Only support realloc in WAMR's app heap */
    (void)exec_env;

    if (!addr) {
        if (memory_inst->heap_handle
            && mem_allocator_is_heap_corrupted(memory_inst->heap_handle)) {
            aot_set_exception(module_inst, "app heap corrupted");
        }
        else {
            aot_set_exception(module_inst, "out of memory");
        }
        return 0;
    }

    if (p_native_addr)
        *p_native_addr = addr;
    return (uint32)(addr - memory_inst->memory_data);
}

void
aot_module_free_internal(AOTModuleInstance *module_inst, WASMExecEnv *exec_env,
                         uint32 ptr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    AOTModule *module = (AOTModule *)module_inst->module;

    if (!memory_inst) {
        return;
    }

    if (ptr) {
        uint8 *addr = memory_inst->memory_data + ptr;
        uint8 *memory_data_end;

        /* memory->memory_data_end may be changed in memory grow */
        SHARED_MEMORY_LOCK(memory_inst);
        memory_data_end = memory_inst->memory_data_end;
        SHARED_MEMORY_UNLOCK(memory_inst);

        if (memory_inst->heap_handle && memory_inst->heap_data < addr
            && addr < memory_inst->heap_data_end) {
            mem_allocator_free(memory_inst->heap_handle, addr);
        }
        else if (module->malloc_func_index != (uint32)-1
                 && module->free_func_index != (uint32)-1
                 && memory_inst->memory_data <= addr
                 && addr < memory_data_end) {
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
                execute_free_function(module_inst, exec_env, free_func, ptr);
        }
    }
}

uint32
aot_module_malloc(AOTModuleInstance *module_inst, uint32 size,
                  void **p_native_addr)
{
    return aot_module_malloc_internal(module_inst, NULL, size, p_native_addr);
}

uint32
aot_module_realloc(AOTModuleInstance *module_inst, uint32 ptr, uint32 size,
                   void **p_native_addr)
{
    return aot_module_realloc_internal(module_inst, NULL, ptr, size,
                                       p_native_addr);
}

void
aot_module_free(AOTModuleInstance *module_inst, uint32 ptr)
{
    aot_module_free_internal(module_inst, NULL, ptr);
}

uint32
aot_module_dup_data(AOTModuleInstance *module_inst, const char *src,
                    uint32 size)
{
    char *buffer;
    uint32 buffer_offset =
        aot_module_malloc(module_inst, size, (void **)&buffer);

    if (buffer_offset != 0) {
        buffer = wasm_runtime_addr_app_to_native(
            (WASMModuleInstanceCommon *)module_inst, buffer_offset);
        bh_memcpy_s(buffer, size, src, size);
    }
    return buffer_offset;
}

bool
aot_enlarge_memory(AOTModuleInstance *module_inst, uint32 inc_page_count)
{
    return wasm_enlarge_memory(module_inst, inc_page_count);
}

bool
aot_invoke_native(WASMExecEnv *exec_env, uint32 func_idx, uint32 argc,
                  uint32 *argv)
{
    AOTModuleInstance *module_inst =
        (AOTModuleInstance *)wasm_runtime_get_module_inst(exec_env);
    AOTModule *aot_module = (AOTModule *)module_inst->module;
    AOTModuleInstanceExtra *module_inst_extra =
        (AOTModuleInstanceExtra *)module_inst->e;
    CApiFuncImport *c_api_func_import =
        module_inst_extra->common.c_api_func_imports
            ? module_inst_extra->common.c_api_func_imports + func_idx
            : NULL;
    uint32 *func_type_indexes = module_inst->func_type_indexes;
    uint32 func_type_idx = func_type_indexes[func_idx];
    AOTFuncType *func_type = aot_module->func_types[func_type_idx];
    void **func_ptrs = module_inst->func_ptrs;
    void *func_ptr = func_ptrs[func_idx];
    AOTImportFunc *import_func;
    const char *signature;
    void *attachment;
    char buf[96];
    bool ret = false;
#if WASM_ENABLE_MULTI_MODULE != 0
    bh_list *sub_module_list_node = NULL;
    const char *sub_inst_name = NULL;
#endif
    bh_assert(func_idx < aot_module->import_func_count);

    import_func = aot_module->import_funcs + func_idx;
    if (import_func->call_conv_wasm_c_api)
        func_ptr =
            c_api_func_import ? c_api_func_import->func_ptr_linked : NULL;

    if (!func_ptr) {
        snprintf(buf, sizeof(buf),
                 "failed to call unlinked import function (%s, %s)",
                 import_func->module_name, import_func->func_name);
        aot_set_exception(module_inst, buf);
        goto fail;
    }

    attachment = import_func->attachment;
    if (import_func->call_conv_wasm_c_api) {
        ret = wasm_runtime_invoke_c_api_native(
            (WASMModuleInstanceCommon *)module_inst, func_ptr, func_type, argc,
            argv, c_api_func_import->with_env_arg, c_api_func_import->env_arg);
    }
    else if (!import_func->call_conv_raw) {
        signature = import_func->signature;
#if WASM_ENABLE_MULTI_MODULE != 0
        sub_module_list_node =
            ((AOTModuleInstanceExtra *)module_inst->e)->sub_module_inst_list;
        sub_module_list_node = bh_list_first_elem(sub_module_list_node);
        while (sub_module_list_node) {
            sub_inst_name =
                ((AOTSubModInstNode *)sub_module_list_node)->module_name;
            if (strcmp(sub_inst_name, import_func->module_name) == 0) {
                exec_env = wasm_runtime_get_exec_env_singleton(
                    (WASMModuleInstanceCommon *)((AOTSubModInstNode *)
                                                     sub_module_list_node)
                        ->module_inst);
                break;
            }
            sub_module_list_node = bh_list_elem_next(sub_module_list_node);
        }
        if (exec_env == NULL) {
            wasm_runtime_set_exception((WASMModuleInstanceCommon *)module_inst,
                                       "create singleton exec_env failed");
            goto fail;
        }
#endif
        ret =
            wasm_runtime_invoke_native(exec_env, func_ptr, func_type, signature,
                                       attachment, argv, argc, argv);
    }
    else {
        signature = import_func->signature;
        ret = wasm_runtime_invoke_native_raw(exec_env, func_ptr, func_type,
                                             signature, attachment, argv, argc,
                                             argv);
    }

fail:
#ifdef OS_ENABLE_HW_BOUND_CHECK
    if (!ret)
        wasm_runtime_access_exce_check_guard_page();
#endif
    return ret;
}

bool
aot_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 table_elem_idx,
                  uint32 argc, uint32 *argv)
{
    AOTModuleInstance *module_inst =
        (AOTModuleInstance *)wasm_runtime_get_module_inst(exec_env);
    AOTModule *aot_module = (AOTModule *)module_inst->module;
    uint32 *func_type_indexes = module_inst->func_type_indexes;
    AOTTableInstance *tbl_inst;
    AOTFuncType *func_type;
    void **func_ptrs = module_inst->func_ptrs, *func_ptr;
    uint32 func_type_idx, func_idx, ext_ret_count;
    AOTImportFunc *import_func;
    const char *signature = NULL;
    void *attachment = NULL;
    char buf[96];
    bool ret;

    /* this function is called from native code, so exec_env->handle and
       exec_env->native_stack_boundary must have been set, we don't set
       it again */

    RECORD_STACK_USAGE(exec_env, (uint8 *)&module_inst);
    if ((uint8 *)&module_inst < exec_env->native_stack_boundary) {
        aot_set_exception_with_id(module_inst, EXCE_NATIVE_STACK_OVERFLOW);
        goto fail;
    }

    tbl_inst = module_inst->tables[tbl_idx];
    bh_assert(tbl_inst);

    if (table_elem_idx >= tbl_inst->cur_size) {
        aot_set_exception_with_id(module_inst, EXCE_UNDEFINED_ELEMENT);
        goto fail;
    }

    func_idx = tbl_inst->elems[table_elem_idx];
    if (func_idx == NULL_REF) {
        aot_set_exception_with_id(module_inst, EXCE_UNINITIALIZED_ELEMENT);
        goto fail;
    }

    func_type_idx = func_type_indexes[func_idx];
    func_type = aot_module->func_types[func_type_idx];

    if (func_idx >= aot_module->import_func_count) {
        /* func pointer was looked up previously */
        bh_assert(func_ptrs[func_idx] != NULL);
    }

    if (!(func_ptr = func_ptrs[func_idx])) {
        bh_assert(func_idx < aot_module->import_func_count);
        import_func = aot_module->import_funcs + func_idx;
        snprintf(buf, sizeof(buf),
                 "failed to call unlinked import function (%s, %s)",
                 import_func->module_name, import_func->func_name);
        aot_set_exception(module_inst, buf);
        goto fail;
    }

    if (func_idx < aot_module->import_func_count) {
        /* Call native function */
        import_func = aot_module->import_funcs + func_idx;
        signature = import_func->signature;
        if (import_func->call_conv_raw) {
            attachment = import_func->attachment;
            ret = wasm_runtime_invoke_native_raw(exec_env, func_ptr, func_type,
                                                 signature, attachment, argv,
                                                 argc, argv);
            if (!ret)
                goto fail;

            return true;
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
            goto fail;
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
        if (!ret) {
            if (argv1 != argv1_buf)
                wasm_runtime_free(argv1);
            goto fail;
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
        if (!ret)
            goto fail;

        return true;
    }

fail:
#ifdef OS_ENABLE_HW_BOUND_CHECK
    wasm_runtime_access_exce_check_guard_page();
#endif
    return false;
}

bool
aot_check_app_addr_and_convert(AOTModuleInstance *module_inst, bool is_str,
                               uint32 app_buf_addr, uint32 app_buf_size,
                               void **p_native_addr)
{
    bool ret;

    ret = wasm_check_app_addr_and_convert(module_inst, is_str, app_buf_addr,
                                          app_buf_size, p_native_addr);

#ifdef OS_ENABLE_HW_BOUND_CHECK
    if (!ret)
        wasm_runtime_access_exce_check_guard_page();
#endif

    return ret;
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

double
aot_sqrt(double x)
{
    return sqrt(x);
}

float
aot_sqrtf(float x)
{
    return sqrtf(x);
}

#if WASM_ENABLE_BULK_MEMORY != 0
bool
aot_memory_init(AOTModuleInstance *module_inst, uint32 seg_index, uint32 offset,
                uint32 len, uint32 dst)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    AOTModule *aot_module;
    uint8 *data;
    uint8 *maddr;
    uint64 seg_len;

    if (bh_bitmap_get_bit(
            ((AOTModuleInstanceExtra *)module_inst->e)->common.data_dropped,
            seg_index)) {
        seg_len = 0;
        data = NULL;
    }
    else {
        aot_module = (AOTModule *)module_inst->module;
        seg_len = aot_module->mem_init_data_list[seg_index]->byte_count;
        data = aot_module->mem_init_data_list[seg_index]->bytes;
    }

    if (!wasm_runtime_validate_app_addr((WASMModuleInstanceCommon *)module_inst,
                                        dst, len))
        return false;

    if ((uint64)offset + (uint64)len > seg_len) {
        aot_set_exception(module_inst, "out of bounds memory access");
        return false;
    }

    maddr = wasm_runtime_addr_app_to_native(
        (WASMModuleInstanceCommon *)module_inst, dst);

    SHARED_MEMORY_LOCK(memory_inst);
    bh_memcpy_s(maddr, memory_inst->memory_data_size - dst, data + offset, len);
    SHARED_MEMORY_UNLOCK(memory_inst);
    return true;
}

bool
aot_data_drop(AOTModuleInstance *module_inst, uint32 seg_index)
{
    bh_bitmap_set_bit(
        ((AOTModuleInstanceExtra *)module_inst->e)->common.data_dropped,
        seg_index);
    /* Currently we can't free the dropped data segment
       as the mem_init_data_count is a continuous array */
    return true;
}
#endif /* WASM_ENABLE_BULK_MEMORY */

#if WASM_ENABLE_THREAD_MGR != 0
bool
aot_set_aux_stack(WASMExecEnv *exec_env, uint32 start_offset, uint32 size)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTModule *module = (AOTModule *)module_inst->module;

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
        uint8 *global_addr = module_inst->global_data + global_offset;
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
    AOTModule *module = (AOTModule *)module_inst->module;

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
        sizeof(void *) * module_inst->memory_count
        + sizeof(AOTMemoryInstance) * module_inst->memory_count;
    for (i = 0; i < module_inst->memory_count; i++) {
        AOTMemoryInstance *mem_inst = module_inst->memories[i];
        mem_conspn->memories_size +=
            mem_inst->num_bytes_per_page * mem_inst->cur_page_count;
        mem_conspn->app_heap_size =
            mem_inst->heap_data_end - mem_inst->heap_data;
        /* size of app heap structure */
        mem_conspn->memories_size += mem_allocator_get_heap_struct_size();
    }

    mem_conspn->tables_size +=
        sizeof(AOTTableInstance *) * module_inst->table_count;
    for (i = 0; i < module_inst->table_count; i++) {
        tbl_inst = module_inst->tables[i];
        mem_conspn->tables_size += offsetof(AOTTableInstance, elems);
        mem_conspn->tables_size += sizeof(uint32) * tbl_inst->max_size;
    }

    /* func_ptrs and func_type_indexes */
    mem_conspn->functions_size =
        (sizeof(void *) + sizeof(uint32))
        * (((AOTModule *)module_inst->module)->import_func_count
           + ((AOTModule *)module_inst->module)->func_count);

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
    bh_bitmap_set_bit(
        ((AOTModuleInstanceExtra *)module_inst->e)->common.elem_dropped,
        tbl_seg_idx);
}

void
aot_table_init(AOTModuleInstance *module_inst, uint32 tbl_idx,
               uint32 tbl_seg_idx, uint32 length, uint32 src_offset,
               uint32 dst_offset)
{
    AOTTableInstance *tbl_inst;
    AOTTableInitData *tbl_seg;
    uint32 *tbl_seg_elems = NULL, tbl_seg_len = 0;
    const AOTModule *module = (AOTModule *)module_inst->module;

    tbl_inst = module_inst->tables[tbl_idx];
    bh_assert(tbl_inst);

    tbl_seg = module->table_init_data_list[tbl_seg_idx];
    bh_assert(tbl_seg);

    if (!bh_bitmap_get_bit(
            ((AOTModuleInstanceExtra *)module_inst->e)->common.elem_dropped,
            tbl_seg_idx)) {
        /* table segment isn't dropped */
        tbl_seg_elems = tbl_seg->func_indexes;
        tbl_seg_len = tbl_seg->func_index_count;
    }

    if (offset_len_out_of_bounds(src_offset, length, tbl_seg_len)
        || offset_len_out_of_bounds(dst_offset, length, tbl_inst->cur_size)) {
        aot_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    if (!length) {
        return;
    }

    bh_memcpy_s((uint8 *)tbl_inst + offsetof(AOTTableInstance, elems)
                    + dst_offset * sizeof(uint32),
                (tbl_inst->cur_size - dst_offset) * sizeof(uint32),
                tbl_seg_elems + src_offset, length * sizeof(uint32));
}

void
aot_table_copy(AOTModuleInstance *module_inst, uint32 src_tbl_idx,
               uint32 dst_tbl_idx, uint32 length, uint32 src_offset,
               uint32 dst_offset)
{
    AOTTableInstance *src_tbl_inst, *dst_tbl_inst;

    src_tbl_inst = module_inst->tables[src_tbl_idx];
    bh_assert(src_tbl_inst);

    dst_tbl_inst = module_inst->tables[dst_tbl_idx];
    bh_assert(dst_tbl_inst);

    if (offset_len_out_of_bounds(dst_offset, length, dst_tbl_inst->cur_size)
        || offset_len_out_of_bounds(src_offset, length,
                                    src_tbl_inst->cur_size)) {
        aot_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    /* if src_offset >= dst_offset, copy from front to back */
    /* if src_offset < dst_offset, copy from back to front */
    /* merge all together */
    bh_memmove_s((uint8 *)dst_tbl_inst + offsetof(AOTTableInstance, elems)
                     + dst_offset * sizeof(uint32),
                 (dst_tbl_inst->cur_size - dst_offset) * sizeof(uint32),
                 (uint8 *)src_tbl_inst + offsetof(AOTTableInstance, elems)
                     + src_offset * sizeof(uint32),
                 length * sizeof(uint32));
}

void
aot_table_fill(AOTModuleInstance *module_inst, uint32 tbl_idx, uint32 length,
               uint32 val, uint32 data_offset)
{
    AOTTableInstance *tbl_inst;

    tbl_inst = module_inst->tables[tbl_idx];
    bh_assert(tbl_inst);

    if (offset_len_out_of_bounds(data_offset, length, tbl_inst->cur_size)) {
        aot_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    for (; length != 0; data_offset++, length--) {
        tbl_inst->elems[data_offset] = val;
    }
}

uint32
aot_table_grow(AOTModuleInstance *module_inst, uint32 tbl_idx,
               uint32 inc_entries, uint32 init_val)
{
    uint32 entry_count, i, orig_tbl_sz;
    AOTTableInstance *tbl_inst;

    tbl_inst = module_inst->tables[tbl_idx];
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
        tbl_inst->elems[tbl_inst->cur_size + i] = init_val;
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
    AOTModule *module = (AOTModule *)module_inst->module;

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
        module_inst->func_perf_profilings + func_index;
#endif

    if (!frame) {
        aot_set_exception((AOTModuleInstance *)exec_env->module_inst,
                          "auxiliary call stack overflow");
        return false;
    }

#if WASM_ENABLE_PERF_PROFILING != 0
    frame->time_started = os_time_thread_cputime_us();
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
    uint64 elapsed = os_time_thread_cputime_us() - cur_frame->time_started;
    cur_frame->func_perf_prof_info->total_exec_time += elapsed;
    cur_frame->func_perf_prof_info->total_exec_cnt++;

    /* parent function */
    if (prev_frame)
        prev_frame->func_perf_prof_info->children_exec_time += elapsed;
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
    if (!bh_vector_destroy(module_inst->frames)
        || !bh_vector_init(module_inst->frames, n, sizeof(WASMCApiFrame),
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

        if (!bh_vector_append(module_inst->frames, &frame)) {
            bh_vector_destroy(module_inst->frames);
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
            exception_unlock(module_inst);                                \
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

    if (!module_inst->frames) {
        return 0;
    }

    total_frames = (uint32)bh_vector_size(module_inst->frames);
    if (total_frames == 0) {
        return 0;
    }

    exception_lock(module_inst);
    snprintf(line_buf, sizeof(line_buf), "\n");
    PRINT_OR_DUMP();

    while (n < total_frames) {
        WASMCApiFrame frame = { 0 };
        uint32 line_length, i;

        if (!bh_vector_get(module_inst->frames, n, &frame)) {
            exception_unlock(module_inst);
            return 0;
        }

        /* function name not exported, print number instead */
        if (frame.func_name_wp == NULL) {
            line_length =
                snprintf(line_buf, sizeof(line_buf),
                         "#%02" PRIu32 " $f%" PRIu32 "\n", n, frame.func_index);
        }
        else {
            line_length =
                snprintf(line_buf, sizeof(line_buf), "#%02" PRIu32 " %s\n", n,
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
    exception_unlock(module_inst);

    return total_len + 1;
}
#endif /* end of WASM_ENABLE_DUMP_CALL_STACK */

#if WASM_ENABLE_PERF_PROFILING != 0
void
aot_dump_perf_profiling(const AOTModuleInstance *module_inst)
{
    AOTFuncPerfProfInfo *perf_prof =
        (AOTFuncPerfProfInfo *)module_inst->func_perf_profilings;
    AOTModule *module = (AOTModule *)module_inst->module;
    uint32 total_func_count = module->import_func_count + module->func_count, i;
    const char *func_name;

    os_printf("Performance profiler data:\n");
    for (i = 0; i < total_func_count; i++, perf_prof++) {
        if (perf_prof->total_exec_cnt == 0)
            continue;

        func_name = get_func_name_from_index(module_inst, i);

        if (func_name)
            os_printf(
                "  func %s, execution time: %.3f ms, execution count: %" PRIu32
                " times, children execution time: %.3f ms\n",
                func_name, perf_prof->total_exec_time / 1000.0f,
                perf_prof->total_exec_cnt,
                perf_prof->children_exec_time / 1000.0f);
        else
            os_printf("  func %" PRIu32
                      ", execution time: %.3f ms, execution count: %" PRIu32
                      " times, children execution time: %.3f ms\n",
                      i, perf_prof->total_exec_time / 1000.0f,
                      perf_prof->total_exec_cnt,
                      perf_prof->children_exec_time / 1000.0f);
    }
}

double
aot_summarize_wasm_execute_time(const AOTModuleInstance *inst)
{
    double ret = 0;

    AOTModule *module = (AOTModule *)inst->module;
    uint32 total_func_count = module->import_func_count + module->func_count, i;

    for (i = 0; i < total_func_count; i++) {
        AOTFuncPerfProfInfo *perf_prof =
            (AOTFuncPerfProfInfo *)inst->func_perf_profilings + i;
        ret += (perf_prof->total_exec_time - perf_prof->children_exec_time)
               / 1000.0f;
    }

    return ret;
}

double
aot_get_wasm_func_exec_time(const AOTModuleInstance *inst,
                            const char *func_name)
{
    AOTModule *module = (AOTModule *)inst->module;
    uint32 total_func_count = module->import_func_count + module->func_count, i;

    for (i = 0; i < total_func_count; i++) {
        const char *name_in_wasm = get_func_name_from_index(inst, i);
        if (name_in_wasm && strcmp(func_name, name_in_wasm) == 0) {
            AOTFuncPerfProfInfo *perf_prof =
                (AOTFuncPerfProfInfo *)inst->func_perf_profilings + i;
            return (perf_prof->total_exec_time - perf_prof->children_exec_time)
                   / 1000.0f;
        }
    }

    return -1.0;
}
#endif /* end of WASM_ENABLE_PERF_PROFILING */

#if WASM_ENABLE_STATIC_PGO != 0

/* indirect call target */
#define IPVK_IndirectCallTarget 0
/* memory intrinsic functions size */
#define IPVK_MemOPSize 1
#define IPVK_First IPVK_IndirectCallTarget
#define IPVK_Last IPVK_MemOPSize

#define INSTR_PROF_DEFAULT_NUM_VAL_PER_SITE 24
#define INSTR_PROF_MAX_NUM_VAL_PER_SITE 255

static int hasNonDefaultValsPerSite = 0;
static uint32 VPMaxNumValsPerSite = INSTR_PROF_DEFAULT_NUM_VAL_PER_SITE;

static bool
cmpxchg_ptr(void **ptr, void *old_val, void *new_val)
{
#if defined(os_atomic_cmpxchg)
    return os_atomic_cmpxchg(ptr, &old_val, new_val);
#else
    /* TODO: add lock when thread-manager is enabled */
    void *read = *ptr;
    if (read == old_val) {
        *ptr = new_val;
        return true;
    }
    return false;
#endif
}

static int
allocateValueProfileCounters(LLVMProfileData *Data)
{
    ValueProfNode **Mem;
    uint64 NumVSites = 0, total_size;
    uint32 VKI;

    /* When dynamic allocation is enabled, allow tracking the max number of
       values allowed. */
    if (!hasNonDefaultValsPerSite)
        VPMaxNumValsPerSite = INSTR_PROF_MAX_NUM_VAL_PER_SITE;

    for (VKI = IPVK_First; VKI <= IPVK_Last; ++VKI)
        NumVSites += Data->num_value_sites[VKI];

    /* If NumVSites = 0, calloc is allowed to return a non-null pointer. */
    bh_assert(NumVSites > 0 && "NumVSites can't be zero");

    total_size = (uint64)sizeof(ValueProfNode *) * NumVSites;
    if (total_size > UINT32_MAX
        || !(Mem = (ValueProfNode **)wasm_runtime_malloc((uint32)total_size))) {
        return 0;
    }
    memset(Mem, 0, (uint32)total_size);

    if (!cmpxchg_ptr((void **)&Data->values, NULL, Mem)) {
        wasm_runtime_free(Mem);
        return 0;
    }
    return 1;
}

static ValueProfNode *
allocateOneNode(void)
{
    ValueProfNode *Node;

    Node = wasm_runtime_malloc((uint32)sizeof(ValueProfNode));
    if (Node)
        memset(Node, 0, sizeof(ValueProfNode));
    return Node;
}

static void
instrumentTargetValueImpl(uint64 TargetValue, void *Data, uint32 CounterIndex,
                          uint64 CountValue)
{
    ValueProfNode **ValueCounters;
    ValueProfNode *PrevVNode = NULL, *MinCountVNode = NULL, *CurVNode;
    LLVMProfileData *PData = (LLVMProfileData *)Data;
    uint64 MinCount = UINT64_MAX;
    uint8 VDataCount = 0;
    bool success = false;

    if (!PData)
        return;
    if (!CountValue)
        return;
    if (!PData->values) {
        if (!allocateValueProfileCounters(PData))
            return;
    }

    ValueCounters = (ValueProfNode **)PData->values;
    CurVNode = ValueCounters[CounterIndex];

    while (CurVNode) {
        if (TargetValue == CurVNode->value) {
            CurVNode->count += CountValue;
            return;
        }
        if (CurVNode->count < MinCount) {
            MinCount = CurVNode->count;
            MinCountVNode = CurVNode;
        }
        PrevVNode = CurVNode;
        CurVNode = CurVNode->next;
        ++VDataCount;
    }

    if (VDataCount >= VPMaxNumValsPerSite) {
        if (MinCountVNode->count <= CountValue) {
            CurVNode = MinCountVNode;
            CurVNode->value = TargetValue;
            CurVNode->count = CountValue;
        }
        else
            MinCountVNode->count -= CountValue;

        return;
    }

    CurVNode = allocateOneNode();
    if (!CurVNode)
        return;
    CurVNode->value = TargetValue;
    CurVNode->count += CountValue;

    if (!ValueCounters[CounterIndex]) {
        success =
            cmpxchg_ptr((void **)&ValueCounters[CounterIndex], NULL, CurVNode);
    }
    else if (PrevVNode && !PrevVNode->next) {
        success = cmpxchg_ptr((void **)&PrevVNode->next, 0, CurVNode);
    }

    if (!success) {
        wasm_runtime_free(CurVNode);
    }
}

void
llvm_profile_instrument_target(uint64 target_value, void *data,
                               uint32 counter_idx)
{
    instrumentTargetValueImpl(target_value, data, counter_idx, 1);
}

static inline uint32
popcount64(uint64 u)
{
    uint32 ret = 0;
    while (u) {
        u = (u & (u - 1));
        ret++;
    }
    return ret;
}

static inline uint32
clz64(uint64 type)
{
    uint32 num = 0;
    if (type == 0)
        return 64;
    while (!(type & 0x8000000000000000LL)) {
        num++;
        type <<= 1;
    }
    return num;
}

/* Map an (observed) memop size value to the representative value of its range.
   For example, 5 -> 5, 22 -> 17, 99 -> 65, 256 -> 256, 1001 -> 513. */
static uint64
InstrProfGetRangeRepValue(uint64 Value)
{
    if (Value <= 8)
        /* The first ranges are individually tracked. Use the value as is. */
        return Value;
    else if (Value >= 513)
        /* The last range is mapped to its lowest value. */
        return 513;
    else if (popcount64(Value) == 1)
        /* If it's a power of two, use it as is. */
        return Value;
    else
        /* Otherwise, take to the previous power of two + 1. */
        return (((uint64)1) << (64 - clz64(Value) - 1)) + 1;
}

void
llvm_profile_instrument_memop(uint64 target_value, void *data,
                              uint32 counter_idx)
{
    uint64 rep_value = InstrProfGetRangeRepValue(target_value);
    instrumentTargetValueImpl(rep_value, data, counter_idx, 1);
}

static uint32
get_pgo_prof_data_size(AOTModuleInstance *module_inst, uint32 *p_num_prof_data,
                       uint32 *p_num_prof_counters, uint32 *p_padding_size,
                       uint32 *p_prof_counters_size, uint32 *p_prof_names_size,
                       uint32 *p_value_counters_size, uint8 **p_prof_names)
{
    AOTModule *module = (AOTModule *)module_inst->module;
    LLVMProfileData *prof_data;
    uint8 *prof_names = NULL;
    uint32 num_prof_data = 0, num_prof_counters = 0, padding_size, i;
    uint32 prof_counters_size = 0, prof_names_size = 0;
    uint32 total_size, total_size_wo_value_counters;

    for (i = 0; i < module->data_section_count; i++) {
        if (!strncmp(module->data_sections[i].name, "__llvm_prf_data", 15)) {
            bh_assert(module->data_sections[i].size == sizeof(LLVMProfileData));
            num_prof_data++;
            prof_data = (LLVMProfileData *)module->data_sections[i].data;
            num_prof_counters += prof_data->num_counters;
        }
        else if (!strncmp(module->data_sections[i].name, "__llvm_prf_cnts",
                          15)) {
            prof_counters_size += module->data_sections[i].size;
        }
        else if (!strncmp(module->data_sections[i].name, "__llvm_prf_names",
                          16)) {
            prof_names_size = module->data_sections[i].size;
            prof_names = module->data_sections[i].data;
        }
    }

    if (prof_counters_size != num_prof_counters * sizeof(uint64))
        return 0;

    total_size = sizeof(LLVMProfileRawHeader)
                 + num_prof_data * sizeof(LLVMProfileData_64)
                 + prof_counters_size + prof_names_size;
    padding_size = sizeof(uint64) - (prof_names_size % sizeof(uint64));
    if (padding_size != sizeof(uint64))
        total_size += padding_size;

    /* Total size excluding value counters */
    total_size_wo_value_counters = total_size;

    for (i = 0; i < module->data_section_count; i++) {
        if (!strncmp(module->data_sections[i].name, "__llvm_prf_data", 15)) {
            uint32 j, k, num_value_sites, num_value_nodes;
            ValueProfNode **values, *value_node;

            prof_data = (LLVMProfileData *)module->data_sections[i].data;
            values = prof_data->values;

            if (prof_data->num_value_sites[0] > 0
                || prof_data->num_value_sites[1] > 0) {
                /* TotalSize (uint32) and NumValueKinds (uint32) */
                total_size += 8;
                for (j = 0; j < 2; j++) {
                    if ((num_value_sites = prof_data->num_value_sites[j]) > 0) {
                        /* ValueKind (uint32) and NumValueSites (uint32) */
                        total_size += 8;
                        /* (Value + Counter) group counts of each value site,
                           each count is one byte */
                        total_size += align_uint(num_value_sites, 8);

                        if (values) {
                            for (k = 0; k < num_value_sites; k++) {
                                num_value_nodes = 0;
                                value_node = *values;
                                while (value_node) {
                                    num_value_nodes++;
                                    value_node = value_node->next;
                                }
                                if (num_value_nodes) {
                                    /* (Value + Counter) groups */
                                    total_size += num_value_nodes * 8 * 2;
                                }
                                values++;
                            }
                        }
                    }
                }
            }
        }
    }

    if (p_num_prof_data)
        *p_num_prof_data = num_prof_data;
    if (p_num_prof_counters)
        *p_num_prof_counters = num_prof_counters;
    if (p_padding_size)
        *p_padding_size = padding_size;
    if (p_prof_counters_size)
        *p_prof_counters_size = prof_counters_size;
    if (p_prof_names_size)
        *p_prof_names_size = prof_names_size;
    if (p_value_counters_size)
        *p_value_counters_size = total_size - total_size_wo_value_counters;
    if (p_prof_names)
        *p_prof_names = prof_names;

    return total_size;
}

uint32
aot_get_pgo_prof_data_size(AOTModuleInstance *module_inst)
{
    return get_pgo_prof_data_size(module_inst, NULL, NULL, NULL, NULL, NULL,
                                  NULL, NULL);
}

static union {
    int a;
    char b;
} __ue = { .a = 1 };

#define is_little_endian() (__ue.b == 1)

uint32
aot_dump_pgo_prof_data_to_buf(AOTModuleInstance *module_inst, char *buf,
                              uint32 len)
{
    AOTModule *module = (AOTModule *)module_inst->module;
    LLVMProfileRawHeader prof_header = { 0 };
    LLVMProfileData *prof_data;
    uint8 *prof_names = NULL;
    uint32 num_prof_data = 0, num_prof_counters = 0, padding_size, i;
    uint32 prof_counters_size = 0, prof_names_size = 0;
    uint32 value_counters_size = 0, value_counters_size_backup = 0;
    uint32 total_size, size;
    int64 counters_delta, offset_counters;

    total_size = get_pgo_prof_data_size(module_inst, &num_prof_data,
                                        &num_prof_counters, &padding_size,
                                        &prof_counters_size, &prof_names_size,
                                        &value_counters_size, &prof_names);
    if (len < total_size)
        return 0;

    value_counters_size_backup = value_counters_size;
    value_counters_size = 0;

    prof_header.counters_delta = counters_delta =
        sizeof(LLVMProfileData_64) * num_prof_data;
    offset_counters = 0;
    for (i = 0; i < module->data_section_count; i++) {
        if (!strncmp(module->data_sections[i].name, "__llvm_prf_data", 15)) {
            prof_data = (LLVMProfileData *)module->data_sections[i].data;
            prof_data->offset_counters = counters_delta + offset_counters;
            offset_counters += prof_data->num_counters * sizeof(uint64);
            counters_delta -= sizeof(LLVMProfileData_64);
        }
    }

    prof_header.magic = 0xFF6C70726F667281LL;
    /* Version 8 */
    prof_header.version = 0x0000000000000008LL;
    /* with VARIANT_MASK_IR_PROF (IR Instrumentation) */
    prof_header.version |= 0x1ULL << 56;
    /* with VARIANT_MASK_MEMPROF (Memory Profile) */
    prof_header.version |= 0x1ULL << 62;
    prof_header.num_prof_data = num_prof_data;
    prof_header.num_prof_counters = num_prof_counters;
    prof_header.names_size = prof_names_size;
    prof_header.value_kind_last = 1;

    if (!is_little_endian()) {
        aot_exchange_uint64((uint8 *)&prof_header.magic);
        aot_exchange_uint64((uint8 *)&prof_header.version);
        aot_exchange_uint64((uint8 *)&prof_header.num_prof_data);
        aot_exchange_uint64((uint8 *)&prof_header.num_prof_counters);
        aot_exchange_uint64((uint8 *)&prof_header.names_size);
        aot_exchange_uint64((uint8 *)&prof_header.counters_delta);
        aot_exchange_uint64((uint8 *)&prof_header.value_kind_last);
    }

    size = sizeof(LLVMProfileRawHeader);
    bh_memcpy_s(buf, size, &prof_header, size);
    buf += size;

    for (i = 0; i < module->data_section_count; i++) {
        if (!strncmp(module->data_sections[i].name, "__llvm_prf_data", 15)) {
            LLVMProfileData_64 *prof_data_64 = (LLVMProfileData_64 *)buf;

            /* Convert LLVMProfileData to LLVMProfileData_64, the pointer width
               in the output file is alawys 8 bytes */
            prof_data = (LLVMProfileData *)module->data_sections[i].data;
            prof_data_64->func_md5 = prof_data->func_md5;
            prof_data_64->func_hash = prof_data->func_hash;
            prof_data_64->offset_counters = prof_data->offset_counters;
            prof_data_64->func_ptr = prof_data->func_ptr;
            prof_data_64->values = (uint64)(uintptr_t)prof_data->values;
            prof_data_64->num_counters = prof_data->num_counters;
            prof_data_64->num_value_sites[0] = prof_data->num_value_sites[0];
            prof_data_64->num_value_sites[1] = prof_data->num_value_sites[1];

            if (!is_little_endian()) {
                aot_exchange_uint64((uint8 *)&prof_data_64->func_hash);
                aot_exchange_uint64((uint8 *)&prof_data_64->offset_counters);
                aot_exchange_uint64((uint8 *)&prof_data_64->offset_counters);
                aot_exchange_uint64((uint8 *)&prof_data_64->func_ptr);
                aot_exchange_uint64((uint8 *)&prof_data_64->values);
                aot_exchange_uint32((uint8 *)&prof_data_64->num_counters);
                aot_exchange_uint16((uint8 *)&prof_data_64->num_value_sites[0]);
                aot_exchange_uint16((uint8 *)&prof_data_64->num_value_sites[1]);
            }
            buf += sizeof(LLVMProfileData_64);
        }
    }

    for (i = 0; i < module->data_section_count; i++) {
        if (!strncmp(module->data_sections[i].name, "__llvm_prf_cnts", 15)) {
            size = module->data_sections[i].size;
            bh_memcpy_s(buf, size, module->data_sections[i].data, size);
            buf += size;
        }
    }

    if (prof_names && prof_names_size > 0) {
        size = prof_names_size;
        bh_memcpy_s(buf, size, prof_names, size);
        buf += size;
        padding_size = sizeof(uint64) - (prof_names_size % sizeof(uint64));
        if (padding_size != sizeof(uint64)) {
            char padding_buf[8] = { 0 };
            bh_memcpy_s(buf, padding_size, padding_buf, padding_size);
            buf += padding_size;
        }
    }

    for (i = 0; i < module->data_section_count; i++) {
        if (!strncmp(module->data_sections[i].name, "__llvm_prf_data", 15)) {
            uint32 j, k, num_value_sites, num_value_nodes;
            ValueProfNode **values, **values_tmp, *value_node;

            prof_data = (LLVMProfileData *)module->data_sections[i].data;
            values = values_tmp = prof_data->values;

            if (prof_data->num_value_sites[0] > 0
                || prof_data->num_value_sites[1] > 0) {
                uint32 *buf_total_size = (uint32 *)buf;

                buf += 4; /* emit TotalSize later */
                *(uint32 *)buf = (prof_data->num_value_sites[0] > 0
                                  && prof_data->num_value_sites[1] > 0)
                                     ? 2
                                     : 1;
                if (!is_little_endian())
                    aot_exchange_uint32((uint8 *)buf);
                buf += 4;

                for (j = 0; j < 2; j++) {
                    if ((num_value_sites = prof_data->num_value_sites[j]) > 0) {
                        /* ValueKind */
                        *(uint32 *)buf = j;
                        if (!is_little_endian())
                            aot_exchange_uint32((uint8 *)buf);
                        buf += 4;
                        /* NumValueSites */
                        *(uint32 *)buf = num_value_sites;
                        if (!is_little_endian())
                            aot_exchange_uint32((uint8 *)buf);
                        buf += 4;

                        for (k = 0; k < num_value_sites; k++) {
                            num_value_nodes = 0;
                            if (values_tmp) {
                                value_node = *values_tmp;
                                while (value_node) {
                                    num_value_nodes++;
                                    value_node = value_node->next;
                                }
                                values_tmp++;
                            }
                            bh_assert(num_value_nodes < 255);
                            *(uint8 *)buf++ = (uint8)num_value_nodes;
                        }
                        if (num_value_sites % 8) {
                            buf += 8 - (num_value_sites % 8);
                        }

                        for (k = 0; k < num_value_sites; k++) {
                            if (values) {
                                value_node = *values;
                                while (value_node) {
                                    *(uint64 *)buf = value_node->value;
                                    if (!is_little_endian())
                                        aot_exchange_uint64((uint8 *)buf);
                                    buf += 8;
                                    *(uint64 *)buf = value_node->count;
                                    if (!is_little_endian())
                                        aot_exchange_uint64((uint8 *)buf);
                                    buf += 8;
                                    value_node = value_node->next;
                                }
                                values++;
                            }
                        }
                    }
                }

                /* TotalSize */
                *(uint32 *)buf_total_size =
                    (uint8 *)buf - (uint8 *)buf_total_size;
                if (!is_little_endian())
                    aot_exchange_uint64((uint8 *)buf_total_size);
                value_counters_size += (uint8 *)buf - (uint8 *)buf_total_size;
            }
        }
    }

    bh_assert(value_counters_size == value_counters_size_backup);
    (void)value_counters_size_backup;

    return total_size;
}
#endif /* end of WASM_ENABLE_STATIC_PGO != 0 */
