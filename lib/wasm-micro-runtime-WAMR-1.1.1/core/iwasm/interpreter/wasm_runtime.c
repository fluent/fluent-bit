/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_runtime.h"
#include "wasm_loader.h"
#include "wasm_interp.h"
#include "bh_common.h"
#include "bh_log.h"
#include "mem_alloc.h"
#include "../common/wasm_runtime_common.h"
#if WASM_ENABLE_SHARED_MEMORY != 0
#include "../common/wasm_shared_memory.h"
#endif
#if WASM_ENABLE_THREAD_MGR != 0
#include "../libraries/thread-mgr/thread_manager.h"
#endif
#if WASM_ENABLE_DEBUG_INTERP != 0
#include "../libraries/debug-engine/debug_engine.h"
#endif

static void
set_error_buf(char *error_buf, uint32 error_buf_size, const char *string)
{
    if (error_buf != NULL) {
        snprintf(error_buf, error_buf_size,
                 "WASM module instantiate failed: %s", string);
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
        snprintf(error_buf, error_buf_size,
                 "WASM module instantiate failed: %s", buf);
    }
}

WASMModule *
wasm_load(uint8 *buf, uint32 size, char *error_buf, uint32 error_buf_size)
{
    return wasm_loader_load(buf, size,
#if WASM_ENABLE_MULTI_MODULE != 0
                            true,
#endif
                            error_buf, error_buf_size);
}

WASMModule *
wasm_load_from_sections(WASMSection *section_list, char *error_buf,
                        uint32 error_buf_size)
{
    return wasm_loader_load_from_sections(section_list, error_buf,
                                          error_buf_size);
}

void
wasm_unload(WASMModule *module)
{
    wasm_loader_unload(module);
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

#if WASM_ENABLE_MULTI_MODULE != 0
static WASMModuleInstance *
get_sub_module_inst(const WASMModuleInstance *parent_module_inst,
                    const WASMModule *sub_module)
{
    bh_list *sub_module_inst_list = parent_module_inst->sub_module_inst_list;
    WASMSubModInstNode *node = bh_list_first_elem(sub_module_inst_list);

    while (node && sub_module != node->module_inst->module) {
        node = bh_list_elem_next(node);
    }
    return node ? node->module_inst : NULL;
}
#endif

/**
 * Destroy memory instances.
 */
static void
memories_deinstantiate(WASMModuleInstance *module_inst,
                       WASMMemoryInstance **memories, uint32 count)
{
    uint32 i;
    if (memories) {
        for (i = 0; i < count; i++) {
            if (memories[i]) {
#if WASM_ENABLE_MULTI_MODULE != 0
                WASMModule *module = module_inst->module;
                if (i < module->import_memory_count
                    && module->import_memories[i].u.memory.import_module) {
                    continue;
                }
#endif
#if WASM_ENABLE_SHARED_MEMORY != 0
                if (memories[i]->is_shared) {
                    int32 ref_count = shared_memory_dec_reference(
                        (WASMModuleCommon *)module_inst->module);
                    bh_assert(ref_count >= 0);

                    /* if the reference count is not zero,
                        don't free the memory */
                    if (ref_count > 0)
                        continue;
                }
                os_mutex_destroy(&memories[i]->mem_lock);
#endif
                if (memories[i]->heap_handle) {
                    mem_allocator_destroy(memories[i]->heap_handle);
                    wasm_runtime_free(memories[i]->heap_handle);
                    memories[i]->heap_handle = NULL;
                }
                if (memories[i]->memory_data) {
#ifndef OS_ENABLE_HW_BOUND_CHECK
                    wasm_runtime_free(memories[i]->memory_data);
#else
#ifdef BH_PLATFORM_WINDOWS
                    os_mem_decommit(memories[i]->memory_data,
                                    memories[i]->num_bytes_per_page
                                        * memories[i]->cur_page_count);
#endif
                    os_munmap((uint8 *)memories[i]->memory_data,
                              8 * (uint64)BH_GB);
#endif
                }
                wasm_runtime_free(memories[i]);
            }
        }
        wasm_runtime_free(memories);
    }
    (void)module_inst;
}

static WASMMemoryInstance *
memory_instantiate(WASMModuleInstance *module_inst, uint32 num_bytes_per_page,
                   uint32 init_page_count, uint32 max_page_count,
                   uint32 heap_size, uint32 flags, char *error_buf,
                   uint32 error_buf_size)
{
    WASMModule *module = module_inst->module;
    WASMMemoryInstance *memory;
    uint64 memory_data_size;
    uint32 heap_offset = num_bytes_per_page * init_page_count;
    uint32 inc_page_count, aux_heap_base, global_idx;
    uint32 bytes_of_last_page, bytes_to_page_end;
    uint8 *global_addr;
#ifdef OS_ENABLE_HW_BOUND_CHECK
    uint8 *mapped_mem;
    uint64 map_size = 8 * (uint64)BH_GB;
    uint64 page_size = os_getpagesize();
#endif

#if WASM_ENABLE_SHARED_MEMORY != 0
    bool is_shared_memory = flags & 0x02 ? true : false;

    /* shared memory */
    if (is_shared_memory) {
        WASMSharedMemNode *node = wasm_module_get_shared_memory(
            (WASMModuleCommon *)module_inst->module);
        /* If the memory of this module has been instantiated,
            return the memory instance directly */
        if (node) {
            uint32 ref_count;
            ref_count = shared_memory_inc_reference(
                (WASMModuleCommon *)module_inst->module);
            bh_assert(ref_count > 0);
            memory = (WASMMemoryInstance *)shared_memory_get_memory_inst(node);
            bh_assert(memory);

            (void)ref_count;
            return memory;
        }
    }
#endif /* end of WASM_ENABLE_SHARED_MEMORY */

    if (heap_size > 0 && module_inst->module->malloc_function != (uint32)-1
        && module_inst->module->free_function != (uint32)-1) {
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
            global_idx = module->aux_heap_base_global_index;
            bh_assert(module_inst->globals
                      && global_idx < module_inst->global_count);
            global_addr = module_inst->global_data
                          + module_inst->globals[global_idx].data_offset;
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
    LOG_VERBOSE("  heap offset: %u, heap size: %d\n", heap_offset, heap_size);

    memory_data_size = (uint64)num_bytes_per_page * init_page_count;
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (is_shared_memory) {
        /* Allocate max page for shared memory */
        memory_data_size = (uint64)num_bytes_per_page * max_page_count;
    }
#endif
    bh_assert(memory_data_size <= 4 * (uint64)BH_GB);

    /* Allocate memory space, addr data and global data */
    if (!(memory = runtime_malloc((uint64)sizeof(WASMMemoryInstance), error_buf,
                                  error_buf_size))) {
        return NULL;
    }

#ifndef OS_ENABLE_HW_BOUND_CHECK
    if (memory_data_size > 0
        && !(memory->memory_data =
                 runtime_malloc(memory_data_size, error_buf, error_buf_size))) {
        goto fail1;
    }
#else
    memory_data_size = (memory_data_size + page_size - 1) & ~(page_size - 1);

    /* Totally 8G is mapped, the opcode load/store address range is 0 to 8G:
     *   ea = i + memarg.offset
     * both i and memarg.offset are u32 in range 0 to 4G
     * so the range of ea is 0 to 8G
     */
    if (!(memory->memory_data = mapped_mem =
              os_mmap(NULL, map_size, MMAP_PROT_NONE, MMAP_MAP_NONE))) {
        set_error_buf(error_buf, error_buf_size, "mmap memory failed");
        goto fail1;
    }

#ifdef BH_PLATFORM_WINDOWS
    if (!os_mem_commit(mapped_mem, memory_data_size,
                       MMAP_PROT_READ | MMAP_PROT_WRITE)) {
        set_error_buf(error_buf, error_buf_size, "commit memory failed");
        os_munmap(mapped_mem, map_size);
        goto fail1;
    }
#endif

    if (os_mprotect(mapped_mem, memory_data_size,
                    MMAP_PROT_READ | MMAP_PROT_WRITE)
        != 0) {
        set_error_buf(error_buf, error_buf_size, "mprotect memory failed");
        goto fail2;
    }
    /* Newly allocated pages are filled with zero by the OS, we don't fill it
     * again here */
#endif /* end of OS_ENABLE_HW_BOUND_CHECK */

    if (memory_data_size > UINT32_MAX)
        memory_data_size = (uint32)memory_data_size;

    memory->module_type = Wasm_Module_Bytecode;
    memory->num_bytes_per_page = num_bytes_per_page;
    memory->cur_page_count = init_page_count;
    memory->max_page_count = max_page_count;
    memory->memory_data_size = (uint32)memory_data_size;

    memory->heap_data = memory->memory_data + heap_offset;
    memory->heap_data_end = memory->heap_data + heap_size;
    memory->memory_data_end = memory->memory_data + (uint32)memory_data_size;

    /* Initialize heap */
    if (heap_size > 0) {
        uint32 heap_struct_size = mem_allocator_get_heap_struct_size();

        if (!(memory->heap_handle = runtime_malloc(
                  (uint64)heap_struct_size, error_buf, error_buf_size))) {
            goto fail2;
        }
        if (!mem_allocator_create_with_struct_and_pool(
                memory->heap_handle, heap_struct_size, memory->heap_data,
                heap_size)) {
            set_error_buf(error_buf, error_buf_size, "init app heap failed");
            goto fail3;
        }
    }

#if WASM_ENABLE_FAST_JIT != 0
    if (memory_data_size > 0) {
#if UINTPTR_MAX == UINT64_MAX
        memory->mem_bound_check_1byte = memory_data_size - 1;
        memory->mem_bound_check_2bytes = memory_data_size - 2;
        memory->mem_bound_check_4bytes = memory_data_size - 4;
        memory->mem_bound_check_8bytes = memory_data_size - 8;
        memory->mem_bound_check_16bytes = memory_data_size - 16;
#else
        memory->mem_bound_check_1byte = (uint32)memory_data_size - 1;
        memory->mem_bound_check_2bytes = (uint32)memory_data_size - 2;
        memory->mem_bound_check_4bytes = (uint32)memory_data_size - 4;
        memory->mem_bound_check_8bytes = (uint32)memory_data_size - 8;
        memory->mem_bound_check_16bytes = (uint32)memory_data_size - 16;
#endif
    }
#endif

#if WASM_ENABLE_SHARED_MEMORY != 0
    if (0 != os_mutex_init(&memory->mem_lock)) {
        set_error_buf(error_buf, error_buf_size, "init mutex failed");
        goto fail4;
    }
    if (is_shared_memory) {
        memory->is_shared = true;
        if (!shared_memory_set_memory_inst(
                (WASMModuleCommon *)module_inst->module,
                (WASMMemoryInstanceCommon *)memory)) {
            set_error_buf(error_buf, error_buf_size, "allocate memory failed");
            goto fail5;
        }
    }
#endif
    LOG_VERBOSE("Memory instantiate success.");
    return memory;
#if WASM_ENABLE_SHARED_MEMORY != 0
fail5:
    os_mutex_destroy(&memory->mem_lock);
fail4:
    if (heap_size > 0)
        mem_allocator_destroy(memory->heap_handle);
#endif
fail3:
    if (heap_size > 0)
        wasm_runtime_free(memory->heap_handle);
fail2:
#ifndef OS_ENABLE_HW_BOUND_CHECK
    if (memory->memory_data)
        wasm_runtime_free(memory->memory_data);
#else
#ifdef BH_PLATFORM_WINDOWS
    os_mem_decommit(mapped_mem, memory_data_size);
#endif
    os_munmap(mapped_mem, map_size);
#endif
fail1:
    wasm_runtime_free(memory);
    return NULL;
}

/**
 * Instantiate memories in a module.
 */
static WASMMemoryInstance **
memories_instantiate(const WASMModule *module, WASMModuleInstance *module_inst,
                     uint32 heap_size, char *error_buf, uint32 error_buf_size)
{
    WASMImport *import;
    uint32 mem_index = 0, i,
           memory_count = module->import_memory_count + module->memory_count;
    uint64 total_size;
    WASMMemoryInstance **memories, *memory;

    total_size = sizeof(WASMMemoryInstance *) * (uint64)memory_count;

    if (!(memories = runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    /* instantiate memories from import section */
    import = module->import_memories;
    for (i = 0; i < module->import_memory_count; i++, import++) {
        uint32 num_bytes_per_page = import->u.memory.num_bytes_per_page;
        uint32 init_page_count = import->u.memory.init_page_count;
        uint32 max_page_count = import->u.memory.max_page_count;
        uint32 flags = import->u.memory.flags;
        uint32 actual_heap_size = heap_size;

#if WASM_ENABLE_MULTI_MODULE != 0
        if (import->u.memory.import_module != NULL) {
            WASMModuleInstance *module_inst_linked;

            if (!(module_inst_linked = get_sub_module_inst(
                      module_inst, import->u.memory.import_module))) {
                set_error_buf(error_buf, error_buf_size, "unknown memory");
                memories_deinstantiate(module_inst, memories, memory_count);
                return NULL;
            }

            if (!(memory = memories[mem_index++] = wasm_lookup_memory(
                      module_inst_linked, import->u.memory.field_name))) {
                set_error_buf(error_buf, error_buf_size, "unknown memory");
                memories_deinstantiate(module_inst, memories, memory_count);
                return NULL;
            }
        }
        else
#endif
        {
            if (!(memory = memories[mem_index++] = memory_instantiate(
                      module_inst, num_bytes_per_page, init_page_count,
                      max_page_count, actual_heap_size, flags, error_buf,
                      error_buf_size))) {
                memories_deinstantiate(module_inst, memories, memory_count);
                return NULL;
            }
        }
    }

    /* instantiate memories from memory section */
    for (i = 0; i < module->memory_count; i++) {
        if (!(memory = memories[mem_index++] = memory_instantiate(
                  module_inst, module->memories[i].num_bytes_per_page,
                  module->memories[i].init_page_count,
                  module->memories[i].max_page_count, heap_size,
                  module->memories[i].flags, error_buf, error_buf_size))) {
            memories_deinstantiate(module_inst, memories, memory_count);
            return NULL;
        }
    }

    bh_assert(mem_index == memory_count);
    (void)module_inst;
    return memories;
}

/**
 * Destroy table instances.
 */
static void
tables_deinstantiate(WASMTableInstance **tables, uint32 count)
{
    uint32 i;
    if (tables) {
        for (i = 0; i < count; i++)
            if (tables[i])
                wasm_runtime_free(tables[i]);
        wasm_runtime_free(tables);
    }
}

/**
 * Instantiate tables in a module.
 */
static WASMTableInstance **
tables_instantiate(const WASMModule *module, WASMModuleInstance *module_inst,
                   char *error_buf, uint32 error_buf_size)
{
    WASMImport *import;
    uint32 table_index = 0, i,
           table_count = module->import_table_count + module->table_count;
    uint64 total_size = sizeof(WASMTableInstance *) * (uint64)table_count;
    WASMTableInstance **tables, *table;

    if (!(tables = runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    /* instantiate tables from import section */
    import = module->import_tables;
    for (i = 0; i < module->import_table_count; i++, import++) {
        uint32 max_size_fixed = 0;
#if WASM_ENABLE_MULTI_MODULE != 0
        WASMTableInstance *table_inst_linked = NULL;
        WASMModuleInstance *module_inst_linked = NULL;

        if (import->u.table.import_module) {
            if (!(module_inst_linked = get_sub_module_inst(
                      module_inst, import->u.table.import_module))) {
                set_error_buf(error_buf, error_buf_size, "unknown table");
                tables_deinstantiate(tables, table_count);
                return NULL;
            }

            if (!(table_inst_linked = wasm_lookup_table(
                      module_inst_linked, import->u.table.field_name))) {
                set_error_buf(error_buf, error_buf_size, "unknown table");
                tables_deinstantiate(tables, table_count);
                return NULL;
            }

            total_size = offsetof(WASMTableInstance, base_addr);
        }
        else
#endif
        {
            /* in order to save memory, alloc resource as few as possible */
            max_size_fixed = import->u.table.possible_grow
                                 ? import->u.table.max_size
                                 : import->u.table.init_size;

            /* it is a built-in table, every module has its own */
            total_size = offsetof(WASMTableInstance, base_addr);
            total_size += (uint64)max_size_fixed * sizeof(uint32);
        }

        if (!(table = tables[table_index++] =
                  runtime_malloc(total_size, error_buf, error_buf_size))) {
            tables_deinstantiate(tables, table_count);
            return NULL;
        }

        /* Set all elements to -1 to mark them as uninitialized elements */
        memset(table, -1, (uint32)total_size);

#if WASM_ENABLE_MULTI_MODULE != 0
        table->table_inst_linked = table_inst_linked;
        if (table_inst_linked != NULL) {
            table->elem_type = table_inst_linked->elem_type;
            table->cur_size = table_inst_linked->cur_size;
            table->max_size = table_inst_linked->max_size;
        }
        else
#endif
        {
            table->elem_type = import->u.table.elem_type;
            table->cur_size = import->u.table.init_size;
            table->max_size = max_size_fixed;
        }
    }

    /* instantiate tables from table section */
    for (i = 0; i < module->table_count; i++) {
        uint32 max_size_fixed = 0;

        total_size = offsetof(WASMTableInstance, base_addr);
#if WASM_ENABLE_MULTI_MODULE != 0
        /* in case, a module which imports this table will grow it */
        max_size_fixed = module->tables[i].max_size;
#else
        max_size_fixed = module->tables[i].possible_grow
                             ? module->tables[i].max_size
                             : module->tables[i].init_size;
#endif
        total_size += sizeof(uint32) * (uint64)max_size_fixed;

        if (!(table = tables[table_index++] =
                  runtime_malloc(total_size, error_buf, error_buf_size))) {
            tables_deinstantiate(tables, table_count);
            return NULL;
        }

        /* Set all elements to -1 to mark them as uninitialized elements */
        memset(table, -1, (uint32)total_size);
        table->elem_type = module->tables[i].elem_type;
        table->cur_size = module->tables[i].init_size;
        table->max_size = max_size_fixed;
#if WASM_ENABLE_MULTI_MODULE != 0
        table->table_inst_linked = NULL;
#endif
    }

    bh_assert(table_index == table_count);
    (void)module_inst;
    return tables;
}

/**
 * Destroy function instances.
 */
static void
functions_deinstantiate(WASMFunctionInstance *functions, uint32 count)
{
    if (functions) {
        wasm_runtime_free(functions);
    }
}

/**
 * Instantiate functions in a module.
 */
static WASMFunctionInstance *
functions_instantiate(const WASMModule *module, WASMModuleInstance *module_inst,
                      char *error_buf, uint32 error_buf_size)
{
    WASMImport *import;
    uint32 i,
        function_count = module->import_function_count + module->function_count;
    uint64 total_size = sizeof(WASMFunctionInstance) * (uint64)function_count;
    WASMFunctionInstance *functions, *function;

    if (!(functions = runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    total_size = sizeof(void *) * (uint64)module->import_function_count;
    if (total_size > 0
        && !(module_inst->import_func_ptrs =
                 runtime_malloc(total_size, error_buf, error_buf_size))) {
        wasm_runtime_free(functions);
        return NULL;
    }

    /* instantiate functions from import section */
    function = functions;
    import = module->import_functions;
    for (i = 0; i < module->import_function_count; i++, import++) {
        function->is_import_func = true;

#if WASM_ENABLE_MULTI_MODULE != 0
        if (import->u.function.import_module) {
            function->import_module_inst = get_sub_module_inst(
                module_inst, import->u.function.import_module);

            if (function->import_module_inst) {
                function->import_func_inst =
                    wasm_lookup_function(function->import_module_inst,
                                         import->u.function.field_name, NULL);
            }
        }
#endif /* WASM_ENABLE_MULTI_MODULE */
        function->u.func_import = &import->u.function;
        function->param_cell_num = import->u.function.func_type->param_cell_num;
        function->ret_cell_num = import->u.function.func_type->ret_cell_num;
        function->param_count =
            (uint16)function->u.func_import->func_type->param_count;
        function->param_types = function->u.func_import->func_type->types;
        function->local_cell_num = 0;
        function->local_count = 0;
        function->local_types = NULL;

        /* Copy the function pointer to current instance */
        module_inst->import_func_ptrs[i] =
            function->u.func_import->func_ptr_linked;

        function++;
    }

    /* instantiate functions from function section */
    for (i = 0; i < module->function_count; i++) {
        function->is_import_func = false;
        function->u.func = module->functions[i];

        function->param_cell_num = function->u.func->param_cell_num;
        function->ret_cell_num = function->u.func->ret_cell_num;
        function->local_cell_num = function->u.func->local_cell_num;

        function->param_count =
            (uint16)function->u.func->func_type->param_count;
        function->local_count = (uint16)function->u.func->local_count;
        function->param_types = function->u.func->func_type->types;
        function->local_types = function->u.func->local_types;

        function->local_offsets = function->u.func->local_offsets;

#if WASM_ENABLE_FAST_INTERP != 0
        function->const_cell_num = function->u.func->const_cell_num;
#endif

        function++;
    }

#if WASM_ENABLE_FAST_JIT != 0
    module_inst->fast_jit_func_ptrs = module->fast_jit_func_ptrs;
#endif

    bh_assert((uint32)(function - functions) == function_count);
    (void)module_inst;
    return functions;
}

/**
 * Destroy global instances.
 */
static void
globals_deinstantiate(WASMGlobalInstance *globals)
{
    if (globals)
        wasm_runtime_free(globals);
}

static bool
check_global_init_expr(const WASMModule *module, uint32 global_index,
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
        || (module->import_globals + global_index)->u.global.is_mutable) {
        set_error_buf(error_buf, error_buf_size,
                      "constant expression required");
        return false;
    }

    return true;
}

/**
 * Instantiate globals in a module.
 */
static WASMGlobalInstance *
globals_instantiate(const WASMModule *module, WASMModuleInstance *module_inst,
                    uint32 *p_global_data_size, char *error_buf,
                    uint32 error_buf_size)
{
    WASMImport *import;
    uint32 global_data_offset = 0;
    uint32 i, global_count = module->import_global_count + module->global_count;
    uint64 total_size = sizeof(WASMGlobalInstance) * (uint64)global_count;
    WASMGlobalInstance *globals, *global;

    if (!(globals = runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    /* instantiate globals from import section */
    global = globals;
    import = module->import_globals;
    for (i = 0; i < module->import_global_count; i++, import++) {
        WASMGlobalImport *global_import = &import->u.global;
        global->type = global_import->type;
        global->is_mutable = global_import->is_mutable;
#if WASM_ENABLE_MULTI_MODULE != 0
        if (global_import->import_module) {
            if (!(global->import_module_inst = get_sub_module_inst(
                      module_inst, global_import->import_module))) {
                set_error_buf(error_buf, error_buf_size, "unknown global");
                goto fail;
            }

            if (!(global->import_global_inst = wasm_lookup_global(
                      global->import_module_inst, global_import->field_name))) {
                set_error_buf(error_buf, error_buf_size, "unknown global");
                goto fail;
            }

            /* The linked global instance has been initialized, we
               just need to copy the value. */
            bh_memcpy_s(&(global->initial_value), sizeof(WASMValue),
                        &(global_import->import_global_linked->init_expr),
                        sizeof(WASMValue));
        }
        else
#endif
        {
            /* native globals share their initial_values in one module */
            bh_memcpy_s(&(global->initial_value), sizeof(WASMValue),
                        &(global_import->global_data_linked),
                        sizeof(WASMValue));
        }
        global->data_offset = global_data_offset;
        global_data_offset += wasm_value_type_size(global->type);

        global++;
    }

    /* instantiate globals from global section */
    for (i = 0; i < module->global_count; i++) {
        InitializerExpression *init_expr = &(module->globals[i].init_expr);

        global->type = module->globals[i].type;
        global->is_mutable = module->globals[i].is_mutable;
        global->data_offset = global_data_offset;

        global_data_offset += wasm_value_type_size(global->type);

        if (init_expr->init_expr_type == INIT_EXPR_TYPE_GET_GLOBAL) {
            if (!check_global_init_expr(module, init_expr->u.global_index,
                                        error_buf, error_buf_size)) {
                goto fail;
            }

            bh_memcpy_s(
                &(global->initial_value), sizeof(WASMValue),
                &(globals[init_expr->u.global_index].initial_value),
                sizeof(globals[init_expr->u.global_index].initial_value));
        }
#if WASM_ENABLE_REF_TYPES != 0
        else if (init_expr->init_expr_type == INIT_EXPR_TYPE_REFNULL_CONST) {
            global->initial_value.u32 = (uint32)NULL_REF;
        }
#endif
        else {
            bh_memcpy_s(&(global->initial_value), sizeof(WASMValue),
                        &(init_expr->u), sizeof(init_expr->u));
        }
        global++;
    }

    bh_assert((uint32)(global - globals) == global_count);
    *p_global_data_size = global_data_offset;
    (void)module_inst;
    return globals;
fail:
    wasm_runtime_free(globals);
    return NULL;
}

/**
 * Return export function count in module export section.
 */
static uint32
get_export_count(const WASMModule *module, uint8 kind)
{
    WASMExport *export = module->exports;
    uint32 count = 0, i;

    for (i = 0; i < module->export_count; i++, export ++)
        if (export->kind == kind)
            count++;

    return count;
}

/**
 * Destroy export function instances.
 */
static void
export_functions_deinstantiate(WASMExportFuncInstance *functions)
{
    if (functions)
        wasm_runtime_free(functions);
}

/**
 * Instantiate export functions in a module.
 */
static WASMExportFuncInstance *
export_functions_instantiate(const WASMModule *module,
                             WASMModuleInstance *module_inst,
                             uint32 export_func_count, char *error_buf,
                             uint32 error_buf_size)
{
    WASMExportFuncInstance *export_funcs, *export_func;
    WASMExport *export = module->exports;
    uint32 i;
    uint64 total_size =
        sizeof(WASMExportFuncInstance) * (uint64)export_func_count;

    if (!(export_func = export_funcs =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    for (i = 0; i < module->export_count; i++, export ++)
        if (export->kind == EXPORT_KIND_FUNC) {
            export_func->name = export->name;
            export_func->function = &module_inst->functions[export->index];
            export_func++;
        }

    bh_assert((uint32)(export_func - export_funcs) == export_func_count);
    return export_funcs;
}

#if WASM_ENABLE_MULTI_MODULE != 0
static void
export_globals_deinstantiate(WASMExportGlobInstance *globals)
{
    if (globals)
        wasm_runtime_free(globals);
}

static WASMExportGlobInstance *
export_globals_instantiate(const WASMModule *module,
                           WASMModuleInstance *module_inst,
                           uint32 export_glob_count, char *error_buf,
                           uint32 error_buf_size)
{
    WASMExportGlobInstance *export_globals, *export_global;
    WASMExport *export = module->exports;
    uint32 i;
    uint64 total_size =
        sizeof(WASMExportGlobInstance) * (uint64)export_glob_count;

    if (!(export_global = export_globals =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    for (i = 0; i < module->export_count; i++, export ++)
        if (export->kind == EXPORT_KIND_GLOBAL) {
            export_global->name = export->name;
            export_global->global = &module_inst->globals[export->index];
            export_global++;
        }

    bh_assert((uint32)(export_global - export_globals) == export_glob_count);
    return export_globals;
}
#endif

static bool
execute_post_inst_function(WASMModuleInstance *module_inst)
{
    WASMFunctionInstance *post_inst_func = NULL;
    WASMType *post_inst_func_type;
    uint32 i;

    for (i = 0; i < module_inst->export_func_count; i++)
        if (!strcmp(module_inst->export_functions[i].name,
                    "__post_instantiate")) {
            post_inst_func = module_inst->export_functions[i].function;
            break;
        }

    if (!post_inst_func)
        /* Not found */
        return true;

    post_inst_func_type = post_inst_func->u.func->func_type;
    if (post_inst_func_type->param_count != 0
        || post_inst_func_type->result_count != 0)
        /* Not a valid function type, ignore it */
        return true;

    return wasm_create_exec_env_and_call_function(module_inst, post_inst_func,
                                                  0, NULL);
}

#if WASM_ENABLE_BULK_MEMORY != 0
static bool
execute_memory_init_function(WASMModuleInstance *module_inst)
{
    WASMFunctionInstance *memory_init_func = NULL;
    WASMType *memory_init_func_type;
    uint32 i;

    for (i = 0; i < module_inst->export_func_count; i++)
        if (!strcmp(module_inst->export_functions[i].name,
                    "__wasm_call_ctors")) {
            memory_init_func = module_inst->export_functions[i].function;
            break;
        }

    if (!memory_init_func)
        /* Not found */
        return true;

    memory_init_func_type = memory_init_func->u.func->func_type;
    if (memory_init_func_type->param_count != 0
        || memory_init_func_type->result_count != 0)
        /* Not a valid function type, ignore it */
        return true;

    return wasm_create_exec_env_and_call_function(module_inst, memory_init_func,
                                                  0, NULL);
}
#endif

static bool
execute_start_function(WASMModuleInstance *module_inst)
{
    WASMFunctionInstance *func = module_inst->start_function;

    if (!func)
        return true;

    bh_assert(!func->is_import_func && func->param_cell_num == 0
              && func->ret_cell_num == 0);

    return wasm_create_exec_env_and_call_function(module_inst, func, 0, NULL);
}

static bool
execute_malloc_function(WASMModuleInstance *module_inst,
                        WASMFunctionInstance *malloc_func,
                        WASMFunctionInstance *retain_func, uint32 size,
                        uint32 *p_result)
{
#ifdef OS_ENABLE_HW_BOUND_CHECK
    WASMExecEnv *exec_env_tls = wasm_runtime_get_exec_env_tls();
#endif
    uint32 argv[2], argc;
    bool ret;

    argv[0] = size;
    argc = 1;

    /* if __retain is exported, then this module is compiled by
        assemblyscript, the memory should be managed by as's runtime,
        in this case we need to call the retain function after malloc
        the memory */
    if (retain_func) {
        /* the malloc functino from assemblyscript is:
            function __new(size: usize, id: u32)
            id = 0 means this is an ArrayBuffer object */
        argv[1] = 0;
        argc = 2;
    }

#ifdef OS_ENABLE_HW_BOUND_CHECK
    if (exec_env_tls != NULL) {
        bh_assert(exec_env_tls->module_inst
                  == (WASMModuleInstanceCommon *)module_inst);
        ret = wasm_call_function(exec_env_tls, malloc_func, argc, argv);

        if (retain_func && ret) {
            ret = wasm_call_function(exec_env_tls, retain_func, 1, argv);
        }
    }
    else
#endif
    {
        ret = wasm_create_exec_env_and_call_function(module_inst, malloc_func,
                                                     argc, argv);

        if (retain_func && ret) {
            ret = wasm_create_exec_env_and_call_function(module_inst,
                                                         retain_func, 1, argv);
        }
    }

    if (ret)
        *p_result = argv[0];
    return ret;
}

static bool
execute_free_function(WASMModuleInstance *module_inst,
                      WASMFunctionInstance *free_func, uint32 offset)
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
        return wasm_call_function(exec_env_tls, free_func, 1, argv);
    }
    else
#endif
    {
        return wasm_create_exec_env_and_call_function(module_inst, free_func, 1,
                                                      argv);
    }
}

#if WASM_ENABLE_MULTI_MODULE != 0
static bool
sub_module_instantiate(WASMModule *module, WASMModuleInstance *module_inst,
                       uint32 stack_size, uint32 heap_size, char *error_buf,
                       uint32 error_buf_size)
{
    bh_list *sub_module_inst_list = module_inst->sub_module_inst_list;
    WASMRegisteredModule *sub_module_list_node =
        bh_list_first_elem(module->import_module_list);

    while (sub_module_list_node) {
        WASMSubModInstNode *sub_module_inst_list_node = NULL;
        WASMModule *sub_module = (WASMModule *)sub_module_list_node->module;
        WASMModuleInstance *sub_module_inst = NULL;

        sub_module_inst =
            wasm_instantiate(sub_module, false, stack_size, heap_size,
                             error_buf, error_buf_size);
        if (!sub_module_inst) {
            LOG_DEBUG("instantiate %s failed",
                      sub_module_list_node->module_name);
            goto failed;
        }

        sub_module_inst_list_node = runtime_malloc(sizeof(WASMSubModInstNode),
                                                   error_buf, error_buf_size);
        if (!sub_module_inst_list_node) {
            LOG_DEBUG("Malloc WASMSubModInstNode failed, SZ:%d",
                      sizeof(WASMSubModInstNode));
            goto failed;
        }

        sub_module_inst_list_node->module_inst = sub_module_inst;
        sub_module_inst_list_node->module_name =
            sub_module_list_node->module_name;
        bh_list_status ret =
            bh_list_insert(sub_module_inst_list, sub_module_inst_list_node);
        bh_assert(BH_LIST_SUCCESS == ret);
        (void)ret;

        sub_module_list_node = bh_list_elem_next(sub_module_list_node);

#if WASM_ENABLE_LIBC_WASI != 0
        {
            /*
             * reactor instances may assume that _initialize will be called by
             * the environment at most once, and that none of their other
             * exports are accessed before that call.
             *
             * let the loader decide how to act if there is no _initialize
             * in a reactor
             */
            WASMFunctionInstance *initialize =
                wasm_lookup_function(sub_module_inst, "_initialize", NULL);
            if (initialize
                && !wasm_create_exec_env_and_call_function(
                    sub_module_inst, initialize, 0, NULL)) {
                set_error_buf(error_buf, error_buf_size,
                              "Call _initialize failed ");
                goto failed;
            }
        }
#endif

        continue;
    failed:
        if (sub_module_inst_list_node) {
            bh_list_remove(sub_module_inst_list, sub_module_inst_list_node);
            wasm_runtime_free(sub_module_inst_list_node);
        }

        if (sub_module_inst)
            wasm_deinstantiate(sub_module_inst, false);
        return false;
    }

    return true;
}

static void
sub_module_deinstantiate(WASMModuleInstance *module_inst)
{
    bh_list *list = module_inst->sub_module_inst_list;
    WASMSubModInstNode *node = bh_list_first_elem(list);
    while (node) {
        WASMSubModInstNode *next_node = bh_list_elem_next(node);
        bh_list_remove(list, node);
        wasm_deinstantiate(node->module_inst, false);
        wasm_runtime_free(node);
        node = next_node;
    }
}
#endif

static bool
check_linked_symbol(WASMModuleInstance *module_inst, char *error_buf,
                    uint32 error_buf_size)
{
    WASMModule *module = module_inst->module;
    uint32 i;

    for (i = 0; i < module->import_function_count; i++) {
        WASMFunctionImport *func =
            &((module->import_functions + i)->u.function);
        if (!func->func_ptr_linked
#if WASM_ENABLE_MULTI_MODULE != 0
            && !func->import_func_linked
#endif
        ) {
#if WASM_ENABLE_WAMR_COMPILER == 0
            LOG_WARNING("warning: failed to link import function (%s, %s)",
                        func->module_name, func->field_name);
#else
            /* do nothing to avoid confused message */
#endif /* WASM_ENABLE_WAMR_COMPILER == 0 */
        }
    }

    for (i = 0; i < module->import_global_count; i++) {
        WASMGlobalImport *global = &((module->import_globals + i)->u.global);
        if (!global->is_linked) {
#if WASM_ENABLE_SPEC_TEST != 0
            set_error_buf(error_buf, error_buf_size,
                          "unknown import or incompatible import type");
            return false;
#else
#if WASM_ENABLE_WAMR_COMPILER == 0
            LOG_DEBUG("warning: failed to link import global (%s, %s)",
                      global->module_name, global->field_name);
#else
            /* do nothing to avoid confused message */
#endif /* WASM_ENABLE_WAMR_COMPILER == 0 */
#endif /* WASM_ENABLE_SPEC_TEST != 0 */
        }
    }

    return true;
}

#if WASM_ENABLE_FAST_JIT != 0
static uint32
get_smallest_type_idx(WASMModule *module, WASMType *func_type)
{
    uint32 i;

    for (i = 0; i < module->type_count; i++) {
        if (func_type == module->types[i])
            return i;
    }

    bh_assert(0);
    return -1;
}

static bool
init_func_type_indexes(WASMModuleInstance *module_inst, char *error_buf,
                       uint32 error_buf_size)
{
    uint32 i;
    uint64 total_size = (uint64)sizeof(uint32) * module_inst->function_count;

    /* Allocate memory */
    if (!(module_inst->func_type_indexes =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    for (i = 0; i < module_inst->function_count; i++) {
        WASMFunctionInstance *func_inst = module_inst->functions + i;
        WASMType *func_type = func_inst->is_import_func
                                  ? func_inst->u.func_import->func_type
                                  : func_inst->u.func->func_type;
        module_inst->func_type_indexes[i] =
            get_smallest_type_idx(module_inst->module, func_type);
    }

    return true;
}
#endif

/**
 * Instantiate module
 */
WASMModuleInstance *
wasm_instantiate(WASMModule *module, bool is_sub_inst, uint32 stack_size,
                 uint32 heap_size, char *error_buf, uint32 error_buf_size)
{
    WASMModuleInstance *module_inst;
    WASMGlobalInstance *globals = NULL, *global;
    uint32 global_count, global_data_size = 0, i;
    uint32 base_offset, length;
    uint8 *global_data, *global_data_end;
#if WASM_ENABLE_MULTI_MODULE != 0
    bool ret = false;
#endif

    if (!module)
        return NULL;

#if WASM_ENABLE_DEBUG_INTERP != 0
    if (!is_sub_inst) {
        os_mutex_lock(&module->ref_count_lock);
        if (module->ref_count != 0) {
            LOG_WARNING(
                "warning: multiple instances referencing the same module may "
                "cause unexpected behaviour during debugging");
        }
        module->ref_count++;
        os_mutex_unlock(&module->ref_count_lock);
    }
#endif

    /* Check heap size */
    heap_size = align_uint(heap_size, 8);
    if (heap_size > APP_HEAP_SIZE_MAX)
        heap_size = APP_HEAP_SIZE_MAX;

    /* Allocate the memory */
    if (!(module_inst = runtime_malloc(sizeof(WASMModuleInstance), error_buf,
                                       error_buf_size))) {
#if WASM_ENABLE_DEBUG_INTERP != 0
        if (!is_sub_inst) {
            os_mutex_lock(&module->ref_count_lock);
            module->ref_count--;
            os_mutex_unlock(&module->ref_count_lock);
        }
#endif
        return NULL;
    }

    module_inst->module = module;

#if WASM_ENABLE_MULTI_MODULE != 0
    module_inst->sub_module_inst_list = &module_inst->sub_module_inst_list_head;
    ret = sub_module_instantiate(module, module_inst, stack_size, heap_size,
                                 error_buf, error_buf_size);
    if (!ret) {
        LOG_DEBUG("build a sub module list failed");
        goto fail;
    }
#endif

#if WASM_ENABLE_DUMP_CALL_STACK != 0
    if (!(module_inst->frames = runtime_malloc((uint64)sizeof(Vector),
                                               error_buf, error_buf_size))) {
        goto fail;
    }
#endif

    /* Instantiate global firstly to get the mutable data size */
    global_count = module->import_global_count + module->global_count;
    if (global_count
        && !(globals =
                 globals_instantiate(module, module_inst, &global_data_size,
                                     error_buf, error_buf_size))) {
        goto fail;
    }
    module_inst->global_count = global_count;
    module_inst->globals = globals;

    module_inst->memory_count =
        module->import_memory_count + module->memory_count;
    module_inst->table_count = module->import_table_count + module->table_count;
    module_inst->function_count =
        module->import_function_count + module->function_count;

    /* export */
    module_inst->export_func_count = get_export_count(module, EXPORT_KIND_FUNC);
#if WASM_ENABLE_MULTI_MODULE != 0
    module_inst->export_tab_count = get_export_count(module, EXPORT_KIND_TABLE);
    module_inst->export_mem_count =
        get_export_count(module, EXPORT_KIND_MEMORY);
    module_inst->export_glob_count =
        get_export_count(module, EXPORT_KIND_GLOBAL);
#endif

    if (global_count > 0) {
        if (!(module_inst->global_data = runtime_malloc(
                  global_data_size, error_buf, error_buf_size))) {
            goto fail;
        }
    }

    /* Instantiate memories/tables/functions */
    if ((module_inst->memory_count > 0
         && !(module_inst->memories = memories_instantiate(
                  module, module_inst, heap_size, error_buf, error_buf_size)))
        || (module_inst->table_count > 0
            && !(module_inst->tables = tables_instantiate(
                     module, module_inst, error_buf, error_buf_size)))
        || (module_inst->function_count > 0
            && !(module_inst->functions = functions_instantiate(
                     module, module_inst, error_buf, error_buf_size)))
        || (module_inst->export_func_count > 0
            && !(module_inst->export_functions = export_functions_instantiate(
                     module, module_inst, module_inst->export_func_count,
                     error_buf, error_buf_size)))
#if WASM_ENABLE_MULTI_MODULE != 0
        || (module_inst->export_glob_count > 0
            && !(module_inst->export_globals = export_globals_instantiate(
                     module, module_inst, module_inst->export_glob_count,
                     error_buf, error_buf_size)))
#endif
#if WASM_ENABLE_FAST_JIT != 0
        || (module_inst->function_count > 0
            && !init_func_type_indexes(module_inst, error_buf, error_buf_size))
#endif
    ) {
        goto fail;
    }

    if (global_count > 0) {
        /* Initialize the global data */
        global_data = module_inst->global_data;
        global_data_end = global_data + global_data_size;
        global = globals;
        for (i = 0; i < global_count; i++, global++) {
            switch (global->type) {
                case VALUE_TYPE_I32:
                case VALUE_TYPE_F32:
#if WASM_ENABLE_REF_TYPES != 0
                case VALUE_TYPE_FUNCREF:
                case VALUE_TYPE_EXTERNREF:
#endif
                    *(int32 *)global_data = global->initial_value.i32;
                    global_data += sizeof(int32);
                    break;
                case VALUE_TYPE_I64:
                case VALUE_TYPE_F64:
                    bh_memcpy_s(global_data,
                                (uint32)(global_data_end - global_data),
                                &global->initial_value.i64, sizeof(int64));
                    global_data += sizeof(int64);
                    break;
                default:
                    bh_assert(0);
            }
        }
        bh_assert(global_data == global_data_end);
    }

    if (!check_linked_symbol(module_inst, error_buf, error_buf_size)) {
        goto fail;
    }

    /* Initialize the memory data with data segment section */
    module_inst->default_memory =
        module_inst->memory_count ? module_inst->memories[0] : NULL;

    for (i = 0; i < module->data_seg_count; i++) {
        WASMMemoryInstance *memory = NULL;
        uint8 *memory_data = NULL;
        uint32 memory_size = 0;
        WASMDataSeg *data_seg = module->data_segments[i];

#if WASM_ENABLE_BULK_MEMORY != 0
        if (data_seg->is_passive)
            continue;
#endif

        /* has check it in loader */
        memory = module_inst->memories[data_seg->memory_index];
        bh_assert(memory);

        memory_data = memory->memory_data;
        memory_size = memory->num_bytes_per_page * memory->cur_page_count;
        bh_assert(memory_data || memory_size == 0);

        bh_assert(data_seg->base_offset.init_expr_type
                      == INIT_EXPR_TYPE_I32_CONST
                  || data_seg->base_offset.init_expr_type
                         == INIT_EXPR_TYPE_GET_GLOBAL);

        if (data_seg->base_offset.init_expr_type == INIT_EXPR_TYPE_GET_GLOBAL) {
            if (!check_global_init_expr(module,
                                        data_seg->base_offset.u.global_index,
                                        error_buf, error_buf_size)) {
                goto fail;
            }

            if (!globals
                || globals[data_seg->base_offset.u.global_index].type
                       != VALUE_TYPE_I32) {
                set_error_buf(error_buf, error_buf_size,
                              "data segment does not fit");
                goto fail;
            }

            base_offset =
                globals[data_seg->base_offset.u.global_index].initial_value.i32;
        }
        else {
            base_offset = (uint32)data_seg->base_offset.u.i32;
        }

        /* check offset */
        if (base_offset > memory_size) {
            LOG_DEBUG("base_offset(%d) > memory_size(%d)", base_offset,
                      memory_size);
#if WASM_ENABLE_REF_TYPES != 0
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds memory access");
#else
            set_error_buf(error_buf, error_buf_size,
                          "data segment does not fit");
#endif
            goto fail;
        }

        /* check offset + length(could be zero) */
        length = data_seg->data_length;
        if (base_offset + length > memory_size) {
            LOG_DEBUG("base_offset(%d) + length(%d) > memory_size(%d)",
                      base_offset, length, memory_size);
#if WASM_ENABLE_REF_TYPES != 0
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds memory access");
#else
            set_error_buf(error_buf, error_buf_size,
                          "data segment does not fit");
#endif
            goto fail;
        }

        if (memory_data) {
            bh_memcpy_s(memory_data + base_offset, memory_size - base_offset,
                        data_seg->data, length);
        }
    }

    /* Initialize the table data with table segment section */
    module_inst->default_table =
        module_inst->table_count ? module_inst->tables[0] : NULL;
    /* in case there is no table */
    for (i = 0; module_inst->table_count > 0 && i < module->table_seg_count;
         i++) {
        WASMTableSeg *table_seg = module->table_segments + i;
        /* has check it in loader */
        WASMTableInstance *table = module_inst->tables[table_seg->table_index];
        bh_assert(table);

#if WASM_ENABLE_REF_TYPES != 0
        if (table->elem_type != VALUE_TYPE_FUNCREF
            && table->elem_type != VALUE_TYPE_EXTERNREF) {
            set_error_buf(error_buf, error_buf_size,
                          "elements segment does not fit");
            goto fail;
        }
#endif

        uint32 *table_data = (uint32 *)table->base_addr;
#if WASM_ENABLE_MULTI_MODULE != 0
        table_data = table->table_inst_linked
                         ? (uint32 *)table->table_inst_linked->base_addr
                         : table_data;
#endif
        bh_assert(table_data);

#if WASM_ENABLE_REF_TYPES != 0
        if (!wasm_elem_is_active(table_seg->mode))
            continue;
#endif

        /* init vec(funcidx) or vec(expr) */
#if WASM_ENABLE_REF_TYPES != 0
        bh_assert(table_seg->base_offset.init_expr_type
                      == INIT_EXPR_TYPE_I32_CONST
                  || table_seg->base_offset.init_expr_type
                         == INIT_EXPR_TYPE_GET_GLOBAL
                  || table_seg->base_offset.init_expr_type
                         == INIT_EXPR_TYPE_FUNCREF_CONST
                  || table_seg->base_offset.init_expr_type
                         == INIT_EXPR_TYPE_REFNULL_CONST);
#else
        bh_assert(table_seg->base_offset.init_expr_type
                      == INIT_EXPR_TYPE_I32_CONST
                  || table_seg->base_offset.init_expr_type
                         == INIT_EXPR_TYPE_GET_GLOBAL);
#endif

        if (table_seg->base_offset.init_expr_type
            == INIT_EXPR_TYPE_GET_GLOBAL) {
            if (!check_global_init_expr(module,
                                        table_seg->base_offset.u.global_index,
                                        error_buf, error_buf_size)) {
                goto fail;
            }

            if (!globals
                || globals[table_seg->base_offset.u.global_index].type
                       != VALUE_TYPE_I32) {
                set_error_buf(error_buf, error_buf_size,
                              "elements segment does not fit");
                goto fail;
            }

            table_seg->base_offset.u.i32 =
                globals[table_seg->base_offset.u.global_index]
                    .initial_value.i32;
        }

        /* check offset since length might negative */
        if ((uint32)table_seg->base_offset.u.i32 > table->cur_size) {
            LOG_DEBUG("base_offset(%d) > table->cur_size(%d)",
                      table_seg->base_offset.u.i32, table->cur_size);
#if WASM_ENABLE_REF_TYPES != 0
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds table access");
#else
            set_error_buf(error_buf, error_buf_size,
                          "elements segment does not fit");
#endif
            goto fail;
        }

        /* check offset + length(could be zero) */
        length = table_seg->function_count;
        if ((uint32)table_seg->base_offset.u.i32 + length > table->cur_size) {
            LOG_DEBUG("base_offset(%d) + length(%d)> table->cur_size(%d)",
                      table_seg->base_offset.u.i32, length, table->cur_size);
#if WASM_ENABLE_REF_TYPES != 0
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds table access");
#else
            set_error_buf(error_buf, error_buf_size,
                          "elements segment does not fit");
#endif
            goto fail;
        }

        /**
         * Check function index in the current module inst for now.
         * will check the linked table inst owner in future.
         * so loader check is enough
         */
        bh_memcpy_s(
            table_data + table_seg->base_offset.u.i32,
            (uint32)((table->cur_size - (uint32)table_seg->base_offset.u.i32)
                     * sizeof(uint32)),
            table_seg->func_indexes, (uint32)(length * sizeof(uint32)));
    }

    /* module instance type */
    module_inst->module_type = Wasm_Module_Bytecode;

    /* Initialize the thread related data */
    if (stack_size == 0)
        stack_size = DEFAULT_WASM_STACK_SIZE;
#if WASM_ENABLE_SPEC_TEST != 0
    if (stack_size < 128 * 1024)
        stack_size = 128 * 1024;
#endif
    module_inst->default_wasm_stack_size = stack_size;

    if (module->malloc_function != (uint32)-1) {
        module_inst->malloc_function =
            &module_inst->functions[module->malloc_function];
    }

    if (module->free_function != (uint32)-1) {
        module_inst->free_function =
            &module_inst->functions[module->free_function];
    }

    if (module->retain_function != (uint32)-1) {
        module_inst->retain_function =
            &module_inst->functions[module->retain_function];
    }

#if WASM_ENABLE_LIBC_WASI != 0
    /* The sub-instance will get the wasi_ctx from main-instance */
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
                error_buf, error_buf_size)) {
            goto fail;
        }
    }
#endif

    if (module->start_function != (uint32)-1) {
        /* TODO: fix start function can be import function issue */
        if (module->start_function >= module->import_function_count)
            module_inst->start_function =
                &module_inst->functions[module->start_function];
    }

    /* Execute __post_instantiate function */
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
    (void)global_data_end;

    return module_inst;

fail:
    wasm_deinstantiate(module_inst, false);
    return NULL;
}

void
wasm_deinstantiate(WASMModuleInstance *module_inst, bool is_sub_inst)
{
    if (!module_inst)
        return;

#if WASM_ENABLE_FAST_JIT != 0
    if (module_inst->func_type_indexes)
        wasm_runtime_free(module_inst->func_type_indexes);
#endif

#if WASM_ENABLE_MULTI_MODULE != 0
    sub_module_deinstantiate(module_inst);
#endif

#if WASM_ENABLE_LIBC_WASI != 0
    /* Destroy wasi resource before freeing app heap, since some fields of
       wasi contex are allocated from app heap, and if app heap is freed,
       these fields will be set to NULL, we cannot free their internal data
       which may allocated from global heap. */
    /* Only destroy wasi ctx in the main module instance */
    if (!is_sub_inst)
        wasm_runtime_destroy_wasi((WASMModuleInstanceCommon *)module_inst);
#endif

    if (module_inst->memory_count > 0)
        memories_deinstantiate(module_inst, module_inst->memories,
                               module_inst->memory_count);

    if (module_inst->import_func_ptrs) {
        wasm_runtime_free(module_inst->import_func_ptrs);
    }

    tables_deinstantiate(module_inst->tables, module_inst->table_count);
    functions_deinstantiate(module_inst->functions,
                            module_inst->function_count);
    globals_deinstantiate(module_inst->globals);
    export_functions_deinstantiate(module_inst->export_functions);
#if WASM_ENABLE_MULTI_MODULE != 0
    export_globals_deinstantiate(module_inst->export_globals);
#endif

    if (module_inst->global_data)
        wasm_runtime_free(module_inst->global_data);

#if WASM_ENABLE_REF_TYPES != 0
    wasm_externref_cleanup((WASMModuleInstanceCommon *)module_inst);
#endif

    if (module_inst->exec_env_singleton)
        wasm_exec_env_destroy(module_inst->exec_env_singleton);

#if WASM_ENABLE_DUMP_CALL_STACK != 0
    if (module_inst->frames) {
        bh_vector_destroy(module_inst->frames);
        wasm_runtime_free(module_inst->frames);
        module_inst->frames = NULL;
    }
#endif

#if WASM_ENABLE_DEBUG_INTERP != 0
    if (!is_sub_inst) {
        os_mutex_lock(&module_inst->module->ref_count_lock);
        module_inst->module->ref_count--;
        os_mutex_unlock(&module_inst->module->ref_count_lock);
    }
#endif

    wasm_runtime_free(module_inst);
}

WASMFunctionInstance *
wasm_lookup_function(const WASMModuleInstance *module_inst, const char *name,
                     const char *signature)
{
    uint32 i;
    for (i = 0; i < module_inst->export_func_count; i++)
        if (!strcmp(module_inst->export_functions[i].name, name))
            return module_inst->export_functions[i].function;
    (void)signature;
    return NULL;
}

#if WASM_ENABLE_MULTI_MODULE != 0
WASMGlobalInstance *
wasm_lookup_global(const WASMModuleInstance *module_inst, const char *name)
{
    uint32 i;
    for (i = 0; i < module_inst->export_glob_count; i++)
        if (!strcmp(module_inst->export_globals[i].name, name))
            return module_inst->export_globals[i].global;
    return NULL;
}

WASMMemoryInstance *
wasm_lookup_memory(const WASMModuleInstance *module_inst, const char *name)
{
    /**
     * using a strong assumption that one module instance only has
     * one memory instance
     */
    (void)module_inst->export_memories;
    return module_inst->memories[0];
}

WASMTableInstance *
wasm_lookup_table(const WASMModuleInstance *module_inst, const char *name)
{
    /**
     * using a strong assumption that one module instance only has
     * one table instance
     */
    (void)module_inst->export_tables;
    return module_inst->tables[0];
}
#endif

static bool
clear_wasi_proc_exit_exception(WASMModuleInstance *module_inst)
{
#if WASM_ENABLE_LIBC_WASI != 0
    const char *exception = wasm_get_exception(module_inst);
    if (exception && !strcmp(exception, "Exception: wasi proc exit")) {
        /* The "wasi proc exit" exception is thrown by native lib to
           let wasm app exit, which is a normal behavior, we clear
           the exception here. */
        wasm_set_exception(module_inst, NULL);
        return true;
    }
    return false;
#else
    return false;
#endif
}

#ifdef OS_ENABLE_HW_BOUND_CHECK

#ifndef BH_PLATFORM_WINDOWS
void
wasm_signal_handler(WASMSignalInfo *sig_info)
{
    WASMExecEnv *exec_env_tls = sig_info->exec_env_tls;
    void *sig_addr = sig_info->sig_addr;
    WASMModuleInstance *module_inst;
    WASMMemoryInstance *memory_inst;
    WASMJmpBuf *jmpbuf_node;
    uint8 *mapped_mem_start_addr = NULL;
    uint8 *mapped_mem_end_addr = NULL;
    uint8 *stack_min_addr;
    uint32 page_size;
    uint32 guard_page_count = STACK_OVERFLOW_CHECK_GUARD_PAGE_COUNT;

    /* Check whether current thread is running wasm function */
    if (exec_env_tls && exec_env_tls->handle == os_self_thread()
        && (jmpbuf_node = exec_env_tls->jmpbuf_stack_top)) {
        /* Get mapped mem info of current instance */
        module_inst = (WASMModuleInstance *)exec_env_tls->module_inst;
        /* Get the default memory instance */
        memory_inst = module_inst->default_memory;
        if (memory_inst) {
            mapped_mem_start_addr = (uint8 *)memory_inst->memory_data;
            mapped_mem_end_addr =
                (uint8 *)memory_inst->memory_data + 8 * (uint64)BH_GB;
        }

        /* Get stack info of current thread */
        page_size = os_getpagesize();
        stack_min_addr = os_thread_get_stack_boundary();

        if (memory_inst
            && (mapped_mem_start_addr <= (uint8 *)sig_addr
                && (uint8 *)sig_addr < mapped_mem_end_addr)) {
            /* The address which causes segmentation fault is inside
               the memory instance's guard regions */
            wasm_set_exception(module_inst, "out of bounds memory access");
            os_longjmp(jmpbuf_node->jmpbuf, 1);
        }
        else if (stack_min_addr - page_size <= (uint8 *)sig_addr
                 && (uint8 *)sig_addr
                        < stack_min_addr + page_size * guard_page_count) {
            /* The address which causes segmentation fault is inside
               native thread's guard page */
            wasm_set_exception(module_inst, "native stack overflow");
            os_longjmp(jmpbuf_node->jmpbuf, 1);
        }
    }
}
#else  /* else of BH_PLATFORM_WINDOWS */
LONG
wasm_exception_handler(WASMSignalInfo *sig_info)
{
    WASMExecEnv *exec_env_tls = sig_info->exec_env_tls;
    EXCEPTION_POINTERS *exce_info = sig_info->exce_info;
    PEXCEPTION_RECORD ExceptionRecord = exce_info->ExceptionRecord;
    uint8 *sig_addr = (uint8 *)ExceptionRecord->ExceptionInformation[1];
    WASMModuleInstance *module_inst;
    WASMMemoryInstance *memory_inst;
    WASMJmpBuf *jmpbuf_node;
    uint8 *mapped_mem_start_addr = NULL;
    uint8 *mapped_mem_end_addr = NULL;
    uint32 page_size = os_getpagesize();

    if (exec_env_tls && exec_env_tls->handle == os_self_thread()
        && (jmpbuf_node = exec_env_tls->jmpbuf_stack_top)) {
        module_inst = (WASMModuleInstance *)exec_env_tls->module_inst;
        if (ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            /* Get the default memory instance */
            memory_inst = module_inst->default_memory;
            if (memory_inst) {
                mapped_mem_start_addr = (uint8 *)memory_inst->memory_data;
                mapped_mem_end_addr =
                    (uint8 *)memory_inst->memory_data + 8 * (uint64)BH_GB;
                if (mapped_mem_start_addr <= (uint8 *)sig_addr
                    && (uint8 *)sig_addr < mapped_mem_end_addr) {
                    /* The address which causes segmentation fault is inside
                       the memory instance's guard regions.
                       Set exception and let the wasm func continue to run, when
                       the wasm func returns, the caller will check whether the
                       exception is thrown and return to runtime. */
                    wasm_set_exception(module_inst,
                                       "out of bounds memory access");
                    /* Skip current instruction */
                    return EXCEPTION_CONTINUE_SEARCH;
                }
            }
        }
        else if (ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW) {
            /* Set stack overflow exception and let the wasm func continue
               to run, when the wasm func returns, the caller will check
               whether the exception is thrown and return to runtime, and
               the damaged stack will be recovered by _resetstkoflw(). */
            wasm_set_exception(module_inst, "native stack overflow");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    os_printf("Unhandled exception thrown:  exception code: 0x%lx, "
              "exception address: %p, exception information: %p\n",
              ExceptionRecord->ExceptionCode, ExceptionRecord->ExceptionAddress,
              sig_addr);
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif /* end of BH_PLATFORM_WINDOWS */

static void
call_wasm_with_hw_bound_check(WASMModuleInstance *module_inst,
                              WASMExecEnv *exec_env,
                              WASMFunctionInstance *function, unsigned argc,
                              uint32 argv[])
{
    WASMExecEnv *exec_env_tls = wasm_runtime_get_exec_env_tls();
    WASMJmpBuf jmpbuf_node = { 0 }, *jmpbuf_node_pop;
    uint32 page_size = os_getpagesize();
    uint32 guard_page_count = STACK_OVERFLOW_CHECK_GUARD_PAGE_COUNT;
#ifdef BH_PLATFORM_WINDOWS
    const char *exce;
    int result;
#endif
    bool ret = true;

    /* Check native stack overflow firstly to ensure we have enough
       native stack to run the following codes before actually calling
       the aot function in invokeNative function. */
    if ((uint8 *)&exec_env_tls < exec_env->native_stack_boundary
                                     + page_size * (guard_page_count + 1)) {
        wasm_set_exception(module_inst, "native stack overflow");
        return;
    }

    if (exec_env_tls && (exec_env_tls != exec_env)) {
        wasm_set_exception(module_inst, "invalid exec env");
        return;
    }

    if (!os_thread_signal_inited()) {
        wasm_set_exception(module_inst, "thread signal env not inited");
        return;
    }

    wasm_exec_env_push_jmpbuf(exec_env, &jmpbuf_node);

    wasm_runtime_set_exec_env_tls(exec_env);
    if (os_setjmp(jmpbuf_node.jmpbuf) == 0) {
#ifndef BH_PLATFORM_WINDOWS
        wasm_interp_call_wasm(module_inst, exec_env, function, argc, argv);
#else
        __try {
            wasm_interp_call_wasm(module_inst, exec_env, function, argc, argv);
        } __except (wasm_get_exception(module_inst)
                        ? EXCEPTION_EXECUTE_HANDLER
                        : EXCEPTION_CONTINUE_SEARCH) {
            /* exception was thrown in wasm_exception_handler */
            ret = false;
        }
        if ((exce = wasm_get_exception(module_inst))
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

    if (wasm_get_exception(module_inst)) {
#if WASM_ENABLE_DUMP_CALL_STACK != 0
        if (wasm_interp_create_call_stack(exec_env)) {
            wasm_interp_dump_call_stack(exec_env, true, NULL, 0);
        }
#endif
        wasm_interp_restore_wasm_frame(exec_env);
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
}
#define interp_call_wasm call_wasm_with_hw_bound_check
#else
#define interp_call_wasm wasm_interp_call_wasm
#endif

bool
wasm_call_function(WASMExecEnv *exec_env, WASMFunctionInstance *function,
                   unsigned argc, uint32 argv[])
{
    WASMModuleInstance *module_inst =
        (WASMModuleInstance *)exec_env->module_inst;

    /* set thread handle and stack boundary */
    wasm_exec_env_set_thread_info(exec_env);

    interp_call_wasm(module_inst, exec_env, function, argc, argv);
    (void)clear_wasi_proc_exit_exception(module_inst);
    return !wasm_get_exception(module_inst) ? true : false;
}

bool
wasm_create_exec_env_and_call_function(WASMModuleInstance *module_inst,
                                       WASMFunctionInstance *func,
                                       unsigned argc, uint32 argv[])
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
            wasm_set_exception(module_inst, "allocate memory failed");
            return false;
        }
    }

    ret = wasm_call_function(exec_env, func, argc, argv);

    /* don't destroy the exec_env if it isn't created in this function */
    if (!existing_exec_env)
        wasm_exec_env_destroy(exec_env);

    return ret;
}

bool
wasm_create_exec_env_singleton(WASMModuleInstance *module_inst)
{
    WASMExecEnv *exec_env = NULL;

    if (module_inst->exec_env_singleton) {
        return true;
    }

    exec_env = wasm_exec_env_create((WASMModuleInstanceCommon *)module_inst,
                                    module_inst->default_wasm_stack_size);
    if (exec_env)
        module_inst->exec_env_singleton = exec_env;

    return exec_env ? true : false;
}

void
wasm_set_exception(WASMModuleInstance *module_inst, const char *exception)
{
    if (exception)
        snprintf(module_inst->cur_exception, sizeof(module_inst->cur_exception),
                 "Exception: %s", exception);
    else
        module_inst->cur_exception[0] = '\0';
}

const char *
wasm_get_exception(WASMModuleInstance *module_inst)
{
    if (module_inst->cur_exception[0] == '\0')
        return NULL;
    else
        return module_inst->cur_exception;
}

#if WASM_ENABLE_PERF_PROFILING != 0
void
wasm_dump_perf_profiling(const WASMModuleInstance *module_inst)
{
    WASMExportFuncInstance *export_func;
    WASMFunctionInstance *func_inst;
    char *func_name;
    uint32 i, j;

    os_printf("Performance profiler data:\n");
    for (i = 0; i < module_inst->function_count; i++) {
        func_inst = module_inst->functions + i;
        if (func_inst->is_import_func) {
            func_name = func_inst->u.func_import->field_name;
        }
#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
        else if (func_inst->u.func->field_name) {
            func_name = func_inst->u.func->field_name;
        }
#endif
        else {
            func_name = NULL;
            for (j = 0; j < module_inst->export_func_count; j++) {
                export_func = module_inst->export_functions + j;
                if (export_func->function == func_inst) {
                    func_name = export_func->name;
                    break;
                }
            }
        }

        if (func_name)
            os_printf("  func %s, execution time: %.3f ms, execution count: %d "
                      "times\n",
                      func_name,
                      module_inst->functions[i].total_exec_time / 1000.0f,
                      module_inst->functions[i].total_exec_cnt);
        else
            os_printf("  func %d, execution time: %.3f ms, execution count: %d "
                      "times\n",
                      i, module_inst->functions[i].total_exec_time / 1000.0f,
                      module_inst->functions[i].total_exec_cnt);
    }
}
#endif

uint32
wasm_module_malloc(WASMModuleInstance *module_inst, uint32 size,
                   void **p_native_addr)
{
    WASMMemoryInstance *memory = module_inst->default_memory;
    uint8 *addr = NULL;
    uint32 offset = 0;

    if (!memory) {
        wasm_set_exception(module_inst, "uninitialized memory");
        return 0;
    }

    if (memory->heap_handle) {
        addr = mem_allocator_malloc(memory->heap_handle, size);
    }
    else if (module_inst->malloc_function && module_inst->free_function) {
        if (!execute_malloc_function(module_inst, module_inst->malloc_function,
                                     module_inst->retain_function, size,
                                     &offset)) {
            return 0;
        }
        /* If we use app's malloc function,
           the default memory may be changed while memory growing */
        memory = module_inst->default_memory;
        addr = offset ? memory->memory_data + offset : NULL;
    }

    if (!addr) {
        if (memory->heap_handle
            && mem_allocator_is_heap_corrupted(memory->heap_handle)) {
            wasm_runtime_show_app_heap_corrupted_prompt();
            wasm_set_exception(module_inst, "app heap corrupted");
        }
        else {
            LOG_WARNING("warning: allocate %u bytes memory failed", size);
        }
        return 0;
    }
    if (p_native_addr)
        *p_native_addr = addr;

    return (uint32)(addr - memory->memory_data);
}

uint32
wasm_module_realloc(WASMModuleInstance *module_inst, uint32 ptr, uint32 size,
                    void **p_native_addr)
{
    WASMMemoryInstance *memory = module_inst->default_memory;
    uint8 *addr = NULL;

    if (!memory) {
        wasm_set_exception(module_inst, "uninitialized memory");
        return 0;
    }

    if (memory->heap_handle) {
        addr = mem_allocator_realloc(
            memory->heap_handle, ptr ? memory->memory_data + ptr : NULL, size);
    }

    /* Only support realloc in WAMR's app heap */

    if (!addr) {
        if (memory->heap_handle
            && mem_allocator_is_heap_corrupted(memory->heap_handle)) {
            wasm_set_exception(module_inst, "app heap corrupted");
        }
        else {
            wasm_set_exception(module_inst, "out of memory");
        }
        return 0;
    }
    if (p_native_addr)
        *p_native_addr = addr;

    return (uint32)(addr - memory->memory_data);
}

void
wasm_module_free(WASMModuleInstance *module_inst, uint32 ptr)
{
    if (ptr) {
        WASMMemoryInstance *memory = module_inst->default_memory;
        uint8 *addr;

        if (!memory) {
            return;
        }

        addr = memory->memory_data + ptr;

        if (memory->heap_handle && memory->heap_data <= addr
            && addr < memory->heap_data_end) {
            mem_allocator_free(memory->heap_handle, addr);
        }
        else if (module_inst->malloc_function && module_inst->free_function
                 && memory->memory_data <= addr
                 && addr < memory->memory_data_end) {
            execute_free_function(module_inst, module_inst->free_function, ptr);
        }
    }
}

uint32
wasm_module_dup_data(WASMModuleInstance *module_inst, const char *src,
                     uint32 size)
{
    char *buffer;
    uint32 buffer_offset =
        wasm_module_malloc(module_inst, size, (void **)&buffer);
    if (buffer_offset != 0) {
        buffer = wasm_addr_app_to_native(module_inst, buffer_offset);
        bh_memcpy_s(buffer, size, src, size);
    }
    return buffer_offset;
}

bool
wasm_validate_app_addr(WASMModuleInstance *module_inst, uint32 app_offset,
                       uint32 size)
{
    WASMMemoryInstance *memory = module_inst->default_memory;
    uint32 memory_data_size;

    if (!memory) {
        goto fail;
    }

    memory_data_size = memory->num_bytes_per_page * memory->cur_page_count;

    /* integer overflow check */
    if (app_offset > UINT32_MAX - size) {
        goto fail;
    }

    if (app_offset + size <= memory_data_size) {
        return true;
    }
fail:
    wasm_set_exception(module_inst, "out of bounds memory access");
    return false;
}

bool
wasm_validate_native_addr(WASMModuleInstance *module_inst, void *native_ptr,
                          uint32 size)
{
    WASMMemoryInstance *memory = module_inst->default_memory;
    uint8 *addr = (uint8 *)native_ptr;

    if (!memory) {
        goto fail;
    }

    /* integer overflow check */
    if ((uintptr_t)addr > UINTPTR_MAX - size) {
        goto fail;
    }

    if (memory->memory_data <= addr && addr + size <= memory->memory_data_end) {
        return true;
    }
fail:
    wasm_set_exception(module_inst, "out of bounds memory access");
    return false;
}

void *
wasm_addr_app_to_native(WASMModuleInstance *module_inst, uint32 app_offset)
{
    WASMMemoryInstance *memory = module_inst->default_memory;
    uint8 *addr;

    if (!memory)
        return NULL;

    addr = memory->memory_data + app_offset;

    if (memory->memory_data <= addr && addr < memory->memory_data_end)
        return addr;
    return NULL;
}

uint32
wasm_addr_native_to_app(WASMModuleInstance *module_inst, void *native_ptr)
{
    WASMMemoryInstance *memory = module_inst->default_memory;
    uint8 *addr = (uint8 *)native_ptr;

    if (!memory)
        return 0;

    if (memory->memory_data <= addr && addr < memory->memory_data_end)
        return (uint32)(addr - memory->memory_data);
    return 0;
}

bool
wasm_get_app_addr_range(WASMModuleInstance *module_inst, uint32 app_offset,
                        uint32 *p_app_start_offset, uint32 *p_app_end_offset)
{
    WASMMemoryInstance *memory = module_inst->default_memory;
    uint32 memory_data_size;

    if (!memory)
        return false;

    memory_data_size = memory->num_bytes_per_page * memory->cur_page_count;

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
wasm_get_native_addr_range(WASMModuleInstance *module_inst, uint8 *native_ptr,
                           uint8 **p_native_start_addr,
                           uint8 **p_native_end_addr)
{
    WASMMemoryInstance *memory = module_inst->default_memory;
    uint8 *addr = (uint8 *)native_ptr;

    if (!memory)
        return false;

    if (memory->memory_data <= addr && addr < memory->memory_data_end) {
        if (p_native_start_addr)
            *p_native_start_addr = memory->memory_data;
        if (p_native_end_addr)
            *p_native_end_addr = memory->memory_data_end;
        return true;
    }
    return false;
}

#ifndef OS_ENABLE_HW_BOUND_CHECK
bool
wasm_enlarge_memory(WASMModuleInstance *module, uint32 inc_page_count)
{
    WASMMemoryInstance *memory = module->default_memory;
    uint8 *memory_data_old, *memory_data_new, *heap_data_old;
    uint32 num_bytes_per_page, heap_size, total_size_old;
    uint32 cur_page_count, max_page_count, total_page_count;
    uint64 total_size_new;
    bool ret = true;

    if (!memory)
        return false;

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
        if (mem_allocator_is_heap_corrupted(memory->heap_handle)) {
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

#if WASM_ENABLE_FAST_JIT != 0
#if UINTPTR_MAX == UINT64_MAX
    memory->mem_bound_check_1byte = total_size_new - 1;
    memory->mem_bound_check_2bytes = total_size_new - 2;
    memory->mem_bound_check_4bytes = total_size_new - 4;
    memory->mem_bound_check_8bytes = total_size_new - 8;
    memory->mem_bound_check_16bytes = total_size_new - 16;
#else
    memory->mem_bound_check_1byte = (uint32)total_size_new - 1;
    memory->mem_bound_check_2bytes = (uint32)total_size_new - 2;
    memory->mem_bound_check_4bytes = (uint32)total_size_new - 4;
    memory->mem_bound_check_8bytes = (uint32)total_size_new - 8;
    memory->mem_bound_check_16bytes = (uint32)total_size_new - 16;
#endif
#endif

    return ret;
}
#else
bool
wasm_enlarge_memory(WASMModuleInstance *module, uint32 inc_page_count)
{
    WASMMemoryInstance *memory = module->default_memory;
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
    if (!os_mem_commit(memory->memory_data_end,
                       (uint32)total_size_new - total_size_old,
                       MMAP_PROT_READ | MMAP_PROT_WRITE)) {
        return false;
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
        return false;
    }

    /* The increased pages are filled with zero by the OS when os_mmap,
       no need to memset it again here */

    memory->num_bytes_per_page = num_bytes_per_page;
    memory->cur_page_count = total_page_count;
    memory->max_page_count = max_page_count;
    memory->memory_data_size = (uint32)total_size_new;
    memory->memory_data_end = memory->memory_data + (uint32)total_size_new;

#if WASM_ENABLE_FAST_JIT != 0
    memory->mem_bound_check_1byte = total_size_new - 1;
    memory->mem_bound_check_2bytes = total_size_new - 2;
    memory->mem_bound_check_4bytes = total_size_new - 4;
    memory->mem_bound_check_8bytes = total_size_new - 8;
    memory->mem_bound_check_16bytes = total_size_new - 16;
#endif

    return true;
}
#endif /* end of OS_ENABLE_HW_BOUND_CHECK */

#if WASM_ENABLE_REF_TYPES != 0
bool
wasm_enlarge_table(WASMModuleInstance *module_inst, uint32 table_idx,
                   uint32 inc_entries, uint32 init_val)
{
    uint32 entry_count, *new_table_data_start, i;
    WASMTableInstance *table_inst;

    if (!inc_entries) {
        return true;
    }

    bh_assert(table_idx < module_inst->table_count);
    table_inst = wasm_get_table_inst(module_inst, table_idx);
    if (!table_inst) {
        return false;
    }

    if (inc_entries > UINT32_MAX - table_inst->cur_size) {
        return false;
    }

    entry_count = table_inst->cur_size + inc_entries;
    if (entry_count > table_inst->max_size) {
        return false;
    }

    /* fill in */
    new_table_data_start =
        (uint32 *)((uint8 *)table_inst + offsetof(WASMTableInstance, base_addr))
        + table_inst->cur_size;
    for (i = 0; i < inc_entries; ++i) {
        new_table_data_start[i] = init_val;
    }

    table_inst->cur_size = entry_count;
    return true;
}
#endif /* WASM_ENABLE_REF_TYPES != 0 */

static bool
call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 elem_idx,
              uint32 argc, uint32 argv[], bool check_type_idx, uint32 type_idx)
{
    WASMModuleInstance *module_inst = NULL;
    WASMTableInstance *table_inst = NULL;
    uint32 func_idx = 0;
    WASMFunctionInstance *func_inst = NULL;

    module_inst = (WASMModuleInstance *)exec_env->module_inst;
    bh_assert(module_inst);

    table_inst = module_inst->tables[tbl_idx];
    if (!table_inst) {
        wasm_set_exception(module_inst, "unknown table");
        goto got_exception;
    }

    if (elem_idx >= table_inst->cur_size) {
        wasm_set_exception(module_inst, "undefined element");
        goto got_exception;
    }

    /**
     * please be aware that table_inst->base_addr may point
     * to another module's table
     **/
    func_idx = ((uint32 *)table_inst->base_addr)[elem_idx];
    if (func_idx == NULL_REF) {
        wasm_set_exception(module_inst, "uninitialized element");
        goto got_exception;
    }

    /**
     * we insist to call functions owned by the module itself
     **/
    if (func_idx >= module_inst->function_count) {
        wasm_set_exception(module_inst, "unknown function");
        goto got_exception;
    }

    func_inst = module_inst->functions + func_idx;

    if (check_type_idx) {
        WASMType *cur_type = module_inst->module->types[type_idx];
        WASMType *cur_func_type;

        if (func_inst->is_import_func)
            cur_func_type = func_inst->u.func_import->func_type;
        else
            cur_func_type = func_inst->u.func->func_type;

        if (cur_type != cur_func_type) {
            wasm_set_exception(module_inst, "indirect call type mismatch");
            goto got_exception;
        }
    }

    interp_call_wasm(module_inst, exec_env, func_inst, argc, argv);

    (void)clear_wasi_proc_exit_exception(module_inst);
    return !wasm_get_exception(module_inst) ? true : false;

got_exception:
    return false;
}

bool
wasm_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 elem_idx,
                   uint32 argc, uint32 argv[])
{
    return call_indirect(exec_env, tbl_idx, elem_idx, argc, argv, false, 0);
}

#if WASM_ENABLE_FAST_JIT != 0
bool
jit_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 elem_idx,
                  uint32 type_idx, uint32 argc, uint32 argv[])
{
    return call_indirect(exec_env, tbl_idx, elem_idx, argc, argv, true,
                         type_idx);
}
#endif

#if WASM_ENABLE_THREAD_MGR != 0
bool
wasm_set_aux_stack(WASMExecEnv *exec_env, uint32 start_offset, uint32 size)
{
    WASMModuleInstance *module_inst =
        (WASMModuleInstance *)exec_env->module_inst;
    uint32 stack_top_idx = module_inst->module->aux_stack_top_global_index;
    uint32 data_end = module_inst->module->aux_data_end;
    uint32 stack_bottom = module_inst->module->aux_stack_bottom;
    bool is_stack_before_data = stack_bottom < data_end ? true : false;

    /* Check the aux stack space, currently we don't allocate space in heap */
    if ((is_stack_before_data && (size > start_offset))
        || ((!is_stack_before_data) && (start_offset - data_end < size)))
        return false;

    if (stack_top_idx != (uint32)-1) {
        /* The aux stack top is a wasm global,
            set the initial value for the global */
        uint8 *global_addr = module_inst->global_data
                             + module_inst->globals[stack_top_idx].data_offset;
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
wasm_get_aux_stack(WASMExecEnv *exec_env, uint32 *start_offset, uint32 *size)
{
    WASMModuleInstance *module_inst =
        (WASMModuleInstance *)exec_env->module_inst;

    /* The aux stack information is resolved in loader
        and store in module */
    uint32 stack_bottom = module_inst->module->aux_stack_bottom;
    uint32 total_aux_stack_size = module_inst->module->aux_stack_size;

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
void
wasm_get_module_mem_consumption(const WASMModule *module,
                                WASMModuleMemConsumption *mem_conspn)
{
    uint32 i, size;

    memset(mem_conspn, 0, sizeof(*mem_conspn));

    mem_conspn->module_struct_size = sizeof(WASMModule);

    mem_conspn->types_size = sizeof(WASMType *) * module->type_count;
    for (i = 0; i < module->type_count; i++) {
        WASMType *type = module->types[i];
        size = offsetof(WASMType, types)
               + sizeof(uint8) * (type->param_count + type->result_count);
        mem_conspn->types_size += size;
    }

    mem_conspn->imports_size = sizeof(WASMImport) * module->import_count;

    mem_conspn->functions_size =
        sizeof(WASMFunction *) * module->function_count;
    for (i = 0; i < module->function_count; i++) {
        WASMFunction *func = module->functions[i];
        WASMType *type = func->func_type;
        size = sizeof(WASMFunction) + func->local_count
               + sizeof(uint16) * (type->param_count + func->local_count);
#if WASM_ENABLE_FAST_INTERP != 0
        size +=
            func->code_compiled_size + sizeof(uint32) * func->const_cell_num;
#endif
        mem_conspn->functions_size += size;
    }

    mem_conspn->tables_size = sizeof(WASMTable) * module->table_count;
    mem_conspn->memories_size = sizeof(WASMMemory) * module->memory_count;
    mem_conspn->globals_size = sizeof(WASMGlobal) * module->global_count;
    mem_conspn->exports_size = sizeof(WASMExport) * module->export_count;

    mem_conspn->table_segs_size =
        sizeof(WASMTableSeg) * module->table_seg_count;
    for (i = 0; i < module->table_seg_count; i++) {
        WASMTableSeg *table_seg = &module->table_segments[i];
        mem_conspn->tables_size += sizeof(uint32) * table_seg->function_count;
    }

    mem_conspn->data_segs_size = sizeof(WASMDataSeg *) * module->data_seg_count;
    for (i = 0; i < module->data_seg_count; i++) {
        mem_conspn->data_segs_size += sizeof(WASMDataSeg);
    }

    if (module->const_str_list) {
        StringNode *node = module->const_str_list, *node_next;
        while (node) {
            node_next = node->next;
            mem_conspn->const_strs_size +=
                sizeof(StringNode) + strlen(node->str) + 1;
            node = node_next;
        }
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
}

void
wasm_get_module_inst_mem_consumption(const WASMModuleInstance *module_inst,
                                     WASMModuleInstMemConsumption *mem_conspn)
{
    uint32 i, size;

    memset(mem_conspn, 0, sizeof(*mem_conspn));

    mem_conspn->module_inst_struct_size = sizeof(WASMModuleInstance);

    mem_conspn->memories_size =
        sizeof(WASMMemoryInstance *) * module_inst->memory_count;
    for (i = 0; i < module_inst->memory_count; i++) {
        WASMMemoryInstance *memory = module_inst->memories[i];
        size = sizeof(WASMMemoryInstance)
               + memory->num_bytes_per_page * memory->cur_page_count;
        mem_conspn->memories_size += size;
        mem_conspn->app_heap_size += memory->heap_data_end - memory->heap_data;
        /* size of app heap structure */
        mem_conspn->memories_size += mem_allocator_get_heap_struct_size();
    }

    mem_conspn->tables_size =
        sizeof(WASMTableInstance *) * module_inst->table_count;
    for (i = 0; i < module_inst->table_count; i++) {
        WASMTableInstance *table = module_inst->tables[i];
#if WASM_ENABLE_MULTI_MODULE != 0
        if (table->table_inst_linked) {
            size = offsetof(WASMTableInstance, base_addr);
        }
        else
#endif
        {
            size = offsetof(WASMTableInstance, base_addr)
                   + sizeof(uint32) * table->cur_size;
        }
        mem_conspn->tables_size += size;
    }

    mem_conspn->functions_size =
        sizeof(WASMFunctionInstance) * module_inst->function_count;

    mem_conspn->globals_size =
        sizeof(WASMGlobalInstance) * module_inst->global_count;
    if (module_inst->global_count > 0) {
        WASMGlobalInstance *global =
            &module_inst->globals[module_inst->global_count - 1];
        mem_conspn->globals_size +=
            global->data_offset + wasm_value_type_size(global->type);
    }

    mem_conspn->exports_size =
        sizeof(WASMExportFuncInstance) * module_inst->export_func_count;

    mem_conspn->total_size += mem_conspn->module_inst_struct_size;
    mem_conspn->total_size += mem_conspn->memories_size;
    mem_conspn->total_size += mem_conspn->functions_size;
    mem_conspn->total_size += mem_conspn->tables_size;
    mem_conspn->total_size += mem_conspn->globals_size;
    mem_conspn->total_size += mem_conspn->exports_size;
}
#endif /* end of (WASM_ENABLE_MEMORY_PROFILING != 0) \
                 || (WASM_ENABLE_MEMORY_TRACING != 0) */

#if WASM_ENABLE_DUMP_CALL_STACK != 0
bool
wasm_interp_create_call_stack(struct WASMExecEnv *exec_env)
{
    WASMModuleInstance *module_inst =
        (WASMModuleInstance *)wasm_exec_env_get_module_inst(exec_env);
    WASMInterpFrame *first_frame,
        *cur_frame = wasm_exec_env_get_cur_frame(exec_env);
    uint32 n = 0;

    /* count frames includes a function */
    first_frame = cur_frame;
    while (cur_frame) {
        if (cur_frame->function) {
            n++;
        }
        cur_frame = cur_frame->prev_frame;
    }

    /* release previous stack frames and create new ones */
    if (!bh_vector_destroy(module_inst->frames)
        || !bh_vector_init(module_inst->frames, n, sizeof(WASMCApiFrame),
                           false)) {
        return false;
    }

    cur_frame = first_frame;
    n = 0;

    while (cur_frame) {
        WASMCApiFrame frame = { 0 };
        WASMFunctionInstance *func_inst = cur_frame->function;
        const char *func_name = NULL;
        const uint8 *func_code_base = NULL;

        if (!func_inst) {
            cur_frame = cur_frame->prev_frame;
            continue;
        }

        /* place holder, will overwrite it in wasm_c_api */
        frame.instance = module_inst;
        frame.module_offset = 0;
        frame.func_index = (uint32)(func_inst - module_inst->functions);

        func_code_base = wasm_get_func_code(func_inst);
        if (!cur_frame->ip || !func_code_base) {
            frame.func_offset = 0;
        }
        else {
            frame.func_offset = (uint32)(cur_frame->ip - func_code_base);
        }

        /* look for the function name */
        if (func_inst->is_import_func) {
            func_name = func_inst->u.func_import->field_name;
        }
        else {
#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
            func_name = func_inst->u.func->field_name;
#endif
            /* if custom name section is not generated,
                search symbols from export table */
            if (!func_name) {
                uint32 i;
                for (i = 0; i < module_inst->export_func_count; i++) {
                    WASMExportFuncInstance *export_func =
                        module_inst->export_functions + i;
                    if (export_func->function == func_inst) {
                        func_name = export_func->name;
                        break;
                    }
                }
            }
        }

        frame.func_name_wp = func_name;

        if (!bh_vector_append(module_inst->frames, &frame)) {
            bh_vector_destroy(module_inst->frames);
            return false;
        }

        cur_frame = cur_frame->prev_frame;
        n++;
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
wasm_interp_dump_call_stack(struct WASMExecEnv *exec_env, bool print, char *buf,
                            uint32 len)
{
    WASMModuleInstance *module_inst =
        (WASMModuleInstance *)wasm_exec_env_get_module_inst(exec_env);
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

    snprintf(line_buf, sizeof(line_buf), "\n");
    PRINT_OR_DUMP();

    while (n < total_frames) {
        WASMCApiFrame frame = { 0 };
        uint32 line_length, i;

        if (!bh_vector_get(module_inst->frames, n, &frame)) {
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
