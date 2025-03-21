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
#include "../common/wasm_memory.h"
#if WASM_ENABLE_SHARED_MEMORY != 0
#include "../common/wasm_shared_memory.h"
#endif
#if WASM_ENABLE_THREAD_MGR != 0
#include "../libraries/thread-mgr/thread_manager.h"
#endif
#if WASM_ENABLE_DEBUG_INTERP != 0
#include "../libraries/debug-engine/debug_engine.h"
#endif
#if WASM_ENABLE_FAST_JIT != 0
#include "../fast-jit/jit_compiler.h"
#endif
#if WASM_ENABLE_JIT != 0
#include "../aot/aot_runtime.h"
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
wasm_load(uint8 *buf, uint32 size,
#if WASM_ENABLE_MULTI_MODULE != 0
          bool main_module,
#endif
          char *error_buf, uint32 error_buf_size)
{
    return wasm_loader_load(buf, size,
#if WASM_ENABLE_MULTI_MODULE != 0
                            main_module,
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
    bh_list *sub_module_inst_list = parent_module_inst->e->sub_module_inst_list;
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
#ifdef WASM_LINEAR_MEMORY_MMAP
    uint64 map_size;
#endif
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
                if (shared_memory_is_shared(memories[i])) {
                    uint32 ref_count = shared_memory_dec_reference(memories[i]);
                    /* if the reference count is not zero,
                        don't free the memory */
                    if (ref_count > 0)
                        continue;
                }
#endif
                if (memories[i]->heap_handle) {
                    mem_allocator_destroy(memories[i]->heap_handle);
                    wasm_runtime_free(memories[i]->heap_handle);
                    memories[i]->heap_handle = NULL;
                }
                if (memories[i]->memory_data) {
#ifndef OS_ENABLE_HW_BOUND_CHECK
#ifdef WASM_LINEAR_MEMORY_MMAP
                    if (shared_memory_is_shared(memories[i])) {
                        map_size = (uint64)memories[i]->num_bytes_per_page
                                   * memories[i]->max_page_count;
                        wasm_munmap_linear_memory(memories[i]->memory_data,
                                                  map_size, map_size);
                    }
                    else
#endif
                        wasm_runtime_free(memories[i]->memory_data);
#else
                    map_size = (uint64)memories[i]->num_bytes_per_page
                               * memories[i]->cur_page_count;
                    wasm_munmap_linear_memory(memories[i]->memory_data,
                                              map_size, 8 * (uint64)BH_GB);
#endif
                }
            }
        }
        wasm_runtime_free(memories);
    }
    (void)module_inst;
}

static WASMMemoryInstance *
memory_instantiate(WASMModuleInstance *module_inst, WASMModuleInstance *parent,
                   WASMMemoryInstance *memory, uint32 memory_idx,
                   uint32 num_bytes_per_page, uint32 init_page_count,
                   uint32 max_page_count, uint32 heap_size, uint32 flags,
                   char *error_buf, uint32 error_buf_size)
{
    WASMModule *module = module_inst->module;
    uint64 memory_data_size, max_memory_data_size;
    uint32 heap_offset = num_bytes_per_page * init_page_count;
    uint32 inc_page_count, aux_heap_base, global_idx;
    uint32 bytes_of_last_page, bytes_to_page_end;
    uint8 *global_addr;
#ifdef WASM_LINEAR_MEMORY_MMAP
    uint8 *mapped_mem = NULL;
    uint64 map_size;
#endif

#if WASM_ENABLE_SHARED_MEMORY != 0
    bool is_shared_memory = flags & 0x02 ? true : false;

    /* shared memory */
    if (is_shared_memory && parent != NULL) {
        bh_assert(parent->memory_count > memory_idx);
        memory = parent->memories[memory_idx];
        shared_memory_inc_reference(memory);
        return memory;
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
            global_idx = module->aux_heap_base_global_index;
            bh_assert(module_inst->e->globals
                      && global_idx < module_inst->e->global_count);
            global_addr = module_inst->global_data
                          + module_inst->e->globals[global_idx].data_offset;
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
    LOG_VERBOSE("  heap offset: %u, heap size: %d\n", heap_offset, heap_size);

    memory_data_size = (uint64)num_bytes_per_page * init_page_count;
    max_memory_data_size = (uint64)num_bytes_per_page * max_page_count;
    bh_assert(memory_data_size <= UINT32_MAX);
    bh_assert(max_memory_data_size <= 4 * (uint64)BH_GB);
    (void)max_memory_data_size;

    bh_assert(memory != NULL);

#ifndef OS_ENABLE_HW_BOUND_CHECK
#if WASM_ENABLE_SHARED_MEMORY != 0
    if (is_shared_memory) {
        /* Allocate maximum memory size when memory is shared */
#if WASM_ENABLE_SHARED_MEMORY_MMAP != 0
        map_size = max_memory_data_size;
        if (max_memory_data_size > 0
            && !(memory->memory_data = mapped_mem =
                     wasm_mmap_linear_memory(map_size, &max_memory_data_size,
                                             error_buf, error_buf_size))) {
            goto fail1;
        }
#else
        if (max_memory_data_size > 0
            && !(memory->memory_data = runtime_malloc(
                     max_memory_data_size, error_buf, error_buf_size))) {
            goto fail1;
        }
#endif
    }
    else
#endif /* end of WASM_ENABLE_SHARED_MEMORY != 0 */
    {
        /* Allocate initial memory size when memory is not shared */
        if (memory_data_size > 0
            && !(memory->memory_data = runtime_malloc(
                     memory_data_size, error_buf, error_buf_size))) {
            goto fail1;
        }
    }
#else  /* else of OS_ENABLE_HW_BOUND_CHECK */
    /* Totally 8G is mapped, the opcode load/store address range is 0 to 8G:
     *   ea = i + memarg.offset
     * both i and memarg.offset are u32 in range 0 to 4G
     * so the range of ea is 0 to 8G
     */
    map_size = 8 * (uint64)BH_GB;
    if (!(memory->memory_data = mapped_mem = wasm_mmap_linear_memory(
              map_size, &memory_data_size, error_buf, error_buf_size))) {
        set_error_buf(error_buf, error_buf_size, "mmap memory failed");
        goto fail1;
    }
#endif /* end of OS_ENABLE_HW_BOUND_CHECK */

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

    if (memory_data_size > 0) {
        wasm_runtime_set_mem_bound_check_bytes(memory, memory_data_size);
    }

#if WASM_ENABLE_SHARED_MEMORY != 0
    if (is_shared_memory) {
        memory->is_shared_memory = 1;
        memory->ref_count = 1;
    }
#endif

    LOG_VERBOSE("Memory instantiate success.");
    return memory;

fail3:
    if (heap_size > 0)
        wasm_runtime_free(memory->heap_handle);
fail2:
#ifdef WASM_LINEAR_MEMORY_MMAP
    if (mapped_mem)
        wasm_munmap_linear_memory(mapped_mem, memory_data_size, map_size);
    else
#endif
    {
        if (memory->memory_data)
            wasm_runtime_free(memory->memory_data);
    }
fail1:
    return NULL;
}

/**
 * Instantiate memories in a module.
 */
static WASMMemoryInstance **
memories_instantiate(const WASMModule *module, WASMModuleInstance *module_inst,
                     WASMModuleInstance *parent, uint32 heap_size,
                     char *error_buf, uint32 error_buf_size)
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

    memory = module_inst->global_table_data.memory_instances;

    /* instantiate memories from import section */
    import = module->import_memories;
    for (i = 0; i < module->import_memory_count; i++, import++, memory++) {
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

            if (!(memories[mem_index++] = wasm_lookup_memory(
                      module_inst_linked, import->u.memory.field_name))) {
                set_error_buf(error_buf, error_buf_size, "unknown memory");
                memories_deinstantiate(module_inst, memories, memory_count);
                return NULL;
            }
        }
        else
#endif
        {
            if (!(memories[mem_index] = memory_instantiate(
                      module_inst, parent, memory, mem_index,
                      num_bytes_per_page, init_page_count, max_page_count,
                      actual_heap_size, flags, error_buf, error_buf_size))) {
                memories_deinstantiate(module_inst, memories, memory_count);
                return NULL;
            }
            mem_index++;
        }
    }

    /* instantiate memories from memory section */
    for (i = 0; i < module->memory_count; i++, memory++) {
        if (!(memories[mem_index] = memory_instantiate(
                  module_inst, parent, memory, mem_index,
                  module->memories[i].num_bytes_per_page,
                  module->memories[i].init_page_count,
                  module->memories[i].max_page_count, heap_size,
                  module->memories[i].flags, error_buf, error_buf_size))) {
            memories_deinstantiate(module_inst, memories, memory_count);
            return NULL;
        }
        mem_index++;
    }

    bh_assert(mem_index == memory_count);
    (void)module_inst;
    return memories;
}

/**
 * Destroy table instances.
 */
static void
tables_deinstantiate(WASMModuleInstance *module_inst)
{
    if (module_inst->tables) {
        wasm_runtime_free(module_inst->tables);
    }
#if WASM_ENABLE_MULTI_MODULE != 0
    if (module_inst->e->table_insts_linked) {
        wasm_runtime_free(module_inst->e->table_insts_linked);
    }
#endif
}

/**
 * Instantiate tables in a module.
 */
static WASMTableInstance **
tables_instantiate(const WASMModule *module, WASMModuleInstance *module_inst,
                   WASMTableInstance *first_table, char *error_buf,
                   uint32 error_buf_size)
{
    WASMImport *import;
    uint32 table_index = 0, i;
    uint32 table_count = module->import_table_count + module->table_count;
    uint64 total_size = (uint64)sizeof(WASMTableInstance *) * table_count;
    WASMTableInstance **tables, *table = first_table;
#if WASM_ENABLE_MULTI_MODULE != 0
    uint64 total_size_of_tables_linked =
        (uint64)sizeof(WASMTableInstance *) * module->import_table_count;
    WASMTableInstance **table_linked = NULL;
#endif

    if (!(tables = runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

#if WASM_ENABLE_MULTI_MODULE != 0
    if (module->import_table_count > 0
        && !(module_inst->e->table_insts_linked = table_linked = runtime_malloc(
                 total_size_of_tables_linked, error_buf, error_buf_size))) {
        goto fail;
    }
#endif

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
                goto fail;
            }

            if (!(table_inst_linked = wasm_lookup_table(
                      module_inst_linked, import->u.table.field_name))) {
                set_error_buf(error_buf, error_buf_size, "unknown table");
                goto fail;
            }

            total_size = offsetof(WASMTableInstance, elems);
        }
        else
#endif
        {
            /* in order to save memory, alloc resource as few as possible */
            max_size_fixed = import->u.table.possible_grow
                                 ? import->u.table.max_size
                                 : import->u.table.init_size;

            /* it is a built-in table, every module has its own */
            total_size = offsetof(WASMTableInstance, elems);
            total_size += (uint64)max_size_fixed * sizeof(uint32);
        }

        tables[table_index++] = table;

        /* Set all elements to -1 to mark them as uninitialized elements */
        memset(table, -1, (uint32)total_size);

#if WASM_ENABLE_MULTI_MODULE != 0
        *table_linked = table_inst_linked;
        if (table_inst_linked != NULL) {
            table->cur_size = table_inst_linked->cur_size;
            table->max_size = table_inst_linked->max_size;
        }
        else
#endif
        {
            table->cur_size = import->u.table.init_size;
            table->max_size = max_size_fixed;
        }

        table = (WASMTableInstance *)((uint8 *)table + (uint32)total_size);
#if WASM_ENABLE_MULTI_MODULE != 0
        table_linked++;
#endif
    }

    /* instantiate tables from table section */
    for (i = 0; i < module->table_count; i++) {
        uint32 max_size_fixed = 0;

        total_size = offsetof(WASMTableInstance, elems);
#if WASM_ENABLE_MULTI_MODULE != 0
        /* in case, a module which imports this table will grow it */
        max_size_fixed = module->tables[i].max_size;
#else
        max_size_fixed = module->tables[i].possible_grow
                             ? module->tables[i].max_size
                             : module->tables[i].init_size;
#endif
        total_size += sizeof(uint32) * (uint64)max_size_fixed;

        tables[table_index++] = table;

        /* Set all elements to -1 to mark them as uninitialized elements */
        memset(table, -1, (uint32)total_size);
        table->cur_size = module->tables[i].init_size;
        table->max_size = max_size_fixed;

        table = (WASMTableInstance *)((uint8 *)table + (uint32)total_size);
    }

    bh_assert(table_index == table_count);
    (void)module_inst;
    return tables;
#if WASM_ENABLE_MULTI_MODULE != 0
fail:
    wasm_runtime_free(tables);
    return NULL;
#endif
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
    bh_assert((uint32)(function - functions) == function_count);

#if WASM_ENABLE_FAST_JIT != 0
    module_inst->fast_jit_func_ptrs = module->fast_jit_func_ptrs;
#endif

    return functions;
}

#if WASM_ENABLE_TAGS != 0
/**
 * Destroy tags instances.
 */
static void
tags_deinstantiate(WASMTagInstance *tags, void **import_tag_ptrs)
{
    if (tags) {
        wasm_runtime_free(tags);
    }
    if (import_tag_ptrs) {
        wasm_runtime_free(import_tag_ptrs);
    }
}

/**
 * Instantiate tags in a module.
 */
static WASMTagInstance *
tags_instantiate(const WASMModule *module, WASMModuleInstance *module_inst,
                 char *error_buf, uint32 error_buf_size)
{
    WASMImport *import;
    uint32 i, tag_count = module->import_tag_count + module->tag_count;
    uint64 total_size = sizeof(WASMTagInstance) * (uint64)tag_count;
    WASMTagInstance *tags, *tag;

    if (!(tags = runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    total_size = sizeof(void *) * (uint64)module->import_tag_count;
    if (total_size > 0
        && !(module_inst->e->import_tag_ptrs =
                 runtime_malloc(total_size, error_buf, error_buf_size))) {
        wasm_runtime_free(tags);
        return NULL;
    }

    /* instantiate tags from import section */
    tag = tags;
    import = module->import_tags;
    for (i = 0; i < module->import_tag_count; i++, import++) {
        tag->is_import_tag = true;
        tag->u.tag_import = &import->u.tag;
        tag->type = import->u.tag.type;
        tag->attribute = import->u.tag.attribute;
#if WASM_ENABLE_MULTI_MODULE != 0
        if (import->u.tag.import_module) {
            if (!(tag->import_module_inst = get_sub_module_inst(
                      module_inst, import->u.tag.import_module))) {
                set_error_buf(error_buf, error_buf_size, "unknown tag");
                goto fail;
            }

            if (!(tag->import_tag_inst =
                      wasm_lookup_tag(tag->import_module_inst,
                                      import->u.tag.field_name, NULL))) {
                set_error_buf(error_buf, error_buf_size, "unknown tag");
                goto fail;
            }

            /* Copy the imported tag to current instance */
            module_inst->e->import_tag_ptrs[i] =
                tag->u.tag_import->import_tag_linked;
        }
#endif
        tag++;
    }

    /* instantiate tags from tag section */
    for (i = 0; i < module->tag_count; i++) {
        tag->is_import_tag = false;
        tag->type = module->tags[i]->type;
        tag->u.tag = module->tags[i];

#if WASM_ENABLE_FAST_INTERP != 0
        /* tag->const_cell_num = function->u.func->const_cell_num; */
#endif
        tag++;
    }
    bh_assert((uint32)(tag - tags) == tag_count);

    return tags;

#if WASM_ENABLE_MULTI_MODULE != 0
fail:
    tags_deinstantiate(tags, module_inst->e->import_tag_ptrs);
    /* clean up */
    module_inst->e->import_tag_ptrs = NULL;
    return NULL;
#endif
}
#endif

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
                    char *error_buf, uint32 error_buf_size)
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
#if WASM_ENABLE_FAST_JIT != 0
        bh_assert(global_data_offset == global_import->data_offset);
#endif
        global->data_offset = global_data_offset;
        global_data_offset += wasm_value_type_size(global->type);

        global++;
    }

    /* instantiate globals from global section */
    for (i = 0; i < module->global_count; i++) {
        InitializerExpression *init_expr = &(module->globals[i].init_expr);

        global->type = module->globals[i].type;
        global->is_mutable = module->globals[i].is_mutable;
#if WASM_ENABLE_FAST_JIT != 0
        bh_assert(global_data_offset == module->globals[i].data_offset);
#endif
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
    bh_assert(global_data_offset == module->global_data_size);
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
            export_func->function = &module_inst->e->functions[export->index];
            export_func++;
        }

    bh_assert((uint32)(export_func - export_funcs) == export_func_count);
    return export_funcs;
}

#if WASM_ENABLE_TAGS != 0
/**
 * Destroy export function instances.
 */
static void
export_tags_deinstantiate(WASMExportTagInstance *tags)
{
    if (tags)
        wasm_runtime_free(tags);
}

/**
 * Instantiate export functions in a module.
 */
static WASMExportTagInstance *
export_tags_instantiate(const WASMModule *module,
                        WASMModuleInstance *module_inst,
                        uint32 export_tag_count, char *error_buf,
                        uint32 error_buf_size)
{
    WASMExportTagInstance *export_tags, *export_tag;
    WASMExport *export = module->exports;
    uint32 i;
    uint64 total_size =
        sizeof(WASMExportTagInstance) * (uint64)export_tag_count;

    if (!(export_tag = export_tags =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    for (i = 0; i < module->export_count; i++, export ++)
        if (export->kind == EXPORT_KIND_TAG) {
            export_tag->name = export->name;

            bh_assert(module_inst->e->tags);

            export_tag->tag = &module_inst->e->tags[export->index];
            export_tag++;
        }

    bh_assert((uint32)(export_tag - export_tags) == export_tag_count);
    return export_tags;
}
#endif

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
            export_global->global = &module_inst->e->globals[export->index];
            export_global++;
        }

    bh_assert((uint32)(export_global - export_globals) == export_glob_count);
    return export_globals;
}
#endif

static WASMFunctionInstance *
lookup_post_instantiate_func(WASMModuleInstance *module_inst,
                             const char *func_name)
{
    WASMFunctionInstance *func;
    WASMType *func_type;

    if (!(func = wasm_lookup_function(module_inst, func_name, NULL)))
        /* Not found */
        return NULL;

    func_type = func->u.func->func_type;
    if (!(func_type->param_count == 0 && func_type->result_count == 0))
        /* Not a valid function type, ignore it */
        return NULL;

    return func;
}

static bool
execute_post_instantiate_functions(WASMModuleInstance *module_inst,
                                   bool is_sub_inst, WASMExecEnv *exec_env_main)
{
    WASMFunctionInstance *start_func = module_inst->e->start_function;
    WASMFunctionInstance *initialize_func = NULL;
    WASMFunctionInstance *post_inst_func = NULL;
    WASMFunctionInstance *call_ctors_func = NULL;
#if WASM_ENABLE_LIBC_WASI != 0
    WASMModule *module = module_inst->module;
#endif
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

    if (!start_func && !initialize_func && !post_inst_func
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
                wasm_set_exception(module_inst, "allocate memory failed");
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

    /* Execute start function for both main insance and sub instance */
    if (start_func && !wasm_call_function(exec_env, start_func, 0, NULL)) {
        goto fail;
    }

#if WASM_ENABLE_LIBC_WASI != 0
    if (initialize_func
        && !wasm_call_function(exec_env, initialize_func, 0, NULL)) {
        goto fail;
    }
#else
    (void)initialize_func;
#endif

    if (post_inst_func
        && !wasm_call_function(exec_env, post_inst_func, 0, NULL)) {
        goto fail;
    }

    if (call_ctors_func
        && !wasm_call_function(exec_env, call_ctors_func, 0, NULL)) {
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
execute_malloc_function(WASMModuleInstance *module_inst, WASMExecEnv *exec_env,
                        WASMFunctionInstance *malloc_func,
                        WASMFunctionInstance *retain_func, uint32 size,
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

    ret = wasm_call_function(exec_env, malloc_func, argc, argv);

    if (retain_func && ret)
        ret = wasm_call_function(exec_env, retain_func, 1, argv);

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
execute_free_function(WASMModuleInstance *module_inst, WASMExecEnv *exec_env,
                      WASMFunctionInstance *free_func, uint32 offset)
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

    ret = wasm_call_function(exec_env, free_func, 1, argv);

    if (module_inst_old)
        /* Restore the existing exec_env's module inst */
        wasm_exec_env_restore_module_inst(exec_env, module_inst_old);

    if (exec_env_created)
        wasm_exec_env_destroy(exec_env_created);

    return ret;
}

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
            /* will throw exception only if calling */
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
            set_error_buf_v(error_buf, error_buf_size,
                            "failed to link import global (%s, %s)",
                            global->module_name, global->field_name);
            return false;
#else
            /* do nothing to avoid confused message */
#endif /* WASM_ENABLE_WAMR_COMPILER == 0 */
#endif /* WASM_ENABLE_SPEC_TEST != 0 */
        }
    }

    return true;
}

#if WASM_ENABLE_JIT != 0
static bool
init_func_ptrs(WASMModuleInstance *module_inst, WASMModule *module,
               char *error_buf, uint32 error_buf_size)
{
    uint32 i;
    void **func_ptrs;
    uint64 total_size = (uint64)sizeof(void *) * module_inst->e->function_count;

    /* Allocate memory */
    if (!(func_ptrs = module_inst->func_ptrs =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    /* Set import function pointers */
    for (i = 0; i < module->import_function_count; i++, func_ptrs++) {
        WASMFunctionImport *import_func =
            &module->import_functions[i].u.function;
        /* TODO: handle multi module */
        *func_ptrs = import_func->func_ptr_linked;
    }

    /* The defined function pointers will be set in
       wasm_runtime_set_running_mode, no need to set them here */
    return true;
}
#endif /* end of WASM_ENABLE_JIT != 0 */

#if WASM_ENABLE_FAST_JIT != 0 || WASM_ENABLE_JIT != 0
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
    uint64 total_size = (uint64)sizeof(uint32) * module_inst->e->function_count;

    /* Allocate memory */
    if (!(module_inst->func_type_indexes =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    for (i = 0; i < module_inst->e->function_count; i++) {
        WASMFunctionInstance *func_inst = module_inst->e->functions + i;
        WASMType *func_type = func_inst->is_import_func
                                  ? func_inst->u.func_import->func_type
                                  : func_inst->u.func->func_type;
        module_inst->func_type_indexes[i] =
            get_smallest_type_idx(module_inst->module, func_type);
    }

    return true;
}
#endif /* end of WASM_ENABLE_FAST_JIT != 0 || WASM_ENABLE_JIT != 0 */

static bool
set_running_mode(WASMModuleInstance *module_inst, RunningMode running_mode,
                 bool first_time_set)
{
    WASMModule *module = module_inst->module;

    if (running_mode == Mode_Default) {
#if WASM_ENABLE_FAST_JIT == 0 && WASM_ENABLE_JIT == 0
        running_mode = Mode_Interp;
#elif WASM_ENABLE_FAST_JIT != 0 && WASM_ENABLE_JIT == 0
        running_mode = Mode_Fast_JIT;
#elif WASM_ENABLE_FAST_JIT == 0 && WASM_ENABLE_JIT != 0
        running_mode = Mode_LLVM_JIT;
#else /* WASM_ENABLE_FAST_JIT != 0 && WASM_ENABLE_JIT != 0 */
#if WASM_ENABLE_LAZY_JIT == 0
        running_mode = Mode_LLVM_JIT;
#else
        running_mode = Mode_Multi_Tier_JIT;
#endif
#endif
    }

    if (!wasm_runtime_is_running_mode_supported(running_mode))
        return false;

#if !(WASM_ENABLE_FAST_JIT != 0 && WASM_ENABLE_JIT != 0 \
      && WASM_ENABLE_LAZY_JIT != 0) /* No possible multi-tier JIT */
    module_inst->e->running_mode = running_mode;

    if (running_mode == Mode_Interp) {
        /* Do nothing for Mode_Interp */
    }
    else if (running_mode == Mode_Fast_JIT) {
        /* Do nothing for Mode_Fast_JIT since
           module_inst->fast_jit_func_ptrs is same as
           module->fast_jit_func_ptrs */
    }
#if WASM_ENABLE_JIT != 0
    else if (running_mode == Mode_LLVM_JIT) {
        /* Set defined function pointers */
        bh_memcpy_s(module_inst->func_ptrs + module->import_function_count,
                    sizeof(void *) * module->function_count, module->func_ptrs,
                    sizeof(void *) * module->function_count);
    }
#endif
    else {
        bh_assert(0);
    }
#else /* Possible multi-tier JIT */
    os_mutex_lock(&module->instance_list_lock);

    module_inst->e->running_mode = running_mode;

    if (running_mode == Mode_Interp) {
        /* Do nothing for Mode_Interp */
    }
#if WASM_ENABLE_FAST_JIT != 0
    else if (running_mode == Mode_Fast_JIT) {
        JitGlobals *jit_globals = jit_compiler_get_jit_globals();
        uint32 i;

        /* Allocate memory for fast_jit_func_ptrs if needed */
        if (!module_inst->fast_jit_func_ptrs
            || module_inst->fast_jit_func_ptrs == module->fast_jit_func_ptrs) {
            uint64 total_size = (uint64)sizeof(void *) * module->function_count;
            if (!(module_inst->fast_jit_func_ptrs =
                      runtime_malloc(total_size, NULL, 0))) {
                os_mutex_unlock(&module->instance_list_lock);
                return false;
            }
        }

        for (i = 0; i < module->function_count; i++) {
            if (module->functions[i]->fast_jit_jitted_code) {
                /* current fast jit function has been compiled */
                module_inst->fast_jit_func_ptrs[i] =
                    module->functions[i]->fast_jit_jitted_code;
            }
            else {
                module_inst->fast_jit_func_ptrs[i] =
                    jit_globals->compile_fast_jit_and_then_call;
            }
        }
    }
#endif
#if WASM_ENABLE_JIT != 0
    else if (running_mode == Mode_LLVM_JIT) {
        void **llvm_jit_func_ptrs;
        uint32 i;

        /* Notify backend threads to start llvm jit compilation */
        module->enable_llvm_jit_compilation = true;

        /* Wait until llvm jit finishes initialization */
        os_mutex_lock(&module->tierup_wait_lock);
        while (!module->llvm_jit_inited) {
            os_cond_reltimedwait(&module->tierup_wait_cond,
                                 &module->tierup_wait_lock, 10000);
            if (module->orcjit_stop_compiling) {
                /* init_llvm_jit_functions_stage2 failed */
                os_mutex_unlock(&module->tierup_wait_lock);
                os_mutex_unlock(&module->instance_list_lock);
                return false;
            }
        }
        os_mutex_unlock(&module->tierup_wait_lock);

        llvm_jit_func_ptrs =
            module_inst->func_ptrs + module->import_function_count;
        for (i = 0; i < module->function_count; i++) {
            llvm_jit_func_ptrs[i] = module->functions[i]->llvm_jit_func_ptr;
        }
    }
#endif
    else if (running_mode == Mode_Multi_Tier_JIT) {
        /* Notify backend threads to start llvm jit compilation */
        module->enable_llvm_jit_compilation = true;

        /* Free fast_jit_func_ptrs if it is allocated before */
        if (module_inst->fast_jit_func_ptrs
            && module_inst->fast_jit_func_ptrs != module->fast_jit_func_ptrs) {
            wasm_runtime_free(module_inst->fast_jit_func_ptrs);
        }
        module_inst->fast_jit_func_ptrs = module->fast_jit_func_ptrs;

        /* Copy all llvm jit func ptrs from the module */
        bh_memcpy_s(module_inst->func_ptrs + module->import_function_count,
                    sizeof(void *) * module->function_count, module->func_ptrs,
                    sizeof(void *) * module->function_count);
    }
    else {
        bh_assert(0);
    }

    /* Add module instance into module's instance list if not added */
    if (first_time_set) {
        bool found = false;
        WASMModuleInstance *node = module->instance_list;

        while (node) {
            if (node == module_inst) {
                found = true;
                break;
            }
            node = node->e->next;
        }

        if (!found) {
            module_inst->e->next = module->instance_list;
            module->instance_list = module_inst;
        }
    }

    os_mutex_unlock(&module->instance_list_lock);
#endif /* end of !(WASM_ENABLE_FAST_JIT != 0 && WASM_ENABLE_JIT != 0 \
                   && WASM_ENABLE_LAZY_JIT != 0) */

    (void)module;
    return true;
}

bool
wasm_set_running_mode(WASMModuleInstance *module_inst, RunningMode running_mode)
{
    return set_running_mode(module_inst, running_mode, false);
}

/**
 * Instantiate module
 */
WASMModuleInstance *
wasm_instantiate(WASMModule *module, WASMModuleInstance *parent,
                 WASMExecEnv *exec_env_main, uint32 stack_size,
                 uint32 heap_size, char *error_buf, uint32 error_buf_size)
{
    WASMModuleInstance *module_inst;
    WASMGlobalInstance *globals = NULL, *global;
    WASMTableInstance *first_table;
    uint32 global_count, i;
    uint32 base_offset, length, extra_info_offset;
    uint32 module_inst_struct_size =
        offsetof(WASMModuleInstance, global_table_data.bytes);
    uint64 module_inst_mem_inst_size;
    uint64 total_size, table_size = 0;
    uint8 *global_data, *global_data_end;
#if WASM_ENABLE_MULTI_MODULE != 0
    bool ret = false;
#endif
    const bool is_sub_inst = parent != NULL;

    if (!module)
        return NULL;

    /* Check the heap size */
    heap_size = align_uint(heap_size, 8);
    if (heap_size > APP_HEAP_SIZE_MAX)
        heap_size = APP_HEAP_SIZE_MAX;

    module_inst_mem_inst_size =
        (uint64)sizeof(WASMMemoryInstance)
        * (module->import_memory_count + module->memory_count);

#if WASM_ENABLE_JIT != 0
    /* If the module dosen't have memory, reserve one mem_info space
       with empty content to align with llvm jit compiler */
    if (module_inst_mem_inst_size == 0)
        module_inst_mem_inst_size = (uint64)sizeof(WASMMemoryInstance);
#endif

    /* Size of module inst, memory instances and global data */
    total_size = (uint64)module_inst_struct_size + module_inst_mem_inst_size
                 + module->global_data_size;

    /* Calculate the size of table data */
    for (i = 0; i < module->import_table_count; i++) {
        WASMTableImport *import_table = &module->import_tables[i].u.table;
        table_size += offsetof(WASMTableInstance, elems);
#if WASM_ENABLE_MULTI_MODULE != 0
        table_size += (uint64)sizeof(uint32) * import_table->max_size;
#else
        table_size += (uint64)sizeof(uint32)
                      * (import_table->possible_grow ? import_table->max_size
                                                     : import_table->init_size);
#endif
    }
    for (i = 0; i < module->table_count; i++) {
        WASMTable *table = module->tables + i;
        table_size += offsetof(WASMTableInstance, elems);
#if WASM_ENABLE_MULTI_MODULE != 0
        table_size += (uint64)sizeof(uint32) * table->max_size;
#else
        table_size +=
            (uint64)sizeof(uint32)
            * (table->possible_grow ? table->max_size : table->init_size);
#endif
    }
    total_size += table_size;

    /* The offset of WASMModuleInstanceExtra, make it 8-byte aligned */
    total_size = (total_size + 7LL) & ~7LL;
    extra_info_offset = (uint32)total_size;
    total_size += sizeof(WASMModuleInstanceExtra);

    /* Allocate the memory for module instance with memory instances,
       global data, table data appended at the end */
    if (!(module_inst =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    module_inst->module_type = Wasm_Module_Bytecode;
    module_inst->module = module;
    module_inst->e =
        (WASMModuleInstanceExtra *)((uint8 *)module_inst + extra_info_offset);

#if WASM_ENABLE_MULTI_MODULE != 0
    module_inst->e->sub_module_inst_list =
        &module_inst->e->sub_module_inst_list_head;
    ret = wasm_runtime_sub_module_instantiate(
        (WASMModuleCommon *)module, (WASMModuleInstanceCommon *)module_inst,
        stack_size, heap_size, error_buf, error_buf_size);
    if (!ret) {
        LOG_DEBUG("build a sub module list failed");
        goto fail;
    }
#endif

#if WASM_ENABLE_BULK_MEMORY != 0
    if (module->data_seg_count > 0) {
        module_inst->e->common.data_dropped =
            bh_bitmap_new(0, module->data_seg_count);
        if (module_inst->e->common.data_dropped == NULL) {
            LOG_DEBUG("failed to allocate bitmaps");
            set_error_buf(error_buf, error_buf_size,
                          "failed to allocate bitmaps");
            goto fail;
        }
        for (i = 0; i < module->data_seg_count; i++) {
            if (!module->data_segments[i]->is_passive)
                bh_bitmap_set_bit(module_inst->e->common.data_dropped, i);
        }
    }
#endif
#if WASM_ENABLE_REF_TYPES != 0
    if (module->table_seg_count > 0) {
        module_inst->e->common.elem_dropped =
            bh_bitmap_new(0, module->table_seg_count);
        if (module_inst->e->common.elem_dropped == NULL) {
            LOG_DEBUG("failed to allocate bitmaps");
            set_error_buf(error_buf, error_buf_size,
                          "failed to allocate bitmaps");
            goto fail;
        }
        for (i = 0; i < module->table_seg_count; i++) {
            if (wasm_elem_is_active(module->table_segments[i].mode))
                bh_bitmap_set_bit(module_inst->e->common.elem_dropped, i);
        }
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
        && !(globals = globals_instantiate(module, module_inst, error_buf,
                                           error_buf_size))) {
        goto fail;
    }
    module_inst->e->global_count = global_count;
    module_inst->e->globals = globals;
    module_inst->global_data = (uint8 *)module_inst + module_inst_struct_size
                               + module_inst_mem_inst_size;
    module_inst->global_data_size = module->global_data_size;
    first_table = (WASMTableInstance *)(module_inst->global_data
                                        + module->global_data_size);

    module_inst->memory_count =
        module->import_memory_count + module->memory_count;
    module_inst->table_count = module->import_table_count + module->table_count;
    module_inst->e->function_count =
        module->import_function_count + module->function_count;
#if WASM_ENABLE_TAGS != 0
    module_inst->e->tag_count = module->import_tag_count + module->tag_count;
#endif

    /* export */
    module_inst->export_func_count = get_export_count(module, EXPORT_KIND_FUNC);
#if WASM_ENABLE_MULTI_MODULE != 0
    module_inst->export_table_count =
        get_export_count(module, EXPORT_KIND_TABLE);
    module_inst->export_memory_count =
        get_export_count(module, EXPORT_KIND_MEMORY);
#if WASM_ENABLE_TAGS != 0
    module_inst->e->export_tag_count =
        get_export_count(module, EXPORT_KIND_TAG);
#endif
    module_inst->export_global_count =
        get_export_count(module, EXPORT_KIND_GLOBAL);
#endif

    /* Instantiate memories/tables/functions/tags */
    if ((module_inst->memory_count > 0
         && !(module_inst->memories =
                  memories_instantiate(module, module_inst, parent, heap_size,
                                       error_buf, error_buf_size)))
        || (module_inst->table_count > 0
            && !(module_inst->tables =
                     tables_instantiate(module, module_inst, first_table,
                                        error_buf, error_buf_size)))
        || (module_inst->e->function_count > 0
            && !(module_inst->e->functions = functions_instantiate(
                     module, module_inst, error_buf, error_buf_size)))
        || (module_inst->export_func_count > 0
            && !(module_inst->export_functions = export_functions_instantiate(
                     module, module_inst, module_inst->export_func_count,
                     error_buf, error_buf_size)))
#if WASM_ENABLE_TAGS != 0
        || (module_inst->e->tag_count > 0
            && !(module_inst->e->tags = tags_instantiate(
                     module, module_inst, error_buf, error_buf_size)))
        || (module_inst->e->export_tag_count > 0
            && !(module_inst->e->export_tags = export_tags_instantiate(
                     module, module_inst, module_inst->e->export_tag_count,
                     error_buf, error_buf_size)))
#endif
#if WASM_ENABLE_MULTI_MODULE != 0
        || (module_inst->export_global_count > 0
            && !(module_inst->export_globals = export_globals_instantiate(
                     module, module_inst, module_inst->export_global_count,
                     error_buf, error_buf_size)))
#endif
#if WASM_ENABLE_JIT != 0
        || (module_inst->e->function_count > 0
            && !init_func_ptrs(module_inst, module, error_buf, error_buf_size))
#endif
#if WASM_ENABLE_FAST_JIT != 0 || WASM_ENABLE_JIT != 0
        || (module_inst->e->function_count > 0
            && !init_func_type_indexes(module_inst, error_buf, error_buf_size))
#endif
    ) {
        goto fail;
    }
    if (global_count > 0) {
        /* Initialize the global data */
        global_data = module_inst->global_data;
        global_data_end = global_data + module->global_data_size;
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
#if WASM_ENABLE_SIMD != 0
                case VALUE_TYPE_V128:
                    bh_memcpy_s(global_data, (uint32)sizeof(V128),
                                &global->initial_value.v128, sizeof(V128));
                    global_data += sizeof(V128);
                    break;
#endif
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
    for (i = 0; i < module->data_seg_count; i++) {
        WASMMemoryInstance *memory = NULL;
        uint8 *memory_data = NULL;
        uint64 memory_size = 0;
        WASMDataSeg *data_seg = module->data_segments[i];

#if WASM_ENABLE_BULK_MEMORY != 0
        if (data_seg->is_passive)
            continue;
#endif
        if (is_sub_inst)
            /* Ignore setting memory init data if the memory has been
               initialized */
            continue;

        /* has check it in loader */
        memory = module_inst->memories[data_seg->memory_index];
        bh_assert(memory);

        memory_data = memory->memory_data;
        memory_size =
            (uint64)memory->num_bytes_per_page * memory->cur_page_count;
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
            LOG_DEBUG("base_offset(%u) > memory_size(%" PRIu64 ")", base_offset,
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
        if ((uint64)base_offset + length > memory_size) {
            LOG_DEBUG("base_offset(%u) + length(%u) > memory_size(%" PRIu64 ")",
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
            bh_memcpy_s(memory_data + base_offset,
                        (uint32)memory_size - base_offset, data_seg->data,
                        length);
        }
    }

    /* Initialize the table data with table segment section */
    for (i = 0; module_inst->table_count > 0 && i < module->table_seg_count;
         i++) {
        WASMTableSeg *table_seg = module->table_segments + i;
        /* has check it in loader */
        WASMTableInstance *table = module_inst->tables[table_seg->table_index];
        uint32 *table_data;
#if WASM_ENABLE_REF_TYPES != 0
        uint8 tbl_elem_type;
        uint32 tbl_init_size, tbl_max_size;
#endif

        bh_assert(table);

#if WASM_ENABLE_REF_TYPES != 0
        (void)wasm_runtime_get_table_inst_elem_type(
            (WASMModuleInstanceCommon *)module_inst, table_seg->table_index,
            &tbl_elem_type, &tbl_init_size, &tbl_max_size);
        if (tbl_elem_type != VALUE_TYPE_FUNCREF
            && tbl_elem_type != VALUE_TYPE_EXTERNREF) {
            set_error_buf(error_buf, error_buf_size,
                          "elements segment does not fit");
            goto fail;
        }
        (void)tbl_init_size;
        (void)tbl_max_size;
#endif

        table_data = table->elems;
#if WASM_ENABLE_MULTI_MODULE != 0
        if (table_seg->table_index < module->import_table_count
            && module_inst->e->table_insts_linked[table_seg->table_index]) {
            table_data =
                module_inst->e->table_insts_linked[table_seg->table_index]
                    ->elems;
        }
#endif
        bh_assert(table_data);

#if WASM_ENABLE_REF_TYPES != 0
        if (!wasm_elem_is_active(table_seg->mode))
            continue;
#endif

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

        /* init vec(funcidx) or vec(expr) */
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

    /* Initialize the thread related data */
    if (stack_size == 0)
        stack_size = DEFAULT_WASM_STACK_SIZE;
#if WASM_ENABLE_SPEC_TEST != 0
    if (stack_size < 128 * 1024)
        stack_size = 128 * 1024;
#endif
    module_inst->default_wasm_stack_size = stack_size;

    if (module->malloc_function != (uint32)-1) {
        module_inst->e->malloc_function =
            &module_inst->e->functions[module->malloc_function];
    }

    if (module->free_function != (uint32)-1) {
        module_inst->e->free_function =
            &module_inst->e->functions[module->free_function];
    }

    if (module->retain_function != (uint32)-1) {
        module_inst->e->retain_function =
            &module_inst->e->functions[module->retain_function];
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

#if WASM_ENABLE_DEBUG_INTERP != 0
    if (!is_sub_inst) {
        /* Add module instance into module's instance list */
        os_mutex_lock(&module->instance_list_lock);
        if (module->instance_list) {
            LOG_WARNING(
                "warning: multiple instances referencing to the same module "
                "may cause unexpected behaviour during debugging");
        }
        module_inst->e->next = module->instance_list;
        module->instance_list = module_inst;
        os_mutex_unlock(&module->instance_list_lock);
    }
#endif

    /* Set running mode before executing wasm functions */
    if (!set_running_mode(module_inst, wasm_runtime_get_default_running_mode(),
                          true)) {
        set_error_buf(error_buf, error_buf_size,
                      "set instance running mode failed");
        goto fail;
    }

    if (module->start_function != (uint32)-1) {
        /* TODO: fix start function can be import function issue */
        if (module->start_function >= module->import_function_count)
            module_inst->e->start_function =
                &module_inst->e->functions[module->start_function];
    }

    if (!execute_post_instantiate_functions(module_inst, is_sub_inst,
                                            exec_env_main)) {
        set_error_buf(error_buf, error_buf_size, module_inst->cur_exception);
        goto fail;
    }

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

    if (module_inst->exec_env_singleton) {
        /* wasm_exec_env_destroy will call
           wasm_cluster_wait_for_all_except_self to wait for other
           threads, so as to destroy their exec_envs and module
           instances first, and avoid accessing the shared resources
           of current module instance after it is deinstantiated. */
        wasm_exec_env_destroy(module_inst->exec_env_singleton);
    }

#if WASM_ENABLE_DEBUG_INTERP != 0                         \
    || (WASM_ENABLE_FAST_JIT != 0 && WASM_ENABLE_JIT != 0 \
        && WASM_ENABLE_LAZY_JIT != 0)
    /* Remove instance from module's instance list before freeing
       func_ptrs and fast_jit_func_ptrs of the instance, to avoid
       accessing the freed memory in the jit backend compilation
       threads */
    {
        WASMModule *module = module_inst->module;
        WASMModuleInstance *instance_prev = NULL, *instance;
        os_mutex_lock(&module->instance_list_lock);

        instance = module->instance_list;
        while (instance) {
            if (instance == module_inst) {
                if (!instance_prev)
                    module->instance_list = instance->e->next;
                else
                    instance_prev->e->next = instance->e->next;
                break;
            }
            instance_prev = instance;
            instance = instance->e->next;
        }

        os_mutex_unlock(&module->instance_list_lock);
    }
#endif

#if WASM_ENABLE_JIT != 0
    if (module_inst->func_ptrs)
        wasm_runtime_free(module_inst->func_ptrs);
#endif

#if WASM_ENABLE_FAST_JIT != 0 && WASM_ENABLE_JIT != 0 \
    && WASM_ENABLE_LAZY_JIT != 0
    if (module_inst->fast_jit_func_ptrs
        && module_inst->fast_jit_func_ptrs
               != module_inst->module->fast_jit_func_ptrs)
        wasm_runtime_free(module_inst->fast_jit_func_ptrs);
#endif

#if WASM_ENABLE_FAST_JIT != 0 || WASM_ENABLE_JIT != 0
    if (module_inst->func_type_indexes)
        wasm_runtime_free(module_inst->func_type_indexes);
#endif

#if WASM_ENABLE_MULTI_MODULE != 0
    wasm_runtime_sub_module_deinstantiate(
        (WASMModuleInstanceCommon *)module_inst);
#endif

    if (module_inst->memory_count > 0)
        memories_deinstantiate(module_inst, module_inst->memories,
                               module_inst->memory_count);

    if (module_inst->import_func_ptrs) {
        wasm_runtime_free(module_inst->import_func_ptrs);
    }

    tables_deinstantiate(module_inst);
    functions_deinstantiate(module_inst->e->functions,
                            module_inst->e->function_count);
#if WASM_ENABLE_TAGS != 0
    tags_deinstantiate(module_inst->e->tags, module_inst->e->import_tag_ptrs);
#endif

    globals_deinstantiate(module_inst->e->globals);
    export_functions_deinstantiate(module_inst->export_functions);
#if WASM_ENABLE_TAGS != 0
    export_tags_deinstantiate(module_inst->e->export_tags);
#endif

#if WASM_ENABLE_MULTI_MODULE != 0
    export_globals_deinstantiate(module_inst->export_globals);
#endif

#if WASM_ENABLE_REF_TYPES != 0
    wasm_externref_cleanup((WASMModuleInstanceCommon *)module_inst);
#endif

#if WASM_ENABLE_DUMP_CALL_STACK != 0
    if (module_inst->frames) {
        bh_vector_destroy(module_inst->frames);
        wasm_runtime_free(module_inst->frames);
        module_inst->frames = NULL;
    }
#endif

    if (module_inst->e->common.c_api_func_imports)
        wasm_runtime_free(module_inst->e->common.c_api_func_imports);

    if (!is_sub_inst) {
#if WASM_ENABLE_WASI_NN != 0
        wasi_nn_destroy(module_inst);
#endif
        wasm_native_call_context_dtors((WASMModuleInstanceCommon *)module_inst);
    }

#if WASM_ENABLE_BULK_MEMORY != 0
    bh_bitmap_delete(module_inst->e->common.data_dropped);
#endif
#if WASM_ENABLE_REF_TYPES != 0
    bh_bitmap_delete(module_inst->e->common.elem_dropped);
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
    for (i = 0; i < module_inst->export_global_count; i++)
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

#if WASM_ENABLE_TAGS != 0
WASMTagInstance *
wasm_lookup_tag(const WASMModuleInstance *module_inst, const char *name,
                const char *signature)
{
    uint32 i;
    for (i = 0; i < module_inst->e->export_tag_count; i++)
        if (!strcmp(module_inst->e->export_tags[i].name, name))
            return module_inst->e->export_tags[i].tag;
    (void)signature;
    return NULL;
}
#endif

#endif

#ifdef OS_ENABLE_HW_BOUND_CHECK
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
    WASMRuntimeFrame *prev_frame = wasm_exec_env_get_cur_frame(exec_env);
    uint8 *prev_top = exec_env->wasm_stack.s.top;
#ifdef BH_PLATFORM_WINDOWS
    int result;
    bool has_exception;
    char exception[EXCEPTION_BUF_LEN];
#endif
    bool ret = true;

    /* Check native stack overflow firstly to ensure we have enough
       native stack to run the following codes before actually calling
       the aot function in invokeNative function. */
    RECORD_STACK_USAGE(exec_env, (uint8 *)&exec_env_tls);
    if ((uint8 *)&exec_env_tls < exec_env->native_stack_boundary
                                     + page_size * (guard_page_count + 1)) {
        wasm_set_exception(module_inst, "native stack overflow");
        return;
    }

    if (!exec_env_tls) {
        if (!os_thread_signal_inited()) {
            wasm_set_exception(module_inst, "thread signal env not inited");
            return;
        }

        /* Set thread handle and stack boundary if they haven't been set */
        wasm_exec_env_set_thread_info(exec_env);

        wasm_runtime_set_exec_env_tls(exec_env);
    }
    else {
        if (exec_env_tls != exec_env) {
            wasm_set_exception(module_inst, "invalid exec env");
            return;
        }
    }

    wasm_exec_env_push_jmpbuf(exec_env, &jmpbuf_node);

    if (os_setjmp(jmpbuf_node.jmpbuf) == 0) {
#ifndef BH_PLATFORM_WINDOWS
        wasm_interp_call_wasm(module_inst, exec_env, function, argc, argv);
#else
        __try {
            wasm_interp_call_wasm(module_inst, exec_env, function, argc, argv);
        } __except (wasm_copy_exception(module_inst, NULL)
                        ? EXCEPTION_EXECUTE_HANDLER
                        : EXCEPTION_CONTINUE_SEARCH) {
            /* Exception was thrown in wasm_exception_handler */
            ret = false;
        }
        has_exception = wasm_copy_exception(module_inst, exception);
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

    /* Note: can't check wasm_get_exception(module_inst) here, there may be
     * exception which is not caught by hardware (e.g. uninitialized elements),
     * then the stack-frame is already freed inside wasm_interp_call_wasm */
    if (!ret) {
#if WASM_ENABLE_DUMP_CALL_STACK != 0
        if (wasm_interp_create_call_stack(exec_env)) {
            wasm_interp_dump_call_stack(exec_env, true, NULL, 0);
        }
#endif
        /* Restore operand frames */
        wasm_exec_env_set_cur_frame(exec_env, prev_frame);
        exec_env->wasm_stack.s.top = prev_top;
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

#ifndef OS_ENABLE_HW_BOUND_CHECK
    /* Set thread handle and stack boundary */
    wasm_exec_env_set_thread_info(exec_env);
#else
    /* Set thread info in call_wasm_with_hw_bound_check when
       hw bound check is enabled */
#endif

    /* Set exec env so it can be later retrieved from instance */
    module_inst->e->common.cur_exec_env = exec_env;

    interp_call_wasm(module_inst, exec_env, function, argc, argv);
    return !wasm_copy_exception(module_inst, NULL);
}

#if WASM_ENABLE_PERF_PROFILING != 0 || WASM_ENABLE_DUMP_CALL_STACK != 0
/* look for the function name */
static char *
get_func_name_from_index(const WASMModuleInstance *inst, uint32 func_index)
{
    char *func_name = NULL;
    WASMFunctionInstance *func_inst = inst->e->functions + func_index;

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
            unsigned j;
            for (j = 0; j < inst->export_func_count; j++) {
                WASMExportFuncInstance *export_func =
                    inst->export_functions + j;
                if (export_func->function == func_inst) {
                    func_name = export_func->name;
                    break;
                }
            }
        }
    }

    return func_name;
}
#endif /*WASM_ENABLE_PERF_PROFILING != 0 || WASM_ENABLE_DUMP_CALL_STACK != 0*/

#if WASM_ENABLE_PERF_PROFILING != 0
void
wasm_dump_perf_profiling(const WASMModuleInstance *module_inst)
{
    WASMFunctionInstance *func_inst;
    char *func_name;
    uint32 i;

    os_printf("Performance profiler data:\n");
    for (i = 0; i < module_inst->e->function_count; i++) {
        func_inst = module_inst->e->functions + i;

        if (func_inst->total_exec_cnt == 0)
            continue;

        func_name = get_func_name_from_index(module_inst, i);
        if (func_name)
            os_printf(
                "  func %s, execution time: %.3f ms, execution count: %" PRIu32
                " times, children execution time: %.3f ms\n",
                func_name, func_inst->total_exec_time / 1000.0f,
                func_inst->total_exec_cnt,
                func_inst->children_exec_time / 1000.0f);
        else
            os_printf("  func %" PRIu32
                      ", execution time: %.3f ms, execution count: %" PRIu32
                      " times, children execution time: %.3f ms\n",
                      i, func_inst->total_exec_time / 1000.0f,
                      func_inst->total_exec_cnt,
                      func_inst->children_exec_time / 1000.0f);
    }
}

double
wasm_summarize_wasm_execute_time(const WASMModuleInstance *inst)
{
    double ret = 0;

    unsigned i;
    for (i = 0; i < inst->e->function_count; i++) {
        WASMFunctionInstance *func = inst->e->functions + i;
        ret += (func->total_exec_time - func->children_exec_time) / 1000.0f;
    }

    return ret;
}

double
wasm_get_wasm_func_exec_time(const WASMModuleInstance *inst,
                             const char *func_name)
{
    unsigned i;
    for (i = 0; i < inst->e->function_count; i++) {
        char *name_in_wasm = get_func_name_from_index(inst, i);
        if (name_in_wasm && strcmp(name_in_wasm, func_name) == 0) {
            WASMFunctionInstance *func = inst->e->functions + i;
            return (func->total_exec_time - func->children_exec_time) / 1000.0f;
        }
    }

    return -1.0;
}
#endif /*WASM_ENABLE_PERF_PROFILING != 0*/

uint32
wasm_module_malloc_internal(WASMModuleInstance *module_inst,
                            WASMExecEnv *exec_env, uint32 size,
                            void **p_native_addr)
{
    WASMMemoryInstance *memory = wasm_get_default_memory(module_inst);
    uint8 *addr = NULL;
    uint32 offset = 0;

    if (!memory) {
        wasm_set_exception(module_inst, "uninitialized memory");
        return 0;
    }

    if (memory->heap_handle) {
        addr = mem_allocator_malloc(memory->heap_handle, size);
    }
    else if (module_inst->e->malloc_function && module_inst->e->free_function) {
        if (!execute_malloc_function(
                module_inst, exec_env, module_inst->e->malloc_function,
                module_inst->e->retain_function, size, &offset)) {
            return 0;
        }
        /* If we use app's malloc function,
           the default memory may be changed while memory growing */
        memory = wasm_get_default_memory(module_inst);
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
wasm_module_realloc_internal(WASMModuleInstance *module_inst,
                             WASMExecEnv *exec_env, uint32 ptr, uint32 size,
                             void **p_native_addr)
{
    WASMMemoryInstance *memory = wasm_get_default_memory(module_inst);
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
    (void)exec_env;

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
wasm_module_free_internal(WASMModuleInstance *module_inst,
                          WASMExecEnv *exec_env, uint32 ptr)
{
    WASMMemoryInstance *memory = wasm_get_default_memory(module_inst);

    if (!memory) {
        return;
    }

    if (ptr) {
        uint8 *addr = memory->memory_data + ptr;
        uint8 *memory_data_end;

        /* memory->memory_data_end may be changed in memory grow */
        SHARED_MEMORY_LOCK(memory);
        memory_data_end = memory->memory_data_end;
        SHARED_MEMORY_UNLOCK(memory);

        if (memory->heap_handle && memory->heap_data <= addr
            && addr < memory->heap_data_end) {
            mem_allocator_free(memory->heap_handle, addr);
        }
        else if (module_inst->e->malloc_function
                 && module_inst->e->free_function && memory->memory_data <= addr
                 && addr < memory_data_end) {
            execute_free_function(module_inst, exec_env,
                                  module_inst->e->free_function, ptr);
        }
    }
}

uint32
wasm_module_malloc(WASMModuleInstance *module_inst, uint32 size,
                   void **p_native_addr)
{
    return wasm_module_malloc_internal(module_inst, NULL, size, p_native_addr);
}

uint32
wasm_module_realloc(WASMModuleInstance *module_inst, uint32 ptr, uint32 size,
                    void **p_native_addr)
{
    return wasm_module_realloc_internal(module_inst, NULL, ptr, size,
                                        p_native_addr);
}

void
wasm_module_free(WASMModuleInstance *module_inst, uint32 ptr)
{
    wasm_module_free_internal(module_inst, NULL, ptr);
}

uint32
wasm_module_dup_data(WASMModuleInstance *module_inst, const char *src,
                     uint32 size)
{
    char *buffer;
    uint32 buffer_offset =
        wasm_module_malloc(module_inst, size, (void **)&buffer);
    if (buffer_offset != 0) {
        buffer = wasm_runtime_addr_app_to_native(
            (WASMModuleInstanceCommon *)module_inst, buffer_offset);
        bh_memcpy_s(buffer, size, src, size);
    }
    return buffer_offset;
}

#if WASM_ENABLE_REF_TYPES != 0
bool
wasm_enlarge_table(WASMModuleInstance *module_inst, uint32 table_idx,
                   uint32 inc_size, uint32 init_val)
{
    uint32 total_size, *new_table_data_start, i;
    WASMTableInstance *table_inst;

    if (!inc_size) {
        return true;
    }

    bh_assert(table_idx < module_inst->table_count);
    table_inst = wasm_get_table_inst(module_inst, table_idx);
    if (!table_inst) {
        return false;
    }

    if (inc_size > UINT32_MAX - table_inst->cur_size) {
        return false;
    }

    total_size = table_inst->cur_size + inc_size;
    if (total_size > table_inst->max_size) {
        return false;
    }

    /* fill in */
    new_table_data_start = table_inst->elems + table_inst->cur_size;
    for (i = 0; i < inc_size; ++i) {
        new_table_data_start[i] = init_val;
    }

    table_inst->cur_size = total_size;
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

    func_idx = table_inst->elems[elem_idx];
    if (func_idx == NULL_REF) {
        wasm_set_exception(module_inst, "uninitialized element");
        goto got_exception;
    }

    /**
     * we insist to call functions owned by the module itself
     **/
    if (func_idx >= module_inst->e->function_count) {
        wasm_set_exception(module_inst, "unknown function");
        goto got_exception;
    }

    func_inst = module_inst->e->functions + func_idx;

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

    return !wasm_copy_exception(module_inst, NULL);

got_exception:
    return false;
}

bool
wasm_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 elem_idx,
                   uint32 argc, uint32 argv[])
{
    return call_indirect(exec_env, tbl_idx, elem_idx, argc, argv, false, 0);
}

#if WASM_ENABLE_THREAD_MGR != 0
bool
wasm_set_aux_stack(WASMExecEnv *exec_env, uint32 start_offset, uint32 size)
{
    WASMModuleInstance *module_inst =
        (WASMModuleInstance *)exec_env->module_inst;
    uint32 stack_top_idx = module_inst->module->aux_stack_top_global_index;

#if WASM_ENABLE_HEAP_AUX_STACK_ALLOCATION == 0
    /* Check the aux stack space */
    uint32 data_end = module_inst->module->aux_data_end;
    uint32 stack_bottom = module_inst->module->aux_stack_bottom;
    bool is_stack_before_data = stack_bottom < data_end ? true : false;
    if ((is_stack_before_data && (size > start_offset))
        || ((!is_stack_before_data) && (start_offset - data_end < size)))
        return false;
#endif

    if (stack_top_idx != (uint32)-1) {
        /* The aux stack top is a wasm global,
            set the initial value for the global */
        uint8 *global_addr =
            module_inst->global_data
            + module_inst->e->globals[stack_top_idx].data_offset;
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

    mem_conspn->module_inst_struct_size = (uint8 *)module_inst->e
                                          - (uint8 *)module_inst
                                          + sizeof(WASMModuleInstanceExtra);

    mem_conspn->memories_size =
        sizeof(WASMMemoryInstance *) * module_inst->memory_count;
    for (i = 0; i < module_inst->memory_count; i++) {
        WASMMemoryInstance *memory = module_inst->memories[i];
        size = memory->num_bytes_per_page * memory->cur_page_count;
        mem_conspn->memories_size += size;
        mem_conspn->app_heap_size += memory->heap_data_end - memory->heap_data;
        /* size of app heap structure */
        mem_conspn->memories_size += mem_allocator_get_heap_struct_size();
        /* Module instance structures have been appened into the end of
           module instance */
    }

    mem_conspn->tables_size =
        sizeof(WASMTableInstance *) * module_inst->table_count;
    /* Table instance structures and table elements have been appened into
       the end of module instance */

    mem_conspn->functions_size =
        sizeof(WASMFunctionInstance) * module_inst->e->function_count;

    mem_conspn->globals_size =
        sizeof(WASMGlobalInstance) * module_inst->e->global_count;
    /* Global data has been appened into the end of module instance */

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
        frame.func_index = (uint32)(func_inst - module_inst->e->functions);

        func_code_base = wasm_get_func_code(func_inst);
        if (!cur_frame->ip || !func_code_base) {
            frame.func_offset = 0;
        }
        else {
            frame.func_offset = (uint32)(cur_frame->ip - func_code_base);
        }

        func_name = get_func_name_from_index(module_inst, frame.func_index);
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
            exception_unlock(module_inst);                                \
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

#if WASM_ENABLE_FAST_JIT != 0 || WASM_ENABLE_JIT != 0 \
    || WASM_ENABLE_WAMR_COMPILER != 0
void
jit_set_exception_with_id(WASMModuleInstance *module_inst, uint32 id)
{
    if (id != EXCE_ALREADY_THROWN)
        wasm_set_exception_with_id(module_inst, id);
#ifdef OS_ENABLE_HW_BOUND_CHECK
    wasm_runtime_access_exce_check_guard_page();
#endif
}

bool
jit_check_app_addr_and_convert(WASMModuleInstance *module_inst, bool is_str,
                               uint32 app_buf_addr, uint32 app_buf_size,
                               void **p_native_addr)
{
    bool ret = wasm_check_app_addr_and_convert(
        module_inst, is_str, app_buf_addr, app_buf_size, p_native_addr);

#ifdef OS_ENABLE_HW_BOUND_CHECK
    if (!ret)
        wasm_runtime_access_exce_check_guard_page();
#endif

    return ret;
}
#endif /* end of WASM_ENABLE_FAST_JIT != 0 || WASM_ENABLE_JIT != 0 \
          || WASM_ENABLE_WAMR_COMPILER != 0 */

#if WASM_ENABLE_FAST_JIT != 0
bool
fast_jit_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 elem_idx,
                       uint32 type_idx, uint32 argc, uint32 *argv)
{
    return call_indirect(exec_env, tbl_idx, elem_idx, argc, argv, true,
                         type_idx);
}
#endif /* end of WASM_ENABLE_FAST_JIT != 0 */

#if WASM_ENABLE_JIT != 0 || WASM_ENABLE_WAMR_COMPILER != 0

bool
llvm_jit_call_indirect(WASMExecEnv *exec_env, uint32 tbl_idx, uint32 elem_idx,
                       uint32 argc, uint32 *argv)
{
    bool ret;

    bh_assert(exec_env->module_inst->module_type == Wasm_Module_Bytecode);

    ret = call_indirect(exec_env, tbl_idx, elem_idx, argc, argv, false, 0);
#ifdef OS_ENABLE_HW_BOUND_CHECK
    if (!ret)
        wasm_runtime_access_exce_check_guard_page();
#endif
    return ret;
}

bool
llvm_jit_invoke_native(WASMExecEnv *exec_env, uint32 func_idx, uint32 argc,
                       uint32 *argv)
{
    WASMModuleInstance *module_inst;
    WASMModule *module;
    uint32 *func_type_indexes;
    uint32 func_type_idx;
    WASMType *func_type;
    void *func_ptr;
    WASMFunctionImport *import_func;
    CApiFuncImport *c_api_func_import = NULL;
    const char *signature;
    void *attachment;
    char buf[96];
    bool ret = false;

    bh_assert(exec_env->module_inst->module_type == Wasm_Module_Bytecode);

    module_inst = (WASMModuleInstance *)wasm_runtime_get_module_inst(exec_env);
    module = module_inst->module;
    func_type_indexes = module_inst->func_type_indexes;
    func_type_idx = func_type_indexes[func_idx];
    func_type = module->types[func_type_idx];
    func_ptr = module_inst->func_ptrs[func_idx];

    bh_assert(func_idx < module->import_function_count);

    import_func = &module->import_functions[func_idx].u.function;
    if (import_func->call_conv_wasm_c_api) {
        if (module_inst->e->common.c_api_func_imports) {
            c_api_func_import =
                module_inst->e->common.c_api_func_imports + func_idx;
            func_ptr = c_api_func_import->func_ptr_linked;
        }
        else {
            c_api_func_import = NULL;
            func_ptr = NULL;
        }
    }

    if (!func_ptr) {
        snprintf(buf, sizeof(buf),
                 "failed to call unlinked import function (%s, %s)",
                 import_func->module_name, import_func->field_name);
        wasm_set_exception(module_inst, buf);
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

#if WASM_ENABLE_BULK_MEMORY != 0
bool
llvm_jit_memory_init(WASMModuleInstance *module_inst, uint32 seg_index,
                     uint32 offset, uint32 len, uint32 dst)
{
    WASMMemoryInstance *memory_inst;
    WASMModule *module;
    uint8 *data;
    uint8 *maddr;
    uint64 seg_len;

    bh_assert(module_inst->module_type == Wasm_Module_Bytecode);

    memory_inst = wasm_get_default_memory(module_inst);

    if (bh_bitmap_get_bit(module_inst->e->common.data_dropped, seg_index)) {
        seg_len = 0;
        data = NULL;
    }
    else {
        module = module_inst->module;
        seg_len = module->data_segments[seg_index]->data_length;
        data = module->data_segments[seg_index]->data;
    }

    if (!wasm_runtime_validate_app_addr((WASMModuleInstanceCommon *)module_inst,
                                        dst, len))
        return false;

    if ((uint64)offset + (uint64)len > seg_len) {
        wasm_set_exception(module_inst, "out of bounds memory access");
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
llvm_jit_data_drop(WASMModuleInstance *module_inst, uint32 seg_index)
{
    bh_assert(module_inst->module_type == Wasm_Module_Bytecode);

    bh_bitmap_set_bit(module_inst->e->common.data_dropped, seg_index);
    /* Currently we can't free the dropped data segment
       as they are stored in wasm bytecode */
    return true;
}
#endif /* end of WASM_ENABLE_BULK_MEMORY != 0 */

#if WASM_ENABLE_REF_TYPES != 0
void
llvm_jit_drop_table_seg(WASMModuleInstance *module_inst, uint32 tbl_seg_idx)
{
    bh_assert(module_inst->module_type == Wasm_Module_Bytecode);
    bh_bitmap_set_bit(module_inst->e->common.elem_dropped, tbl_seg_idx);
}

void
llvm_jit_table_init(WASMModuleInstance *module_inst, uint32 tbl_idx,
                    uint32 tbl_seg_idx, uint32 length, uint32 src_offset,
                    uint32 dst_offset)
{
    WASMTableInstance *tbl_inst;
    WASMTableSeg *tbl_seg;
    uint32 *tbl_seg_elems = NULL, tbl_seg_len = 0;

    bh_assert(module_inst->module_type == Wasm_Module_Bytecode);

    tbl_inst = wasm_get_table_inst(module_inst, tbl_idx);
    tbl_seg = module_inst->module->table_segments + tbl_seg_idx;

    bh_assert(tbl_inst);
    bh_assert(tbl_seg);

    if (!bh_bitmap_get_bit(module_inst->e->common.elem_dropped, tbl_seg_idx)) {
        /* table segment isn't dropped */
        tbl_seg_elems = tbl_seg->func_indexes;
        tbl_seg_len = tbl_seg->function_count;
    }

    if (offset_len_out_of_bounds(src_offset, length, tbl_seg_len)
        || offset_len_out_of_bounds(dst_offset, length, tbl_inst->cur_size)) {
        jit_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    if (!length) {
        return;
    }

    bh_memcpy_s((uint8 *)tbl_inst + offsetof(WASMTableInstance, elems)
                    + dst_offset * sizeof(uint32),
                (uint32)sizeof(uint32) * (tbl_inst->cur_size - dst_offset),
                tbl_seg_elems + src_offset, (uint32)(length * sizeof(uint32)));
}

void
llvm_jit_table_copy(WASMModuleInstance *module_inst, uint32 src_tbl_idx,
                    uint32 dst_tbl_idx, uint32 length, uint32 src_offset,
                    uint32 dst_offset)
{
    WASMTableInstance *src_tbl_inst;
    WASMTableInstance *dst_tbl_inst;

    bh_assert(module_inst->module_type == Wasm_Module_Bytecode);

    src_tbl_inst = wasm_get_table_inst(module_inst, src_tbl_idx);
    dst_tbl_inst = wasm_get_table_inst(module_inst, dst_tbl_idx);
    bh_assert(src_tbl_inst);
    bh_assert(dst_tbl_inst);

    if (offset_len_out_of_bounds(dst_offset, length, dst_tbl_inst->cur_size)
        || offset_len_out_of_bounds(src_offset, length,
                                    src_tbl_inst->cur_size)) {
        jit_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    /* if src_offset >= dst_offset, copy from front to back */
    /* if src_offset < dst_offset, copy from back to front */
    /* merge all together */
    bh_memmove_s((uint8 *)dst_tbl_inst + offsetof(WASMTableInstance, elems)
                     + sizeof(uint32) * dst_offset,
                 (uint32)sizeof(uint32) * (dst_tbl_inst->cur_size - dst_offset),
                 (uint8 *)src_tbl_inst + offsetof(WASMTableInstance, elems)
                     + sizeof(uint32) * src_offset,
                 (uint32)sizeof(uint32) * length);
}

void
llvm_jit_table_fill(WASMModuleInstance *module_inst, uint32 tbl_idx,
                    uint32 length, uint32 val, uint32 data_offset)
{
    WASMTableInstance *tbl_inst;

    bh_assert(module_inst->module_type == Wasm_Module_Bytecode);

    tbl_inst = wasm_get_table_inst(module_inst, tbl_idx);
    bh_assert(tbl_inst);

    if (offset_len_out_of_bounds(data_offset, length, tbl_inst->cur_size)) {
        jit_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    for (; length != 0; data_offset++, length--) {
        tbl_inst->elems[data_offset] = val;
    }
}

uint32
llvm_jit_table_grow(WASMModuleInstance *module_inst, uint32 tbl_idx,
                    uint32 inc_size, uint32 init_val)
{
    WASMTableInstance *tbl_inst;
    uint32 i, orig_size, total_size;

    bh_assert(module_inst->module_type == Wasm_Module_Bytecode);

    tbl_inst = wasm_get_table_inst(module_inst, tbl_idx);
    if (!tbl_inst) {
        return (uint32)-1;
    }

    orig_size = tbl_inst->cur_size;

    if (!inc_size) {
        return orig_size;
    }

    if (tbl_inst->cur_size > UINT32_MAX - inc_size) { /* integer overflow */
        return (uint32)-1;
    }

    total_size = tbl_inst->cur_size + inc_size;
    if (total_size > tbl_inst->max_size) {
        return (uint32)-1;
    }

    /* fill in */
    for (i = 0; i < inc_size; ++i) {
        tbl_inst->elems[tbl_inst->cur_size + i] = init_val;
    }

    tbl_inst->cur_size = total_size;
    return orig_size;
}
#endif /* end of WASM_ENABLE_REF_TYPES != 0 */

#if WASM_ENABLE_DUMP_CALL_STACK != 0 || WASM_ENABLE_PERF_PROFILING != 0
bool
llvm_jit_alloc_frame(WASMExecEnv *exec_env, uint32 func_index)
{
    WASMModuleInstance *module_inst;
    WASMInterpFrame *frame;
    uint32 size;

    bh_assert(exec_env->module_inst->module_type == Wasm_Module_Bytecode);

    module_inst = (WASMModuleInstance *)exec_env->module_inst;
    size = wasm_interp_interp_frame_size(0);

    frame = wasm_exec_env_alloc_wasm_frame(exec_env, size);
    if (!frame) {
        wasm_set_exception(module_inst, "wasm operand stack overflow");
        return false;
    }

    frame->function = module_inst->e->functions + func_index;
    frame->ip = NULL;
    frame->sp = frame->lp;
#if WASM_ENABLE_PERF_PROFILING != 0
    frame->time_started = os_time_thread_cputime_us();
#endif
    frame->prev_frame = wasm_exec_env_get_cur_frame(exec_env);
    wasm_exec_env_set_cur_frame(exec_env, frame);

    return true;
}

void
llvm_jit_free_frame(WASMExecEnv *exec_env)
{
    WASMInterpFrame *frame;
    WASMInterpFrame *prev_frame;

    bh_assert(exec_env->module_inst->module_type == Wasm_Module_Bytecode);

    frame = wasm_exec_env_get_cur_frame(exec_env);
    prev_frame = frame->prev_frame;

#if WASM_ENABLE_PERF_PROFILING != 0
    if (frame->function) {
        uint64 elapsed = os_time_thread_cputime_us() - frame->time_started;
        frame->function->total_exec_time += elapsed;
        frame->function->total_exec_cnt++;

        /* parent function */
        if (prev_frame)
            prev_frame->function->children_exec_time += elapsed;
    }
#endif
    wasm_exec_env_free_wasm_frame(exec_env, frame);
    wasm_exec_env_set_cur_frame(exec_env, prev_frame);
}
#endif /* end of WASM_ENABLE_DUMP_CALL_STACK != 0 \
          || WASM_ENABLE_PERF_PROFILING != 0 */

#endif /* end of WASM_ENABLE_JIT != 0 || WASM_ENABLE_WAMR_COMPILER != 0 */

#if WASM_ENABLE_LIBC_WASI != 0 && WASM_ENABLE_MULTI_MODULE != 0
void
wasm_propagate_wasi_args(WASMModule *module)
{
    if (!module->import_count)
        return;

    bh_assert(&module->import_module_list_head);

    WASMRegisteredModule *node =
        bh_list_first_elem(&module->import_module_list_head);
    while (node) {
        WASIArguments *wasi_args_impt_mod =
            &((WASMModule *)(node->module))->wasi_args;
        bh_assert(wasi_args_impt_mod);

        bh_memcpy_s(wasi_args_impt_mod, sizeof(WASIArguments),
                    &module->wasi_args, sizeof(WASIArguments));
        node = bh_list_elem_next(node);
    }
}
#endif
