/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot.h"

static char aot_error[128];

char *
aot_get_last_error(void)
{
    return aot_error[0] == '\0' ? "" : aot_error;
}

void
aot_set_last_error_v(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(aot_error, sizeof(aot_error), format, args);
    va_end(args);
}

void
aot_set_last_error(const char *error)
{
    if (error)
        snprintf(aot_error, sizeof(aot_error), "Error: %s", error);
    else
        aot_error[0] = '\0';
}

static void
aot_destroy_mem_init_data_list(AOTMemInitData **data_list, uint32 count)
{
    uint32 i;
    for (i = 0; i < count; i++)
        if (data_list[i]) {
            if (data_list[i]->bytes)
                wasm_runtime_free(data_list[i]->bytes);
            wasm_runtime_free(data_list[i]);
        }
    wasm_runtime_free(data_list);
}

static AOTMemInitData **
aot_create_mem_init_data_list(const WASMModule *module)
{
    AOTMemInitData **data_list;
    uint64 size;
    uint32 i;

    /* Allocate memory */
    size = sizeof(AOTMemInitData *) * (uint64)module->data_seg_count;
    if (size >= UINT32_MAX
        || !(data_list = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    memset(data_list, 0, size);

    /* Create each memory data segment */
    for (i = 0; i < module->data_seg_count; i++) {
        size = sizeof(AOTMemInitData);
        if (size >= UINT32_MAX
            || !(data_list[i] = wasm_runtime_malloc((uint32)size))) {
            aot_set_last_error("allocate memory failed.");
            goto fail;
        }

#if WASM_ENABLE_BULK_MEMORY != 0
        /* Set bulk memory specific properties if enabled */
        data_list[i]->is_passive = module->data_segments[i]->is_passive;
        data_list[i]->memory_index = module->data_segments[i]->memory_index;
#endif
        data_list[i]->offset = module->data_segments[i]->base_offset;
        data_list[i]->byte_count = module->data_segments[i]->data_length;
        data_list[i]->bytes = NULL;
        /* Allocate memory for AOT compiler is OK, because the data segment
         * is small and the host memory is enough */
        if (data_list[i]->byte_count > 0) {
            data_list[i]->bytes = wasm_runtime_malloc(data_list[i]->byte_count);
            if (!data_list[i]->bytes) {
                aot_set_last_error("allocate memory failed.");
                goto fail;
            }
            /* Copy the actual data bytes from the WASM module */
            memcpy(data_list[i]->bytes, module->data_segments[i]->data,
                   module->data_segments[i]->data_length);
        }
    }

    return data_list;

fail:
    /* Clean up allocated memory in case of failure */
    aot_destroy_mem_init_data_list(data_list, module->data_seg_count);
    return NULL;
}

static void
aot_destroy_table_init_data_list(AOTTableInitData **data_list, uint32 count)
{
    uint32 i;
    for (i = 0; i < count; i++)
        if (data_list[i])
            wasm_runtime_free(data_list[i]);
    wasm_runtime_free(data_list);
}

static AOTTableInitData **
aot_create_table_init_data_list(const WASMModule *module)
{
    AOTTableInitData **data_list;
    uint64 size;
    uint32 i;

    /* Allocate memory */
    size = sizeof(AOTTableInitData *) * (uint64)module->table_seg_count;
    if (size >= UINT32_MAX
        || !(data_list = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    memset(data_list, 0, size);

    /* Create each table data segment */
    for (i = 0; i < module->table_seg_count; i++) {
        size = offsetof(AOTTableInitData, init_values)
               + sizeof(InitializerExpression)
                     * (uint64)module->table_segments[i].value_count;
        if (size >= UINT32_MAX
            || !(data_list[i] = wasm_runtime_malloc((uint32)size))) {
            aot_set_last_error("allocate memory failed.");
            goto fail;
        }

        data_list[i]->offset = module->table_segments[i].base_offset;
        data_list[i]->value_count = module->table_segments[i].value_count;
        data_list[i]->mode = module->table_segments[i].mode;
        data_list[i]->elem_type = module->table_segments[i].elem_type;
        /* runtime control it */
        data_list[i]->table_index = module->table_segments[i].table_index;
        bh_memcpy_s(&data_list[i]->offset, sizeof(AOTInitExpr),
                    &module->table_segments[i].base_offset,
                    sizeof(AOTInitExpr));
        data_list[i]->value_count = module->table_segments[i].value_count;
#if WASM_ENABLE_GC != 0
        data_list[i]->elem_ref_type = module->table_segments[i].elem_ref_type;
#endif
        bh_memcpy_s(data_list[i]->init_values,
                    sizeof(InitializerExpression)
                        * module->table_segments[i].value_count,
                    module->table_segments[i].init_values,
                    sizeof(InitializerExpression)
                        * module->table_segments[i].value_count);
    }

    return data_list;

fail:
    aot_destroy_table_init_data_list(data_list, module->table_seg_count);
    return NULL;
}

static void
get_value_type_size(uint8 value_type, bool gc_enabled, uint32 *p_size_64bit,
                    uint32 *p_size_32bit)
{
    uint32 size_64bit = 0, size_32bit = 0;

    if (value_type == VALUE_TYPE_I32 || value_type == VALUE_TYPE_F32)
        size_64bit = size_32bit = sizeof(int32);
    else if (value_type == VALUE_TYPE_I64 || value_type == VALUE_TYPE_F64)
        size_64bit = size_32bit = sizeof(int64);
    else if (value_type == VALUE_TYPE_V128)
        size_64bit = size_32bit = sizeof(int64) * 2;
    else if (!gc_enabled
             && (value_type == VALUE_TYPE_FUNCREF
                 || value_type == VALUE_TYPE_EXTERNREF))
        size_64bit = size_32bit = sizeof(int32);
    else if (gc_enabled
             && ((value_type >= (uint8)REF_TYPE_ARRAYREF
                  && value_type <= (uint8)REF_TYPE_NULLFUNCREF)
                 || (value_type >= (uint8)REF_TYPE_HT_NULLABLE
                     && value_type <= (uint8)REF_TYPE_HT_NON_NULLABLE)
#if WASM_ENABLE_STRINGREF != 0
                 || (value_type >= (uint8)REF_TYPE_STRINGVIEWWTF8
                     && value_type <= (uint8)REF_TYPE_STRINGREF)
                 || (value_type >= (uint8)REF_TYPE_STRINGVIEWITER
                     && value_type <= (uint8)REF_TYPE_STRINGVIEWWTF16)
#endif
                     )) {
        size_64bit = sizeof(uint64);
        size_32bit = sizeof(uint32);
    }
    else if (gc_enabled && value_type == PACKED_TYPE_I8) {
        size_64bit = size_32bit = sizeof(int8);
    }
    else if (gc_enabled && value_type == PACKED_TYPE_I16) {
        size_64bit = size_32bit = sizeof(int16);
    }
    else {
        bh_assert(0);
    }

    *p_size_64bit = size_64bit;
    *p_size_32bit = size_32bit;
}

static AOTImportGlobal *
aot_create_import_globals(const WASMModule *module, bool gc_enabled,
                          uint32 *p_import_global_data_size_64bit,
                          uint32 *p_import_global_data_size_32bit)
{
    AOTImportGlobal *import_globals;
    uint64 size;
    uint32 i, data_offset_64bit = 0, data_offset_32bit = 0;
    uint32 value_size_64bit, value_size_32bit;

    /* Allocate memory */
    size = sizeof(AOTImportGlobal) * (uint64)module->import_global_count;
    if (size >= UINT32_MAX
        || !(import_globals = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    memset(import_globals, 0, (uint32)size);

    /* Create each import global */
    for (i = 0; i < module->import_global_count; i++) {
        WASMGlobalImport *import_global = &module->import_globals[i].u.global;
        import_globals[i].module_name = import_global->module_name;
        import_globals[i].global_name = import_global->field_name;
        import_globals[i].type.val_type = import_global->type.val_type;
        import_globals[i].type.is_mutable = import_global->type.is_mutable;
        import_globals[i].global_data_linked =
            import_global->global_data_linked;

        import_globals[i].data_offset_64bit = data_offset_64bit;
        import_globals[i].data_offset_32bit = data_offset_32bit;

        get_value_type_size(import_global->type.val_type, gc_enabled,
                            &value_size_64bit, &value_size_32bit);

        import_globals[i].size_64bit = value_size_64bit;
        import_globals[i].size_32bit = value_size_32bit;
        data_offset_64bit += value_size_64bit;
        data_offset_32bit += value_size_32bit;
    }

    *p_import_global_data_size_64bit = data_offset_64bit;
    *p_import_global_data_size_32bit = data_offset_32bit;
    return import_globals;
}

static AOTGlobal *
aot_create_globals(const WASMModule *module, bool gc_enabled,
                   uint32 global_data_start_offset_64bit,
                   uint32 global_data_start_offset_32bit,
                   uint32 *p_global_data_size_64bit,
                   uint32 *p_global_data_size_32bit)
{
    AOTGlobal *globals;
    uint64 size;
    uint32 i;
    uint32 data_offset_64bit = global_data_start_offset_64bit;
    uint32 data_offset_32bit = global_data_start_offset_32bit;
    uint32 value_size_64bit, value_size_32bit;

    /* Allocate memory */
    size = sizeof(AOTGlobal) * (uint64)module->global_count;
    if (size >= UINT32_MAX || !(globals = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    memset(globals, 0, (uint32)size);

    /* Create each global */
    for (i = 0; i < module->global_count; i++) {
        WASMGlobal *global = &module->globals[i];
        globals[i].type.val_type = global->type.val_type;
        globals[i].type.is_mutable = global->type.is_mutable;
        memcpy(&globals[i].init_expr, &global->init_expr,
               sizeof(global->init_expr));

        globals[i].data_offset_64bit = data_offset_64bit;
        globals[i].data_offset_32bit = data_offset_32bit;

        get_value_type_size(global->type.val_type, gc_enabled,
                            &value_size_64bit, &value_size_32bit);

        globals[i].size_64bit = value_size_64bit;
        globals[i].size_32bit = value_size_32bit;
        data_offset_64bit += value_size_64bit;
        data_offset_32bit += value_size_32bit;
    }

    *p_global_data_size_64bit =
        data_offset_64bit - global_data_start_offset_64bit;
    *p_global_data_size_32bit =
        data_offset_32bit - global_data_start_offset_32bit;
    return globals;
}

static AOTImportFunc *
aot_create_import_funcs(const WASMModule *module)
{
    AOTImportFunc *import_funcs;
    uint64 size;
    uint32 i, j;

    /* Allocate memory */
    size = sizeof(AOTImportFunc) * (uint64)module->import_function_count;
    if (size >= UINT32_MAX
        || !(import_funcs = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    /* Create each import function */
    for (i = 0; i < module->import_function_count; i++) {
        WASMFunctionImport *import_func =
            &module->import_functions[i].u.function;
        import_funcs[i].module_name = import_func->module_name;
        import_funcs[i].func_name = import_func->field_name;
        import_funcs[i].func_ptr_linked = import_func->func_ptr_linked;
        import_funcs[i].func_type = import_func->func_type;
        import_funcs[i].signature = import_func->signature;
        import_funcs[i].attachment = import_func->attachment;
        import_funcs[i].call_conv_raw = import_func->call_conv_raw;
        import_funcs[i].call_conv_wasm_c_api = false;
        /* Resolve function type index */
        for (j = 0; j < module->type_count; j++)
            if (import_func->func_type == (WASMFuncType *)module->types[j]) {
                import_funcs[i].func_type_index = j;
                break;
            }
    }

    return import_funcs;
}

static void
aot_destroy_funcs(AOTFunc **funcs, uint32 count)
{
    uint32 i;

    for (i = 0; i < count; i++)
        if (funcs[i]) {
            if (funcs[i]->local_offsets)
                wasm_runtime_free(funcs[i]->local_offsets);
            wasm_runtime_free(funcs[i]);
        }
    wasm_runtime_free(funcs);
}

static AOTFunc **
aot_create_funcs(const WASMModule *module, uint32 pointer_size)
{
    AOTFunc **funcs;
    uint64 size;
    uint32 i, j;

    /* Allocate memory */
    size = sizeof(AOTFunc *) * (uint64)module->function_count;
    if (size >= UINT32_MAX || !(funcs = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    memset(funcs, 0, size);

    /* Create each function */
    for (i = 0; i < module->function_count; i++) {
        WASMFunction *func = module->functions[i];
        AOTFuncType *func_type = NULL;
        AOTFunc *aot_func = NULL;
        uint64 total_size;
        uint32 offset = 0;

        size = sizeof(AOTFunc);
        if (!(aot_func = funcs[i] = wasm_runtime_malloc((uint32)size))) {
            aot_set_last_error("allocate memory failed.");
            goto fail;
        }
        memset(aot_func, 0, sizeof(AOTFunc));

        func_type = aot_func->func_type = func->func_type;

        /* Resolve function type index */
        for (j = 0; j < module->type_count; j++) {
            if (func_type == (WASMFuncType *)module->types[j]) {
                aot_func->func_type_index = j;
                break;
            }
        }

        total_size = sizeof(uint16)
                     * ((uint64)func_type->param_count + func->local_count);
        if ((total_size > 0)
            && (total_size >= UINT32_MAX
                || !(aot_func->local_offsets =
                         wasm_runtime_malloc((uint32)total_size)))) {
            aot_set_last_error("allocate memory failed.");
            goto fail;
        }

        /* Resolve local variable info and code info */
        aot_func->local_count = func->local_count;
        aot_func->local_types_wp = func->local_types;
        aot_func->code = func->code;
        aot_func->code_size = func->code_size;

        /* Resolve local offsets */
        for (j = 0; j < func_type->param_count; j++) {
            aot_func->local_offsets[j] = (uint16)offset;
            offset += wasm_value_type_cell_num_internal(func_type->types[j],
                                                        pointer_size);
        }
        aot_func->param_cell_num = offset;

        for (j = 0; j < func->local_count; j++) {
            aot_func->local_offsets[func_type->param_count + j] =
                (uint16)offset;
            offset += wasm_value_type_cell_num_internal(func->local_types[j],
                                                        pointer_size);
        }
        aot_func->local_cell_num = offset - aot_func->param_cell_num;

        aot_func->max_stack_cell_num = func->max_stack_cell_num;
        /* We use max_stack_cell_num calculated from wasm_loader, which is based
         * on wamrc's target type.
         *  - If the wamrc is compiled as 64bit, then the number is enough for
         *      both 32bit and 64bit runtime target
         *  - If the wamrc is compiled as 32bit, then we multiply this number by
         *      two to avoid overflow on 64bit runtime target  */
        if (sizeof(uintptr_t) == 4) {
            aot_func->max_stack_cell_num *= 2;
        }
    }

    return funcs;

fail:
    aot_destroy_funcs(funcs, module->function_count);
    return NULL;
}

#if WASM_ENABLE_GC != 0
static void
calculate_struct_field_sizes_offsets(AOTCompData *comp_data, bool is_target_x86,
                                     bool gc_enabled)
{
    uint32 i;

    for (i = 0; i < comp_data->type_count; i++) {
        if (comp_data->types[i]->type_flag == WASM_TYPE_STRUCT) {
            WASMStructType *struct_type = (WASMStructType *)comp_data->types[i];
            WASMStructFieldType *fields = struct_type->fields;
            uint32 field_offset_64bit, field_offset_32bit;
            uint32 field_size_64bit, field_size_32bit, j;

            /* offsetof(WASMStructObject, field_data) in 64-bit */
            field_offset_64bit = sizeof(uint64);

            /* offsetof(WASMStructObject, field_data) in 32-bit */
            field_offset_32bit = sizeof(uint32);

            for (j = 0; j < struct_type->field_count; j++) {
                get_value_type_size(fields[j].field_type, gc_enabled,
                                    &field_size_64bit, &field_size_32bit);

                fields[j].field_size_64bit = field_size_64bit;
                fields[j].field_size_32bit = field_size_32bit;

                if (!is_target_x86) {
                    if (field_size_64bit == 2)
                        field_offset_64bit = align_uint(field_offset_64bit, 2);
                    else if (field_size_64bit >= 4)
                        field_offset_64bit = align_uint(field_offset_64bit, 4);

                    if (field_size_32bit == 2)
                        field_offset_32bit = align_uint(field_offset_32bit, 2);
                    else if (field_size_32bit >= 4)
                        field_offset_32bit = align_uint(field_offset_32bit, 4);
                }

                fields[j].field_offset_64bit = field_offset_64bit;
                fields[j].field_offset_32bit = field_offset_32bit;

                field_offset_64bit += field_size_64bit;
                field_offset_32bit += field_size_32bit;
            }
        }
    }
}
#endif

/**
 * Checks if target architecture is 64-bit based on target_arch string.
 *
 * @param target_arch The target architecture string (e.g. "x86_64", "aarch64")
 * @return true if target is 64-bit architecture, false otherwise
 *
 * If target_arch is NULL, detection is based on UINTPTR_MAX.
 * Otherwise looks for "64" in target_arch string.
 */
static bool
arch_is_64bit(const char *target_arch)
{
    if (!target_arch) {
#if UINTPTR_MAX == UINT64_MAX
        return true;
#else
        return false;
#endif
    }
    /* All 64bit targets contains "64" string in their target name */
    return strstr(target_arch, "64") != NULL;
}

/**
 * Checks if target architecture is x86/x64 based on target_arch string.
 *
 * @param target_arch The target architecture string (e.g. "x86_64", "i386")
 * @return true if target is x86/x64 architecture, false otherwise
 *
 * If target_arch is NULL, detection is based on build-time definitions.
 * Otherwise checks for x86_64 or i386 in target_arch string.
 */
static bool
arch_is_x86(const char *target_arch)
{
    if (!target_arch) {
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64) \
    || defined(BUILD_TARGET_X86_32)
        return true;
#else
        return false;
#endif
    }
    return !strncmp(target_arch, "x86_64", 6)
           || !strncmp(target_arch, "i386", 4);
}

/**
 * Initialize memory information in AOT compilation data from WASM module.
 *
 * @param comp_data the AOT compilation data structure to initialize
 * @param module the source WASM module containing memory information
 * @return true if initialization succeeded, false otherwise
 */
static bool
aot_init_memories(AOTCompData *comp_data, WASMModule *module)
{
    uint32 i, j;
    uint64 size;

    comp_data->memory_count =
        module->import_memory_count + module->memory_count;

    /* Allocate memory for memory array, reserve one AOTMemory space at least */
    if (!comp_data->memory_count)
        comp_data->memory_count = 1;

    size = (uint64)comp_data->memory_count * sizeof(AOTMemory);
    if (size >= UINT32_MAX
        || !(comp_data->memories = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("create memories array failed.\n");
        return false;
    }
    memset(comp_data->memories, 0, size);

    if (!(module->import_memory_count + module->memory_count)) {
        comp_data->memories[0].num_bytes_per_page = DEFAULT_NUM_BYTES_PER_PAGE;
    }

    /* Set memory page count */
    for (i = 0; i < module->import_memory_count + module->memory_count; i++) {
        if (i < module->import_memory_count) {
            comp_data->memories[i].flags =
                module->import_memories[i].u.memory.mem_type.flags;
            comp_data->memories[i].num_bytes_per_page =
                module->import_memories[i].u.memory.mem_type.num_bytes_per_page;
            comp_data->memories[i].init_page_count =
                module->import_memories[i].u.memory.mem_type.init_page_count;
            comp_data->memories[i].max_page_count =
                module->import_memories[i].u.memory.mem_type.max_page_count;
        }
        else {
            j = i - module->import_memory_count;
            comp_data->memories[i].flags = module->memories[j].flags;
            comp_data->memories[i].num_bytes_per_page =
                module->memories[j].num_bytes_per_page;
            comp_data->memories[i].init_page_count =
                module->memories[j].init_page_count;
            comp_data->memories[i].max_page_count =
                module->memories[j].max_page_count;
        }
    }

    return true;
}

/**
 * Initialize table information in AOT compilation data from WASM module.
 *
 * @param comp_data the AOT compilation data structure to initialize
 * @param module the source WASM module containing table information
 * @return true if initialization succeeded, false otherwise
 */
static bool
aot_init_tables(AOTCompData *comp_data, WASMModule *module)
{
    uint32 i, j;
    uint64 size;

    comp_data->table_count = module->import_table_count + module->table_count;

    if (comp_data->table_count > 0) {
        size = sizeof(AOTTable) * (uint64)comp_data->table_count;
        if (size >= UINT32_MAX
            || !(comp_data->tables = wasm_runtime_malloc((uint32)size))) {
            aot_set_last_error("create tables array failed.\n");
            return false;
        }
        memset(comp_data->tables, 0, size);
        for (i = 0; i < comp_data->table_count; i++) {
            if (i < module->import_table_count) {
                comp_data->tables[i].table_type.elem_type =
                    module->import_tables[i].u.table.table_type.elem_type;
                comp_data->tables[i].table_type.flags =
                    module->import_tables[i].u.table.table_type.flags;
                comp_data->tables[i].table_type.init_size =
                    module->import_tables[i].u.table.table_type.init_size;
                comp_data->tables[i].table_type.max_size =
                    module->import_tables[i].u.table.table_type.max_size;
#if WASM_ENABLE_GC != 0
                comp_data->tables[i].table_type.elem_ref_type =
                    module->import_tables[i].u.table.table_type.elem_ref_type;
#endif
                comp_data->tables[i].table_type.possible_grow =
                    module->import_tables[i].u.table.table_type.possible_grow;
            }
            else {
                j = i - module->import_table_count;
                comp_data->tables[i].table_type.elem_type =
                    module->tables[j].table_type.elem_type;
                comp_data->tables[i].table_type.flags =
                    module->tables[j].table_type.flags;
                comp_data->tables[i].table_type.init_size =
                    module->tables[j].table_type.init_size;
                comp_data->tables[i].table_type.max_size =
                    module->tables[j].table_type.max_size;
                comp_data->tables[i].table_type.possible_grow =
                    module->tables[j].table_type.possible_grow;
#if WASM_ENABLE_GC != 0
                comp_data->tables[j].table_type.elem_ref_type =
                    module->tables[j].table_type.elem_ref_type;
                /* Note: if the init_expr contains extra data for struct/array
                 * initialization information (init_expr.u.data), the pointer is
                 * copied.
                 * The pointers should still belong to wasm module, so DO NOT
                 * free the pointers copied to comp_data */
                comp_data->tables[j].init_expr = module->tables[j].init_expr;
#endif
            }
        }
    }

    return true;
}

/**
 * Initialize memory segment information in AOT compilation data.
 *
 * @param comp_data the AOT compilation data structure to initialize
 * @param module the source WASM module containing memory segments
 * @return true if initialization succeeded, false otherwise
 */
static bool
aot_init_memory_segments(AOTCompData *comp_data, WASMModule *module)
{
    comp_data->mem_init_data_count = module->data_seg_count;
    if (comp_data->mem_init_data_count > 0
        && !(comp_data->mem_init_data_list =
                 aot_create_mem_init_data_list(module))) {
        return false;
    }
    return true;
}

/**
 * Initialize table segment information in AOT compilation data.
 *
 * @param comp_data the AOT compilation data structure to initialize
 * @param module the source WASM module containing table segments
 * @return true if initialization succeeded, false otherwise
 */
static bool
aot_init_table_segments(AOTCompData *comp_data, WASMModule *module)
{
    comp_data->table_init_data_count = module->table_seg_count;
    if (comp_data->table_init_data_count > 0
        && !(comp_data->table_init_data_list =
                 aot_create_table_init_data_list(module))) {
        return false;
    }
    return true;
}

/**
 * Initialize global variable information in AOT compilation data.
 *
 * @param comp_data the AOT compilation data structure to initialize
 * @param module the source WASM module containing global information
 * @param gc_enabled whether garbage collection is enabled
 * @param import_global_data_size_64bit [out] size of imported global data for
 * 64-bit
 * @param import_global_data_size_32bit [out] size of imported global data for
 * 32-bit
 * @param global_data_size_64bit [out] size of global data for 64-bit
 * @param global_data_size_32bit [out] size of global data for 32-bit
 * @return true if initialization succeeded, false otherwise
 */
static bool
aot_init_globals(AOTCompData *comp_data, WASMModule *module, bool gc_enabled,
                 uint32 *import_global_data_size_64bit,
                 uint32 *import_global_data_size_32bit,
                 uint32 *global_data_size_64bit, uint32 *global_data_size_32bit)
{
    comp_data->import_global_count = module->import_global_count;
    if (comp_data->import_global_count > 0
        && !(comp_data->import_globals = aot_create_import_globals(
                 module, gc_enabled, import_global_data_size_64bit,
                 import_global_data_size_32bit))) {
        return false;
    }

    comp_data->global_count = module->global_count;
    if (comp_data->global_count
        && !(comp_data->globals = aot_create_globals(
                 module, gc_enabled, *import_global_data_size_64bit,
                 *import_global_data_size_32bit, global_data_size_64bit,
                 global_data_size_32bit))) {
        return false;
    }

    comp_data->global_data_size_64bit =
        *import_global_data_size_64bit + *global_data_size_64bit;
    comp_data->global_data_size_32bit =
        *import_global_data_size_32bit + *global_data_size_32bit;

    return true;
}

/**
 * Initialize type information in AOT compilation data.
 *
 * @param comp_data the AOT compilation data structure to initialize
 * @param module the source WASM module containing type information
 * @param is_target_x86 whether the target architecture is x86
 * @param gc_enabled whether garbage collection is enabled
 * @return true if initialization succeeded, false otherwise
 */
static bool
aot_init_types(AOTCompData *comp_data, WASMModule *module, bool is_target_x86,
               bool gc_enabled)
{
    comp_data->type_count = module->type_count;
    comp_data->types = module->types;
#if WASM_ENABLE_GC != 0
    calculate_struct_field_sizes_offsets(comp_data, is_target_x86, gc_enabled);
#endif
    return true;
}

/**
 * Initialize function information in AOT compilation data.
 *
 * @param comp_data the AOT compilation data structure to initialize
 * @param module the source WASM module containing function information
 * @param is_64bit_target whether the target architecture is 64-bit
 * @return true if initialization succeeded, false otherwise
 */
static bool
aot_init_functions(AOTCompData *comp_data, WASMModule *module,
                   bool is_64bit_target)
{
    comp_data->import_func_count = module->import_function_count;
    if (comp_data->import_func_count
        && !(comp_data->import_funcs = aot_create_import_funcs(module))) {
        return false;
    }

    comp_data->func_count = module->function_count;
    if (comp_data->func_count
        && !(comp_data->funcs =
                 aot_create_funcs(module, is_64bit_target ? 8 : 4))) {
        return false;
    }

    return true;
}

/**
 * Initialize auxiliary data in AOT compilation data.
 *
 * @param comp_data the AOT compilation data structure to initialize
 * @param module the source WASM module containing auxiliary data
 */
static void
aot_init_aux_data(AOTCompData *comp_data, WASMModule *module)
{
    comp_data->aux_data_end_global_index = module->aux_data_end_global_index;
    comp_data->aux_data_end = module->aux_data_end;
    comp_data->aux_heap_base_global_index = module->aux_heap_base_global_index;
    comp_data->aux_heap_base = module->aux_heap_base;
    comp_data->aux_stack_top_global_index = module->aux_stack_top_global_index;
    comp_data->aux_stack_bottom = module->aux_stack_bottom;
    comp_data->aux_stack_size = module->aux_stack_size;

    comp_data->start_func_index = module->start_function;
    comp_data->malloc_func_index = module->malloc_function;
    comp_data->free_func_index = module->free_function;
    comp_data->retain_func_index = module->retain_function;

#if WASM_ENABLE_STRINGREF != 0
    comp_data->string_literal_count = module->string_literal_count;
    comp_data->string_literal_ptrs_wp = module->string_literal_ptrs;
    comp_data->string_literal_lengths_wp = module->string_literal_lengths;
#endif
}

AOTCompData *
aot_create_comp_data(WASMModule *module, const char *target_arch,
                     bool gc_enabled)
{
    AOTCompData *comp_data;
    uint32 import_global_data_size_64bit = 0, global_data_size_64bit = 0;
    uint32 import_global_data_size_32bit = 0, global_data_size_32bit = 0;
    bool is_64bit_target = arch_is_64bit(target_arch);
    bool is_target_x86 = arch_is_x86(target_arch);

    if (!(comp_data = wasm_runtime_malloc(sizeof(AOTCompData)))) {
        aot_set_last_error("create compile data failed.\n");
        return NULL;
    }
    memset(comp_data, 0, sizeof(AOTCompData));

    if (!aot_init_memories(comp_data, module)
        || !aot_init_memory_segments(comp_data, module)
        || !aot_init_tables(comp_data, module)
        || !aot_init_table_segments(comp_data, module)
        || !aot_init_globals(comp_data, module, gc_enabled,
                             &import_global_data_size_64bit,
                             &import_global_data_size_32bit,
                             &global_data_size_64bit, &global_data_size_32bit)
        || !aot_init_types(comp_data, module, is_target_x86, gc_enabled)
        || !aot_init_functions(comp_data, module, is_64bit_target)) {
        goto fail;
    }

#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
    comp_data->name_section_buf = module->name_section_buf;
    comp_data->name_section_buf_end = module->name_section_buf_end;
#endif

    aot_init_aux_data(comp_data, module);

    comp_data->wasm_module = module;

    return comp_data;

fail:

    aot_destroy_comp_data(comp_data);
    return NULL;
}

void
aot_destroy_comp_data(AOTCompData *comp_data)
{
    if (!comp_data)
        return;

    if (comp_data->import_memories)
        wasm_runtime_free(comp_data->import_memories);

    if (comp_data->memories)
        wasm_runtime_free(comp_data->memories);

    if (comp_data->mem_init_data_list)
        aot_destroy_mem_init_data_list(comp_data->mem_init_data_list,
                                       comp_data->mem_init_data_count);

    if (comp_data->import_tables)
        wasm_runtime_free(comp_data->import_tables);

    if (comp_data->tables)
        wasm_runtime_free(comp_data->tables);

    if (comp_data->table_init_data_list)
        aot_destroy_table_init_data_list(comp_data->table_init_data_list,
                                         comp_data->table_init_data_count);

    if (comp_data->import_globals)
        wasm_runtime_free(comp_data->import_globals);

    if (comp_data->globals)
        wasm_runtime_free(comp_data->globals);

    if (comp_data->import_funcs)
        wasm_runtime_free(comp_data->import_funcs);

    if (comp_data->funcs)
        aot_destroy_funcs(comp_data->funcs, comp_data->func_count);

    if (comp_data->aot_name_section_buf)
        wasm_runtime_free(comp_data->aot_name_section_buf);

    wasm_runtime_free(comp_data);
}
