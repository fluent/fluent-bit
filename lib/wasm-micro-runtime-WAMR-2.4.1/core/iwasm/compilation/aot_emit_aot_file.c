/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_emit_aot_file.h"
#include "../aot/aot_runtime.h"

#define PUT_U64_TO_ADDR(addr, value)        \
    do {                                    \
        union {                             \
            uint64 val;                     \
            uint32 parts[2];                \
        } u;                                \
        u.val = (value);                    \
        ((uint32 *)(addr))[0] = u.parts[0]; \
        ((uint32 *)(addr))[1] = u.parts[1]; \
    } while (0)

#define CHECK_SIZE(size)                                   \
    do {                                                   \
        if (size == (uint32)-1) {                          \
            aot_set_last_error("get symbol size failed."); \
            return (uint32)-1;                             \
        }                                                  \
    } while (0)

/* Internal function in object file */
typedef struct AOTObjectFunc {
    char *func_name;
    /* text offset of aot_func#n */
    uint64 text_offset;
    /* text offset of aot_func_internal#n */
    uint64 text_offset_of_aot_func_internal;
} AOTObjectFunc;

/* Symbol table list node */
typedef struct AOTSymbolNode {
    struct AOTSymbolNode *next;
    uint32 str_len;
    char *symbol;
} AOTSymbolNode;

typedef struct AOTSymbolList {
    AOTSymbolNode *head;
    AOTSymbolNode *end;
    uint32 len;
} AOTSymbolList;

/* AOT object data */
struct AOTObjectData {
    AOTCompContext *comp_ctx;

    LLVMMemoryBufferRef mem_buf;
    LLVMBinaryRef binary;

    AOTTargetInfo target_info;

    void *text;
    uint32 text_size;

    void *text_unlikely;
    uint32 text_unlikely_size;

    void *text_hot;
    uint32 text_hot_size;

    /* literal data and size */
    void *literal;
    uint32 literal_size;

    AOTObjectDataSection *data_sections;
    uint32 data_sections_count;

    AOTObjectFunc *funcs;
    uint32 func_count;

    AOTSymbolList symbol_list;
    AOTRelocationGroup *relocation_groups;
    uint32 relocation_group_count;

    const char *stack_sizes_section_name;
    uint32 stack_sizes_offset;
    uint32 *stack_sizes;
};

#if 0
static void dump_buf(uint8 *buf, uint32 size, char *title)
{
    int i;
    printf("------ %s -------", title);
    for (i = 0; i < size; i++) {
        if ((i % 16) == 0)
            printf("\n");
        printf("%02x ", (unsigned char)buf[i]);
    }
    printf("\n\n");
}
#endif

static bool
is_32bit_binary(const AOTObjectData *obj_data)
{
    /* bit 1: 0 is 32-bit, 1 is 64-bit */
    return obj_data->target_info.bin_type & 2 ? false : true;
}

static bool
is_little_endian_binary(const AOTObjectData *obj_data)
{
    /* bit 0: 0 is little-endian, 1 is big-endian */
    return obj_data->target_info.bin_type & 1 ? false : true;
}

static bool
str_starts_with(const char *str, const char *prefix)
{
    size_t len_pre = strlen(prefix), len_str = strlen(str);
    return (len_str >= len_pre) && !memcmp(str, prefix, len_pre);
}

static uint32
get_file_header_size()
{
    /* magic number (4 bytes) + version (4 bytes) */
    return sizeof(uint32) + sizeof(uint32);
}

static uint32
get_string_size(AOTCompContext *comp_ctx, const char *s)
{
    /* string size (2 bytes) + string content + '\0' */
    return (uint32)sizeof(uint16) + (uint32)strlen(s) + 1;
}

static uint32
get_target_info_section_size()
{
    return sizeof(AOTTargetInfo);
}

static uint32
get_init_expr_size(const AOTCompContext *comp_ctx, const AOTCompData *comp_data,
                   InitializerExpression *expr);

static uint32
get_mem_init_data_size(AOTCompContext *comp_ctx, AOTMemInitData *mem_init_data)
{
    /* init expr type (4 bytes)
     * + init expr value (4 bytes, valid value can only be i32/get_global)
     * + byte count (4 bytes) + bytes */
    uint32 total_size =
        (uint32)(get_init_expr_size(comp_ctx, comp_ctx->comp_data,
                                    &mem_init_data->offset)
                 + sizeof(uint32) + mem_init_data->byte_count);

    /* bulk_memory enabled:
        is_passive (4 bytes) + memory_index (4 bytes)
       bulk memory disabled:
        placeholder (4 bytes) + placeholder (4 bytes)
    */
    total_size += (sizeof(uint32) + sizeof(uint32));

    return total_size;
}

static uint32
get_mem_init_data_list_size(AOTCompContext *comp_ctx,
                            AOTMemInitData **mem_init_data_list,
                            uint32 mem_init_data_count)
{
    AOTMemInitData **mem_init_data = mem_init_data_list;
    uint32 size = 0, i;

    for (i = 0; i < mem_init_data_count; i++, mem_init_data++) {
        size = align_uint(size, 4);
        size += get_mem_init_data_size(comp_ctx, *mem_init_data);
    }
    return size;
}

static uint32
get_import_memory_size(AOTCompData *comp_data)
{
    /* currently we only emit import_memory_count = 0 */
    return sizeof(uint32);
}

static uint32
get_memory_size(AOTCompData *comp_data)
{
    /* memory_count + count * (flags + num_bytes_per_page +
                               init_page_count + max_page_count) */
    return (uint32)(sizeof(uint32)
                    + comp_data->memory_count * sizeof(uint32) * 4);
}

static uint32
get_mem_info_size(AOTCompContext *comp_ctx, AOTCompData *comp_data)
{
    /* import_memory_size + memory_size
       + init_data_count + init_data_list */
    return get_import_memory_size(comp_data) + get_memory_size(comp_data)
           + (uint32)sizeof(uint32)
           + get_mem_init_data_list_size(comp_ctx,
                                         comp_data->mem_init_data_list,
                                         comp_data->mem_init_data_count);
}

static uint32
get_init_expr_size(const AOTCompContext *comp_ctx, const AOTCompData *comp_data,
                   InitializerExpression *expr)
{
    /* init_expr_type */
    uint32 size = sizeof(uint32);
#if WASM_ENABLE_GC != 0
    WASMModule *module = comp_data->wasm_module;
#endif
    bh_assert(expr != NULL);
    /* + init value size */
    switch (expr->init_expr_type) {
        case INIT_EXPR_NONE:
            /* no init value, used in table initializer */
            break;
        case INIT_EXPR_TYPE_I32_CONST:
        case INIT_EXPR_TYPE_F32_CONST:
        case INIT_EXPR_TYPE_GET_GLOBAL:
            size += sizeof(uint32);
            break;
        case INIT_EXPR_TYPE_I64_CONST:
        case INIT_EXPR_TYPE_F64_CONST:
            size += sizeof(uint64);
            break;
        case INIT_EXPR_TYPE_V128_CONST:
            size += sizeof(uint64) * 2;
            break;
        case INIT_EXPR_TYPE_FUNCREF_CONST:
        case INIT_EXPR_TYPE_REFNULL_CONST:
            /* ref_index */
            size += sizeof(uint32);
            break;
#if WASM_ENABLE_GC != 0
        case INIT_EXPR_TYPE_I31_NEW:
            /* i32 */
            size += sizeof(uint32);
            break;
        case INIT_EXPR_TYPE_STRUCT_NEW:
        {
            uint32 i;
            WASMStructNewInitValues *struct_new_init_values =
                (WASMStructNewInitValues *)expr->u.unary.v.data;

            /* type_index + field_count + fields */
            size += sizeof(uint32) + sizeof(uint32);

            bh_assert(struct_new_init_values->type_idx < module->type_count);

            for (i = 0; i < struct_new_init_values->count; i++) {
                WASMStructType *struct_type =
                    (WASMStructType *)
                        module->types[struct_new_init_values->type_idx];
                uint32 field_size;

                bh_assert(struct_type);
                bh_assert(struct_type->field_count
                          == struct_new_init_values->count);

                field_size = wasm_value_type_size_internal(
                    struct_type->fields[i].field_type, comp_ctx->pointer_size);
                if (field_size < sizeof(uint32))
                    field_size = sizeof(uint32);
                size += field_size;
            }
            break;
        }
        case INIT_EXPR_TYPE_STRUCT_NEW_DEFAULT:
            /* type_index */
            size += sizeof(uint32);
            break;
        case INIT_EXPR_TYPE_ARRAY_NEW_DEFAULT:
            /* array_elem_type + type_index + len */
            size += sizeof(uint32) * 3;
            break;
        case INIT_EXPR_TYPE_ARRAY_NEW:
        case INIT_EXPR_TYPE_ARRAY_NEW_FIXED:
        {
            WASMArrayNewInitValues *array_new_init_values =
                (WASMArrayNewInitValues *)expr->u.unary.v.data;
            WASMArrayType *array_type = NULL;
            uint32 value_count;

            array_type =
                (WASMArrayType *)module->types[array_new_init_values->type_idx];

            bh_assert(array_type);
            bh_assert(array_new_init_values->type_idx < module->type_count);

            value_count =
                (expr->init_expr_type == INIT_EXPR_TYPE_ARRAY_NEW_FIXED)
                    ? array_new_init_values->length
                    : 1;

            /* array_elem_type + type_index + len + elems */
            size += sizeof(uint32) * 3
                    + (uint64)wasm_value_type_size_internal(
                          array_type->elem_type, comp_ctx->pointer_size)
                          * value_count;
            break;
        }
#endif /* end of WASM_ENABLE_GC != 0 */
#if WASM_ENABLE_EXTENDED_CONST_EXPR != 0
        case INIT_EXPR_TYPE_I32_ADD:
        case INIT_EXPR_TYPE_I32_SUB:
        case INIT_EXPR_TYPE_I32_MUL:
        case INIT_EXPR_TYPE_I64_ADD:
        case INIT_EXPR_TYPE_I64_SUB:
        case INIT_EXPR_TYPE_I64_MUL:
        {
            size +=
                get_init_expr_size(comp_ctx, comp_data, expr->u.binary.l_expr);
            size +=
                get_init_expr_size(comp_ctx, comp_data, expr->u.binary.r_expr);
            break;
        }
#endif
        default:
            bh_assert(0);
    }

    return size;
}

static uint32
get_table_init_data_size(AOTCompContext *comp_ctx,
                         AOTTableInitData *table_init_data)
{
    uint32 size, i;

    /*
     * mode (4 bytes), elem_type (4 bytes)
     *
     * table_index(4 bytes)
     */
    size = (uint32)(sizeof(uint32) * 2 + sizeof(uint32))
           /* Size of WasmRefType - inner padding (ref type + nullable +
              heap_type) */
           + 8;

    size += get_init_expr_size(comp_ctx, comp_ctx->comp_data,
                               &table_init_data->offset);

    /* + value count/func index count (4 bytes) + init_values */
    size += sizeof(uint32);
    for (i = 0; i < table_init_data->value_count; i++) {
        size += get_init_expr_size(comp_ctx, comp_ctx->comp_data,
                                   &table_init_data->init_values[i]);
    }

    return size;
}

static uint32
get_table_init_data_list_size(AOTCompContext *comp_ctx,
                              AOTTableInitData **table_init_data_list,
                              uint32 table_init_data_count)
{
    /*
     * ------------------------------
     * | table_init_data_count
     * ------------------------------
     * |                     | U32 mode
     * | AOTTableInitData[N] | U32 elem_type
     * |                     | U32 table_index
     * |                     | U32 offset.init_expr_type
     * |                     | U64 offset.u.i64
     * |                     | U32 func_index_count / elem_count
     * |                     | UINTPTR [func_index_count] / [elem_count]
     * ------------------------------
     */
    AOTTableInitData **table_init_data = table_init_data_list;
    uint32 size = 0, i;

    /* table_init_data_count(4 bytes) */
    size = (uint32)sizeof(uint32);

    for (i = 0; i < table_init_data_count; i++, table_init_data++) {
        size = align_uint(size, 4);
        size += get_table_init_data_size(comp_ctx, *table_init_data);
    }
    return size;
}

static uint32
get_import_table_size(const AOTCompContext *comp_ctx,
                      const AOTCompData *comp_data)
{
    /*
     * ------------------------------
     * | import_table_count
     * ------------------------------
     * |                   | U8 elem_type
     * |                   | U8 flags
     * |                   | U8 possible_grow
     * | AOTImportTable[N] | U8 elem_ref_type.nullable (for GC only)
     * |                   | U32 init_size
     * |                   | U32 max_size
     * |                   | U32 elem_ref_type.heap_type (for GC only)
     * ------------------------------
     */
    uint32 size = 0, i;

    size = (uint32)sizeof(uint32);
    for (i = 0; i < comp_data->import_table_count; i++) {
        size += sizeof(uint32) * 3;
#if WASM_ENABLE_GC != 0
        if (comp_ctx->enable_gc
            && comp_data->import_tables[i].table_type.elem_ref_type)
            size += sizeof(uint32);
#endif
    }
    return size;
}

static uint32
get_table_size(const AOTCompContext *comp_ctx, const AOTCompData *comp_data)
{
    /*
     * ------------------------------
     * | table_count
     * ------------------------------
     * |             | U8 elem_type
     * |             | U8 flags
     * |             | U8 possible_grow
     * | AOTTable[N] | U8 elem_ref_type.nullable (for GC only)
     * |             | U32 init_size
     * |             | U32 max_size
     * |             | U32 elem_ref_type.heap_type (for GC only)
     * |             | N   init_expr (for GC only)
     * ------------------------------
     */
    uint32 size = 0, i;

    size = (uint32)sizeof(uint32);
    for (i = 0; i < comp_data->table_count; i++) {
        size += sizeof(uint32) * 3;
#if WASM_ENABLE_GC != 0
        if (comp_ctx->enable_gc) {
            if (comp_data->tables[i].table_type.elem_ref_type) {
                size += sizeof(uint32);
            }
            size += get_init_expr_size(comp_ctx, comp_data,
                                       &comp_data->tables[i].init_expr);
        }
#endif
    }
    return size;
}

static uint32
get_table_info_size(AOTCompContext *comp_ctx, AOTCompData *comp_data)
{
    /*
     * ------------------------------
     * | import_table_count
     * ------------------------------
     * |
     * | AOTImportTable[import_table_count]
     * |
     * ------------------------------
     * | table_count
     * ------------------------------
     * |
     * | AOTTable[table_count]
     * |
     * ------------------------------
     * | table_init_data_count
     * ------------------------------
     * |
     * | AOTTableInitData*[table_init_data_count]
     * |
     * ------------------------------
     */
    return get_import_table_size(comp_ctx, comp_data)
           + get_table_size(comp_ctx, comp_data)
           + get_table_init_data_list_size(comp_ctx,
                                           comp_data->table_init_data_list,
                                           comp_data->table_init_data_count);
}

static uint32
get_func_type_size(AOTCompContext *comp_ctx, AOTFuncType *func_type)
{
#if WASM_ENABLE_GC != 0
    /* type flag + equivalence type flag + is_sub_final + parent_type_idx
       + rec_count + rec_idx + param count + result count
       + ref_type_map_count + types + context of ref_type_map */
    if (comp_ctx->enable_gc) {
        uint32 size = 0;

        /* type flag */
        size += sizeof(func_type->base_type.type_flag);
        /* equivalence type flag + is_sub_final */
        size += sizeof(uint16);
        /* parent_type_idx */
        size += sizeof(func_type->base_type.parent_type_idx);
        /* rec_count */
        size += sizeof(func_type->base_type.rec_count);
        /* rec_idx */
        size += sizeof(func_type->base_type.rec_idx);
        /* param count */
        size += sizeof(func_type->param_count);
        /* result count */
        size += sizeof(func_type->result_count);
        /* ref_type_map_count */
        size += sizeof(func_type->ref_type_map_count);
        /* param and result types */
        size += func_type->param_count + func_type->result_count;
        /* align size */
        size = align_uint(size, 4);
        /* ref_type_map */
        size += func_type->ref_type_map_count * 8;

        return size;
    }
    else
#endif
    {
        /* type flag + param count + result count + types */
        return (uint32)sizeof(uint16) * 3 + func_type->param_count
               + func_type->result_count;
    }
}

#if WASM_ENABLE_GC != 0
static uint32
get_struct_type_size(AOTCompContext *comp_ctx, AOTStructType *struct_type)
{
    uint32 size = 0;
    /* type flag + equivalence type flag + is_sub_final + parent_type_idx
       + rec_count + rec_idx + field count + fields */

    /* type flag */
    size += sizeof(struct_type->base_type.type_flag);
    /* equivalence type flag + is_sub_final */
    size += sizeof(uint16);
    /* parent_type_idx */
    size += sizeof(struct_type->base_type.parent_type_idx);
    /* rec_count */
    size += sizeof(struct_type->base_type.rec_count);
    /* rec_idx */
    size += sizeof(struct_type->base_type.rec_idx);
    /* field count */
    size += sizeof(struct_type->field_count);
    /* field types */
    size += struct_type->field_count * 2;
    /* ref_type_map_count */
    size += sizeof(struct_type->ref_type_map_count);
    size = align_uint(size, 4);
    /* ref_type_map */
    size += struct_type->ref_type_map_count * 8;
    return size;
}

static uint32
get_array_type_size(AOTCompContext *comp_ctx, AOTArrayType *array_type)
{
    uint32 size = 0;
    /* type flag + equivalence type flag + is_sub_final + parent_type_idx
       + rec_count + rec_idx + elem_flags + elem_type + elem_ref_type */

    /* type flag */
    size += sizeof(array_type->base_type.type_flag);
    /* equivalence type flag + is_sub_final */
    size += sizeof(uint16);
    /* parent_type_idx (u32) */
    size += sizeof(array_type->base_type.parent_type_idx);
    /* rec_count */
    size += sizeof(array_type->base_type.rec_count);
    /* rec_idx */
    size += sizeof(array_type->base_type.rec_idx);
    /* elem_flags (u16) */
    size += sizeof(array_type->elem_flags);
    /* elem_type (u8) */
    size += sizeof(array_type->elem_type);
    /* elem_ref_type */
    if (array_type->elem_ref_type) {
        /* nullable (u8) */
        size += sizeof(uint8);
        /* heap type (u32) */
        size += sizeof(uint32);
    }

    return size;
}
#endif

static uint32
get_type_info_size(AOTCompContext *comp_ctx, AOTCompData *comp_data)
{
    /* Initial size with size of type count */
    uint32 size = 4;
    uint32 i;

#if WASM_ENABLE_GC != 0
    if (comp_ctx->enable_gc) {
        for (i = 0; i < comp_data->type_count; i++) {
            uint32 j;

            size = align_uint(size, 4);

            /* Emit simple info if there is an equivalence type */
            for (j = 0; j < i; j++) {
                if (comp_data->types[j] == comp_data->types[i]) {
                    /* type_flag (2 bytes) + equivalence type flag (1 byte)
                       + padding (1 byte) + equivalence type index */
                    size += 8;
                    break;
                }
            }
            if (j < i)
                continue;

            if (comp_data->types[i]->type_flag == WASM_TYPE_FUNC)
                size += get_func_type_size(comp_ctx,
                                           (AOTFuncType *)comp_data->types[i]);
            else if (comp_data->types[i]->type_flag == WASM_TYPE_STRUCT)
                size += get_struct_type_size(
                    comp_ctx, (AOTStructType *)comp_data->types[i]);
            else if (comp_data->types[i]->type_flag == WASM_TYPE_ARRAY)
                size += get_array_type_size(
                    comp_ctx, (AOTArrayType *)comp_data->types[i]);
            else
                bh_assert(0);
        }
    }
    else
#endif
    {
        for (i = 0; i < comp_data->type_count; i++) {
            size = align_uint(size, 4);
            size += get_func_type_size(comp_ctx,
                                       (AOTFuncType *)comp_data->types[i]);
        }
    }

    return size;
}

static uint32
get_import_global_size(AOTCompContext *comp_ctx, AOTImportGlobal *import_global)
{
    /* type (1 byte) + is_mutable (1 byte) + module_name + global_name */
    uint32 size = (uint32)sizeof(uint8) * 2
                  + get_string_size(comp_ctx, import_global->module_name);
    size = align_uint(size, 2);
    size += get_string_size(comp_ctx, import_global->global_name);
    return size;
}

static uint32
get_import_globals_size(AOTCompContext *comp_ctx,
                        AOTImportGlobal *import_globals,
                        uint32 import_global_count)
{
    AOTImportGlobal *import_global = import_globals;
    uint32 size = 0, i;

    for (i = 0; i < import_global_count; i++, import_global++) {
        size = align_uint(size, 2);
        size += get_import_global_size(comp_ctx, import_global);
    }
    return size;
}

static uint32
get_import_global_info_size(AOTCompContext *comp_ctx, AOTCompData *comp_data)
{
    /* import global count + import globals */
    return (uint32)sizeof(uint32)
           + get_import_globals_size(comp_ctx, comp_data->import_globals,
                                     comp_data->import_global_count);
}

static uint32
get_global_size(AOTCompContext *comp_ctx, AOTGlobal *global)
{
    /* type (1 byte) + is_mutable (1 byte) + padding (2 bytes)
            + init expr value (include init expr type) */
    return sizeof(uint8) * 2 + sizeof(uint8) * 2
           + get_init_expr_size(comp_ctx, comp_ctx->comp_data,
                                &global->init_expr);
}

static uint32
get_globals_size(AOTCompContext *comp_ctx, AOTGlobal *globals,
                 uint32 global_count)
{
    AOTGlobal *global = globals;
    uint32 size = 0, i;

    for (i = 0; i < global_count; i++, global++) {
        size = align_uint(size, 4);
        size += get_global_size(comp_ctx, global);
    }
    return size;
}

static uint32
get_global_info_size(AOTCompContext *comp_ctx, AOTCompData *comp_data)
{
    /* global count + globals */
    return (uint32)sizeof(uint32)
           + get_globals_size(comp_ctx, comp_data->globals,
                              comp_data->global_count);
}

static uint32
get_import_func_size(AOTCompContext *comp_ctx, AOTImportFunc *import_func)
{
    /* type index (2 bytes) + module_name + func_name */
    uint32 size = (uint32)sizeof(uint16)
                  + get_string_size(comp_ctx, import_func->module_name);
    size = align_uint(size, 2);
    size += get_string_size(comp_ctx, import_func->func_name);
    return size;
}

static uint32
get_import_funcs_size(AOTCompContext *comp_ctx, AOTImportFunc *import_funcs,
                      uint32 import_func_count)
{
    AOTImportFunc *import_func = import_funcs;
    uint32 size = 0, i;

    for (i = 0; i < import_func_count; i++, import_func++) {
        size = align_uint(size, 2);
        size += get_import_func_size(comp_ctx, import_func);
    }
    return size;
}

static uint32
get_import_func_info_size(AOTCompContext *comp_ctx, AOTCompData *comp_data)
{
    /* import func count + import funcs */
    return (uint32)sizeof(uint32)
           + get_import_funcs_size(comp_ctx, comp_data->import_funcs,
                                   comp_data->import_func_count);
}

static uint32
get_object_data_sections_size(AOTCompContext *comp_ctx,
                              AOTObjectDataSection *data_sections,
                              uint32 data_sections_count)
{
    AOTObjectDataSection *data_section = data_sections;
    uint32 size = 0, i;

    for (i = 0; i < data_sections_count; i++, data_section++) {
        /* name + size + data */
        size = align_uint(size, 2);
        size += get_string_size(comp_ctx, data_section->name);
        size = align_uint(size, 4);
        size += (uint32)sizeof(uint32);
        size += data_section->size;
    }
    return size;
}

static uint32
get_object_data_section_info_size(AOTCompContext *comp_ctx,
                                  AOTObjectData *obj_data)
{
    /* data sections count + data sections */
    return (uint32)sizeof(uint32)
           + get_object_data_sections_size(comp_ctx, obj_data->data_sections,
                                           obj_data->data_sections_count);
}

static uint32
get_init_data_section_size(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                           AOTObjectData *obj_data)
{
    uint32 size = 0;

    size += get_mem_info_size(comp_ctx, comp_data);

    size = align_uint(size, 4);
    size += get_table_info_size(comp_ctx, comp_data);

    size = align_uint(size, 4);
    size += get_type_info_size(comp_ctx, comp_data);

    size = align_uint(size, 4);
    size += get_import_global_info_size(comp_ctx, comp_data);

    size = align_uint(size, 4);
    size += get_global_info_size(comp_ctx, comp_data);

    size = align_uint(size, 4);
    size += get_import_func_info_size(comp_ctx, comp_data);

    /* func count + start func index */
    size = align_uint(size, 4);
    size += (uint32)sizeof(uint32) * 2;

    /* aux data/heap/stack data */
    size += sizeof(uint32) * 10;

    size += get_object_data_section_info_size(comp_ctx, obj_data);
    return size;
}

static uint32
get_text_section_size(AOTObjectData *obj_data)
{
    return sizeof(uint32) + align_uint(obj_data->literal_size, 4)
           + align_uint(obj_data->text_size, 4)
           + align_uint(obj_data->text_unlikely_size, 4)
           + align_uint(obj_data->text_hot_size, 4);
}

static uint32
get_func_section_size(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                      AOTObjectData *obj_data)
{
    uint32 size = 0;

    /* text offsets */
    if (is_32bit_binary(obj_data))
        size = (uint32)sizeof(uint32) * comp_data->func_count;
    else
        size = (uint32)sizeof(uint64) * comp_data->func_count;

    /* function type indexes */
    size += (uint32)sizeof(uint32) * comp_data->func_count;

    /* max_local_cell_nums */
    size += (uint32)sizeof(uint32) * comp_data->func_count;

    /* max_stack_cell_nums */
    size += (uint32)sizeof(uint32) * comp_data->func_count;

#if WASM_ENABLE_GC != 0
    /* func_local_ref_flags */
    if (comp_ctx->enable_gc) {
        AOTFuncType *func_type;
        uint32 i, j, local_ref_flags_cell_num;

        for (i = 0; i < comp_data->import_func_count; i++) {
            func_type = comp_data->import_funcs[i].func_type;
            /* recalculate cell_num based on target pointer size */
            local_ref_flags_cell_num = 0;
            for (j = 0; j < func_type->param_count; j++) {
                local_ref_flags_cell_num += wasm_value_type_cell_num_internal(
                    func_type->types[j], comp_ctx->pointer_size);
            }
            local_ref_flags_cell_num =
                local_ref_flags_cell_num > 2 ? local_ref_flags_cell_num : 2;

            size = align_uint(size, 4);
            size += (uint32)sizeof(uint32);
            size += (uint32)sizeof(uint8) * local_ref_flags_cell_num;
        }

        for (i = 0; i < comp_data->func_count; i++) {
            func_type = comp_data->funcs[i]->func_type;
            local_ref_flags_cell_num = comp_data->funcs[i]->param_cell_num
                                       + comp_data->funcs[i]->local_cell_num;

            size = align_uint(size, 4);
            size += (uint32)sizeof(uint32);
            size += (uint32)sizeof(uint8) * local_ref_flags_cell_num;
        }
    }
#endif

    return size;
}

static uint32
get_export_size(AOTCompContext *comp_ctx, AOTExport *export)
{
    /* export index + export kind + 1 byte padding + export name */
    return (uint32)sizeof(uint32) + sizeof(uint8) + 1
           + get_string_size(comp_ctx, export->name);
}

static uint32
get_exports_size(AOTCompContext *comp_ctx, AOTExport *exports,
                 uint32 export_count)
{
    AOTExport *export = exports;
    uint32 size = 0, i;

    for (i = 0; i < export_count; i++, export ++) {
        size = align_uint(size, 4);
        size += get_export_size(comp_ctx, export);
    }
    return size;
}

static uint32
get_export_section_size(AOTCompContext *comp_ctx, AOTCompData *comp_data)
{
    /* export count + exports */
    return (uint32)sizeof(uint32)
           + get_exports_size(comp_ctx, comp_data->wasm_module->exports,
                              comp_data->wasm_module->export_count);
}

static uint32
get_relocation_size(AOTRelocation *relocation, bool is_32bin)
{
    /* offset + addend + relocation type + symbol name */
    uint32 size = 0;
    if (is_32bin)
        size = sizeof(uint32) * 2; /* offset and addend */
    else
        size = sizeof(uint64) * 2;  /* offset and addend */
    size += (uint32)sizeof(uint32); /* relocation type */
    size += (uint32)sizeof(uint32); /* symbol name index */
    return size;
}

static uint32
get_relocations_size(AOTObjectData *obj_data,
                     AOTRelocationGroup *relocation_group,
                     AOTRelocation *relocations, uint32 relocation_count,
                     bool is_32bin)
{
    AOTRelocation *relocation = relocations;
    uint32 size = 0, i;

    for (i = 0; i < relocation_count; i++, relocation++) {
        /* ignore the relocations to aot_func_internal#n in text section
           for windows platform since they will be applied in
           aot_emit_text_section */

        const char *name = relocation->symbol_name;
        if ((!strcmp(relocation_group->section_name, ".text")
             || !strcmp(relocation_group->section_name, ".ltext"))
            && !strncmp(name, AOT_FUNC_INTERNAL_PREFIX,
                        strlen(AOT_FUNC_INTERNAL_PREFIX))
            && ((!strncmp(obj_data->comp_ctx->target_arch, "x86_64", 6)
                 /* Windows AOT_COFF64_BIN_TYPE */
                 && obj_data->target_info.bin_type == 6
                 /* IMAGE_REL_AMD64_REL32 in windows x86_64 */
                 && relocation->relocation_type == 4)
                || (!strncmp(obj_data->comp_ctx->target_arch, "i386", 4)
                    /* Windows AOT_COFF32_BIN_TYPE */
                    && obj_data->target_info.bin_type == 4
                    /* IMAGE_REL_I386_REL32 in windows x86_32 */
                    && relocation->relocation_type == 20))) {
            continue;
        }
        size = align_uint(size, 4);
        size += get_relocation_size(relocation, is_32bin);
    }
    return size;
}

static uint32
get_relocation_group_size(AOTObjectData *obj_data,
                          AOTRelocationGroup *relocation_group, bool is_32bin)
{
    uint32 size = 0;
    /* section name index + relocation count + relocations */
    size += (uint32)sizeof(uint32);
    size += (uint32)sizeof(uint32);
    size += get_relocations_size(obj_data, relocation_group,
                                 relocation_group->relocations,
                                 relocation_group->relocation_count, is_32bin);
    return size;
}

static uint32
get_relocation_groups_size(AOTObjectData *obj_data,
                           AOTRelocationGroup *relocation_groups,
                           uint32 relocation_group_count, bool is_32bin)
{
    AOTRelocationGroup *relocation_group = relocation_groups;
    uint32 size = 0, i;

    for (i = 0; i < relocation_group_count; i++, relocation_group++) {
        size = align_uint(size, 4);
        size += get_relocation_group_size(obj_data, relocation_group, is_32bin);
    }
    return size;
}

/* return the index (in order of insertion) of the symbol,
   create if not exits, -1 if failed */
static uint32
get_relocation_symbol_index(const char *symbol_name, bool *is_new,
                            AOTSymbolList *symbol_list)
{
    AOTSymbolNode *sym;
    uint32 index = 0;

    sym = symbol_list->head;
    while (sym) {
        if (!strcmp(sym->symbol, symbol_name)) {
            if (is_new)
                *is_new = false;
            return index;
        }

        sym = sym->next;
        index++;
    }

    /* Not found in symbol_list, add it */
    sym = wasm_runtime_malloc(sizeof(AOTSymbolNode));
    if (!sym) {
        return (uint32)-1;
    }

    memset(sym, 0, sizeof(AOTSymbolNode));
    sym->symbol = (char *)symbol_name;
    sym->str_len = (uint32)strlen(symbol_name);

    if (!symbol_list->head) {
        symbol_list->head = symbol_list->end = sym;
    }
    else {
        symbol_list->end->next = sym;
        symbol_list->end = sym;
    }
    symbol_list->len++;

    if (is_new)
        *is_new = true;
    return index;
}

static uint32
get_relocation_symbol_size(AOTCompContext *comp_ctx, AOTRelocation *relocation,
                           AOTSymbolList *symbol_list)
{
    uint32 size = 0, index = 0;
    bool is_new = false;

    index = get_relocation_symbol_index(relocation->symbol_name, &is_new,
                                        symbol_list);
    CHECK_SIZE(index);

    if (is_new) {
        size += get_string_size(comp_ctx, relocation->symbol_name);
        size = align_uint(size, 2);
    }

    relocation->symbol_index = index;
    return size;
}

static uint32
get_relocations_symbol_size(AOTCompContext *comp_ctx,
                            AOTRelocation *relocations, uint32 relocation_count,
                            AOTSymbolList *symbol_list)
{
    AOTRelocation *relocation = relocations;
    uint32 size = 0, curr_size, i;

    for (i = 0; i < relocation_count; i++, relocation++) {
        curr_size =
            get_relocation_symbol_size(comp_ctx, relocation, symbol_list);
        CHECK_SIZE(curr_size);

        size += curr_size;
    }
    return size;
}

static uint32
get_relocation_group_symbol_size(AOTCompContext *comp_ctx,
                                 AOTRelocationGroup *relocation_group,
                                 AOTSymbolList *symbol_list)
{
    uint32 size = 0, index = 0, curr_size;
    bool is_new = false;

    index = get_relocation_symbol_index(relocation_group->section_name, &is_new,
                                        symbol_list);
    CHECK_SIZE(index);

    if (is_new) {
        size += get_string_size(comp_ctx, relocation_group->section_name);
        size = align_uint(size, 2);
    }

    relocation_group->name_index = index;

    curr_size = get_relocations_symbol_size(
        comp_ctx, relocation_group->relocations,
        relocation_group->relocation_count, symbol_list);
    CHECK_SIZE(curr_size);
    size += curr_size;

    return size;
}

static uint32
get_relocation_groups_symbol_size(AOTCompContext *comp_ctx,
                                  AOTRelocationGroup *relocation_groups,
                                  uint32 relocation_group_count,
                                  AOTSymbolList *symbol_list)
{
    AOTRelocationGroup *relocation_group = relocation_groups;
    uint32 size = 0, curr_size, i;

    for (i = 0; i < relocation_group_count; i++, relocation_group++) {
        curr_size = get_relocation_group_symbol_size(comp_ctx, relocation_group,
                                                     symbol_list);
        CHECK_SIZE(curr_size);
        size += curr_size;
    }
    return size;
}

static uint32
get_symbol_size_from_symbol_list(AOTCompContext *comp_ctx,
                                 AOTSymbolList *symbol_list)
{
    AOTSymbolNode *sym;
    uint32 size = 0;

    sym = symbol_list->head;
    while (sym) {
        /* (uint16)str_len + str */
        size += get_string_size(comp_ctx, sym->symbol);
        size = align_uint(size, 2);
        sym = sym->next;
    }

    return size;
}

static uint32
get_relocation_section_symbol_size(AOTCompContext *comp_ctx,
                                   AOTObjectData *obj_data)
{
    AOTRelocationGroup *relocation_groups = obj_data->relocation_groups;
    uint32 relocation_group_count = obj_data->relocation_group_count;
    uint32 string_count = 0, symbol_table_size = 0;

    /* section size will be calculated twice,
       get symbol size from symbol list directly in the second calculation */
    if (obj_data->symbol_list.len > 0) {
        symbol_table_size =
            get_symbol_size_from_symbol_list(comp_ctx, &obj_data->symbol_list);
    }
    else {
        symbol_table_size = get_relocation_groups_symbol_size(
            comp_ctx, relocation_groups, relocation_group_count,
            &obj_data->symbol_list);
    }
    CHECK_SIZE(symbol_table_size);
    string_count = obj_data->symbol_list.len;

    /* string_count + string_offsets + total_string_len
       + [str (string_len + str)] */
    return (uint32)(sizeof(uint32) + sizeof(uint32) * string_count
                    + sizeof(uint32) + symbol_table_size);
}

static uint32
get_relocation_section_size(AOTCompContext *comp_ctx, AOTObjectData *obj_data)
{
    AOTRelocationGroup *relocation_groups = obj_data->relocation_groups;
    uint32 relocation_group_count = obj_data->relocation_group_count;
    uint32 symbol_table_size = 0;

    symbol_table_size = get_relocation_section_symbol_size(comp_ctx, obj_data);
    CHECK_SIZE(symbol_table_size);
    symbol_table_size = align_uint(symbol_table_size, 4);

    /* relocation group count + symbol_table + relocation groups */
    return (uint32)sizeof(uint32) + symbol_table_size
           + get_relocation_groups_size(obj_data, relocation_groups,
                                        relocation_group_count,
                                        is_32bit_binary(obj_data));
}

static uint32
get_native_symbol_list_size(AOTCompContext *comp_ctx)
{
    uint32 len = 0;
    AOTNativeSymbol *sym = NULL;

    sym = bh_list_first_elem(&comp_ctx->native_symbols);

    while (sym) {
        len = align_uint(len, 2);
        len += get_string_size(comp_ctx, sym->symbol);
        sym = bh_list_elem_next(sym);
    }

    return len;
}

#if WASM_ENABLE_STRINGREF != 0
static uint32
get_string_literal_section_size(AOTCompContext *comp_ctx,
                                AOTCompData *comp_data);
#endif

static uint32
get_custom_sections_size(AOTCompContext *comp_ctx, AOTCompData *comp_data);

uint32
aot_get_aot_file_size(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                      AOTObjectData *obj_data)
{
    uint32 size = 0;
    uint32 size_custom_section = 0;
#if WASM_ENABLE_STRINGREF != 0
    uint32 size_string_literal_section = 0;
#endif

    /* aot file header */
    size += get_file_header_size();

    /* target info section */
    size = align_uint(size, 4);
    /* section id + section size */
    size += (uint32)sizeof(uint32) * 2;
    size += get_target_info_section_size();

    /* init data section */
    size = align_uint(size, 4);
    /* section id + section size */
    size += (uint32)sizeof(uint32) * 2;
    size += get_init_data_section_size(comp_ctx, comp_data, obj_data);

    /* text section */
    size = align_uint(size, 4);
    /* section id + section size */
    size += (uint32)sizeof(uint32) * 2;
    size += get_text_section_size(obj_data);

    /* function section */
    size = align_uint(size, 4);
    /* section id + section size */
    size += (uint32)sizeof(uint32) * 2;
    size += get_func_section_size(comp_ctx, comp_data, obj_data);

    /* export section */
    size = align_uint(size, 4);
    /* section id + section size */
    size += (uint32)sizeof(uint32) * 2;
    size += get_export_section_size(comp_ctx, comp_data);

    /* relocation section */
    size = align_uint(size, 4);
    /* section id + section size */
    size += (uint32)sizeof(uint32) * 2;
    size += get_relocation_section_size(comp_ctx, obj_data);

    if (get_native_symbol_list_size(comp_ctx) > 0) {
        /* emit only when there are native symbols */
        size = align_uint(size, 4);
        /* section id + section size + sub section id + symbol count */
        size += (uint32)sizeof(uint32) * 4;
        size += get_native_symbol_list_size(comp_ctx);
    }

    size_custom_section = get_custom_sections_size(comp_ctx, comp_data);
    if (size_custom_section > 0) {
        size = align_uint(size, 4);
        size += size_custom_section;
    }

#if WASM_ENABLE_STRINGREF != 0
    /* string literal section */
    size_string_literal_section =
        get_string_literal_section_size(comp_ctx, comp_data);
    if (size_string_literal_section > 0) {
        size = align_uint(size, 4);
        /* section id + section size + sub section id */
        size += (uint32)sizeof(uint32) * 3;
        size += size_string_literal_section;
    }
#endif

    return size;
}

#define exchange_uint8(p_data) (void)0

static void
exchange_uint16(uint8 *p_data)
{
    uint8 value = *p_data;
    *p_data = *(p_data + 1);
    *(p_data + 1) = value;
}

static void
exchange_uint32(uint8 *p_data)
{
    uint8 value = *p_data;
    *p_data = *(p_data + 3);
    *(p_data + 3) = value;

    value = *(p_data + 1);
    *(p_data + 1) = *(p_data + 2);
    *(p_data + 2) = value;
}

static void
exchange_uint64(uint8 *p_data)
{
    uint32 value;

    value = *(uint32 *)p_data;
    *(uint32 *)p_data = *(uint32 *)(p_data + 4);
    *(uint32 *)(p_data + 4) = value;
    exchange_uint32(p_data);
    exchange_uint32(p_data + 4);
}

static void
exchange_uint128(uint8 *p_data)
{
    /* swap high 64bit and low 64bit */
    uint64 value = *(uint64 *)p_data;
    *(uint64 *)p_data = *(uint64 *)(p_data + 8);
    *(uint64 *)(p_data + 8) = value;
    /* exchange high 64bit */
    exchange_uint64(p_data);
    /* exchange low 64bit */
    exchange_uint64(p_data + 8);
}

static union {
    int a;
    char b;
} __ue = { .a = 1 };

#define is_little_endian() (__ue.b == 1)

#define CHECK_BUF(length)                       \
    do {                                        \
        if (buf + offset + length > buf_end) {  \
            aot_set_last_error("buf overflow"); \
            return false;                       \
        }                                       \
    } while (0)

#define EMIT_U8(v)                           \
    do {                                     \
        CHECK_BUF(1);                        \
        *(uint8 *)(buf + offset) = (uint8)v; \
        offset++;                            \
    } while (0)

#define EMIT_U16(v)                       \
    do {                                  \
        uint16 t = (uint16)v;             \
        CHECK_BUF(2);                     \
        if (!is_little_endian())          \
            exchange_uint16((uint8 *)&t); \
        *(uint16 *)(buf + offset) = t;    \
        offset += (uint32)sizeof(uint16); \
    } while (0)

#define EMIT_U32(v)                       \
    do {                                  \
        uint32 t = (uint32)v;             \
        CHECK_BUF(4);                     \
        if (!is_little_endian())          \
            exchange_uint32((uint8 *)&t); \
        *(uint32 *)(buf + offset) = t;    \
        offset += (uint32)sizeof(uint32); \
    } while (0)

#define EMIT_U64(v)                       \
    do {                                  \
        uint64 t = (uint64)v;             \
        CHECK_BUF(8);                     \
        if (!is_little_endian())          \
            exchange_uint64((uint8 *)&t); \
        PUT_U64_TO_ADDR(buf + offset, t); \
        offset += (uint32)sizeof(uint64); \
    } while (0)

#define EMIT_V128(v)                         \
    do {                                     \
        uint64 *t = (uint64 *)v.i64x2;       \
        CHECK_BUF(16);                       \
        if (!is_little_endian())             \
            exchange_uint128((uint8 *)t);    \
        PUT_U64_TO_ADDR(buf + offset, t[0]); \
        offset += (uint32)sizeof(uint64);    \
        PUT_U64_TO_ADDR(buf + offset, t[1]); \
        offset += (uint32)sizeof(uint64);    \
    } while (0)

#define EMIT_BUF(v, len)              \
    do {                              \
        CHECK_BUF(len);               \
        memcpy(buf + offset, v, len); \
        offset += len;                \
    } while (0)

/* Emit string with '\0'
 */
#define EMIT_STR(s)                                   \
    do {                                              \
        uint32 str_len = (uint32)strlen(s) + 1;       \
        if (str_len > INT16_MAX) {                    \
            aot_set_last_error("emit string failed: " \
                               "string too long");    \
            return false;                             \
        }                                             \
        EMIT_U16(str_len);                            \
        EMIT_BUF(s, str_len);                         \
    } while (0)

#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
static bool
read_leb(uint8 **p_buf, const uint8 *buf_end, uint32 maxbits, bool sign,
         uint64 *p_result)
{
    const uint8 *buf = *p_buf;
    uint64 result = 0;
    uint32 shift = 0;
    uint32 offset = 0, bcnt = 0;
    uint64 byte;

    while (true) {
        /* uN or SN must not exceed ceil(N/7) bytes */
        if (bcnt + 1 > (maxbits + 6) / 7) {
            aot_set_last_error("integer representation too long");
            return false;
        }

        if (buf + offset + 1 > buf_end) {
            aot_set_last_error("unexpected end of section or function");
            return false;
        }
        byte = buf[offset];
        offset += 1;
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        bcnt += 1;
        if ((byte & 0x80) == 0) {
            break;
        }
    }

    if (!sign && maxbits == 32 && shift >= maxbits) {
        /* The top bits set represent values > 32 bits */
        if (((uint8)byte) & 0xf0)
            goto fail_integer_too_large;
    }
    else if (sign && maxbits == 32) {
        if (shift < maxbits) {
            /* Sign extend, second highest bit is the sign bit */
            if ((uint8)byte & 0x40)
                result |= (~((uint64)0)) << shift;
        }
        else {
            /* The top bits should be a sign-extension of the sign bit */
            bool sign_bit_set = ((uint8)byte) & 0x8;
            int top_bits = ((uint8)byte) & 0xf0;
            if ((sign_bit_set && top_bits != 0x70)
                || (!sign_bit_set && top_bits != 0))
                goto fail_integer_too_large;
        }
    }
    else if (sign && maxbits == 64) {
        if (shift < maxbits) {
            /* Sign extend, second highest bit is the sign bit */
            if ((uint8)byte & 0x40)
                result |= (~((uint64)0)) << shift;
        }
        else {
            /* The top bits should be a sign-extension of the sign bit */
            bool sign_bit_set = ((uint8)byte) & 0x1;
            int top_bits = ((uint8)byte) & 0xfe;

            if ((sign_bit_set && top_bits != 0x7e)
                || (!sign_bit_set && top_bits != 0))
                goto fail_integer_too_large;
        }
    }

    *p_buf += offset;
    *p_result = result;
    return true;

fail_integer_too_large:
    aot_set_last_error("integer too large");
    return false;
}

/* NOLINTNEXTLINE */
#define read_leb_uint32(p, p_end, res)                         \
    do {                                                       \
        uint64 res64;                                          \
        if (!read_leb((uint8 **)&p, p_end, 32, false, &res64)) \
            goto fail;                                         \
        res = (uint32)res64;                                   \
    } while (0)

/*
 * - transfer .name section in .wasm (comp_data->name_section_buf) to
 *   aot buf (comp_data->aot_name_section_buf)
 * - leb128 to u32
 * - add `\0` at the end of every name, and adjust length(+1)
 */
static uint32
get_name_section_size(AOTCompData *comp_data)
{
    /* original name section content in .wasm */
    const uint8 *p = comp_data->name_section_buf,
                *p_end = comp_data->name_section_buf_end;
    uint8 *buf, *buf_end;
    uint32 name_type, subsection_size;
    uint32 previous_name_type = 0;
    uint32 num_func_name;
    uint32 func_index;
    uint32 previous_func_index = ~0U;
    uint32 func_name_len;
    uint32 name_index;
    int i = 0;
    uint32 name_len;
    uint32 offset = 0;
    uint32 max_aot_buf_size = 0;

    if (p >= p_end) {
        aot_set_last_error("unexpected end");
        return 0;
    }

    max_aot_buf_size = 4 * (uint32)(p_end - p);
    if (!(buf = comp_data->aot_name_section_buf =
              wasm_runtime_malloc(max_aot_buf_size))) {
        aot_set_last_error("allocate memory for custom name section failed.");
        return 0;
    }
    memset(buf, 0, (uint32)max_aot_buf_size);
    buf_end = buf + max_aot_buf_size;

    /* the size of "name". it should be 4 */
    read_leb_uint32(p, p_end, name_len);
    offset = align_uint(offset, 4);
    EMIT_U32(name_len);

    if (name_len != 4 || p + name_len > p_end) {
        aot_set_last_error("unexpected end");
        return 0;
    }

    /* "name" */
    if (memcmp(p, "name", 4) != 0) {
        aot_set_last_error("invalid custom name section");
        return 0;
    }
    EMIT_BUF(p, name_len);
    p += name_len;

    while (p < p_end) {
        read_leb_uint32(p, p_end, name_type);
        if (i != 0) {
            if (name_type == previous_name_type) {
                aot_set_last_error("duplicate sub-section");
                return 0;
            }
            if (name_type < previous_name_type) {
                aot_set_last_error("out-of-order sub-section");
                return 0;
            }
        }
        previous_name_type = name_type;
        read_leb_uint32(p, p_end, subsection_size);
        switch (name_type) {
            case SUB_SECTION_TYPE_FUNC:
                if (subsection_size) {
                    offset = align_uint(offset, 4);
                    EMIT_U32(name_type);
                    EMIT_U32(subsection_size);

                    read_leb_uint32(p, p_end, num_func_name);
                    EMIT_U32(num_func_name);

                    for (name_index = 0; name_index < num_func_name;
                         name_index++) {
                        read_leb_uint32(p, p_end, func_index);
                        offset = align_uint(offset, 4);
                        EMIT_U32(func_index);
                        if (func_index == previous_func_index) {
                            aot_set_last_error("duplicate function name");
                            return 0;
                        }
                        if (func_index < previous_func_index
                            && previous_func_index != ~0U) {
                            aot_set_last_error("out-of-order function index ");
                            return 0;
                        }
                        previous_func_index = func_index;
                        read_leb_uint32(p, p_end, func_name_len);
                        offset = align_uint(offset, 2);

                        /* emit a string ends with `\0` */
                        if (func_name_len + 1 > UINT16_MAX) {
                            aot_set_last_error(
                                "emit string failed: string too long");
                            goto fail;
                        }
                        /* extra 1 byte for \0 */
                        EMIT_U16(func_name_len + 1);
                        EMIT_BUF(p, func_name_len);
                        p += func_name_len;
                        EMIT_U8(0);
                    }
                }
                break;
            case SUB_SECTION_TYPE_MODULE: /* TODO: Parse for module subsection
                                           */
            case SUB_SECTION_TYPE_LOCAL:  /* TODO: Parse for local subsection */
            default:
                p = p + subsection_size;
                break;
        }
        i++;
    }

    return offset;
fail:
    return 0;
}
#endif /* end of WASM_ENABLE_LOAD_CUSTOM_SECTION != 0 */

#if WASM_ENABLE_STRINGREF != 0
static uint32
get_string_literal_section_size(AOTCompContext *comp_ctx,
                                AOTCompData *comp_data)
{
    uint32 i;
    uint32 size = 0;
    uint32 string_count = comp_data->string_literal_count;

    if (string_count == 0) {
        return 0;
    }

    /* reserved slot + string count + string_lengths */
    size += sizeof(uint32) * (2 + string_count);

    for (i = 0; i < string_count; i++) {
        size += comp_data->string_literal_lengths_wp[i];
    }

    return size;
}
#endif /* end of WASM_ENABLE_STRINGREF != 0 */

static uint32
get_custom_sections_size(AOTCompContext *comp_ctx, AOTCompData *comp_data)
{
#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
    uint32 size = 0, i;

    for (i = 0; i < comp_ctx->custom_sections_count; i++) {
        const char *section_name = comp_ctx->custom_sections_wp[i];
        const uint8 *content = NULL;
        uint32 length = 0;

        if (strcmp(section_name, "name") == 0) {
            /* custom name section */
            comp_data->aot_name_section_size = get_name_section_size(comp_data);
            if (comp_data->aot_name_section_size == 0) {
                LOG_WARNING("Can't find custom section [name], ignore it");
                continue;
            }

            size = align_uint(size, 4);
            /* section id + section size + sub section id */
            size += (uint32)sizeof(uint32) * 3;
            size += comp_data->aot_name_section_size;
            continue;
        }

        content = wasm_loader_get_custom_section(comp_data->wasm_module,
                                                 section_name, &length);
        if (!content) {
            LOG_WARNING("Can't find custom section [%s], ignore it",
                        section_name);
            continue;
        }

        size = align_uint(size, 4);
        /* section id + section size + sub section id */
        size += (uint32)sizeof(uint32) * 3;
        /* section name and len */
        size += get_string_size(comp_ctx, section_name);
        /* section content */
        size += length;
    }

    return size;
#else
    return 0;
#endif
}

static bool
aot_emit_file_header(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                     AOTCompData *comp_data, AOTObjectData *obj_data)
{
    uint32 offset = *p_offset;
    uint32 aot_curr_version = AOT_CURRENT_VERSION;

    EMIT_U8('\0');
    EMIT_U8('a');
    EMIT_U8('o');
    EMIT_U8('t');

    EMIT_U32(aot_curr_version);

    *p_offset = offset;
    return true;
}

static bool
aot_emit_target_info_section(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                             AOTCompData *comp_data, AOTObjectData *obj_data)
{
    uint32 offset = *p_offset;
    uint32 section_size = get_target_info_section_size();
    AOTTargetInfo *target_info = &obj_data->target_info;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(AOT_SECTION_TYPE_TARGET_INFO);
    EMIT_U32(section_size);

    EMIT_U16(target_info->bin_type);
    EMIT_U16(target_info->abi_type);
    EMIT_U16(target_info->e_type);
    EMIT_U16(target_info->e_machine);
    EMIT_U32(target_info->e_version);
    EMIT_U32(target_info->e_flags);
    EMIT_U64(target_info->feature_flags);
    EMIT_U64(target_info->reserved);
    EMIT_BUF(target_info->arch, sizeof(target_info->arch));

    if (offset - *p_offset != section_size + sizeof(uint32) * 2) {
        aot_set_last_error("emit target info failed.");
        return false;
    }

    *p_offset = offset;

    return true;
}

static bool
aot_emit_init_expr(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                   AOTCompContext *comp_ctx, InitializerExpression *expr);

static bool
aot_emit_mem_info(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                  AOTCompContext *comp_ctx, AOTCompData *comp_data,
                  AOTObjectData *obj_data)
{
    uint32 offset = *p_offset, i;
    AOTMemInitData **init_datas = comp_data->mem_init_data_list;

    *p_offset = offset = align_uint(offset, 4);

    /* Emit import memory count, only emit 0 currently.
       TODO: emit the actual import memory count and
             the full import memory info. */
    EMIT_U32(0);

    /* Emit memory count */
    EMIT_U32(comp_data->memory_count);
    /* Emit memory items */
    for (i = 0; i < comp_data->memory_count; i++) {
        EMIT_U32(comp_data->memories[i].flags);
        EMIT_U32(comp_data->memories[i].num_bytes_per_page);
        EMIT_U32(comp_data->memories[i].init_page_count);
        EMIT_U32(comp_data->memories[i].max_page_count);
    }

    /* Emit mem init data count */
    EMIT_U32(comp_data->mem_init_data_count);
    /* Emit mem init data items */
    for (i = 0; i < comp_data->mem_init_data_count; i++) {
        offset = align_uint(offset, 4);
#if WASM_ENABLE_BULK_MEMORY != 0
        if (comp_ctx->enable_bulk_memory) {
            EMIT_U32(init_datas[i]->is_passive);
            EMIT_U32(init_datas[i]->memory_index);
        }
        else
#endif
        {
            /* emit two placeholder to keep the same size */
            EMIT_U32(0);
            EMIT_U32(0);
        }
        if (!aot_emit_init_expr(buf, buf_end, &offset, comp_ctx,
                                &init_datas[i]->offset))
            return false;
        EMIT_U32(init_datas[i]->byte_count);
        if (init_datas[i]->byte_count) {
            EMIT_BUF(init_datas[i]->bytes, init_datas[i]->byte_count);
        }
    }

    if (offset - *p_offset != get_mem_info_size(comp_ctx, comp_data)) {
        aot_set_last_error("emit memory info failed.");
        return false;
    }

    *p_offset = offset;

    return true;
}

static bool
aot_emit_init_expr(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                   AOTCompContext *comp_ctx, InitializerExpression *expr)
{
    if (expr == NULL) {
        aot_set_last_error("invalid init expr.");
        return false;
    }
    uint32 offset = *p_offset;
#if WASM_ENABLE_GC != 0
    WASMModule *module = comp_ctx->comp_data->wasm_module;
#endif

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(expr->init_expr_type);
    switch (expr->init_expr_type) {
        case INIT_EXPR_NONE:
            break;
        case INIT_EXPR_TYPE_I32_CONST:
        case INIT_EXPR_TYPE_F32_CONST:
            EMIT_U32(expr->u.unary.v.i32);
            break;
        case INIT_EXPR_TYPE_I64_CONST:
        case INIT_EXPR_TYPE_F64_CONST:
            EMIT_U64(expr->u.unary.v.i64);
            break;
        case INIT_EXPR_TYPE_V128_CONST:
            EMIT_V128(expr->u.unary.v.v128);
            break;
        case INIT_EXPR_TYPE_GET_GLOBAL:
            EMIT_U32(expr->u.unary.v.global_index);
            break;
        case INIT_EXPR_TYPE_FUNCREF_CONST:
        case INIT_EXPR_TYPE_REFNULL_CONST:
            EMIT_U32(expr->u.unary.v.ref_index);
            break;
#if WASM_ENABLE_GC != 0
        case INIT_EXPR_TYPE_I31_NEW:
            EMIT_U32(expr->u.unary.v.i32);
            break;
        case INIT_EXPR_TYPE_STRUCT_NEW:
        {
            uint32 i;
            WASMStructNewInitValues *init_values =
                (WASMStructNewInitValues *)expr->u.unary.v.data;
            WASMStructType *struct_type = NULL;

            EMIT_U32(init_values->type_idx);
            EMIT_U32(init_values->count);

            bh_assert(init_values->type_idx < module->type_count);

            struct_type =
                (WASMStructType *)module->types[init_values->type_idx];

            bh_assert(struct_type);
            bh_assert(struct_type->field_count == init_values->count);

            for (i = 0; i < init_values->count; i++) {
                uint32 field_size = wasm_value_type_size_internal(
                    struct_type->fields[i].field_type, comp_ctx->pointer_size);
                if (field_size <= sizeof(uint32))
                    EMIT_U32(init_values->fields[i].u32);
                else if (field_size == sizeof(uint64))
                    EMIT_U64(init_values->fields[i].u64);
                else if (field_size == sizeof(uint64) * 2)
                    EMIT_V128(init_values->fields[i].v128);
                else {
                    bh_assert(0);
                }
            }

            break;
        }
        case INIT_EXPR_TYPE_STRUCT_NEW_DEFAULT:
            EMIT_U32(expr->u.unary.v.type_index);
            break;
        case INIT_EXPR_TYPE_ARRAY_NEW_DEFAULT:
        {
            WASMArrayType *array_type = NULL;

            bh_assert(expr->u.unary.v.array_new_default.type_index
                      < module->type_count);
            array_type =
                (WASMArrayType *)
                    module->types[expr->u.unary.v.array_new_default.type_index];

            EMIT_U32(array_type->elem_type);
            EMIT_U32(expr->u.unary.v.array_new_default.type_index);
            EMIT_U32(expr->u.unary.v.array_new_default.length);
            break;
        }
        case INIT_EXPR_TYPE_ARRAY_NEW:
        case INIT_EXPR_TYPE_ARRAY_NEW_FIXED:
        {
            uint32 value_count, i, field_size;
            WASMArrayNewInitValues *init_values =
                (WASMArrayNewInitValues *)expr->u.unary.v.data;
            WASMArrayType *array_type = NULL;

            bh_assert(init_values->type_idx < module->type_count);
            array_type = (WASMArrayType *)module->types[init_values->type_idx];

            EMIT_U32(array_type->elem_type);
            EMIT_U32(init_values->type_idx);
            EMIT_U32(init_values->length);

            value_count =
                (expr->init_expr_type == INIT_EXPR_TYPE_ARRAY_NEW_FIXED)
                    ? init_values->length
                    : 1;

            field_size = wasm_value_type_size_internal(array_type->elem_type,
                                                       comp_ctx->pointer_size);

            for (i = 0; i < value_count; i++) {
                if (field_size <= sizeof(uint32))
                    EMIT_U32(init_values->elem_data[i].u32);
                else if (field_size == sizeof(uint64))
                    EMIT_U64(init_values->elem_data[i].u64);
                else if (field_size == sizeof(uint64) * 2)
                    EMIT_V128(init_values->elem_data[i].v128);
                else {
                    bh_assert(0);
                }
            }
            break;
        }
#endif /* end of WASM_ENABLE_GC != 0 */
#if WASM_ENABLE_EXTENDED_CONST_EXPR != 0
        case INIT_EXPR_TYPE_I32_ADD:
        case INIT_EXPR_TYPE_I32_SUB:
        case INIT_EXPR_TYPE_I32_MUL:
        case INIT_EXPR_TYPE_I64_ADD:
        case INIT_EXPR_TYPE_I64_SUB:
        case INIT_EXPR_TYPE_I64_MUL:
            if (comp_ctx->enable_extended_const) {
                if (!aot_emit_init_expr(buf, buf_end, &offset, comp_ctx,
                                        expr->u.binary.l_expr)) {
                    return false;
                }
                if (!aot_emit_init_expr(buf, buf_end, &offset, comp_ctx,
                                        expr->u.binary.r_expr)) {
                    return false;
                }
            }
            break;
#endif
        default:
            aot_set_last_error("invalid init expr type.");
            return false;
    }

    *p_offset = offset;
    return true;
}

static bool
aot_emit_table_info(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                    AOTCompContext *comp_ctx, AOTCompData *comp_data,
                    AOTObjectData *obj_data)
{
    uint32 offset = *p_offset, i, j;
    AOTTableInitData **init_datas = comp_data->table_init_data_list;

    *p_offset = offset = align_uint(offset, 4);

    /* Emit import table count */
    EMIT_U32(comp_data->import_table_count);
    /* Emit table items */
    for (i = 0; i < comp_data->import_table_count; i++) {
        /* TODO:
         * EMIT_STR(comp_data->import_tables[i].module_name );
         * EMIT_STR(comp_data->import_tables[i].table_name);
         */
        EMIT_U8(comp_data->import_tables[i].table_type.elem_type);
        EMIT_U8(comp_data->import_tables[i].table_type.flags);
        EMIT_U8(comp_data->import_tables[i].table_type.possible_grow);
#if WASM_ENABLE_GC != 0
        if (comp_ctx->enable_gc
            && comp_data->import_tables[i].table_type.elem_ref_type) {
            EMIT_U8(comp_data->import_tables[i]
                        .table_type.elem_ref_type->ref_ht_common.nullable);
        }
        else
#endif
        {
            /* emit one placeholder to keep the same size */
            EMIT_U8(0);
        }
        EMIT_U32(comp_data->import_tables[i].table_type.init_size);
        EMIT_U32(comp_data->import_tables[i].table_type.max_size);
#if WASM_ENABLE_GC != 0
        if (comp_ctx->enable_gc
            && comp_data->import_tables[i].table_type.elem_ref_type) {
            bh_assert(wasm_is_type_multi_byte_type(
                comp_data->import_tables[i].table_type.elem_type));
            EMIT_U32(comp_data->import_tables[i]
                         .table_type.elem_ref_type->ref_ht_common.heap_type);
        }
#endif
    }

    /* Emit table count */
    EMIT_U32(comp_data->table_count);
    /* Emit table items */
    for (i = 0; i < comp_data->table_count; i++) {
        EMIT_U8(comp_data->tables[i].table_type.elem_type);
        EMIT_U8(comp_data->tables[i].table_type.flags);
        EMIT_U8(comp_data->tables[i].table_type.possible_grow);
#if WASM_ENABLE_GC != 0
        if (comp_ctx->enable_gc
            && comp_data->tables[i].table_type.elem_ref_type) {
            EMIT_U8(comp_data->tables[i]
                        .table_type.elem_ref_type->ref_ht_common.nullable);
        }
        else
#endif
        {
            /* emit one placeholder to keep the same size */
            EMIT_U8(0);
        }
        EMIT_U32(comp_data->tables[i].table_type.init_size);
        EMIT_U32(comp_data->tables[i].table_type.max_size);
#if WASM_ENABLE_GC != 0
        if (comp_ctx->enable_gc) {
            if (comp_data->tables[i].table_type.elem_ref_type) {
                bh_assert(wasm_is_type_multi_byte_type(
                    comp_data->tables[i].table_type.elem_type));
                EMIT_U32(
                    comp_data->tables[i]
                        .table_type.elem_ref_type->ref_ht_common.heap_type);
            }
            if (!aot_emit_init_expr(buf, buf_end, &offset, comp_ctx,
                                    &comp_data->tables[i].init_expr)) {
                return false;
            }
        }
#endif
    }

    /* Emit table init data count */
    EMIT_U32(comp_data->table_init_data_count);
    /* Emit table init data items */
    for (i = 0; i < comp_data->table_init_data_count; i++) {
        offset = align_uint(offset, 4);
        EMIT_U32(init_datas[i]->mode);
        EMIT_U32(init_datas[i]->elem_type);
        EMIT_U32(init_datas[i]->table_index);
        if (!aot_emit_init_expr(buf, buf_end, &offset, comp_ctx,
                                &init_datas[i]->offset))
            return false;

#if WASM_ENABLE_GC != 0
        if (comp_ctx->enable_gc && init_datas[i]->elem_ref_type) {
            EMIT_U16(init_datas[i]->elem_ref_type->ref_ht_common.ref_type);
            EMIT_U16(init_datas[i]->elem_ref_type->ref_ht_common.nullable);
            EMIT_U32(init_datas[i]->elem_ref_type->ref_ht_common.heap_type);
        }
        else
#endif
        {
            EMIT_U16(init_datas[i]->elem_type);
            EMIT_U16(0);
            EMIT_U32(0);
        }
        EMIT_U32(init_datas[i]->value_count);
        for (j = 0; j < init_datas[i]->value_count; j++) {
            if (!aot_emit_init_expr(buf, buf_end, &offset, comp_ctx,
                                    &init_datas[i]->init_values[j]))
                return false;
        }
    }

    if (offset - *p_offset != get_table_info_size(comp_ctx, comp_data)) {
        aot_set_last_error("emit table info failed.");
        return false;
    }

    *p_offset = offset;

    return true;
}

#if WASM_ENABLE_GC != 0
static bool
aot_emit_reftype_map(uint8 *buf, uint8 *buf_end, uint32 *p_offset, uint32 count,
                     WASMRefTypeMap *refmap)
{
    uint32 offset = *p_offset, i;

    for (i = 0; i < count; i++) {
        EMIT_U16(refmap->index);
        WASMRefType *ref_type = refmap->ref_type;

        /* Note: WASMRefType is a union type */
        EMIT_U8(ref_type->ref_ht_common.ref_type);
        EMIT_U8(ref_type->ref_ht_common.nullable);
        EMIT_U32(ref_type->ref_ht_common.heap_type);

        refmap++;
    }

    *p_offset = offset;
    return true;
}
#endif

static bool
aot_emit_type_info(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                   AOTCompContext *comp_ctx, AOTCompData *comp_data,
                   AOTObjectData *obj_data)
{
    uint32 offset = *p_offset, i;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(comp_data->type_count);

#if WASM_ENABLE_GC != 0
    if (comp_ctx->enable_gc) {
        AOTType **types = comp_data->types;
        int32 idx;
        uint32 j;

        for (i = 0; i < comp_data->type_count; i++) {
            offset = align_uint(offset, 4);

            /* Emit simple info if there is an equivalence type */
            for (j = 0; j < i; j++) {
                if (types[j] == types[i]) {
                    EMIT_U16(types[i]->type_flag);
                    /* equivalence type flag is true */
                    EMIT_U8(1);
                    EMIT_U8(0);
                    /* equivalence type index */
                    EMIT_U32(j);
                    break;
                }
            }
            if (j < i)
                continue;

            EMIT_U16(types[i]->type_flag);
            /* equivalence type flag is false */
            EMIT_U8(0);
            EMIT_U8(types[i]->is_sub_final);
            EMIT_U32(types[i]->parent_type_idx);

            EMIT_U16(types[i]->rec_count);
            EMIT_U16(types[i]->rec_idx);

            /* Emit WASM_TYPE_FUNC */
            if (types[i]->type_flag == WASM_TYPE_FUNC) {
                AOTFuncType *func_type = (AOTFuncType *)types[i];
                EMIT_U16(func_type->param_count);
                EMIT_U16(func_type->result_count);
                EMIT_U16(func_type->ref_type_map_count);
                EMIT_BUF(func_type->types,
                         func_type->param_count + func_type->result_count);

                offset = align_uint(offset, 4);

                aot_emit_reftype_map(buf, buf_end, &offset,
                                     func_type->ref_type_map_count,
                                     func_type->ref_type_maps);
            }
            /* Emit WASM_TYPE_STRUCT */
            else if (types[i]->type_flag == WASM_TYPE_STRUCT) {
                AOTStructType *struct_type = (AOTStructType *)types[i];
                EMIT_U16(struct_type->field_count);
                EMIT_U16(struct_type->ref_type_map_count);

                for (idx = 0; idx < struct_type->field_count; idx++) {
                    EMIT_U8(struct_type->fields[idx].field_flags);
                    EMIT_U8(struct_type->fields[idx].field_type);
                }

                offset = align_uint(offset, 4);

                aot_emit_reftype_map(buf, buf_end, &offset,
                                     struct_type->ref_type_map_count,
                                     struct_type->ref_type_maps);
            }
            /* Emit WASM_TYPE_ARRAY */
            else if (types[i]->type_flag == WASM_TYPE_ARRAY) {
                AOTArrayType *array_type = (AOTArrayType *)types[i];
                EMIT_U16(array_type->elem_flags);
                EMIT_U8(array_type->elem_type);
                if (array_type->elem_ref_type) {
                    bh_assert(
                        wasm_is_type_multi_byte_type(array_type->elem_type));
                    EMIT_U8(array_type->elem_ref_type->ref_ht_common.nullable);
                    EMIT_U32(
                        array_type->elem_ref_type->ref_ht_common.heap_type);
                }
            }
            else {
                aot_set_last_error("invalid type flag.");
                return false;
            }
        }

        if (offset - *p_offset != get_type_info_size(comp_ctx, comp_data)) {
            aot_set_last_error("emit function type info failed.");
            return false;
        }

        *p_offset = offset;
    }
    else
#endif
    {
        AOTFuncType **func_types = (AOTFuncType **)comp_data->types;

        for (i = 0; i < comp_data->type_count; i++) {
            offset = align_uint(offset, 4);
            /* If GC is disabled, only emit function type info */
            EMIT_U16(WASM_TYPE_FUNC);
            /* Omit to emit dummy padding for is_sub_final,
             * parent_type_index, rec_count, rec_idx, 10 bytes in total */
            EMIT_U16(func_types[i]->param_count);
            EMIT_U16(func_types[i]->result_count);
            /* Omit to emit dummy padding for ref_type_map_count, 2 bytes in
             * total */
            EMIT_BUF(func_types[i]->types,
                     func_types[i]->param_count + func_types[i]->result_count);
        }

        if (offset - *p_offset != get_type_info_size(comp_ctx, comp_data)) {
            aot_set_last_error("emit function type info failed.");
            return false;
        }

        *p_offset = offset;
    }

    return true;
}

static bool
aot_emit_import_global_info(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                            AOTCompContext *comp_ctx, AOTCompData *comp_data,
                            AOTObjectData *obj_data)
{
    uint32 offset = *p_offset, i;
    AOTImportGlobal *import_global = comp_data->import_globals;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(comp_data->import_global_count);

    for (i = 0; i < comp_data->import_global_count; i++, import_global++) {
        offset = align_uint(offset, 2);
        EMIT_U8(import_global->type.val_type);
        EMIT_U8(import_global->type.is_mutable);
        EMIT_STR(import_global->module_name);
        offset = align_uint(offset, 2);
        EMIT_STR(import_global->global_name);
    }

    if (offset - *p_offset
        != get_import_global_info_size(comp_ctx, comp_data)) {
        aot_set_last_error("emit import global info failed.");
        return false;
    }

    *p_offset = offset;

    return true;
}

static bool
aot_emit_global_info(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                     AOTCompContext *comp_ctx, AOTCompData *comp_data,
                     AOTObjectData *obj_data)
{
    uint32 offset = *p_offset, i;
    AOTGlobal *global = comp_data->globals;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(comp_data->global_count);

    for (i = 0; i < comp_data->global_count; i++, global++) {
        offset = align_uint(offset, 4);
        EMIT_U8(global->type.val_type);
        EMIT_U8(global->type.is_mutable);

        offset = align_uint(offset, 4);
        if (!aot_emit_init_expr(buf, buf_end, &offset, comp_ctx,
                                &global->init_expr))
            return false;
    }

    if (offset - *p_offset != get_global_info_size(comp_ctx, comp_data)) {
        aot_set_last_error("emit global info failed.");
        return false;
    }

    *p_offset = offset;

    return true;
}

static bool
aot_emit_import_func_info(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                          AOTCompContext *comp_ctx, AOTCompData *comp_data,
                          AOTObjectData *obj_data)
{
    uint32 offset = *p_offset, i;
    AOTImportFunc *import_func = comp_data->import_funcs;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(comp_data->import_func_count);

    for (i = 0; i < comp_data->import_func_count; i++, import_func++) {
        offset = align_uint(offset, 2);
        EMIT_U16(import_func->func_type_index);
        EMIT_STR(import_func->module_name);
        offset = align_uint(offset, 2);
        EMIT_STR(import_func->func_name);
    }

    if (offset - *p_offset != get_import_func_info_size(comp_ctx, comp_data)) {
        aot_set_last_error("emit import function info failed.");
        return false;
    }

    *p_offset = offset;

    return true;
}

static bool
aot_emit_object_data_section_info(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                                  AOTCompContext *comp_ctx,
                                  AOTObjectData *obj_data)
{
    uint32 offset = *p_offset, i;
    AOTObjectDataSection *data_section = obj_data->data_sections;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(obj_data->data_sections_count);

    for (i = 0; i < obj_data->data_sections_count; i++, data_section++) {
        offset = align_uint(offset, 2);
        EMIT_STR(data_section->name);
        offset = align_uint(offset, 4);
        EMIT_U32(data_section->size);
        if (obj_data->stack_sizes_section_name != NULL
            && !strcmp(obj_data->stack_sizes_section_name,
                       data_section->name)) {
            uint32 ss_offset = obj_data->stack_sizes_offset;
            uint32 ss_size =
                obj_data->func_count * sizeof(*obj_data->stack_sizes);
            LOG_VERBOSE("Replacing stack_sizes in %s section, offset %" PRIu32
                        ", size %" PRIu32,
                        obj_data->stack_sizes_section_name, ss_offset, ss_size);
            bh_assert(ss_offset + ss_size <= data_section->size);
            /* 0 .. ss_offset */
            if (ss_offset > 0) {
                EMIT_BUF(data_section->data, ss_offset);
            }
            /* ss_offset .. ss_offset+ss_size */
            EMIT_BUF(obj_data->stack_sizes, ss_size);
            /* ss_offset+ss_size .. data_section->size */
            if (data_section->size > ss_offset + ss_size) {
                EMIT_BUF(data_section->data + ss_offset + ss_size,
                         data_section->size - (ss_offset + ss_size));
            }
        }
        else {
            EMIT_BUF(data_section->data, data_section->size);
        }
    }

    if (offset - *p_offset
        != get_object_data_section_info_size(comp_ctx, obj_data)) {
        aot_set_last_error("emit object data section info failed.");
        return false;
    }

    *p_offset = offset;

    return true;
}

static bool
aot_emit_init_data_section(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                           AOTCompContext *comp_ctx, AOTCompData *comp_data,
                           AOTObjectData *obj_data)
{
    uint32 section_size =
        get_init_data_section_size(comp_ctx, comp_data, obj_data);
    uint32 offset = *p_offset;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(AOT_SECTION_TYPE_INIT_DATA);
    EMIT_U32(section_size);

    if (!aot_emit_mem_info(buf, buf_end, &offset, comp_ctx, comp_data, obj_data)
        || !aot_emit_table_info(buf, buf_end, &offset, comp_ctx, comp_data,
                                obj_data)
        || !aot_emit_type_info(buf, buf_end, &offset, comp_ctx, comp_data,
                               obj_data)
        || !aot_emit_import_global_info(buf, buf_end, &offset, comp_ctx,
                                        comp_data, obj_data)
        || !aot_emit_global_info(buf, buf_end, &offset, comp_ctx, comp_data,
                                 obj_data)
        || !aot_emit_import_func_info(buf, buf_end, &offset, comp_ctx,
                                      comp_data, obj_data))
        return false;

    offset = align_uint(offset, 4);
    EMIT_U32(comp_data->func_count);
    EMIT_U32(comp_data->start_func_index);

    EMIT_U32(comp_data->aux_data_end_global_index);
    EMIT_U64(comp_data->aux_data_end);
    EMIT_U32(comp_data->aux_heap_base_global_index);
    EMIT_U64(comp_data->aux_heap_base);
    EMIT_U32(comp_data->aux_stack_top_global_index);
    EMIT_U64(comp_data->aux_stack_bottom);
    EMIT_U32(comp_data->aux_stack_size);

    if (!aot_emit_object_data_section_info(buf, buf_end, &offset, comp_ctx,
                                           obj_data))
        return false;

    if (offset - *p_offset != section_size + sizeof(uint32) * 2) {
        aot_set_last_error("emit init data section failed.");
        return false;
    }

    *p_offset = offset;

    return true;
}

static bool
aot_emit_text_section(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                      AOTCompData *comp_data, AOTObjectData *obj_data)
{
    uint32 section_size = get_text_section_size(obj_data);
    uint32 offset = *p_offset;
    uint8 placeholder = 0;
    AOTRelocationGroup *relocation_group;
    AOTRelocation *relocation;
    uint32 i, j, relocation_count;
    uint8 *text;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(AOT_SECTION_TYPE_TEXT);
    EMIT_U32(section_size);
    EMIT_U32(obj_data->literal_size);

    if (obj_data->literal_size > 0) {
        EMIT_BUF(obj_data->literal, obj_data->literal_size);
        while (offset & 3)
            EMIT_BUF(&placeholder, 1);
    }

    text = buf + offset;

    if (obj_data->text_size > 0) {
        EMIT_BUF(obj_data->text, obj_data->text_size);
        while (offset & 3)
            EMIT_BUF(&placeholder, 1);
    }
    if (obj_data->text_unlikely_size > 0) {
        EMIT_BUF(obj_data->text_unlikely, obj_data->text_unlikely_size);
        while (offset & 3)
            EMIT_BUF(&placeholder, 1);
    }
    if (obj_data->text_hot_size > 0) {
        EMIT_BUF(obj_data->text_hot, obj_data->text_hot_size);
        while (offset & 3)
            EMIT_BUF(&placeholder, 1);
    }

    if (offset - *p_offset != section_size + sizeof(uint32) * 2) {
        aot_set_last_error("emit text section failed.");
        return false;
    }

    /* apply relocations to aot_func_internal#n in text section for
       windows platform */
    if ((!strncmp(obj_data->comp_ctx->target_arch, "x86_64", 6)
         /* Windows AOT_COFF64_BIN_TYPE */
         && obj_data->target_info.bin_type == 6)
        || (!strncmp(obj_data->comp_ctx->target_arch, "i386", 4)
            /* Windows AOT_COFF32_BIN_TYPE */
            && obj_data->target_info.bin_type == 4)) {
        relocation_group = obj_data->relocation_groups;
        for (i = 0; i < obj_data->relocation_group_count;
             i++, relocation_group++) {
            /* relocation in text section */
            if ((!strcmp(relocation_group->section_name, ".text")
                 || !strcmp(relocation_group->section_name, ".ltext"))) {
                relocation = relocation_group->relocations;
                relocation_count = relocation_group->relocation_count;
                for (j = 0; j < relocation_count; j++) {
                    /* relocation to aot_func_internal#n */
                    const char *name = relocation->symbol_name;
                    if (str_starts_with(name, AOT_FUNC_INTERNAL_PREFIX)
                        && ((obj_data->target_info.bin_type
                                 == 6 /* AOT_COFF64_BIN_TYPE */
                             && relocation->relocation_type
                                    == 4 /* IMAGE_REL_AMD64_REL32 */)
                            || (obj_data->target_info.bin_type
                                    == 4 /* AOT_COFF32_BIN_TYPE */
                                && relocation->relocation_type
                                       == 20 /* IMAGE_REL_I386_REL32 */))) {
                        uint32 func_idx =
                            atoi(name + strlen(AOT_FUNC_INTERNAL_PREFIX));
                        uint64 text_offset, reloc_offset, reloc_addend;

                        bh_assert(func_idx < obj_data->func_count);

                        text_offset = obj_data->funcs[func_idx]
                                          .text_offset_of_aot_func_internal;
                        reloc_offset = relocation->relocation_offset;
                        reloc_addend = relocation->relocation_addend;
                        /* S + A - P */
                        *(uint32 *)(text + reloc_offset) =
                            (uint32)(text_offset + reloc_addend - reloc_offset
                                     - 4);

                        /* remove current relocation as it has been applied */
                        if (j < relocation_count - 1) {
                            uint32 move_size =
                                (uint32)(sizeof(AOTRelocation)
                                         * (relocation_count - 1 - j));
                            bh_memmove_s(relocation, move_size, relocation + 1,
                                         move_size);
                        }
                        relocation_group->relocation_count--;
                    }
                    else {
                        relocation++;
                    }
                }
            }
        }
    }

    *p_offset = offset;

    return true;
}

#if WASM_ENABLE_GC != 0
static bool
aot_emit_ref_flag(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                  uint8 pointer_size, int8 type)
{
    uint32 j, offset = *p_offset;
    uint16 value_type_cell_num;

    if (wasm_is_type_reftype(type) && !wasm_is_reftype_i31ref(type)) {
        EMIT_U8(1);
        if (pointer_size == sizeof(uint64))
            EMIT_U8(1);
    }
    else {
        value_type_cell_num = wasm_value_type_cell_num(type);
        for (j = 0; j < value_type_cell_num; j++)
            EMIT_U8(0);
    }

    *p_offset = offset;
    return true;
}
#endif

static bool
aot_emit_func_section(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                      AOTCompContext *comp_ctx, AOTCompData *comp_data,
                      AOTObjectData *obj_data)
{
    uint32 section_size = get_func_section_size(comp_ctx, comp_data, obj_data);
    uint32 i, offset = *p_offset;
    AOTObjectFunc *func = obj_data->funcs;
    AOTFunc **funcs = comp_data->funcs;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(AOT_SECTION_TYPE_FUNCTION);
    EMIT_U32(section_size);

    for (i = 0; i < obj_data->func_count; i++, func++) {
        if (is_32bit_binary(obj_data))
            EMIT_U32(func->text_offset);
        else
            EMIT_U64(func->text_offset);
    }

    for (i = 0; i < comp_data->func_count; i++)
        EMIT_U32(funcs[i]->func_type_index);

    for (i = 0; i < comp_data->func_count; i++) {
        uint32 max_local_cell_num =
            funcs[i]->param_cell_num + funcs[i]->local_cell_num;
        EMIT_U32(max_local_cell_num);
    }

    for (i = 0; i < comp_data->func_count; i++)
        EMIT_U32(funcs[i]->max_stack_cell_num);

#if WASM_ENABLE_GC != 0
    if (comp_ctx->enable_gc) {
        /* emit func_local_ref_flag arrays for both import and AOTed funcs */
        AOTFuncType *func_type;
        uint32 j, local_ref_flags_cell_num, paddings;

        for (i = 0; i < comp_data->import_func_count; i++) {
            func_type = comp_data->import_funcs[i].func_type;
            /* recalculate cell_num based on target pointer size */
            local_ref_flags_cell_num = 0;
            for (j = 0; j < func_type->param_count; j++) {
                local_ref_flags_cell_num += wasm_value_type_cell_num_internal(
                    func_type->types[j], comp_ctx->pointer_size);
            }
            paddings =
                local_ref_flags_cell_num < 2 ? 2 - local_ref_flags_cell_num : 0;
            local_ref_flags_cell_num =
                local_ref_flags_cell_num > 2 ? local_ref_flags_cell_num : 2;

            offset = align_uint(offset, 4);
            EMIT_U32(local_ref_flags_cell_num);
            for (j = 0; j < func_type->param_count; j++) {
                if (!aot_emit_ref_flag(buf, buf_end, &offset,
                                       comp_ctx->pointer_size,
                                       func_type->types[j]))
                    return false;
            }
            for (j = 0; j < paddings; j++)
                EMIT_U8(0);
        }

        for (i = 0; i < comp_data->func_count; i++) {
            func_type = funcs[i]->func_type;
            local_ref_flags_cell_num =
                funcs[i]->param_cell_num + funcs[i]->local_cell_num;

            offset = align_uint(offset, 4);
            EMIT_U32(local_ref_flags_cell_num);
            /* emit local_ref_flag for param variables */
            for (j = 0; j < func_type->param_count; j++) {
                if (!aot_emit_ref_flag(buf, buf_end, &offset,
                                       comp_ctx->pointer_size,
                                       func_type->types[j]))
                    return false;
            }
            /* emit local_ref_flag for local variables */
            for (j = 0; j < funcs[i]->local_count; j++) {
                if (!aot_emit_ref_flag(buf, buf_end, &offset,
                                       comp_ctx->pointer_size,
                                       funcs[i]->local_types_wp[j]))
                    return false;
            }
        }
    }
#endif /* end of WASM_ENABLE_GC != 0 */

    if (offset - *p_offset != section_size + sizeof(uint32) * 2) {
        aot_set_last_error("emit function section failed.");
        return false;
    }

    *p_offset = offset;

    return true;
}

static bool
aot_emit_export_section(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                        AOTCompContext *comp_ctx, AOTCompData *comp_data,
                        AOTObjectData *obj_data)
{
    uint32 section_size = get_export_section_size(comp_ctx, comp_data);
    AOTExport *export = comp_data->wasm_module->exports;
    uint32 export_count = comp_data->wasm_module->export_count;
    uint32 i, offset = *p_offset;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(AOT_SECTION_TYPE_EXPORT);
    EMIT_U32(section_size);
    EMIT_U32(export_count);

    for (i = 0; i < export_count; i++, export ++) {
        offset = align_uint(offset, 4);
        EMIT_U32(export->index);
        EMIT_U8(export->kind);
        EMIT_U8(0);
        EMIT_STR(export->name);
    }

    if (offset - *p_offset != section_size + sizeof(uint32) * 2) {
        aot_set_last_error("emit export section failed.");
        return false;
    }

    *p_offset = offset;

    return true;
}

static bool
aot_emit_relocation_symbol_table(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                                 AOTCompContext *comp_ctx,
                                 AOTCompData *comp_data,
                                 AOTObjectData *obj_data)
{
    uint32 symbol_offset = 0, total_string_len = 0;
    uint32 offset = *p_offset;
    AOTSymbolNode *sym;

    EMIT_U32(obj_data->symbol_list.len);

    /* emit symbol offsets */
    sym = (AOTSymbolNode *)(obj_data->symbol_list.head);
    while (sym) {
        EMIT_U32(symbol_offset);
        /* string_len + str[0 .. string_len - 1] */
        symbol_offset += get_string_size(comp_ctx, sym->symbol);
        symbol_offset = align_uint(symbol_offset, 2);
        sym = sym->next;
    }

    /* emit total string len */
    total_string_len = symbol_offset;
    EMIT_U32(total_string_len);

    /* emit symbols */
    sym = (AOTSymbolNode *)(obj_data->symbol_list.head);
    while (sym) {
        EMIT_STR(sym->symbol);
        offset = align_uint(offset, 2);
        sym = sym->next;
    }

    *p_offset = offset;
    return true;
}

static bool
aot_emit_relocation_section(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                            AOTCompContext *comp_ctx, AOTCompData *comp_data,
                            AOTObjectData *obj_data)
{
    uint32 section_size = get_relocation_section_size(comp_ctx, obj_data);
    uint32 i, offset = *p_offset;
    AOTRelocationGroup *relocation_group = obj_data->relocation_groups;

    if (section_size == (uint32)-1)
        return false;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(AOT_SECTION_TYPE_RELOCATION);
    EMIT_U32(section_size);

    aot_emit_relocation_symbol_table(buf, buf_end, &offset, comp_ctx, comp_data,
                                     obj_data);

    offset = align_uint(offset, 4);
    EMIT_U32(obj_data->relocation_group_count);

    /* emit each relocation group */
    for (i = 0; i < obj_data->relocation_group_count; i++, relocation_group++) {
        AOTRelocation *relocation = relocation_group->relocations;
        uint32 j;

        offset = align_uint(offset, 4);
        EMIT_U32(relocation_group->name_index);
        offset = align_uint(offset, 4);
        EMIT_U32(relocation_group->relocation_count);

        /* emit each relocation */
        for (j = 0; j < relocation_group->relocation_count; j++, relocation++) {
            offset = align_uint(offset, 4);
            if (is_32bit_binary(obj_data)) {
                EMIT_U32(relocation->relocation_offset);
                EMIT_U32(relocation->relocation_addend);
            }
            else {
                EMIT_U64(relocation->relocation_offset);
                EMIT_U64(relocation->relocation_addend);
            }
            EMIT_U32(relocation->relocation_type);
            EMIT_U32(relocation->symbol_index);
        }
    }

    if (offset - *p_offset != section_size + sizeof(uint32) * 2) {
        aot_set_last_error("emit relocation section failed.");
        return false;
    }

    *p_offset = offset;
    return true;
}

static bool
aot_emit_native_symbol(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                       AOTCompContext *comp_ctx)
{
    uint32 offset = *p_offset;
    AOTNativeSymbol *sym = NULL;

    if (bh_list_length(&comp_ctx->native_symbols) == 0)
        /* emit only when there are native symbols */
        return true;

    *p_offset = offset = align_uint(offset, 4);

    EMIT_U32(AOT_SECTION_TYPE_CUSTOM);
    /* sub section id + symbol count + symbol list */
    EMIT_U32(sizeof(uint32) * 2 + get_native_symbol_list_size(comp_ctx));
    EMIT_U32(AOT_CUSTOM_SECTION_NATIVE_SYMBOL);
    EMIT_U32(bh_list_length(&comp_ctx->native_symbols));

    sym = bh_list_first_elem(&comp_ctx->native_symbols);

    while (sym) {
        offset = align_uint(offset, 2);
        EMIT_STR(sym->symbol);
        sym = bh_list_elem_next(sym);
    }

    *p_offset = offset;

    return true;
}

#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
static bool
aot_emit_name_section(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                      AOTCompData *comp_data, AOTCompContext *comp_ctx)
{
    uint32 offset = *p_offset;

    if (comp_data->aot_name_section_size == 0)
        return true;

    offset = align_uint(offset, 4);

    EMIT_U32(AOT_SECTION_TYPE_CUSTOM);
    /* sub section id + name section size */
    EMIT_U32(sizeof(uint32) * 1 + comp_data->aot_name_section_size);
    EMIT_U32(AOT_CUSTOM_SECTION_NAME);
    bh_memcpy_s((uint8 *)(buf + offset), (uint32)(buf_end - buf),
                comp_data->aot_name_section_buf,
                (uint32)comp_data->aot_name_section_size);
    offset += comp_data->aot_name_section_size;

    *p_offset = offset;

    LOG_DEBUG("emit name section");
    return true;
}
#endif

#if WASM_ENABLE_STRINGREF != 0
static bool
aot_emit_string_literal_section(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                                AOTCompData *comp_data,
                                AOTCompContext *comp_ctx)
{
    uint32 string_count = comp_data->string_literal_count;

    if (string_count > 0) {
        uint32 offset = *p_offset;
        uint32 i;

        *p_offset = offset = align_uint(offset, 4);

        EMIT_U32(AOT_SECTION_TYPE_CUSTOM);
        /* sub section id + string literal section size */
        EMIT_U32(sizeof(uint32) * 1
                 + get_string_literal_section_size(comp_ctx, comp_data));
        EMIT_U32(AOT_CUSTOM_SECTION_STRING_LITERAL);

        /* reserved */
        EMIT_U32(0);

        /* string literal count */
        EMIT_U32(string_count);

        for (i = 0; i < string_count; i++) {
            EMIT_U32(comp_data->string_literal_lengths_wp[i]);
        }

        for (i = 0; i < string_count; i++) {
            uint32 string_length = comp_data->string_literal_lengths_wp[i];
            bh_memcpy_s((uint8 *)(buf + offset), (uint32)(buf_end - buf),
                        comp_data->string_literal_ptrs_wp[i], string_length);
            offset += string_length;
        }

        *p_offset = offset;
    }

    return true;
}
#endif /* end of WASM_ENABLE_STRINGREF != 0 */

static bool
aot_emit_custom_sections(uint8 *buf, uint8 *buf_end, uint32 *p_offset,
                         AOTCompData *comp_data, AOTCompContext *comp_ctx)
{
#if WASM_ENABLE_LOAD_CUSTOM_SECTION != 0
    uint32 offset = *p_offset, i;

    for (i = 0; i < comp_ctx->custom_sections_count; i++) {
        const char *section_name = comp_ctx->custom_sections_wp[i];
        const uint8 *content = NULL;
        uint32 length = 0;

        if (strcmp(section_name, "name") == 0) {
            *p_offset = offset;
            if (!aot_emit_name_section(buf, buf_end, p_offset, comp_data,
                                       comp_ctx))
                return false;

            offset = *p_offset;
            continue;
        }

        content = wasm_loader_get_custom_section(comp_data->wasm_module,
                                                 section_name, &length);
        if (!content) {
            /* Warning has been reported during calculating size */
            continue;
        }

        offset = align_uint(offset, 4);
        EMIT_U32(AOT_SECTION_TYPE_CUSTOM);
        /* sub section id + content */
        EMIT_U32(sizeof(uint32) * 1 + get_string_size(comp_ctx, section_name)
                 + length);
        EMIT_U32(AOT_CUSTOM_SECTION_RAW);
        EMIT_STR(section_name);
        bh_memcpy_s((uint8 *)(buf + offset), (uint32)(buf_end - buf), content,
                    length);
        offset += length;
    }

    *p_offset = offset;
#endif

    return true;
}

typedef uint32 U32;
typedef int32 I32;
typedef uint16 U16;
typedef uint8 U8;

struct coff_hdr {
    U16 u16Machine;
    U16 u16NumSections;
    U32 u32DateTimeStamp;
    U32 u32SymTblPtr;
    U32 u32NumSymbols;
    U16 u16PeHdrSize;
    U16 u16Characs;
};

#define E_TYPE_REL 1
#define E_TYPE_XIP 4

#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_I386 0x014c
#define IMAGE_FILE_MACHINE_IA64 0x0200

#define AOT_COFF32_BIN_TYPE 4 /* 32-bit little endian */
#define AOT_COFF64_BIN_TYPE 6 /* 64-bit little endian */

#define EI_NIDENT 16

typedef uint32 elf32_word;
typedef int32 elf32_sword;
typedef uint16 elf32_half;
typedef uint32 elf32_off;
typedef uint32 elf32_addr;

struct elf32_ehdr {
    unsigned char e_ident[EI_NIDENT]; /* ident bytes */
    elf32_half e_type;                /* file type */
    elf32_half e_machine;             /* target machine */
    elf32_word e_version;             /* file version */
    elf32_addr e_entry;               /* start address */
    elf32_off e_phoff;                /* phdr file offset */
    elf32_off e_shoff;                /* shdr file offset */
    elf32_word e_flags;               /* file flags */
    elf32_half e_ehsize;              /* sizeof ehdr */
    elf32_half e_phentsize;           /* sizeof phdr */
    elf32_half e_phnum;               /* number phdrs */
    elf32_half e_shentsize;           /* sizeof shdr */
    elf32_half e_shnum;               /* number shdrs */
    elf32_half e_shstrndx;            /* shdr string index */
};

struct elf32_rel {
    elf32_addr r_offset;
    elf32_word r_info;
} elf32_rel;

struct elf32_rela {
    elf32_addr r_offset;
    elf32_word r_info;
    elf32_sword r_addend;
} elf32_rela;

typedef uint32 elf64_word;
typedef int32 elf64_sword;
typedef uint64 elf64_xword;
typedef int64 elf64_sxword;
typedef uint16 elf64_half;
typedef uint64 elf64_off;
typedef uint64 elf64_addr;

struct elf64_ehdr {
    unsigned char e_ident[EI_NIDENT]; /* ident bytes */
    elf64_half e_type;                /* file type */
    elf64_half e_machine;             /* target machine */
    elf64_word e_version;             /* file version */
    elf64_addr e_entry;               /* start address */
    elf64_off e_phoff;                /* phdr file offset */
    elf64_off e_shoff;                /* shdr file offset */
    elf64_word e_flags;               /* file flags */
    elf64_half e_ehsize;              /* sizeof ehdr */
    elf64_half e_phentsize;           /* sizeof phdr */
    elf64_half e_phnum;               /* number phdrs */
    elf64_half e_shentsize;           /* sizeof shdr */
    elf64_half e_shnum;               /* number shdrs */
    elf64_half e_shstrndx;            /* shdr string index */
};

typedef struct elf64_rel {
    elf64_addr r_offset;
    elf64_xword r_info;
} elf64_rel;

typedef struct elf64_rela {
    elf64_addr r_offset;
    elf64_xword r_info;
    elf64_sxword r_addend;
} elf64_rela;

#define SET_TARGET_INFO_VALUE(f, val, type, little) \
    do {                                            \
        type tmp = val;                             \
        if ((little && !is_little_endian())         \
            || (!little && is_little_endian()))     \
            exchange_##type((uint8 *)&tmp);         \
        obj_data->target_info.f = tmp;              \
    } while (0)

#define SET_TARGET_INFO_FIELD(f, v, type, little) \
    SET_TARGET_INFO_VALUE(f, elf_header->v, type, little)

/* in windows 32, the symbol name may start with '_' */
static char *
LLVMGetSymbolNameAndUnDecorate(LLVMSymbolIteratorRef si,
                               AOTTargetInfo target_info)
{
    char *original_name = (char *)LLVMGetSymbolName(si);
    if (!original_name) {
        return NULL;
    }

    if (target_info.bin_type != AOT_COFF32_BIN_TYPE) {
        return original_name;
    }

    if (*original_name == '_') {
        return ++original_name;
    }

    return original_name;
}

static bool
aot_resolve_target_info(AOTCompContext *comp_ctx, AOTObjectData *obj_data)
{
    LLVMBinaryType bin_type = LLVMBinaryGetType(obj_data->binary);
    const uint8 *elf_buf = (uint8 *)LLVMGetBufferStart(obj_data->mem_buf);
    uint32 elf_size = (uint32)LLVMGetBufferSize(obj_data->mem_buf);

    if (bin_type != LLVMBinaryTypeCOFF && bin_type != LLVMBinaryTypeELF32L
        && bin_type != LLVMBinaryTypeELF32B && bin_type != LLVMBinaryTypeELF64L
        && bin_type != LLVMBinaryTypeELF64B
        && bin_type != LLVMBinaryTypeMachO32L
        && bin_type != LLVMBinaryTypeMachO32B
        && bin_type != LLVMBinaryTypeMachO64L
        && bin_type != LLVMBinaryTypeMachO64B) {
        aot_set_last_error("invalid llvm binary bin_type.");
        return false;
    }

    obj_data->target_info.bin_type = bin_type - LLVMBinaryTypeELF32L;

    if (bin_type == LLVMBinaryTypeCOFF) {
        struct coff_hdr *coff_header;

        if (!elf_buf || elf_size < sizeof(struct coff_hdr)) {
            aot_set_last_error("invalid coff_hdr buffer.");
            return false;
        }
        coff_header = (struct coff_hdr *)elf_buf;

        /* Emit eXecute In Place file type while in indirect mode */
        if (comp_ctx->is_indirect_mode)
            obj_data->target_info.e_type = E_TYPE_XIP;
        else
            obj_data->target_info.e_type = E_TYPE_REL;

        obj_data->target_info.e_machine = coff_header->u16Machine;
        obj_data->target_info.e_version = 1;
        obj_data->target_info.e_flags = 0;

        if (coff_header->u16Machine == IMAGE_FILE_MACHINE_AMD64
            || coff_header->u16Machine == IMAGE_FILE_MACHINE_IA64)
            obj_data->target_info.bin_type = AOT_COFF64_BIN_TYPE;
        else if (coff_header->u16Machine == IMAGE_FILE_MACHINE_I386)
            obj_data->target_info.bin_type = AOT_COFF32_BIN_TYPE;
    }
    else if (bin_type == LLVMBinaryTypeELF32L
             || bin_type == LLVMBinaryTypeELF32B) {
        struct elf32_ehdr *elf_header;
        bool is_little_bin = bin_type == LLVMBinaryTypeELF32L;
        uint16 e_type;

        if (!elf_buf || elf_size < sizeof(struct elf32_ehdr)) {
            aot_set_last_error("invalid elf32 buffer.");
            return false;
        }

        elf_header = (struct elf32_ehdr *)elf_buf;
        e_type = elf_header->e_type;

        /* Emit eXecute In Place file type while in indirect mode */
        if (comp_ctx->is_indirect_mode)
            e_type = E_TYPE_XIP;

        SET_TARGET_INFO_VALUE(e_type, e_type, uint16, is_little_bin);
        SET_TARGET_INFO_FIELD(e_machine, e_machine, uint16, is_little_bin);
        SET_TARGET_INFO_FIELD(e_version, e_version, uint32, is_little_bin);
        SET_TARGET_INFO_FIELD(e_flags, e_flags, uint32, is_little_bin);
    }
    else if (bin_type == LLVMBinaryTypeELF64L
             || bin_type == LLVMBinaryTypeELF64B) {
        struct elf64_ehdr *elf_header;
        bool is_little_bin = bin_type == LLVMBinaryTypeELF64L;
        uint16 e_type;

        if (!elf_buf || elf_size < sizeof(struct elf64_ehdr)) {
            aot_set_last_error("invalid elf64 buffer.");
            return false;
        }

        elf_header = (struct elf64_ehdr *)elf_buf;
        e_type = elf_header->e_type;

        /* Emit eXecute In Place file type while in indirect mode */
        if (comp_ctx->is_indirect_mode)
            e_type = E_TYPE_XIP;

        SET_TARGET_INFO_VALUE(e_type, e_type, uint16, is_little_bin);
        SET_TARGET_INFO_FIELD(e_machine, e_machine, uint16, is_little_bin);
        SET_TARGET_INFO_FIELD(e_version, e_version, uint32, is_little_bin);
        SET_TARGET_INFO_FIELD(e_flags, e_flags, uint32, is_little_bin);
    }
    else if (bin_type == LLVMBinaryTypeMachO32L
             || bin_type == LLVMBinaryTypeMachO32B) {
        /* TODO: parse file type of Mach-O 32 */
        aot_set_last_error("invalid llvm binary bin_type.");
        return false;
    }
    else if (bin_type == LLVMBinaryTypeMachO64L
             || bin_type == LLVMBinaryTypeMachO64B) {
        /* TODO: parse file type of Mach-O 64 */
        aot_set_last_error("invalid llvm binary bin_type.");
        return false;
    }

    bh_assert(sizeof(obj_data->target_info.arch)
              == sizeof(comp_ctx->target_arch));
    bh_memcpy_s(obj_data->target_info.arch, sizeof(obj_data->target_info.arch),
                comp_ctx->target_arch, sizeof(comp_ctx->target_arch));

    return true;
}

static bool
aot_resolve_text(AOTObjectData *obj_data)
{
#if WASM_ENABLE_DEBUG_AOT != 0
    LLVMBinaryType bin_type = LLVMBinaryGetType(obj_data->binary);
    if (bin_type == LLVMBinaryTypeELF32L || bin_type == LLVMBinaryTypeELF64L) {
        obj_data->text = (char *)LLVMGetBufferStart(obj_data->mem_buf);
        obj_data->text_size = (uint32)LLVMGetBufferSize(obj_data->mem_buf);
    }
    else
#endif
    {
        LLVMSectionIteratorRef sec_itr;
        char *name;

        if (!(sec_itr = LLVMObjectFileCopySectionIterator(obj_data->binary))) {
            aot_set_last_error("llvm get section iterator failed.");
            return false;
        }
        while (
            !LLVMObjectFileIsSectionIteratorAtEnd(obj_data->binary, sec_itr)) {
            if ((name = (char *)LLVMGetSectionName(sec_itr))) {
                if (!strcmp(name, ".text") || !strcmp(name, ".ltext")) {
                    obj_data->text = (char *)LLVMGetSectionContents(sec_itr);
                    obj_data->text_size = (uint32)LLVMGetSectionSize(sec_itr);
                }
                else if (!strcmp(name, ".text.unlikely.")
                         || !strcmp(name, ".ltext.unlikely.")) {
                    obj_data->text_unlikely =
                        (char *)LLVMGetSectionContents(sec_itr);
                    obj_data->text_unlikely_size =
                        (uint32)LLVMGetSectionSize(sec_itr);
                }
                else if (!strcmp(name, ".text.hot.")
                         || !strcmp(name, ".ltext.hot.")) {
                    obj_data->text_hot =
                        (char *)LLVMGetSectionContents(sec_itr);
                    obj_data->text_hot_size =
                        (uint32)LLVMGetSectionSize(sec_itr);
                }
            }
            LLVMMoveToNextSection(sec_itr);
        }
        LLVMDisposeSectionIterator(sec_itr);
    }

    return true;
}

static bool
aot_resolve_literal(AOTObjectData *obj_data)
{
    LLVMSectionIteratorRef sec_itr;
    char *name;

    if (!(sec_itr = LLVMObjectFileCopySectionIterator(obj_data->binary))) {
        aot_set_last_error("llvm get section iterator failed.");
        return false;
    }
    while (!LLVMObjectFileIsSectionIteratorAtEnd(obj_data->binary, sec_itr)) {
        if ((name = (char *)LLVMGetSectionName(sec_itr))
            && !strcmp(name, ".literal")) {
            obj_data->literal = (char *)LLVMGetSectionContents(sec_itr);
            obj_data->literal_size = (uint32)LLVMGetSectionSize(sec_itr);
            break;
        }
        LLVMMoveToNextSection(sec_itr);
    }
    LLVMDisposeSectionIterator(sec_itr);

    return true;
}

static bool
get_relocations_count(LLVMSectionIteratorRef sec_itr, uint32 *p_count);

static bool
is_data_section(AOTObjectData *obj_data, LLVMSectionIteratorRef sec_itr,
                char *section_name)
{
    uint32 relocation_count = 0;

    return (!strcmp(section_name, ".data") || !strcmp(section_name, ".sdata")
            || !strcmp(section_name, ".rodata")
#if LLVM_VERSION_MAJOR >= 19
            /* https://github.com/llvm/llvm-project/pull/82214 */
            || !strcmp(section_name, ".srodata")
#endif
            /* ".rodata.cst4/8/16/.." */
            || !strncmp(section_name, ".rodata.cst", strlen(".rodata.cst"))
#if LLVM_VERSION_MAJOR >= 19
            /* https://github.com/llvm/llvm-project/pull/82214
             * ".srodata.cst4/8/16/.." */
            || !strncmp(section_name, ".srodata.cst", strlen(".srodata.cst"))
#endif
            /* ".rodata.strn.m" */
            || !strncmp(section_name, ".rodata.str", strlen(".rodata.str"))
            || (!strcmp(section_name, ".rdata")
                && get_relocations_count(sec_itr, &relocation_count)
                && relocation_count > 0)
            || !strcmp(section_name, aot_stack_sizes_section_name)
            || (obj_data->comp_ctx->enable_llvm_pgo
                && (!strncmp(section_name, "__llvm_prf_cnts", 15)
                    || !strncmp(section_name, "__llvm_prf_data", 15)
                    || !strncmp(section_name, "__llvm_prf_names", 16))));
}

static bool
get_object_data_sections_count(AOTObjectData *obj_data, uint32 *p_count)
{
    LLVMSectionIteratorRef sec_itr;
    char *name;
    uint32 count = 0;

    if (!(sec_itr = LLVMObjectFileCopySectionIterator(obj_data->binary))) {
        aot_set_last_error("llvm get section iterator failed.");
        return false;
    }
    while (!LLVMObjectFileIsSectionIteratorAtEnd(obj_data->binary, sec_itr)) {
        if ((name = (char *)LLVMGetSectionName(sec_itr))
            && (is_data_section(obj_data, sec_itr, name))) {
            count++;
        }
        LLVMMoveToNextSection(sec_itr);
    }
    LLVMDisposeSectionIterator(sec_itr);

    *p_count = count;
    return true;
}

static bool
aot_resolve_object_data_sections(AOTObjectData *obj_data)
{
    LLVMSectionIteratorRef sec_itr;
    char *name;
    AOTObjectDataSection *data_section;
    uint32 sections_count;
    uint32 size;

    if (!get_object_data_sections_count(obj_data, &sections_count)) {
        return false;
    }

    if (sections_count > 0) {
        uint32 llvm_prf_cnts_idx = 0, llvm_prf_data_idx = 0;
        char buf[32];

        size = (uint32)sizeof(AOTObjectDataSection) * sections_count;
        if (!(data_section = obj_data->data_sections =
                  wasm_runtime_malloc(size))) {
            aot_set_last_error("allocate memory for data sections failed.");
            return false;
        }
        memset(obj_data->data_sections, 0, size);
        obj_data->data_sections_count = sections_count;

        if (!(sec_itr = LLVMObjectFileCopySectionIterator(obj_data->binary))) {
            aot_set_last_error("llvm get section iterator failed.");
            return false;
        }
        while (
            !LLVMObjectFileIsSectionIteratorAtEnd(obj_data->binary, sec_itr)) {
            if ((name = (char *)LLVMGetSectionName(sec_itr))
                && (is_data_section(obj_data, sec_itr, name))) {
                data_section->name = name;
                if (obj_data->comp_ctx->enable_llvm_pgo
                    && !strcmp(name, "__llvm_prf_cnts")) {
                    snprintf(buf, sizeof(buf), "%s%u", name,
                             llvm_prf_cnts_idx++);
                    size = (uint32)(strlen(buf) + 1);
                    if (!(data_section->name = wasm_runtime_malloc(size))) {
                        aot_set_last_error(
                            "allocate memory for data section name failed.");
                        return false;
                    }
                    bh_memcpy_s(data_section->name, size, buf, size);
                    data_section->is_name_allocated = true;
                }
                else if (obj_data->comp_ctx->enable_llvm_pgo
                         && !strcmp(name, "__llvm_prf_data")) {
                    snprintf(buf, sizeof(buf), "%s%u", name,
                             llvm_prf_data_idx++);
                    size = (uint32)(strlen(buf) + 1);
                    if (!(data_section->name = wasm_runtime_malloc(size))) {
                        aot_set_last_error(
                            "allocate memory for data section name failed.");
                        return false;
                    }
                    bh_memcpy_s(data_section->name, size, buf, size);
                    data_section->is_name_allocated = true;
                }
                else if (obj_data->comp_ctx->enable_llvm_pgo
                         && !strcmp(name, "__llvm_prf_bits")) {
                    LOG_WARNING("__llvm_prf_bits section is not supported and "
                                "shouldn't be used in PGO.");
                    return false;
                }

                if (obj_data->comp_ctx->enable_llvm_pgo
                    && !strcmp(name, "__llvm_prf_names")) {
                    data_section->data = (uint8 *)aot_compress_aot_func_names(
                        obj_data->comp_ctx, &data_section->size);
                    data_section->is_data_allocated = true;
                }
                else {
                    data_section->data =
                        (uint8 *)LLVMGetSectionContents(sec_itr);
                    data_section->size = (uint32)LLVMGetSectionSize(sec_itr);
                }
                data_section++;
            }
            LLVMMoveToNextSection(sec_itr);
        }
        LLVMDisposeSectionIterator(sec_itr);
    }

    return true;
}

static bool
read_stack_usage_file(const AOTCompContext *comp_ctx, const char *filename,
                      uint32 *sizes, uint32 count)
{
    FILE *fp = NULL;
    if (filename == NULL) {
        aot_set_last_error("no stack usage file is specified.");
        return false;
    }
    fp = fopen(filename, "r");
    if (fp == NULL) {
        LOG_ERROR("failed to open stack usage file: %s", filename);
        goto fail;
    }
    /*
     * the file consists of lines like:
     *
     * WASM Module:aot_func#9  72  static
     */
    const char *aot_func_prefix = AOT_FUNC_PREFIX;
    const char *aot_func_internal_prefix = AOT_FUNC_INTERNAL_PREFIX;
    uint32 precheck_found = 0;
    uint32 precheck_stack_size_max = 0;
    uint32 precheck_stack_size_min = UINT32_MAX;
    uint32 found = 0;
    while (true) {
        const char *prefix;
        char line[100];
        char *cp = fgets(line, sizeof(line), fp);
        char *fn;
        char *colon;
        uintmax_t func_idx;
        uintmax_t sz;
        int ret;

        if (cp == NULL) {
            break;
        }
        /*
         * Note: strrchr (not strchr) because a module name can contain
         * colons.
         */
        colon = strrchr(cp, ':');
        if (colon == NULL) {
            goto fail;
        }
        fn = strstr(colon, aot_func_prefix);
        if (fn != NULL) {
            prefix = aot_func_prefix;
        }
        else {
            fn = strstr(colon, aot_func_internal_prefix);
            if (fn == NULL) {
                LOG_ERROR("failed to parse stack usage line: %s", cp);
                goto fail;
            }
            prefix = aot_func_internal_prefix;
        }
        ret = sscanf(fn + strlen(prefix), "%ju %ju static", &func_idx, &sz);
        if (ret != 2) {
            goto fail;
        }
        if (sz > UINT32_MAX) {
            goto fail;
        }
        if (func_idx > UINT32_MAX) {
            goto fail;
        }
        if (func_idx >= count) {
            goto fail;
        }
        if (prefix == aot_func_prefix) {
            if (sz < precheck_stack_size_min) {
                precheck_stack_size_min = (uint32)sz;
            }
            if (sz > precheck_stack_size_max) {
                precheck_stack_size_max = (uint32)sz;
            }
            precheck_found++;
            continue;
        }
        sizes[func_idx] = (uint32)sz;
        found++;
    }
    fclose(fp);
    if (precheck_found != count) {
        LOG_ERROR("%" PRIu32 " precheck entries found while %" PRIu32
                  " entries are expected",
                  precheck_found, count);
        return false;
    }
    if (found != count) {
        /*
         * LLVM seems to eliminate calls to an empty function
         * (and eliminate the function) even if it's marked noinline.
         */
        LOG_VERBOSE("%" PRIu32 " entries found while %" PRIu32
                    " entries are expected. Maybe LLVM optimization eliminated "
                    "some functions.",
                    found, count);
    }
    if (precheck_stack_size_min != precheck_stack_size_max) {
        /*
         * Note: this is too strict.
         *
         * actually, the stack consumption of the precheck functions
         * can depend on the type of them.
         * that is, depending on various factors including
         * calling conventions and compilers, a function with many
         * parameters can consume more stack, even if it merely does
         * a tail-call to another function.
         */
        bool musttail = aot_target_precheck_can_use_musttail(comp_ctx);
        if (musttail) {
            LOG_WARNING(
                "precheck functions use variable amount of stack. (%" PRIu32
                " - %" PRIu32 ")",
                precheck_stack_size_min, precheck_stack_size_max);
        }
        else {
            LOG_VERBOSE("precheck functions use %" PRIu32 " - %" PRIu32
                        " bytes of stack.",
                        precheck_stack_size_min, precheck_stack_size_max);
        }
    }
    else {
        LOG_VERBOSE("precheck functions use %" PRIu32 " bytes of stack.",
                    precheck_stack_size_max);
    }
    if (precheck_stack_size_max >= 1024) {
        LOG_WARNING("precheck functions themselves consume relatively large "
                    "amount of stack (%" PRIu32
                    "). Please ensure the runtime has large enough "
                    "WASM_STACK_GUARD_SIZE.",
                    precheck_stack_size_max);
    }
    return true;
fail:
    if (fp != NULL)
        fclose(fp);
    aot_set_last_error("failed to read stack usage file.");
    return false;
}

static bool
aot_resolve_stack_sizes(AOTCompContext *comp_ctx, AOTObjectData *obj_data)
{
    LLVMSectionIteratorRef sec_itr = NULL;
    LLVMSymbolIteratorRef sym_itr;
    const char *name;

    if (!(sym_itr = LLVMObjectFileCopySymbolIterator(obj_data->binary))) {
        aot_set_last_error("llvm get symbol iterator failed.");
        return false;
    }

    while (!LLVMObjectFileIsSymbolIteratorAtEnd(obj_data->binary, sym_itr)) {
        if ((name =
                 LLVMGetSymbolNameAndUnDecorate(sym_itr, obj_data->target_info))
            && (!strcmp(name, aot_stack_sizes_alias_name))) {
#if 0 /* cf. https://github.com/llvm/llvm-project/issues/67765 */
            uint64 sz = LLVMGetSymbolSize(sym_itr);
            if (sz != sizeof(uint32) * obj_data->func_count
                /* sz of COFF64/COFF32 is 0, ignore the check */
                && obj_data->target_info.bin_type != AOT_COFF64_BIN_TYPE
                && obj_data->target_info.bin_type != AOT_COFF32_BIN_TYPE) {
                aot_set_last_error("stack_sizes had unexpected size.");
                goto fail;
            }
#endif
            uint64 addr = LLVMGetSymbolAddress(sym_itr);
            if (!(sec_itr =
                      LLVMObjectFileCopySectionIterator(obj_data->binary))) {
                aot_set_last_error("llvm get section iterator failed.");
                goto fail;
            }
            LLVMMoveToContainingSection(sec_itr, sym_itr);
            const char *sec_name = LLVMGetSectionName(sec_itr);
            LOG_VERBOSE("stack_sizes found in section %s offset %" PRIu64 ".",
                        sec_name, addr);
            if (strcmp(sec_name, aot_stack_sizes_section_name) || addr != 0) {
                aot_set_last_error(
                    "stack_sizes found at an unexpected location.");
                goto fail;
            }
            /*
             * Note: We can't always modify stack_sizes in-place.
             * E.g. When WAMRC_LLC_COMPILER is used, LLVM sometimes uses
             * read-only mmap of the temporary file to back
             * LLVMGetSectionContents.
             */
            const uint32 *ro_stack_sizes =
                (const uint32 *)(LLVMGetSectionContents(sec_itr) + addr);
            uint32 i;
            for (i = 0; i < obj_data->func_count; i++) {
                /* Note: -1 == AOT_NEG_ONE from aot_create_stack_sizes */
                if (ro_stack_sizes[i] != (uint32)-1) {
                    aot_set_last_error("unexpected data in stack_sizes.");
                    goto fail;
                }
            }
            /*
             * Record section/offset and construct a copy of stack_sizes.
             * aot_emit_object_data_section_info will emit this copy.
             */
            obj_data->stack_sizes_section_name = sec_name;
            obj_data->stack_sizes_offset = (uint32)addr;
            obj_data->stack_sizes = wasm_runtime_malloc(
                obj_data->func_count * sizeof(*obj_data->stack_sizes));
            if (obj_data->stack_sizes == NULL) {
                aot_set_last_error("failed to allocate memory.");
                goto fail;
            }
            uint32 *stack_sizes = obj_data->stack_sizes;
            for (i = 0; i < obj_data->func_count; i++) {
                stack_sizes[i] = (uint32)-1;
            }
            if (!read_stack_usage_file(comp_ctx, comp_ctx->stack_usage_file,
                                       stack_sizes, obj_data->func_count)) {
                goto fail;
            }
            for (i = 0; i < obj_data->func_count; i++) {
                const AOTFuncContext *func_ctx = comp_ctx->func_ctxes[i];
                bool musttail = aot_target_precheck_can_use_musttail(comp_ctx);
                unsigned int stack_consumption_to_call_wrapped_func =
                    musttail ? 0
                             : aot_estimate_stack_usage_for_function_call(
                                 comp_ctx, func_ctx->aot_func->func_type);

                /*
                 * LLVM seems to eliminate calls to an empty function
                 * (and eliminate the function) even if it's marked noinline.
                 *
                 * Note: -1 == AOT_NEG_ONE from aot_create_stack_sizes
                 */
                if (stack_sizes[i] == (uint32)-1) {
                    if (func_ctx->stack_consumption_for_func_call != 0) {
                        /*
                         * This happens if a function calling another
                         * function has been optimized out.
                         *
                         * for example,
                         *
                         *   (func $func
                         *     (local i32)
                         *     local.get 0
                         *     if
                         *       call $another
                         *     end
                         *   )
                         */
                        LOG_VERBOSE("AOT func#%" PRIu32
                                    " had call(s) but eliminated?",
                                    i);
                    }
                    else {
                        LOG_VERBOSE("AOT func#%" PRIu32 " eliminated?", i);
                    }
                    stack_sizes[i] = 0;
                }
                else {
                    LOG_VERBOSE("AOT func#%" PRIu32 " stack_size %u + %" PRIu32
                                " + %u",
                                i, stack_consumption_to_call_wrapped_func,
                                stack_sizes[i],
                                func_ctx->stack_consumption_for_func_call);
                    if (UINT32_MAX - stack_sizes[i]
                        < func_ctx->stack_consumption_for_func_call) {
                        aot_set_last_error("stack size overflow.");
                        goto fail;
                    }
                    stack_sizes[i] += func_ctx->stack_consumption_for_func_call;
                    if (UINT32_MAX - stack_sizes[i]
                        < stack_consumption_to_call_wrapped_func) {
                        aot_set_last_error("stack size overflow.");
                        goto fail;
                    }
                    stack_sizes[i] += stack_consumption_to_call_wrapped_func;
                }
            }
            LLVMDisposeSectionIterator(sec_itr);
            LLVMDisposeSymbolIterator(sym_itr);
            return true;
        }
        LLVMMoveToNextSymbol(sym_itr);
    }
    aot_set_last_error("stack_sizes not found.");
fail:
    if (sec_itr)
        LLVMDisposeSectionIterator(sec_itr);
    LLVMDisposeSymbolIterator(sym_itr);
    return false;
}

static bool
aot_resolve_functions(AOTCompContext *comp_ctx, AOTObjectData *obj_data)
{
    AOTObjectFunc *func;
    LLVMSymbolIteratorRef sym_itr;
    char *name, *prefix = AOT_FUNC_PREFIX;
    uint32 func_index, total_size;

    /* allocate memory for aot function */
    obj_data->func_count = comp_ctx->comp_data->func_count;
    if (obj_data->func_count) {
        if ((comp_ctx->enable_stack_bound_check
             || comp_ctx->enable_stack_estimation)
            && !aot_resolve_stack_sizes(comp_ctx, obj_data))
            return false;
        total_size = (uint32)sizeof(AOTObjectFunc) * obj_data->func_count;
        if (!(obj_data->funcs = wasm_runtime_malloc(total_size))) {
            aot_set_last_error("allocate memory for functions failed.");
            return false;
        }
        memset(obj_data->funcs, 0, total_size);
    }

    if (!(sym_itr = LLVMObjectFileCopySymbolIterator(obj_data->binary))) {
        aot_set_last_error("llvm get symbol iterator failed.");
        return false;
    }

    while (!LLVMObjectFileIsSymbolIteratorAtEnd(obj_data->binary, sym_itr)) {
        name = LLVMGetSymbolNameAndUnDecorate(sym_itr, obj_data->target_info);
        if (name && str_starts_with(name, prefix)) {
            /* symbol aot_func#n */
            func_index = (uint32)atoi(name + strlen(prefix));
            if (func_index < obj_data->func_count) {
                LLVMSectionIteratorRef contain_section;
                char *contain_section_name;

                func = obj_data->funcs + func_index;
                func->func_name = name;

                if (!(contain_section = LLVMObjectFileCopySectionIterator(
                          obj_data->binary))) {
                    aot_set_last_error("llvm get section iterator failed.");
                    LLVMDisposeSymbolIterator(sym_itr);
                    return false;
                }
                LLVMMoveToContainingSection(contain_section, sym_itr);
                contain_section_name =
                    (char *)LLVMGetSectionName(contain_section);
                LLVMDisposeSectionIterator(contain_section);

                if (!strcmp(contain_section_name, ".text.unlikely.")
                    || !strcmp(contain_section_name, ".ltext.unlikely.")) {
                    func->text_offset = align_uint(obj_data->text_size, 4)
                                        + LLVMGetSymbolAddress(sym_itr);
                }
                else if (!strcmp(contain_section_name, ".text.hot.")
                         || !strcmp(contain_section_name, ".ltext.hot.")) {
                    func->text_offset =
                        align_uint(obj_data->text_size, 4)
                        + align_uint(obj_data->text_unlikely_size, 4)
                        + LLVMGetSymbolAddress(sym_itr);
                }
                else {
                    func->text_offset = LLVMGetSymbolAddress(sym_itr);
                }
            }
        }
        else if (name && str_starts_with(name, AOT_FUNC_INTERNAL_PREFIX)) {
            /* symbol aot_func_internal#n */
            func_index = (uint32)atoi(name + strlen(AOT_FUNC_INTERNAL_PREFIX));
            if (func_index < obj_data->func_count) {
                LLVMSectionIteratorRef contain_section;
                char *contain_section_name;

                func = obj_data->funcs + func_index;

                if (!(contain_section = LLVMObjectFileCopySectionIterator(
                          obj_data->binary))) {
                    aot_set_last_error("llvm get section iterator failed.");
                    LLVMDisposeSymbolIterator(sym_itr);
                    return false;
                }
                LLVMMoveToContainingSection(contain_section, sym_itr);
                contain_section_name =
                    (char *)LLVMGetSectionName(contain_section);
                LLVMDisposeSectionIterator(contain_section);

                if (!strcmp(contain_section_name, ".text.unlikely.")
                    || !strcmp(contain_section_name, ".ltext.unlikely.")) {
                    func->text_offset_of_aot_func_internal =
                        align_uint(obj_data->text_size, 4)
                        + LLVMGetSymbolAddress(sym_itr);
                }
                else if (!strcmp(contain_section_name, ".text.hot.")
                         || !strcmp(contain_section_name, ".ltext.hot.")) {
                    func->text_offset_of_aot_func_internal =
                        align_uint(obj_data->text_size, 4)
                        + align_uint(obj_data->text_unlikely_size, 4)
                        + LLVMGetSymbolAddress(sym_itr);
                }
                else {
                    func->text_offset_of_aot_func_internal =
                        LLVMGetSymbolAddress(sym_itr);
                }
            }
        }
        LLVMMoveToNextSymbol(sym_itr);
    }
    LLVMDisposeSymbolIterator(sym_itr);

    return true;
}

static bool
get_relocations_count(LLVMSectionIteratorRef sec_itr, uint32 *p_count)
{
    uint32 relocation_count = 0;
    LLVMRelocationIteratorRef rel_itr;

    if (!(rel_itr = LLVMGetRelocations(sec_itr))) {
        aot_set_last_error("llvm get relocations failed.");
        LLVMDisposeSectionIterator(sec_itr);
        return false;
    }

    while (!LLVMIsRelocationIteratorAtEnd(sec_itr, rel_itr)) {
        relocation_count++;
        LLVMMoveToNextRelocation(rel_itr);
    }
    LLVMDisposeRelocationIterator(rel_itr);

    *p_count = relocation_count;
    return true;
}

static bool
aot_resolve_object_relocation_group(AOTObjectData *obj_data,
                                    AOTRelocationGroup *group,
                                    LLVMSectionIteratorRef rel_sec)
{
    LLVMRelocationIteratorRef rel_itr;
    AOTRelocation *relocation = group->relocations;
    uint32 size;
    bool is_binary_32bit = is_32bit_binary(obj_data);
    bool is_binary_little_endian = is_little_endian_binary(obj_data);
    bool has_addend = str_starts_with(group->section_name, ".rela");
    uint8 *rela_content = NULL;

    /* calculate relocations count and allocate memory */
    if (!get_relocations_count(rel_sec, &group->relocation_count))
        return false;
    if (group->relocation_count == 0) {
        aot_set_last_error("invalid relocations count");
        return false;
    }
    size = (uint32)sizeof(AOTRelocation) * group->relocation_count;
    if (!(relocation = group->relocations = wasm_runtime_malloc(size))) {
        aot_set_last_error("allocate memory for relocations failed.");
        return false;
    }
    memset(group->relocations, 0, size);

    if (has_addend) {
        uint64 rela_content_size;
        /* LLVM doesn't provide C API to get relocation addend. So we have to
         * parse it manually. */
        rela_content = (uint8 *)LLVMGetSectionContents(rel_sec);
        rela_content_size = LLVMGetSectionSize(rel_sec);
        if (is_binary_32bit)
            size = (uint32)sizeof(struct elf32_rela) * group->relocation_count;
        else
            size = (uint32)sizeof(struct elf64_rela) * group->relocation_count;
        if (rela_content_size != (uint64)size) {
            aot_set_last_error("invalid relocation section content.");
            return false;
        }
    }

    /* parse each relocation */
    if (!(rel_itr = LLVMGetRelocations(rel_sec))) {
        aot_set_last_error("llvm get relocations failed.");
        return false;
    }
    while (!LLVMIsRelocationIteratorAtEnd(rel_sec, rel_itr)) {
        uint64 offset = LLVMGetRelocationOffset(rel_itr);
        uint64 type = LLVMGetRelocationType(rel_itr);
        LLVMSymbolIteratorRef rel_sym = LLVMGetRelocationSymbol(rel_itr);

        if (!rel_sym) {
            aot_set_last_error("llvm get relocation symbol failed.");
            goto fail;
        }

        /* parse relocation addend from relocation content */
        if (has_addend) {
            if (is_binary_32bit) {
                int32 addend =
                    (int32)(((struct elf32_rela *)rela_content)->r_addend);
                if (is_binary_little_endian != is_little_endian())
                    exchange_uint32((uint8 *)&addend);
                relocation->relocation_addend = (int64)addend;
                rela_content += sizeof(struct elf32_rela);
            }
            else {
                int64 addend =
                    (int64)(((struct elf64_rela *)rela_content)->r_addend);
                if (is_binary_little_endian != is_little_endian())
                    exchange_uint64((uint8 *)&addend);
                relocation->relocation_addend = addend;
                rela_content += sizeof(struct elf64_rela);
            }
        }

        /* set relocation fields */
        relocation->relocation_type = (uint32)type;
        relocation->symbol_name =
            LLVMGetSymbolNameAndUnDecorate(rel_sym, obj_data->target_info);
        relocation->relocation_offset = offset;
        if (!strcmp(group->section_name, ".rela.text.unlikely.")
            || !strcmp(group->section_name, ".rel.text.unlikely.")) {
            relocation->relocation_offset += align_uint(obj_data->text_size, 4);
        }
        else if (!strcmp(group->section_name, ".rela.text.hot.")
                 || !strcmp(group->section_name, ".rel.text.hot.")) {
            relocation->relocation_offset +=
                align_uint(obj_data->text_size, 4)
                + align_uint(obj_data->text_unlikely_size, 4);
        }
        if (!strcmp(relocation->symbol_name, ".text.unlikely.")) {
            relocation->symbol_name = ".text";
            relocation->relocation_addend += align_uint(obj_data->text_size, 4);
        }
        if (!strcmp(relocation->symbol_name, ".text.hot.")) {
            relocation->symbol_name = ".text";
            relocation->relocation_addend +=
                align_uint(obj_data->text_size, 4)
                + align_uint(obj_data->text_unlikely_size, 4);
        }

        /*
         * Note: aot_stack_sizes_section_name section only contains
         * stack_sizes table.
         */
        if (!strcmp(relocation->symbol_name, aot_stack_sizes_name)) {
            /* discard const */
            relocation->symbol_name = (char *)aot_stack_sizes_section_name;
        }

        if (obj_data->comp_ctx->enable_llvm_pgo
            && (!strcmp(relocation->symbol_name, "__llvm_prf_cnts")
                || !strcmp(relocation->symbol_name, "__llvm_prf_data"))) {
            LLVMSectionIteratorRef sec_itr;
            char buf[32], *section_name;
            uint32 prof_section_idx = 0;

            if (!(sec_itr =
                      LLVMObjectFileCopySectionIterator(obj_data->binary))) {
                aot_set_last_error("llvm get section iterator failed.");
                LLVMDisposeSymbolIterator(rel_sym);
                goto fail;
            }
            while (!LLVMObjectFileIsSectionIteratorAtEnd(obj_data->binary,
                                                         sec_itr)) {
                section_name = (char *)LLVMGetSectionName(sec_itr);
                if (section_name
                    && !strcmp(section_name, relocation->symbol_name)) {
                    if (LLVMGetSectionContainsSymbol(sec_itr, rel_sym))
                        break;
                    prof_section_idx++;
                }
                LLVMMoveToNextSection(sec_itr);
            }
            LLVMDisposeSectionIterator(sec_itr);

            if (!strcmp(group->section_name, ".rela.text")
                || !strcmp(group->section_name, ".rel.text")) {
                snprintf(buf, sizeof(buf), "%s%u", relocation->symbol_name,
                         prof_section_idx);
                size = (uint32)(strlen(buf) + 1);
                if (!(relocation->symbol_name = wasm_runtime_malloc(size))) {
                    aot_set_last_error(
                        "allocate memory for relocation symbol name failed.");
                    LLVMDisposeSymbolIterator(rel_sym);
                    goto fail;
                }
                bh_memcpy_s(relocation->symbol_name, size, buf, size);
                relocation->is_symbol_name_allocated = true;
            }
            else if (!strncmp(group->section_name, ".rela__llvm_prf_data", 20)
                     || !strncmp(group->section_name, ".rel__llvm_prf_data",
                                 19)) {
                snprintf(buf, sizeof(buf), "%s%u", relocation->symbol_name,
                         prof_section_idx);
                size = (uint32)(strlen(buf) + 1);
                if (!(relocation->symbol_name = wasm_runtime_malloc(size))) {
                    aot_set_last_error(
                        "allocate memory for relocation symbol name failed.");
                    LLVMDisposeSymbolIterator(rel_sym);
                    goto fail;
                }
                bh_memcpy_s(relocation->symbol_name, size, buf, size);
                relocation->is_symbol_name_allocated = true;
            }
        }

        /* for ".LCPIxxx", ".LJTIxxx", ".LBBxxx" and switch lookup table
         * relocation, transform the symbol name to real section name and set
         * addend to the offset of the symbol in the real section */
        if (relocation->symbol_name
            && (str_starts_with(relocation->symbol_name, ".LCPI")
                || str_starts_with(relocation->symbol_name, ".LJTI")
                || str_starts_with(relocation->symbol_name, ".LBB")
                || str_starts_with(relocation->symbol_name, ".Lswitch.table.")
#if LLVM_VERSION_MAJOR >= 16
                /* cf. https://reviews.llvm.org/D123264 */
                || str_starts_with(relocation->symbol_name, ".Lpcrel_hi")
#endif
#if LLVM_VERSION_MAJOR >= 19
                /* cf.
                 * https://github.com/llvm/llvm-project/pull/95031
                 * https://github.com/llvm/llvm-project/pull/89693
                 *
                 * note: the trailing space in ".L0 " is intentional. */
                || !strcmp(relocation->symbol_name, "")
                || !strcmp(relocation->symbol_name, ".L0 ")
#endif
                    )) {
            /* change relocation->relocation_addend and
               relocation->symbol_name */
            LLVMSectionIteratorRef contain_section;
            if (!(contain_section =
                      LLVMObjectFileCopySectionIterator(obj_data->binary))) {
                aot_set_last_error("llvm get section iterator failed.");
                goto fail;
            }
            LLVMMoveToContainingSection(contain_section, rel_sym);
            if (LLVMObjectFileIsSectionIteratorAtEnd(obj_data->binary,
                                                     contain_section)) {
                LLVMDisposeSectionIterator(contain_section);
                aot_set_last_error("llvm get containing section failed.");
                goto fail;
            }
            relocation->relocation_addend += LLVMGetSymbolAddress(rel_sym);
            relocation->symbol_name =
                (char *)LLVMGetSectionName(contain_section);
            LLVMDisposeSectionIterator(contain_section);
        }

        LLVMDisposeSymbolIterator(rel_sym);
        LLVMMoveToNextRelocation(rel_itr);
        relocation++;
    }
    LLVMDisposeRelocationIterator(rel_itr);
    return true;

fail:
    LLVMDisposeRelocationIterator(rel_itr);
    return false;
}

static bool
is_relocation_section_name(AOTObjectData *obj_data, char *section_name)
{
    return (!strcmp(section_name, ".rela.text")
            || !strcmp(section_name, ".rel.text")
            || !strcmp(section_name, ".rela.text.unlikely.")
            || !strcmp(section_name, ".rel.text.unlikely.")
            || !strcmp(section_name, ".rela.text.hot.")
            || !strcmp(section_name, ".rel.text.hot.")
            || !strcmp(section_name, ".rela.ltext")
            || !strcmp(section_name, ".rel.ltext")
            || !strcmp(section_name, ".rela.ltext.unlikely.")
            || !strcmp(section_name, ".rel.ltext.unlikely.")
            || !strcmp(section_name, ".rela.ltext.hot.")
            || !strcmp(section_name, ".rel.ltext.hot.")
            || !strcmp(section_name, ".rela.literal")
            || !strcmp(section_name, ".rela.data")
            || !strcmp(section_name, ".rel.data")
            || !strcmp(section_name, ".rela.sdata")
            || !strcmp(section_name, ".rel.sdata")
            || !strcmp(section_name, ".rela.rodata")
            || !strcmp(section_name, ".rel.rodata")
            || (obj_data->comp_ctx->enable_llvm_pgo
                && (!strcmp(section_name, ".rela__llvm_prf_data")
                    || !strcmp(section_name, ".rel__llvm_prf_data")))
            /* ".rela.rodata.cst4/8/16/.." */
            || !strncmp(section_name, ".rela.rodata.cst",
                        strlen(".rela.rodata.cst"))
            /* ".rel.rodata.cst4/8/16/.." */
            || !strncmp(section_name, ".rel.rodata.cst",
                        strlen(".rel.rodata.cst")));
}

static bool
is_relocation_section(AOTObjectData *obj_data, LLVMSectionIteratorRef sec_itr)
{
    uint32 count = 0;
    char *name = (char *)LLVMGetSectionName(sec_itr);
    if (name) {
        if (is_relocation_section_name(obj_data, name))
            return true;
        else if ((!strcmp(name, ".text") || !strcmp(name, ".text.unlikely.")
                  || !strcmp(name, ".text.hot.") || !strcmp(name, ".rdata"))
                 && get_relocations_count(sec_itr, &count) && count > 0)
            return true;
    }
    return false;
}

static bool
is_readonly_section(const char *name)
{
    return !strcmp(name, ".rel.text") || !strcmp(name, ".rela.text")
           || !strcmp(name, ".rel.ltext") || !strcmp(name, ".rela.ltext")
           || !strcmp(name, ".rela.literal") || !strcmp(name, ".text")
           || !strcmp(name, ".ltext");
}

static bool
get_relocation_groups_count(AOTObjectData *obj_data, uint32 *p_count)
{
    uint32 count = 0;
    LLVMSectionIteratorRef sec_itr;

    if (!(sec_itr = LLVMObjectFileCopySectionIterator(obj_data->binary))) {
        aot_set_last_error("llvm get section iterator failed.");
        return false;
    }
    while (!LLVMObjectFileIsSectionIteratorAtEnd(obj_data->binary, sec_itr)) {
        if (is_relocation_section(obj_data, sec_itr)) {
            count++;
        }
        LLVMMoveToNextSection(sec_itr);
    }
    LLVMDisposeSectionIterator(sec_itr);

    *p_count = count;
    return true;
}

static bool
aot_resolve_object_relocation_groups(AOTObjectData *obj_data)
{
    LLVMSectionIteratorRef sec_itr;
    AOTRelocationGroup *relocation_group;
    uint32 group_count, llvm_prf_data_idx = 0;
    char *name;
    uint32 size;

    /* calculate relocation groups count and allocate memory */
    if (!get_relocation_groups_count(obj_data, &group_count))
        return false;

    if (0 == (obj_data->relocation_group_count = group_count))
        return true;

    size = (uint32)sizeof(AOTRelocationGroup) * group_count;
    if (!(relocation_group = obj_data->relocation_groups =
              wasm_runtime_malloc(size))) {
        aot_set_last_error("allocate memory for relocation groups failed.");
        return false;
    }

    memset(obj_data->relocation_groups, 0, size);

    /* resolve each relocation group */
    if (!(sec_itr = LLVMObjectFileCopySectionIterator(obj_data->binary))) {
        aot_set_last_error("llvm get section iterator failed.");
        return false;
    }
    while (!LLVMObjectFileIsSectionIteratorAtEnd(obj_data->binary, sec_itr)) {
        if (is_relocation_section(obj_data, sec_itr)) {
            name = (char *)LLVMGetSectionName(sec_itr);
            relocation_group->section_name = name;

            if (obj_data->comp_ctx->enable_llvm_pgo
                && (!strcmp(name, ".rela__llvm_prf_data")
                    || !strcmp(name, ".rel__llvm_prf_data"))) {
                char buf[32];
                snprintf(buf, sizeof(buf), "%s%u", name, llvm_prf_data_idx);
                size = (uint32)(strlen(buf) + 1);
                if (!(relocation_group->section_name =
                          wasm_runtime_malloc(size))) {
                    aot_set_last_error(
                        "allocate memory for section name failed.");
                    LLVMDisposeSectionIterator(sec_itr);
                    return false;
                }
                bh_memcpy_s(relocation_group->section_name, size, buf, size);
                relocation_group->is_section_name_allocated = true;
            }

            if (!aot_resolve_object_relocation_group(obj_data, relocation_group,
                                                     sec_itr)) {
                LLVMDisposeSectionIterator(sec_itr);
                return false;
            }

            if (obj_data->comp_ctx->enable_llvm_pgo
                && (!strcmp(name, ".rela__llvm_prf_data")
                    || !strcmp(name, ".rel__llvm_prf_data"))) {
                llvm_prf_data_idx++;
            }

            if (!strcmp(relocation_group->section_name, ".rela.text.unlikely.")
                || !strcmp(relocation_group->section_name, ".rela.text.hot.")) {
                relocation_group->section_name = ".rela.text";
            }
            else if (!strcmp(relocation_group->section_name,
                             ".rela.ltext.unlikely.")
                     || !strcmp(relocation_group->section_name,
                                ".rela.ltext.hot.")) {
                relocation_group->section_name = ".rela.ltext";
            }
            else if (!strcmp(relocation_group->section_name,
                             ".rel.text.unlikely.")
                     || !strcmp(relocation_group->section_name,
                                ".rel.text.hot.")) {
                relocation_group->section_name = ".rel.text";
            }
            else if (!strcmp(relocation_group->section_name,
                             ".rel.ltext.unlikely.")
                     || !strcmp(relocation_group->section_name,
                                ".rel.ltext.hot.")) {
                relocation_group->section_name = ".rel.ltext";
            }

            /*
             * Relocations in read-only sections are problematic,
             * especially for XIP on platforms which don't have
             * copy-on-write mappings.
             */
            if (obj_data->comp_ctx->is_indirect_mode
                && is_readonly_section(relocation_group->section_name)) {
                LOG_WARNING("%" PRIu32
                            " text relocations in %s section for indirect mode",
                            relocation_group->relocation_count,
                            relocation_group->section_name);
            }

            relocation_group++;
        }
        LLVMMoveToNextSection(sec_itr);
    }
    LLVMDisposeSectionIterator(sec_itr);

    return true;
}

static void
destroy_relocation_groups(AOTRelocationGroup *relocation_groups,
                          uint32 relocation_group_count)
{
    uint32 i, j;
    AOTRelocationGroup *relocation_group = relocation_groups;

    for (i = 0; i < relocation_group_count; i++, relocation_group++) {
        if (relocation_group->relocations) {
            for (j = 0; j < relocation_group->relocation_count; j++) {
                if (relocation_group->relocations[j].is_symbol_name_allocated)
                    wasm_runtime_free(
                        relocation_group->relocations[j].symbol_name);
            }
            wasm_runtime_free(relocation_group->relocations);
        }
        if (relocation_group->is_section_name_allocated)
            wasm_runtime_free(relocation_group->section_name);
    }
    wasm_runtime_free(relocation_groups);
}

static void
destroy_relocation_symbol_list(AOTSymbolList *symbol_list)
{
    AOTSymbolNode *elem;

    elem = symbol_list->head;
    while (elem) {
        AOTSymbolNode *next = elem->next;
        wasm_runtime_free(elem);
        elem = next;
    }
}

void
aot_obj_data_destroy(AOTObjectData *obj_data)
{
    if (obj_data->binary)
        LLVMDisposeBinary(obj_data->binary);
    if (obj_data->mem_buf)
        LLVMDisposeMemoryBuffer(obj_data->mem_buf);
    if (obj_data->funcs)
        wasm_runtime_free(obj_data->funcs);
    if (obj_data->data_sections) {
        uint32 i;
        for (i = 0; i < obj_data->data_sections_count; i++) {
            if (obj_data->data_sections[i].name
                && obj_data->data_sections[i].is_name_allocated) {
                wasm_runtime_free(obj_data->data_sections[i].name);
            }
            if (obj_data->data_sections[i].data
                && obj_data->data_sections[i].is_data_allocated) {
                wasm_runtime_free(obj_data->data_sections[i].data);
            }
        }
        wasm_runtime_free(obj_data->data_sections);
    }
    if (obj_data->relocation_groups)
        destroy_relocation_groups(obj_data->relocation_groups,
                                  obj_data->relocation_group_count);
    if (obj_data->symbol_list.len)
        destroy_relocation_symbol_list(&obj_data->symbol_list);
    if (obj_data->stack_sizes)
        wasm_runtime_free(obj_data->stack_sizes);
    wasm_runtime_free(obj_data);
}

AOTObjectData *
aot_obj_data_create(AOTCompContext *comp_ctx)
{
    char *err = NULL;
    AOTObjectData *obj_data;
    LLVMTargetRef target = LLVMGetTargetMachineTarget(comp_ctx->target_machine);

    bh_print_time("Begin to emit object file to buffer");

    if (!(obj_data = wasm_runtime_malloc(sizeof(AOTObjectData)))) {
        aot_set_last_error("allocate memory failed.");
        return false;
    }
    memset(obj_data, 0, sizeof(AOTObjectData));
    obj_data->comp_ctx = comp_ctx;

    bh_print_time("Begin to emit object file");
    if (comp_ctx->external_llc_compiler || comp_ctx->external_asm_compiler) {
        /* Generate a temp file name */
        int ret;
        char obj_file_name[64];

        if (!aot_generate_tempfile_name("wamrc-obj", "o", obj_file_name,
                                        sizeof(obj_file_name))) {
            goto fail;
        }

        if (!aot_emit_object_file(comp_ctx, obj_file_name)) {
            goto fail;
        }

        /* create memory buffer from object file */
        ret = LLVMCreateMemoryBufferWithContentsOfFile(
            obj_file_name, &obj_data->mem_buf, &err);
        /* remove temp object file */
        unlink(obj_file_name);

        if (ret != 0) {
            if (err) {
                LLVMDisposeMessage(err);
                err = NULL;
            }
            aot_set_last_error("create mem buffer with file failed.");
            goto fail;
        }
    }
    else if (!strncmp(LLVMGetTargetName(target), "arc", 3)) {
        /* Emit to assembly file instead for arc target
           as it cannot emit to object file */
        char file_name[] = "wasm-XXXXXX", buf[128];
        int ret;

        if (!bh_mkstemp(file_name, sizeof(file_name))) {
            aot_set_last_error("make temp file failed.");
            goto fail;
        }

        snprintf(buf, sizeof(buf), "%s%s", file_name, ".s");
        if (LLVMTargetMachineEmitToFile(comp_ctx->target_machine,
                                        comp_ctx->module, buf, LLVMAssemblyFile,
                                        &err)
            != 0) {
            if (err) {
                LLVMDisposeMessage(err);
                err = NULL;
            }
            aot_set_last_error("emit elf to object file failed.");
            goto fail;
        }

        /* call arc gcc to compile assembly file to object file */
        /* TODO: get arc gcc from environment variable firstly
                 and check whether the toolchain exists actually */
        snprintf(buf, sizeof(buf), "%s%s%s%s%s%s",
                 "/opt/zephyr-sdk/arc-zephyr-elf/bin/arc-zephyr-elf-gcc ",
                 "-mcpu=arcem -o ", file_name, ".o -c ", file_name, ".s");
        /* TODO: use try..catch to handle possible exceptions */
        ret = bh_system(buf);
        /* remove temp assembly file */
        snprintf(buf, sizeof(buf), "%s%s", file_name, ".s");
        unlink(buf);

        if (ret != 0) {
            aot_set_last_error("failed to compile asm file to obj file "
                               "with arc gcc toolchain.");
            goto fail;
        }

        /* create memory buffer from object file */
        snprintf(buf, sizeof(buf), "%s%s", file_name, ".o");
        ret = LLVMCreateMemoryBufferWithContentsOfFile(buf, &obj_data->mem_buf,
                                                       &err);
        /* remove temp object file */
        snprintf(buf, sizeof(buf), "%s%s", file_name, ".o");
        unlink(buf);

        if (ret != 0) {
            if (err) {
                LLVMDisposeMessage(err);
                err = NULL;
            }
            aot_set_last_error("create mem buffer with file failed.");
            goto fail;
        }
    }
    else {
        if (LLVMTargetMachineEmitToMemoryBuffer(
                comp_ctx->target_machine, comp_ctx->module, LLVMObjectFile,
                &err, &obj_data->mem_buf)
            != 0) {
            if (err) {
                LLVMDisposeMessage(err);
                err = NULL;
            }
            aot_set_last_error("llvm emit to memory buffer failed.");
            goto fail;
        }
    }

    if (!(obj_data->binary = LLVMCreateBinary(obj_data->mem_buf, NULL, &err))) {
        if (err) {
            LLVMDisposeMessage(err);
            err = NULL;
        }
        aot_set_last_error("llvm create binary failed.");
        goto fail;
    }

    /* Create wasm feature flags form compile options */
    obj_data->target_info.feature_flags = 0;
    if (comp_ctx->enable_simd) {
        obj_data->target_info.feature_flags |= WASM_FEATURE_SIMD_128BIT;
    }
    if (comp_ctx->enable_bulk_memory) {
        obj_data->target_info.feature_flags |= WASM_FEATURE_BULK_MEMORY;
    }
    if (comp_ctx->enable_thread_mgr) {
        obj_data->target_info.feature_flags |= WASM_FEATURE_MULTI_THREAD;
    }
    if (comp_ctx->enable_ref_types) {
        obj_data->target_info.feature_flags |= WASM_FEATURE_REF_TYPES;
    }
    if (comp_ctx->enable_gc) {
        obj_data->target_info.feature_flags |= WASM_FEATURE_GARBAGE_COLLECTION;
    }
    if (comp_ctx->aux_stack_frame_type == AOT_STACK_FRAME_TYPE_TINY) {
        obj_data->target_info.feature_flags |= WASM_FEATURE_TINY_STACK_FRAME;
    }
    if (comp_ctx->call_stack_features.frame_per_function) {
        obj_data->target_info.feature_flags |= WASM_FEATURE_FRAME_PER_FUNCTION;
    }
    if (!comp_ctx->call_stack_features.func_idx) {
        obj_data->target_info.feature_flags |= WASM_FEATURE_FRAME_NO_FUNC_IDX;
    }

    bh_print_time("Begin to resolve object file info");

    /* resolve target info/text/relocations/functions */
    if (!aot_resolve_target_info(comp_ctx, obj_data)
        || !aot_resolve_text(obj_data) || !aot_resolve_literal(obj_data)
        || !aot_resolve_object_data_sections(obj_data)
        || !aot_resolve_functions(comp_ctx, obj_data)
        || !aot_resolve_object_relocation_groups(obj_data))
        goto fail;

    return obj_data;

fail:
    aot_obj_data_destroy(obj_data);
    return NULL;
}

uint8 *
aot_emit_aot_file_buf(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                      uint32 *p_aot_file_size)
{
    AOTObjectData *obj_data = aot_obj_data_create(comp_ctx);
    uint8 *aot_file_buf;
    uint32 aot_file_size;

    if (!obj_data)
        return NULL;

    aot_file_size = aot_get_aot_file_size(comp_ctx, comp_data, obj_data);
    if (aot_file_size == 0) {
        aot_set_last_error("get aot file size failed");
        goto fail1;
    }

    if (!(aot_file_buf = wasm_runtime_malloc(aot_file_size))) {
        aot_set_last_error("allocate memory failed.");
        goto fail1;
    }

    memset(aot_file_buf, 0, aot_file_size);
    if (!aot_emit_aot_file_buf_ex(comp_ctx, comp_data, obj_data, aot_file_buf,
                                  aot_file_size))
        goto fail2;

    *p_aot_file_size = aot_file_size;

    aot_obj_data_destroy(obj_data);
    return aot_file_buf;

fail2:
    wasm_runtime_free(aot_file_buf);

fail1:
    aot_obj_data_destroy(obj_data);
    return NULL;
}

bool
aot_emit_aot_file_buf_ex(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                         AOTObjectData *obj_data, uint8 *buf,
                         uint32 aot_file_size)
{
    uint8 *buf_end = buf + aot_file_size;
    uint32 offset = 0;

    if (!aot_emit_file_header(buf, buf_end, &offset, comp_data, obj_data)
        || !aot_emit_target_info_section(buf, buf_end, &offset, comp_data,
                                         obj_data)
        || !aot_emit_init_data_section(buf, buf_end, &offset, comp_ctx,
                                       comp_data, obj_data)
        || !aot_emit_text_section(buf, buf_end, &offset, comp_data, obj_data)
        || !aot_emit_func_section(buf, buf_end, &offset, comp_ctx, comp_data,
                                  obj_data)
        || !aot_emit_export_section(buf, buf_end, &offset, comp_ctx, comp_data,
                                    obj_data)
        || !aot_emit_relocation_section(buf, buf_end, &offset, comp_ctx,
                                        comp_data, obj_data)
        || !aot_emit_native_symbol(buf, buf_end, &offset, comp_ctx)
        || !aot_emit_custom_sections(buf, buf_end, &offset, comp_data, comp_ctx)
#if WASM_ENABLE_STRINGREF != 0
        || !aot_emit_string_literal_section(buf, buf_end, &offset, comp_data,
                                            comp_ctx)
#endif
    )
        return false;

#if 0
    dump_buf(buf, offset, "sections");
#endif

    if (offset != aot_file_size) {
        aot_set_last_error("emit aot file failed.");
        return false;
    }

    return true;
}

bool
aot_emit_aot_file(AOTCompContext *comp_ctx, AOTCompData *comp_data,
                  const char *file_name)
{
    uint8 *aot_file_buf;
    uint32 aot_file_size;
    bool ret = false;
    FILE *file;

    bh_print_time("Begin to emit AOT file");

    if (!(aot_file_buf =
              aot_emit_aot_file_buf(comp_ctx, comp_data, &aot_file_size))) {
        return false;
    }

    /* write buffer to file */
    if (!(file = fopen(file_name, "wb"))) {
        aot_set_last_error("open or create aot file failed.");
        goto fail1;
    }
    if (!fwrite(aot_file_buf, aot_file_size, 1, file)) {
        aot_set_last_error("write to aot file failed.");
        goto fail2;
    }

    ret = true;

fail2:
    fclose(file);

fail1:
    wasm_runtime_free(aot_file_buf);

    return ret;
}
