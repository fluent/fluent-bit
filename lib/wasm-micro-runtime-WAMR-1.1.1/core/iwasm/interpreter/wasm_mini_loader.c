/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_loader.h"
#include "bh_common.h"
#include "bh_log.h"
#include "wasm.h"
#include "wasm_opcode.h"
#include "wasm_runtime.h"
#include "../common/wasm_native.h"
#include "../common/wasm_memory.h"
#if WASM_ENABLE_FAST_JIT != 0
#include "../fast-jit/jit_compiler.h"
#include "../fast-jit/jit_codecache.h"
#endif

/* Read a value of given type from the address pointed to by the given
   pointer and increase the pointer to the position just after the
   value being read.  */
#define TEMPLATE_READ_VALUE(Type, p) \
    (p += sizeof(Type), *(Type *)(p - sizeof(Type)))

static void
set_error_buf(char *error_buf, uint32 error_buf_size, const char *string)
{
    if (error_buf != NULL)
        snprintf(error_buf, error_buf_size, "WASM module load failed: %s",
                 string);
}

#define CHECK_BUF(buf, buf_end, length)                            \
    do {                                                           \
        bh_assert(buf + length >= buf && buf + length <= buf_end); \
    } while (0)

#define CHECK_BUF1(buf, buf_end, length)                           \
    do {                                                           \
        bh_assert(buf + length >= buf && buf + length <= buf_end); \
    } while (0)

#define skip_leb(p) while (*p++ & 0x80)
#define skip_leb_int64(p, p_end) skip_leb(p)
#define skip_leb_uint32(p, p_end) skip_leb(p)
#define skip_leb_int32(p, p_end) skip_leb(p)

static bool
is_32bit_type(uint8 type)
{
    if (type == VALUE_TYPE_I32 || type == VALUE_TYPE_F32
#if WASM_ENABLE_REF_TYPES != 0
        || type == VALUE_TYPE_FUNCREF || type == VALUE_TYPE_EXTERNREF
#endif
    )
        return true;
    return false;
}

static bool
is_64bit_type(uint8 type)
{
    if (type == VALUE_TYPE_I64 || type == VALUE_TYPE_F64)
        return true;
    return false;
}

static bool
is_value_type(uint8 type)
{
    if (type == VALUE_TYPE_I32 || type == VALUE_TYPE_I64
        || type == VALUE_TYPE_F32 || type == VALUE_TYPE_F64
#if WASM_ENABLE_REF_TYPES != 0
        || type == VALUE_TYPE_FUNCREF || type == VALUE_TYPE_EXTERNREF
#endif
    )
        return true;
    return false;
}

static bool
is_byte_a_type(uint8 type)
{
    return is_value_type(type) || (type == VALUE_TYPE_VOID);
}

static void
read_leb(uint8 **p_buf, const uint8 *buf_end, uint32 maxbits, bool sign,
         uint64 *p_result, char *error_buf, uint32 error_buf_size)
{
    const uint8 *buf = *p_buf;
    uint64 result = 0;
    uint32 shift = 0;
    uint32 offset = 0, bcnt = 0;
    uint64 byte;

    while (true) {
        bh_assert(bcnt + 1 <= (maxbits + 6) / 7);
        CHECK_BUF(buf, buf_end, offset + 1);
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
        bh_assert(!(((uint8)byte) & 0xf0));
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
            bh_assert(!((sign_bit_set && top_bits != 0x70)
                        || (!sign_bit_set && top_bits != 0)));
            (void)top_bits;
            (void)sign_bit_set;
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

            bh_assert(!((sign_bit_set && top_bits != 0x7e)
                        || (!sign_bit_set && top_bits != 0)));
            (void)top_bits;
            (void)sign_bit_set;
        }
    }

    *p_buf += offset;
    *p_result = result;
}

#define read_uint8(p) TEMPLATE_READ_VALUE(uint8, p)
#define read_uint32(p) TEMPLATE_READ_VALUE(uint32, p)
#define read_bool(p) TEMPLATE_READ_VALUE(bool, p)

#define read_leb_int64(p, p_end, res)                              \
    do {                                                           \
        uint64 res64;                                              \
        read_leb((uint8 **)&p, p_end, 64, true, &res64, error_buf, \
                 error_buf_size);                                  \
        res = (int64)res64;                                        \
    } while (0)

#define read_leb_uint32(p, p_end, res)                              \
    do {                                                            \
        uint64 res64;                                               \
        read_leb((uint8 **)&p, p_end, 32, false, &res64, error_buf, \
                 error_buf_size);                                   \
        res = (uint32)res64;                                        \
    } while (0)

#define read_leb_int32(p, p_end, res)                              \
    do {                                                           \
        uint64 res64;                                              \
        read_leb((uint8 **)&p, p_end, 32, true, &res64, error_buf, \
                 error_buf_size);                                  \
        res = (int32)res64;                                        \
    } while (0)

static void *
loader_malloc(uint64 size, char *error_buf, uint32 error_buf_size)
{
    void *mem;

    if (size >= UINT32_MAX || !(mem = wasm_runtime_malloc((uint32)size))) {
        set_error_buf(error_buf, error_buf_size, "allocate memory failed");
        return NULL;
    }

    memset(mem, 0, (uint32)size);
    return mem;
}

static char *
const_str_list_insert(const uint8 *str, uint32 len, WASMModule *module,
                      bool is_load_from_file_buf, char *error_buf,
                      uint32 error_buf_size)
{
    StringNode *node, *node_next;

    if (len == 0) {
        return "";
    }
    else if (is_load_from_file_buf) {
        /* As the file buffer can be referred to after loading, we use
           the previous byte of leb encoded size to adjust the string:
           move string 1 byte backward and then append '\0' */
        char *c_str = (char *)str - 1;
        bh_memmove_s(c_str, len + 1, c_str + 1, len);
        c_str[len] = '\0';
        return c_str;
    }

    /* Search const str list */
    node = module->const_str_list;
    while (node) {
        node_next = node->next;
        if (strlen(node->str) == len && !memcmp(node->str, str, len))
            break;
        node = node_next;
    }

    if (node) {
        LOG_DEBUG("reuse %s", node->str);
        return node->str;
    }

    if (!(node = loader_malloc(sizeof(StringNode) + len + 1, error_buf,
                               error_buf_size))) {
        return NULL;
    }

    node->str = ((char *)node) + sizeof(StringNode);
    bh_memcpy_s(node->str, len + 1, str, len);
    node->str[len] = '\0';

    if (!module->const_str_list) {
        /* set as head */
        module->const_str_list = node;
        node->next = NULL;
    }
    else {
        /* insert it */
        node->next = module->const_str_list;
        module->const_str_list = node;
    }

    return node->str;
}

static void
destroy_wasm_type(WASMType *type)
{
    if (type->ref_count > 1) {
        /* The type is referenced by other types
           of current wasm module */
        type->ref_count--;
        return;
    }

    wasm_runtime_free(type);
}

static bool
load_init_expr(const uint8 **p_buf, const uint8 *buf_end,
               InitializerExpression *init_expr, uint8 type, char *error_buf,
               uint32 error_buf_size)
{
    const uint8 *p = *p_buf, *p_end = buf_end;
    uint8 flag, end_byte, *p_float;
    uint32 i;

    CHECK_BUF(p, p_end, 1);
    init_expr->init_expr_type = read_uint8(p);
    flag = init_expr->init_expr_type;

    switch (flag) {
        /* i32.const */
        case INIT_EXPR_TYPE_I32_CONST:
            bh_assert(type == VALUE_TYPE_I32);
            read_leb_int32(p, p_end, init_expr->u.i32);
            break;
        /* i64.const */
        case INIT_EXPR_TYPE_I64_CONST:
            bh_assert(type == VALUE_TYPE_I64);
            read_leb_int64(p, p_end, init_expr->u.i64);
            break;
        /* f32.const */
        case INIT_EXPR_TYPE_F32_CONST:
            bh_assert(type == VALUE_TYPE_F32);
            CHECK_BUF(p, p_end, 4);
            p_float = (uint8 *)&init_expr->u.f32;
            for (i = 0; i < sizeof(float32); i++)
                *p_float++ = *p++;
            break;
        /* f64.const */
        case INIT_EXPR_TYPE_F64_CONST:
            bh_assert(type == VALUE_TYPE_F64);
            CHECK_BUF(p, p_end, 8);
            p_float = (uint8 *)&init_expr->u.f64;
            for (i = 0; i < sizeof(float64); i++)
                *p_float++ = *p++;
            break;
#if WASM_ENABLE_REF_TYPES != 0
        case INIT_EXPR_TYPE_FUNCREF_CONST:
        {
            bh_assert(type == VALUE_TYPE_FUNCREF);
            read_leb_uint32(p, p_end, init_expr->u.ref_index);
            break;
        }
        case INIT_EXPR_TYPE_REFNULL_CONST:
        {
            uint8 reftype;

            CHECK_BUF(p, p_end, 1);
            reftype = read_uint8(p);

            bh_assert(type == reftype);

            init_expr->u.ref_index = NULL_REF;
            (void)reftype;
            break;
        }
#endif /* WASM_ENABLE_REF_TYPES != 0 */
        /* get_global */
        case INIT_EXPR_TYPE_GET_GLOBAL:
            read_leb_uint32(p, p_end, init_expr->u.global_index);
            break;
        default:
            bh_assert(0);
            break;
    }
    CHECK_BUF(p, p_end, 1);
    end_byte = read_uint8(p);
    bh_assert(end_byte == 0x0b);
    *p_buf = p;

    (void)end_byte;
    return true;
}

static bool
load_type_section(const uint8 *buf, const uint8 *buf_end, WASMModule *module,
                  char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end, *p_org;
    uint32 type_count, param_count, result_count, i, j;
    uint32 param_cell_num, ret_cell_num;
    uint64 total_size;
    uint8 flag;
    WASMType *type;

    read_leb_uint32(p, p_end, type_count);

    if (type_count) {
        module->type_count = type_count;
        total_size = sizeof(WASMType *) * (uint64)type_count;
        if (!(module->types =
                  loader_malloc(total_size, error_buf, error_buf_size))) {
            return false;
        }

        for (i = 0; i < type_count; i++) {
            CHECK_BUF(p, p_end, 1);
            flag = read_uint8(p);
            bh_assert(flag == 0x60);

            read_leb_uint32(p, p_end, param_count);

            /* Resolve param count and result count firstly */
            p_org = p;
            CHECK_BUF(p, p_end, param_count);
            p += param_count;
            read_leb_uint32(p, p_end, result_count);
            CHECK_BUF(p, p_end, result_count);
            p = p_org;

            bh_assert(param_count <= UINT16_MAX && result_count <= UINT16_MAX);

            total_size = offsetof(WASMType, types)
                         + sizeof(uint8) * (uint64)(param_count + result_count);
            if (!(type = module->types[i] =
                      loader_malloc(total_size, error_buf, error_buf_size))) {
                return false;
            }

            /* Resolve param types and result types */
            type->ref_count = 1;
            type->param_count = (uint16)param_count;
            type->result_count = (uint16)result_count;
            for (j = 0; j < param_count; j++) {
                CHECK_BUF(p, p_end, 1);
                type->types[j] = read_uint8(p);
            }
            read_leb_uint32(p, p_end, result_count);
            for (j = 0; j < result_count; j++) {
                CHECK_BUF(p, p_end, 1);
                type->types[param_count + j] = read_uint8(p);
            }
            for (j = 0; j < param_count + result_count; j++) {
                bh_assert(is_value_type(type->types[j]));
            }

            param_cell_num = wasm_get_cell_num(type->types, param_count);
            ret_cell_num =
                wasm_get_cell_num(type->types + param_count, result_count);
            bh_assert(param_cell_num <= UINT16_MAX
                      && ret_cell_num <= UINT16_MAX);
            type->param_cell_num = (uint16)param_cell_num;
            type->ret_cell_num = (uint16)ret_cell_num;

            /* If there is already a same type created, use it instead */
            for (j = 0; j < i; ++j) {
                if (wasm_type_equal(type, module->types[j])) {
                    bh_assert(module->types[j]->ref_count != UINT16_MAX);
                    destroy_wasm_type(type);
                    module->types[i] = module->types[j];
                    module->types[j]->ref_count++;
                    break;
                }
            }
        }
    }

    bh_assert(p == p_end);
    LOG_VERBOSE("Load type section success.\n");
    (void)flag;
    return true;
}

static void
adjust_table_max_size(uint32 init_size, uint32 max_size_flag, uint32 *max_size)
{
    uint32 default_max_size =
        init_size * 2 > TABLE_MAX_SIZE ? init_size * 2 : TABLE_MAX_SIZE;

    if (max_size_flag) {
        /* module defines the table limitation */
        bh_assert(init_size <= *max_size);

        if (init_size < *max_size) {
            *max_size =
                *max_size < default_max_size ? *max_size : default_max_size;
        }
    }
    else {
        /* partial defined table limitation, gives a default value */
        *max_size = default_max_size;
    }
}

static bool
load_function_import(const uint8 **p_buf, const uint8 *buf_end,
                     const WASMModule *parent_module,
                     const char *sub_module_name, const char *function_name,
                     WASMFunctionImport *function, char *error_buf,
                     uint32 error_buf_size)
{
    const uint8 *p = *p_buf, *p_end = buf_end;
    uint32 declare_type_index = 0;
    WASMType *declare_func_type = NULL;
    WASMFunction *linked_func = NULL;
    const char *linked_signature = NULL;
    void *linked_attachment = NULL;
    bool linked_call_conv_raw = false;

    read_leb_uint32(p, p_end, declare_type_index);
    *p_buf = p;

    bh_assert(declare_type_index < parent_module->type_count);

    declare_func_type = parent_module->types[declare_type_index];

    /* check built-in modules */
    linked_func = wasm_native_resolve_symbol(
        sub_module_name, function_name, declare_func_type, &linked_signature,
        &linked_attachment, &linked_call_conv_raw);

    function->module_name = (char *)sub_module_name;
    function->field_name = (char *)function_name;
    function->func_type = declare_func_type;
    function->func_ptr_linked = linked_func;
    function->signature = linked_signature;
    function->attachment = linked_attachment;
    function->call_conv_raw = linked_call_conv_raw;
    return true;
}

static bool
load_table_import(const uint8 **p_buf, const uint8 *buf_end,
                  WASMModule *parent_module, const char *sub_module_name,
                  const char *table_name, WASMTableImport *table,
                  char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = *p_buf, *p_end = buf_end;
    uint32 declare_elem_type = 0, declare_max_size_flag = 0,
           declare_init_size = 0, declare_max_size = 0;

    CHECK_BUF(p, p_end, 1);
    /* 0x70 or 0x6F */
    declare_elem_type = read_uint8(p);
    bh_assert(VALUE_TYPE_FUNCREF == declare_elem_type
#if WASM_ENABLE_REF_TYPES != 0
              || VALUE_TYPE_EXTERNREF == declare_elem_type
#endif
    );

    read_leb_uint32(p, p_end, declare_max_size_flag);
    read_leb_uint32(p, p_end, declare_init_size);
    if (declare_max_size_flag & 1) {
        read_leb_uint32(p, p_end, declare_max_size);
        bh_assert(table->init_size <= table->max_size);
    }

    adjust_table_max_size(declare_init_size, declare_max_size_flag,
                          &declare_max_size);
    *p_buf = p;

    bh_assert(
        !((declare_max_size_flag & 1) && declare_init_size > declare_max_size));

    /* now we believe all declaration are ok */
    table->elem_type = declare_elem_type;
    table->init_size = declare_init_size;
    table->flags = declare_max_size_flag;
    table->max_size = declare_max_size;
    return true;
}

static bool
load_memory_import(const uint8 **p_buf, const uint8 *buf_end,
                   WASMModule *parent_module, const char *sub_module_name,
                   const char *memory_name, WASMMemoryImport *memory,
                   char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = *p_buf, *p_end = buf_end;
#if WASM_ENABLE_APP_FRAMEWORK != 0
    uint32 pool_size = wasm_runtime_memory_pool_size();
    uint32 max_page_count = pool_size * APP_MEMORY_MAX_GLOBAL_HEAP_PERCENT
                            / DEFAULT_NUM_BYTES_PER_PAGE;
#else
    uint32 max_page_count = DEFAULT_MAX_PAGES;
#endif /* WASM_ENABLE_APP_FRAMEWORK */
    uint32 declare_max_page_count_flag = 0;
    uint32 declare_init_page_count = 0;
    uint32 declare_max_page_count = 0;

    read_leb_uint32(p, p_end, declare_max_page_count_flag);
    read_leb_uint32(p, p_end, declare_init_page_count);
    bh_assert(declare_init_page_count <= 65536);

    if (declare_max_page_count_flag & 1) {
        read_leb_uint32(p, p_end, declare_max_page_count);
        bh_assert(declare_init_page_count <= declare_max_page_count);
        bh_assert(declare_max_page_count <= 65536);
        if (declare_max_page_count > max_page_count) {
            declare_max_page_count = max_page_count;
        }
    }
    else {
        /* Limit the maximum memory size to max_page_count */
        declare_max_page_count = max_page_count;
    }

    /* now we believe all declaration are ok */
    memory->flags = declare_max_page_count_flag;
    memory->init_page_count = declare_init_page_count;
    memory->max_page_count = declare_max_page_count;
    memory->num_bytes_per_page = DEFAULT_NUM_BYTES_PER_PAGE;

    *p_buf = p;
    return true;
}

static bool
load_global_import(const uint8 **p_buf, const uint8 *buf_end,
                   const WASMModule *parent_module, char *sub_module_name,
                   char *global_name, WASMGlobalImport *global, char *error_buf,
                   uint32 error_buf_size)
{
    const uint8 *p = *p_buf, *p_end = buf_end;
    uint8 declare_type = 0;
    uint8 declare_mutable = 0;
    bool is_mutable = false;
    bool ret = false;

    CHECK_BUF(p, p_end, 2);
    declare_type = read_uint8(p);
    declare_mutable = read_uint8(p);
    *p_buf = p;

    bh_assert(declare_mutable < 2);

    is_mutable = declare_mutable & 1 ? true : false;

#if WASM_ENABLE_LIBC_BUILTIN != 0
    /* check built-in modules */
    ret = wasm_native_lookup_libc_builtin_global(sub_module_name, global_name,
                                                 global);
    if (ret) {
        bh_assert(global->type == declare_type
                  && global->is_mutable != declare_mutable);
    }
#endif /* WASM_ENABLE_LIBC_BUILTIN */

    global->is_linked = ret;
    global->module_name = sub_module_name;
    global->field_name = global_name;
    global->type = declare_type;
    global->is_mutable = is_mutable;
    (void)p_end;
    return true;
}

static bool
load_table(const uint8 **p_buf, const uint8 *buf_end, WASMTable *table,
           char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = *p_buf, *p_end = buf_end, *p_org;

    CHECK_BUF(p, p_end, 1);
    /* 0x70 or 0x6F */
    table->elem_type = read_uint8(p);
    bh_assert((VALUE_TYPE_FUNCREF == table->elem_type)
#if WASM_ENABLE_REF_TYPES != 0
              || VALUE_TYPE_EXTERNREF == table->elem_type
#endif
    );

    p_org = p;
    read_leb_uint32(p, p_end, table->flags);
    bh_assert(p - p_org <= 1);
    bh_assert(table->flags <= 1);
    (void)p_org;

    read_leb_uint32(p, p_end, table->init_size);
    if (table->flags == 1) {
        read_leb_uint32(p, p_end, table->max_size);
        bh_assert(table->init_size <= table->max_size);
    }

    adjust_table_max_size(table->init_size, table->flags, &table->max_size);

    *p_buf = p;
    return true;
}

static bool
load_memory(const uint8 **p_buf, const uint8 *buf_end, WASMMemory *memory,
            char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = *p_buf, *p_end = buf_end, *p_org;
#if WASM_ENABLE_APP_FRAMEWORK != 0
    uint32 pool_size = wasm_runtime_memory_pool_size();
    uint32 max_page_count = pool_size * APP_MEMORY_MAX_GLOBAL_HEAP_PERCENT
                            / DEFAULT_NUM_BYTES_PER_PAGE;
#else
    uint32 max_page_count = DEFAULT_MAX_PAGES;
#endif

    p_org = p;
    read_leb_uint32(p, p_end, memory->flags);
    bh_assert(p - p_org <= 1);
    (void)p_org;
#if WASM_ENABLE_SHARED_MEMORY == 0
    bh_assert(memory->flags <= 1);
#else
    bh_assert(memory->flags <= 3 && memory->flags != 2);
#endif

    read_leb_uint32(p, p_end, memory->init_page_count);
    bh_assert(memory->init_page_count <= 65536);

    if (memory->flags & 1) {
        read_leb_uint32(p, p_end, memory->max_page_count);
        bh_assert(memory->init_page_count <= memory->max_page_count);
        bh_assert(memory->max_page_count <= 65536);
        if (memory->max_page_count > max_page_count)
            memory->max_page_count = max_page_count;
    }
    else {
        /* Limit the maximum memory size to max_page_count */
        memory->max_page_count = max_page_count;
    }

    memory->num_bytes_per_page = DEFAULT_NUM_BYTES_PER_PAGE;

    *p_buf = p;
    return true;
}

static bool
load_import_section(const uint8 *buf, const uint8 *buf_end, WASMModule *module,
                    bool is_load_from_file_buf, char *error_buf,
                    uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end, *p_old;
    uint32 import_count, name_len, type_index, i, u32, flags;
    uint64 total_size;
    WASMImport *import;
    WASMImport *import_functions = NULL, *import_tables = NULL;
    WASMImport *import_memories = NULL, *import_globals = NULL;
    char *sub_module_name, *field_name;
    uint8 u8, kind;

    read_leb_uint32(p, p_end, import_count);

    if (import_count) {
        module->import_count = import_count;
        total_size = sizeof(WASMImport) * (uint64)import_count;
        if (!(module->imports =
                  loader_malloc(total_size, error_buf, error_buf_size))) {
            return false;
        }

        p_old = p;

        /* Scan firstly to get import count of each type */
        for (i = 0; i < import_count; i++) {
            /* module name */
            read_leb_uint32(p, p_end, name_len);
            CHECK_BUF(p, p_end, name_len);
            p += name_len;

            /* field name */
            read_leb_uint32(p, p_end, name_len);
            CHECK_BUF(p, p_end, name_len);
            p += name_len;

            CHECK_BUF(p, p_end, 1);
            /* 0x00/0x01/0x02/0x03 */
            kind = read_uint8(p);

            switch (kind) {
                case IMPORT_KIND_FUNC: /* import function */
                    read_leb_uint32(p, p_end, type_index);
                    module->import_function_count++;
                    break;

                case IMPORT_KIND_TABLE: /* import table */
                    CHECK_BUF(p, p_end, 1);
                    /* 0x70 */
                    u8 = read_uint8(p);
                    read_leb_uint32(p, p_end, flags);
                    read_leb_uint32(p, p_end, u32);
                    if (flags & 1)
                        read_leb_uint32(p, p_end, u32);
                    module->import_table_count++;
#if WASM_ENABLE_REF_TYPES == 0
                    bh_assert(module->import_table_count <= 1);
#endif
                    break;

                case IMPORT_KIND_MEMORY: /* import memory */
                    read_leb_uint32(p, p_end, flags);
                    read_leb_uint32(p, p_end, u32);
                    if (flags & 1)
                        read_leb_uint32(p, p_end, u32);
                    module->import_memory_count++;
                    bh_assert(module->import_memory_count <= 1);
                    break;

                case IMPORT_KIND_GLOBAL: /* import global */
                    CHECK_BUF(p, p_end, 2);
                    p += 2;
                    module->import_global_count++;
                    break;

                default:
                    bh_assert(0);
                    break;
            }
        }

        if (module->import_function_count)
            import_functions = module->import_functions = module->imports;
        if (module->import_table_count)
            import_tables = module->import_tables =
                module->imports + module->import_function_count;
        if (module->import_memory_count)
            import_memories = module->import_memories =
                module->imports + module->import_function_count
                + module->import_table_count;
        if (module->import_global_count)
            import_globals = module->import_globals =
                module->imports + module->import_function_count
                + module->import_table_count + module->import_memory_count;

        p = p_old;

        /* Scan again to resolve the data */
        for (i = 0; i < import_count; i++) {
            WASMModule *sub_module = NULL;

            /* load module name */
            read_leb_uint32(p, p_end, name_len);
            CHECK_BUF(p, p_end, name_len);
            if (!(sub_module_name = const_str_list_insert(
                      p, name_len, module, is_load_from_file_buf, error_buf,
                      error_buf_size))) {
                return false;
            }
            p += name_len;

            /* load field name */
            read_leb_uint32(p, p_end, name_len);
            CHECK_BUF(p, p_end, name_len);
            if (!(field_name = const_str_list_insert(
                      p, name_len, module, is_load_from_file_buf, error_buf,
                      error_buf_size))) {
                return false;
            }
            p += name_len;

            CHECK_BUF(p, p_end, 1);
            /* 0x00/0x01/0x02/0x03 */
            kind = read_uint8(p);

            LOG_DEBUG("import #%d: (%s, %s), kind: %d", i, sub_module_name,
                      field_name, kind);
            switch (kind) {
                case IMPORT_KIND_FUNC: /* import function */
                    bh_assert(import_functions);
                    import = import_functions++;
                    if (!load_function_import(
                            &p, p_end, module, sub_module_name, field_name,
                            &import->u.function, error_buf, error_buf_size)) {
                        return false;
                    }
                    break;

                case IMPORT_KIND_TABLE: /* import table */
                    bh_assert(import_tables);
                    import = import_tables++;
                    if (!load_table_import(&p, p_end, module, sub_module_name,
                                           field_name, &import->u.table,
                                           error_buf, error_buf_size)) {
                        LOG_DEBUG("can not import such a table (%s,%s)",
                                  sub_module_name, field_name);
                        return false;
                    }
                    break;

                case IMPORT_KIND_MEMORY: /* import memory */
                    bh_assert(import_memories);
                    import = import_memories++;
                    if (!load_memory_import(&p, p_end, module, sub_module_name,
                                            field_name, &import->u.memory,
                                            error_buf, error_buf_size)) {
                        return false;
                    }
                    break;

                case IMPORT_KIND_GLOBAL: /* import global */
                    bh_assert(import_globals);
                    import = import_globals++;
                    if (!load_global_import(&p, p_end, module, sub_module_name,
                                            field_name, &import->u.global,
                                            error_buf, error_buf_size)) {
                        return false;
                    }
                    break;

                default:
                    bh_assert(0);
                    import = NULL;
                    break;
            }
            import->kind = kind;
            import->u.names.module_name = sub_module_name;
            import->u.names.field_name = field_name;
            (void)sub_module;
        }

#if WASM_ENABLE_LIBC_WASI != 0
        import = module->import_functions;
        for (i = 0; i < module->import_function_count; i++, import++) {
            if (!strcmp(import->u.names.module_name, "wasi_unstable")
                || !strcmp(import->u.names.module_name,
                           "wasi_snapshot_preview1")) {
                module->import_wasi_api = true;
                break;
            }
        }
#endif
    }

    bh_assert(p == p_end);

    LOG_VERBOSE("Load import section success.\n");
    (void)u8;
    (void)u32;
    (void)type_index;
    return true;
}

static bool
init_function_local_offsets(WASMFunction *func, char *error_buf,
                            uint32 error_buf_size)
{
    WASMType *param_type = func->func_type;
    uint32 param_count = param_type->param_count;
    uint8 *param_types = param_type->types;
    uint32 local_count = func->local_count;
    uint8 *local_types = func->local_types;
    uint32 i, local_offset = 0;
    uint64 total_size = sizeof(uint16) * ((uint64)param_count + local_count);

    if (total_size > 0
        && !(func->local_offsets =
                 loader_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    for (i = 0; i < param_count; i++) {
        func->local_offsets[i] = (uint16)local_offset;
        local_offset += wasm_value_type_cell_num(param_types[i]);
    }

    for (i = 0; i < local_count; i++) {
        func->local_offsets[param_count + i] = (uint16)local_offset;
        local_offset += wasm_value_type_cell_num(local_types[i]);
    }

    bh_assert(local_offset == func->param_cell_num + func->local_cell_num);
    return true;
}

static bool
load_function_section(const uint8 *buf, const uint8 *buf_end,
                      const uint8 *buf_code, const uint8 *buf_code_end,
                      WASMModule *module, char *error_buf,
                      uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    const uint8 *p_code = buf_code, *p_code_end, *p_code_save;
    uint32 func_count;
    uint64 total_size;
    uint32 code_count = 0, code_size, type_index, i, j, k, local_type_index;
    uint32 local_count, local_set_count, sub_local_count, local_cell_num;
    uint8 type;
    WASMFunction *func;

    read_leb_uint32(p, p_end, func_count);

    if (buf_code)
        read_leb_uint32(p_code, buf_code_end, code_count);

    bh_assert(func_count == code_count);

    if (func_count) {
        module->function_count = func_count;
        total_size = sizeof(WASMFunction *) * (uint64)func_count;
        if (!(module->functions =
                  loader_malloc(total_size, error_buf, error_buf_size))) {
            return false;
        }

        for (i = 0; i < func_count; i++) {
            /* Resolve function type */
            read_leb_uint32(p, p_end, type_index);
            bh_assert(type_index < module->type_count);

            read_leb_uint32(p_code, buf_code_end, code_size);
            bh_assert(code_size > 0 && p_code + code_size <= buf_code_end);

            /* Resolve local set count */
            p_code_end = p_code + code_size;
            local_count = 0;
            read_leb_uint32(p_code, buf_code_end, local_set_count);
            p_code_save = p_code;

            /* Calculate total local count */
            for (j = 0; j < local_set_count; j++) {
                read_leb_uint32(p_code, buf_code_end, sub_local_count);
                bh_assert(sub_local_count <= UINT32_MAX - local_count);

                CHECK_BUF(p_code, buf_code_end, 1);
                /* 0x7F/0x7E/0x7D/0x7C */
                type = read_uint8(p_code);
                local_count += sub_local_count;
            }

            /* Alloc memory, layout: function structure + local types */
            code_size = (uint32)(p_code_end - p_code);

            total_size = sizeof(WASMFunction) + (uint64)local_count;
            if (!(func = module->functions[i] =
                      loader_malloc(total_size, error_buf, error_buf_size))) {
                return false;
            }

            /* Set function type, local count, code size and code body */
            func->func_type = module->types[type_index];
            func->local_count = local_count;
            if (local_count > 0)
                func->local_types = (uint8 *)func + sizeof(WASMFunction);
            func->code_size = code_size;
            /*
             * we shall make a copy of code body [p_code, p_code + code_size]
             * when we are worrying about inappropriate releasing behaviour.
             * all code bodies are actually in a buffer which user allocates in
             * his embedding environment and we don't have power on them.
             * it will be like:
             * code_body_cp = malloc(code_size);
             * memcpy(code_body_cp, p_code, code_size);
             * func->code = code_body_cp;
             */
            func->code = (uint8 *)p_code;

            /* Load each local type */
            p_code = p_code_save;
            local_type_index = 0;
            for (j = 0; j < local_set_count; j++) {
                read_leb_uint32(p_code, buf_code_end, sub_local_count);
                /* Note: sub_local_count is allowed to be 0 */
                bh_assert(local_type_index <= UINT32_MAX - sub_local_count
                          && local_type_index + sub_local_count <= local_count);

                CHECK_BUF(p_code, buf_code_end, 1);
                /* 0x7F/0x7E/0x7D/0x7C */
                type = read_uint8(p_code);
                bh_assert(is_value_type(type));
                for (k = 0; k < sub_local_count; k++) {
                    func->local_types[local_type_index++] = type;
                }
            }

            func->param_cell_num = func->func_type->param_cell_num;
            func->ret_cell_num = func->func_type->ret_cell_num;
            local_cell_num =
                wasm_get_cell_num(func->local_types, func->local_count);
            bh_assert(local_cell_num <= UINT16_MAX);

            func->local_cell_num = (uint16)local_cell_num;

            if (!init_function_local_offsets(func, error_buf, error_buf_size))
                return false;

            p_code = p_code_end;
        }
    }

    bh_assert(p == p_end);
    LOG_VERBOSE("Load function section success.\n");
    (void)code_count;
    return true;
}

static bool
check_function_index(const WASMModule *module, uint32 function_index,
                     char *error_buf, uint32 error_buf_size)
{
    return (function_index
            < module->import_function_count + module->function_count);
}

static bool
load_table_section(const uint8 *buf, const uint8 *buf_end, WASMModule *module,
                   char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 table_count, i;
    uint64 total_size;
    WASMTable *table;

    read_leb_uint32(p, p_end, table_count);
#if WASM_ENABLE_REF_TYPES == 0
    bh_assert(module->import_table_count + table_count <= 1);
#endif

    if (table_count) {
        module->table_count = table_count;
        total_size = sizeof(WASMTable) * (uint64)table_count;
        if (!(module->tables =
                  loader_malloc(total_size, error_buf, error_buf_size))) {
            return false;
        }

        /* load each table */
        table = module->tables;
        for (i = 0; i < table_count; i++, table++)
            if (!load_table(&p, p_end, table, error_buf, error_buf_size))
                return false;
    }

    bh_assert(p == p_end);
    LOG_VERBOSE("Load table section success.\n");
    return true;
}

static bool
load_memory_section(const uint8 *buf, const uint8 *buf_end, WASMModule *module,
                    char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 memory_count, i;
    uint64 total_size;
    WASMMemory *memory;

    read_leb_uint32(p, p_end, memory_count);
    bh_assert(module->import_memory_count + memory_count <= 1);

    if (memory_count) {
        module->memory_count = memory_count;
        total_size = sizeof(WASMMemory) * (uint64)memory_count;
        if (!(module->memories =
                  loader_malloc(total_size, error_buf, error_buf_size))) {
            return false;
        }

        /* load each memory */
        memory = module->memories;
        for (i = 0; i < memory_count; i++, memory++)
            if (!load_memory(&p, p_end, memory, error_buf, error_buf_size))
                return false;
    }

    bh_assert(p == p_end);
    LOG_VERBOSE("Load memory section success.\n");
    return true;
}

static bool
load_global_section(const uint8 *buf, const uint8 *buf_end, WASMModule *module,
                    char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 global_count, i;
    uint64 total_size;
    WASMGlobal *global;
    uint8 mutable;

    read_leb_uint32(p, p_end, global_count);

    if (global_count) {
        module->global_count = global_count;
        total_size = sizeof(WASMGlobal) * (uint64)global_count;
        if (!(module->globals =
                  loader_malloc(total_size, error_buf, error_buf_size))) {
            return false;
        }

        global = module->globals;

        for (i = 0; i < global_count; i++, global++) {
            CHECK_BUF(p, p_end, 2);
            global->type = read_uint8(p);
            mutable = read_uint8(p);
            bh_assert(mutable < 2);
            global->is_mutable = mutable ? true : false;

            /* initialize expression */
            if (!load_init_expr(&p, p_end, &(global->init_expr), global->type,
                                error_buf, error_buf_size))
                return false;

            if (INIT_EXPR_TYPE_GET_GLOBAL == global->init_expr.init_expr_type) {
                /**
                 * Currently, constant expressions occurring as initializers
                 * of globals are further constrained in that contained
                 * global.get instructions are
                 * only allowed to refer to imported globals.
                 */
                uint32 target_global_index = global->init_expr.u.global_index;
                bh_assert(target_global_index < module->import_global_count);
                (void)target_global_index;
            }
            else if (INIT_EXPR_TYPE_FUNCREF_CONST
                     == global->init_expr.init_expr_type) {
                bh_assert(global->init_expr.u.ref_index
                          < module->import_function_count
                                + module->function_count);
            }
        }
    }

    bh_assert(p == p_end);
    LOG_VERBOSE("Load global section success.\n");
    return true;
}

static bool
load_export_section(const uint8 *buf, const uint8 *buf_end, WASMModule *module,
                    bool is_load_from_file_buf, char *error_buf,
                    uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 export_count, i, j, index;
    uint64 total_size;
    uint32 str_len;
    WASMExport *export;
    const char *name;

    read_leb_uint32(p, p_end, export_count);

    if (export_count) {
        module->export_count = export_count;
        total_size = sizeof(WASMExport) * (uint64)export_count;
        if (!(module->exports =
                  loader_malloc(total_size, error_buf, error_buf_size))) {
            return false;
        }

        export = module->exports;
        for (i = 0; i < export_count; i++, export ++) {
            read_leb_uint32(p, p_end, str_len);
            CHECK_BUF(p, p_end, str_len);

            for (j = 0; j < i; j++) {
                name = module->exports[j].name;
                bh_assert(!(strlen(name) == str_len
                            && memcmp(name, p, str_len) == 0));
            }

            if (!(export->name = const_str_list_insert(
                      p, str_len, module, is_load_from_file_buf, error_buf,
                      error_buf_size))) {
                return false;
            }

            p += str_len;
            CHECK_BUF(p, p_end, 1);
            export->kind = read_uint8(p);
            read_leb_uint32(p, p_end, index);
            export->index = index;

            switch (export->kind) {
                /* function index */
                case EXPORT_KIND_FUNC:
                    bh_assert(index < module->function_count
                                          + module->import_function_count);
                    break;
                /* table index */
                case EXPORT_KIND_TABLE:
                    bh_assert(index < module->table_count
                                          + module->import_table_count);
                    break;
                /* memory index */
                case EXPORT_KIND_MEMORY:
                    bh_assert(index < module->memory_count
                                          + module->import_memory_count);
                    break;
                /* global index */
                case EXPORT_KIND_GLOBAL:
                    bh_assert(index < module->global_count
                                          + module->import_global_count);
                    break;
                default:
                    bh_assert(0);
                    break;
            }
        }
    }

    bh_assert(p == p_end);
    LOG_VERBOSE("Load export section success.\n");
    (void)name;
    return true;
}

static bool
check_table_index(const WASMModule *module, uint32 table_index, char *error_buf,
                  uint32 error_buf_size)
{
#if WASM_ENABLE_REF_TYPES == 0
    if (table_index != 0) {
        return false;
    }
#endif

    if (table_index >= module->import_table_count + module->table_count) {
        return false;
    }
    return true;
}

static bool
load_table_index(const uint8 **p_buf, const uint8 *buf_end, WASMModule *module,
                 uint32 *p_table_index, char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = *p_buf, *p_end = buf_end;
    uint32 table_index;

    read_leb_uint32(p, p_end, table_index);
    if (!check_table_index(module, table_index, error_buf, error_buf_size)) {
        return false;
    }

    *p_table_index = table_index;
    *p_buf = p;
    return true;
}

#if WASM_ENABLE_REF_TYPES != 0
static bool
load_elem_type(const uint8 **p_buf, const uint8 *buf_end, uint32 *p_elem_type,
               bool elemkind_zero, char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = *p_buf, *p_end = buf_end;
    uint8 elem_type;

    CHECK_BUF(p, p_end, 1);
    elem_type = read_uint8(p);
    if ((elemkind_zero && elem_type != 0)
        || (!elemkind_zero && elem_type != VALUE_TYPE_FUNCREF
            && elem_type != VALUE_TYPE_EXTERNREF)) {
        set_error_buf(error_buf, error_buf_size, "invalid reference type");
        return false;
    }

    if (elemkind_zero)
        *p_elem_type = VALUE_TYPE_FUNCREF;
    else
        *p_elem_type = elem_type;
    *p_buf = p;

    (void)p_end;
    return true;
}
#endif /* WASM_ENABLE_REF_TYPES != 0*/

static bool
load_func_index_vec(const uint8 **p_buf, const uint8 *buf_end,
                    WASMModule *module, WASMTableSeg *table_segment,
                    bool use_init_expr, char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = *p_buf, *p_end = buf_end;
    uint32 function_count, function_index = 0, i;
    uint64 total_size;

    read_leb_uint32(p, p_end, function_count);
    table_segment->function_count = function_count;
    total_size = sizeof(uint32) * (uint64)function_count;
    if (total_size > 0
        && !(table_segment->func_indexes = (uint32 *)loader_malloc(
                 total_size, error_buf, error_buf_size))) {
        return false;
    }

    for (i = 0; i < function_count; i++) {
        InitializerExpression init_expr = { 0 };

#if WASM_ENABLE_REF_TYPES != 0
        if (!use_init_expr) {
            read_leb_uint32(p, p_end, function_index);
        }
        else {
            if (!load_init_expr(&p, p_end, &init_expr, table_segment->elem_type,
                                error_buf, error_buf_size))
                return false;

            function_index = init_expr.u.ref_index;
        }
#else
        read_leb_uint32(p, p_end, function_index);
#endif

        /* since we are using -1 to indicate ref.null */
        if (init_expr.init_expr_type != INIT_EXPR_TYPE_REFNULL_CONST
            && !check_function_index(module, function_index, error_buf,
                                     error_buf_size)) {
            return false;
        }
        table_segment->func_indexes[i] = function_index;
    }

    *p_buf = p;
    return true;
}

static bool
load_table_segment_section(const uint8 *buf, const uint8 *buf_end,
                           WASMModule *module, char *error_buf,
                           uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 table_segment_count, i, table_index, function_count;
    uint64 total_size;
    WASMTableSeg *table_segment;

    read_leb_uint32(p, p_end, table_segment_count);

    if (table_segment_count) {
        module->table_seg_count = table_segment_count;
        total_size = sizeof(WASMTableSeg) * (uint64)table_segment_count;
        if (!(module->table_segments =
                  loader_malloc(total_size, error_buf, error_buf_size))) {
            return false;
        }

        table_segment = module->table_segments;
        for (i = 0; i < table_segment_count; i++, table_segment++) {
            bh_assert(p < p_end);

#if WASM_ENABLE_REF_TYPES != 0
            read_leb_uint32(p, p_end, table_segment->mode);
            /* last three bits */
            table_segment->mode = table_segment->mode & 0x07;
            switch (table_segment->mode) {
                /* elemkind/elemtype + active */
                case 0:
                case 4:
                    table_segment->elem_type = VALUE_TYPE_FUNCREF;
                    table_segment->table_index = 0;

                    if (!check_table_index(module, table_segment->table_index,
                                           error_buf, error_buf_size))
                        return false;

                    if (!load_init_expr(&p, p_end, &table_segment->base_offset,
                                        VALUE_TYPE_I32, error_buf,
                                        error_buf_size))
                        return false;

                    if (!load_func_index_vec(&p, p_end, module, table_segment,
                                             table_segment->mode == 0 ? false
                                                                      : true,
                                             error_buf, error_buf_size))
                        return false;
                    break;
                /* elemkind + passive/declarative */
                case 1:
                case 3:
                    if (!load_elem_type(&p, p_end, &table_segment->elem_type,
                                        true, error_buf, error_buf_size))
                        return false;
                    if (!load_func_index_vec(&p, p_end, module, table_segment,
                                             false, error_buf, error_buf_size))
                        return false;
                    break;
                /* elemkind/elemtype + table_idx + active */
                case 2:
                case 6:
                    if (!load_table_index(&p, p_end, module,
                                          &table_segment->table_index,
                                          error_buf, error_buf_size))
                        return false;
                    if (!load_init_expr(&p, p_end, &table_segment->base_offset,
                                        VALUE_TYPE_I32, error_buf,
                                        error_buf_size))
                        return false;
                    if (!load_elem_type(&p, p_end, &table_segment->elem_type,
                                        table_segment->mode == 2 ? true : false,
                                        error_buf, error_buf_size))
                        return false;
                    if (!load_func_index_vec(&p, p_end, module, table_segment,
                                             table_segment->mode == 2 ? false
                                                                      : true,
                                             error_buf, error_buf_size))
                        return false;
                    break;
                case 5:
                case 7:
                    if (!load_elem_type(&p, p_end, &table_segment->elem_type,
                                        false, error_buf, error_buf_size))
                        return false;
                    if (!load_func_index_vec(&p, p_end, module, table_segment,
                                             true, error_buf, error_buf_size))
                        return false;
                    break;
                default:
                    return false;
            }
#else
            /*
             * like:      00  41 05 0b               04 00 01 00 01
             * for: (elem 0   (offset (i32.const 5)) $f1 $f2 $f1 $f2)
             */
            if (!load_table_index(&p, p_end, module,
                                  &table_segment->table_index, error_buf,
                                  error_buf_size))
                return false;
            if (!load_init_expr(&p, p_end, &table_segment->base_offset,
                                VALUE_TYPE_I32, error_buf, error_buf_size))
                return false;
            if (!load_func_index_vec(&p, p_end, module, table_segment, false,
                                     error_buf, error_buf_size))
                return false;
#endif /* WASM_ENABLE_REF_TYPES != 0 */
        }
    }

    (void)table_index;
    (void)function_count;
    bh_assert(p == p_end);
    LOG_VERBOSE("Load table segment section success.\n");
    return true;
}

static bool
load_data_segment_section(const uint8 *buf, const uint8 *buf_end,
                          WASMModule *module, char *error_buf,
                          uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 data_seg_count, i, mem_index, data_seg_len;
    uint64 total_size;
    WASMDataSeg *dataseg;
    InitializerExpression init_expr;
#if WASM_ENABLE_BULK_MEMORY != 0
    bool is_passive = false;
    uint32 mem_flag;
#endif

    read_leb_uint32(p, p_end, data_seg_count);

#if WASM_ENABLE_BULK_MEMORY != 0
    bh_assert(module->data_seg_count1 == 0
              || data_seg_count == module->data_seg_count1);
#endif

    if (data_seg_count) {
        module->data_seg_count = data_seg_count;
        total_size = sizeof(WASMDataSeg *) * (uint64)data_seg_count;
        if (!(module->data_segments =
                  loader_malloc(total_size, error_buf, error_buf_size))) {
            return false;
        }

        for (i = 0; i < data_seg_count; i++) {
            read_leb_uint32(p, p_end, mem_index);
#if WASM_ENABLE_BULK_MEMORY != 0
            is_passive = false;
            mem_flag = mem_index & 0x03;
            switch (mem_flag) {
                case 0x01:
                    is_passive = true;
                    break;
                case 0x00:
                    /* no memory index, treat index as 0 */
                    mem_index = 0;
                    goto check_mem_index;
                case 0x02:
                    /* read following memory index */
                    read_leb_uint32(p, p_end, mem_index);
                check_mem_index:
                    bh_assert(mem_index < module->import_memory_count
                                              + module->memory_count);
                    break;
                case 0x03:
                default:
                    bh_assert(0);
                    break;
            }
#else
            bh_assert(mem_index
                      < module->import_memory_count + module->memory_count);
#endif /* WASM_ENABLE_BULK_MEMORY */

#if WASM_ENABLE_BULK_MEMORY != 0
            if (!is_passive)
#endif
                if (!load_init_expr(&p, p_end, &init_expr, VALUE_TYPE_I32,
                                    error_buf, error_buf_size))
                    return false;

            read_leb_uint32(p, p_end, data_seg_len);

            if (!(dataseg = module->data_segments[i] = loader_malloc(
                      sizeof(WASMDataSeg), error_buf, error_buf_size))) {
                return false;
            }

#if WASM_ENABLE_BULK_MEMORY != 0
            dataseg->is_passive = is_passive;
            if (!is_passive)
#endif
            {
                bh_memcpy_s(&dataseg->base_offset,
                            sizeof(InitializerExpression), &init_expr,
                            sizeof(InitializerExpression));

                dataseg->memory_index = mem_index;
            }

            dataseg->data_length = data_seg_len;
            CHECK_BUF(p, p_end, data_seg_len);
            dataseg->data = (uint8 *)p;
            p += data_seg_len;
        }
    }

    bh_assert(p == p_end);
    LOG_VERBOSE("Load data segment section success.\n");
    return true;
}

#if WASM_ENABLE_BULK_MEMORY != 0
static bool
load_datacount_section(const uint8 *buf, const uint8 *buf_end,
                       WASMModule *module, char *error_buf,
                       uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 data_seg_count1 = 0;

    read_leb_uint32(p, p_end, data_seg_count1);
    module->data_seg_count1 = data_seg_count1;

    bh_assert(p == p_end);
    LOG_VERBOSE("Load datacount section success.\n");
    return true;
}
#endif

static bool
load_code_section(const uint8 *buf, const uint8 *buf_end, const uint8 *buf_func,
                  const uint8 *buf_func_end, WASMModule *module,
                  char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    const uint8 *p_func = buf_func;
    uint32 func_count = 0, code_count;

    /* code has been loaded in function section, so pass it here, just check
     * whether function and code section have inconsistent lengths */
    read_leb_uint32(p, p_end, code_count);

    if (buf_func)
        read_leb_uint32(p_func, buf_func_end, func_count);

    bh_assert(func_count == code_count);
    LOG_VERBOSE("Load code segment section success.\n");
    (void)code_count;
    (void)func_count;
    return true;
}

static bool
load_start_section(const uint8 *buf, const uint8 *buf_end, WASMModule *module,
                   char *error_buf, uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    WASMType *type;
    uint32 start_function;

    read_leb_uint32(p, p_end, start_function);

    bh_assert(start_function
              < module->function_count + module->import_function_count);

    if (start_function < module->import_function_count)
        type = module->import_functions[start_function].u.function.func_type;
    else
        type = module->functions[start_function - module->import_function_count]
                   ->func_type;

    bh_assert(type->param_count == 0 && type->result_count == 0);

    module->start_function = start_function;

    bh_assert(p == p_end);
    LOG_VERBOSE("Load start section success.\n");
    (void)type;
    return true;
}

#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
static bool
handle_name_section(const uint8 *buf, const uint8 *buf_end, WASMModule *module,
                    bool is_load_from_file_buf, char *error_buf,
                    uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 name_type, subsection_size;
    uint32 previous_name_type = 0;
    uint32 num_func_name;
    uint32 func_index;
    uint32 previous_func_index = ~0U;
    uint32 func_name_len;
    uint32 name_index;
    int i = 0;

    bh_assert(p < p_end);

    while (p < p_end) {
        read_leb_uint32(p, p_end, name_type);
        if (i != 0) {
            bh_assert(name_type > previous_name_type);
        }
        previous_name_type = name_type;
        read_leb_uint32(p, p_end, subsection_size);
        CHECK_BUF(p, p_end, subsection_size);
        switch (name_type) {
            case SUB_SECTION_TYPE_FUNC:
                if (subsection_size) {
                    read_leb_uint32(p, p_end, num_func_name);
                    for (name_index = 0; name_index < num_func_name;
                         name_index++) {
                        read_leb_uint32(p, p_end, func_index);
                        bh_assert(func_index > previous_func_index);
                        previous_func_index = func_index;
                        read_leb_uint32(p, p_end, func_name_len);
                        CHECK_BUF(p, p_end, func_name_len);
                        /* Skip the import functions */
                        if (func_index >= module->import_count) {
                            func_index -= module->import_count;
                            bh_assert(func_index < module->function_count);
                            if (!(module->functions[func_index]->field_name =
                                      const_str_list_insert(
                                          p, func_name_len, module,
                                          is_load_from_file_buf, error_buf,
                                          error_buf_size))) {
                                return false;
                            }
                        }
                        p += func_name_len;
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

    return true;
}
#endif

static bool
load_user_section(const uint8 *buf, const uint8 *buf_end, WASMModule *module,
                  bool is_load_from_file_buf, char *error_buf,
                  uint32 error_buf_size)
{
    const uint8 *p = buf, *p_end = buf_end;
    uint32 name_len;

    bh_assert(p < p_end);

    read_leb_uint32(p, p_end, name_len);

    bh_assert(name_len > 0 && p + name_len <= p_end);

#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
    if (memcmp(p, "name", 4) == 0) {
        p += name_len;
        handle_name_section(p, p_end, module, is_load_from_file_buf, error_buf,
                            error_buf_size);
    }
#endif
    LOG_VERBOSE("Load custom section success.\n");
    (void)name_len;
    return true;
}

#if WASM_ENABLE_REF_TYPES != 0
static bool
get_table_elem_type(const WASMModule *module, uint32 table_idx,
                    uint8 *p_elem_type, char *error_buf, uint32 error_buf_size)
{
    if (!check_table_index(module, table_idx, error_buf, error_buf_size)) {
        return false;
    }

    if (p_elem_type) {
        if (table_idx < module->import_table_count)
            *p_elem_type = module->import_tables[table_idx].u.table.elem_type;
        else
            *p_elem_type =
                module->tables[module->import_table_count + table_idx]
                    .elem_type;
    }
    return true;
}

static bool
get_table_seg_elem_type(const WASMModule *module, uint32 table_seg_idx,
                        uint8 *p_elem_type, char *error_buf,
                        uint32 error_buf_size)
{
    if (table_seg_idx >= module->table_seg_count) {
        return false;
    }

    if (p_elem_type) {
        *p_elem_type = module->table_segments[table_seg_idx].elem_type;
    }
    return true;
}
#endif

static bool
wasm_loader_prepare_bytecode(WASMModule *module, WASMFunction *func,
                             uint32 cur_func_idx, char *error_buf,
                             uint32 error_buf_size);

#if WASM_ENABLE_FAST_INTERP != 0 && WASM_ENABLE_LABELS_AS_VALUES != 0
void **
wasm_interp_get_handle_table();

static void **handle_table;
#endif

static bool
load_from_sections(WASMModule *module, WASMSection *sections,
                   bool is_load_from_file_buf, char *error_buf,
                   uint32 error_buf_size)
{
    WASMExport *export;
    WASMSection *section = sections;
    const uint8 *buf, *buf_end, *buf_code = NULL, *buf_code_end = NULL,
                                *buf_func = NULL, *buf_func_end = NULL;
    WASMGlobal *aux_data_end_global = NULL, *aux_heap_base_global = NULL;
    WASMGlobal *aux_stack_top_global = NULL, *global;
    uint32 aux_data_end = (uint32)-1, aux_heap_base = (uint32)-1;
    uint32 aux_stack_top = (uint32)-1, global_index, func_index, i;
    uint32 aux_data_end_global_index = (uint32)-1;
    uint32 aux_heap_base_global_index = (uint32)-1;
    WASMType *func_type;

    /* Find code and function sections if have */
    while (section) {
        if (section->section_type == SECTION_TYPE_CODE) {
            buf_code = section->section_body;
            buf_code_end = buf_code + section->section_body_size;
        }
        else if (section->section_type == SECTION_TYPE_FUNC) {
            buf_func = section->section_body;
            buf_func_end = buf_func + section->section_body_size;
        }
        section = section->next;
    }

    section = sections;
    while (section) {
        buf = section->section_body;
        buf_end = buf + section->section_body_size;
        LOG_DEBUG("load section, type: %d", section->section_type);
        switch (section->section_type) {
            case SECTION_TYPE_USER:
                /* unsupported user section, ignore it. */
                if (!load_user_section(buf, buf_end, module,
                                       is_load_from_file_buf, error_buf,
                                       error_buf_size))
                    return false;
                break;
            case SECTION_TYPE_TYPE:
                if (!load_type_section(buf, buf_end, module, error_buf,
                                       error_buf_size))
                    return false;
                break;
            case SECTION_TYPE_IMPORT:
                if (!load_import_section(buf, buf_end, module,
                                         is_load_from_file_buf, error_buf,
                                         error_buf_size))
                    return false;
                break;
            case SECTION_TYPE_FUNC:
                if (!load_function_section(buf, buf_end, buf_code, buf_code_end,
                                           module, error_buf, error_buf_size))
                    return false;
                break;
            case SECTION_TYPE_TABLE:
                if (!load_table_section(buf, buf_end, module, error_buf,
                                        error_buf_size))
                    return false;
                break;
            case SECTION_TYPE_MEMORY:
                if (!load_memory_section(buf, buf_end, module, error_buf,
                                         error_buf_size))
                    return false;
                break;
            case SECTION_TYPE_GLOBAL:
                if (!load_global_section(buf, buf_end, module, error_buf,
                                         error_buf_size))
                    return false;
                break;
            case SECTION_TYPE_EXPORT:
                if (!load_export_section(buf, buf_end, module,
                                         is_load_from_file_buf, error_buf,
                                         error_buf_size))
                    return false;
                break;
            case SECTION_TYPE_START:
                if (!load_start_section(buf, buf_end, module, error_buf,
                                        error_buf_size))
                    return false;
                break;
            case SECTION_TYPE_ELEM:
                if (!load_table_segment_section(buf, buf_end, module, error_buf,
                                                error_buf_size))
                    return false;
                break;
            case SECTION_TYPE_CODE:
                if (!load_code_section(buf, buf_end, buf_func, buf_func_end,
                                       module, error_buf, error_buf_size))
                    return false;
                break;
            case SECTION_TYPE_DATA:
                if (!load_data_segment_section(buf, buf_end, module, error_buf,
                                               error_buf_size))
                    return false;
                break;
#if WASM_ENABLE_BULK_MEMORY != 0
            case SECTION_TYPE_DATACOUNT:
                if (!load_datacount_section(buf, buf_end, module, error_buf,
                                            error_buf_size))
                    return false;
                break;
#endif
            default:
                set_error_buf(error_buf, error_buf_size, "invalid section id");
                return false;
        }

        section = section->next;
    }

    module->aux_data_end_global_index = (uint32)-1;
    module->aux_heap_base_global_index = (uint32)-1;
    module->aux_stack_top_global_index = (uint32)-1;

    /* Resolve auxiliary data/stack/heap info and reset memory info */
    export = module->exports;
    for (i = 0; i < module->export_count; i++, export ++) {
        if (export->kind == EXPORT_KIND_GLOBAL) {
            if (!strcmp(export->name, "__heap_base")) {
                global_index = export->index - module->import_global_count;
                global = module->globals + global_index;
                if (global->type == VALUE_TYPE_I32 && !global->is_mutable
                    && global->init_expr.init_expr_type
                           == INIT_EXPR_TYPE_I32_CONST) {
                    aux_heap_base_global = global;
                    aux_heap_base = global->init_expr.u.i32;
                    aux_heap_base_global_index = export->index;
                    LOG_VERBOSE("Found aux __heap_base global, value: %d",
                                aux_heap_base);
                }
            }
            else if (!strcmp(export->name, "__data_end")) {
                global_index = export->index - module->import_global_count;
                global = module->globals + global_index;
                if (global->type == VALUE_TYPE_I32 && !global->is_mutable
                    && global->init_expr.init_expr_type
                           == INIT_EXPR_TYPE_I32_CONST) {
                    aux_data_end_global = global;
                    aux_data_end = global->init_expr.u.i32;
                    aux_data_end_global_index = export->index;
                    LOG_VERBOSE("Found aux __data_end global, value: %d",
                                aux_data_end);

                    aux_data_end = align_uint(aux_data_end, 16);
                }
            }

            /* For module compiled with -pthread option, the global is:
                [0] stack_top       <-- 0
                [1] tls_pointer
                [2] tls_size
                [3] data_end        <-- 3
                [4] global_base
                [5] heap_base       <-- 5
                [6] dso_handle

                For module compiled without -pthread option:
                [0] stack_top       <-- 0
                [1] data_end        <-- 1
                [2] global_base
                [3] heap_base       <-- 3
                [4] dso_handle
            */
            if (aux_data_end_global && aux_heap_base_global
                && aux_data_end <= aux_heap_base) {
                module->aux_data_end_global_index = aux_data_end_global_index;
                module->aux_data_end = aux_data_end;
                module->aux_heap_base_global_index = aux_heap_base_global_index;
                module->aux_heap_base = aux_heap_base;

                /* Resolve aux stack top global */
                for (global_index = 0; global_index < module->global_count;
                     global_index++) {
                    global = module->globals + global_index;
                    if (global->is_mutable /* heap_base and data_end is
                                              not mutable */
                        && global->type == VALUE_TYPE_I32
                        && global->init_expr.init_expr_type
                               == INIT_EXPR_TYPE_I32_CONST
                        && (uint32)global->init_expr.u.i32 <= aux_heap_base) {
                        aux_stack_top_global = global;
                        aux_stack_top = (uint32)global->init_expr.u.i32;
                        module->aux_stack_top_global_index =
                            module->import_global_count + global_index;
                        module->aux_stack_bottom = aux_stack_top;
                        module->aux_stack_size =
                            aux_stack_top > aux_data_end
                                ? aux_stack_top - aux_data_end
                                : aux_stack_top;
                        LOG_VERBOSE("Found aux stack top global, value: %d, "
                                    "global index: %d, stack size: %d",
                                    aux_stack_top, global_index,
                                    module->aux_stack_size);
                        break;
                    }
                }
                if (!aux_stack_top_global) {
                    /* Auxiliary stack global isn't found, it must be unused
                       in the wasm app, as if it is used, the global must be
                       defined. Here we set it to __heap_base global and set
                       its size to 0. */
                    aux_stack_top_global = aux_heap_base_global;
                    aux_stack_top = aux_heap_base;
                    module->aux_stack_top_global_index =
                        module->aux_heap_base_global_index;
                    module->aux_stack_bottom = aux_stack_top;
                    module->aux_stack_size = 0;
                }
                break;
            }
        }
    }

    module->malloc_function = (uint32)-1;
    module->free_function = (uint32)-1;
    module->retain_function = (uint32)-1;

    /* Resolve malloc/free function exported by wasm module */
    export = module->exports;
    for (i = 0; i < module->export_count; i++, export ++) {
        if (export->kind == EXPORT_KIND_FUNC) {
            if (!strcmp(export->name, "malloc")
                && export->index >= module->import_function_count) {
                func_index = export->index - module->import_function_count;
                func_type = module->functions[func_index]->func_type;
                if (func_type->param_count == 1 && func_type->result_count == 1
                    && func_type->types[0] == VALUE_TYPE_I32
                    && func_type->types[1] == VALUE_TYPE_I32) {
                    bh_assert(module->malloc_function == (uint32)-1);
                    module->malloc_function = export->index;
                    LOG_VERBOSE("Found malloc function, name: %s, index: %u",
                                export->name, export->index);
                }
            }
            else if (!strcmp(export->name, "__new")
                     && export->index >= module->import_function_count) {
                /* __new && __pin for AssemblyScript */
                func_index = export->index - module->import_function_count;
                func_type = module->functions[func_index]->func_type;
                if (func_type->param_count == 2 && func_type->result_count == 1
                    && func_type->types[0] == VALUE_TYPE_I32
                    && func_type->types[1] == VALUE_TYPE_I32
                    && func_type->types[2] == VALUE_TYPE_I32) {
                    uint32 j;
                    WASMExport *export_tmp;

                    bh_assert(module->malloc_function == (uint32)-1);
                    module->malloc_function = export->index;
                    LOG_VERBOSE("Found malloc function, name: %s, index: %u",
                                export->name, export->index);

                    /* resolve retain function.
                       If not found, reset malloc function index */
                    export_tmp = module->exports;
                    for (j = 0; j < module->export_count; j++, export_tmp++) {
                        if ((export_tmp->kind == EXPORT_KIND_FUNC)
                            && (!strcmp(export_tmp->name, "__retain")
                                || !strcmp(export_tmp->name, "__pin"))
                            && (export_tmp->index
                                >= module->import_function_count)) {
                            func_index = export_tmp->index
                                         - module->import_function_count;
                            func_type =
                                module->functions[func_index]->func_type;
                            if (func_type->param_count == 1
                                && func_type->result_count == 1
                                && func_type->types[0] == VALUE_TYPE_I32
                                && func_type->types[1] == VALUE_TYPE_I32) {
                                bh_assert(module->retain_function
                                          == (uint32)-1);
                                module->retain_function = export_tmp->index;
                                LOG_VERBOSE("Found retain function, name: %s, "
                                            "index: %u",
                                            export_tmp->name,
                                            export_tmp->index);
                                break;
                            }
                        }
                    }
                    if (j == module->export_count) {
                        module->malloc_function = (uint32)-1;
                        LOG_VERBOSE("Can't find retain function,"
                                    "reset malloc function index to -1");
                    }
                }
            }
            else if (((!strcmp(export->name, "free"))
                      || (!strcmp(export->name, "__release"))
                      || (!strcmp(export->name, "__unpin")))
                     && export->index >= module->import_function_count) {
                func_index = export->index - module->import_function_count;
                func_type = module->functions[func_index]->func_type;
                if (func_type->param_count == 1 && func_type->result_count == 0
                    && func_type->types[0] == VALUE_TYPE_I32) {
                    bh_assert(module->free_function == (uint32)-1);
                    module->free_function = export->index;
                    LOG_VERBOSE("Found free function, name: %s, index: %u",
                                export->name, export->index);
                }
            }
        }
    }

#if WASM_ENABLE_FAST_INTERP != 0 && WASM_ENABLE_LABELS_AS_VALUES != 0
    handle_table = wasm_interp_get_handle_table();
#endif

    for (i = 0; i < module->function_count; i++) {
        WASMFunction *func = module->functions[i];
        if (!wasm_loader_prepare_bytecode(module, func, i, error_buf,
                                          error_buf_size)) {
            return false;
        }

        if (i == module->function_count - 1) {
            bh_assert(func->code + func->code_size == buf_code_end);
        }
    }

    if (!module->possible_memory_grow) {
        WASMMemoryImport *memory_import;
        WASMMemory *memory;

        if (aux_data_end_global && aux_heap_base_global
            && aux_stack_top_global) {
            uint64 init_memory_size;
            uint32 shrunk_memory_size = align_uint(aux_heap_base, 8);

            if (module->import_memory_count) {
                memory_import = &module->import_memories[0].u.memory;
                init_memory_size = (uint64)memory_import->num_bytes_per_page
                                   * memory_import->init_page_count;
                if (shrunk_memory_size <= init_memory_size) {
                    /* Reset memory info to decrease memory usage */
                    memory_import->num_bytes_per_page = shrunk_memory_size;
                    memory_import->init_page_count = 1;
                    LOG_VERBOSE("Shrink import memory size to %d",
                                shrunk_memory_size);
                }
            }
            if (module->memory_count) {
                memory = &module->memories[0];
                init_memory_size = (uint64)memory->num_bytes_per_page
                                   * memory->init_page_count;
                if (shrunk_memory_size <= init_memory_size) {
                    /* Reset memory info to decrease memory usage */
                    memory->num_bytes_per_page = shrunk_memory_size;
                    memory->init_page_count = 1;
                    LOG_VERBOSE("Shrink memory size to %d", shrunk_memory_size);
                }
            }
        }

        if (module->import_memory_count) {
            memory_import = &module->import_memories[0].u.memory;
            if (memory_import->init_page_count < DEFAULT_MAX_PAGES)
                memory_import->num_bytes_per_page *=
                    memory_import->init_page_count;
            else
                memory_import->num_bytes_per_page = UINT32_MAX;

            if (memory_import->init_page_count > 0)
                memory_import->init_page_count = memory_import->max_page_count =
                    1;
            else
                memory_import->init_page_count = memory_import->max_page_count =
                    0;
        }

        if (module->memory_count) {
            memory = &module->memories[0];
            if (memory->init_page_count < DEFAULT_MAX_PAGES)
                memory->num_bytes_per_page *= memory->init_page_count;
            else
                memory->num_bytes_per_page = UINT32_MAX;

            if (memory->init_page_count > 0)
                memory->init_page_count = memory->max_page_count = 1;
            else
                memory->init_page_count = memory->max_page_count = 0;
        }
    }

#if WASM_ENABLE_FAST_JIT != 0
    if (!(module->fast_jit_func_ptrs =
              loader_malloc(sizeof(void *) * module->function_count, error_buf,
                            error_buf_size))) {
        return false;
    }
    if (!jit_compiler_compile_all(module)) {
        set_error_buf(error_buf, error_buf_size, "fast jit compilation failed");
        return false;
    }
#endif

#if WASM_ENABLE_MEMORY_TRACING != 0
    wasm_runtime_dump_module_mem_consumption(module);
#endif
    return true;
}

static WASMModule *
create_module(char *error_buf, uint32 error_buf_size)
{
    WASMModule *module =
        loader_malloc(sizeof(WASMModule), error_buf, error_buf_size);
#if WASM_ENABLE_FAST_INTERP == 0
    bh_list_status ret;
#endif

    if (!module) {
        return NULL;
    }

    module->module_type = Wasm_Module_Bytecode;

    /* Set start_function to -1, means no start function */
    module->start_function = (uint32)-1;

#if WASM_ENABLE_FAST_INTERP == 0
    module->br_table_cache_list = &module->br_table_cache_list_head;
    ret = bh_list_init(module->br_table_cache_list);
    bh_assert(ret == BH_LIST_SUCCESS);
    (void)ret;
#endif

    return module;
}

WASMModule *
wasm_loader_load_from_sections(WASMSection *section_list, char *error_buf,
                               uint32 error_buf_size)
{
    WASMModule *module = create_module(error_buf, error_buf_size);
    if (!module)
        return NULL;

    if (!load_from_sections(module, section_list, false, error_buf,
                            error_buf_size)) {
        wasm_loader_unload(module);
        return NULL;
    }

    LOG_VERBOSE("Load module from sections success.\n");
    return module;
}

static void
destroy_sections(WASMSection *section_list)
{
    WASMSection *section = section_list, *next;
    while (section) {
        next = section->next;
        wasm_runtime_free(section);
        section = next;
    }
}

/* clang-format off */
static uint8 section_ids[] = {
    SECTION_TYPE_USER,
    SECTION_TYPE_TYPE,
    SECTION_TYPE_IMPORT,
    SECTION_TYPE_FUNC,
    SECTION_TYPE_TABLE,
    SECTION_TYPE_MEMORY,
    SECTION_TYPE_GLOBAL,
    SECTION_TYPE_EXPORT,
    SECTION_TYPE_START,
    SECTION_TYPE_ELEM,
#if WASM_ENABLE_BULK_MEMORY != 0
    SECTION_TYPE_DATACOUNT,
#endif
    SECTION_TYPE_CODE,
    SECTION_TYPE_DATA
};
/* clang-format on */

static uint8
get_section_index(uint8 section_type)
{
    uint8 max_id = sizeof(section_ids) / sizeof(uint8);

    for (uint8 i = 0; i < max_id; i++) {
        if (section_type == section_ids[i])
            return i;
    }

    return (uint8)-1;
}

static bool
create_sections(const uint8 *buf, uint32 size, WASMSection **p_section_list,
                char *error_buf, uint32 error_buf_size)
{
    WASMSection *section_list_end = NULL, *section;
    const uint8 *p = buf, *p_end = buf + size /*, *section_body*/;
    uint8 section_type, section_index, last_section_index = (uint8)-1;
    uint32 section_size;

    bh_assert(!*p_section_list);

    p += 8;
    while (p < p_end) {
        CHECK_BUF(p, p_end, 1);
        section_type = read_uint8(p);
        section_index = get_section_index(section_type);
        if (section_index != (uint8)-1) {
            if (section_type != SECTION_TYPE_USER) {
                /* Custom sections may be inserted at any place,
                   while other sections must occur at most once
                   and in prescribed order. */
                bh_assert(last_section_index == (uint8)-1
                          || last_section_index < section_index);
                last_section_index = section_index;
            }
            read_leb_uint32(p, p_end, section_size);
            CHECK_BUF1(p, p_end, section_size);

            if (!(section = loader_malloc(sizeof(WASMSection), error_buf,
                                          error_buf_size))) {
                return false;
            }

            section->section_type = section_type;
            section->section_body = (uint8 *)p;
            section->section_body_size = section_size;

            if (!*p_section_list)
                *p_section_list = section_list_end = section;
            else {
                section_list_end->next = section;
                section_list_end = section;
            }

            p += section_size;
        }
        else {
            bh_assert(0);
        }
    }

    (void)last_section_index;
    return true;
}

static void
exchange32(uint8 *p_data)
{
    uint8 value = *p_data;
    *p_data = *(p_data + 3);
    *(p_data + 3) = value;

    value = *(p_data + 1);
    *(p_data + 1) = *(p_data + 2);
    *(p_data + 2) = value;
}

static union {
    int a;
    char b;
} __ue = { .a = 1 };

#define is_little_endian() (__ue.b == 1)

static bool
load(const uint8 *buf, uint32 size, WASMModule *module, char *error_buf,
     uint32 error_buf_size)
{
    const uint8 *buf_end = buf + size;
    const uint8 *p = buf, *p_end = buf_end;
    uint32 magic_number, version;
    WASMSection *section_list = NULL;

    CHECK_BUF1(p, p_end, sizeof(uint32));
    magic_number = read_uint32(p);
    if (!is_little_endian())
        exchange32((uint8 *)&magic_number);

    bh_assert(magic_number == WASM_MAGIC_NUMBER);

    CHECK_BUF1(p, p_end, sizeof(uint32));
    version = read_uint32(p);
    if (!is_little_endian())
        exchange32((uint8 *)&version);

    if (version != WASM_CURRENT_VERSION) {
        set_error_buf(error_buf, error_buf_size, "unknown binary version");
        return false;
    }

    if (!create_sections(buf, size, &section_list, error_buf, error_buf_size)
        || !load_from_sections(module, section_list, true, error_buf,
                               error_buf_size)) {
        destroy_sections(section_list);
        return false;
    }

    destroy_sections(section_list);
    (void)p_end;
    return true;
}

WASMModule *
wasm_loader_load(uint8 *buf, uint32 size, char *error_buf,
                 uint32 error_buf_size)
{
    WASMModule *module = create_module(error_buf, error_buf_size);
    if (!module) {
        return NULL;
    }

#if WASM_ENABLE_FAST_JIT != 0
    module->load_addr = (uint8 *)buf;
    module->load_size = size;
#endif

    if (!load(buf, size, module, error_buf, error_buf_size)) {
        goto fail;
    }

    LOG_VERBOSE("Load module success.\n");
    return module;

fail:
    wasm_loader_unload(module);
    return NULL;
}

void
wasm_loader_unload(WASMModule *module)
{
    uint32 i;

    if (!module)
        return;

    if (module->types) {
        for (i = 0; i < module->type_count; i++) {
            if (module->types[i])
                destroy_wasm_type(module->types[i]);
        }
        wasm_runtime_free(module->types);
    }

    if (module->imports)
        wasm_runtime_free(module->imports);

    if (module->functions) {
        for (i = 0; i < module->function_count; i++) {
            if (module->functions[i]) {
                if (module->functions[i]->local_offsets)
                    wasm_runtime_free(module->functions[i]->local_offsets);
#if WASM_ENABLE_FAST_INTERP != 0
                if (module->functions[i]->code_compiled)
                    wasm_runtime_free(module->functions[i]->code_compiled);
                if (module->functions[i]->consts)
                    wasm_runtime_free(module->functions[i]->consts);
#endif
                wasm_runtime_free(module->functions[i]);
            }
        }
        wasm_runtime_free(module->functions);
    }

    if (module->tables)
        wasm_runtime_free(module->tables);

    if (module->memories)
        wasm_runtime_free(module->memories);

    if (module->globals)
        wasm_runtime_free(module->globals);

    if (module->exports)
        wasm_runtime_free(module->exports);

    if (module->table_segments) {
        for (i = 0; i < module->table_seg_count; i++) {
            if (module->table_segments[i].func_indexes)
                wasm_runtime_free(module->table_segments[i].func_indexes);
        }
        wasm_runtime_free(module->table_segments);
    }

    if (module->data_segments) {
        for (i = 0; i < module->data_seg_count; i++) {
            if (module->data_segments[i])
                wasm_runtime_free(module->data_segments[i]);
        }
        wasm_runtime_free(module->data_segments);
    }

    if (module->const_str_list) {
        StringNode *node = module->const_str_list, *node_next;
        while (node) {
            node_next = node->next;
            wasm_runtime_free(node);
            node = node_next;
        }
    }

#if WASM_ENABLE_FAST_INTERP == 0
    if (module->br_table_cache_list) {
        BrTableCache *node = bh_list_first_elem(module->br_table_cache_list);
        BrTableCache *node_next;
        while (node) {
            node_next = bh_list_elem_next(node);
            wasm_runtime_free(node);
            node = node_next;
        }
    }
#endif

#if WASM_ENABLE_FAST_JIT != 0
    if (module->fast_jit_func_ptrs) {
        for (i = 0; i < module->function_count; i++) {
            if (module->fast_jit_func_ptrs[i])
                jit_code_cache_free(module->fast_jit_func_ptrs[i]);
        }
        wasm_runtime_free(module->fast_jit_func_ptrs);
    }
#endif

    wasm_runtime_free(module);
}

bool
wasm_loader_find_block_addr(WASMExecEnv *exec_env, BlockAddr *block_addr_cache,
                            const uint8 *start_addr, const uint8 *code_end_addr,
                            uint8 label_type, uint8 **p_else_addr,
                            uint8 **p_end_addr)
{
    const uint8 *p = start_addr, *p_end = code_end_addr;
    uint8 *else_addr = NULL;
    char error_buf[128];
    uint32 block_nested_depth = 1, count, i, j, t;
    uint32 error_buf_size = sizeof(error_buf);
    uint8 opcode, u8;
    BlockAddr block_stack[16] = { 0 }, *block;

    i = ((uintptr_t)start_addr) & (uintptr_t)(BLOCK_ADDR_CACHE_SIZE - 1);
    block = block_addr_cache + BLOCK_ADDR_CONFLICT_SIZE * i;

    for (j = 0; j < BLOCK_ADDR_CONFLICT_SIZE; j++) {
        if (block[j].start_addr == start_addr) {
            /* Cache hit */
            *p_else_addr = block[j].else_addr;
            *p_end_addr = block[j].end_addr;
            return true;
        }
    }

    /* Cache unhit */
    block_stack[0].start_addr = start_addr;

    while (p < code_end_addr) {
        opcode = *p++;

        switch (opcode) {
            case WASM_OP_UNREACHABLE:
            case WASM_OP_NOP:
                break;

            case WASM_OP_BLOCK:
            case WASM_OP_LOOP:
            case WASM_OP_IF:
                /* block result type: 0x40/0x7F/0x7E/0x7D/0x7C */
                u8 = read_uint8(p);
                if (block_nested_depth
                    < sizeof(block_stack) / sizeof(BlockAddr)) {
                    block_stack[block_nested_depth].start_addr = p;
                    block_stack[block_nested_depth].else_addr = NULL;
                }
                block_nested_depth++;
                break;

            case EXT_OP_BLOCK:
            case EXT_OP_LOOP:
            case EXT_OP_IF:
                /* block type */
                skip_leb_uint32(p, p_end);
                if (block_nested_depth
                    < sizeof(block_stack) / sizeof(BlockAddr)) {
                    block_stack[block_nested_depth].start_addr = p;
                    block_stack[block_nested_depth].else_addr = NULL;
                }
                block_nested_depth++;
                break;

            case WASM_OP_ELSE:
                if (label_type == LABEL_TYPE_IF && block_nested_depth == 1)
                    else_addr = (uint8 *)(p - 1);
                if (block_nested_depth - 1
                    < sizeof(block_stack) / sizeof(BlockAddr))
                    block_stack[block_nested_depth - 1].else_addr =
                        (uint8 *)(p - 1);
                break;

            case WASM_OP_END:
                if (block_nested_depth == 1) {
                    if (label_type == LABEL_TYPE_IF)
                        *p_else_addr = else_addr;
                    *p_end_addr = (uint8 *)(p - 1);

                    block_stack[0].end_addr = (uint8 *)(p - 1);
                    for (t = 0; t < sizeof(block_stack) / sizeof(BlockAddr);
                         t++) {
                        start_addr = block_stack[t].start_addr;
                        if (start_addr) {
                            i = ((uintptr_t)start_addr)
                                & (uintptr_t)(BLOCK_ADDR_CACHE_SIZE - 1);
                            block =
                                block_addr_cache + BLOCK_ADDR_CONFLICT_SIZE * i;
                            for (j = 0; j < BLOCK_ADDR_CONFLICT_SIZE; j++)
                                if (!block[j].start_addr)
                                    break;

                            if (j == BLOCK_ADDR_CONFLICT_SIZE) {
                                memmove(block + 1, block,
                                        (BLOCK_ADDR_CONFLICT_SIZE - 1)
                                            * sizeof(BlockAddr));
                                j = 0;
                            }
                            block[j].start_addr = block_stack[t].start_addr;
                            block[j].else_addr = block_stack[t].else_addr;
                            block[j].end_addr = block_stack[t].end_addr;
                        }
                        else
                            break;
                    }
                    return true;
                }
                else {
                    block_nested_depth--;
                    if (block_nested_depth
                        < sizeof(block_stack) / sizeof(BlockAddr))
                        block_stack[block_nested_depth].end_addr =
                            (uint8 *)(p - 1);
                }
                break;

            case WASM_OP_BR:
            case WASM_OP_BR_IF:
                skip_leb_uint32(p, p_end); /* labelidx */
                break;

            case WASM_OP_BR_TABLE:
                read_leb_uint32(p, p_end, count); /* lable num */
#if WASM_ENABLE_FAST_INTERP != 0
                for (i = 0; i <= count; i++) /* lableidxs */
                    skip_leb_uint32(p, p_end);
#else
                p += count + 1;
                while (*p == WASM_OP_NOP)
                    p++;
#endif
                break;

#if WASM_ENABLE_FAST_INTERP == 0
            case EXT_OP_BR_TABLE_CACHE:
                read_leb_uint32(p, p_end, count); /* lable num */
                while (*p == WASM_OP_NOP)
                    p++;
                break;
#endif

            case WASM_OP_RETURN:
                break;

            case WASM_OP_CALL:
#if WASM_ENABLE_TAIL_CALL != 0
            case WASM_OP_RETURN_CALL:
#endif
                skip_leb_uint32(p, p_end); /* funcidx */
                break;

            case WASM_OP_CALL_INDIRECT:
#if WASM_ENABLE_TAIL_CALL != 0
            case WASM_OP_RETURN_CALL_INDIRECT:
#endif
                skip_leb_uint32(p, p_end); /* typeidx */
                CHECK_BUF(p, p_end, 1);
                u8 = read_uint8(p); /* 0x00 */
                break;

            case WASM_OP_DROP:
            case WASM_OP_SELECT:
            case WASM_OP_DROP_64:
            case WASM_OP_SELECT_64:
                break;
#if WASM_ENABLE_REF_TYPES != 0
            case WASM_OP_SELECT_T:
                skip_leb_uint32(p, p_end); /* vec length */
                CHECK_BUF(p, p_end, 1);
                u8 = read_uint8(p); /* typeidx */
                break;
            case WASM_OP_TABLE_GET:
            case WASM_OP_TABLE_SET:
                skip_leb_uint32(p, p_end); /* table index */
                break;
            case WASM_OP_REF_NULL:
                CHECK_BUF(p, p_end, 1);
                u8 = read_uint8(p); /* type */
                break;
            case WASM_OP_REF_IS_NULL:
                break;
            case WASM_OP_REF_FUNC:
                skip_leb_uint32(p, p_end); /* func index */
                break;
#endif /* WASM_ENABLE_REF_TYPES */
            case WASM_OP_GET_LOCAL:
            case WASM_OP_SET_LOCAL:
            case WASM_OP_TEE_LOCAL:
            case WASM_OP_GET_GLOBAL:
            case WASM_OP_SET_GLOBAL:
            case WASM_OP_GET_GLOBAL_64:
            case WASM_OP_SET_GLOBAL_64:
            case WASM_OP_SET_GLOBAL_AUX_STACK:
                skip_leb_uint32(p, p_end); /* localidx */
                break;

            case EXT_OP_GET_LOCAL_FAST:
            case EXT_OP_SET_LOCAL_FAST:
            case EXT_OP_TEE_LOCAL_FAST:
                CHECK_BUF(p, p_end, 1);
                p++;
                break;

            case WASM_OP_I32_LOAD:
            case WASM_OP_I64_LOAD:
            case WASM_OP_F32_LOAD:
            case WASM_OP_F64_LOAD:
            case WASM_OP_I32_LOAD8_S:
            case WASM_OP_I32_LOAD8_U:
            case WASM_OP_I32_LOAD16_S:
            case WASM_OP_I32_LOAD16_U:
            case WASM_OP_I64_LOAD8_S:
            case WASM_OP_I64_LOAD8_U:
            case WASM_OP_I64_LOAD16_S:
            case WASM_OP_I64_LOAD16_U:
            case WASM_OP_I64_LOAD32_S:
            case WASM_OP_I64_LOAD32_U:
            case WASM_OP_I32_STORE:
            case WASM_OP_I64_STORE:
            case WASM_OP_F32_STORE:
            case WASM_OP_F64_STORE:
            case WASM_OP_I32_STORE8:
            case WASM_OP_I32_STORE16:
            case WASM_OP_I64_STORE8:
            case WASM_OP_I64_STORE16:
            case WASM_OP_I64_STORE32:
                skip_leb_uint32(p, p_end); /* align */
                skip_leb_uint32(p, p_end); /* offset */
                break;

            case WASM_OP_MEMORY_SIZE:
            case WASM_OP_MEMORY_GROW:
                skip_leb_uint32(p, p_end); /* 0x00 */
                break;

            case WASM_OP_I32_CONST:
                skip_leb_int32(p, p_end);
                break;
            case WASM_OP_I64_CONST:
                skip_leb_int64(p, p_end);
                break;
            case WASM_OP_F32_CONST:
                p += sizeof(float32);
                break;
            case WASM_OP_F64_CONST:
                p += sizeof(float64);
                break;

            case WASM_OP_I32_EQZ:
            case WASM_OP_I32_EQ:
            case WASM_OP_I32_NE:
            case WASM_OP_I32_LT_S:
            case WASM_OP_I32_LT_U:
            case WASM_OP_I32_GT_S:
            case WASM_OP_I32_GT_U:
            case WASM_OP_I32_LE_S:
            case WASM_OP_I32_LE_U:
            case WASM_OP_I32_GE_S:
            case WASM_OP_I32_GE_U:
            case WASM_OP_I64_EQZ:
            case WASM_OP_I64_EQ:
            case WASM_OP_I64_NE:
            case WASM_OP_I64_LT_S:
            case WASM_OP_I64_LT_U:
            case WASM_OP_I64_GT_S:
            case WASM_OP_I64_GT_U:
            case WASM_OP_I64_LE_S:
            case WASM_OP_I64_LE_U:
            case WASM_OP_I64_GE_S:
            case WASM_OP_I64_GE_U:
            case WASM_OP_F32_EQ:
            case WASM_OP_F32_NE:
            case WASM_OP_F32_LT:
            case WASM_OP_F32_GT:
            case WASM_OP_F32_LE:
            case WASM_OP_F32_GE:
            case WASM_OP_F64_EQ:
            case WASM_OP_F64_NE:
            case WASM_OP_F64_LT:
            case WASM_OP_F64_GT:
            case WASM_OP_F64_LE:
            case WASM_OP_F64_GE:
            case WASM_OP_I32_CLZ:
            case WASM_OP_I32_CTZ:
            case WASM_OP_I32_POPCNT:
            case WASM_OP_I32_ADD:
            case WASM_OP_I32_SUB:
            case WASM_OP_I32_MUL:
            case WASM_OP_I32_DIV_S:
            case WASM_OP_I32_DIV_U:
            case WASM_OP_I32_REM_S:
            case WASM_OP_I32_REM_U:
            case WASM_OP_I32_AND:
            case WASM_OP_I32_OR:
            case WASM_OP_I32_XOR:
            case WASM_OP_I32_SHL:
            case WASM_OP_I32_SHR_S:
            case WASM_OP_I32_SHR_U:
            case WASM_OP_I32_ROTL:
            case WASM_OP_I32_ROTR:
            case WASM_OP_I64_CLZ:
            case WASM_OP_I64_CTZ:
            case WASM_OP_I64_POPCNT:
            case WASM_OP_I64_ADD:
            case WASM_OP_I64_SUB:
            case WASM_OP_I64_MUL:
            case WASM_OP_I64_DIV_S:
            case WASM_OP_I64_DIV_U:
            case WASM_OP_I64_REM_S:
            case WASM_OP_I64_REM_U:
            case WASM_OP_I64_AND:
            case WASM_OP_I64_OR:
            case WASM_OP_I64_XOR:
            case WASM_OP_I64_SHL:
            case WASM_OP_I64_SHR_S:
            case WASM_OP_I64_SHR_U:
            case WASM_OP_I64_ROTL:
            case WASM_OP_I64_ROTR:
            case WASM_OP_F32_ABS:
            case WASM_OP_F32_NEG:
            case WASM_OP_F32_CEIL:
            case WASM_OP_F32_FLOOR:
            case WASM_OP_F32_TRUNC:
            case WASM_OP_F32_NEAREST:
            case WASM_OP_F32_SQRT:
            case WASM_OP_F32_ADD:
            case WASM_OP_F32_SUB:
            case WASM_OP_F32_MUL:
            case WASM_OP_F32_DIV:
            case WASM_OP_F32_MIN:
            case WASM_OP_F32_MAX:
            case WASM_OP_F32_COPYSIGN:
            case WASM_OP_F64_ABS:
            case WASM_OP_F64_NEG:
            case WASM_OP_F64_CEIL:
            case WASM_OP_F64_FLOOR:
            case WASM_OP_F64_TRUNC:
            case WASM_OP_F64_NEAREST:
            case WASM_OP_F64_SQRT:
            case WASM_OP_F64_ADD:
            case WASM_OP_F64_SUB:
            case WASM_OP_F64_MUL:
            case WASM_OP_F64_DIV:
            case WASM_OP_F64_MIN:
            case WASM_OP_F64_MAX:
            case WASM_OP_F64_COPYSIGN:
            case WASM_OP_I32_WRAP_I64:
            case WASM_OP_I32_TRUNC_S_F32:
            case WASM_OP_I32_TRUNC_U_F32:
            case WASM_OP_I32_TRUNC_S_F64:
            case WASM_OP_I32_TRUNC_U_F64:
            case WASM_OP_I64_EXTEND_S_I32:
            case WASM_OP_I64_EXTEND_U_I32:
            case WASM_OP_I64_TRUNC_S_F32:
            case WASM_OP_I64_TRUNC_U_F32:
            case WASM_OP_I64_TRUNC_S_F64:
            case WASM_OP_I64_TRUNC_U_F64:
            case WASM_OP_F32_CONVERT_S_I32:
            case WASM_OP_F32_CONVERT_U_I32:
            case WASM_OP_F32_CONVERT_S_I64:
            case WASM_OP_F32_CONVERT_U_I64:
            case WASM_OP_F32_DEMOTE_F64:
            case WASM_OP_F64_CONVERT_S_I32:
            case WASM_OP_F64_CONVERT_U_I32:
            case WASM_OP_F64_CONVERT_S_I64:
            case WASM_OP_F64_CONVERT_U_I64:
            case WASM_OP_F64_PROMOTE_F32:
            case WASM_OP_I32_REINTERPRET_F32:
            case WASM_OP_I64_REINTERPRET_F64:
            case WASM_OP_F32_REINTERPRET_I32:
            case WASM_OP_F64_REINTERPRET_I64:
            case WASM_OP_I32_EXTEND8_S:
            case WASM_OP_I32_EXTEND16_S:
            case WASM_OP_I64_EXTEND8_S:
            case WASM_OP_I64_EXTEND16_S:
            case WASM_OP_I64_EXTEND32_S:
                break;
            case WASM_OP_MISC_PREFIX:
            {
                uint32 opcode1;

                read_leb_uint32(p, p_end, opcode1);

                switch (opcode1) {
                    case WASM_OP_I32_TRUNC_SAT_S_F32:
                    case WASM_OP_I32_TRUNC_SAT_U_F32:
                    case WASM_OP_I32_TRUNC_SAT_S_F64:
                    case WASM_OP_I32_TRUNC_SAT_U_F64:
                    case WASM_OP_I64_TRUNC_SAT_S_F32:
                    case WASM_OP_I64_TRUNC_SAT_U_F32:
                    case WASM_OP_I64_TRUNC_SAT_S_F64:
                    case WASM_OP_I64_TRUNC_SAT_U_F64:
                        break;
#if WASM_ENABLE_BULK_MEMORY != 0
                    case WASM_OP_MEMORY_INIT:
                        skip_leb_uint32(p, p_end);
                        /* skip memory idx */
                        p++;
                        break;
                    case WASM_OP_DATA_DROP:
                        skip_leb_uint32(p, p_end);
                        break;
                    case WASM_OP_MEMORY_COPY:
                        /* skip two memory idx */
                        p += 2;
                        break;
                    case WASM_OP_MEMORY_FILL:
                        /* skip memory idx */
                        p++;
                        break;
#endif
#if WASM_ENABLE_REF_TYPES != 0
                    case WASM_OP_TABLE_INIT:
                    case WASM_OP_TABLE_COPY:
                        /* tableidx */
                        skip_leb_uint32(p, p_end);
                        /* elemidx */
                        skip_leb_uint32(p, p_end);
                        break;
                    case WASM_OP_ELEM_DROP:
                        /* elemidx */
                        skip_leb_uint32(p, p_end);
                        break;
                    case WASM_OP_TABLE_SIZE:
                    case WASM_OP_TABLE_GROW:
                    case WASM_OP_TABLE_FILL:
                        skip_leb_uint32(p, p_end); /* table idx */
                        break;
#endif /* WASM_ENABLE_REF_TYPES */
                    default:
                        bh_assert(0);
                        break;
                }
                break;
            }

#if WASM_ENABLE_SHARED_MEMORY != 0
            case WASM_OP_ATOMIC_PREFIX:
            {
                /* atomic_op (1 u8) + memarg (2 u32_leb) */
                opcode = read_uint8(p);
                if (opcode != WASM_OP_ATOMIC_FENCE) {
                    skip_leb_uint32(p, p_end); /* align */
                    skip_leb_uint32(p, p_end); /* offset */
                }
                else {
                    /* atomic.fence doesn't have memarg */
                    p++;
                }
                break;
            }
#endif

            default:
                bh_assert(0);
                break;
        }
    }

    (void)u8;
    return false;
}

#define REF_I32 VALUE_TYPE_I32
#define REF_F32 VALUE_TYPE_F32
#define REF_I64_1 VALUE_TYPE_I64
#define REF_I64_2 VALUE_TYPE_I64
#define REF_F64_1 VALUE_TYPE_F64
#define REF_F64_2 VALUE_TYPE_F64
#define REF_ANY VALUE_TYPE_ANY

#if WASM_ENABLE_FAST_INTERP != 0

#if WASM_DEBUG_PREPROCESSOR != 0
#define LOG_OP(...) os_printf(__VA_ARGS__)
#else
#define LOG_OP(...) (void)0
#endif

#define PATCH_ELSE 0
#define PATCH_END 1
typedef struct BranchBlockPatch {
    struct BranchBlockPatch *next;
    uint8 patch_type;
    uint8 *code_compiled;
} BranchBlockPatch;
#endif

typedef struct BranchBlock {
    uint8 label_type;
    BlockType block_type;
    uint8 *start_addr;
    uint8 *else_addr;
    uint8 *end_addr;
    uint32 stack_cell_num;
#if WASM_ENABLE_FAST_INTERP != 0
    uint16 dynamic_offset;
    uint8 *code_compiled;
    BranchBlockPatch *patch_list;
    /* This is used to save params frame_offset of of if block */
    int16 *param_frame_offsets;
#endif

    /* Indicate the operand stack is in polymorphic state.
     * If the opcode is one of unreachable/br/br_table/return, stack is marked
     * to polymorphic state until the block's 'end' opcode is processed.
     * If stack is in polymorphic state and stack is empty, instruction can
     * pop any type of value directly without decreasing stack top pointer
     * and stack cell num. */
    bool is_stack_polymorphic;
} BranchBlock;

typedef struct WASMLoaderContext {
    /* frame ref stack */
    uint8 *frame_ref;
    uint8 *frame_ref_bottom;
    uint8 *frame_ref_boundary;
    uint32 frame_ref_size;
    uint32 stack_cell_num;
    uint32 max_stack_cell_num;

    /* frame csp stack */
    BranchBlock *frame_csp;
    BranchBlock *frame_csp_bottom;
    BranchBlock *frame_csp_boundary;
    uint32 frame_csp_size;
    uint32 csp_num;
    uint32 max_csp_num;

#if WASM_ENABLE_FAST_INTERP != 0
    /* frame offset stack */
    int16 *frame_offset;
    int16 *frame_offset_bottom;
    int16 *frame_offset_boundary;
    uint32 frame_offset_size;
    int16 dynamic_offset;
    int16 start_dynamic_offset;
    int16 max_dynamic_offset;

    /* preserved local offset */
    int16 preserved_local_offset;

    /* const buffer */
    uint8 *const_buf;
    uint16 num_const;
    uint16 const_cell_num;
    uint32 const_buf_size;

    /* processed code */
    uint8 *p_code_compiled;
    uint8 *p_code_compiled_end;
    uint32 code_compiled_size;
    /* If the last opcode will be dropped, the peak memory usage will be larger
     * than the final code_compiled_size, we record the peak size to ensure
     * there will not be invalid memory access during second traverse */
    uint32 code_compiled_peak_size;
#endif
} WASMLoaderContext;

typedef struct Const {
    WASMValue value;
    uint16 slot_index;
    uint8 value_type;
} Const;

static void *
memory_realloc(void *mem_old, uint32 size_old, uint32 size_new, char *error_buf,
               uint32 error_buf_size)
{
    uint8 *mem_new;
    bh_assert(size_new > size_old);
    if ((mem_new = loader_malloc(size_new, error_buf, error_buf_size))) {
        bh_memcpy_s(mem_new, size_new, mem_old, size_old);
        memset(mem_new + size_old, 0, size_new - size_old);
        wasm_runtime_free(mem_old);
    }
    return mem_new;
}

#define MEM_REALLOC(mem, size_old, size_new)                               \
    do {                                                                   \
        void *mem_new = memory_realloc(mem, size_old, size_new, error_buf, \
                                       error_buf_size);                    \
        if (!mem_new)                                                      \
            goto fail;                                                     \
        mem = mem_new;                                                     \
    } while (0)

#define CHECK_CSP_PUSH()                                                  \
    do {                                                                  \
        if (ctx->frame_csp >= ctx->frame_csp_boundary) {                  \
            MEM_REALLOC(                                                  \
                ctx->frame_csp_bottom, ctx->frame_csp_size,               \
                (uint32)(ctx->frame_csp_size + 8 * sizeof(BranchBlock))); \
            ctx->frame_csp_size += (uint32)(8 * sizeof(BranchBlock));     \
            ctx->frame_csp_boundary =                                     \
                ctx->frame_csp_bottom                                     \
                + ctx->frame_csp_size / sizeof(BranchBlock);              \
            ctx->frame_csp = ctx->frame_csp_bottom + ctx->csp_num;        \
        }                                                                 \
    } while (0)

#define CHECK_CSP_POP()               \
    do {                              \
        bh_assert(ctx->csp_num >= 1); \
    } while (0)

#if WASM_ENABLE_FAST_INTERP != 0
static bool
check_offset_push(WASMLoaderContext *ctx, char *error_buf,
                  uint32 error_buf_size)
{
    uint32 cell_num = (uint32)(ctx->frame_offset - ctx->frame_offset_bottom);
    if (ctx->frame_offset >= ctx->frame_offset_boundary) {
        MEM_REALLOC(ctx->frame_offset_bottom, ctx->frame_offset_size,
                    ctx->frame_offset_size + 16);
        ctx->frame_offset_size += 16;
        ctx->frame_offset_boundary =
            ctx->frame_offset_bottom + ctx->frame_offset_size / sizeof(int16);
        ctx->frame_offset = ctx->frame_offset_bottom + cell_num;
    }
    return true;
fail:
    return false;
}

static bool
check_offset_pop(WASMLoaderContext *ctx, uint32 cells)
{
    if (ctx->frame_offset - cells < ctx->frame_offset_bottom)
        return false;
    return true;
}

static void
free_label_patch_list(BranchBlock *frame_csp)
{
    BranchBlockPatch *label_patch = frame_csp->patch_list;
    BranchBlockPatch *next;
    while (label_patch != NULL) {
        next = label_patch->next;
        wasm_runtime_free(label_patch);
        label_patch = next;
    }
    frame_csp->patch_list = NULL;
}

static void
free_all_label_patch_lists(BranchBlock *frame_csp, uint32 csp_num)
{
    BranchBlock *tmp_csp = frame_csp;

    for (uint32 i = 0; i < csp_num; i++) {
        free_label_patch_list(tmp_csp);
        tmp_csp++;
    }
}

#endif

static bool
check_stack_push(WASMLoaderContext *ctx, char *error_buf, uint32 error_buf_size)
{
    if (ctx->frame_ref >= ctx->frame_ref_boundary) {
        MEM_REALLOC(ctx->frame_ref_bottom, ctx->frame_ref_size,
                    ctx->frame_ref_size + 16);
        ctx->frame_ref_size += 16;
        ctx->frame_ref_boundary = ctx->frame_ref_bottom + ctx->frame_ref_size;
        ctx->frame_ref = ctx->frame_ref_bottom + ctx->stack_cell_num;
    }
    return true;
fail:
    return false;
}

static bool
check_stack_top_values(uint8 *frame_ref, int32 stack_cell_num, uint8 type,
                       char *error_buf, uint32 error_buf_size)
{
    bh_assert(!((is_32bit_type(type) && stack_cell_num < 1)
                || (is_64bit_type(type) && stack_cell_num < 2)));

    bh_assert(!(
        (type == VALUE_TYPE_I32 && *(frame_ref - 1) != REF_I32)
        || (type == VALUE_TYPE_F32 && *(frame_ref - 1) != REF_F32)
        || (type == VALUE_TYPE_I64
            && (*(frame_ref - 2) != REF_I64_1 || *(frame_ref - 1) != REF_I64_2))
        || (type == VALUE_TYPE_F64
            && (*(frame_ref - 2) != REF_F64_1
                || *(frame_ref - 1) != REF_F64_2))));
    return true;
}

static bool
check_stack_pop(WASMLoaderContext *ctx, uint8 type, char *error_buf,
                uint32 error_buf_size)
{
    int32 block_stack_cell_num =
        (int32)(ctx->stack_cell_num - (ctx->frame_csp - 1)->stack_cell_num);

    if (block_stack_cell_num > 0 && *(ctx->frame_ref - 1) == VALUE_TYPE_ANY) {
        /* the stack top is a value of any type, return success */
        return true;
    }

    if (!check_stack_top_values(ctx->frame_ref, block_stack_cell_num, type,
                                error_buf, error_buf_size))
        return false;

    return true;
}

static void
wasm_loader_ctx_destroy(WASMLoaderContext *ctx)
{
    if (ctx) {
        if (ctx->frame_ref_bottom)
            wasm_runtime_free(ctx->frame_ref_bottom);
        if (ctx->frame_csp_bottom) {
#if WASM_ENABLE_FAST_INTERP != 0
            free_all_label_patch_lists(ctx->frame_csp_bottom, ctx->csp_num);
#endif
            wasm_runtime_free(ctx->frame_csp_bottom);
        }
#if WASM_ENABLE_FAST_INTERP != 0
        if (ctx->frame_offset_bottom)
            wasm_runtime_free(ctx->frame_offset_bottom);
        if (ctx->const_buf)
            wasm_runtime_free(ctx->const_buf);
#endif
        wasm_runtime_free(ctx);
    }
}

static WASMLoaderContext *
wasm_loader_ctx_init(WASMFunction *func, char *error_buf, uint32 error_buf_size)
{
    WASMLoaderContext *loader_ctx =
        loader_malloc(sizeof(WASMLoaderContext), error_buf, error_buf_size);
    if (!loader_ctx)
        return NULL;

    loader_ctx->frame_ref_size = 32;
    if (!(loader_ctx->frame_ref_bottom = loader_ctx->frame_ref = loader_malloc(
              loader_ctx->frame_ref_size, error_buf, error_buf_size)))
        goto fail;
    loader_ctx->frame_ref_boundary = loader_ctx->frame_ref_bottom + 32;

    loader_ctx->frame_csp_size = sizeof(BranchBlock) * 8;
    if (!(loader_ctx->frame_csp_bottom = loader_ctx->frame_csp = loader_malloc(
              loader_ctx->frame_csp_size, error_buf, error_buf_size)))
        goto fail;
    loader_ctx->frame_csp_boundary = loader_ctx->frame_csp_bottom + 8;

#if WASM_ENABLE_FAST_INTERP != 0
    loader_ctx->frame_offset_size = sizeof(int16) * 32;
    if (!(loader_ctx->frame_offset_bottom = loader_ctx->frame_offset =
              loader_malloc(loader_ctx->frame_offset_size, error_buf,
                            error_buf_size)))
        goto fail;
    loader_ctx->frame_offset_boundary = loader_ctx->frame_offset_bottom + 32;

    loader_ctx->num_const = 0;
    loader_ctx->const_buf_size = sizeof(Const) * 8;
    if (!(loader_ctx->const_buf = loader_malloc(loader_ctx->const_buf_size,
                                                error_buf, error_buf_size)))
        goto fail;

    if (func->param_cell_num >= (int32)INT16_MAX - func->local_cell_num) {
        set_error_buf(error_buf, error_buf_size,
                      "fast interpreter offset overflow");
        goto fail;
    }

    loader_ctx->start_dynamic_offset = loader_ctx->dynamic_offset =
        loader_ctx->max_dynamic_offset =
            func->param_cell_num + func->local_cell_num;
#endif
    return loader_ctx;

fail:
    wasm_loader_ctx_destroy(loader_ctx);
    return NULL;
}

static bool
wasm_loader_push_frame_ref(WASMLoaderContext *ctx, uint8 type, char *error_buf,
                           uint32 error_buf_size)
{
    if (type == VALUE_TYPE_VOID)
        return true;

    if (!check_stack_push(ctx, error_buf, error_buf_size))
        return false;

    *ctx->frame_ref++ = type;
    ctx->stack_cell_num++;
    if (ctx->stack_cell_num > ctx->max_stack_cell_num)
        ctx->max_stack_cell_num = ctx->stack_cell_num;

    if (is_32bit_type(type))
        return true;

    if (!check_stack_push(ctx, error_buf, error_buf_size))
        return false;
    *ctx->frame_ref++ = type;
    ctx->stack_cell_num++;
    if (ctx->stack_cell_num > ctx->max_stack_cell_num)
        ctx->max_stack_cell_num = ctx->stack_cell_num;
    return true;
}

static bool
wasm_loader_pop_frame_ref(WASMLoaderContext *ctx, uint8 type, char *error_buf,
                          uint32 error_buf_size)
{
    BranchBlock *cur_block = ctx->frame_csp - 1;
    int32 available_stack_cell =
        (int32)(ctx->stack_cell_num - cur_block->stack_cell_num);

    /* Directly return success if current block is in stack
     * polymorphic state while stack is empty. */
    if (available_stack_cell <= 0 && cur_block->is_stack_polymorphic)
        return true;

    if (type == VALUE_TYPE_VOID)
        return true;

    if (!check_stack_pop(ctx, type, error_buf, error_buf_size))
        return false;

    ctx->frame_ref--;
    ctx->stack_cell_num--;

    if (is_32bit_type(type) || *ctx->frame_ref == VALUE_TYPE_ANY)
        return true;

    ctx->frame_ref--;
    ctx->stack_cell_num--;
    return true;
}

static bool
wasm_loader_push_pop_frame_ref(WASMLoaderContext *ctx, uint8 pop_cnt,
                               uint8 type_push, uint8 type_pop, char *error_buf,
                               uint32 error_buf_size)
{
    for (int i = 0; i < pop_cnt; i++) {
        if (!wasm_loader_pop_frame_ref(ctx, type_pop, error_buf,
                                       error_buf_size))
            return false;
    }
    if (!wasm_loader_push_frame_ref(ctx, type_push, error_buf, error_buf_size))
        return false;
    return true;
}

static bool
wasm_loader_push_frame_csp(WASMLoaderContext *ctx, uint8 label_type,
                           BlockType block_type, uint8 *start_addr,
                           char *error_buf, uint32 error_buf_size)
{
    CHECK_CSP_PUSH();
    memset(ctx->frame_csp, 0, sizeof(BranchBlock));
    ctx->frame_csp->label_type = label_type;
    ctx->frame_csp->block_type = block_type;
    ctx->frame_csp->start_addr = start_addr;
    ctx->frame_csp->stack_cell_num = ctx->stack_cell_num;
#if WASM_ENABLE_FAST_INTERP != 0
    ctx->frame_csp->dynamic_offset = ctx->dynamic_offset;
    ctx->frame_csp->patch_list = NULL;
#endif
    ctx->frame_csp++;
    ctx->csp_num++;
    if (ctx->csp_num > ctx->max_csp_num)
        ctx->max_csp_num = ctx->csp_num;
    return true;
fail:
    return false;
}

static bool
wasm_loader_pop_frame_csp(WASMLoaderContext *ctx, char *error_buf,
                          uint32 error_buf_size)
{
    CHECK_CSP_POP();
#if WASM_ENABLE_FAST_INTERP != 0
    if ((ctx->frame_csp - 1)->param_frame_offsets)
        wasm_runtime_free((ctx->frame_csp - 1)->param_frame_offsets);
#endif
    ctx->frame_csp--;
    ctx->csp_num--;
    return true;
}

#if WASM_ENABLE_FAST_INTERP != 0

#if WASM_ENABLE_LABELS_AS_VALUES != 0
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS != 0
#define emit_label(opcode)                                      \
    do {                                                        \
        wasm_loader_emit_ptr(loader_ctx, handle_table[opcode]); \
        LOG_OP("\nemit_op [%02x]\t", opcode);                   \
    } while (0)
#define skip_label()                                            \
    do {                                                        \
        wasm_loader_emit_backspace(loader_ctx, sizeof(void *)); \
        LOG_OP("\ndelete last op\n");                           \
    } while (0)
#else /* else of WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS */
#define emit_label(opcode)                                                     \
    do {                                                                       \
        int32 offset =                                                         \
            (int32)((uint8 *)handle_table[opcode] - (uint8 *)handle_table[0]); \
        if (!(offset >= INT16_MIN && offset < INT16_MAX)) {                    \
            set_error_buf(error_buf, error_buf_size,                           \
                          "pre-compiled label offset out of range");           \
            goto fail;                                                         \
        }                                                                      \
        wasm_loader_emit_int16(loader_ctx, offset);                            \
        LOG_OP("\nemit_op [%02x]\t", opcode);                                  \
    } while (0)
#define skip_label()                                           \
    do {                                                       \
        wasm_loader_emit_backspace(loader_ctx, sizeof(int16)); \
        LOG_OP("\ndelete last op\n");                          \
    } while (0)
#endif /* end of WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS */
#else  /* else of WASM_ENABLE_LABELS_AS_VALUES */
#define emit_label(opcode)                          \
    do {                                            \
        wasm_loader_emit_uint8(loader_ctx, opcode); \
        LOG_OP("\nemit_op [%02x]\t", opcode);       \
    } while (0)
#define skip_label()                                           \
    do {                                                       \
        wasm_loader_emit_backspace(loader_ctx, sizeof(uint8)); \
        LOG_OP("\ndelete last op\n");                          \
    } while (0)
#endif /* end of WASM_ENABLE_LABELS_AS_VALUES */

#define emit_empty_label_addr_and_frame_ip(type)                             \
    do {                                                                     \
        if (!add_label_patch_to_list(loader_ctx->frame_csp - 1, type,        \
                                     loader_ctx->p_code_compiled, error_buf, \
                                     error_buf_size))                        \
            goto fail;                                                       \
        /* label address, to be patched */                                   \
        wasm_loader_emit_ptr(loader_ctx, NULL);                              \
    } while (0)

#define emit_br_info(frame_csp)                                         \
    do {                                                                \
        if (!wasm_loader_emit_br_info(loader_ctx, frame_csp, error_buf, \
                                      error_buf_size))                  \
            goto fail;                                                  \
    } while (0)

#define LAST_OP_OUTPUT_I32()                                                   \
    (last_op >= WASM_OP_I32_EQZ && last_op <= WASM_OP_I32_ROTR)                \
        || (last_op == WASM_OP_I32_LOAD || last_op == WASM_OP_F32_LOAD)        \
        || (last_op >= WASM_OP_I32_LOAD8_S && last_op <= WASM_OP_I32_LOAD16_U) \
        || (last_op >= WASM_OP_F32_ABS && last_op <= WASM_OP_F32_COPYSIGN)     \
        || (last_op >= WASM_OP_I32_WRAP_I64                                    \
            && last_op <= WASM_OP_I32_TRUNC_U_F64)                             \
        || (last_op >= WASM_OP_F32_CONVERT_S_I32                               \
            && last_op <= WASM_OP_F32_DEMOTE_F64)                              \
        || (last_op == WASM_OP_I32_REINTERPRET_F32)                            \
        || (last_op == WASM_OP_F32_REINTERPRET_I32)                            \
        || (last_op == EXT_OP_COPY_STACK_TOP)

#define LAST_OP_OUTPUT_I64()                                                   \
    (last_op >= WASM_OP_I64_CLZ && last_op <= WASM_OP_I64_ROTR)                \
        || (last_op >= WASM_OP_F64_ABS && last_op <= WASM_OP_F64_COPYSIGN)     \
        || (last_op == WASM_OP_I64_LOAD || last_op == WASM_OP_F64_LOAD)        \
        || (last_op >= WASM_OP_I64_LOAD8_S && last_op <= WASM_OP_I64_LOAD32_U) \
        || (last_op >= WASM_OP_I64_EXTEND_S_I32                                \
            && last_op <= WASM_OP_I64_TRUNC_U_F64)                             \
        || (last_op >= WASM_OP_F64_CONVERT_S_I32                               \
            && last_op <= WASM_OP_F64_PROMOTE_F32)                             \
        || (last_op == WASM_OP_I64_REINTERPRET_F64)                            \
        || (last_op == WASM_OP_F64_REINTERPRET_I64)                            \
        || (last_op == EXT_OP_COPY_STACK_TOP_I64)

#define GET_CONST_OFFSET(type, val)                                    \
    do {                                                               \
        if (!(wasm_loader_get_const_offset(loader_ctx, type, &val,     \
                                           &operand_offset, error_buf, \
                                           error_buf_size)))           \
            goto fail;                                                 \
    } while (0)

#define GET_CONST_F32_OFFSET(type, fval)                               \
    do {                                                               \
        if (!(wasm_loader_get_const_offset(loader_ctx, type, &fval,    \
                                           &operand_offset, error_buf, \
                                           error_buf_size)))           \
            goto fail;                                                 \
    } while (0)

#define GET_CONST_F64_OFFSET(type, fval)                               \
    do {                                                               \
        if (!(wasm_loader_get_const_offset(loader_ctx, type, &fval,    \
                                           &operand_offset, error_buf, \
                                           error_buf_size)))           \
            goto fail;                                                 \
    } while (0)

#define emit_operand(ctx, offset)            \
    do {                                     \
        wasm_loader_emit_int16(ctx, offset); \
        LOG_OP("%d\t", offset);              \
    } while (0)

#define emit_byte(ctx, byte)               \
    do {                                   \
        wasm_loader_emit_uint8(ctx, byte); \
        LOG_OP("%d\t", byte);              \
    } while (0)

#define emit_uint32(ctx, value)              \
    do {                                     \
        wasm_loader_emit_uint32(ctx, value); \
        LOG_OP("%d\t", value);               \
    } while (0)

#define emit_uint64(ctx, value)                     \
    do {                                            \
        wasm_loader_emit_const(ctx, &value, false); \
        LOG_OP("%lld\t", value);                    \
    } while (0)

#define emit_float32(ctx, value)                   \
    do {                                           \
        wasm_loader_emit_const(ctx, &value, true); \
        LOG_OP("%f\t", value);                     \
    } while (0)

#define emit_float64(ctx, value)                    \
    do {                                            \
        wasm_loader_emit_const(ctx, &value, false); \
        LOG_OP("%f\t", value);                      \
    } while (0)

static bool
wasm_loader_ctx_reinit(WASMLoaderContext *ctx)
{
    if (!(ctx->p_code_compiled =
              loader_malloc(ctx->code_compiled_peak_size, NULL, 0)))
        return false;
    ctx->p_code_compiled_end =
        ctx->p_code_compiled + ctx->code_compiled_peak_size;

    /* clean up frame ref */
    memset(ctx->frame_ref_bottom, 0, ctx->frame_ref_size);
    ctx->frame_ref = ctx->frame_ref_bottom;
    ctx->stack_cell_num = 0;

    /* clean up frame csp */
    memset(ctx->frame_csp_bottom, 0, ctx->frame_csp_size);
    ctx->frame_csp = ctx->frame_csp_bottom;
    ctx->csp_num = 0;
    ctx->max_csp_num = 0;

    /* clean up frame offset */
    memset(ctx->frame_offset_bottom, 0, ctx->frame_offset_size);
    ctx->frame_offset = ctx->frame_offset_bottom;
    ctx->dynamic_offset = ctx->start_dynamic_offset;

    /* init preserved local offsets */
    ctx->preserved_local_offset = ctx->max_dynamic_offset;

    /* const buf is reserved */
    return true;
}

static void
increase_compiled_code_space(WASMLoaderContext *ctx, int32 size)
{
    ctx->code_compiled_size += size;
    if (ctx->code_compiled_size >= ctx->code_compiled_peak_size) {
        ctx->code_compiled_peak_size = ctx->code_compiled_size;
    }
}

static void
wasm_loader_emit_const(WASMLoaderContext *ctx, void *value, bool is_32_bit)
{
    uint32 size = is_32_bit ? sizeof(uint32) : sizeof(uint64);

    if (ctx->p_code_compiled) {
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        bh_assert(((uintptr_t)ctx->p_code_compiled & 1) == 0);
#endif
        bh_memcpy_s(ctx->p_code_compiled,
                    (uint32)(ctx->p_code_compiled_end - ctx->p_code_compiled),
                    value, size);
        ctx->p_code_compiled += size;
    }
    else {
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        bh_assert((ctx->code_compiled_size & 1) == 0);
#endif
        increase_compiled_code_space(ctx, size);
    }
}

static void
wasm_loader_emit_uint32(WASMLoaderContext *ctx, uint32 value)
{
    if (ctx->p_code_compiled) {
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        bh_assert(((uintptr_t)ctx->p_code_compiled & 1) == 0);
#endif
        STORE_U32(ctx->p_code_compiled, value);
        ctx->p_code_compiled += sizeof(uint32);
    }
    else {
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        bh_assert((ctx->code_compiled_size & 1) == 0);
#endif
        increase_compiled_code_space(ctx, sizeof(uint32));
    }
}

static void
wasm_loader_emit_int16(WASMLoaderContext *ctx, int16 value)
{
    if (ctx->p_code_compiled) {
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        bh_assert(((uintptr_t)ctx->p_code_compiled & 1) == 0);
#endif
        STORE_U16(ctx->p_code_compiled, (uint16)value);
        ctx->p_code_compiled += sizeof(int16);
    }
    else {
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        bh_assert((ctx->code_compiled_size & 1) == 0);
#endif
        increase_compiled_code_space(ctx, sizeof(uint16));
    }
}

static void
wasm_loader_emit_uint8(WASMLoaderContext *ctx, uint8 value)
{
    if (ctx->p_code_compiled) {
        *(ctx->p_code_compiled) = value;
        ctx->p_code_compiled += sizeof(uint8);
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        ctx->p_code_compiled++;
        bh_assert(((uintptr_t)ctx->p_code_compiled & 1) == 0);
#endif
    }
    else {
        increase_compiled_code_space(ctx, sizeof(uint8));
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        increase_compiled_code_space(ctx, sizeof(uint8));
        bh_assert((ctx->code_compiled_size & 1) == 0);
#endif
    }
}

static void
wasm_loader_emit_ptr(WASMLoaderContext *ctx, void *value)
{
    if (ctx->p_code_compiled) {
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        bh_assert(((uintptr_t)ctx->p_code_compiled & 1) == 0);
#endif
        STORE_PTR(ctx->p_code_compiled, value);
        ctx->p_code_compiled += sizeof(void *);
    }
    else {
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        bh_assert((ctx->code_compiled_size & 1) == 0);
#endif
        increase_compiled_code_space(ctx, sizeof(void *));
    }
}

static void
wasm_loader_emit_backspace(WASMLoaderContext *ctx, uint32 size)
{
    if (ctx->p_code_compiled) {
        ctx->p_code_compiled -= size;
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        if (size == sizeof(uint8)) {
            ctx->p_code_compiled--;
            bh_assert(((uintptr_t)ctx->p_code_compiled & 1) == 0);
        }
#endif
    }
    else {
        ctx->code_compiled_size -= size;
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
        if (size == sizeof(uint8)) {
            ctx->code_compiled_size--;
            bh_assert((ctx->code_compiled_size & 1) == 0);
        }
#endif
    }
}

static bool
preserve_referenced_local(WASMLoaderContext *loader_ctx, uint8 opcode,
                          uint32 local_index, uint32 local_type,
                          bool *preserved, char *error_buf,
                          uint32 error_buf_size)
{
    uint32 i = 0;
    int16 preserved_offset = (int16)local_index;

    *preserved = false;
    while (i < loader_ctx->stack_cell_num) {
        uint8 cur_type = loader_ctx->frame_ref_bottom[i];

        /* move previous local into dynamic space before a set/tee_local opcode
         */
        if (loader_ctx->frame_offset_bottom[i] == (int16)local_index) {
            if (!(*preserved)) {
                *preserved = true;
                skip_label();
                preserved_offset = loader_ctx->preserved_local_offset;
                if (loader_ctx->p_code_compiled) {
                    bh_assert(preserved_offset != (int16)local_index);
                }
                if (is_32bit_type(local_type)) {
                    /* Only increase preserve offset in the second traversal */
                    if (loader_ctx->p_code_compiled)
                        loader_ctx->preserved_local_offset++;
                    emit_label(EXT_OP_COPY_STACK_TOP);
                }
                else {
                    if (loader_ctx->p_code_compiled)
                        loader_ctx->preserved_local_offset += 2;
                    emit_label(EXT_OP_COPY_STACK_TOP_I64);
                }
                emit_operand(loader_ctx, local_index);
                emit_operand(loader_ctx, preserved_offset);
                emit_label(opcode);
            }
            loader_ctx->frame_offset_bottom[i] = preserved_offset;
        }

        if (is_32bit_type(cur_type))
            i++;
        else
            i += 2;
    }

    return true;

#if WASM_ENABLE_LABELS_AS_VALUES != 0
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
fail:
    return false;
#endif
#endif
}

static bool
preserve_local_for_block(WASMLoaderContext *loader_ctx, uint8 opcode,
                         char *error_buf, uint32 error_buf_size)
{
    uint32 i = 0;
    bool preserve_local;

    /* preserve locals before blocks to ensure that "tee/set_local" inside
        blocks will not influence the value of these locals */
    while (i < loader_ctx->stack_cell_num) {
        int16 cur_offset = loader_ctx->frame_offset_bottom[i];
        uint8 cur_type = loader_ctx->frame_ref_bottom[i];

        if ((cur_offset < loader_ctx->start_dynamic_offset)
            && (cur_offset >= 0)) {
            if (!(preserve_referenced_local(loader_ctx, opcode, cur_offset,
                                            cur_type, &preserve_local,
                                            error_buf, error_buf_size)))
                return false;
        }

        if (is_32bit_type(cur_type == VALUE_TYPE_I32)) {
            i++;
        }
        else {
            i += 2;
        }
    }

    return true;
}

static bool
add_label_patch_to_list(BranchBlock *frame_csp, uint8 patch_type,
                        uint8 *p_code_compiled, char *error_buf,
                        uint32 error_buf_size)
{
    BranchBlockPatch *patch =
        loader_malloc(sizeof(BranchBlockPatch), error_buf, error_buf_size);
    if (!patch) {
        return false;
    }
    patch->patch_type = patch_type;
    patch->code_compiled = p_code_compiled;
    if (!frame_csp->patch_list) {
        frame_csp->patch_list = patch;
        patch->next = NULL;
    }
    else {
        patch->next = frame_csp->patch_list;
        frame_csp->patch_list = patch;
    }
    return true;
}

static void
apply_label_patch(WASMLoaderContext *ctx, uint8 depth, uint8 patch_type)
{
    BranchBlock *frame_csp = ctx->frame_csp - depth;
    BranchBlockPatch *node = frame_csp->patch_list;
    BranchBlockPatch *node_prev = NULL, *node_next;

    if (!ctx->p_code_compiled)
        return;

    while (node) {
        node_next = node->next;
        if (node->patch_type == patch_type) {
            STORE_PTR(node->code_compiled, ctx->p_code_compiled);
            if (node_prev == NULL) {
                frame_csp->patch_list = node_next;
            }
            else {
                node_prev->next = node_next;
            }
            wasm_runtime_free(node);
        }
        else {
            node_prev = node;
        }
        node = node_next;
    }
}

static bool
wasm_loader_emit_br_info(WASMLoaderContext *ctx, BranchBlock *frame_csp,
                         char *error_buf, uint32 error_buf_size)
{
    /* br info layout:
     *  a) arity of target block
     *  b) total cell num of arity values
     *  c) each arity value's cell num
     *  d) each arity value's src frame offset
     *  e) each arity values's dst dynamic offset
     *  f) branch target address
     *
     *  Note: b-e are omitted when arity is 0 so that
     *  interpreter can recover the br info quickly.
     */
    BlockType *block_type = &frame_csp->block_type;
    uint8 *types = NULL, cell;
    uint32 arity = 0;
    int32 i;
    int16 *frame_offset = ctx->frame_offset;
    uint16 dynamic_offset;

    /* Note: loop's arity is different from if and block. loop's arity is
     * its parameter count while if and block arity is result count.
     */
    if (frame_csp->label_type == LABEL_TYPE_LOOP)
        arity = block_type_get_param_types(block_type, &types);
    else
        arity = block_type_get_result_types(block_type, &types);

    /* Part a */
    emit_uint32(ctx, arity);

    if (arity) {
        /* Part b */
        emit_uint32(ctx, wasm_get_cell_num(types, arity));

        /* Part c */
        for (i = (int32)arity - 1; i >= 0; i--) {
            cell = (uint8)wasm_value_type_cell_num(types[i]);
            emit_byte(ctx, cell);
        }
        /* Part d */
        for (i = (int32)arity - 1; i >= 0; i--) {
            cell = (uint8)wasm_value_type_cell_num(types[i]);
            frame_offset -= cell;
            emit_operand(ctx, *(int16 *)(frame_offset));
        }
        /* Part e */
        dynamic_offset =
            frame_csp->dynamic_offset + wasm_get_cell_num(types, arity);
        for (i = (int32)arity - 1; i >= 0; i--) {
            cell = (uint8)wasm_value_type_cell_num(types[i]);
            dynamic_offset -= cell;
            emit_operand(ctx, dynamic_offset);
        }
    }

    /* Part f */
    if (frame_csp->label_type == LABEL_TYPE_LOOP) {
        wasm_loader_emit_ptr(ctx, frame_csp->code_compiled);
    }
    else {
        if (!add_label_patch_to_list(frame_csp, PATCH_END, ctx->p_code_compiled,
                                     error_buf, error_buf_size))
            return false;
        /* label address, to be patched */
        wasm_loader_emit_ptr(ctx, NULL);
    }

    return true;
}

static bool
wasm_loader_push_frame_offset(WASMLoaderContext *ctx, uint8 type,
                              bool disable_emit, int16 operand_offset,
                              char *error_buf, uint32 error_buf_size)
{
    if (type == VALUE_TYPE_VOID)
        return true;

    /* only check memory overflow in first traverse */
    if (ctx->p_code_compiled == NULL) {
        if (!check_offset_push(ctx, error_buf, error_buf_size))
            return false;
    }

    if (disable_emit)
        *(ctx->frame_offset)++ = operand_offset;
    else {
        emit_operand(ctx, ctx->dynamic_offset);
        *(ctx->frame_offset)++ = ctx->dynamic_offset;
        ctx->dynamic_offset++;
        if (ctx->dynamic_offset > ctx->max_dynamic_offset) {
            ctx->max_dynamic_offset = ctx->dynamic_offset;
            bh_assert(ctx->max_dynamic_offset < INT16_MAX);
        }
    }

    if (is_32bit_type(type))
        return true;

    if (ctx->p_code_compiled == NULL) {
        if (!check_offset_push(ctx, error_buf, error_buf_size))
            return false;
    }

    ctx->frame_offset++;
    if (!disable_emit) {
        ctx->dynamic_offset++;
        if (ctx->dynamic_offset > ctx->max_dynamic_offset) {
            ctx->max_dynamic_offset = ctx->dynamic_offset;
            bh_assert(ctx->max_dynamic_offset < INT16_MAX);
        }
    }
    return true;
}

/* This function should be in front of wasm_loader_pop_frame_ref
    as they both use ctx->stack_cell_num, and ctx->stack_cell_num
    will be modified by wasm_loader_pop_frame_ref */
static bool
wasm_loader_pop_frame_offset(WASMLoaderContext *ctx, uint8 type,
                             char *error_buf, uint32 error_buf_size)
{
    /* if ctx->frame_csp equals ctx->frame_csp_bottom,
        then current block is the function block */
    uint32 depth = ctx->frame_csp > ctx->frame_csp_bottom ? 1 : 0;
    BranchBlock *cur_block = ctx->frame_csp - depth;
    int32 available_stack_cell =
        (int32)(ctx->stack_cell_num - cur_block->stack_cell_num);

    /* Directly return success if current block is in stack
     * polymorphic state while stack is empty. */
    if (available_stack_cell <= 0 && cur_block->is_stack_polymorphic)
        return true;

    if (type == VALUE_TYPE_VOID)
        return true;

    if (is_32bit_type(type)) {
        /* Check the offset stack bottom to ensure the frame offset
            stack will not go underflow. But we don't thrown error
            and return true here, because the error msg should be
            given in wasm_loader_pop_frame_ref */
        if (!check_offset_pop(ctx, 1))
            return true;

        ctx->frame_offset -= 1;
        if ((*(ctx->frame_offset) > ctx->start_dynamic_offset)
            && (*(ctx->frame_offset) < ctx->max_dynamic_offset))
            ctx->dynamic_offset -= 1;
    }
    else {
        if (!check_offset_pop(ctx, 2))
            return true;

        ctx->frame_offset -= 2;
        if ((*(ctx->frame_offset) > ctx->start_dynamic_offset)
            && (*(ctx->frame_offset) < ctx->max_dynamic_offset))
            ctx->dynamic_offset -= 2;
    }
    emit_operand(ctx, *(ctx->frame_offset));
    return true;
}

static bool
wasm_loader_push_pop_frame_offset(WASMLoaderContext *ctx, uint8 pop_cnt,
                                  uint8 type_push, uint8 type_pop,
                                  bool disable_emit, int16 operand_offset,
                                  char *error_buf, uint32 error_buf_size)
{
    for (int i = 0; i < pop_cnt; i++) {
        if (!wasm_loader_pop_frame_offset(ctx, type_pop, error_buf,
                                          error_buf_size))
            return false;
    }
    if (!wasm_loader_push_frame_offset(ctx, type_push, disable_emit,
                                       operand_offset, error_buf,
                                       error_buf_size))
        return false;

    return true;
}

static bool
wasm_loader_push_frame_ref_offset(WASMLoaderContext *ctx, uint8 type,
                                  bool disable_emit, int16 operand_offset,
                                  char *error_buf, uint32 error_buf_size)
{
    if (!(wasm_loader_push_frame_offset(ctx, type, disable_emit, operand_offset,
                                        error_buf, error_buf_size)))
        return false;
    if (!(wasm_loader_push_frame_ref(ctx, type, error_buf, error_buf_size)))
        return false;

    return true;
}

static bool
wasm_loader_pop_frame_ref_offset(WASMLoaderContext *ctx, uint8 type,
                                 char *error_buf, uint32 error_buf_size)
{
    /* put wasm_loader_pop_frame_offset in front of wasm_loader_pop_frame_ref */
    if (!wasm_loader_pop_frame_offset(ctx, type, error_buf, error_buf_size))
        return false;
    if (!wasm_loader_pop_frame_ref(ctx, type, error_buf, error_buf_size))
        return false;

    return true;
}

static bool
wasm_loader_push_pop_frame_ref_offset(WASMLoaderContext *ctx, uint8 pop_cnt,
                                      uint8 type_push, uint8 type_pop,
                                      bool disable_emit, int16 operand_offset,
                                      char *error_buf, uint32 error_buf_size)
{
    if (!wasm_loader_push_pop_frame_offset(ctx, pop_cnt, type_push, type_pop,
                                           disable_emit, operand_offset,
                                           error_buf, error_buf_size))
        return false;
    if (!wasm_loader_push_pop_frame_ref(ctx, pop_cnt, type_push, type_pop,
                                        error_buf, error_buf_size))
        return false;

    return true;
}

static bool
wasm_loader_get_const_offset(WASMLoaderContext *ctx, uint8 type, void *value,
                             int16 *offset, char *error_buf,
                             uint32 error_buf_size)
{
    int8 bytes_to_increase;
    int16 operand_offset = 0;
    Const *c;

    /* Search existing constant */
    for (c = (Const *)ctx->const_buf;
         (uint8 *)c < ctx->const_buf + ctx->num_const * sizeof(Const); c++) {
        if ((type == c->value_type)
            && ((type == VALUE_TYPE_I64 && *(int64 *)value == c->value.i64)
                || (type == VALUE_TYPE_I32 && *(int32 *)value == c->value.i32)
#if WASM_ENABLE_REF_TYPES != 0
                || (type == VALUE_TYPE_FUNCREF
                    && *(int32 *)value == c->value.i32)
                || (type == VALUE_TYPE_EXTERNREF
                    && *(int32 *)value == c->value.i32)
#endif
                || (type == VALUE_TYPE_F64
                    && (0 == memcmp(value, &(c->value.f64), sizeof(float64))))
                || (type == VALUE_TYPE_F32
                    && (0
                        == memcmp(value, &(c->value.f32), sizeof(float32)))))) {
            operand_offset = c->slot_index;
            break;
        }
        if (c->value_type == VALUE_TYPE_I64 || c->value_type == VALUE_TYPE_F64)
            operand_offset += 2;
        else
            operand_offset += 1;
    }

    if ((uint8 *)c == ctx->const_buf + ctx->num_const * sizeof(Const)) {
        /* New constant, append to the const buffer */
        if ((type == VALUE_TYPE_F64) || (type == VALUE_TYPE_I64)) {
            bytes_to_increase = 2;
        }
        else {
            bytes_to_increase = 1;
        }

        /* The max cell num of const buffer is 32768 since the valid index range
         * is -32768 ~ -1. Return an invalid index 0 to indicate the buffer is
         * full */
        if (ctx->const_cell_num > INT16_MAX - bytes_to_increase + 1) {
            *offset = 0;
            return true;
        }

        if ((uint8 *)c == ctx->const_buf + ctx->const_buf_size) {
            MEM_REALLOC(ctx->const_buf, ctx->const_buf_size,
                        ctx->const_buf_size + 4 * sizeof(Const));
            ctx->const_buf_size += 4 * sizeof(Const);
            c = (Const *)(ctx->const_buf + ctx->num_const * sizeof(Const));
        }
        c->value_type = type;
        switch (type) {
            case VALUE_TYPE_F64:
                bh_memcpy_s(&(c->value.f64), sizeof(WASMValue), value,
                            sizeof(float64));
                ctx->const_cell_num += 2;
                /* The const buf will be reversed, we use the second cell */
                /* of the i64/f64 const so the finnal offset is corrent */
                operand_offset++;
                break;
            case VALUE_TYPE_I64:
                c->value.i64 = *(int64 *)value;
                ctx->const_cell_num += 2;
                operand_offset++;
                break;
            case VALUE_TYPE_F32:
                bh_memcpy_s(&(c->value.f32), sizeof(WASMValue), value,
                            sizeof(float32));
                ctx->const_cell_num++;
                break;
            case VALUE_TYPE_I32:
                c->value.i32 = *(int32 *)value;
                ctx->const_cell_num++;
                break;
#if WASM_ENABLE_REF_TYPES != 0
            case VALUE_TYPE_EXTERNREF:
            case VALUE_TYPE_FUNCREF:
                c->value.i32 = *(int32 *)value;
                ctx->const_cell_num++;
                break;
#endif
            default:
                break;
        }
        c->slot_index = operand_offset;
        ctx->num_const++;
        LOG_OP("#### new const [%d]: %ld\n", ctx->num_const,
               (int64)c->value.i64);
    }
    /* use negetive index for const */
    operand_offset = -(operand_offset + 1);
    *offset = operand_offset;
    return true;
fail:
    return false;
}

/*
    PUSH(POP)_XXX = push(pop) frame_ref + push(pop) frame_offset
    -- Mostly used for the binary / compare operation
    PUSH(POP)_OFFSET_TYPE only push(pop) the frame_offset stack
    -- Mostly used in block / control instructions

    The POP will always emit the offset on the top of the frame_offset stack
    PUSH can be used in two ways:
    1. directly PUSH:
            PUSH_XXX();
        will allocate a dynamic space and emit
    2. silent PUSH:
            operand_offset = xxx; disable_emit = true;
            PUSH_XXX();
        only push the frame_offset stack, no emit
*/
#define PUSH_I32()                                                           \
    do {                                                                     \
        if (!wasm_loader_push_frame_ref_offset(loader_ctx, VALUE_TYPE_I32,   \
                                               disable_emit, operand_offset, \
                                               error_buf, error_buf_size))   \
            goto fail;                                                       \
    } while (0)

#define PUSH_F32()                                                           \
    do {                                                                     \
        if (!wasm_loader_push_frame_ref_offset(loader_ctx, VALUE_TYPE_F32,   \
                                               disable_emit, operand_offset, \
                                               error_buf, error_buf_size))   \
            goto fail;                                                       \
    } while (0)

#define PUSH_I64()                                                           \
    do {                                                                     \
        if (!wasm_loader_push_frame_ref_offset(loader_ctx, VALUE_TYPE_I64,   \
                                               disable_emit, operand_offset, \
                                               error_buf, error_buf_size))   \
            goto fail;                                                       \
    } while (0)

#define PUSH_F64()                                                           \
    do {                                                                     \
        if (!wasm_loader_push_frame_ref_offset(loader_ctx, VALUE_TYPE_F64,   \
                                               disable_emit, operand_offset, \
                                               error_buf, error_buf_size))   \
            goto fail;                                                       \
    } while (0)

#define PUSH_FUNCREF()                                                         \
    do {                                                                       \
        if (!wasm_loader_push_frame_ref_offset(loader_ctx, VALUE_TYPE_FUNCREF, \
                                               disable_emit, operand_offset,   \
                                               error_buf, error_buf_size))     \
            goto fail;                                                         \
    } while (0)

#define POP_I32()                                                         \
    do {                                                                  \
        if (!wasm_loader_pop_frame_ref_offset(loader_ctx, VALUE_TYPE_I32, \
                                              error_buf, error_buf_size)) \
            goto fail;                                                    \
    } while (0)

#define POP_F32()                                                         \
    do {                                                                  \
        if (!wasm_loader_pop_frame_ref_offset(loader_ctx, VALUE_TYPE_F32, \
                                              error_buf, error_buf_size)) \
            goto fail;                                                    \
    } while (0)

#define POP_I64()                                                         \
    do {                                                                  \
        if (!wasm_loader_pop_frame_ref_offset(loader_ctx, VALUE_TYPE_I64, \
                                              error_buf, error_buf_size)) \
            goto fail;                                                    \
    } while (0)

#define POP_F64()                                                         \
    do {                                                                  \
        if (!wasm_loader_pop_frame_ref_offset(loader_ctx, VALUE_TYPE_F64, \
                                              error_buf, error_buf_size)) \
            goto fail;                                                    \
    } while (0)

#define PUSH_OFFSET_TYPE(type)                                              \
    do {                                                                    \
        if (!(wasm_loader_push_frame_offset(loader_ctx, type, disable_emit, \
                                            operand_offset, error_buf,      \
                                            error_buf_size)))               \
            goto fail;                                                      \
    } while (0)

#define POP_OFFSET_TYPE(type)                                           \
    do {                                                                \
        if (!(wasm_loader_pop_frame_offset(loader_ctx, type, error_buf, \
                                           error_buf_size)))            \
            goto fail;                                                  \
    } while (0)

#define POP_AND_PUSH(type_pop, type_push)                         \
    do {                                                          \
        if (!(wasm_loader_push_pop_frame_ref_offset(              \
                loader_ctx, 1, type_push, type_pop, disable_emit, \
                operand_offset, error_buf, error_buf_size)))      \
            goto fail;                                            \
    } while (0)

/* type of POPs should be the same */
#define POP2_AND_PUSH(type_pop, type_push)                        \
    do {                                                          \
        if (!(wasm_loader_push_pop_frame_ref_offset(              \
                loader_ctx, 2, type_push, type_pop, disable_emit, \
                operand_offset, error_buf, error_buf_size)))      \
            goto fail;                                            \
    } while (0)

#else /* WASM_ENABLE_FAST_INTERP */

#define PUSH_I32()                                                    \
    do {                                                              \
        if (!(wasm_loader_push_frame_ref(loader_ctx, VALUE_TYPE_I32,  \
                                         error_buf, error_buf_size))) \
            goto fail;                                                \
    } while (0)

#define PUSH_F32()                                                    \
    do {                                                              \
        if (!(wasm_loader_push_frame_ref(loader_ctx, VALUE_TYPE_F32,  \
                                         error_buf, error_buf_size))) \
            goto fail;                                                \
    } while (0)

#define PUSH_I64()                                                    \
    do {                                                              \
        if (!(wasm_loader_push_frame_ref(loader_ctx, VALUE_TYPE_I64,  \
                                         error_buf, error_buf_size))) \
            goto fail;                                                \
    } while (0)

#define PUSH_F64()                                                    \
    do {                                                              \
        if (!(wasm_loader_push_frame_ref(loader_ctx, VALUE_TYPE_F64,  \
                                         error_buf, error_buf_size))) \
            goto fail;                                                \
    } while (0)

#define PUSH_FUNCREF()                                                   \
    do {                                                                 \
        if (!(wasm_loader_push_frame_ref(loader_ctx, VALUE_TYPE_FUNCREF, \
                                         error_buf, error_buf_size)))    \
            goto fail;                                                   \
    } while (0)

#define POP_I32()                                                              \
    do {                                                                       \
        if (!(wasm_loader_pop_frame_ref(loader_ctx, VALUE_TYPE_I32, error_buf, \
                                        error_buf_size)))                      \
            goto fail;                                                         \
    } while (0)

#define POP_F32()                                                              \
    do {                                                                       \
        if (!(wasm_loader_pop_frame_ref(loader_ctx, VALUE_TYPE_F32, error_buf, \
                                        error_buf_size)))                      \
            goto fail;                                                         \
    } while (0)

#define POP_I64()                                                              \
    do {                                                                       \
        if (!(wasm_loader_pop_frame_ref(loader_ctx, VALUE_TYPE_I64, error_buf, \
                                        error_buf_size)))                      \
            goto fail;                                                         \
    } while (0)

#define POP_F64()                                                              \
    do {                                                                       \
        if (!(wasm_loader_pop_frame_ref(loader_ctx, VALUE_TYPE_F64, error_buf, \
                                        error_buf_size)))                      \
            goto fail;                                                         \
    } while (0)

#define POP_FUNCREF()                                                   \
    do {                                                                \
        if (!(wasm_loader_pop_frame_ref(loader_ctx, VALUE_TYPE_FUNCREF, \
                                        error_buf, error_buf_size)))    \
            goto fail;                                                  \
    } while (0)

#define POP_AND_PUSH(type_pop, type_push)                              \
    do {                                                               \
        if (!(wasm_loader_push_pop_frame_ref(loader_ctx, 1, type_push, \
                                             type_pop, error_buf,      \
                                             error_buf_size)))         \
            goto fail;                                                 \
    } while (0)

/* type of POPs should be the same */
#define POP2_AND_PUSH(type_pop, type_push)                             \
    do {                                                               \
        if (!(wasm_loader_push_pop_frame_ref(loader_ctx, 2, type_push, \
                                             type_pop, error_buf,      \
                                             error_buf_size)))         \
            goto fail;                                                 \
    } while (0)
#endif /* WASM_ENABLE_FAST_INTERP */

#if WASM_ENABLE_FAST_INTERP != 0

static bool
reserve_block_ret(WASMLoaderContext *loader_ctx, uint8 opcode,
                  bool disable_emit, char *error_buf, uint32 error_buf_size)
{
    int16 operand_offset = 0;
    BranchBlock *block = (opcode == WASM_OP_ELSE) ? loader_ctx->frame_csp - 1
                                                  : loader_ctx->frame_csp;
    BlockType *block_type = &block->block_type;
    uint8 *return_types = NULL;
    uint32 return_count = 0, value_count = 0, total_cel_num = 0;
    int32 i = 0;
    int16 dynamic_offset, dynamic_offset_org, *frame_offset = NULL,
                                              *frame_offset_org = NULL;

    return_count = block_type_get_result_types(block_type, &return_types);

    /* If there is only one return value, use EXT_OP_COPY_STACK_TOP/_I64 instead
     * of EXT_OP_COPY_STACK_VALUES for interpreter performance. */
    if (return_count == 1) {
        uint8 cell = (uint8)wasm_value_type_cell_num(return_types[0]);
        if (cell <= 2 /* V128 isn't supported whose cell num is 4 */
            && block->dynamic_offset != *(loader_ctx->frame_offset - cell)) {
            /* insert op_copy before else opcode */
            if (opcode == WASM_OP_ELSE)
                skip_label();
            emit_label(cell == 1 ? EXT_OP_COPY_STACK_TOP
                                 : EXT_OP_COPY_STACK_TOP_I64);
            emit_operand(loader_ctx, *(loader_ctx->frame_offset - cell));
            emit_operand(loader_ctx, block->dynamic_offset);

            if (opcode == WASM_OP_ELSE) {
                *(loader_ctx->frame_offset - cell) = block->dynamic_offset;
            }
            else {
                loader_ctx->frame_offset -= cell;
                loader_ctx->dynamic_offset = block->dynamic_offset;
                PUSH_OFFSET_TYPE(return_types[0]);
                wasm_loader_emit_backspace(loader_ctx, sizeof(int16));
            }
            if (opcode == WASM_OP_ELSE)
                emit_label(opcode);
        }
        return true;
    }

    /* Copy stack top values to block's results which are in dynamic space.
     * The instruction format:
     *   Part a: values count
     *   Part b: all values total cell num
     *   Part c: each value's cell_num, src offset and dst offset
     *   Part d: each value's src offset and dst offset
     *   Part e: each value's dst offset
     */
    frame_offset = frame_offset_org = loader_ctx->frame_offset;
    dynamic_offset = dynamic_offset_org =
        block->dynamic_offset + wasm_get_cell_num(return_types, return_count);

    /* First traversal to get the count of values needed to be copied. */
    for (i = (int32)return_count - 1; i >= 0; i--) {
        uint8 cells = (uint8)wasm_value_type_cell_num(return_types[i]);

        frame_offset -= cells;
        dynamic_offset -= cells;
        if (dynamic_offset != *frame_offset) {
            value_count++;
            total_cel_num += cells;
        }
    }

    if (value_count) {
        uint32 j = 0;
        uint8 *emit_data = NULL, *cells = NULL;
        int16 *src_offsets = NULL;
        uint16 *dst_offsets = NULL;
        uint64 size =
            (uint64)value_count
            * (sizeof(*cells) + sizeof(*src_offsets) + sizeof(*dst_offsets));

        /* Allocate memory for the emit data */
        if (!(emit_data = loader_malloc(size, error_buf, error_buf_size)))
            return false;

        cells = emit_data;
        src_offsets = (int16 *)(cells + value_count);
        dst_offsets = (uint16 *)(src_offsets + value_count);

        /* insert op_copy before else opcode */
        if (opcode == WASM_OP_ELSE)
            skip_label();
        emit_label(EXT_OP_COPY_STACK_VALUES);
        /* Part a) */
        emit_uint32(loader_ctx, value_count);
        /* Part b) */
        emit_uint32(loader_ctx, total_cel_num);

        /* Second traversal to get each value's cell num,  src offset and dst
         * offset. */
        frame_offset = frame_offset_org;
        dynamic_offset = dynamic_offset_org;
        for (i = (int32)return_count - 1, j = 0; i >= 0; i--) {
            uint8 cell = (uint8)wasm_value_type_cell_num(return_types[i]);
            frame_offset -= cell;
            dynamic_offset -= cell;
            if (dynamic_offset != *frame_offset) {
                /* cell num */
                cells[j] = cell;
                /* src offset */
                src_offsets[j] = *frame_offset;
                /* dst offset */
                dst_offsets[j] = dynamic_offset;
                j++;
            }
            if (opcode == WASM_OP_ELSE) {
                *frame_offset = dynamic_offset;
            }
            else {
                loader_ctx->frame_offset = frame_offset;
                loader_ctx->dynamic_offset = dynamic_offset;
                PUSH_OFFSET_TYPE(return_types[i]);
                wasm_loader_emit_backspace(loader_ctx, sizeof(int16));
                loader_ctx->frame_offset = frame_offset_org;
                loader_ctx->dynamic_offset = dynamic_offset_org;
            }
        }

        bh_assert(j == value_count);

        /* Emit the cells, src_offsets and dst_offsets */
        for (j = 0; j < value_count; j++)
            emit_byte(loader_ctx, cells[j]);
        for (j = 0; j < value_count; j++)
            emit_operand(loader_ctx, src_offsets[j]);
        for (j = 0; j < value_count; j++)
            emit_operand(loader_ctx, dst_offsets[j]);

        if (opcode == WASM_OP_ELSE)
            emit_label(opcode);

        wasm_runtime_free(emit_data);
    }

    return true;

fail:
    return false;
}

#endif /* WASM_ENABLE_FAST_INTERP */

#define RESERVE_BLOCK_RET()                                                 \
    do {                                                                    \
        if (!reserve_block_ret(loader_ctx, opcode, disable_emit, error_buf, \
                               error_buf_size))                             \
            goto fail;                                                      \
    } while (0)

#define PUSH_TYPE(type)                                               \
    do {                                                              \
        if (!(wasm_loader_push_frame_ref(loader_ctx, type, error_buf, \
                                         error_buf_size)))            \
            goto fail;                                                \
    } while (0)

#define POP_TYPE(type)                                               \
    do {                                                             \
        if (!(wasm_loader_pop_frame_ref(loader_ctx, type, error_buf, \
                                        error_buf_size)))            \
            goto fail;                                               \
    } while (0)

#define PUSH_CSP(label_type, block_type, _start_addr)                       \
    do {                                                                    \
        if (!wasm_loader_push_frame_csp(loader_ctx, label_type, block_type, \
                                        _start_addr, error_buf,             \
                                        error_buf_size))                    \
            goto fail;                                                      \
    } while (0)

#define POP_CSP()                                                              \
    do {                                                                       \
        if (!wasm_loader_pop_frame_csp(loader_ctx, error_buf, error_buf_size)) \
            goto fail;                                                         \
    } while (0)

#define GET_LOCAL_INDEX_TYPE_AND_OFFSET()                        \
    do {                                                         \
        read_leb_uint32(p, p_end, local_idx);                    \
        bh_assert(local_idx < param_count + local_count);        \
        local_type = local_idx < param_count                     \
                         ? param_types[local_idx]                \
                         : local_types[local_idx - param_count]; \
        local_offset = local_offsets[local_idx];                 \
    } while (0)

#define CHECK_BR(depth)                                         \
    do {                                                        \
        if (!wasm_loader_check_br(loader_ctx, depth, error_buf, \
                                  error_buf_size))              \
            goto fail;                                          \
    } while (0)

#define CHECK_MEMORY()                                                     \
    do {                                                                   \
        bh_assert(module->import_memory_count + module->memory_count > 0); \
    } while (0)

static bool
wasm_loader_check_br(WASMLoaderContext *loader_ctx, uint32 depth,
                     char *error_buf, uint32 error_buf_size)
{
    BranchBlock *target_block, *cur_block;
    BlockType *target_block_type;
    uint8 *types = NULL, *frame_ref;
    uint32 arity = 0;
    int32 i, available_stack_cell;
    uint16 cell_num;

    if (loader_ctx->csp_num < depth + 1) {
        set_error_buf(error_buf, error_buf_size,
                      "unknown label, "
                      "unexpected end of section or function");
        return false;
    }

    cur_block = loader_ctx->frame_csp - 1;
    target_block = loader_ctx->frame_csp - (depth + 1);
    target_block_type = &target_block->block_type;
    frame_ref = loader_ctx->frame_ref;

    /* Note: loop's arity is different from if and block. loop's arity is
     * its parameter count while if and block arity is result count.
     */
    if (target_block->label_type == LABEL_TYPE_LOOP)
        arity = block_type_get_param_types(target_block_type, &types);
    else
        arity = block_type_get_result_types(target_block_type, &types);

    /* If the stack is in polymorphic state, just clear the stack
     * and then re-push the values to make the stack top values
     * match block type. */
    if (cur_block->is_stack_polymorphic) {
        for (i = (int32)arity - 1; i >= 0; i--) {
#if WASM_ENABLE_FAST_INTERP != 0
            POP_OFFSET_TYPE(types[i]);
#endif
            POP_TYPE(types[i]);
        }
        for (i = 0; i < (int32)arity; i++) {
#if WASM_ENABLE_FAST_INTERP != 0
            bool disable_emit = true;
            int16 operand_offset = 0;
            PUSH_OFFSET_TYPE(types[i]);
#endif
            PUSH_TYPE(types[i]);
        }
        return true;
    }

    available_stack_cell =
        (int32)(loader_ctx->stack_cell_num - cur_block->stack_cell_num);

    /* Check stack top values match target block type */
    for (i = (int32)arity - 1; i >= 0; i--) {
        if (!check_stack_top_values(frame_ref, available_stack_cell, types[i],
                                    error_buf, error_buf_size))
            return false;
        cell_num = wasm_value_type_cell_num(types[i]);
        frame_ref -= cell_num;
        available_stack_cell -= cell_num;
    }

    return true;

fail:
    return false;
}

static BranchBlock *
check_branch_block(WASMLoaderContext *loader_ctx, uint8 **p_buf, uint8 *buf_end,
                   char *error_buf, uint32 error_buf_size)
{
    uint8 *p = *p_buf, *p_end = buf_end;
    BranchBlock *frame_csp_tmp;
    uint32 depth;

    read_leb_uint32(p, p_end, depth);
    CHECK_BR(depth);
    frame_csp_tmp = loader_ctx->frame_csp - depth - 1;
#if WASM_ENABLE_FAST_INTERP != 0
    emit_br_info(frame_csp_tmp);
#endif

    *p_buf = p;
    return frame_csp_tmp;
fail:
    return NULL;
}

static bool
check_block_stack(WASMLoaderContext *loader_ctx, BranchBlock *block,
                  char *error_buf, uint32 error_buf_size)
{
    BlockType *block_type = &block->block_type;
    uint8 *return_types = NULL;
    uint32 return_count = 0;
    int32 available_stack_cell, return_cell_num, i;
    uint8 *frame_ref = NULL;

    available_stack_cell =
        (int32)(loader_ctx->stack_cell_num - block->stack_cell_num);

    return_count = block_type_get_result_types(block_type, &return_types);
    return_cell_num =
        return_count > 0 ? wasm_get_cell_num(return_types, return_count) : 0;

    /* If the stack is in polymorphic state, just clear the stack
     * and then re-push the values to make the stack top values
     * match block type. */
    if (block->is_stack_polymorphic) {
        for (i = (int32)return_count - 1; i >= 0; i--) {
#if WASM_ENABLE_FAST_INTERP != 0
            POP_OFFSET_TYPE(return_types[i]);
#endif
            POP_TYPE(return_types[i]);
        }

        /* Check stack is empty */
        bh_assert(loader_ctx->stack_cell_num == block->stack_cell_num);

        for (i = 0; i < (int32)return_count; i++) {
#if WASM_ENABLE_FAST_INTERP != 0
            bool disable_emit = true;
            int16 operand_offset = 0;
            PUSH_OFFSET_TYPE(return_types[i]);
#endif
            PUSH_TYPE(return_types[i]);
        }
        return true;
    }

    /* Check stack cell num equals return cell num */
    bh_assert(available_stack_cell == return_cell_num);

    /* Check stack values match return types */
    frame_ref = loader_ctx->frame_ref;
    for (i = (int32)return_count - 1; i >= 0; i--) {
        if (!check_stack_top_values(frame_ref, available_stack_cell,
                                    return_types[i], error_buf, error_buf_size))
            return false;
        frame_ref -= wasm_value_type_cell_num(return_types[i]);
        available_stack_cell -= wasm_value_type_cell_num(return_types[i]);
    }

    (void)return_cell_num;
    return true;

fail:
    return false;
}

#if WASM_ENABLE_FAST_INTERP != 0
/* Copy parameters to dynamic space.
 * 1) POP original parameter out;
 * 2) Push and copy original values to dynamic space.
 * The copy instruction format:
 *   Part a: param count
 *   Part b: all param total cell num
 *   Part c: each param's cell_num, src offset and dst offset
 *   Part d: each param's src offset
 *   Part e: each param's dst offset
 */
static bool
copy_params_to_dynamic_space(WASMLoaderContext *loader_ctx, bool is_if_block,
                             char *error_buf, uint32 error_buf_size)
{
    int16 *frame_offset = NULL;
    uint8 *cells = NULL, cell;
    int16 *src_offsets = NULL;
    uint8 *emit_data = NULL;
    uint32 i;
    BranchBlock *block = loader_ctx->frame_csp - 1;
    BlockType *block_type = &block->block_type;
    WASMType *wasm_type = block_type->u.type;
    uint32 param_count = block_type->u.type->param_count;
    int16 condition_offset = 0;
    bool disable_emit = false;
    int16 operand_offset = 0;

    uint64 size = (uint64)param_count * (sizeof(*cells) + sizeof(*src_offsets));

    /* For if block, we also need copy the condition operand offset. */
    if (is_if_block)
        size += sizeof(*cells) + sizeof(*src_offsets);

    /* Allocate memory for the emit data */
    if (!(emit_data = loader_malloc(size, error_buf, error_buf_size)))
        return false;

    cells = emit_data;
    src_offsets = (int16 *)(cells + param_count);

    if (is_if_block)
        condition_offset = *loader_ctx->frame_offset;

    /* POP original parameter out */
    for (i = 0; i < param_count; i++) {
        POP_OFFSET_TYPE(wasm_type->types[param_count - i - 1]);
        wasm_loader_emit_backspace(loader_ctx, sizeof(int16));
    }
    frame_offset = loader_ctx->frame_offset;

    /* Get each param's cell num and src offset */
    for (i = 0; i < param_count; i++) {
        cell = (uint8)wasm_value_type_cell_num(wasm_type->types[i]);
        cells[i] = cell;
        src_offsets[i] = *frame_offset;
        frame_offset += cell;
    }

    /* emit copy instruction */
    emit_label(EXT_OP_COPY_STACK_VALUES);
    /* Part a) */
    emit_uint32(loader_ctx, is_if_block ? param_count + 1 : param_count);
    /* Part b) */
    emit_uint32(loader_ctx, is_if_block ? wasm_type->param_cell_num + 1
                                        : wasm_type->param_cell_num);
    /* Part c) */
    for (i = 0; i < param_count; i++)
        emit_byte(loader_ctx, cells[i]);
    if (is_if_block)
        emit_byte(loader_ctx, 1);

    /* Part d) */
    for (i = 0; i < param_count; i++)
        emit_operand(loader_ctx, src_offsets[i]);
    if (is_if_block)
        emit_operand(loader_ctx, condition_offset);

    /* Part e) */
    /* Push to dynamic space. The push will emit the dst offset. */
    for (i = 0; i < param_count; i++)
        PUSH_OFFSET_TYPE(wasm_type->types[i]);
    if (is_if_block)
        PUSH_OFFSET_TYPE(VALUE_TYPE_I32);

    /* Free the emit data */
    wasm_runtime_free(emit_data);

    return true;

fail:
    return false;
}
#endif

/* reset the stack to the state of before entering the last block */
#if WASM_ENABLE_FAST_INTERP != 0
#define RESET_STACK()                                                     \
    do {                                                                  \
        loader_ctx->stack_cell_num =                                      \
            (loader_ctx->frame_csp - 1)->stack_cell_num;                  \
        loader_ctx->frame_ref =                                           \
            loader_ctx->frame_ref_bottom + loader_ctx->stack_cell_num;    \
        loader_ctx->frame_offset =                                        \
            loader_ctx->frame_offset_bottom + loader_ctx->stack_cell_num; \
    } while (0)
#else
#define RESET_STACK()                                                  \
    do {                                                               \
        loader_ctx->stack_cell_num =                                   \
            (loader_ctx->frame_csp - 1)->stack_cell_num;               \
        loader_ctx->frame_ref =                                        \
            loader_ctx->frame_ref_bottom + loader_ctx->stack_cell_num; \
    } while (0)
#endif

/* set current block's stack polymorphic state */
#define SET_CUR_BLOCK_STACK_POLYMORPHIC_STATE(flag)          \
    do {                                                     \
        BranchBlock *_cur_block = loader_ctx->frame_csp - 1; \
        _cur_block->is_stack_polymorphic = flag;             \
    } while (0)

#define BLOCK_HAS_PARAM(block_type) \
    (!block_type.is_value_type && block_type.u.type->param_count > 0)

#define PRESERVE_LOCAL_FOR_BLOCK()                                    \
    do {                                                              \
        if (!(preserve_local_for_block(loader_ctx, opcode, error_buf, \
                                       error_buf_size))) {            \
            goto fail;                                                \
        }                                                             \
    } while (0)

static bool
wasm_loader_prepare_bytecode(WASMModule *module, WASMFunction *func,
                             uint32 cur_func_idx, char *error_buf,
                             uint32 error_buf_size)
{
    uint8 *p = func->code, *p_end = func->code + func->code_size, *p_org;
    uint32 param_count, local_count, global_count;
    uint8 *param_types, *local_types, local_type, global_type;
    BlockType func_block_type;
    uint16 *local_offsets, local_offset;
    uint32 count, local_idx, global_idx, u32, align, mem_offset, i;
    int32 i32, i32_const = 0;
    int64 i64_const;
    uint8 opcode, u8;
    bool return_value = false;
    WASMLoaderContext *loader_ctx;
    BranchBlock *frame_csp_tmp;
#if WASM_ENABLE_BULK_MEMORY != 0
    uint32 segment_index;
#endif
#if WASM_ENABLE_FAST_INTERP != 0
    uint8 *func_const_end, *func_const = NULL;
    int16 operand_offset = 0;
    uint8 last_op = 0;
    bool disable_emit, preserve_local = false;
    float32 f32_const;
    float64 f64_const;

    LOG_OP("\nProcessing func | [%d] params | [%d] locals | [%d] return\n",
           func->param_cell_num, func->local_cell_num, func->ret_cell_num);
#endif

    global_count = module->import_global_count + module->global_count;

    param_count = func->func_type->param_count;
    param_types = func->func_type->types;

    func_block_type.is_value_type = false;
    func_block_type.u.type = func->func_type;

    local_count = func->local_count;
    local_types = func->local_types;
    local_offsets = func->local_offsets;

    if (!(loader_ctx = wasm_loader_ctx_init(func, error_buf, error_buf_size))) {
        goto fail;
    }

#if WASM_ENABLE_FAST_INTERP != 0
    /* For the first traverse, the initial value of preserved_local_offset has
     * not been determined, we use the INT16_MAX to represent that a slot has
     * been copied to preserve space. For second traverse, this field will be
     * set to the appropriate value in wasm_loader_ctx_reinit.
     * This is for Issue #1230,
     * https://github.com/bytecodealliance/wasm-micro-runtime/issues/1230, the
     * drop opcodes need to know which slots are preserved, so those slots will
     * not be treated as dynamically allocated slots */
    loader_ctx->preserved_local_offset = INT16_MAX;

re_scan:
    if (loader_ctx->code_compiled_size > 0) {
        if (!wasm_loader_ctx_reinit(loader_ctx)) {
            set_error_buf(error_buf, error_buf_size, "allocate memory failed");
            goto fail;
        }
        p = func->code;
        func->code_compiled = loader_ctx->p_code_compiled;
        func->code_compiled_size = loader_ctx->code_compiled_size;
    }
#endif

    PUSH_CSP(LABEL_TYPE_FUNCTION, func_block_type, p);

    while (p < p_end) {
        opcode = *p++;
#if WASM_ENABLE_FAST_INTERP != 0
        p_org = p;
        disable_emit = false;
        emit_label(opcode);
#endif

        switch (opcode) {
            case WASM_OP_UNREACHABLE:
                RESET_STACK();
                SET_CUR_BLOCK_STACK_POLYMORPHIC_STATE(true);
                break;

            case WASM_OP_NOP:
#if WASM_ENABLE_FAST_INTERP != 0
                skip_label();
#endif
                break;

            case WASM_OP_IF:
#if WASM_ENABLE_FAST_INTERP != 0
                PRESERVE_LOCAL_FOR_BLOCK();
#endif
                POP_I32();
                goto handle_op_block_and_loop;
            case WASM_OP_BLOCK:
            case WASM_OP_LOOP:
#if WASM_ENABLE_FAST_INTERP != 0
                PRESERVE_LOCAL_FOR_BLOCK();
#endif
            handle_op_block_and_loop:
            {
                uint8 value_type;
                BlockType block_type;

                p_org = p - 1;
                value_type = read_uint8(p);
                if (is_byte_a_type(value_type)) {
                    /* If the first byte is one of these special values:
                     * 0x40/0x7F/0x7E/0x7D/0x7C, take it as the type of
                     * the single return value. */
                    block_type.is_value_type = true;
                    block_type.u.value_type = value_type;
                }
                else {
                    uint32 type_index;
                    /* Resolve the leb128 encoded type index as block type */
                    p--;
                    read_leb_uint32(p, p_end, type_index);
                    bh_assert(type_index < module->type_count);
                    block_type.is_value_type = false;
                    block_type.u.type = module->types[type_index];
#if WASM_ENABLE_FAST_INTERP == 0 && WASM_ENABLE_WAMR_COMPILER == 0 \
    && WASM_ENABLE_JIT == 0
                    /* If block use type index as block type, change the opcode
                     * to new extended opcode so that interpreter can resolve
                     * the block quickly.
                     */
                    *p_org = EXT_OP_BLOCK + (opcode - WASM_OP_BLOCK);
#endif
                }

                /* Pop block parameters from stack */
                if (BLOCK_HAS_PARAM(block_type)) {
                    WASMType *wasm_type = block_type.u.type;
                    for (i = 0; i < block_type.u.type->param_count; i++)
                        POP_TYPE(
                            wasm_type->types[wasm_type->param_count - i - 1]);
                }

                PUSH_CSP(LABEL_TYPE_BLOCK + (opcode - WASM_OP_BLOCK),
                         block_type, p);

                /* Pass parameters to block */
                if (BLOCK_HAS_PARAM(block_type)) {
                    for (i = 0; i < block_type.u.type->param_count; i++)
                        PUSH_TYPE(block_type.u.type->types[i]);
                }

#if WASM_ENABLE_FAST_INTERP != 0
                if (opcode == WASM_OP_BLOCK) {
                    skip_label();
                }
                else if (opcode == WASM_OP_LOOP) {
                    skip_label();
                    if (BLOCK_HAS_PARAM(block_type)) {
                        /* Make sure params are in dynamic space */
                        if (!copy_params_to_dynamic_space(
                                loader_ctx, false, error_buf, error_buf_size))
                            goto fail;
                    }
                    (loader_ctx->frame_csp - 1)->code_compiled =
                        loader_ctx->p_code_compiled;
                }
                else if (opcode == WASM_OP_IF) {
                    /* If block has parameters, we should make sure they are in
                     * dynamic space. Otherwise, when else branch is missing,
                     * the later opcode may consume incorrect operand offset.
                     * Spec case:
                     *   (func (export "params-id") (param i32) (result i32)
                     *       (i32.const 1)
                     *       (i32.const 2)
                     *       (if (param i32 i32) (result i32 i32) (local.get 0)
                     * (then)) (i32.add)
                     *   )
                     *
                     * So we should emit a copy instruction before the if.
                     *
                     * And we also need to save the parameter offsets and
                     * recover them before entering else branch.
                     *
                     */
                    if (BLOCK_HAS_PARAM(block_type)) {
                        BranchBlock *block = loader_ctx->frame_csp - 1;
                        uint64 size;

                        /* skip the if condition operand offset */
                        wasm_loader_emit_backspace(loader_ctx, sizeof(int16));
                        /* skip the if label */
                        skip_label();
                        /* Emit a copy instruction */
                        if (!copy_params_to_dynamic_space(
                                loader_ctx, true, error_buf, error_buf_size))
                            goto fail;

                        /* Emit the if instruction */
                        emit_label(opcode);
                        /* Emit the new condition operand offset */
                        POP_OFFSET_TYPE(VALUE_TYPE_I32);

                        /* Save top param_count values of frame_offset stack, so
                         * that we can recover it before executing else branch
                         */
                        size = sizeof(int16)
                               * (uint64)block_type.u.type->param_cell_num;
                        if (!(block->param_frame_offsets = loader_malloc(
                                  size, error_buf, error_buf_size)))
                            goto fail;
                        bh_memcpy_s(block->param_frame_offsets, (uint32)size,
                                    loader_ctx->frame_offset
                                        - size / sizeof(int16),
                                    (uint32)size);
                    }

                    emit_empty_label_addr_and_frame_ip(PATCH_ELSE);
                    emit_empty_label_addr_and_frame_ip(PATCH_END);
                }
#endif
                break;
            }

            case WASM_OP_ELSE:
            {
                BlockType block_type = (loader_ctx->frame_csp - 1)->block_type;
                bh_assert(loader_ctx->csp_num >= 2
                          && (loader_ctx->frame_csp - 1)->label_type
                                 == LABEL_TYPE_IF);

                /* check whether if branch's stack matches its result type */
                if (!check_block_stack(loader_ctx, loader_ctx->frame_csp - 1,
                                       error_buf, error_buf_size))
                    goto fail;

                (loader_ctx->frame_csp - 1)->else_addr = p - 1;

#if WASM_ENABLE_FAST_INTERP != 0
                /* if the result of if branch is in local or const area, add a
                 * copy op */
                RESERVE_BLOCK_RET();

                emit_empty_label_addr_and_frame_ip(PATCH_END);
                apply_label_patch(loader_ctx, 1, PATCH_ELSE);
#endif
                RESET_STACK();
                SET_CUR_BLOCK_STACK_POLYMORPHIC_STATE(false);

                /* Pass parameters to if-false branch */
                if (BLOCK_HAS_PARAM(block_type)) {
                    for (i = 0; i < block_type.u.type->param_count; i++)
                        PUSH_TYPE(block_type.u.type->types[i]);
                }

#if WASM_ENABLE_FAST_INTERP != 0
                /* Recover top param_count values of frame_offset stack */
                if (BLOCK_HAS_PARAM((block_type))) {
                    uint32 size;
                    BranchBlock *block = loader_ctx->frame_csp - 1;
                    size = sizeof(int16) * block_type.u.type->param_cell_num;
                    bh_memcpy_s(loader_ctx->frame_offset, size,
                                block->param_frame_offsets, size);
                    loader_ctx->frame_offset += (size / sizeof(int16));
                }
#endif

                break;
            }

            case WASM_OP_END:
            {
                BranchBlock *cur_block = loader_ctx->frame_csp - 1;

                /* check whether block stack matches its result type */
                if (!check_block_stack(loader_ctx, cur_block, error_buf,
                                       error_buf_size))
                    goto fail;

                /* if no else branch, and return types do not match param types,
                 * fail */
                if (cur_block->label_type == LABEL_TYPE_IF
                    && !cur_block->else_addr) {
                    uint32 block_param_count = 0, block_ret_count = 0;
                    uint8 *block_param_types = NULL, *block_ret_types = NULL;
                    BlockType *cur_block_type = &cur_block->block_type;
                    if (cur_block_type->is_value_type) {
                        if (cur_block_type->u.value_type != VALUE_TYPE_VOID) {
                            block_ret_count = 1;
                            block_ret_types = &cur_block_type->u.value_type;
                        }
                    }
                    else {
                        block_param_count = cur_block_type->u.type->param_count;
                        block_ret_count = cur_block_type->u.type->result_count;
                        block_param_types = cur_block_type->u.type->types;
                        block_ret_types =
                            cur_block_type->u.type->types + block_param_count;
                    }
                    bh_assert(block_param_count == block_ret_count
                              && (!block_param_count
                                  || !memcmp(block_param_types, block_ret_types,
                                             block_param_count)));
                    (void)block_ret_types;
                    (void)block_ret_count;
                    (void)block_param_types;
                }

                POP_CSP();

#if WASM_ENABLE_FAST_INTERP != 0
                skip_label();
                /* copy the result to the block return address */
                RESERVE_BLOCK_RET();

                apply_label_patch(loader_ctx, 0, PATCH_END);
                free_label_patch_list(loader_ctx->frame_csp);
                if (loader_ctx->frame_csp->label_type == LABEL_TYPE_FUNCTION) {
                    int32 idx;
                    uint8 ret_type;

                    emit_label(WASM_OP_RETURN);
                    for (idx = (int32)func->func_type->result_count - 1;
                         idx >= 0; idx--) {
                        ret_type = *(func->func_type->types
                                     + func->func_type->param_count + idx);
                        POP_OFFSET_TYPE(ret_type);
                    }
                }
#endif
                if (loader_ctx->csp_num > 0) {
                    loader_ctx->frame_csp->end_addr = p - 1;
                }
                else {
                    /* end of function block, function will return */
                    bh_assert(p == p_end);
                }

                break;
            }

            case WASM_OP_BR:
            {
                if (!(frame_csp_tmp = check_branch_block(
                          loader_ctx, &p, p_end, error_buf, error_buf_size)))
                    goto fail;

                RESET_STACK();
                SET_CUR_BLOCK_STACK_POLYMORPHIC_STATE(true);
                break;
            }

            case WASM_OP_BR_IF:
            {
                POP_I32();

                if (!(frame_csp_tmp = check_branch_block(
                          loader_ctx, &p, p_end, error_buf, error_buf_size)))
                    goto fail;

                break;
            }

            case WASM_OP_BR_TABLE:
            {
                uint8 *ret_types = NULL;
                uint32 ret_count = 0;
#if WASM_ENABLE_FAST_INTERP == 0
                uint8 *p_depth_begin, *p_depth;
                uint32 depth, j;
                BrTableCache *br_table_cache = NULL;

                p_org = p - 1;
#endif

                read_leb_uint32(p, p_end, count);
#if WASM_ENABLE_FAST_INTERP != 0
                emit_uint32(loader_ctx, count);
#endif
                POP_I32();

#if WASM_ENABLE_FAST_INTERP == 0
                p_depth_begin = p_depth = p;
#endif
                for (i = 0; i <= count; i++) {
                    if (!(frame_csp_tmp =
                              check_branch_block(loader_ctx, &p, p_end,
                                                 error_buf, error_buf_size)))
                        goto fail;

#if WASM_ENABLE_FAST_INTERP == 0
                    depth = (uint32)(loader_ctx->frame_csp - 1 - frame_csp_tmp);
                    if (br_table_cache) {
                        br_table_cache->br_depths[i] = depth;
                    }
                    else {
                        if (depth > 255) {
                            /* The depth cannot be stored in one byte,
                               create br_table cache to store each depth */
#if WASM_ENABLE_DEBUG_INTERP != 0
                            if (!record_fast_op(module, p_org, *p_org,
                                                error_buf, error_buf_size)) {
                                goto fail;
                            }
#endif
                            if (!(br_table_cache = loader_malloc(
                                      offsetof(BrTableCache, br_depths)
                                          + sizeof(uint32)
                                                * (uint64)(count + 1),
                                      error_buf, error_buf_size))) {
                                goto fail;
                            }
                            *p_org = EXT_OP_BR_TABLE_CACHE;
                            br_table_cache->br_table_op_addr = p_org;
                            br_table_cache->br_count = count;
                            /* Copy previous depths which are one byte */
                            for (j = 0; j < i; j++) {
                                br_table_cache->br_depths[j] = p_depth_begin[j];
                            }
                            br_table_cache->br_depths[i] = depth;
                            bh_list_insert(module->br_table_cache_list,
                                           br_table_cache);
                        }
                        else {
                            /* The depth can be stored in one byte, use the
                               byte of the leb to store it */
                            *p_depth++ = (uint8)depth;
                        }
                    }
#endif
                }

#if WASM_ENABLE_FAST_INTERP == 0
                /* Set the tailing bytes to nop */
                if (br_table_cache)
                    p_depth = p_depth_begin;
                while (p_depth < p)
                    *p_depth++ = WASM_OP_NOP;
#endif

                RESET_STACK();
                SET_CUR_BLOCK_STACK_POLYMORPHIC_STATE(true);

                (void)ret_count;
                (void)ret_types;
                break;
            }

            case WASM_OP_RETURN:
            {
                int32 idx;
                uint8 ret_type;
                for (idx = (int32)func->func_type->result_count - 1; idx >= 0;
                     idx--) {
                    ret_type = *(func->func_type->types
                                 + func->func_type->param_count + idx);
                    POP_TYPE(ret_type);
#if WASM_ENABLE_FAST_INTERP != 0
                    /* emit the offset after return opcode */
                    POP_OFFSET_TYPE(ret_type);
#endif
                }

                RESET_STACK();
                SET_CUR_BLOCK_STACK_POLYMORPHIC_STATE(true);

                break;
            }

            case WASM_OP_CALL:
#if WASM_ENABLE_TAIL_CALL != 0
            case WASM_OP_RETURN_CALL:
#endif
            {
                WASMType *func_type;
                uint32 func_idx;
                int32 idx;

                read_leb_uint32(p, p_end, func_idx);
#if WASM_ENABLE_FAST_INTERP != 0
                /* we need to emit func_idx before arguments */
                emit_uint32(loader_ctx, func_idx);
#endif

                bh_assert(func_idx < module->import_function_count
                                         + module->function_count);

                if (func_idx < module->import_function_count)
                    func_type =
                        module->import_functions[func_idx].u.function.func_type;
                else
                    func_type = module
                                    ->functions[func_idx
                                                - module->import_function_count]
                                    ->func_type;

                if (func_type->param_count > 0) {
                    for (idx = (int32)(func_type->param_count - 1); idx >= 0;
                         idx--) {
                        POP_TYPE(func_type->types[idx]);
#if WASM_ENABLE_FAST_INTERP != 0
                        POP_OFFSET_TYPE(func_type->types[idx]);
#endif
                    }
                }

#if WASM_ENABLE_TAIL_CALL != 0
                if (opcode == WASM_OP_CALL) {
#endif
                    for (i = 0; i < func_type->result_count; i++) {
                        PUSH_TYPE(func_type->types[func_type->param_count + i]);
#if WASM_ENABLE_FAST_INTERP != 0
                        /* Here we emit each return value's dynamic_offset. But
                         * in fact these offsets are continuous, so interpreter
                         * only need to get the first return value's offset.
                         */
                        PUSH_OFFSET_TYPE(
                            func_type->types[func_type->param_count + i]);
#endif
                    }
#if WASM_ENABLE_TAIL_CALL != 0
                }
                else {
                    bh_assert(func_type->result_count
                              == func->func_type->result_count);
                    for (i = 0; i < func_type->result_count; i++) {
                        bh_assert(
                            func_type->types[func_type->param_count + i]
                            == func->func_type
                                   ->types[func->func_type->param_count + i]);
                    }
                }
#endif
                func->has_op_func_call = true;
                break;
            }

            case WASM_OP_CALL_INDIRECT:
#if WASM_ENABLE_TAIL_CALL != 0
            case WASM_OP_RETURN_CALL_INDIRECT:
#endif
            {
                int32 idx;
                WASMType *func_type;
                uint32 type_idx, table_idx;

                bh_assert(module->import_table_count + module->table_count > 0);

                read_leb_uint32(p, p_end, type_idx);

#if WASM_ENABLE_REF_TYPES != 0
                read_leb_uint32(p, p_end, table_idx);
#else
                CHECK_BUF(p, p_end, 1);
                table_idx = read_uint8(p);
#endif
                if (!check_table_index(module, table_idx, error_buf,
                                       error_buf_size)) {
                    goto fail;
                }

#if WASM_ENABLE_FAST_INTERP != 0
                /* we need to emit before arguments */
                emit_uint32(loader_ctx, type_idx);
                emit_uint32(loader_ctx, table_idx);
#endif

                /* skip elem idx */
                POP_I32();

                bh_assert(type_idx < module->type_count);

                func_type = module->types[type_idx];

                if (func_type->param_count > 0) {
                    for (idx = (int32)(func_type->param_count - 1); idx >= 0;
                         idx--) {
                        POP_TYPE(func_type->types[idx]);
#if WASM_ENABLE_FAST_INTERP != 0
                        POP_OFFSET_TYPE(func_type->types[idx]);
#endif
                    }
                }

#if WASM_ENABLE_TAIL_CALL != 0
                if (opcode == WASM_OP_CALL) {
#endif
                    for (i = 0; i < func_type->result_count; i++) {
                        PUSH_TYPE(func_type->types[func_type->param_count + i]);
#if WASM_ENABLE_FAST_INTERP != 0
                        PUSH_OFFSET_TYPE(
                            func_type->types[func_type->param_count + i]);
#endif
                    }
#if WASM_ENABLE_TAIL_CALL != 0
                }
                else {
                    bh_assert(func_type->result_count
                              == func->func_type->result_count);
                    for (i = 0; i < func_type->result_count; i++) {
                        bh_assert(
                            func_type->types[func_type->param_count + i]
                            == func->func_type
                                   ->types[func->func_type->param_count + i]);
                    }
                }
#endif

                func->has_op_func_call = true;
                break;
            }

            case WASM_OP_DROP:
            {
                BranchBlock *cur_block = loader_ctx->frame_csp - 1;
                int32 available_stack_cell =
                    (int32)(loader_ctx->stack_cell_num
                            - cur_block->stack_cell_num);

                bh_assert(!(available_stack_cell <= 0
                            && !cur_block->is_stack_polymorphic));

                if (available_stack_cell > 0) {
                    if (is_32bit_type(*(loader_ctx->frame_ref - 1))) {
                        loader_ctx->frame_ref--;
                        loader_ctx->stack_cell_num--;
#if WASM_ENABLE_FAST_INTERP != 0
                        skip_label();
                        loader_ctx->frame_offset--;
                        if ((*(loader_ctx->frame_offset)
                             > loader_ctx->start_dynamic_offset)
                            && (*(loader_ctx->frame_offset)
                                < loader_ctx->max_dynamic_offset))
                            loader_ctx->dynamic_offset--;
#endif
                    }
                    else if (is_64bit_type(*(loader_ctx->frame_ref - 1))) {
                        loader_ctx->frame_ref -= 2;
                        loader_ctx->stack_cell_num -= 2;
#if WASM_ENABLE_FAST_INTERP == 0
                        *(p - 1) = WASM_OP_DROP_64;
#endif
#if WASM_ENABLE_FAST_INTERP != 0
                        skip_label();
                        loader_ctx->frame_offset -= 2;
                        if ((*(loader_ctx->frame_offset)
                             > loader_ctx->start_dynamic_offset)
                            && (*(loader_ctx->frame_offset)
                                < loader_ctx->max_dynamic_offset))
                            loader_ctx->dynamic_offset -= 2;
#endif
                    }
                    else {
                        bh_assert(0);
                    }
                }
                else {
#if WASM_ENABLE_FAST_INTERP != 0
                    skip_label();
#endif
                }
                break;
            }

            case WASM_OP_SELECT:
            {
                uint8 ref_type;
                BranchBlock *cur_block = loader_ctx->frame_csp - 1;
                int32 available_stack_cell;

                POP_I32();

                available_stack_cell = (int32)(loader_ctx->stack_cell_num
                                               - cur_block->stack_cell_num);

                bh_assert(!(available_stack_cell <= 0
                            && !cur_block->is_stack_polymorphic));

                if (available_stack_cell > 0) {
                    switch (*(loader_ctx->frame_ref - 1)) {
                        case REF_I32:
                        case REF_F32:
                            break;
                        case REF_I64_2:
                        case REF_F64_2:
#if WASM_ENABLE_FAST_INTERP == 0
                            *(p - 1) = WASM_OP_SELECT_64;
#endif
#if WASM_ENABLE_FAST_INTERP != 0
                            if (loader_ctx->p_code_compiled) {
                                uint8 opcode_tmp = WASM_OP_SELECT_64;
                                uint8 *p_code_compiled_tmp =
                                    loader_ctx->p_code_compiled - 2;
#if WASM_ENABLE_LABELS_AS_VALUES != 0
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS != 0
                                *(void **)(p_code_compiled_tmp
                                           - sizeof(void *)) =
                                    handle_table[opcode_tmp];
#else
                                int32 offset =
                                    (int32)((uint8 *)handle_table[opcode_tmp]
                                            - (uint8 *)handle_table[0]);
                                if (!(offset >= INT16_MIN
                                      && offset < INT16_MAX)) {
                                    set_error_buf(error_buf, error_buf_size,
                                                  "pre-compiled label offset "
                                                  "out of range");
                                    goto fail;
                                }
                                *(int16 *)(p_code_compiled_tmp
                                           - sizeof(int16)) = (int16)offset;
#endif /* end of WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS */
#else  /* else of WASM_ENABLE_LABELS_AS_VALUES */
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS != 0
                                *(p_code_compiled_tmp - 1) = opcode_tmp;
#else
                                *(p_code_compiled_tmp - 2) = opcode_tmp;
#endif /* end of WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS */
#endif /* end of WASM_ENABLE_LABELS_AS_VALUES */
                            }
#endif
                            break;
                    }

                    ref_type = *(loader_ctx->frame_ref - 1);
#if WASM_ENABLE_FAST_INTERP != 0
                    POP_OFFSET_TYPE(ref_type);
#endif
                    POP_TYPE(ref_type);
#if WASM_ENABLE_FAST_INTERP != 0
                    POP_OFFSET_TYPE(ref_type);
#endif
                    POP_TYPE(ref_type);
#if WASM_ENABLE_FAST_INTERP != 0
                    PUSH_OFFSET_TYPE(ref_type);
#endif
                    PUSH_TYPE(ref_type);
                }
                else {
#if WASM_ENABLE_FAST_INTERP != 0
                    PUSH_OFFSET_TYPE(VALUE_TYPE_ANY);
#endif
                    PUSH_TYPE(VALUE_TYPE_ANY);
                }
                break;
            }

#if WASM_ENABLE_REF_TYPES != 0
            case WASM_OP_SELECT_T:
            {
                uint8 vec_len, ref_type;

                read_leb_uint32(p, p_end, vec_len);
                if (!vec_len) {
                    set_error_buf(error_buf, error_buf_size,
                                  "invalid result arity");
                    goto fail;
                }

                CHECK_BUF(p, p_end, 1);
                ref_type = read_uint8(p);
                if (!is_value_type(ref_type)) {
                    set_error_buf(error_buf, error_buf_size,
                                  "unknown value type");
                    goto fail;
                }

                POP_I32();

#if WASM_ENABLE_FAST_INTERP != 0
                if (loader_ctx->p_code_compiled) {
                    uint8 opcode_tmp = WASM_OP_SELECT;
                    uint8 *p_code_compiled_tmp =
                        loader_ctx->p_code_compiled - 2;

                    if (ref_type == VALUE_TYPE_F64
                        || ref_type == VALUE_TYPE_I64)
                        opcode_tmp = WASM_OP_SELECT_64;

#if WASM_ENABLE_LABELS_AS_VALUES != 0
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS != 0
                    *(void **)(p_code_compiled_tmp - sizeof(void *)) =
                        handle_table[opcode_tmp];
#else
                    int32 offset = (int32)((uint8 *)handle_table[opcode_tmp]
                                           - (uint8 *)handle_table[0]);
                    if (!(offset >= INT16_MIN && offset < INT16_MAX)) {
                        set_error_buf(error_buf, error_buf_size,
                                      "pre-compiled label offset out of range");
                        goto fail;
                    }
                    *(int16 *)(p_code_compiled_tmp - sizeof(int16)) =
                        (int16)offset;
#endif /* end of WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS */
#else  /* else of WASM_ENABLE_LABELS_AS_VALUES */
#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS != 0
                    *(p_code_compiled_tmp - 1) = opcode_tmp;
#else
                    *(p_code_compiled_tmp - 2) = opcode_tmp;
#endif /* end of WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS */
#endif /* end of WASM_ENABLE_LABELS_AS_VALUES */
                }
#endif /* WASM_ENABLE_FAST_INTERP != 0 */

#if WASM_ENABLE_FAST_INTERP != 0
                POP_OFFSET_TYPE(ref_type);
                POP_TYPE(ref_type);
                POP_OFFSET_TYPE(ref_type);
                POP_TYPE(ref_type);
                PUSH_OFFSET_TYPE(ref_type);
                PUSH_TYPE(ref_type);
#else
                POP2_AND_PUSH(ref_type, ref_type);
#endif /* WASM_ENABLE_FAST_INTERP != 0 */

                (void)vec_len;
                break;
            }

            /* table.get x. tables[x]. [i32] -> [t] */
            /* table.set x. tables[x]. [i32 t] -> [] */
            case WASM_OP_TABLE_GET:
            case WASM_OP_TABLE_SET:
            {
                uint8 decl_ref_type;
                uint32 table_idx;

                read_leb_uint32(p, p_end, table_idx);
                if (!get_table_elem_type(module, table_idx, &decl_ref_type,
                                         error_buf, error_buf_size))
                    goto fail;

#if WASM_ENABLE_FAST_INTERP != 0
                emit_uint32(loader_ctx, table_idx);
#endif

                if (opcode == WASM_OP_TABLE_GET) {
                    POP_I32();
#if WASM_ENABLE_FAST_INTERP != 0
                    PUSH_OFFSET_TYPE(decl_ref_type);
#endif
                    PUSH_TYPE(decl_ref_type);
                }
                else {
#if WASM_ENABLE_FAST_INTERP != 0
                    POP_OFFSET_TYPE(decl_ref_type);
#endif
                    POP_TYPE(decl_ref_type);
                    POP_I32();
                }
                break;
            }
            case WASM_OP_REF_NULL:
            {
                uint8 ref_type;

                CHECK_BUF(p, p_end, 1);
                ref_type = read_uint8(p);
                if (ref_type != VALUE_TYPE_FUNCREF
                    && ref_type != VALUE_TYPE_EXTERNREF) {
                    set_error_buf(error_buf, error_buf_size,
                                  "unknown value type");
                    goto fail;
                }
#if WASM_ENABLE_FAST_INTERP != 0
                PUSH_OFFSET_TYPE(ref_type);
#endif
                PUSH_TYPE(ref_type);
                break;
            }
            case WASM_OP_REF_IS_NULL:
            {
#if WASM_ENABLE_FAST_INTERP != 0
                if (!wasm_loader_pop_frame_ref_offset(loader_ctx,
                                                      VALUE_TYPE_FUNCREF,
                                                      error_buf, error_buf_size)
                    && !wasm_loader_pop_frame_ref_offset(
                        loader_ctx, VALUE_TYPE_EXTERNREF, error_buf,
                        error_buf_size)) {
                    goto fail;
                }
#else
                if (!wasm_loader_pop_frame_ref(loader_ctx, VALUE_TYPE_FUNCREF,
                                               error_buf, error_buf_size)
                    && !wasm_loader_pop_frame_ref(loader_ctx,
                                                  VALUE_TYPE_EXTERNREF,
                                                  error_buf, error_buf_size)) {
                    goto fail;
                }
#endif
                PUSH_I32();
                break;
            }
            case WASM_OP_REF_FUNC:
            {
                uint32 func_idx = 0;
                read_leb_uint32(p, p_end, func_idx);

                if (!check_function_index(module, func_idx, error_buf,
                                          error_buf_size)) {
                    goto fail;
                }

                if (func_idx == cur_func_idx + module->import_function_count) {
                    WASMTableSeg *table_seg = module->table_segments;
                    bool func_declared = false;
                    uint32 j;

                    /* Check whether current function is declared */
                    for (i = 0; i < module->table_seg_count; i++, table_seg++) {
                        if (table_seg->elem_type == VALUE_TYPE_FUNCREF
                            && wasm_elem_is_declarative(table_seg->mode)) {
                            for (j = 0; j < table_seg->function_count; j++) {
                                if (table_seg->func_indexes[j] == func_idx) {
                                    func_declared = true;
                                    break;
                                }
                            }
                        }
                    }
                    if (!func_declared) {
                        set_error_buf(error_buf, error_buf_size,
                                      "undeclared function reference");
                        goto fail;
                    }
                }

#if WASM_ENABLE_FAST_INTERP != 0
                emit_uint32(loader_ctx, func_idx);
#endif
                PUSH_FUNCREF();
                break;
            }
#endif /* WASM_ENABLE_REF_TYPES */

            case WASM_OP_GET_LOCAL:
            {
                p_org = p - 1;
                GET_LOCAL_INDEX_TYPE_AND_OFFSET();
                PUSH_TYPE(local_type);

#if WASM_ENABLE_FAST_INTERP != 0
                /* Get Local is optimized out */
                skip_label();
                disable_emit = true;
                operand_offset = local_offset;
                PUSH_OFFSET_TYPE(local_type);
#else
#if (WASM_ENABLE_WAMR_COMPILER == 0) && (WASM_ENABLE_JIT == 0) \
    && (WASM_ENABLE_FAST_JIT == 0)
                if (local_offset < 0x80) {
                    *p_org++ = EXT_OP_GET_LOCAL_FAST;
                    if (is_32bit_type(local_type))
                        *p_org++ = (uint8)local_offset;
                    else
                        *p_org++ = (uint8)(local_offset | 0x80);
                    while (p_org < p)
                        *p_org++ = WASM_OP_NOP;
                }
#endif
#endif
                break;
            }

            case WASM_OP_SET_LOCAL:
            {
                p_org = p - 1;
                GET_LOCAL_INDEX_TYPE_AND_OFFSET();
                POP_TYPE(local_type);

#if WASM_ENABLE_FAST_INTERP != 0
                if (!(preserve_referenced_local(
                        loader_ctx, opcode, local_offset, local_type,
                        &preserve_local, error_buf, error_buf_size)))
                    goto fail;

                if (local_offset < 256) {
                    skip_label();
                    if ((!preserve_local) && (LAST_OP_OUTPUT_I32())) {
                        if (loader_ctx->p_code_compiled)
                            STORE_U16(loader_ctx->p_code_compiled - 2,
                                      local_offset);
                        loader_ctx->frame_offset--;
                        loader_ctx->dynamic_offset--;
                    }
                    else if ((!preserve_local) && (LAST_OP_OUTPUT_I64())) {
                        if (loader_ctx->p_code_compiled)
                            STORE_U16(loader_ctx->p_code_compiled - 2,
                                      local_offset);
                        loader_ctx->frame_offset -= 2;
                        loader_ctx->dynamic_offset -= 2;
                    }
                    else {
                        if (is_32bit_type(local_type)) {
                            emit_label(EXT_OP_SET_LOCAL_FAST);
                            emit_byte(loader_ctx, (uint8)local_offset);
                        }
                        else {
                            emit_label(EXT_OP_SET_LOCAL_FAST_I64);
                            emit_byte(loader_ctx, (uint8)local_offset);
                        }
                        POP_OFFSET_TYPE(local_type);
                    }
                }
                else { /* local index larger than 255, reserve leb */
                    emit_uint32(loader_ctx, local_idx);
                    POP_OFFSET_TYPE(local_type);
                }
#else
#if (WASM_ENABLE_WAMR_COMPILER == 0) && (WASM_ENABLE_JIT == 0) \
    && (WASM_ENABLE_FAST_JIT == 0)
                if (local_offset < 0x80) {
                    *p_org++ = EXT_OP_SET_LOCAL_FAST;
                    if (is_32bit_type(local_type))
                        *p_org++ = (uint8)local_offset;
                    else
                        *p_org++ = (uint8)(local_offset | 0x80);
                    while (p_org < p)
                        *p_org++ = WASM_OP_NOP;
                }
#endif
#endif
                break;
            }

            case WASM_OP_TEE_LOCAL:
            {
                p_org = p - 1;
                GET_LOCAL_INDEX_TYPE_AND_OFFSET();
#if WASM_ENABLE_FAST_INTERP != 0
                /* If the stack is in polymorphic state, do fake pop and push on
                    offset stack to keep the depth of offset stack to be the
                   same with ref stack */
                BranchBlock *cur_block = loader_ctx->frame_csp - 1;
                if (cur_block->is_stack_polymorphic) {
                    POP_OFFSET_TYPE(local_type);
                    PUSH_OFFSET_TYPE(local_type);
                }
#endif
                POP_TYPE(local_type);
                PUSH_TYPE(local_type);

#if WASM_ENABLE_FAST_INTERP != 0
                if (!(preserve_referenced_local(
                        loader_ctx, opcode, local_offset, local_type,
                        &preserve_local, error_buf, error_buf_size)))
                    goto fail;

                if (local_offset < 256) {
                    skip_label();
                    if (is_32bit_type(local_type)) {
                        emit_label(EXT_OP_TEE_LOCAL_FAST);
                        emit_byte(loader_ctx, (uint8)local_offset);
                    }
                    else {
                        emit_label(EXT_OP_TEE_LOCAL_FAST_I64);
                        emit_byte(loader_ctx, (uint8)local_offset);
                    }
                }
                else { /* local index larger than 255, reserve leb */
                    emit_uint32(loader_ctx, local_idx);
                }
                emit_operand(loader_ctx,
                             *(loader_ctx->frame_offset
                               - wasm_value_type_cell_num(local_type)));
#else
#if (WASM_ENABLE_WAMR_COMPILER == 0) && (WASM_ENABLE_JIT == 0) \
    && (WASM_ENABLE_FAST_JIT == 0)
                if (local_offset < 0x80) {
                    *p_org++ = EXT_OP_TEE_LOCAL_FAST;
                    if (is_32bit_type(local_type))
                        *p_org++ = (uint8)local_offset;
                    else
                        *p_org++ = (uint8)(local_offset | 0x80);
                    while (p_org < p)
                        *p_org++ = WASM_OP_NOP;
                }
#endif
#endif
                break;
            }

            case WASM_OP_GET_GLOBAL:
            {
                p_org = p - 1;
                read_leb_uint32(p, p_end, global_idx);
                bh_assert(global_idx < global_count);

                global_type =
                    global_idx < module->import_global_count
                        ? module->import_globals[global_idx].u.global.type
                        : module
                              ->globals[global_idx
                                        - module->import_global_count]
                              .type;

                PUSH_TYPE(global_type);

#if WASM_ENABLE_FAST_INTERP == 0
                if (global_type == VALUE_TYPE_I64
                    || global_type == VALUE_TYPE_F64) {
                    *p_org = WASM_OP_GET_GLOBAL_64;
                }
#else  /* else of WASM_ENABLE_FAST_INTERP */
                if (is_64bit_type(global_type)) {
                    skip_label();
                    emit_label(WASM_OP_GET_GLOBAL_64);
                }
                emit_uint32(loader_ctx, global_idx);
                PUSH_OFFSET_TYPE(global_type);
#endif /* end of WASM_ENABLE_FAST_INTERP */
                break;
            }

            case WASM_OP_SET_GLOBAL:
            {
                bool is_mutable = false;

                p_org = p - 1;
                read_leb_uint32(p, p_end, global_idx);
                bh_assert(global_idx < global_count);

                is_mutable =
                    global_idx < module->import_global_count
                        ? module->import_globals[global_idx].u.global.is_mutable
                        : module
                              ->globals[global_idx
                                        - module->import_global_count]
                              .is_mutable;
                bh_assert(is_mutable);

                global_type =
                    global_idx < module->import_global_count
                        ? module->import_globals[global_idx].u.global.type
                        : module
                              ->globals[global_idx
                                        - module->import_global_count]
                              .type;

                POP_TYPE(global_type);

#if WASM_ENABLE_FAST_INTERP == 0
                if (is_64bit_type(global_type)) {
                    *p_org = WASM_OP_SET_GLOBAL_64;
                }
                else if (module->aux_stack_size > 0
                         && global_idx == module->aux_stack_top_global_index) {
                    *p_org = WASM_OP_SET_GLOBAL_AUX_STACK;
                }
#else  /* else of WASM_ENABLE_FAST_INTERP */
                if (is_64bit_type(global_type)) {
                    skip_label();
                    emit_label(WASM_OP_SET_GLOBAL_64);
                }
                else if (module->aux_stack_size > 0
                         && global_idx == module->aux_stack_top_global_index) {
                    skip_label();
                    emit_label(WASM_OP_SET_GLOBAL_AUX_STACK);
                }
                emit_uint32(loader_ctx, global_idx);
                POP_OFFSET_TYPE(global_type);
#endif /* end of WASM_ENABLE_FAST_INTERP */

                (void)is_mutable;
                break;
            }

            /* load */
            case WASM_OP_I32_LOAD:
            case WASM_OP_I32_LOAD8_S:
            case WASM_OP_I32_LOAD8_U:
            case WASM_OP_I32_LOAD16_S:
            case WASM_OP_I32_LOAD16_U:
            case WASM_OP_I64_LOAD:
            case WASM_OP_I64_LOAD8_S:
            case WASM_OP_I64_LOAD8_U:
            case WASM_OP_I64_LOAD16_S:
            case WASM_OP_I64_LOAD16_U:
            case WASM_OP_I64_LOAD32_S:
            case WASM_OP_I64_LOAD32_U:
            case WASM_OP_F32_LOAD:
            case WASM_OP_F64_LOAD:
            /* store */
            case WASM_OP_I32_STORE:
            case WASM_OP_I32_STORE8:
            case WASM_OP_I32_STORE16:
            case WASM_OP_I64_STORE:
            case WASM_OP_I64_STORE8:
            case WASM_OP_I64_STORE16:
            case WASM_OP_I64_STORE32:
            case WASM_OP_F32_STORE:
            case WASM_OP_F64_STORE:
            {
#if WASM_ENABLE_FAST_INTERP != 0
                /* change F32/F64 into I32/I64 */
                if (opcode == WASM_OP_F32_LOAD) {
                    skip_label();
                    emit_label(WASM_OP_I32_LOAD);
                }
                else if (opcode == WASM_OP_F64_LOAD) {
                    skip_label();
                    emit_label(WASM_OP_I64_LOAD);
                }
                else if (opcode == WASM_OP_F32_STORE) {
                    skip_label();
                    emit_label(WASM_OP_I32_STORE);
                }
                else if (opcode == WASM_OP_F64_STORE) {
                    skip_label();
                    emit_label(WASM_OP_I64_STORE);
                }
#endif
                CHECK_MEMORY();
                read_leb_uint32(p, p_end, align);      /* align */
                read_leb_uint32(p, p_end, mem_offset); /* offset */
#if WASM_ENABLE_FAST_INTERP != 0
                emit_uint32(loader_ctx, mem_offset);
#endif
                switch (opcode) {
                    /* load */
                    case WASM_OP_I32_LOAD:
                    case WASM_OP_I32_LOAD8_S:
                    case WASM_OP_I32_LOAD8_U:
                    case WASM_OP_I32_LOAD16_S:
                    case WASM_OP_I32_LOAD16_U:
                        POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I32);
                        break;
                    case WASM_OP_I64_LOAD:
                    case WASM_OP_I64_LOAD8_S:
                    case WASM_OP_I64_LOAD8_U:
                    case WASM_OP_I64_LOAD16_S:
                    case WASM_OP_I64_LOAD16_U:
                    case WASM_OP_I64_LOAD32_S:
                    case WASM_OP_I64_LOAD32_U:
                        POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I64);
                        break;
                    case WASM_OP_F32_LOAD:
                        POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_F32);
                        break;
                    case WASM_OP_F64_LOAD:
                        POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_F64);
                        break;
                    /* store */
                    case WASM_OP_I32_STORE:
                    case WASM_OP_I32_STORE8:
                    case WASM_OP_I32_STORE16:
                        POP_I32();
                        POP_I32();
                        break;
                    case WASM_OP_I64_STORE:
                    case WASM_OP_I64_STORE8:
                    case WASM_OP_I64_STORE16:
                    case WASM_OP_I64_STORE32:
                        POP_I64();
                        POP_I32();
                        break;
                    case WASM_OP_F32_STORE:
                        POP_F32();
                        POP_I32();
                        break;
                    case WASM_OP_F64_STORE:
                        POP_F64();
                        POP_I32();
                        break;
                    default:
                        break;
                }
                break;
            }

            case WASM_OP_MEMORY_SIZE:
                CHECK_MEMORY();
                /* reserved byte 0x00 */
                bh_assert(*p == 0x00);
                p++;
                PUSH_I32();

                module->possible_memory_grow = true;
                break;

            case WASM_OP_MEMORY_GROW:
                CHECK_MEMORY();
                /* reserved byte 0x00 */
                bh_assert(*p == 0x00);
                p++;
                POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I32);

                func->has_op_memory_grow = true;
                module->possible_memory_grow = true;
                break;

            case WASM_OP_I32_CONST:
                read_leb_int32(p, p_end, i32_const);
#if WASM_ENABLE_FAST_INTERP != 0
                skip_label();
                disable_emit = true;
                GET_CONST_OFFSET(VALUE_TYPE_I32, i32_const);

                if (operand_offset == 0) {
                    disable_emit = false;
                    emit_label(WASM_OP_I32_CONST);
                    emit_uint32(loader_ctx, i32_const);
                }
#else
                (void)i32_const;
#endif
                PUSH_I32();
                break;

            case WASM_OP_I64_CONST:
                read_leb_int64(p, p_end, i64_const);
#if WASM_ENABLE_FAST_INTERP != 0
                skip_label();
                disable_emit = true;
                GET_CONST_OFFSET(VALUE_TYPE_I64, i64_const);

                if (operand_offset == 0) {
                    disable_emit = false;
                    emit_label(WASM_OP_I64_CONST);
                    emit_uint64(loader_ctx, i64_const);
                }
#endif
                PUSH_I64();
                break;

            case WASM_OP_F32_CONST:
                p += sizeof(float32);
#if WASM_ENABLE_FAST_INTERP != 0
                skip_label();
                disable_emit = true;
                bh_memcpy_s((uint8 *)&f32_const, sizeof(float32), p_org,
                            sizeof(float32));
                GET_CONST_F32_OFFSET(VALUE_TYPE_F32, f32_const);

                if (operand_offset == 0) {
                    disable_emit = false;
                    emit_label(WASM_OP_F32_CONST);
                    emit_float32(loader_ctx, f32_const);
                }
#endif
                PUSH_F32();
                break;

            case WASM_OP_F64_CONST:
                p += sizeof(float64);
#if WASM_ENABLE_FAST_INTERP != 0
                skip_label();
                disable_emit = true;
                /* Some MCU may require 8-byte align */
                bh_memcpy_s((uint8 *)&f64_const, sizeof(float64), p_org,
                            sizeof(float64));
                GET_CONST_F64_OFFSET(VALUE_TYPE_F64, f64_const);

                if (operand_offset == 0) {
                    disable_emit = false;
                    emit_label(WASM_OP_F64_CONST);
                    emit_float64(loader_ctx, f64_const);
                }
#endif
                PUSH_F64();
                break;

            case WASM_OP_I32_EQZ:
                POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I32);
                break;

            case WASM_OP_I32_EQ:
            case WASM_OP_I32_NE:
            case WASM_OP_I32_LT_S:
            case WASM_OP_I32_LT_U:
            case WASM_OP_I32_GT_S:
            case WASM_OP_I32_GT_U:
            case WASM_OP_I32_LE_S:
            case WASM_OP_I32_LE_U:
            case WASM_OP_I32_GE_S:
            case WASM_OP_I32_GE_U:
                POP2_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I32);
                break;

            case WASM_OP_I64_EQZ:
                POP_AND_PUSH(VALUE_TYPE_I64, VALUE_TYPE_I32);
                break;

            case WASM_OP_I64_EQ:
            case WASM_OP_I64_NE:
            case WASM_OP_I64_LT_S:
            case WASM_OP_I64_LT_U:
            case WASM_OP_I64_GT_S:
            case WASM_OP_I64_GT_U:
            case WASM_OP_I64_LE_S:
            case WASM_OP_I64_LE_U:
            case WASM_OP_I64_GE_S:
            case WASM_OP_I64_GE_U:
                POP2_AND_PUSH(VALUE_TYPE_I64, VALUE_TYPE_I32);
                break;

            case WASM_OP_F32_EQ:
            case WASM_OP_F32_NE:
            case WASM_OP_F32_LT:
            case WASM_OP_F32_GT:
            case WASM_OP_F32_LE:
            case WASM_OP_F32_GE:
                POP2_AND_PUSH(VALUE_TYPE_F32, VALUE_TYPE_I32);
                break;

            case WASM_OP_F64_EQ:
            case WASM_OP_F64_NE:
            case WASM_OP_F64_LT:
            case WASM_OP_F64_GT:
            case WASM_OP_F64_LE:
            case WASM_OP_F64_GE:
                POP2_AND_PUSH(VALUE_TYPE_F64, VALUE_TYPE_I32);
                break;

            case WASM_OP_I32_CLZ:
            case WASM_OP_I32_CTZ:
            case WASM_OP_I32_POPCNT:
                POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I32);
                break;

            case WASM_OP_I32_ADD:
            case WASM_OP_I32_SUB:
            case WASM_OP_I32_MUL:
            case WASM_OP_I32_DIV_S:
            case WASM_OP_I32_DIV_U:
            case WASM_OP_I32_REM_S:
            case WASM_OP_I32_REM_U:
            case WASM_OP_I32_AND:
            case WASM_OP_I32_OR:
            case WASM_OP_I32_XOR:
            case WASM_OP_I32_SHL:
            case WASM_OP_I32_SHR_S:
            case WASM_OP_I32_SHR_U:
            case WASM_OP_I32_ROTL:
            case WASM_OP_I32_ROTR:
                POP2_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I32);
                break;

            case WASM_OP_I64_CLZ:
            case WASM_OP_I64_CTZ:
            case WASM_OP_I64_POPCNT:
                POP_AND_PUSH(VALUE_TYPE_I64, VALUE_TYPE_I64);
                break;

            case WASM_OP_I64_ADD:
            case WASM_OP_I64_SUB:
            case WASM_OP_I64_MUL:
            case WASM_OP_I64_DIV_S:
            case WASM_OP_I64_DIV_U:
            case WASM_OP_I64_REM_S:
            case WASM_OP_I64_REM_U:
            case WASM_OP_I64_AND:
            case WASM_OP_I64_OR:
            case WASM_OP_I64_XOR:
            case WASM_OP_I64_SHL:
            case WASM_OP_I64_SHR_S:
            case WASM_OP_I64_SHR_U:
            case WASM_OP_I64_ROTL:
            case WASM_OP_I64_ROTR:
                POP2_AND_PUSH(VALUE_TYPE_I64, VALUE_TYPE_I64);
                break;

            case WASM_OP_F32_ABS:
            case WASM_OP_F32_NEG:
            case WASM_OP_F32_CEIL:
            case WASM_OP_F32_FLOOR:
            case WASM_OP_F32_TRUNC:
            case WASM_OP_F32_NEAREST:
            case WASM_OP_F32_SQRT:
                POP_AND_PUSH(VALUE_TYPE_F32, VALUE_TYPE_F32);
                break;

            case WASM_OP_F32_ADD:
            case WASM_OP_F32_SUB:
            case WASM_OP_F32_MUL:
            case WASM_OP_F32_DIV:
            case WASM_OP_F32_MIN:
            case WASM_OP_F32_MAX:
            case WASM_OP_F32_COPYSIGN:
                POP2_AND_PUSH(VALUE_TYPE_F32, VALUE_TYPE_F32);
                break;

            case WASM_OP_F64_ABS:
            case WASM_OP_F64_NEG:
            case WASM_OP_F64_CEIL:
            case WASM_OP_F64_FLOOR:
            case WASM_OP_F64_TRUNC:
            case WASM_OP_F64_NEAREST:
            case WASM_OP_F64_SQRT:
                POP_AND_PUSH(VALUE_TYPE_F64, VALUE_TYPE_F64);
                break;

            case WASM_OP_F64_ADD:
            case WASM_OP_F64_SUB:
            case WASM_OP_F64_MUL:
            case WASM_OP_F64_DIV:
            case WASM_OP_F64_MIN:
            case WASM_OP_F64_MAX:
            case WASM_OP_F64_COPYSIGN:
                POP2_AND_PUSH(VALUE_TYPE_F64, VALUE_TYPE_F64);
                break;

            case WASM_OP_I32_WRAP_I64:
                POP_AND_PUSH(VALUE_TYPE_I64, VALUE_TYPE_I32);
                break;

            case WASM_OP_I32_TRUNC_S_F32:
            case WASM_OP_I32_TRUNC_U_F32:
                POP_AND_PUSH(VALUE_TYPE_F32, VALUE_TYPE_I32);
                break;

            case WASM_OP_I32_TRUNC_S_F64:
            case WASM_OP_I32_TRUNC_U_F64:
                POP_AND_PUSH(VALUE_TYPE_F64, VALUE_TYPE_I32);
                break;

            case WASM_OP_I64_EXTEND_S_I32:
            case WASM_OP_I64_EXTEND_U_I32:
                POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I64);
                break;

            case WASM_OP_I64_TRUNC_S_F32:
            case WASM_OP_I64_TRUNC_U_F32:
                POP_AND_PUSH(VALUE_TYPE_F32, VALUE_TYPE_I64);
                break;

            case WASM_OP_I64_TRUNC_S_F64:
            case WASM_OP_I64_TRUNC_U_F64:
                POP_AND_PUSH(VALUE_TYPE_F64, VALUE_TYPE_I64);
                break;

            case WASM_OP_F32_CONVERT_S_I32:
            case WASM_OP_F32_CONVERT_U_I32:
                POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_F32);
                break;

            case WASM_OP_F32_CONVERT_S_I64:
            case WASM_OP_F32_CONVERT_U_I64:
                POP_AND_PUSH(VALUE_TYPE_I64, VALUE_TYPE_F32);
                break;

            case WASM_OP_F32_DEMOTE_F64:
                POP_AND_PUSH(VALUE_TYPE_F64, VALUE_TYPE_F32);
                break;

            case WASM_OP_F64_CONVERT_S_I32:
            case WASM_OP_F64_CONVERT_U_I32:
                POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_F64);
                break;

            case WASM_OP_F64_CONVERT_S_I64:
            case WASM_OP_F64_CONVERT_U_I64:
                POP_AND_PUSH(VALUE_TYPE_I64, VALUE_TYPE_F64);
                break;

            case WASM_OP_F64_PROMOTE_F32:
                POP_AND_PUSH(VALUE_TYPE_F32, VALUE_TYPE_F64);
                break;

            case WASM_OP_I32_REINTERPRET_F32:
                POP_AND_PUSH(VALUE_TYPE_F32, VALUE_TYPE_I32);
                break;

            case WASM_OP_I64_REINTERPRET_F64:
                POP_AND_PUSH(VALUE_TYPE_F64, VALUE_TYPE_I64);
                break;

            case WASM_OP_F32_REINTERPRET_I32:
                POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_F32);
                break;

            case WASM_OP_F64_REINTERPRET_I64:
                POP_AND_PUSH(VALUE_TYPE_I64, VALUE_TYPE_F64);
                break;

            case WASM_OP_I32_EXTEND8_S:
            case WASM_OP_I32_EXTEND16_S:
                POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I32);
                break;

            case WASM_OP_I64_EXTEND8_S:
            case WASM_OP_I64_EXTEND16_S:
            case WASM_OP_I64_EXTEND32_S:
                POP_AND_PUSH(VALUE_TYPE_I64, VALUE_TYPE_I64);
                break;

            case WASM_OP_MISC_PREFIX:
            {
                uint32 opcode1;

                read_leb_uint32(p, p_end, opcode1);
#if WASM_ENABLE_FAST_INTERP != 0
                emit_byte(loader_ctx, ((uint8)opcode1));
#endif
                switch (opcode1) {
                    case WASM_OP_I32_TRUNC_SAT_S_F32:
                    case WASM_OP_I32_TRUNC_SAT_U_F32:
                        POP_AND_PUSH(VALUE_TYPE_F32, VALUE_TYPE_I32);
                        break;
                    case WASM_OP_I32_TRUNC_SAT_S_F64:
                    case WASM_OP_I32_TRUNC_SAT_U_F64:
                        POP_AND_PUSH(VALUE_TYPE_F64, VALUE_TYPE_I32);
                        break;
                    case WASM_OP_I64_TRUNC_SAT_S_F32:
                    case WASM_OP_I64_TRUNC_SAT_U_F32:
                        POP_AND_PUSH(VALUE_TYPE_F32, VALUE_TYPE_I64);
                        break;
                    case WASM_OP_I64_TRUNC_SAT_S_F64:
                    case WASM_OP_I64_TRUNC_SAT_U_F64:
                        POP_AND_PUSH(VALUE_TYPE_F64, VALUE_TYPE_I64);
                        break;
#if WASM_ENABLE_BULK_MEMORY != 0
                    case WASM_OP_MEMORY_INIT:
                        read_leb_uint32(p, p_end, segment_index);
#if WASM_ENABLE_FAST_INTERP != 0
                        emit_uint32(loader_ctx, segment_index);
#endif
                        bh_assert(module->import_memory_count
                                      + module->memory_count
                                  > 0);

                        bh_assert(*p == 0x00);
                        p++;

                        bh_assert(segment_index < module->data_seg_count);
                        bh_assert(module->data_seg_count1 > 0);

                        POP_I32();
                        POP_I32();
                        POP_I32();
                        break;
                    case WASM_OP_DATA_DROP:
                        read_leb_uint32(p, p_end, segment_index);
#if WASM_ENABLE_FAST_INTERP != 0
                        emit_uint32(loader_ctx, segment_index);
#endif
                        bh_assert(segment_index < module->data_seg_count);
                        bh_assert(module->data_seg_count1 > 0);
                        break;
                    case WASM_OP_MEMORY_COPY:
                        /* both src and dst memory index should be 0 */
                        bh_assert(*(int16 *)p == 0x0000);
                        p += 2;

                        bh_assert(module->import_memory_count
                                      + module->memory_count
                                  > 0);

                        POP_I32();
                        POP_I32();
                        POP_I32();
                        break;
                    case WASM_OP_MEMORY_FILL:
                        bh_assert(*p == 0);
                        p++;

                        bh_assert(module->import_memory_count
                                      + module->memory_count
                                  > 0);

                        POP_I32();
                        POP_I32();
                        POP_I32();
                        break;
#endif /* WASM_ENABLE_BULK_MEMORY */
#if WASM_ENABLE_REF_TYPES != 0
                    case WASM_OP_TABLE_INIT:
                    {
                        uint8 seg_ref_type, tbl_ref_type;
                        uint32 table_seg_idx, table_idx;

                        read_leb_uint32(p, p_end, table_seg_idx);
                        read_leb_uint32(p, p_end, table_idx);

                        if (!get_table_elem_type(module, table_idx,
                                                 &tbl_ref_type, error_buf,
                                                 error_buf_size))
                            goto fail;

                        if (!get_table_seg_elem_type(module, table_seg_idx,
                                                     &seg_ref_type, error_buf,
                                                     error_buf_size))
                            goto fail;

                        if (seg_ref_type != tbl_ref_type) {
                            set_error_buf(error_buf, error_buf_size,
                                          "type mismatch");
                            goto fail;
                        }

#if WASM_ENABLE_FAST_INTERP != 0
                        emit_uint32(loader_ctx, table_seg_idx);
                        emit_uint32(loader_ctx, table_idx);
#endif
                        POP_I32();
                        POP_I32();
                        POP_I32();
                        break;
                    }
                    case WASM_OP_ELEM_DROP:
                    {
                        uint32 table_seg_idx;
                        read_leb_uint32(p, p_end, table_seg_idx);
                        if (!get_table_seg_elem_type(module, table_seg_idx,
                                                     NULL, error_buf,
                                                     error_buf_size))
                            goto fail;
#if WASM_ENABLE_FAST_INTERP != 0
                        emit_uint32(loader_ctx, table_seg_idx);
#endif
                        break;
                    }
                    case WASM_OP_TABLE_COPY:
                    {
                        uint8 src_ref_type, dst_ref_type;
                        uint32 src_tbl_idx, dst_tbl_idx;

                        read_leb_uint32(p, p_end, src_tbl_idx);
                        if (!get_table_elem_type(module, src_tbl_idx,
                                                 &src_ref_type, error_buf,
                                                 error_buf_size))
                            goto fail;

                        read_leb_uint32(p, p_end, dst_tbl_idx);
                        if (!get_table_elem_type(module, dst_tbl_idx,
                                                 &dst_ref_type, error_buf,
                                                 error_buf_size))
                            goto fail;

                        if (src_ref_type != dst_ref_type) {
                            set_error_buf(error_buf, error_buf_size,
                                          "type mismatch");
                            goto fail;
                        }

#if WASM_ENABLE_FAST_INTERP != 0
                        emit_uint32(loader_ctx, src_tbl_idx);
                        emit_uint32(loader_ctx, dst_tbl_idx);
#endif
                        POP_I32();
                        POP_I32();
                        POP_I32();
                        break;
                    }
                    case WASM_OP_TABLE_SIZE:
                    {
                        uint32 table_idx;

                        read_leb_uint32(p, p_end, table_idx);
                        /* TODO: shall we create a new function to check
                                 table idx instead of using below function? */
                        if (!get_table_elem_type(module, table_idx, NULL,
                                                 error_buf, error_buf_size))
                            goto fail;

#if WASM_ENABLE_FAST_INTERP != 0
                        emit_uint32(loader_ctx, table_idx);
#endif

                        PUSH_I32();
                        break;
                    }
                    case WASM_OP_TABLE_GROW:
                    case WASM_OP_TABLE_FILL:
                    {
                        uint8 decl_ref_type;
                        uint32 table_idx;

                        read_leb_uint32(p, p_end, table_idx);
                        if (!get_table_elem_type(module, table_idx,
                                                 &decl_ref_type, error_buf,
                                                 error_buf_size))
                            goto fail;

                        if (opcode1 == WASM_OP_TABLE_GROW) {
                            if (table_idx < module->import_table_count) {
                                module->import_tables[table_idx]
                                    .u.table.possible_grow = true;
                            }
                            else {
                                module
                                    ->tables[table_idx
                                             - module->import_table_count]
                                    .possible_grow = true;
                            }
                        }

#if WASM_ENABLE_FAST_INTERP != 0
                        emit_uint32(loader_ctx, table_idx);
#endif

                        POP_I32();
#if WASM_ENABLE_FAST_INTERP != 0
                        POP_OFFSET_TYPE(decl_ref_type);
#endif
                        POP_TYPE(decl_ref_type);
                        if (opcode1 == WASM_OP_TABLE_GROW)
                            PUSH_I32();
                        else
                            POP_I32();
                        break;
                    }
#endif /* WASM_ENABLE_REF_TYPES */
                    default:
                        bh_assert(0);
                        break;
                }
                break;
            }

#if WASM_ENABLE_SHARED_MEMORY != 0
            case WASM_OP_ATOMIC_PREFIX:
            {
                opcode = read_uint8(p);
#if WASM_ENABLE_FAST_INTERP != 0
                emit_byte(loader_ctx, opcode);
#endif
                if (opcode != WASM_OP_ATOMIC_FENCE) {
                    CHECK_MEMORY();
                    read_leb_uint32(p, p_end, align);      /* align */
                    read_leb_uint32(p, p_end, mem_offset); /* offset */
#if WASM_ENABLE_FAST_INTERP != 0
                    emit_uint32(loader_ctx, mem_offset);
#endif
                }
                switch (opcode) {
                    case WASM_OP_ATOMIC_NOTIFY:
                        POP2_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I32);
                        break;
                    case WASM_OP_ATOMIC_WAIT32:
                        POP_I64();
                        POP_I32();
                        POP_I32();
                        PUSH_I32();
                        break;
                    case WASM_OP_ATOMIC_WAIT64:
                        POP_I64();
                        POP_I64();
                        POP_I32();
                        PUSH_I32();
                        break;
                    case WASM_OP_ATOMIC_FENCE:
                        /* reserved byte 0x00 */
                        bh_assert(*p == 0x00);
                        p++;
                        break;
                    case WASM_OP_ATOMIC_I32_LOAD:
                    case WASM_OP_ATOMIC_I32_LOAD8_U:
                    case WASM_OP_ATOMIC_I32_LOAD16_U:
                        POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I32);
                        break;
                    case WASM_OP_ATOMIC_I32_STORE:
                    case WASM_OP_ATOMIC_I32_STORE8:
                    case WASM_OP_ATOMIC_I32_STORE16:
                        POP_I32();
                        POP_I32();
                        break;
                    case WASM_OP_ATOMIC_I64_LOAD:
                    case WASM_OP_ATOMIC_I64_LOAD8_U:
                    case WASM_OP_ATOMIC_I64_LOAD16_U:
                    case WASM_OP_ATOMIC_I64_LOAD32_U:
                        POP_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I64);
                        break;
                    case WASM_OP_ATOMIC_I64_STORE:
                    case WASM_OP_ATOMIC_I64_STORE8:
                    case WASM_OP_ATOMIC_I64_STORE16:
                    case WASM_OP_ATOMIC_I64_STORE32:
                        POP_I64();
                        POP_I32();
                        break;
                    case WASM_OP_ATOMIC_RMW_I32_ADD:
                    case WASM_OP_ATOMIC_RMW_I32_ADD8_U:
                    case WASM_OP_ATOMIC_RMW_I32_ADD16_U:
                    case WASM_OP_ATOMIC_RMW_I32_SUB:
                    case WASM_OP_ATOMIC_RMW_I32_SUB8_U:
                    case WASM_OP_ATOMIC_RMW_I32_SUB16_U:
                    case WASM_OP_ATOMIC_RMW_I32_AND:
                    case WASM_OP_ATOMIC_RMW_I32_AND8_U:
                    case WASM_OP_ATOMIC_RMW_I32_AND16_U:
                    case WASM_OP_ATOMIC_RMW_I32_OR:
                    case WASM_OP_ATOMIC_RMW_I32_OR8_U:
                    case WASM_OP_ATOMIC_RMW_I32_OR16_U:
                    case WASM_OP_ATOMIC_RMW_I32_XOR:
                    case WASM_OP_ATOMIC_RMW_I32_XOR8_U:
                    case WASM_OP_ATOMIC_RMW_I32_XOR16_U:
                    case WASM_OP_ATOMIC_RMW_I32_XCHG:
                    case WASM_OP_ATOMIC_RMW_I32_XCHG8_U:
                    case WASM_OP_ATOMIC_RMW_I32_XCHG16_U:
                        POP2_AND_PUSH(VALUE_TYPE_I32, VALUE_TYPE_I32);
                        break;
                    case WASM_OP_ATOMIC_RMW_I64_ADD:
                    case WASM_OP_ATOMIC_RMW_I64_ADD8_U:
                    case WASM_OP_ATOMIC_RMW_I64_ADD16_U:
                    case WASM_OP_ATOMIC_RMW_I64_ADD32_U:
                    case WASM_OP_ATOMIC_RMW_I64_SUB:
                    case WASM_OP_ATOMIC_RMW_I64_SUB8_U:
                    case WASM_OP_ATOMIC_RMW_I64_SUB16_U:
                    case WASM_OP_ATOMIC_RMW_I64_SUB32_U:
                    case WASM_OP_ATOMIC_RMW_I64_AND:
                    case WASM_OP_ATOMIC_RMW_I64_AND8_U:
                    case WASM_OP_ATOMIC_RMW_I64_AND16_U:
                    case WASM_OP_ATOMIC_RMW_I64_AND32_U:
                    case WASM_OP_ATOMIC_RMW_I64_OR:
                    case WASM_OP_ATOMIC_RMW_I64_OR8_U:
                    case WASM_OP_ATOMIC_RMW_I64_OR16_U:
                    case WASM_OP_ATOMIC_RMW_I64_OR32_U:
                    case WASM_OP_ATOMIC_RMW_I64_XOR:
                    case WASM_OP_ATOMIC_RMW_I64_XOR8_U:
                    case WASM_OP_ATOMIC_RMW_I64_XOR16_U:
                    case WASM_OP_ATOMIC_RMW_I64_XOR32_U:
                    case WASM_OP_ATOMIC_RMW_I64_XCHG:
                    case WASM_OP_ATOMIC_RMW_I64_XCHG8_U:
                    case WASM_OP_ATOMIC_RMW_I64_XCHG16_U:
                    case WASM_OP_ATOMIC_RMW_I64_XCHG32_U:
                        POP_I64();
                        POP_I32();
                        PUSH_I64();
                        break;
                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG:
                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG8_U:
                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG16_U:
                        POP_I32();
                        POP_I32();
                        POP_I32();
                        PUSH_I32();
                        break;
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG:
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG8_U:
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG16_U:
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG32_U:
                        POP_I64();
                        POP_I64();
                        POP_I32();
                        PUSH_I64();
                        break;
                    default:
                        bh_assert(0);
                        break;
                }
                break;
            }
#endif /* end of WASM_ENABLE_SHARED_MEMORY */

            default:
                bh_assert(0);
                break;
        }

#if WASM_ENABLE_FAST_INTERP != 0
        last_op = opcode;
#endif
    }

    if (loader_ctx->csp_num > 0) {
        set_error_buf(error_buf, error_buf_size,
                      "function body must end with END opcode");
        goto fail;
    }

#if WASM_ENABLE_FAST_INTERP != 0
    if (loader_ctx->p_code_compiled == NULL)
        goto re_scan;

    func->const_cell_num = loader_ctx->const_cell_num;
    if (func->const_cell_num > 0) {
        int32 j;

        if (!(func->consts = func_const = loader_malloc(
                  func->const_cell_num * 4, error_buf, error_buf_size)))
            goto fail;

        func_const_end = func->consts + func->const_cell_num * 4;
        /* reverse the const buf */
        for (j = loader_ctx->num_const - 1; j >= 0; j--) {
            Const *c = (Const *)(loader_ctx->const_buf + j * sizeof(Const));
            if (c->value_type == VALUE_TYPE_F64
                || c->value_type == VALUE_TYPE_I64) {
                bh_memcpy_s(func_const, (uint32)(func_const_end - func_const),
                            &(c->value.f64), (uint32)sizeof(int64));
                func_const += sizeof(int64);
            }
            else {
                bh_memcpy_s(func_const, (uint32)(func_const_end - func_const),
                            &(c->value.f32), (uint32)sizeof(int32));
                func_const += sizeof(int32);
            }
        }
    }

    func->max_stack_cell_num = loader_ctx->preserved_local_offset
                               - loader_ctx->start_dynamic_offset + 1;
#else
    func->max_stack_cell_num = loader_ctx->max_stack_cell_num;
#endif
    func->max_block_num = loader_ctx->max_csp_num;
    return_value = true;

fail:
    wasm_loader_ctx_destroy(loader_ctx);

    (void)u8;
    (void)u32;
    (void)i32;
    (void)i64_const;
    (void)global_count;
    (void)local_count;
    (void)local_offset;
    (void)p_org;
    (void)mem_offset;
    (void)align;
#if WASM_ENABLE_BULK_MEMORY != 0
    (void)segment_index;
#endif
    return return_value;
}
