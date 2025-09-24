/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_runtime.h"
#include "../compilation/aot_stack_frame.h"
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

bh_static_assert(offsetof(WASMExecEnv, cur_frame) == 1 * sizeof(uintptr_t));
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
bh_static_assert(offsetof(WASMExecEnv, wasm_stack.top_boundary)
                 == 10 * sizeof(uintptr_t));
bh_static_assert(offsetof(WASMExecEnv, wasm_stack.top)
                 == 11 * sizeof(uintptr_t));
bh_static_assert(offsetof(WASMExecEnv, wasm_stack.bottom)
                 == 12 * sizeof(uintptr_t));

bh_static_assert(offsetof(AOTModuleInstance, memories) == 1 * sizeof(uint64));
bh_static_assert(offsetof(AOTModuleInstance, func_ptrs) == 5 * sizeof(uint64));
bh_static_assert(offsetof(AOTModuleInstance, func_type_indexes)
                 == 6 * sizeof(uint64));
bh_static_assert(offsetof(AOTModuleInstance, cur_exception)
                 == 13 * sizeof(uint64));
bh_static_assert(offsetof(AOTModuleInstance, c_api_func_imports)
                 == 13 * sizeof(uint64) + 128 + 7 * sizeof(uint64));
bh_static_assert(offsetof(AOTModuleInstance, global_table_data)
                 == 13 * sizeof(uint64) + 128 + 14 * sizeof(uint64));

bh_static_assert(sizeof(AOTMemoryInstance) == 120);
bh_static_assert(offsetof(AOTTableInstance, elems) == 24);

bh_static_assert(offsetof(AOTModuleInstanceExtra, stack_sizes) == 0);
bh_static_assert(offsetof(AOTModuleInstanceExtra, shared_heap_base_addr_adj)
                 == 8);
bh_static_assert(offsetof(AOTModuleInstanceExtra, shared_heap_start_off) == 16);
bh_static_assert(offsetof(AOTModuleInstanceExtra, shared_heap_end_off) == 24);
bh_static_assert(offsetof(AOTModuleInstanceExtra, shared_heap) == 32);

bh_static_assert(offsetof(WASMSharedHeap, next) == 0);
bh_static_assert(offsetof(WASMSharedHeap, chain_next) == 8);
bh_static_assert(offsetof(WASMSharedHeap, heap_handle) == 16);
bh_static_assert(offsetof(WASMSharedHeap, base_addr) == 24);
bh_static_assert(offsetof(WASMSharedHeap, size) == 32);
bh_static_assert(offsetof(WASMSharedHeap, start_off_mem64) == 40);
bh_static_assert(offsetof(WASMSharedHeap, start_off_mem32) == 48);

bh_static_assert(sizeof(CApiFuncImport) == sizeof(uintptr_t) * 3);

bh_static_assert(sizeof(wasm_val_t) == 16);
bh_static_assert(offsetof(wasm_val_t, of) == 8);

bh_static_assert(offsetof(AOTFrame, prev_frame) == sizeof(uintptr_t) * 0);
bh_static_assert(offsetof(AOTFrame, func_index) == sizeof(uintptr_t) * 1);
bh_static_assert(offsetof(AOTFrame, time_started) == sizeof(uintptr_t) * 2);
bh_static_assert(offsetof(AOTFrame, func_perf_prof_info)
                 == sizeof(uintptr_t) * 3);
bh_static_assert(offsetof(AOTFrame, ip_offset) == sizeof(uintptr_t) * 4);
bh_static_assert(offsetof(AOTFrame, sp) == sizeof(uintptr_t) * 5);
bh_static_assert(offsetof(AOTFrame, frame_ref) == sizeof(uintptr_t) * 6);
bh_static_assert(offsetof(AOTFrame, lp) == sizeof(uintptr_t) * 7);

bh_static_assert(offsetof(AOTTinyFrame, func_index) == sizeof(uint32) * 0);
bh_static_assert(offsetof(AOTTinyFrame, ip_offset) == sizeof(uint32) * 1);
bh_static_assert(sizeof(AOTTinyFrame) == sizeof(uint32) * 2);

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

#if WASM_ENABLE_AOT_STACK_FRAME != 0
static bool
is_tiny_frame(WASMExecEnv *exec_env)
{
    AOTModule *module =
        (AOTModule *)((AOTModuleInstance *)exec_env->module_inst)->module;

    return module->feature_flags & WASM_FEATURE_TINY_STACK_FRAME;
}

static bool
is_frame_per_function(WASMExecEnv *exec_env)
{
    AOTModule *module =
        (AOTModule *)((AOTModuleInstance *)exec_env->module_inst)->module;

    return module->feature_flags & WASM_FEATURE_FRAME_PER_FUNCTION;
}

#if WASM_ENABLE_DUMP_CALL_STACK != 0
static bool
is_frame_func_idx_disabled(WASMExecEnv *exec_env)
{
    AOTModule *module =
        (AOTModule *)((AOTModuleInstance *)exec_env->module_inst)->module;

    return module->feature_flags & WASM_FEATURE_FRAME_NO_FUNC_IDX;
}
#endif

static void *
get_top_frame(WASMExecEnv *exec_env)
{
    if (is_tiny_frame(exec_env)) {
        return exec_env->wasm_stack.top > exec_env->wasm_stack.bottom
                   ? exec_env->wasm_stack.top - sizeof(AOTTinyFrame)
                   : NULL;
    }
    else {
        return exec_env->cur_frame;
    }
}

static void *
get_prev_frame(WASMExecEnv *exec_env, void *cur_frame)
{
    bh_assert(cur_frame);

    if (is_tiny_frame(exec_env)) {
        if ((uint8 *)cur_frame == exec_env->wasm_stack.bottom) {
            return NULL;
        }
        return ((AOTTinyFrame *)cur_frame) - 1;
    }
    else {
        return ((AOTFrame *)cur_frame)->prev_frame;
    }
}
#endif

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
    /* make spec test happy */
#if WASM_ENABLE_GC != 0
                            + module->global_count
#endif
    ) {
        set_error_buf_v(error_buf, error_buf_size, "unknown global %u",
                        global_index);
        return false;
    }

    if (
    /* make spec test happy */
#if WASM_ENABLE_GC != 0
        global_index < module->import_global_count &&
#endif
        module->import_globals[global_index].type.is_mutable) {
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
#if WASM_ENABLE_GC != 0
            if ((type >= (uint8)REF_TYPE_ARRAYREF
                 && type <= (uint8)REF_TYPE_NULLFUNCREF)
                || (type >= (uint8)REF_TYPE_HT_NULLABLE
                    && type <= (uint8)REF_TYPE_HT_NON_NULLABLE)
#if WASM_ENABLE_STRINGREF != 0
                || (type >= (uint8)REF_TYPE_STRINGVIEWWTF8
                    && type <= (uint8)REF_TYPE_STRINGREF)
                || (type >= (uint8)REF_TYPE_STRINGVIEWITER
                    && type <= (uint8)REF_TYPE_STRINGVIEWWTF16)
#endif
            ) {
                bh_memcpy_s(global_data, sizeof(wasm_obj_t),
                            &initial_value->gc_obj, sizeof(wasm_obj_t));
                break;
            }
#endif /* end of WASM_ENABLE_GC */
            bh_assert(0);
    }
}

#if WASM_ENABLE_GC != 0
static bool
assign_table_init_value(AOTModuleInstance *module_inst, AOTModule *module,
                        InitializerExpression *init_expr, void *addr,
                        char *error_buf, uint32 error_buf_size)
{
    uint8 flag = init_expr->init_expr_type;

    bh_assert(flag >= INIT_EXPR_TYPE_GET_GLOBAL
              && flag <= INIT_EXPR_TYPE_EXTERN_CONVERT_ANY);

    switch (flag) {
        case INIT_EXPR_TYPE_GET_GLOBAL:
        {
            if (!check_global_init_expr(module,
                                        init_expr->u.unary.v.global_index,
                                        error_buf, error_buf_size)) {
                return false;
            }
            if (init_expr->u.unary.v.global_index
                < module->import_global_count) {
                PUT_REF_TO_ADDR(
                    addr,
                    module->import_globals[init_expr->u.unary.v.global_index]
                        .global_data_linked.gc_obj);
            }
            else {
                uint32 global_idx = init_expr->u.unary.v.global_index
                                    - module->import_global_count;
                return assign_table_init_value(
                    module_inst, module, &module->globals[global_idx].init_expr,
                    addr, error_buf, error_buf_size);
            }
            break;
        }
        case INIT_EXPR_TYPE_REFNULL_CONST:
        {
            WASMObjectRef gc_obj = NULL_REF;
            PUT_REF_TO_ADDR(addr, gc_obj);
            break;
        }
        case INIT_EXPR_TYPE_FUNCREF_CONST:
        {
            WASMFuncObjectRef func_obj = NULL;
            uint32 func_idx = init_expr->u.unary.v.u32;

            if (func_idx != UINT32_MAX) {
                if (!(func_obj =
                          aot_create_func_obj(module_inst, func_idx, false,
                                              error_buf, error_buf_size))) {
                    return false;
                }
            }

            PUT_REF_TO_ADDR(addr, func_obj);
            break;
        }
        case INIT_EXPR_TYPE_I31_NEW:
        {
            WASMI31ObjectRef i31_obj =
                wasm_i31_obj_new(init_expr->u.unary.v.i32);
            PUT_REF_TO_ADDR(addr, i31_obj);
            break;
        }
        case INIT_EXPR_TYPE_STRUCT_NEW:
        case INIT_EXPR_TYPE_STRUCT_NEW_DEFAULT:
        {
            WASMRttType *rtt_type;
            WASMStructObjectRef struct_obj;
            WASMStructType *struct_type;
            WASMStructNewInitValues *init_values = NULL;
            uint32 type_idx;

            if (flag == INIT_EXPR_TYPE_STRUCT_NEW) {
                init_values =
                    (WASMStructNewInitValues *)init_expr->u.unary.v.data;
                type_idx = init_values->type_idx;
            }
            else {
                type_idx = init_expr->u.unary.v.type_index;
            }

            struct_type = (WASMStructType *)module->types[type_idx];

            if (!(rtt_type = wasm_rtt_type_new(
                      (WASMType *)struct_type, type_idx, module->rtt_types,
                      module->type_count, &module->rtt_type_lock))) {
                set_error_buf(error_buf, error_buf_size,
                              "create rtt object failed");
                return false;
            }

            if (!(struct_obj = wasm_struct_obj_new_internal(
                      ((AOTModuleInstanceExtra *)module_inst->e)
                          ->common.gc_heap_handle,
                      rtt_type))) {
                set_error_buf(error_buf, error_buf_size,
                              "create struct object failed");
                return false;
            }

            if (flag == INIT_EXPR_TYPE_STRUCT_NEW) {
                uint32 field_idx;

                bh_assert(init_values->count == struct_type->field_count);

                for (field_idx = 0; field_idx < init_values->count;
                     field_idx++) {
                    wasm_struct_obj_set_field(struct_obj, field_idx,
                                              &init_values->fields[field_idx]);
                }
            }

            PUT_REF_TO_ADDR(addr, struct_obj);
            break;
        }
        case INIT_EXPR_TYPE_ARRAY_NEW:
        case INIT_EXPR_TYPE_ARRAY_NEW_DEFAULT:
        case INIT_EXPR_TYPE_ARRAY_NEW_FIXED:
        {
            WASMRttType *rtt_type;
            WASMArrayObjectRef array_obj;
            WASMArrayType *array_type;
            WASMArrayNewInitValues *init_values = NULL;
            WASMValue *arr_init_val = NULL, empty_val = { 0 };
            uint32 type_idx, len;

            if (flag == INIT_EXPR_TYPE_ARRAY_NEW_DEFAULT) {
                type_idx = init_expr->u.unary.v.array_new_default.type_index;
                len = init_expr->u.unary.v.array_new_default.length;
                arr_init_val = &empty_val;
            }
            else {
                init_values =
                    (WASMArrayNewInitValues *)init_expr->u.unary.v.data;
                type_idx = init_values->type_idx;
                len = init_values->length;

                if (flag == INIT_EXPR_TYPE_ARRAY_NEW) {
                    arr_init_val = init_values->elem_data;
                }
            }

            array_type = (WASMArrayType *)module->types[type_idx];

            if (!(rtt_type = wasm_rtt_type_new(
                      (WASMType *)array_type, type_idx, module->rtt_types,
                      module->type_count, &module->rtt_type_lock))) {
                set_error_buf(error_buf, error_buf_size,
                              "create rtt object failed");
                return false;
            }

            if (!(array_obj = wasm_array_obj_new_internal(
                      ((AOTModuleInstanceExtra *)module_inst->e)
                          ->common.gc_heap_handle,
                      rtt_type, len, arr_init_val))) {
                set_error_buf(error_buf, error_buf_size,
                              "create array object failed");
                return false;
            }

            if (flag == INIT_EXPR_TYPE_ARRAY_NEW_FIXED) {
                uint32 elem_idx;

                bh_assert(init_values);

                for (elem_idx = 0; elem_idx < len; elem_idx++) {
                    wasm_array_obj_set_elem(array_obj, elem_idx,
                                            &init_values->elem_data[elem_idx]);
                }
            }

            PUT_REF_TO_ADDR(addr, array_obj);
            break;
        }
        default:
            set_error_buf(error_buf, error_buf_size, "invalid init expr type.");
            return false;
    }

    return true;
}
#endif /* end of WASM_ENABLE_GC != 0 */

static bool
get_init_value_recursive(AOTModuleInstance *module_inst, AOTModule *module,
                         InitializerExpression *expr, WASMValue *value,
                         char *error_buf, uint32 error_buf_size)
{
    uint8 flag = expr->init_expr_type;
    switch (flag) {
        case INIT_EXPR_TYPE_GET_GLOBAL:
        {
            if (!check_global_init_expr(module, expr->u.unary.v.global_index,
                                        error_buf, error_buf_size)) {
                return false;
            }
#if WASM_ENABLE_GC == 0
            *value = module->import_globals[expr->u.unary.v.global_index]
                         .global_data_linked;
#else
            if (expr->u.unary.v.global_index < module->import_global_count) {
                *value = module->import_globals[expr->u.unary.v.global_index]
                             .global_data_linked;
            }
            else {
                *value = module
                             ->globals[expr->u.unary.v.global_index
                                       - module->import_global_count]
                             .init_expr.u.unary.v;
            }
#endif
            break;
        }
        case INIT_EXPR_TYPE_I32_CONST:
        case INIT_EXPR_TYPE_I64_CONST:
        {
            *value = expr->u.unary.v;
            break;
        }
#if WASM_ENABLE_EXTENDED_CONST_EXPR != 0
        case INIT_EXPR_TYPE_I32_ADD:
        case INIT_EXPR_TYPE_I32_SUB:
        case INIT_EXPR_TYPE_I32_MUL:
        case INIT_EXPR_TYPE_I64_ADD:
        case INIT_EXPR_TYPE_I64_SUB:
        case INIT_EXPR_TYPE_I64_MUL:
        {
            WASMValue l_value, r_value;
            if (!get_init_value_recursive(module_inst, module,
                                          expr->u.binary.l_expr, &l_value,
                                          error_buf, error_buf_size)) {
                return false;
            }
            if (!get_init_value_recursive(module_inst, module,
                                          expr->u.binary.r_expr, &r_value,
                                          error_buf, error_buf_size)) {
                return false;
            }

            if (flag == INIT_EXPR_TYPE_I32_ADD) {
                value->i32 = l_value.i32 + r_value.i32;
            }
            else if (flag == INIT_EXPR_TYPE_I32_SUB) {
                value->i32 = l_value.i32 - r_value.i32;
            }
            else if (flag == INIT_EXPR_TYPE_I32_MUL) {
                value->i32 = l_value.i32 * r_value.i32;
            }
            else if (flag == INIT_EXPR_TYPE_I64_ADD) {
                value->i64 = l_value.i64 + r_value.i64;
            }
            else if (flag == INIT_EXPR_TYPE_I64_SUB) {
                value->i64 = l_value.i64 - r_value.i64;
            }
            else if (flag == INIT_EXPR_TYPE_I64_MUL) {
                value->i64 = l_value.i64 * r_value.i64;
            }
            break;
        }
#endif
        default:
            return false;
    }

    return true;
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
        init_global_data(p, import_global->type.val_type,
                         &import_global->global_data_linked);
        p += import_global->size;
    }

    /* Initialize defined global data */
    for (i = 0; i < module->global_count; i++, global++) {
        uint8 flag;
        bh_assert(global->data_offset
                  == (uint32)(p - module_inst->global_data));
        init_expr = &global->init_expr;
        flag = init_expr->init_expr_type;
        switch (flag) {
            case INIT_EXPR_TYPE_GET_GLOBAL:
            case INIT_EXPR_TYPE_I32_CONST:
            case INIT_EXPR_TYPE_I64_CONST:
#if WASM_ENABLE_EXTENDED_CONST_EXPR != 0
            case INIT_EXPR_TYPE_I32_ADD:
            case INIT_EXPR_TYPE_I32_SUB:
            case INIT_EXPR_TYPE_I32_MUL:
            case INIT_EXPR_TYPE_I64_ADD:
            case INIT_EXPR_TYPE_I64_SUB:
            case INIT_EXPR_TYPE_I64_MUL:
#endif
            {
                WASMValue value;
                if (!get_init_value_recursive(module_inst, module, init_expr,
                                              &value, error_buf,
                                              error_buf_size)) {
                    return false;
                }
                init_global_data(p, global->type.val_type, &value);
                break;
            }
#if WASM_ENABLE_GC == 0 && WASM_ENABLE_REF_TYPES != 0
            case INIT_EXPR_TYPE_REFNULL_CONST:
            {
                *(uint32 *)p = NULL_REF;
                break;
            }
#elif WASM_ENABLE_GC != 0
            case INIT_EXPR_TYPE_REFNULL_CONST:
            {
                WASMObjectRef gc_obj = NULL_REF;
                PUT_REF_TO_ADDR(p, gc_obj);
                break;
            }
#endif
#if WASM_ENABLE_GC != 0
            case INIT_EXPR_TYPE_FUNCREF_CONST:
            {
                WASMFuncObjectRef func_obj = NULL;
                uint32 func_idx = init_expr->u.unary.v.ref_index;

                if (func_idx != UINT32_MAX) {
                    if (!(func_obj =
                              aot_create_func_obj(module_inst, func_idx, false,
                                                  error_buf, error_buf_size))) {
                        return false;
                    }
                }

                PUT_REF_TO_ADDR(p, func_obj);
                break;
            }
            case INIT_EXPR_TYPE_I31_NEW:
            {
                WASMI31ObjectRef i31_obj =
                    wasm_i31_obj_new(init_expr->u.unary.v.i32);
                PUT_REF_TO_ADDR(p, i31_obj);
                break;
            }
            case INIT_EXPR_TYPE_STRUCT_NEW:
            case INIT_EXPR_TYPE_STRUCT_NEW_DEFAULT:
            {
                WASMRttType *rtt_type;
                WASMStructObjectRef struct_obj;
                WASMStructType *struct_type;
                WASMStructNewInitValues *init_values = NULL;
                uint32 type_idx;

                if (flag == INIT_EXPR_TYPE_STRUCT_NEW) {
                    init_values =
                        (WASMStructNewInitValues *)init_expr->u.unary.v.data;
                    type_idx = init_values->type_idx;
                }
                else {
                    type_idx = init_expr->u.unary.v.type_index;
                }

                struct_type = (WASMStructType *)module->types[type_idx];

                if (!(rtt_type = wasm_rtt_type_new(
                          (WASMType *)struct_type, type_idx, module->rtt_types,
                          module->type_count, &module->rtt_type_lock))) {
                    set_error_buf(error_buf, error_buf_size,
                                  "create rtt object failed");
                    return false;
                }

                if (!(struct_obj = wasm_struct_obj_new_internal(
                          ((AOTModuleInstanceExtra *)module_inst->e)
                              ->common.gc_heap_handle,
                          rtt_type))) {
                    set_error_buf(error_buf, error_buf_size,
                                  "create struct object failed");
                    return false;
                }

                if (flag == INIT_EXPR_TYPE_STRUCT_NEW) {
                    uint32 field_idx;

                    bh_assert(init_values->count == struct_type->field_count);

                    for (field_idx = 0; field_idx < init_values->count;
                         field_idx++) {
                        wasm_struct_obj_set_field(
                            struct_obj, field_idx,
                            &init_values->fields[field_idx]);
                    }
                }

                PUT_REF_TO_ADDR(p, struct_obj);
                break;
            }
            case INIT_EXPR_TYPE_ARRAY_NEW:
            case INIT_EXPR_TYPE_ARRAY_NEW_DEFAULT:
            case INIT_EXPR_TYPE_ARRAY_NEW_FIXED:
            {
                WASMRttType *rtt_type;
                WASMArrayObjectRef array_obj;
                WASMArrayType *array_type;
                WASMArrayNewInitValues *init_values = NULL;
                WASMValue *arr_init_val = NULL, empty_val = { 0 };
                uint32 type_idx, len;

                if (flag == INIT_EXPR_TYPE_ARRAY_NEW_DEFAULT) {
                    type_idx =
                        init_expr->u.unary.v.array_new_default.type_index;
                    len = init_expr->u.unary.v.array_new_default.length;
                    arr_init_val = &empty_val;
                }
                else {
                    init_values =
                        (WASMArrayNewInitValues *)init_expr->u.unary.v.data;
                    type_idx = init_values->type_idx;
                    len = init_values->length;

                    if (flag == INIT_EXPR_TYPE_ARRAY_NEW) {
                        arr_init_val = init_values->elem_data;
                    }
                }

                array_type = (WASMArrayType *)module->types[type_idx];

                if (!(rtt_type = wasm_rtt_type_new(
                          (WASMType *)array_type, type_idx, module->rtt_types,
                          module->type_count, &module->rtt_type_lock))) {
                    set_error_buf(error_buf, error_buf_size,
                                  "create rtt object failed");
                    return false;
                }

                if (!(array_obj = wasm_array_obj_new_internal(
                          ((AOTModuleInstanceExtra *)module_inst->e)
                              ->common.gc_heap_handle,
                          rtt_type, len, arr_init_val))) {
                    set_error_buf(error_buf, error_buf_size,
                                  "create array object failed");
                    return false;
                }

                if (flag == INIT_EXPR_TYPE_ARRAY_NEW_FIXED) {
                    uint32 elem_idx;

                    bh_assert(init_values);

                    for (elem_idx = 0; elem_idx < len; elem_idx++) {
                        wasm_array_obj_set_elem(
                            array_obj, elem_idx,
                            &init_values->elem_data[elem_idx]);
                    }
                }

                PUT_REF_TO_ADDR(p, array_obj);
                break;
            }
#endif /* end of WASM_ENABLE_GC != 0 */
            default:
            {
                init_global_data(p, global->type.val_type,
                                 &init_expr->u.unary.v);
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
    uint8 offset_flag;

    total_size = (uint64)sizeof(AOTTableInstance *) * module_inst->table_count;
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
            tbl_inst->cur_size = import_table->table_type.init_size;
            tbl_inst->max_size =
                aot_get_imp_tbl_data_slots(import_table, false);
            tbl_inst->elem_type = import_table->table_type.elem_type;
            tbl_inst->is_table64 =
                import_table->table_type.flags & TABLE64_FLAG;
#if WASM_ENABLE_GC != 0
            tbl_inst->elem_ref_type.elem_ref_type =
                import_table->table_type.elem_ref_type;
#endif
        }
        else {
            AOTTable *table = module->tables + (i - module->import_table_count);
            tbl_inst->cur_size = table->table_type.init_size;
            tbl_inst->max_size = aot_get_tbl_data_slots(table, false);
            tbl_inst->elem_type = table->table_type.elem_type;
            tbl_inst->is_table64 = table->table_type.flags & TABLE64_FLAG;
#if WASM_ENABLE_GC != 0
            tbl_inst->elem_ref_type.elem_ref_type =
                table->table_type.elem_ref_type;
#endif
        }

        /* Set all elements to -1 or NULL_REF to mark them as uninitialized
         * elements */
#if WASM_ENABLE_GC == 0
        memset(tbl_inst->elems, 0xff,
               sizeof(table_elem_type_t) * tbl_inst->max_size);
#else
        memset(tbl_inst->elems, 0x00,
               sizeof(table_elem_type_t) * tbl_inst->max_size);
#endif

        module_inst->tables[i] = tbl_inst;
        tbl_inst = (AOTTableInstance *)((uint8 *)tbl_inst
                                        + offsetof(AOTTableInstance, elems)
                                        + sizeof(table_elem_type_t)
                                              * tbl_inst->max_size);
    }

    /* fill table with element segment content */
    for (i = 0; i < module->table_init_data_count; i++) {
#if WASM_ENABLE_GC == 0
        uint32 j;
#endif
        table_seg = module->table_init_data_list[i];

#if WASM_ENABLE_REF_TYPES != 0 || WASM_ENABLE_GC != 0
        if (!wasm_elem_is_active(table_seg->mode))
            continue;
#endif

        bh_assert(table_seg->table_index < module_inst->table_count);

        tbl_inst = module_inst->tables[table_seg->table_index];
        bh_assert(tbl_inst);

        offset_flag = table_seg->offset.init_expr_type;

#if WASM_ENABLE_REF_TYPES != 0
        bh_assert(offset_flag == INIT_EXPR_TYPE_GET_GLOBAL
                  || offset_flag == INIT_EXPR_TYPE_FUNCREF_CONST
                  || offset_flag == INIT_EXPR_TYPE_REFNULL_CONST
                  || (tbl_inst->is_table64 ? is_valid_i64_offset(offset_flag)
                                           : is_valid_i32_offset(offset_flag)));
#else
        bh_assert(offset_flag == INIT_EXPR_TYPE_GET_GLOBAL
                  || (tbl_inst->is_table64 ? is_valid_i64_offset(offset_flag)
                                           : is_valid_i32_offset(offset_flag)));
#endif

        /* Resolve table data base offset */
        /* TODO: The table64 current implementation assumes table max size
         * UINT32_MAX, so the offset conversion here is safe */
        if (offset_flag == INIT_EXPR_TYPE_GET_GLOBAL) {
            global_index = table_seg->offset.u.unary.v.global_index;

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
            WASMValue offset_value;
            if (!get_init_value_recursive(module_inst, module,
                                          &table_seg->offset, &offset_value,
                                          error_buf, error_buf_size)) {
                return false;
            }
            base_offset = (uint32)offset_value.i32;
        }

        /* Copy table data */
        /* base_offset only since length might negative */
        if (base_offset > tbl_inst->cur_size) {
#if WASM_ENABLE_REF_TYPES != 0
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds table access");
#else
            set_error_buf(error_buf, error_buf_size,
                          "type mismatch: elements segment does not fit");
#endif
            return false;
        }

        /* base_offset + length(could be zero) */
        length = table_seg->value_count;
        if (base_offset + length > tbl_inst->cur_size) {
#if WASM_ENABLE_REF_TYPES != 0
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds table access");
#else
            set_error_buf(error_buf, error_buf_size,
                          "type mismatch: elements segment does not fit");
#endif
            return false;
        }

        /**
         * Check function index in the current module inst for now.
         * will check the linked table inst owner in future
         */
#if WASM_ENABLE_GC == 0
        for (j = 0; j < length; j++) {
            tbl_inst->elems[base_offset + j] =
                table_seg->init_values[j].u.unary.v.ref_index;
        }
#endif
    }

    return true;
}

static void
memories_deinstantiate(AOTModuleInstance *module_inst)
{
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
                wasm_deallocate_linear_memory(memory_inst);
            }
        }
    }
    wasm_runtime_free(module_inst->memories);
}

static AOTMemoryInstance *
memory_instantiate(AOTModuleInstance *module_inst, AOTModuleInstance *parent,
                   AOTModule *module, AOTMemoryInstance *memory_inst,
                   AOTMemory *memory, uint32 memory_idx, uint32 heap_size,
                   uint32 max_memory_pages, char *error_buf,
                   uint32 error_buf_size)
{
    void *heap_handle;
    uint32 num_bytes_per_page = memory->num_bytes_per_page;
    uint32 init_page_count = memory->init_page_count;
    uint32 max_page_count = wasm_runtime_get_max_mem(
        max_memory_pages, memory->init_page_count, memory->max_page_count);
    uint32 default_max_pages;
    uint32 inc_page_count, global_idx;
    uint32 bytes_of_last_page, bytes_to_page_end;
    uint64 aux_heap_base,
        heap_offset = (uint64)num_bytes_per_page * init_page_count;
    uint64 memory_data_size, max_memory_data_size;
    uint8 *p = NULL, *global_addr;
    bool is_memory64 = memory->flags & MEMORY64_FLAG;

    bool is_shared_memory = false;
#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared_memory = memory->flags & SHARED_MEMORY_FLAG ? true : false;
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

#if WASM_ENABLE_MEMORY64 != 0
    if (is_memory64) {
        default_max_pages = DEFAULT_MEM64_MAX_PAGES;
    }
    else
#endif
    {
        default_max_pages = DEFAULT_MAX_PAGES;
    }

    if (heap_size > 0 && module->malloc_func_index != (uint32)-1
        && module->free_func_index != (uint32)-1) {
        /* Disable app heap, use malloc/free function exported
           by wasm app to allocate/free memory instead */
        heap_size = 0;
    }

    /* If initial memory is the largest size allowed, disallowing insert host
     * managed heap */
    if (heap_size > 0 && heap_offset == MAX_LINEAR_MEMORY_SIZE) {
        set_error_buf(error_buf, error_buf_size,
                      "failed to insert app heap into linear memory, "
                      "try using `--heap-size=0` option");
        return NULL;
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
                        < (uint64)num_bytes_per_page * init_page_count) {
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
            *(uint32 *)global_addr = (uint32)aux_heap_base;
            LOG_VERBOSE("Reset __heap_base global to %" PRIu64, aux_heap_base);
        }
        else {
            /* Insert app heap before new page */
            inc_page_count =
                (heap_size + num_bytes_per_page - 1) / num_bytes_per_page;
            heap_offset = (uint64)num_bytes_per_page * init_page_count;
            heap_size = (uint64)num_bytes_per_page * inc_page_count;
            if (heap_size > 0)
                heap_size -= 1 * BH_KB;
        }
        init_page_count += inc_page_count;
        max_page_count += inc_page_count;
        if (init_page_count > default_max_pages) {
            set_error_buf(error_buf, error_buf_size,
                          "failed to insert app heap into linear memory, "
                          "try using `--heap-size=0` option");
            return NULL;
        }
        if (max_page_count > default_max_pages)
            max_page_count = default_max_pages;
    }

    LOG_VERBOSE("Memory instantiate:");
    LOG_VERBOSE("  page bytes: %u, init pages: %u, max pages: %u",
                num_bytes_per_page, init_page_count, max_page_count);
    LOG_VERBOSE("  data offset: %" PRIu64 ", stack size: %d",
                module->aux_data_end, module->aux_stack_size);
    LOG_VERBOSE("  heap offset: %" PRIu64 ", heap size: %d\n", heap_offset,
                heap_size);

    max_memory_data_size = (uint64)num_bytes_per_page * max_page_count;
    bh_assert(max_memory_data_size <= GET_MAX_LINEAR_MEMORY_SIZE(is_memory64));
    (void)max_memory_data_size;

    /* TODO: memory64 uses is_memory64 flag */
    if (wasm_allocate_linear_memory(&p, is_shared_memory, is_memory64,
                                    num_bytes_per_page, init_page_count,
                                    max_page_count, &memory_data_size)
        != BHT_OK) {
        set_error_buf(error_buf, error_buf_size,
                      "allocate linear memory failed");
        return NULL;
    }

    memory_inst->module_type = Wasm_Module_AoT;
    memory_inst->num_bytes_per_page = num_bytes_per_page;
    memory_inst->cur_page_count = init_page_count;
    memory_inst->max_page_count = max_page_count;
    memory_inst->memory_data_size = memory_data_size;
#if WASM_ENABLE_MEMORY64 != 0
    if (is_memory64) {
        memory_inst->is_memory64 = 1;
    }
#endif

    /* Init memory info */
    memory_inst->memory_data = p;
    memory_inst->memory_data_end = p + memory_data_size;

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
    wasm_deallocate_linear_memory(memory_inst);

    return NULL;
}

AOTMemoryInstance *
aot_lookup_memory(AOTModuleInstance *module_inst, char const *name)
{
#if WASM_ENABLE_MULTI_MEMORY != 0
    uint32 i;
    for (i = 0; i < module_inst->export_memory_count; i++)
        if (!strcmp(module_inst->export_memories[i].name, name))
            return module_inst->export_memories[i].memory;
    return NULL;
#else
    (void)module_inst->export_memories;
    if (!module_inst->memories)
        return NULL;
    return module_inst->memories[0];
#endif
}

AOTMemoryInstance *
aot_get_default_memory(AOTModuleInstance *module_inst)
{
    if (module_inst->memories)
        return module_inst->memories[0];
    else
        return NULL;
}

AOTMemoryInstance *
aot_get_memory_with_idx(AOTModuleInstance *module_inst, uint32 mem_idx)
{
    if ((mem_idx >= module_inst->memory_count) || !module_inst->memories)
        return NULL;
    return module_inst->memories[mem_idx];
}

static bool
memories_instantiate(AOTModuleInstance *module_inst, AOTModuleInstance *parent,
                     AOTModule *module, uint32 heap_size,
                     uint32 max_memory_pages, char *error_buf,
                     uint32 error_buf_size)
{
    uint32 global_index, global_data_offset, length;
    uint32 i, memory_count = module->memory_count;
    AOTMemoryInstance *memories, *memory_inst;
    AOTMemInitData *data_seg;
    uint64 total_size;
    mem_offset_t base_offset;
    uint8 offset_flag;

    module_inst->memory_count = memory_count;
    total_size = sizeof(AOTMemoryInstance *) * (uint64)memory_count;
    if (!(module_inst->memories =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return false;
    }

    memories = module_inst->global_table_data.memory_instances;
    for (i = 0; i < memory_count; i++, memories++) {
        memory_inst = memory_instantiate(
            module_inst, parent, module, memories, &module->memories[i], i,
            heap_size, max_memory_pages, error_buf, error_buf_size);
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

        offset_flag = data_seg->offset.init_expr_type;
        bh_assert(offset_flag == INIT_EXPR_TYPE_GET_GLOBAL
                  || (memory_inst->is_memory64
                          ? is_valid_i64_offset(offset_flag)
                          : is_valid_i32_offset(offset_flag)));

        /* Resolve memory data base offset */
        if (offset_flag == INIT_EXPR_TYPE_GET_GLOBAL) {
            global_index = data_seg->offset.u.unary.v.global_index;

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

#if WASM_ENABLE_MEMORY64 != 0
            if (memory_inst->is_memory64) {
                base_offset =
                    *(uint64 *)(module_inst->global_data + global_data_offset);
            }
            else
#endif
            {
                base_offset =
                    *(uint32 *)(module_inst->global_data + global_data_offset);
            }
        }
        else {
            WASMValue offset_value;
            if (!get_init_value_recursive(module_inst, module,
                                          &data_seg->offset, &offset_value,
                                          error_buf, error_buf_size)) {
                return false;
            }
#if WASM_ENABLE_MEMORY64 != 0
            if (memory_inst->is_memory64) {
                base_offset = offset_value.i64;
            }
            else
#endif
            {
                base_offset = offset_value.u32;
            }
        }

        /* Copy memory data */
        bh_assert(memory_inst->memory_data
                  || memory_inst->memory_data_size == 0);

        /* Check memory data */
        /* check offset since length might negative */
        if (base_offset > memory_inst->memory_data_size) {
            LOG_DEBUG("base_offset(%" PR_MEM_OFFSET
                      ") > memory_data_size(%" PRIu64 ")",
                      base_offset, memory_inst->memory_data_size);
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
            LOG_DEBUG("base_offset(%" PR_MEM_OFFSET
                      ") + length(%d) > memory_data_size(%" PRIu64 ")",
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
                        (uint32)(memory_inst->memory_data_size - base_offset),
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

static int
cmp_export_func_map(const void *a, const void *b)
{
    uint32 func_idx1 = ((const ExportFuncMap *)a)->func_idx;
    uint32 func_idx2 = ((const ExportFuncMap *)b)->func_idx;
    return func_idx1 < func_idx2 ? -1 : (func_idx1 > func_idx2 ? 1 : 0);
}

AOTFunctionInstance *
aot_lookup_function_with_idx(AOTModuleInstance *module_inst, uint32 func_idx)
{
    AOTModuleInstanceExtra *extra = (AOTModuleInstanceExtra *)module_inst->e;
    AOTFunctionInstance *export_funcs =
        (AOTFunctionInstance *)module_inst->export_functions;
    AOTFunctionInstance *func_inst = NULL;
    ExportFuncMap *export_func_maps, *export_func_map, key;
    uint64 size;
    uint32 i;

    if (module_inst->export_func_count == 0)
        return NULL;

    exception_lock(module_inst);

    /* create the func_idx to export_idx maps if it hasn't been created */
    if (!extra->export_func_maps) {
        size = sizeof(ExportFuncMap) * (uint64)module_inst->export_func_count;
        if (!(export_func_maps = extra->export_func_maps =
                  runtime_malloc(size, NULL, 0))) {
            /* allocate memory failed, lookup the export function one by one */
            for (i = 0; i < module_inst->export_func_count; i++) {
                if (export_funcs[i].func_index == func_idx) {
                    func_inst = &export_funcs[i];
                    break;
                }
            }
            goto unlock_and_return;
        }

        for (i = 0; i < module_inst->export_func_count; i++) {
            export_func_maps[i].func_idx = export_funcs[i].func_index;
            export_func_maps[i].export_idx = i;
        }

        qsort(export_func_maps, module_inst->export_func_count,
              sizeof(ExportFuncMap), cmp_export_func_map);
    }

    /* lookup the map to get the export_idx of the func_idx */
    key.func_idx = func_idx;
    export_func_map =
        bsearch(&key, extra->export_func_maps, module_inst->export_func_count,
                sizeof(ExportFuncMap), cmp_export_func_map);
    if (export_func_map)
        func_inst = &export_funcs[export_func_map->export_idx];

unlock_and_return:
    exception_unlock(module_inst);
    return func_inst;
}

AOTFunctionInstance *
aot_get_function_instance(AOTModuleInstance *module_inst, uint32 func_idx)
{
    AOTModule *module = (AOTModule *)module_inst->module;
    AOTModuleInstanceExtra *extra = (AOTModuleInstanceExtra *)module_inst->e;
    AOTFunctionInstance *func_inst;

    /* lookup from export functions first */
    if ((func_inst = aot_lookup_function_with_idx(module_inst, func_idx)))
        return func_inst;

    exception_lock(module_inst);

    /* allocate functions array if needed */
    if (!extra->functions) {
        uint64 func_count =
            ((uint64)module->import_func_count + module->func_count);
        uint64 total_size = func_count * (uint64)sizeof(AOTFunctionInstance *);

        if ((func_count == 0)
            || !(extra->functions = runtime_malloc(total_size, NULL, 0))) {
            exception_unlock(module_inst);
            return NULL;
        }

        extra->function_count = (uint32)func_count;
    }

    /* instantiate function if needed */
    bh_assert(func_idx < extra->function_count);
    if (!extra->functions[func_idx]) {
        AOTFunctionInstance *function = (AOTFunctionInstance *)runtime_malloc(
            sizeof(AOTFunctionInstance), NULL, 0);
        if (!function) {
            exception_unlock(module_inst);
            return NULL;
        }

        if (func_idx < module->import_func_count) {
            /* instantiate function from import section */
            function->is_import_func = true;
            function->func_name = module->import_funcs[func_idx].func_name;
            function->func_index = func_idx;
            function->u.func_import = &module->import_funcs[func_idx];
        }
        else {
            /* instantiate non-import function */
            uint32 ftype_index =
                module->func_type_indexes[func_idx - module->import_func_count];
            function->is_import_func = false;
            function->func_index = func_idx;
            function->u.func.func_type =
                (AOTFuncType *)module->types[ftype_index];
            function->u.func.func_ptr =
                module->func_ptrs[func_idx - module->import_func_count];
        }

        extra->functions[func_idx] = function;
    }

    exception_unlock(module_inst);

    return extra->functions[func_idx];
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

static int
cmp_func_inst(const void *a, const void *b)
{
    const AOTFunctionInstance *func_inst1 = (const AOTFunctionInstance *)a;
    const AOTFunctionInstance *func_inst2 = (const AOTFunctionInstance *)b;

    return strcmp(func_inst1->func_name, func_inst2->func_name);
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
                        (AOTFuncType *)module->types[ftype_index];
                    export_func->u.func.func_ptr =
                        module->func_ptrs[func_index];
                }
                export_func++;
            }
        }

        qsort(module_inst->export_functions, module_inst->export_func_count,
              sizeof(AOTFunctionInstance), cmp_func_inst);
    }

    return true;
}

#if WASM_ENABLE_MULTI_MEMORY != 0
static WASMExportMemInstance *
export_memories_instantiate(const AOTModule *module,
                            AOTModuleInstance *module_inst,
                            uint32 export_mem_count, char *error_buf,
                            uint32 error_buf_size)
{
    WASMExportMemInstance *export_memories, *export_memory;
    AOTExport *export = module->exports;
    uint32 i;
    uint64 total_size =
        sizeof(WASMExportMemInstance) * (uint64)export_mem_count;

    if (!(export_memory = export_memories =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        return NULL;
    }

    for (i = 0; i < module->export_count; i++, export ++)
        if (export->kind == EXPORT_KIND_MEMORY) {
            export_memory->name = export->name;
            export_memory->memory = module_inst->memories[export->index];
            export_memory++;
        }

    bh_assert((uint32)(export_memory - export_memories) == export_mem_count);
    return export_memories;
}
#endif /* end of if WASM_ENABLE_MULTI_MEMORY != 0 */

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

#if WASM_ENABLE_MULTI_MEMORY != 0
    if (module_inst->export_memory_count) {
        module_inst->export_memories = export_memories_instantiate(
            module, module_inst, module_inst->export_memory_count, error_buf,
            error_buf_size);
        if (!module_inst->export_memories) {
            return false;
        }
    }
#endif

    return create_export_funcs(module_inst, module, error_buf, error_buf_size);
}

static AOTFunctionInstance *
lookup_post_instantiate_func(AOTModuleInstance *module_inst,
                             const char *func_name)
{
    AOTFunctionInstance *func;
    AOTFuncType *func_type;

    if (!(func = aot_lookup_function(module_inst, func_name)))
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
        /* May come from pthread_create_wrapper, thread_spawn_wrapper and
           wasm_cluster_spawn_exec_env. If it comes from the former two,
           the exec_env_tls must be not NULL and equal to exec_env_main,
           else if it comes from the last one, it may be NULL. */
        if (exec_env_tls)
            bh_assert(exec_env_tls == exec_env_main);
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

    /* Execute start function for both main instance and sub instance */
    if (module->start_function) {
        AOTFunctionInstance start_func = { 0 };
        uint32 func_type_idx;

        start_func.func_name = "";
        start_func.func_index = module->start_func_index;
        start_func.is_import_func = false;
        func_type_idx = module->func_type_indexes[module->start_func_index
                                                  - module->import_func_count];
        start_func.u.func.func_type =
            (AOTFuncType *)module->types[func_type_idx];
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
                uint32 max_memory_pages, char *error_buf, uint32 error_buf_size)
{
    AOTModuleInstance *module_inst;
#if WASM_ENABLE_BULK_MEMORY != 0 || WASM_ENABLE_REF_TYPES != 0
    WASMModuleInstanceExtraCommon *common;
#endif
    AOTModuleInstanceExtra *extra = NULL;
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

    /* Align and validate heap size */
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
        table_size += (uint64)sizeof(table_elem_type_t)
                      * (uint64)aot_get_imp_tbl_data_slots(
                          module->import_tables + i, false);
    }

    for (i = 0; i != module->table_count; ++i) {
        table_size += offsetof(AOTTableInstance, elems);
        table_size +=
            (uint64)sizeof(table_elem_type_t)
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
    extra = (AOTModuleInstanceExtra *)module_inst->e;

#if WASM_ENABLE_GC != 0
    /* Initialize gc heap first since it may be used when initializing
       globals and others */
    if (!is_sub_inst) {
        uint32 gc_heap_size = wasm_runtime_get_gc_heap_size_default();

        if (gc_heap_size < GC_HEAP_SIZE_MIN)
            gc_heap_size = GC_HEAP_SIZE_MIN;
        if (gc_heap_size > GC_HEAP_SIZE_MAX)
            gc_heap_size = GC_HEAP_SIZE_MAX;

        extra->common.gc_heap_pool =
            runtime_malloc(gc_heap_size, error_buf, error_buf_size);
        if (!extra->common.gc_heap_pool)
            goto fail;

        extra->common.gc_heap_handle =
            mem_allocator_create(extra->common.gc_heap_pool, gc_heap_size);
        if (!extra->common.gc_heap_handle)
            goto fail;
    }
#endif

#if WASM_ENABLE_MULTI_MODULE != 0
    extra->sub_module_inst_list = &extra->sub_module_inst_list_head;

    /* Allocate memory for import_func_module_insts*/
    if (module->import_func_count > 0
        && !(extra->import_func_module_insts =
                 runtime_malloc((uint64)module->import_func_count
                                    * sizeof(WASMModuleInstanceCommon *),
                                error_buf, error_buf_size))) {
        goto fail;
    }

    ret = wasm_runtime_sub_module_instantiate(
        (WASMModuleCommon *)module, (WASMModuleInstanceCommon *)module_inst,
        stack_size, heap_size, max_memory_pages, error_buf, error_buf_size);
    if (!ret) {
        LOG_DEBUG("build a sub module list failed");
        goto fail;
    }
#endif

    /* Initialize function type indexes before initializing global info,
       module_inst->func_type_indexes may be used in the latter */
    if (!init_func_type_indexes(module_inst, module, error_buf, error_buf_size))
        goto fail;

#if WASM_ENABLE_BULK_MEMORY != 0 || WASM_ENABLE_REF_TYPES != 0
    common = &extra->common;
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
            if (wasm_elem_is_active(module->table_init_data_list[i]->mode)
                || wasm_elem_is_declarative(
                    module->table_init_data_list[i]->mode))
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
    if (!memories_instantiate(module_inst, parent, module, heap_size,
                              max_memory_pages, error_buf, error_buf_size))
        goto fail;

    /* Initialize function pointers */
    if (!init_func_ptrs(module_inst, module, error_buf, error_buf_size))
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

    module_inst->default_wasm_stack_size = stack_size;

    extra->stack_sizes =
        aot_get_data_section_addr(module, AOT_STACK_SIZES_SECTION_NAME, NULL);

    /*
     * The AOT code checks whether the n bytes to access are in shared heap
     * by checking whether the beginning address meets:
     *   addr >= start_off && addr <= end_off - n-bytes + 1
     * where n is 1/2/4/8/16 and `end_off - n-bytes + 1` is constant, e.g.,
     *   UINT32_MAX, UINT32_MAX-1, UINT32_MAX-3 for n = 1, 2 or 4 in 32-bit
     * target. To simplify the check, when shared heap is disabled, we set
     * the start off to UINT64_MAX in 64-bit target and UINT32_MAX in 32-bit
     * target, so in the checking, the above formula will be false, we don't
     * need to check whether the shared heap is enabled or not in the AOT
     * code.
     */
#if UINTPTR_MAX == UINT64_MAX
    extra->shared_heap_start_off.u64 = UINT64_MAX;
#else
    extra->shared_heap_start_off.u32[0] = UINT32_MAX;
#endif
    /* After shared heap chain, will early stop if shared heap is NULL */
    extra->shared_heap = NULL;

#if WASM_ENABLE_PERF_PROFILING != 0
    total_size = sizeof(AOTFuncPerfProfInfo)
                 * ((uint64)module->import_func_count + module->func_count);
    if (!(module_inst->func_perf_profilings =
              runtime_malloc(total_size, error_buf, error_buf_size))) {
        goto fail;
    }
#endif

#if WASM_ENABLE_GC != 0
    for (i = 0; i < module_inst->table_count; i++) {
        uint32 j;
        AOTTable *table;
        AOTTableInstance *table_inst;
        table_elem_type_t *table_data;

        /* bypass imported table since AOTImportTable doesn't have init_expr */
        if (i < module->import_table_count)
            continue;

        table = &module->tables[i - module->import_table_count];
        bh_assert(table);

        if (table->init_expr.init_expr_type == INIT_EXPR_NONE) {
            continue;
        }

        table_inst = module_inst->tables[i];
        bh_assert(table_inst);

        table_data = table_inst->elems;
        bh_assert(table_data);

        for (j = 0; j < table_inst->cur_size; j++) {
            if (!assign_table_init_value(module_inst, module, &table->init_expr,
                                         table_data + j, error_buf,
                                         error_buf_size)) {
                goto fail;
            }
        }
    }

    /* Initialize the table data with table init data */
    for (i = 0;
         module_inst->table_count > 0 && i < module->table_init_data_count;
         i++) {

        AOTTableInitData *table_init_data = module->table_init_data_list[i];
        AOTTableInstance *table;
        table_elem_type_t *table_data;
        uint8 tbl_elem_type;
        uint32 tbl_init_size, tbl_max_size, j;
        WASMRefType *tbl_elem_ref_type;
        WASMValue offset_value;

        bh_assert(table_init_data);

        bh_assert(table_init_data->table_index < module_inst->table_count);
        table = module_inst->tables[table_init_data->table_index];
        bh_assert(table);

        table_data = table->elems;
        bh_assert(table_data);

        wasm_runtime_get_table_inst_elem_type(
            (WASMModuleInstanceCommon *)module_inst,
            table_init_data->table_index, &tbl_elem_type, &tbl_elem_ref_type,
            &tbl_init_size, &tbl_max_size);

        if (!wasm_elem_is_declarative(table_init_data->mode)
            && !wasm_reftype_is_subtype_of(
                table_init_data->elem_type, table_init_data->elem_ref_type,
                table->elem_type, table->elem_ref_type.elem_ref_type,
                module->types, module->type_count)) {
            set_error_buf(error_buf, error_buf_size,
                          "type mismatch: elements segment does not fit");
            goto fail;
        }

        (void)tbl_init_size;
        (void)tbl_max_size;

        if (!wasm_elem_is_active(table_init_data->mode)) {
            continue;
        }
        uint8 offset_flag = table_init_data->offset.init_expr_type;
        bh_assert(offset_flag == INIT_EXPR_TYPE_GET_GLOBAL
                  || offset_flag == INIT_EXPR_TYPE_FUNCREF_CONST
                  || offset_flag == INIT_EXPR_TYPE_REFNULL_CONST
                  || offset_flag == INIT_EXPR_TYPE_I32_CONST
                  || offset_flag == INIT_EXPR_TYPE_I32_ADD
                  || offset_flag == INIT_EXPR_TYPE_I32_SUB
                  || offset_flag == INIT_EXPR_TYPE_I32_MUL);

        /* init vec(funcidx) or vec(expr) */
        if (offset_flag == INIT_EXPR_TYPE_GET_GLOBAL) {
            uint32 data_offset;
            if (!check_global_init_expr(
                    module, table_init_data->offset.u.unary.v.global_index,
                    error_buf, error_buf_size)) {
                goto fail;
            }

            if (table_init_data->offset.u.unary.v.global_index
                < module->import_global_count) {
                data_offset = module
                                  ->import_globals[table_init_data->offset.u
                                                       .unary.v.global_index]
                                  .data_offset;
            }
            else {
                data_offset =
                    module
                        ->globals[table_init_data->offset.u.unary.v.global_index
                                  - module->import_global_count]
                        .data_offset;
            }
            offset_value.i32 =
                *(uint32 *)(module_inst->global_data + data_offset);
        }
        else {
            if (!get_init_value_recursive(
                    module_inst, module, &table_init_data->offset,
                    &offset_value, error_buf, error_buf_size)) {
                goto fail;
            }
        }

        /* check offset since length might negative */
        if ((uint32)offset_value.i32 > table->cur_size) {
            LOG_DEBUG("base_offset(%d) > table->cur_size(%d)", offset_value.i32,
                      table->cur_size);
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds table access");
            goto fail;
        }

        if ((uint32)offset_value.i32 + table_init_data->value_count
            > table->cur_size) {
            LOG_DEBUG("base_offset(%d) + length(%d) > table->cur_size(%d)",
                      offset_value.i32, table_init_data->value_count,
                      table->cur_size);
            set_error_buf(error_buf, error_buf_size,
                          "out of bounds table access");
            goto fail;
        }

        for (j = 0; j < module->table_init_data_list[i]->value_count; j++) {
            if (!assign_table_init_value(module_inst, module,
                                         &table_init_data->init_values[j],
                                         table_data + offset_value.i32 + j,
                                         error_buf, error_buf_size)) {
                goto fail;
            }
        }
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

#if WASM_ENABLE_DUMP_CALL_STACK != 0
static void
destroy_c_api_frames(Vector *frames)
{
    WASMCApiFrame frame = { 0 };
    uint32 i, total_frames, ret;

    total_frames = (uint32)bh_vector_size(frames);

    for (i = 0; i < total_frames; i++) {
        ret = bh_vector_get(frames, i, &frame);
        bh_assert(ret);

        if (frame.lp)
            wasm_runtime_free(frame.lp);
    }

    ret = bh_vector_destroy(frames);
    bh_assert(ret);
    (void)ret;
}
#endif

void
aot_deinstantiate(AOTModuleInstance *module_inst, bool is_sub_inst)
{
    AOTModuleInstanceExtra *extra = (AOTModuleInstanceExtra *)module_inst->e;
    WASMModuleInstanceExtraCommon *common = &extra->common;
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
        destroy_c_api_frames(module_inst->frames);
        wasm_runtime_free(module_inst->frames);
        module_inst->frames = NULL;
    }
#endif

#if WASM_ENABLE_MULTI_MODULE != 0
    wasm_runtime_sub_module_deinstantiate(
        (WASMModuleInstanceCommon *)module_inst);
    if (extra->import_func_module_insts)
        wasm_runtime_free(extra->import_func_module_insts);
#endif

    if (module_inst->tables)
        wasm_runtime_free(module_inst->tables);

    if (module_inst->memories)
        memories_deinstantiate(module_inst);

    if (module_inst->export_functions)
        wasm_runtime_free(module_inst->export_functions);

    if (extra->export_func_maps)
        wasm_runtime_free(extra->export_func_maps);

#if WASM_ENABLE_MULTI_MEMORY != 0
    if (module_inst->export_memories)
        wasm_runtime_free(module_inst->export_memories);
#endif

    if (extra->functions) {
        uint32 func_idx;
        for (func_idx = 0; func_idx < extra->function_count; ++func_idx) {
            if (extra->functions[func_idx]) {
                wasm_runtime_free(extra->functions[func_idx]);
            }
        }
        wasm_runtime_free(extra->functions);
    }

    if (module_inst->func_ptrs)
        wasm_runtime_free(module_inst->func_ptrs);

    if (module_inst->func_type_indexes)
        wasm_runtime_free(module_inst->func_type_indexes);

    if (module_inst->c_api_func_imports)
        wasm_runtime_free(module_inst->c_api_func_imports);

#if WASM_ENABLE_GC != 0
    if (!is_sub_inst) {
        if (common->gc_heap_handle)
            mem_allocator_destroy(common->gc_heap_handle);
        if (common->gc_heap_pool)
            wasm_runtime_free(common->gc_heap_pool);
    }
#endif

    if (!is_sub_inst) {
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
aot_lookup_function(const AOTModuleInstance *module_inst, const char *name)
{
    AOTFunctionInstance *export_funcs =
        (AOTFunctionInstance *)module_inst->export_functions;
    AOTFunctionInstance key = { .func_name = (char *)name };

    if (!export_funcs)
        return NULL;

    return bsearch(&key, export_funcs, module_inst->export_func_count,
                   sizeof(AOTFunctionInstance), cmp_func_inst);
}

#ifdef OS_ENABLE_HW_BOUND_CHECK
static bool
invoke_native_with_hw_bound_check(WASMExecEnv *exec_env, void *func_ptr,
                                  const WASMFuncType *func_type,
                                  const char *signature, void *attachment,
                                  uint32 *argv, uint32 argc, uint32 *argv_ret)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    WASMExecEnv *exec_env_tls = wasm_runtime_get_exec_env_tls();
    WASMJmpBuf jmpbuf_node = { 0 }, *jmpbuf_node_pop;
#ifdef BH_PLATFORM_WINDOWS
    int result;
    bool has_exception;
    char exception[EXCEPTION_BUF_LEN];
#endif
    bool ret;

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

    /* Check native stack overflow firstly to ensure we have enough
       native stack to run the following codes before actually calling
       the aot function in invokeNative function. */
    if (!wasm_runtime_detect_native_stack_overflow(exec_env)) {
        return false;
    }

    wasm_exec_env_push_jmpbuf(exec_env, &jmpbuf_node);

    if (os_setjmp(jmpbuf_node.jmpbuf) == 0) {
#if WASM_ENABLE_QUICK_AOT_ENTRY != 0
        /* Quick call if the quick aot entry is registered */
        if (!signature && func_type->quick_aot_entry) {
            void (*invoke_native)(void *func_ptr, void *exec_env, uint32 *argv,
                                  uint32 *argv_ret) =
                func_type->quick_aot_entry;
            exec_env->attachment = attachment;
            invoke_native(func_ptr, exec_env, argv, argv_ret);
            exec_env->attachment = NULL;
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
                       const WASMFuncType *func_type, const char *signature,
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

#ifdef AOT_STACK_FRAME_DEBUG
typedef void (*stack_frame_callback_t)(struct WASMExecEnv *exec_env);
static stack_frame_callback_t aot_stack_frame_callback;

/* set the callback, only for debug purpose */
void
aot_set_stack_frame_callback(stack_frame_callback_t callback)
{
    aot_stack_frame_callback = callback;
}
#endif

bool
aot_call_function(WASMExecEnv *exec_env, AOTFunctionInstance *function,
                  unsigned argc, uint32 argv[])
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTModule *module = (AOTModule *)module_inst->module;
    AOTFuncType *func_type = function->is_import_func
                                 ? function->u.func_import->func_type
                                 : function->u.func.func_type;
    uint32 result_count = func_type->result_count;
    uint32 ext_ret_count = result_count > 1 ? result_count - 1 : 0;
    bool ret;
    void *func_ptr = function->is_import_func
                         ? function->u.func_import->func_ptr_linked
                         : function->u.func.func_ptr;
    void *attachment = NULL;
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

    if (function->func_index < module->import_func_count) {
        attachment = function->u.func_import->attachment;
    }

    /* Set exec env, so it can be later retrieved from instance */
    module_inst->cur_exec_env = exec_env;

    if (ext_ret_count > 0) {
        uint32 cell_num = 0, i;
        uint8 *ext_ret_types = func_type->types + func_type->param_count + 1;
        uint32 argv1_buf[32], *argv1 = argv1_buf, *ext_rets = NULL;
        uint32 *argv_ret = argv;
        uint32 ext_ret_cell = wasm_get_cell_num(ext_ret_types, ext_ret_count);
        uint64 size;
#if WASM_ENABLE_AOT_STACK_FRAME != 0
        void *prev_frame = get_top_frame(exec_env);
#endif

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

#if WASM_ENABLE_AOT_STACK_FRAME != 0
        if (!is_frame_per_function(exec_env)
            && !aot_alloc_frame(exec_env, function->func_index)) {
            if (argv1 != argv1_buf)
                wasm_runtime_free(argv1);
            return false;
        }
#endif

        ret = invoke_native_internal(exec_env, function->u.func.func_ptr,
                                     func_type, NULL, attachment, argv1, argc,
                                     argv);

        if (!ret) {
#ifdef AOT_STACK_FRAME_DEBUG
            if (aot_stack_frame_callback) {
                aot_stack_frame_callback(exec_env);
            }
#endif
#if WASM_ENABLE_DUMP_CALL_STACK != 0
            if (aot_create_call_stack(exec_env)) {
                aot_dump_call_stack(exec_env, true, NULL, 0);
            }
#endif
        }

#if WASM_ENABLE_AOT_STACK_FRAME != 0
        /* Free all frames allocated, note that some frames
           may be allocated in AOT code and haven't been
           freed if exception occurred */
        while (get_top_frame(exec_env) != prev_frame)
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
#if WASM_ENABLE_AOT_STACK_FRAME != 0
        void *prev_frame = get_top_frame(exec_env);
        /* Only allocate frame for frame-per-call mode; in the
           frame-per-function mode the frame is allocated at the
           beginning of the function. */
        if (!is_frame_per_function(exec_env)
            && !aot_alloc_frame(exec_env, function->func_index)) {
            return false;
        }
#endif

        ret = invoke_native_internal(exec_env, func_ptr, func_type, NULL,
                                     attachment, argv, argc, argv);

        if (!ret) {
#ifdef AOT_STACK_FRAME_DEBUG
            if (aot_stack_frame_callback) {
                aot_stack_frame_callback(exec_env);
            }
#endif
#if WASM_ENABLE_DUMP_CALL_STACK != 0
            if (aot_create_call_stack(exec_env)) {
                aot_dump_call_stack(exec_env, true, NULL, 0);
            }
#endif
        }

#if WASM_ENABLE_AOT_STACK_FRAME != 0
        /* Free all frames allocated, note that some frames
           may be allocated in AOT code and haven't been
           freed if exception occurred */
        while (get_top_frame(exec_env) != prev_frame)
            aot_free_frame(exec_env);
#endif

        return ret;
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
                        AOTFunctionInstance *retain_func, uint64 size,
                        uint64 *p_result)
{
#ifdef OS_ENABLE_HW_BOUND_CHECK
    WASMExecEnv *exec_env_tls = wasm_runtime_get_exec_env_tls();
#endif
    WASMExecEnv *exec_env_created = NULL;
    WASMModuleInstanceCommon *module_inst_old = NULL;
    union {
        uint32 u32[3];
        uint64 u64;
    } argv;
    uint32 argc;
    bool ret;

#if WASM_ENABLE_MEMORY64 != 0
    bool is_memory64 = module_inst->memories[0]->is_memory64;
    if (is_memory64) {
        argc = 2;
        PUT_I64_TO_ADDR(&argv.u64, size);
    }
    else
#endif
    {
        argc = 1;
        argv.u32[0] = (uint32)size;
    }

    /* if __retain is exported, then this module is compiled by
        assemblyscript, the memory should be managed by as's runtime,
        in this case we need to call the retain function after malloc
        the memory */
    if (retain_func) {
        /* the malloc function from assemblyscript is:
            function __new(size: usize, id: u32)
            id = 0 means this is an ArrayBuffer object */
        argv.u32[argc] = 0;
        argc++;
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

    ret = aot_call_function(exec_env, malloc_func, argc, argv.u32);

    if (retain_func && ret)
        ret = aot_call_function(exec_env, retain_func, 1, argv.u32);

    if (module_inst_old)
        /* Restore the existing exec_env's module inst */
        wasm_exec_env_restore_module_inst(exec_env, module_inst_old);

    if (exec_env_created)
        wasm_exec_env_destroy(exec_env_created);

    if (ret) {
#if WASM_ENABLE_MEMORY64 != 0
        if (is_memory64)
            *p_result = argv.u64;
        else
#endif
        {
            *p_result = argv.u32[0];
        }
    }
    return ret;
}

static bool
execute_free_function(AOTModuleInstance *module_inst, WASMExecEnv *exec_env,
                      AOTFunctionInstance *free_func, uint64 offset)
{
#ifdef OS_ENABLE_HW_BOUND_CHECK
    WASMExecEnv *exec_env_tls = wasm_runtime_get_exec_env_tls();
#endif
    WASMExecEnv *exec_env_created = NULL;
    WASMModuleInstanceCommon *module_inst_old = NULL;
    union {
        uint32 u32[2];
        uint64 u64;
    } argv;
    uint32 argc;
    bool ret;

#if WASM_ENABLE_MEMORY64 != 0
    if (module_inst->memories[0]->is_memory64) {
        PUT_I64_TO_ADDR(&argv.u64, offset);
        argc = 2;
    }
    else
#endif
    {
        argv.u32[0] = (uint32)offset;
        argc = 1;
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

    ret = aot_call_function(exec_env, free_func, argc, argv.u32);

    if (module_inst_old)
        /* Restore the existing exec_env's module inst */
        wasm_exec_env_restore_module_inst(exec_env, module_inst_old);

    if (exec_env_created)
        wasm_exec_env_destroy(exec_env_created);

    return ret;
}

uint64
aot_module_malloc_internal(AOTModuleInstance *module_inst,
                           WASMExecEnv *exec_env, uint64 size,
                           void **p_native_addr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    AOTModule *module = (AOTModule *)module_inst->module;
    uint8 *addr = NULL;
    uint64 offset = 0;

    /* TODO: Memory64 size check based on memory idx type */
    bh_assert(size <= UINT32_MAX);

    if (!memory_inst) {
        aot_set_exception(module_inst, "uninitialized memory");
        return 0;
    }

    if (memory_inst->heap_handle) {
        addr = mem_allocator_malloc(memory_inst->heap_handle, (uint32)size);
    }
    else if (module->malloc_func_index != (uint32)-1
             && module->free_func_index != (uint32)-1) {
        AOTFunctionInstance *malloc_func, *retain_func = NULL;
        char *malloc_func_name;

        if (module->retain_func_index != (uint32)-1) {
            malloc_func_name = "__new";
            retain_func = aot_lookup_function(module_inst, "__retain");
            if (!retain_func)
                retain_func = aot_lookup_function(module_inst, "__pin");
            bh_assert(retain_func);
        }
        else {
            malloc_func_name = "malloc";
        }
        malloc_func = aot_lookup_function(module_inst, malloc_func_name);

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
            LOG_WARNING("warning: allocate %" PRIu64 " bytes memory failed",
                        size);
        }
        return 0;
    }
    if (p_native_addr)
        *p_native_addr = addr;
    return (uint64)(addr - memory_inst->memory_data);
}

uint64
aot_module_realloc_internal(AOTModuleInstance *module_inst,
                            WASMExecEnv *exec_env, uint64 ptr, uint64 size,
                            void **p_native_addr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    uint8 *addr = NULL;

    /* TODO: Memory64 ptr and size check based on memory idx type */
    bh_assert(ptr <= UINT32_MAX);
    bh_assert(size <= UINT32_MAX);

    if (!memory_inst) {
        aot_set_exception(module_inst, "uninitialized memory");
        return 0;
    }

    if (memory_inst->heap_handle) {
        addr = mem_allocator_realloc(
            memory_inst->heap_handle,
            (uint32)ptr ? memory_inst->memory_data + (uint32)ptr : NULL,
            (uint32)size);
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
    return (uint64)(addr - memory_inst->memory_data);
}

void
aot_module_free_internal(AOTModuleInstance *module_inst, WASMExecEnv *exec_env,
                         uint64 ptr)
{
    AOTMemoryInstance *memory_inst = aot_get_default_memory(module_inst);
    AOTModule *module = (AOTModule *)module_inst->module;

    if (!memory_inst) {
        return;
    }

    /* TODO: Memory64 ptr and size check based on memory idx type */
    bh_assert(ptr <= UINT32_MAX);

    if (ptr) {
        uint8 *addr = memory_inst->memory_data + (uint32)ptr;
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
            free_func = aot_lookup_function(module_inst, free_func_name);
            if (!free_func && module->retain_func_index != (uint32)-1)
                free_func = aot_lookup_function(module_inst, "__unpin");

            if (free_func)
                execute_free_function(module_inst, exec_env, free_func, ptr);
        }
    }
}

uint64
aot_module_malloc(AOTModuleInstance *module_inst, uint64 size,
                  void **p_native_addr)
{
    return aot_module_malloc_internal(module_inst, NULL, size, p_native_addr);
}

uint64
aot_module_realloc(AOTModuleInstance *module_inst, uint64 ptr, uint64 size,
                   void **p_native_addr)
{
    return aot_module_realloc_internal(module_inst, NULL, ptr, size,
                                       p_native_addr);
}

void
aot_module_free(AOTModuleInstance *module_inst, uint64 ptr)
{
    aot_module_free_internal(module_inst, NULL, ptr);
}

uint64
aot_module_dup_data(AOTModuleInstance *module_inst, const char *src,
                    uint64 size)
{
    char *buffer;
    uint64 buffer_offset;

    /* TODO: Memory64 size check based on memory idx type */
    bh_assert(size <= UINT32_MAX);

    buffer_offset = aot_module_malloc(module_inst, size, (void **)&buffer);

    if (buffer_offset != 0) {
        buffer = wasm_runtime_addr_app_to_native(
            (WASMModuleInstanceCommon *)module_inst, buffer_offset);
        bh_memcpy_s(buffer, (uint32)size, src, (uint32)size);
    }
    return buffer_offset;
}

bool
aot_enlarge_memory(AOTModuleInstance *module_inst, uint32 inc_page_count)
{
    return wasm_enlarge_memory(module_inst, inc_page_count);
}

bool
aot_enlarge_memory_with_idx(AOTModuleInstance *module_inst,
                            uint32 inc_page_count, uint32 memidx)
{
    return wasm_enlarge_memory_with_idx(module_inst, inc_page_count, memidx);
}

bool
aot_invoke_native(WASMExecEnv *exec_env, uint32 func_idx, uint32 argc,
                  uint32 *argv)
{
    AOTModuleInstance *module_inst =
        (AOTModuleInstance *)wasm_runtime_get_module_inst(exec_env);
    AOTModule *aot_module = (AOTModule *)module_inst->module;
    CApiFuncImport *c_api_func_import =
        module_inst->c_api_func_imports
            ? module_inst->c_api_func_imports + func_idx
            : NULL;
    uint32 *func_type_indexes = module_inst->func_type_indexes;
    uint32 func_type_idx = func_type_indexes[func_idx];
    AOTFuncType *func_type = (AOTFuncType *)aot_module->types[func_type_idx];
    void **func_ptrs = module_inst->func_ptrs;
    void *func_ptr = func_ptrs[func_idx];
    AOTImportFunc *import_func;
    const char *signature;
    void *attachment;
    char buf[96];
    bool ret = false;
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
        WASMModuleInstanceCommon *sub_inst = NULL;
        if ((sub_inst = ((AOTModuleInstanceExtra *)module_inst->e)
                            ->import_func_module_insts[func_idx])) {
            exec_env = wasm_runtime_get_exec_env_singleton(sub_inst);
        }
        if (exec_env == NULL) {
            wasm_runtime_set_exception((WASMModuleInstanceCommon *)module_inst,
                                       "create singleton exec_env failed");
            goto fail;
        }
#if WASM_ENABLE_AOT_STACK_FRAME != 0
        void *prev_frame = get_top_frame(exec_env);

        if (!aot_alloc_frame(exec_env, func_idx)) {
            goto fail;
        }
#endif
#endif /* WASM_ENABLE_MULTI_MODULE != 0 */
        ret =
            wasm_runtime_invoke_native(exec_env, func_ptr, func_type, signature,
                                       attachment, argv, argc, argv);
#if WASM_ENABLE_MULTI_MODULE != 0 && WASM_ENABLE_AOT_STACK_FRAME != 0
        /* Free all frames allocated, note that some frames
           may be allocated in AOT code and haven't been
           freed if exception occurred */
        while (get_top_frame(exec_env) != prev_frame)
            aot_free_frame(exec_env);
#endif
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
    table_elem_type_t tbl_elem_val = NULL_REF;
    AOTImportFunc *import_func;
    const char *signature = NULL;
    void *attachment = NULL;
    char buf[96];
    bool ret;

    /* this function is called from native code, so exec_env->handle and
       exec_env->native_stack_boundary must have been set, we don't set
       it again */

    if (!wasm_runtime_detect_native_stack_overflow(exec_env)) {
        goto fail;
    }

    tbl_inst = module_inst->tables[tbl_idx];
    bh_assert(tbl_inst);

    if (table_elem_idx >= tbl_inst->cur_size) {
        aot_set_exception_with_id(module_inst, EXCE_UNDEFINED_ELEMENT);
        goto fail;
    }

    tbl_elem_val = ((table_elem_type_t *)tbl_inst->elems)[table_elem_idx];
    if (tbl_elem_val == NULL_REF) {
        aot_set_exception_with_id(module_inst, EXCE_UNINITIALIZED_ELEMENT);
        goto fail;
    }

#if WASM_ENABLE_GC == 0
    func_idx = (uint32)tbl_elem_val;
#else
    func_idx =
        wasm_func_obj_get_func_idx_bound((WASMFuncObjectRef)tbl_elem_val);
#endif

    func_type_idx = func_type_indexes[func_idx];
    func_type = (AOTFuncType *)aot_module->types[func_type_idx];

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
        attachment = import_func->attachment;
        if (import_func->call_conv_raw) {
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

#if WASM_ENABLE_AOT_STACK_FRAME != 0
        void *prev_frame = get_top_frame(exec_env);
        if (!is_frame_per_function(exec_env)
            && !aot_alloc_frame(exec_env, func_idx)) {
            if (argv1 != argv1_buf)
                wasm_runtime_free(argv1);
            return false;
        }
#endif
        ret = invoke_native_internal(exec_env, func_ptr, func_type, signature,
                                     attachment, argv1, argc, argv);
#if WASM_ENABLE_AOT_STACK_FRAME != 0
        /* Free all frames allocated, note that some frames
           may be allocated in AOT code and haven't been
           freed if exception occurred */
        while (get_top_frame(exec_env) != prev_frame)
            aot_free_frame(exec_env);
#endif

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
#if WASM_ENABLE_AOT_STACK_FRAME != 0
        void *prev_frame = get_top_frame(exec_env);
        /* Only allocate frame for frame-per-call mode; in the
           frame-per-function mode the frame is allocated at the
           beginning of the function. */
        if (!is_frame_per_function(exec_env)
            && !aot_alloc_frame(exec_env, func_idx)) {
            return false;
        }
#endif
        ret = invoke_native_internal(exec_env, func_ptr, func_type, signature,
                                     attachment, argv, argc, argv);
#if WASM_ENABLE_AOT_STACK_FRAME != 0
        /* Free all frames allocated, note that some frames
           may be allocated in AOT code and haven't been
           freed if exception occurred */
        while (get_top_frame(exec_env) != prev_frame)
            aot_free_frame(exec_env);
#endif
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
                               uint64 app_buf_addr, uint64 app_buf_size,
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
                uint32 len, size_t dst)
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
                                        (uint64)dst, (uint64)len))
        return false;

    if ((uint64)offset + (uint64)len > seg_len) {
        aot_set_exception(module_inst, "out of bounds memory access");
        return false;
    }

    maddr = wasm_runtime_addr_app_to_native(
        (WASMModuleInstanceCommon *)module_inst, (uint64)dst);

    SHARED_MEMORY_LOCK(memory_inst);
    bh_memcpy_s(maddr, CLAMP_U64_TO_U32(memory_inst->memory_data_size - dst),
                data + offset, len);
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
aot_set_aux_stack(WASMExecEnv *exec_env, uint64 start_offset, uint32 size)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTModule *module = (AOTModule *)module_inst->module;

    uint32 stack_top_idx = module->aux_stack_top_global_index;
    uint64 data_end = module->aux_data_end;
    uint64 stack_bottom = module->aux_stack_bottom;
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
        /* TODO: Memory64 the type i32/i64 depends on memory idx type*/
        *(int32 *)global_addr = (uint32)start_offset;

        /* The aux stack boundary is a constant value,
            set the value to exec_env */
        exec_env->aux_stack_boundary = (uintptr_t)start_offset - size;
        exec_env->aux_stack_bottom = (uintptr_t)start_offset;
        return true;
    }

    return false;
}

bool
aot_get_aux_stack(WASMExecEnv *exec_env, uint64 *start_offset, uint32 *size)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTModule *module = (AOTModule *)module_inst->module;

    /* The aux stack information is resolved in loader
        and store in module */
    uint64 stack_bottom = module->aux_stack_bottom;
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

    mem_conspn->types_size = sizeof(AOTFuncType *) * module->type_count;
    for (i = 0; i < module->type_count; i++) {
        AOTFuncType *type = (AOTFuncType *)module->types[i];
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
        size = offsetof(AOTTableInitData, init_values)
               + sizeof(InitializerExpression) * init_data->value_count;
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
            (uint64)mem_inst->num_bytes_per_page * mem_inst->cur_page_count;
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

#if WASM_ENABLE_REF_TYPES != 0 || WASM_ENABLE_GC != 0
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
    const AOTModule *module = (AOTModule *)module_inst->module;
    table_elem_type_t *table_elems;
    InitializerExpression *tbl_seg_init_values = NULL, *init_values;
    uint32 i, tbl_seg_len = 0;
#if WASM_ENABLE_GC != 0
    void *func_obj;
#endif

    tbl_inst = module_inst->tables[tbl_idx];
    bh_assert(tbl_inst);

    tbl_seg = module->table_init_data_list[tbl_seg_idx];
    bh_assert(tbl_seg);

    if (!bh_bitmap_get_bit(
            ((AOTModuleInstanceExtra *)module_inst->e)->common.elem_dropped,
            tbl_seg_idx)) {
        /* table segment isn't dropped */
        tbl_seg_init_values = tbl_seg->init_values;
        tbl_seg_len = tbl_seg->value_count;
    }

    if (offset_len_out_of_bounds(src_offset, length, tbl_seg_len)
        || offset_len_out_of_bounds(dst_offset, length, tbl_inst->cur_size)) {
        aot_set_exception_with_id(module_inst, EXCE_OUT_OF_BOUNDS_TABLE_ACCESS);
        return;
    }

    if (!length) {
        return;
    }

    table_elems = tbl_inst->elems + dst_offset;
    init_values = tbl_seg_init_values + src_offset;

    for (i = 0; i < length; i++) {
#if WASM_ENABLE_GC != 0
        /* UINT32_MAX indicates that it is a null ref */
        if (init_values[i].u.unary.v.ref_index != UINT32_MAX) {
            if (!(func_obj = aot_create_func_obj(
                      module_inst, init_values[i].u.unary.v.ref_index, true,
                      NULL, 0))) {
                aot_set_exception_with_id(module_inst, EXCE_NULL_FUNC_OBJ);
                return;
            }
            table_elems[i] = func_obj;
        }
        else {
            table_elems[i] = NULL_REF;
        }
#else
        table_elems[i] = init_values[i].u.unary.v.ref_index;
#endif
    }
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
                     + dst_offset * sizeof(table_elem_type_t),
                 (dst_tbl_inst->cur_size - dst_offset)
                     * sizeof(table_elem_type_t),
                 (uint8 *)src_tbl_inst + offsetof(AOTTableInstance, elems)
                     + src_offset * sizeof(table_elem_type_t),
                 length * sizeof(table_elem_type_t));
}

void
aot_table_fill(AOTModuleInstance *module_inst, uint32 tbl_idx, uint32 length,
               table_elem_type_t val, uint32 data_offset)
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
aot_table_grow(AOTModuleInstance *module_inst, uint32 tbl_idx, uint32 inc_size,
               table_elem_type_t init_val)
{
    AOTTableInstance *tbl_inst;
    uint32 i, orig_size, total_size;

    tbl_inst = module_inst->tables[tbl_idx];
    if (!tbl_inst) {
        return (uint32)-1;
    }

    orig_size = tbl_inst->cur_size;

    if (!inc_size) {
        return orig_size;
    }

    if (tbl_inst->cur_size > UINT32_MAX - inc_size) {
#if WASM_ENABLE_SPEC_TEST == 0
        LOG_WARNING("table grow (%" PRIu32 "-> %" PRIu32
                    ") failed because of integer overflow",
                    tbl_inst->cur_size, inc_size);
#endif
        return (uint32)-1;
    }

    total_size = tbl_inst->cur_size + inc_size;
    if (total_size > tbl_inst->max_size) {
#if WASM_ENABLE_SPEC_TEST == 0
        LOG_WARNING("table grow (%" PRIu32 "-> %" PRIu32
                    ") failed because of over max size",
                    tbl_inst->cur_size, inc_size);
#endif
        return (uint32)-1;
    }

    /* fill in */
    for (i = 0; i < inc_size; ++i) {
        tbl_inst->elems[tbl_inst->cur_size + i] = init_val;
    }

    tbl_inst->cur_size = total_size;
    return orig_size;
}
#endif /* WASM_ENABLE_REF_TYPES != 0 || WASM_ENABLE_GC != 0 */

#if WASM_ENABLE_AOT_STACK_FRAME != 0
#if WASM_ENABLE_DUMP_CALL_STACK != 0 || WASM_ENABLE_PERF_PROFILING != 0
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
#endif /* end of WASM_ENABLE_DUMP_CALL_STACK != 0 || \
          WASM_ENABLE_PERF_PROFILING != 0 */

#if WASM_ENABLE_GC == 0
static bool
aot_alloc_standard_frame(WASMExecEnv *exec_env, uint32 func_index)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
#if WASM_ENABLE_PERF_PROFILING != 0
    AOTFuncPerfProfInfo *func_perf_prof =
        module_inst->func_perf_profilings + func_index;
#endif
    AOTFrame *cur_frame, *frame;
    uint32 size = (uint32)offsetof(AOTFrame, lp);

    cur_frame = (AOTFrame *)exec_env->cur_frame;
    if (!cur_frame)
        frame = (AOTFrame *)exec_env->wasm_stack.bottom;
    else
        frame = (AOTFrame *)((uint8 *)cur_frame + size);

    if ((uint8 *)frame + size > exec_env->wasm_stack.top_boundary) {
        aot_set_exception(module_inst, "wasm operand stack overflow");
        return false;
    }

    frame->func_index = func_index;
    /* No need to initialize ip, it will be committed in jitted code
       when needed */
    /* frame->ip = NULL; */
    frame->prev_frame = (AOTFrame *)exec_env->cur_frame;

#if WASM_ENABLE_PERF_PROFILING != 0
    frame->time_started = (uintptr_t)os_time_thread_cputime_us();
    frame->func_perf_prof_info = func_perf_prof;
#endif
#if WASM_ENABLE_MEMORY_PROFILING != 0
    {
        uint32 wasm_stack_used =
            (uint8 *)frame + size - exec_env->wasm_stack.bottom;
        if (wasm_stack_used > exec_env->max_wasm_stack_used)
            exec_env->max_wasm_stack_used = wasm_stack_used;
    }
#endif

    exec_env->cur_frame = (struct WASMInterpFrame *)frame;

    return true;
}

#else /* else of WASM_ENABLE_GC == 0 */

static bool
aot_alloc_standard_frame(WASMExecEnv *exec_env, uint32 func_index)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTModule *module = (AOTModule *)module_inst->module;
#if WASM_ENABLE_PERF_PROFILING != 0
    AOTFuncPerfProfInfo *func_perf_prof =
        module_inst->func_perf_profilings + func_index;
#endif
    AOTFrame *frame;
    uint32 max_local_cell_num, max_stack_cell_num, all_cell_num;
    uint32 aot_func_idx, frame_size;

    if (func_index >= module->import_func_count) {
        aot_func_idx = func_index - module->import_func_count;
        max_local_cell_num = module->max_local_cell_nums[aot_func_idx];
        max_stack_cell_num = module->max_stack_cell_nums[aot_func_idx];
    }
    else {
        AOTFuncType *func_type = module->import_funcs[func_index].func_type;
        max_local_cell_num =
            func_type->param_cell_num > 2 ? func_type->param_cell_num : 2;
        max_stack_cell_num = 0;
    }

    all_cell_num = max_local_cell_num + max_stack_cell_num;
#if WASM_ENABLE_GC == 0
    frame_size = (uint32)offsetof(AOTFrame, lp) + all_cell_num * 4;
#else
    frame_size =
        (uint32)offsetof(AOTFrame, lp) + align_uint(all_cell_num * 5, 4);
#endif
    frame = wasm_exec_env_alloc_wasm_frame(exec_env, frame_size);

    if (!frame) {
        aot_set_exception(module_inst, "wasm operand stack overflow");
        return false;
    }

#if WASM_ENABLE_PERF_PROFILING != 0
    frame->time_started = (uintptr_t)os_time_thread_cputime_us();
    frame->func_perf_prof_info = func_perf_prof;
#endif

#if WASM_ENABLE_GC != 0
    frame->sp = frame->lp + max_local_cell_num;
    frame->frame_ref = (uint8 *)(frame->sp + max_stack_cell_num);
#endif

    frame->prev_frame = (AOTFrame *)exec_env->cur_frame;
    exec_env->cur_frame = (struct WASMInterpFrame *)frame;

    frame->func_index = func_index;
    return true;
}
#endif /* end of WASM_ENABLE_GC == 0 */

static bool
aot_alloc_tiny_frame(WASMExecEnv *exec_env, uint32 func_index)
{
    AOTTinyFrame *new_frame = (AOTTinyFrame *)exec_env->wasm_stack.top;

    if ((uint8 *)new_frame > exec_env->wasm_stack.top_boundary) {
        aot_set_exception((WASMModuleInstance *)exec_env->module_inst,
                          "wasm operand stack overflow");
        return false;
    }

    new_frame->func_index = func_index;
    exec_env->wasm_stack.top += sizeof(AOTTinyFrame);
    return true;
}

bool
aot_alloc_frame(WASMExecEnv *exec_env, uint32 func_index)
{
    AOTModule *module =
        (AOTModule *)((AOTModuleInstance *)exec_env->module_inst)->module;

    if (is_frame_per_function(exec_env)
        && func_index >= module->import_func_count) {
        /* in frame per function mode the frame is allocated at
        the beginning of each frame, so we only need to allocate
        the frame for imported functions */
        return true;
    }
    if (is_tiny_frame(exec_env)) {
        return aot_alloc_tiny_frame(exec_env, func_index);
    }
    else {
        return aot_alloc_standard_frame(exec_env, func_index);
    }
}

static inline void
aot_free_standard_frame(WASMExecEnv *exec_env)
{
    AOTFrame *cur_frame = (AOTFrame *)exec_env->cur_frame;
    AOTFrame *prev_frame = (AOTFrame *)cur_frame->prev_frame;

#if WASM_ENABLE_PERF_PROFILING != 0
    uint64 time_elapsed =
        (uintptr_t)os_time_thread_cputime_us() - cur_frame->time_started;

    cur_frame->func_perf_prof_info->total_exec_time += time_elapsed;
    cur_frame->func_perf_prof_info->total_exec_cnt++;

    /* parent function */
    if (prev_frame)
        prev_frame->func_perf_prof_info->children_exec_time += time_elapsed;
#endif

#if WASM_ENABLE_GC != 0
    wasm_exec_env_free_wasm_frame(exec_env, cur_frame);
#endif
    exec_env->cur_frame = (struct WASMInterpFrame *)prev_frame;
}

static inline void
aot_free_tiny_frame(WASMExecEnv *exec_env)
{
    exec_env->wasm_stack.top =
        get_prev_frame(exec_env, exec_env->wasm_stack.top);
}

void
aot_free_frame(WASMExecEnv *exec_env)
{
    if (is_tiny_frame(exec_env)) {
        aot_free_tiny_frame(exec_env);
    }
    else {
        aot_free_standard_frame(exec_env);
    }
}

void
aot_frame_update_profile_info(WASMExecEnv *exec_env, bool alloc_frame)
{
#if WASM_ENABLE_PERF_PROFILING != 0
    AOTFrame *cur_frame = (AOTFrame *)exec_env->cur_frame;
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTFuncPerfProfInfo *func_perf_prof =
        module_inst->func_perf_profilings + cur_frame->func_index;

    if (alloc_frame) {
        cur_frame->time_started = (uintptr_t)os_time_thread_cputime_us();
        cur_frame->func_perf_prof_info = func_perf_prof;
    }
    else {
        AOTFrame *prev_frame = cur_frame->prev_frame;
        uint64 time_elapsed =
            (uintptr_t)os_time_thread_cputime_us() - cur_frame->time_started;

        cur_frame->func_perf_prof_info->total_exec_time += time_elapsed;
        cur_frame->func_perf_prof_info->total_exec_cnt++;

        /* parent function */
        if (prev_frame)
            prev_frame->func_perf_prof_info->children_exec_time += time_elapsed;
    }
#endif

#if WASM_ENABLE_MEMORY_PROFILING != 0
    if (alloc_frame) {
#if WASM_ENABLE_GC == 0
        uint32 wasm_stack_used = (uint8 *)exec_env->cur_frame
                                 + (uint32)offsetof(AOTFrame, lp)
                                 - exec_env->wasm_stack.bottom;
#else
        uint32 wasm_stack_used =
            exec_env->wasm_stack.top - exec_env->wasm_stack.bottom;
#endif
        if (wasm_stack_used > exec_env->max_wasm_stack_used)
            exec_env->max_wasm_stack_used = wasm_stack_used;
    }
#endif
}
#endif /* end of WASM_ENABLE_AOT_STACK_FRAME != 0 */

#if WASM_ENABLE_COPY_CALL_STACK != 0
uint32
aot_copy_callstack_tiny_frame(WASMExecEnv *exec_env, WASMCApiFrame *buffer,
                              const uint32 length, const uint32 skip_n,
                              char *error_buf, uint32 error_buf_size)
{
    /*
     * Note for devs: please refrain from such modifications inside of
     * aot_copy_callstack_tiny_frame
     * - any allocations/freeing memory
     * - dereferencing any pointers other than: exec_env, exec_env->module_inst,
     * exec_env->module_inst->module, pointers between stack's bottom and
     * top_boundary For more details check wasm_copy_callstack in
     * wasm_export.h
     */
    uint8 *top_boundary = exec_env->wasm_stack.top_boundary;
    uint8 *top = exec_env->wasm_stack.top;
    uint8 *bottom = exec_env->wasm_stack.bottom;
    uint32 count = 0;

    bool is_top_index_in_range =
        top_boundary >= top && top >= (bottom + sizeof(AOTTinyFrame));
    if (!is_top_index_in_range) {
        char *err_msg =
            "Top of the stack pointer is outside of the stack boundaries";
        strncpy(error_buf, err_msg, error_buf_size);
        return 0;
    }
    bool is_top_aligned_with_bottom =
        (unsigned long)(top - bottom) % sizeof(AOTTinyFrame) == 0;
    if (!is_top_aligned_with_bottom) {
        char *err_msg = "Top of the stack is not aligned with the bottom";
        strncpy(error_buf, err_msg, error_buf_size);
        return 0;
    }

    AOTTinyFrame *frame = (AOTTinyFrame *)(top - sizeof(AOTTinyFrame));
    WASMCApiFrame record_frame;
    while (frame && (uint8_t *)frame >= bottom && count < (skip_n + length)) {
        if (count < skip_n) {
            ++count;
            frame -= 1;
            continue;
        }
        record_frame.instance = exec_env->module_inst;
        record_frame.module_offset = 0;
        record_frame.func_index = frame->func_index;
        record_frame.func_offset = frame->ip_offset;
        buffer[count - skip_n] = record_frame;
        frame -= 1;
        ++count;
    }
    return count >= skip_n ? count - skip_n : 0;
}

uint32
aot_copy_callstack_standard_frame(WASMExecEnv *exec_env, WASMCApiFrame *buffer,
                                  const uint32 length, const uint32 skip_n,
                                  char *error_buf, uint32_t error_buf_size)
{
    /*
     * Note for devs: please refrain from such modifications inside of
     * aot_iterate_callstack_standard_frame
     * - any allocations/freeing memory
     * - dereferencing any pointers other than: exec_env, exec_env->module_inst,
     * exec_env->module_inst->module, pointers between stack's bottom and
     * top_boundary For more details check wasm_iterate_callstack in
     * wasm_export.h
     */

    uint32 count = 0;
#if WASM_ENABLE_GC == 0
    WASMModuleInstance *module_inst =
        (WASMModuleInstance *)wasm_exec_env_get_module_inst(exec_env);
    AOTFrame *cur_frame = (AOTFrame *)wasm_exec_env_get_cur_frame(exec_env);
    uint8 *top_boundary = exec_env->wasm_stack.top_boundary;
    uint8 *bottom = exec_env->wasm_stack.bottom;
    uint32 frame_size = (uint32)offsetof(AOTFrame, lp);

    WASMCApiFrame record_frame;
    while (cur_frame && (uint8_t *)cur_frame >= bottom
           && (uint8_t *)cur_frame + frame_size <= top_boundary
           && count < (skip_n + length)) {
        if (count < skip_n) {
            ++count;
            cur_frame = cur_frame->prev_frame;
            continue;
        }
        record_frame.instance = module_inst;
        record_frame.module_offset = 0;
        record_frame.func_index = (uint32)cur_frame->func_index;
        record_frame.func_offset = (uint32)cur_frame->ip_offset;
        buffer[count - skip_n] = record_frame;
        cur_frame = cur_frame->prev_frame;
        ++count;
    }
#else
/*
 * TODO: add support for standard frames when GC is enabled
 * now it poses a risk due to variable size of the frame
 */
#endif
    return count >= skip_n ? count - skip_n : 0;
}

uint32
aot_copy_callstack(WASMExecEnv *exec_env, WASMCApiFrame *buffer,
                   const uint32 length, const uint32 skip_n, char *error_buf,
                   uint32_t error_buf_size)
{
    /*
     * Note for devs: please refrain from such modifications inside of
     * aot_iterate_callstack
     * - any allocations/freeing memory
     * - dereferencing any pointers other than: exec_env, exec_env->module_inst,
     * exec_env->module_inst->module, pointers between stack's bottom and
     * top_boundary For more details check wasm_iterate_callstack in
     * wasm_export.h
     */
    if (!is_tiny_frame(exec_env)) {
        return aot_copy_callstack_standard_frame(
            exec_env, buffer, length, skip_n, error_buf, error_buf_size);
    }
    else {
        return aot_copy_callstack_tiny_frame(exec_env, buffer, length, skip_n,
                                             error_buf, error_buf_size);
    }
}
#endif // WASM_ENABLE_COPY_CALL_STACK

#if WASM_ENABLE_DUMP_CALL_STACK != 0
bool
aot_create_call_stack(struct WASMExecEnv *exec_env)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTModule *module = (AOTModule *)module_inst->module;
    uint32 n = 0;

    void *top_frame = get_top_frame(exec_env);
    while (top_frame) {
        top_frame = get_prev_frame(exec_env, top_frame);
        n++;
    }

    /* release previous stack frames and create new ones */
    destroy_c_api_frames(module_inst->frames);
    if (!bh_vector_init(module_inst->frames, n, sizeof(WASMCApiFrame), false)) {
        return false;
    }

    top_frame = get_top_frame(exec_env);
    while (n-- > 0) {
        uint32 func_index, ip_offset;
        uint32 *lp = NULL;
#if WASM_ENABLE_GC != 0
        uint32 *sp = NULL;
        uint8 *frame_ref = NULL;
#endif
        if (is_tiny_frame(exec_env)) {
            AOTTinyFrame *frame = (AOTTinyFrame *)top_frame;
            func_index = (uint32)frame->func_index;
            ip_offset = (uint32)frame->ip_offset;
        }
        else {
            AOTFrame *frame = (AOTFrame *)top_frame;
            func_index = (uint32)frame->func_index;
            ip_offset = (uint32)frame->ip_offset;
            lp = frame->lp;
#if WASM_ENABLE_GC != 0
            sp = frame->sp;
            frame_ref = frame->frame_ref;
#endif
        }
        WASMCApiFrame frame = { 0 };
        uint32 max_local_cell_num = 0, max_stack_cell_num = 0;
        uint32 all_cell_num, lp_size;

        frame.instance = module_inst;
        frame.module_offset = 0;
        frame.func_index = func_index;
        frame.func_offset = ip_offset;
        frame.func_name_wp = get_func_name_from_index(module_inst, func_index);

        if (!is_frame_func_idx_disabled(exec_env)) {
            if (func_index >= module->import_func_count) {
                uint32 aot_func_idx = func_index - module->import_func_count;
                max_local_cell_num = module->max_local_cell_nums[aot_func_idx];
                max_stack_cell_num = module->max_stack_cell_nums[aot_func_idx];
            }
            else {
                AOTFuncType *func_type =
                    module->import_funcs[func_index].func_type;
                max_local_cell_num = func_type->param_cell_num > 2
                                         ? func_type->param_cell_num
                                         : 2;
                max_stack_cell_num = 0;
            }
        }

        all_cell_num = max_local_cell_num + max_stack_cell_num;
#if WASM_ENABLE_GC == 0
        lp_size = all_cell_num * 4;
#else
        lp_size = align_uint(all_cell_num * 5, 4);
#endif
        if (lp_size > 0 && !is_tiny_frame(exec_env)) {
            if (!(frame.lp = wasm_runtime_malloc(lp_size))) {
                destroy_c_api_frames(module_inst->frames);
                return false;
            }
            bh_memcpy_s(frame.lp, lp_size, lp, lp_size);

#if WASM_ENABLE_GC != 0
            uint32 local_ref_flags_cell_num =
                module->func_local_ref_flags[frame.func_index]
                    .local_ref_flag_cell_num;
            uint8 *local_ref_flags =
                module->func_local_ref_flags[frame.func_index].local_ref_flags;
            frame.sp = frame.lp + (sp - lp);
            frame.frame_ref = (uint8 *)frame.lp + (frame_ref - (uint8 *)lp);
            /* copy local ref flags from AOT module */
            bh_memcpy_s(frame.frame_ref, local_ref_flags_cell_num,
                        local_ref_flags, lp_size);
#endif
        }

        if (!bh_vector_append(module_inst->frames, &frame)) {
            if (frame.lp)
                wasm_runtime_free(frame.lp);
            destroy_c_api_frames(module_inst->frames);
            return false;
        }

        top_frame = get_prev_frame(exec_env, top_frame);
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
            line_length = snprintf(line_buf, sizeof(line_buf),
                                   "#%02" PRIu32 ": 0x%04x - $f%" PRIu32 "\n",
                                   n, frame.func_offset, frame.func_index);
        }
        else {
            line_length = snprintf(line_buf, sizeof(line_buf),
                                   "#%02" PRIu32 ": 0x%04x - %s\n", n,
                                   frame.func_offset, frame.func_name_wp);
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
#endif /* end of WASM_ENABLE_DUMP_CALL_STACK != 0 */

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
#endif /* end of WASM_ENABLE_PERF_PROFILING != 0 */

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
    /* Version 9 */
    prof_header.version = 0x0000000000000009LL;
    /* with VARIANT_MASK_IR_PROF (IR Instrumentation) */
    prof_header.version |= 0x1ULL << 56;
    /* with VARIANT_MASK_MEMPROF (Memory Profile) */
    prof_header.version |= 0x1ULL << 62;
    prof_header.num_prof_data = num_prof_data;
    prof_header.num_prof_counters = num_prof_counters;
    prof_header.names_size = prof_names_size;
    prof_header.value_kind_last = 1;
    /* __llvm_prf_bits won't be used in PGO, set dummy value here */
    prof_header.num_prof_bitmaps = 0;
    prof_header.bitmap_delta = 0;

    if (!is_little_endian()) {
        aot_exchange_uint64((uint8 *)&prof_header.magic);
        aot_exchange_uint64((uint8 *)&prof_header.version);
        aot_exchange_uint64((uint8 *)&prof_header.num_prof_data);
        aot_exchange_uint64((uint8 *)&prof_header.num_prof_counters);
        aot_exchange_uint64((uint8 *)&prof_header.num_prof_bitmaps);
        aot_exchange_uint64((uint8 *)&prof_header.names_size);
        aot_exchange_uint64((uint8 *)&prof_header.counters_delta);
        aot_exchange_uint64((uint8 *)&prof_header.bitmap_delta);
        aot_exchange_uint64((uint8 *)&prof_header.value_kind_last);
    }

    size = sizeof(LLVMProfileRawHeader);
    bh_memcpy_s(buf, size, &prof_header, size);
    buf += size;

    for (i = 0; i < module->data_section_count; i++) {
        if (!strncmp(module->data_sections[i].name, "__llvm_prf_data", 15)) {
            LLVMProfileData_64 *prof_data_64 = (LLVMProfileData_64 *)buf;

            /* Convert LLVMProfileData to LLVMProfileData_64, the pointer width
               in the output file is always 8 bytes */
            prof_data = (LLVMProfileData *)module->data_sections[i].data;
            prof_data_64->func_md5 = prof_data->func_md5;
            prof_data_64->func_hash = prof_data->func_hash;
            prof_data_64->offset_counters = prof_data->offset_counters;
            prof_data_64->offset_bitmaps = prof_data->offset_bitmaps;
            prof_data_64->func_ptr = prof_data->func_ptr;
            prof_data_64->values = (uint64)(uintptr_t)prof_data->values;
            prof_data_64->num_counters = prof_data->num_counters;
            /* __llvm_prf_bits won't be used in PGO, set dummy value here */
            prof_data_64->num_bitmaps = 0;
            prof_data_64->num_value_sites[0] = prof_data->num_value_sites[0];
            prof_data_64->num_value_sites[1] = prof_data->num_value_sites[1];

            if (!is_little_endian()) {
                aot_exchange_uint64((uint8 *)&prof_data_64->func_hash);
                aot_exchange_uint64((uint8 *)&prof_data_64->offset_counters);
                aot_exchange_uint64((uint8 *)&prof_data_64->offset_bitmaps);
                aot_exchange_uint64((uint8 *)&prof_data_64->func_ptr);
                aot_exchange_uint64((uint8 *)&prof_data_64->values);
                aot_exchange_uint32((uint8 *)&prof_data_64->num_counters);
                aot_exchange_uint32((uint8 *)&prof_data_64->num_bitmaps);
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

#if WASM_ENABLE_GC != 0
void *
aot_create_func_obj(AOTModuleInstance *module_inst, uint32 func_idx,
                    bool throw_exce, char *error_buf, uint32 error_buf_size)
{
    AOTModule *module = (AOTModule *)module_inst->module;
    WASMRttTypeRef rtt_type;
    WASMFuncObjectRef func_obj;
    AOTFuncType *func_type;
    uint32 type_idx;

    if (throw_exce) {
        error_buf = module_inst->cur_exception;
        error_buf_size = sizeof(module_inst->cur_exception);
    }

    if (func_idx >= module->import_func_count + module->func_count) {
        set_error_buf_v(error_buf, error_buf_size, "unknown function %d",
                        func_idx);
        return NULL;
    }

    type_idx = module_inst->func_type_indexes[func_idx];
    func_type = (AOTFuncType *)module->types[type_idx];

    if (!(rtt_type = wasm_rtt_type_new((AOTType *)func_type, type_idx,
                                       module->rtt_types, module->type_count,
                                       &module->rtt_type_lock))) {
        set_error_buf(error_buf, error_buf_size, "create rtt object failed");
        return NULL;
    }

    if (!(func_obj = wasm_func_obj_new_internal(
              ((AOTModuleInstanceExtra *)module_inst->e)->common.gc_heap_handle,
              rtt_type, func_idx))) {
        set_error_buf(error_buf, error_buf_size, "create func object failed");
        return NULL;
    }

    return func_obj;
}

bool
aot_obj_is_instance_of(AOTModuleInstance *module_inst, WASMObjectRef gc_obj,
                       uint32 type_index)
{
    AOTModule *aot_module = (AOTModule *)module_inst->module;
    AOTType **types = aot_module->types;
    uint32 type_count = aot_module->type_count;

    return wasm_obj_is_instance_of(gc_obj, type_index, types, type_count);
}

bool
aot_func_type_is_super_of(AOTModuleInstance *module_inst, uint32 type_idx1,
                          uint32 type_idx2)
{
    AOTModule *aot_module = (AOTModule *)module_inst->module;
    AOTType **types = aot_module->types;

    if (type_idx1 == type_idx2)
        return true;

    bh_assert(types[type_idx1]->type_flag == WASM_TYPE_FUNC);
    bh_assert(types[type_idx2]->type_flag == WASM_TYPE_FUNC);
    return wasm_func_type_is_super_of((WASMFuncType *)types[type_idx1],
                                      (WASMFuncType *)types[type_idx2]);
}

WASMRttTypeRef
aot_rtt_type_new(AOTModuleInstance *module_inst, uint32 type_index)
{
    AOTModule *aot_module = (AOTModule *)module_inst->module;
    AOTType *defined_type = aot_module->types[type_index];
    WASMRttType **rtt_types = aot_module->rtt_types;
    uint32 rtt_type_count = aot_module->type_count;
    korp_mutex *rtt_type_lock = &aot_module->rtt_type_lock;

    return wasm_rtt_type_new(defined_type, type_index, rtt_types,
                             rtt_type_count, rtt_type_lock);
}

bool
aot_array_init_with_data(AOTModuleInstance *module_inst, uint32 seg_index,
                         uint32 data_seg_offset, WASMArrayObjectRef array_obj,
                         uint32 elem_size, uint32 array_len)
{
    AOTModule *aot_module;
    uint8 *data = NULL;
    uint8 *array_elem_base;
    uint64 seg_len = 0;
    uint64 total_size = (int64)elem_size * array_len;

    aot_module = (AOTModule *)module_inst->module;
    seg_len = aot_module->mem_init_data_list[seg_index]->byte_count;
    data = aot_module->mem_init_data_list[seg_index]->bytes;

    if (data_seg_offset >= seg_len || total_size > seg_len - data_seg_offset) {
        aot_set_exception(module_inst, "out of bounds memory access");
        return false;
    }

    array_elem_base = (uint8 *)wasm_array_obj_first_elem_addr(array_obj);
    bh_memcpy_s(array_elem_base, (uint32)total_size, data + data_seg_offset,
                (uint32)total_size);

    return true;
}

static bool
aot_global_traverse_gc_rootset(AOTModuleInstance *module_inst, void *heap)
{
    AOTModule *module = (AOTModule *)module_inst->module;
    uint8 *global_data = module_inst->global_data;
    AOTImportGlobal *import_global = module->import_globals;
    AOTGlobal *global = module->globals;
    WASMObjectRef gc_obj;
    uint32 i;

    for (i = 0; i < module->import_global_count; i++, import_global++) {
        if (wasm_is_type_reftype(import_global->type.val_type)) {
            gc_obj = GET_REF_FROM_ADDR((uint32 *)global_data);
            if (wasm_obj_is_created_from_heap(gc_obj)) {
                if (0 != mem_allocator_add_root((mem_allocator_t)heap, gc_obj))
                    return false;
            }
        }
        global_data += import_global->size;
    }

    for (i = 0; i < module->global_count; i++, global++) {
        if (wasm_is_type_reftype(global->type.val_type)) {
            gc_obj = GET_REF_FROM_ADDR((uint32 *)global_data);
            if (wasm_obj_is_created_from_heap(gc_obj)) {
                if (0 != mem_allocator_add_root((mem_allocator_t)heap, gc_obj))
                    return false;
            }
        }
        global_data += global->size;
    }

    return true;
}

static bool
aot_table_traverse_gc_rootset(WASMModuleInstance *module_inst, void *heap)
{
    AOTTableInstance **tables = (AOTTableInstance **)module_inst->tables;
    AOTTableInstance *table;
    uint32 table_count = module_inst->table_count, i, j;
    WASMObjectRef gc_obj, *table_elems;

    for (i = 0; i < table_count; i++) {
        table = tables[i];
        table_elems = (WASMObjectRef *)table->elems;
        for (j = 0; j < table->cur_size; j++) {
            gc_obj = table_elems[j];
            if (wasm_obj_is_created_from_heap(gc_obj)) {
                if (0 != mem_allocator_add_root((mem_allocator_t)heap, gc_obj))
                    return false;
            }
        }
    }

    return true;
}

static bool
local_object_refs_traverse_gc_rootset(WASMExecEnv *exec_env, void *heap)
{
    WASMLocalObjectRef *r;
    WASMObjectRef gc_obj;

    for (r = exec_env->cur_local_object_ref; r; r = r->prev) {
        gc_obj = r->val;
        if (wasm_obj_is_created_from_heap(gc_obj)) {
            if (0 != mem_allocator_add_root((mem_allocator_t)heap, gc_obj))
                return false;
        }
    }
    return true;
}

static bool
aot_frame_traverse_gc_rootset(WASMExecEnv *exec_env, void *heap)
{
    AOTFrame *frame;
    AOTModule *module;
    LocalRefFlag frame_local_flags;
    WASMObjectRef gc_obj;
    uint32 i, local_ref_flag_cell_num;

    module = (AOTModule *)wasm_exec_env_get_module(exec_env);
    frame = (AOTFrame *)wasm_exec_env_get_cur_frame(exec_env);
    for (; frame; frame = frame->prev_frame) {
        /* local ref flags */
        frame_local_flags = module->func_local_ref_flags[frame->func_index];
        local_ref_flag_cell_num = frame_local_flags.local_ref_flag_cell_num;
        for (i = 0; i < local_ref_flag_cell_num; i++) {
            if (frame_local_flags.local_ref_flags[i]) {
                gc_obj = GET_REF_FROM_ADDR(frame->lp + i);
                if (wasm_obj_is_created_from_heap(gc_obj)) {
                    if (mem_allocator_add_root((mem_allocator_t)heap, gc_obj)) {
                        return false;
                    }
                }
#if UINTPTR_MAX == UINT64_MAX
                bh_assert(frame_local_flags.local_ref_flags[i + 1]);
                i++;
#endif
            }
        }

        /* stack ref flags */
        uint8 *frame_ref = frame->frame_ref;
        for (i = local_ref_flag_cell_num; i < (uint32)(frame->sp - frame->lp);
             i++) {
            if (frame_ref[i]) {
                gc_obj = GET_REF_FROM_ADDR(frame->lp + i);
                if (wasm_obj_is_created_from_heap(gc_obj)) {
                    if (mem_allocator_add_root((mem_allocator_t)heap, gc_obj)) {
                        return false;
                    }
                }
#if UINTPTR_MAX == UINT64_MAX
                bh_assert(frame_ref[i + 1]);
                i++;
#endif
            }
        }
    }
    return true;
}

bool
aot_traverse_gc_rootset(WASMExecEnv *exec_env, void *heap)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    bool ret;

    ret = aot_global_traverse_gc_rootset(module_inst, heap);
    if (!ret)
        return ret;

    ret = aot_table_traverse_gc_rootset(module_inst, heap);
    if (!ret)
        return ret;

    ret = local_object_refs_traverse_gc_rootset(exec_env, heap);
    if (!ret)
        return ret;

    ret = aot_frame_traverse_gc_rootset(exec_env, heap);
    if (!ret)
        return ret;

    return true;
}
#endif /* end of WASM_ENABLE_GC != 0 */

char *
aot_const_str_set_insert(const uint8 *str, int32 len, AOTModule *module,
#if (WASM_ENABLE_WORD_ALIGN_READ != 0)
                         bool is_vram_word_align,
#endif
                         char *error_buf, uint32 error_buf_size)
{
    HashMap *set = module->const_str_set;
    char *c_str, *value;

    /* Create const string set if it isn't created */
    if (!set
        && !(set = module->const_str_set = bh_hash_map_create(
                 32, false, (HashFunc)wasm_string_hash,
                 (KeyEqualFunc)wasm_string_equal, NULL, wasm_runtime_free))) {
        set_error_buf(error_buf, error_buf_size,
                      "create const string set failed");
        return NULL;
    }

    /* Lookup const string set, use the string if found */
    if (!(c_str = runtime_malloc((uint32)len, error_buf, error_buf_size))) {
        return NULL;
    }
#if (WASM_ENABLE_WORD_ALIGN_READ != 0)
    if (is_vram_word_align) {
        bh_memcpy_wa(c_str, (uint32)len, str, (uint32)len);
    }
    else
#endif
    {
        bh_memcpy_s(c_str, len, str, (uint32)len);
    }

    if ((value = bh_hash_map_find(set, c_str))) {
        wasm_runtime_free(c_str);
        return value;
    }

    if (!bh_hash_map_insert(set, c_str, c_str)) {
        set_error_buf(error_buf, error_buf_size,
                      "insert string to hash map failed");
        wasm_runtime_free(c_str);
        return NULL;
    }

    return c_str;
}

#if WASM_ENABLE_DYNAMIC_AOT_DEBUG != 0
AOTModule *g_dynamic_aot_module = NULL;

void __attribute__((noinline)) __enable_dynamic_aot_debug(void)
{
    /* empty implementation. */
}

void (*__enable_dynamic_aot_debug_ptr)(void)
    __attribute__((visibility("default"))) = __enable_dynamic_aot_debug;
#endif

bool
aot_set_module_name(AOTModule *module, const char *name, char *error_buf,
                    uint32_t error_buf_size)
{
    if (!name)
        return false;

    module->name = aot_const_str_set_insert((const uint8 *)name,
                                            (uint32)(strlen(name) + 1), module,
#if (WASM_ENABLE_WORD_ALIGN_READ != 0)
                                            false,
#endif
                                            error_buf, error_buf_size);
#if WASM_ENABLE_DYNAMIC_AOT_DEBUG != 0
    /* export g_dynamic_aot_module for dynamic aot debug */
    g_dynamic_aot_module = module;
    /* trigger breakpoint __enable_dynamic_aot_debug */
    (*__enable_dynamic_aot_debug_ptr)();
#endif
    return module->name != NULL;
}

const char *
aot_get_module_name(AOTModule *module)
{
    return module->name;
}

bool
aot_resolve_symbols(AOTModule *module)
{
    bool ret = true;
    uint32 idx;
    for (idx = 0; idx < module->import_func_count; ++idx) {
        AOTImportFunc *aot_import_func = &module->import_funcs[idx];
        if (!aot_import_func->func_ptr_linked) {
            if (!aot_resolve_import_func(module, aot_import_func)) {
                LOG_WARNING("Failed to link function (%s, %s)",
                            aot_import_func->module_name,
                            aot_import_func->func_name);
                ret = false;
            }
        }
    }
    return ret;
}

#if WASM_ENABLE_MULTI_MODULE != 0
static void *
aot_resolve_function(const AOTModule *module, const char *function_name,
                     const AOTFuncType *expected_function_type, char *error_buf,
                     uint32 error_buf_size);

static void *
aot_resolve_function_ex(const char *module_name, const char *function_name,
                        const AOTFuncType *expected_function_type,
                        char *error_buf, uint32 error_buf_size)
{
    WASMModuleCommon *module_reg;

    module_reg = wasm_runtime_find_module_registered(module_name);
    if (!module_reg || module_reg->module_type != Wasm_Module_AoT) {
        LOG_DEBUG("can not find a module named %s for function %s", module_name,
                  function_name);
        set_error_buf(error_buf, error_buf_size, "unknown import");
        return NULL;
    }
    return aot_resolve_function((AOTModule *)module_reg, function_name,
                                expected_function_type, error_buf,
                                error_buf_size);
}

static void *
aot_resolve_function(const AOTModule *module, const char *function_name,
                     const AOTFuncType *expected_function_type, char *error_buf,
                     uint32 error_buf_size)
{
    void *function = NULL;
    AOTExport *export = NULL;
    AOTFuncType *target_function_type = NULL;

    export = loader_find_export((WASMModuleCommon *)module, module->name,
                                function_name, EXPORT_KIND_FUNC, error_buf,
                                error_buf_size);
    if (!export) {
        return NULL;
    }

    /* resolve function type and function */
    if (export->index < module->import_func_count) {
        target_function_type = module->import_funcs[export->index].func_type;
        function = module->import_funcs[export->index].func_ptr_linked;
    }
    else {
        target_function_type =
            (AOTFuncType *)module
                ->types[module->func_type_indexes[export->index
                                                  - module->import_func_count]];
        function =
            (module->func_ptrs[export->index - module->import_func_count]);
    }
    /* check function type */
    if (!wasm_type_equal((WASMType *)expected_function_type,
                         (WASMType *)target_function_type, module->types,
                         module->type_count)) {
        LOG_DEBUG("%s.%s failed the type check", module->name, function_name);
        set_error_buf(error_buf, error_buf_size, "incompatible import type");
        return NULL;
    }
    return function;
}
#endif /* end of WASM_ENABLE_MULTI_MODULE */

bool
aot_resolve_import_func(AOTModule *module, AOTImportFunc *import_func)
{
#if WASM_ENABLE_MULTI_MODULE != 0
    char error_buf[128];
    AOTModule *sub_module = NULL;
#endif
    import_func->func_ptr_linked = wasm_native_resolve_symbol(
        import_func->module_name, import_func->func_name,
        import_func->func_type, &import_func->signature,
        &import_func->attachment, &import_func->call_conv_raw);
#if WASM_ENABLE_MULTI_MODULE != 0
    if (!import_func->func_ptr_linked) {
        if (!wasm_runtime_is_built_in_module(import_func->module_name)) {
            sub_module = (AOTModule *)wasm_runtime_load_depended_module(
                (WASMModuleCommon *)module, import_func->module_name, error_buf,
                sizeof(error_buf));
            if (!sub_module) {
                LOG_WARNING("Failed to load sub module: %s", error_buf);
            }
            if (!sub_module)
                import_func->func_ptr_linked = aot_resolve_function_ex(
                    import_func->module_name, import_func->func_name,
                    import_func->func_type, error_buf, sizeof(error_buf));
            else
                import_func->func_ptr_linked = aot_resolve_function(
                    sub_module, import_func->func_name, import_func->func_type,
                    error_buf, sizeof(error_buf));
            if (!import_func->func_ptr_linked) {
                LOG_WARNING("Failed to link function: %s", error_buf);
            }
        }
    }
#endif
    return import_func->func_ptr_linked != NULL;
}
