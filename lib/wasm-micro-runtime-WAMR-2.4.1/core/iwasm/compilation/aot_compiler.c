/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_compiler.h"
#include "aot_emit_compare.h"
#include "aot_emit_conversion.h"
#include "aot_emit_memory.h"
#include "aot_emit_variable.h"
#include "aot_emit_const.h"
#include "aot_emit_exception.h"
#include "aot_emit_numberic.h"
#include "aot_emit_control.h"
#include "aot_emit_function.h"
#include "aot_emit_parametric.h"
#include "aot_emit_table.h"
#include "aot_emit_gc.h"
#include "aot_stack_frame_comp.h"
#include "simd/simd_access_lanes.h"
#include "simd/simd_bitmask_extracts.h"
#include "simd/simd_bit_shifts.h"
#include "simd/simd_bitwise_ops.h"
#include "simd/simd_bool_reductions.h"
#include "simd/simd_comparisons.h"
#include "simd/simd_conversions.h"
#include "simd/simd_construct_values.h"
#include "simd/simd_conversions.h"
#include "simd/simd_floating_point.h"
#include "simd/simd_int_arith.h"
#include "simd/simd_load_store.h"
#include "simd/simd_sat_int_arith.h"
#include "../aot/aot_runtime.h"
#include "../interpreter/wasm_opcode.h"
#include <errno.h>

#if WASM_ENABLE_DEBUG_AOT != 0
#include "debug/dwarf_extractor.h"
#endif

#if WASM_ENABLE_STRINGREF != 0
#include "string_object.h"
#include "aot_emit_stringref.h"
#endif

#define CHECK_BUF(buf, buf_end, length)                             \
    do {                                                            \
        if (buf + length > buf_end) {                               \
            aot_set_last_error("read leb failed: unexpected end."); \
            return false;                                           \
        }                                                           \
    } while (0)

static bool
read_leb(const uint8 *buf, const uint8 *buf_end, uint32 *p_offset,
         uint32 maxbits, bool sign, uint64 *p_result)
{
    uint64 result = 0;
    uint32 shift = 0;
    uint32 bcnt = 0;
    uint64 byte;

    while (true) {
        CHECK_BUF(buf, buf_end, 1);
        byte = buf[*p_offset];
        *p_offset += 1;
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            break;
        }
        bcnt += 1;
    }
    if (bcnt > (maxbits + 6) / 7) {
        aot_set_last_error("read leb failed: "
                           "integer representation too long");
        return false;
    }
    if (sign && (shift < maxbits) && (byte & 0x40)) {
        /* Sign extend */
        result |= (~((uint64)0)) << shift;
    }
    *p_result = result;
    return true;
}

/* NOLINTNEXTLINE */
#define read_leb_generic(p, p_end, res, res_type, sign)                     \
    do {                                                                    \
        uint32 off = 0;                                                     \
        uint64 res64;                                                       \
        if (!read_leb(p, p_end, &off, sizeof(res_type) << 3, sign, &res64)) \
            return false;                                                   \
        p += off;                                                           \
        res = (res_type)res64;                                              \
    } while (0)

/* NOLINTNEXTLINE */
#define read_leb_int32(p, p_end, res) \
    read_leb_generic(p, p_end, res, int32, true)

/* NOLINTNEXTLINE */
#define read_leb_int64(p, p_end, res) \
    read_leb_generic(p, p_end, res, int64, true)

/* NOLINTNEXTLINE */
#define read_leb_uint32(p, p_end, res) \
    read_leb_generic(p, p_end, res, uint32, false)

/* NOLINTNEXTLINE */
#define read_leb_uint64(p, p_end, res) \
    read_leb_generic(p, p_end, res, uint64, false)

/* NOLINTNEXTLINE */
#if WASM_ENABLE_MEMORY64 != 0
#define read_leb_mem_offset(p, p_end, res)  \
    do {                                    \
        if (IS_MEMORY64) {                  \
            read_leb_uint64(p, p_end, res); \
        }                                   \
        else {                              \
            read_leb_uint32(p, p_end, res); \
        }                                   \
    } while (0)
#else
#define read_leb_mem_offset read_leb_uint32
#endif

/**
 * Since wamrc uses a full feature Wasm loader,
 * add a post-validator here to run checks according
 * to options, like enable_tail_call, enable_ref_types,
 * and so on.
 */
static bool
aot_validate_wasm(AOTCompContext *comp_ctx)
{
    if (!comp_ctx->enable_ref_types && !comp_ctx->enable_gc) {
        /* Doesn't support multiple tables unless enabling reference type */
        if (comp_ctx->comp_data->import_table_count
                + comp_ctx->comp_data->table_count
            > 1) {
            aot_set_last_error("multiple tables");
            return false;
        }
    }

#if WASM_ENABLE_MEMORY64 != 0
    if (comp_ctx->pointer_size < sizeof(uint64)) {
        if (IS_MEMORY64) {
            aot_set_last_error("Compiling wasm64(contains i64 memory section) "
                               "to 32bit platform is not allowed");
            return false;
        }

        for (uint32 i = 0; i < comp_ctx->comp_data->table_count; ++i) {
            if (IS_TABLE64(i)) {
                aot_set_last_error("Compiling wasm64(contains i64 table "
                                   "section) to 32bit platform is not allowed");
                return false;
            }
        }
    }
#endif

    return true;
}

#define COMPILE_ATOMIC_RMW(OP, NAME)                      \
    case WASM_OP_ATOMIC_RMW_I32_##NAME:                   \
        bytes = 4;                                        \
        op_type = VALUE_TYPE_I32;                         \
        goto OP_ATOMIC_##OP;                              \
    case WASM_OP_ATOMIC_RMW_I64_##NAME:                   \
        bytes = 8;                                        \
        op_type = VALUE_TYPE_I64;                         \
        goto OP_ATOMIC_##OP;                              \
    case WASM_OP_ATOMIC_RMW_I32_##NAME##8_U:              \
        bytes = 1;                                        \
        op_type = VALUE_TYPE_I32;                         \
        goto OP_ATOMIC_##OP;                              \
    case WASM_OP_ATOMIC_RMW_I32_##NAME##16_U:             \
        bytes = 2;                                        \
        op_type = VALUE_TYPE_I32;                         \
        goto OP_ATOMIC_##OP;                              \
    case WASM_OP_ATOMIC_RMW_I64_##NAME##8_U:              \
        bytes = 1;                                        \
        op_type = VALUE_TYPE_I64;                         \
        goto OP_ATOMIC_##OP;                              \
    case WASM_OP_ATOMIC_RMW_I64_##NAME##16_U:             \
        bytes = 2;                                        \
        op_type = VALUE_TYPE_I64;                         \
        goto OP_ATOMIC_##OP;                              \
    case WASM_OP_ATOMIC_RMW_I64_##NAME##32_U:             \
        bytes = 4;                                        \
        op_type = VALUE_TYPE_I64;                         \
        OP_ATOMIC_##OP : bin_op = LLVMAtomicRMWBinOp##OP; \
        goto build_atomic_rmw;

uint32
offset_of_local_in_outs_area(AOTCompContext *comp_ctx, unsigned n)
{
    AOTCompFrame *frame = comp_ctx->aot_frame;
    return frame->cur_frame_size + offset_of_local(comp_ctx, n);
}

static bool
store_value(AOTCompContext *comp_ctx, LLVMValueRef value, uint8 value_type,
            LLVMValueRef cur_frame, uint32 offset)
{
    LLVMValueRef value_offset, value_addr, value_ptr = NULL, res;
    LLVMTypeRef value_ptr_type = NULL;

    if (!(value_offset = I32_CONST(offset))) {
        aot_set_last_error("llvm build const failed");
        return false;
    }

    if (!(value_addr =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, cur_frame,
                                    &value_offset, 1, "value_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }

    switch (value_type) {
        case VALUE_TYPE_I32:
            value_ptr_type = INT32_PTR_TYPE;
            break;
        case VALUE_TYPE_I64:
            value_ptr_type = INT64_PTR_TYPE;
            break;
        case VALUE_TYPE_F32:
            value_ptr_type = F32_PTR_TYPE;
            break;
        case VALUE_TYPE_F64:
            value_ptr_type = F64_PTR_TYPE;
            break;
        case VALUE_TYPE_V128:
            value_ptr_type = V128_PTR_TYPE;
            break;
#if WASM_ENABLE_GC != 0
        case VALUE_TYPE_GC_REF:
            value_ptr_type = GC_REF_PTR_TYPE;
            break;
#endif
        default:
            bh_assert(0);
            break;
    }

    if (!(value_ptr = LLVMBuildBitCast(comp_ctx->builder, value_addr,
                                       value_ptr_type, "value_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }

    if (!(res = LLVMBuildStore(comp_ctx->builder, value, value_ptr))) {
        aot_set_last_error("llvm build store failed");
        return false;
    }

    LLVMSetAlignment(res, 4);

    return true;
}

void
aot_call_stack_features_init_default(AOTCallStackFeatures *features)
{
    memset(features, 1, sizeof(AOTCallStackFeatures));
    features->frame_per_function = false;
}

bool
aot_frame_store_value(AOTCompContext *comp_ctx, LLVMValueRef value,
                      uint8 value_type, LLVMValueRef cur_frame, uint32 offset)
{
    return store_value(comp_ctx, value, value_type, cur_frame, offset);
}

static bool
store_ref(AOTCompContext *comp_ctx, uint32 ref, LLVMValueRef cur_frame,
          uint32 offset, uint32 nbytes)
{
    LLVMValueRef value_ref = NULL, value_offset, value_addr, res;

    if (!(value_offset = I32_CONST(offset))) {
        aot_set_last_error("llvm build const failed");
        return false;
    }

    if (!(value_addr =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, cur_frame,
                                    &value_offset, 1, "value_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }

    switch (nbytes) {
        case 1:
            if (!(value_ref = I8_CONST((uint8)ref))) {
                aot_set_last_error("llvm build const failed");
            }
            break;
        case 2:
            ref = (ref << 8) | ref;

            if (!(value_ref = LLVMConstInt(INT16_TYPE, (uint16)ref, false))) {
                aot_set_last_error("llvm build const failed");
                return false;
            }

            if (!(value_addr =
                      LLVMBuildBitCast(comp_ctx->builder, value_addr,
                                       INT16_PTR_TYPE, "value_addr"))) {
                aot_set_last_error("llvm build bit cast failed");
                return false;
            }
            break;
        case 4:
            ref = (ref << 24) | (ref << 16) | (ref << 8) | ref;

            if (!(value_ref = I32_CONST(ref))) {
                aot_set_last_error("llvm build const failed");
                return false;
            }

            if (!(value_addr =
                      LLVMBuildBitCast(comp_ctx->builder, value_addr,
                                       INT32_PTR_TYPE, "value_addr"))) {
                aot_set_last_error("llvm build bit cast failed");
                return false;
            }
            break;
        default:
            bh_assert(0);
            break;
    }

    if (!(res = LLVMBuildStore(comp_ctx->builder, value_ref, value_addr))) {
        aot_set_last_error("llvm build store failed");
        return false;
    }
    LLVMSetAlignment(res, 1);

    return true;
}

bool
aot_gen_commit_values(AOTCompFrame *frame)
{
    AOTCompContext *comp_ctx = frame->comp_ctx;
    AOTFuncContext *func_ctx = frame->func_ctx;
    AOTValueSlot *p, *end;
    LLVMValueRef value;
    uint32 n;

    if (!frame->comp_ctx->call_stack_features.values) {
        return true;
    }

    /* First, commit reference flags
     * For LLVM JIT, iterate all local and stack ref flags
     * For AOT, ignore local(params + locals) ref flags */
    for (p = comp_ctx->is_jit_mode ? frame->lp
                                   : frame->lp + frame->max_local_cell_num;
         p < frame->sp; p++) {
        if (!p->dirty)
            continue;

        n = (uint32)(p - frame->lp);

        /* Commit reference flag */
        if (comp_ctx->enable_gc) {
            switch (p->type) {
                case VALUE_TYPE_I32:
                case VALUE_TYPE_F32:
                case VALUE_TYPE_I1:
                    if (p->ref != p->committed_ref - 1) {
                        if (!store_ref(comp_ctx, p->ref, func_ctx->cur_frame,
                                       offset_of_ref(comp_ctx, n), 1))
                            return false;
                        p->committed_ref = p->ref + 1;
                    }
                    break;

                case VALUE_TYPE_I64:
                case VALUE_TYPE_F64:
                    bh_assert(p->ref == (p + 1)->ref);
                    if (p->ref != p->committed_ref - 1
                        || p->ref != (p + 1)->committed_ref - 1) {
                        if (!store_ref(comp_ctx, p->ref, func_ctx->cur_frame,
                                       offset_of_ref(comp_ctx, n), 2))
                            return false;
                        p->committed_ref = (p + 1)->committed_ref = p->ref + 1;
                    }
                    p++;
                    break;

                case VALUE_TYPE_V128:
                    bh_assert(p->ref == (p + 1)->ref && p->ref == (p + 2)->ref
                              && p->ref == (p + 3)->ref);
                    if (p->ref != p->committed_ref - 1
                        || p->ref != (p + 1)->committed_ref - 1
                        || p->ref != (p + 2)->committed_ref - 1
                        || p->ref != (p + 3)->committed_ref - 1) {
                        if (!store_ref(comp_ctx, p->ref, func_ctx->cur_frame,
                                       offset_of_ref(comp_ctx, n), 4))
                            return false;
                        p->committed_ref = (p + 1)->committed_ref =
                            (p + 2)->committed_ref = (p + 3)->committed_ref =
                                p->ref + 1;
                    }
                    p += 3;
                    break;

                case REF_TYPE_NULLFUNCREF:
                case REF_TYPE_NULLEXTERNREF:
                case REF_TYPE_NULLREF:
                case REF_TYPE_FUNCREF:
                case REF_TYPE_EXTERNREF:
                case REF_TYPE_ANYREF:
                case REF_TYPE_EQREF:
                case REF_TYPE_HT_NULLABLE:
                case REF_TYPE_HT_NON_NULLABLE:
                case REF_TYPE_I31REF:
                case REF_TYPE_STRUCTREF:
                case REF_TYPE_ARRAYREF:
#if WASM_ENABLE_STRINGREF != 0
                case REF_TYPE_STRINGREF:
                case REF_TYPE_STRINGVIEWWTF8:
                case REF_TYPE_STRINGVIEWWTF16:
                case REF_TYPE_STRINGVIEWITER:
#endif
                case VALUE_TYPE_GC_REF:
                    if (comp_ctx->pointer_size == sizeof(uint64)) {
                        bh_assert(p->ref == (p + 1)->ref);
                        if (p->ref != p->committed_ref - 1
                            || p->ref != (p + 1)->committed_ref - 1) {
                            if (!store_ref(comp_ctx, p->ref,
                                           func_ctx->cur_frame,
                                           offset_of_ref(comp_ctx, n), 2))
                                return false;
                            p->committed_ref = (p + 1)->committed_ref =
                                p->ref + 1;
                        }
                        p++;
                    }
                    else {
                        if (p->ref != p->committed_ref - 1) {
                            if (!store_ref(comp_ctx, p->ref,
                                           func_ctx->cur_frame,
                                           offset_of_ref(comp_ctx, n), 1))
                                return false;
                            p->committed_ref = p->ref + 1;
                        }
                    }
                    break;

                default:
                    bh_assert(0);
                    break;
            }
        }
    }

    /* Second, commit all values */
    for (p = frame->lp; p < frame->sp; p++) {
        if (!p->dirty)
            continue;

        p->dirty = 0;
        n = (uint32)(p - frame->lp);

        /* Commit values */
        switch (p->type) {
            case VALUE_TYPE_I32:
                if (!store_value(comp_ctx, p->value, VALUE_TYPE_I32,
                                 func_ctx->cur_frame,
                                 offset_of_local(comp_ctx, n)))
                    return false;
                break;
            case VALUE_TYPE_I64:
                (++p)->dirty = 0;
                if (!store_value(comp_ctx, p->value, VALUE_TYPE_I64,
                                 func_ctx->cur_frame,
                                 offset_of_local(comp_ctx, n)))
                    return false;
                break;
            case VALUE_TYPE_F32:
                if (!store_value(comp_ctx, p->value, VALUE_TYPE_F32,
                                 func_ctx->cur_frame,
                                 offset_of_local(comp_ctx, n)))
                    return false;
                break;
            case VALUE_TYPE_F64:
                (++p)->dirty = 0;
                if (!store_value(comp_ctx, p->value, VALUE_TYPE_F64,
                                 func_ctx->cur_frame,
                                 offset_of_local(comp_ctx, n)))
                    return false;
                break;
            case VALUE_TYPE_V128:
                (++p)->dirty = 0;
                (++p)->dirty = 0;
                (++p)->dirty = 0;
                if (!store_value(comp_ctx, p->value, VALUE_TYPE_V128,
                                 func_ctx->cur_frame,
                                 offset_of_local(comp_ctx, n)))
                    return false;
                break;
            case VALUE_TYPE_I1:
                if (!(value = LLVMBuildZExt(comp_ctx->builder, p->value,
                                            I32_TYPE, "i32_val"))) {
                    aot_set_last_error("llvm build bit cast failed");
                    return false;
                }
                if (!store_value(comp_ctx, value, VALUE_TYPE_I32,
                                 func_ctx->cur_frame,
                                 offset_of_local(comp_ctx, n)))
                    return false;
                break;
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
                if (comp_ctx->enable_ref_types) {
                    if (!store_value(comp_ctx, p->value, VALUE_TYPE_I32,
                                     func_ctx->cur_frame,
                                     offset_of_local(comp_ctx, n)))
                        return false;
                }
#if WASM_ENABLE_GC != 0
                else if (comp_ctx->enable_gc) {
                    if (comp_ctx->pointer_size == sizeof(uint64))
                        (++p)->dirty = 0;
                    if (!store_value(comp_ctx, p->value, VALUE_TYPE_GC_REF,
                                     func_ctx->cur_frame,
                                     offset_of_local(comp_ctx, n)))
                        return false;
                }
#endif
                else {
                    bh_assert(0);
                }
                break;
#if WASM_ENABLE_GC != 0
            case REF_TYPE_NULLFUNCREF:
            case REF_TYPE_NULLEXTERNREF:
            case REF_TYPE_NULLREF:
            /* case REF_TYPE_FUNCREF: */
            /* case REF_TYPE_EXTERNREF: */
            case REF_TYPE_ANYREF:
            case REF_TYPE_EQREF:
            case REF_TYPE_HT_NULLABLE:
            case REF_TYPE_HT_NON_NULLABLE:
            case REF_TYPE_I31REF:
            case REF_TYPE_STRUCTREF:
            case REF_TYPE_ARRAYREF:
            case VALUE_TYPE_GC_REF:
                if (comp_ctx->pointer_size == sizeof(uint64))
                    (++p)->dirty = 0;
                if (!store_value(comp_ctx, p->value, VALUE_TYPE_GC_REF,
                                 func_ctx->cur_frame,
                                 offset_of_local(comp_ctx, n)))
                    return false;
                break;
#endif
            default:
                bh_assert(0);
                break;
        }
    }

    if (comp_ctx->enable_gc) {
        end = frame->lp + frame->max_local_cell_num + frame->max_stack_cell_num;

        /* Clear reference flags for unused stack slots.  */
        for (p = frame->sp; p < end; p++) {
            bh_assert(!p->ref);
            n = (uint32)(p - frame->lp);

            /* Commit reference flag.  */
            if (p->ref != p->committed_ref - 1) {
                if (!store_ref(comp_ctx, p->ref, func_ctx->cur_frame,
                               offset_of_ref(comp_ctx, n), 1))
                    return false;
                p->committed_ref = 1 + p->ref;
            }
        }
    }

    return true;
}

static bool
aot_standard_frame_gen_commit_ip(AOTCompContext *comp_ctx,
                                 AOTFuncContext *func_ctx,
                                 LLVMValueRef ip_value, bool is_64bit)
{
    LLVMValueRef cur_frame = func_ctx->cur_frame;
    LLVMValueRef value_offset, value_addr, value_ptr;
    uint32 offset_ip;

    if (!comp_ctx->is_jit_mode)
        offset_ip = comp_ctx->pointer_size * 4;
    else
        offset_ip = offsetof(WASMInterpFrame, ip);

    if (!(value_offset = I32_CONST(offset_ip))) {
        aot_set_last_error("llvm build const failed");
        return false;
    }

    if (!(value_addr =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, cur_frame,
                                    &value_offset, 1, "ip_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }

    if (!(value_ptr = LLVMBuildBitCast(
              comp_ctx->builder, value_addr,
              is_64bit ? INT64_PTR_TYPE : INT32_PTR_TYPE, "ip_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }

    if (!LLVMBuildStore(comp_ctx->builder, ip_value, value_ptr)) {
        aot_set_last_error("llvm build store failed");
        return false;
    }

    return true;
}

bool
aot_gen_commit_ip(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                  LLVMValueRef ip_value, bool is_64bit)
{
    switch (comp_ctx->aux_stack_frame_type) {
        case AOT_STACK_FRAME_TYPE_STANDARD:
            return aot_standard_frame_gen_commit_ip(comp_ctx, func_ctx,
                                                    ip_value, is_64bit);
        case AOT_STACK_FRAME_TYPE_TINY:
            return aot_tiny_frame_gen_commit_ip(comp_ctx, func_ctx, ip_value);
        default:
            aot_set_last_error(
                "unsupported mode when generating commit_ip code");
            return false;
    }
}

bool
aot_gen_commit_sp_ip(AOTCompFrame *frame, bool commit_sp, bool commit_ip)
{
    AOTCompContext *comp_ctx = frame->comp_ctx;
    AOTFuncContext *func_ctx = frame->func_ctx;
    LLVMValueRef cur_frame = func_ctx->cur_frame;
    LLVMValueRef value_offset, value_addr, value_ptr, value;
    LLVMTypeRef int8_ptr_ptr_type;
    uint32 offset_sp, n;
    bool is_64bit = (comp_ctx->pointer_size == sizeof(uint64)) ? true : false;
    const AOTValueSlot *sp = frame->sp;
    const uint8 *ip = frame->frame_ip;

    if (!comp_ctx->is_jit_mode) {
        offset_sp = frame->comp_ctx->pointer_size * 5;
    }
    else {
        offset_sp = offsetof(WASMInterpFrame, sp);
    }

    if (commit_ip && comp_ctx->call_stack_features.ip) {
        if (!comp_ctx->is_jit_mode) {
            WASMModule *module = comp_ctx->comp_data->wasm_module;
            if (is_64bit)
                value = I64_CONST((uint64)(uintptr_t)(ip - module->load_addr));
            else
                value = I32_CONST((uint32)(uintptr_t)(ip - module->load_addr));
        }
        else {
            if (is_64bit)
                value = I64_CONST((uint64)(uintptr_t)ip);
            else
                value = I32_CONST((uint32)(uintptr_t)ip);
        }

        if (!value) {
            aot_set_last_error("llvm build const failed");
            return false;
        }

        if (!aot_gen_commit_ip(comp_ctx, func_ctx, value, is_64bit)) {
            return false;
        }
    }

    if (commit_sp && comp_ctx->call_stack_features.values) {
        n = (uint32)(sp - frame->lp);
        value = I32_CONST(offset_of_local(comp_ctx, n));
        if (!value) {
            aot_set_last_error("llvm build const failed");
            return false;
        }

        if (!(value = LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE,
                                            cur_frame, &value, 1, "sp"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }

        if (!(value_offset = I32_CONST(offset_sp))) {
            aot_set_last_error("llvm build const failed");
            return false;
        }

        if (!(value_addr =
                  LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, cur_frame,
                                        &value_offset, 1, "sp_addr"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }

        if (!(int8_ptr_ptr_type = LLVMPointerType(INT8_PTR_TYPE, 0))) {
            aot_set_last_error("llvm build pointer type failed");
            return false;
        }

        if (!(value_ptr = LLVMBuildBitCast(comp_ctx->builder, value_addr,
                                           int8_ptr_ptr_type, "sp_ptr"))) {
            aot_set_last_error("llvm build bit cast failed");
            return false;
        }

        if (!LLVMBuildStore(comp_ctx->builder, value, value_ptr)) {
            aot_set_last_error("llvm build store failed");
            return false;
        }
    }

    return true;
}

static uint32
get_cur_frame_size(const AOTCompContext *comp_ctx, uint32 max_local_cell_num,
                   uint32 max_stack_cell_num)
{
    uint32 all_cell_num = max_local_cell_num + max_stack_cell_num;
    uint32 frame_size;

    if (!comp_ctx->is_jit_mode) {
        /* Refer to aot_alloc_frame */
        if (!comp_ctx->enable_gc)
            frame_size = comp_ctx->pointer_size
                             * (offsetof(AOTFrame, lp) / sizeof(uintptr_t))
                         + all_cell_num * 4;
        else
            frame_size = comp_ctx->pointer_size
                             * (offsetof(AOTFrame, lp) / sizeof(uintptr_t))
                         + align_uint(all_cell_num * 5, 4);
    }
    else {
        /* Refer to wasm_interp_interp_frame_size */
        if (!comp_ctx->enable_gc)
            frame_size = offsetof(WASMInterpFrame, lp) + all_cell_num * 4;
        else
            frame_size =
                offsetof(WASMInterpFrame, lp) + align_uint(all_cell_num * 5, 4);
    }

    return frame_size;
}

static bool
init_comp_frame(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                uint32 func_idx)
{
    AOTCompFrame *aot_frame;
    AOTFunc *aot_func = func_ctx->aot_func;
    AOTFuncType *func_type = aot_func->func_type;
    AOTBlock *block = func_ctx->block_stack.block_list_end;
    LLVMValueRef local_value;
    uint32 max_local_cell_num =
        aot_func->param_cell_num + aot_func->local_cell_num;
    uint32 max_stack_cell_num = aot_func->max_stack_cell_num;
    uint32 all_cell_num = max_local_cell_num + max_stack_cell_num;
    uint32 i, n;
    uint64 total_size;
    uint8 local_type;

    /* Free aot_frame if it was allocated previously for
       compiling other functions */
    if (comp_ctx->aot_frame) {
        wasm_runtime_free(comp_ctx->aot_frame);
        comp_ctx->aot_frame = NULL;
    }

    /* Allocate extra 2 cells since some operations may push more
       operands than the number calculated in wasm loader, such as
       PUSH_F64(F64_CONST(1.0)) in aot_compile_op_f64_promote_f32 */
    all_cell_num += 2;
    total_size = offsetof(AOTCompFrame, lp)
                 + (uint64)sizeof(AOTValueSlot) * all_cell_num;

    if (total_size > UINT32_MAX
        || !(comp_ctx->aot_frame = aot_frame =
                 wasm_runtime_malloc((uint32)total_size))) {
        aot_set_last_error("allocate memory failed.");
        return false;
    }
    memset(aot_frame, 0, (uint32)total_size);

    aot_frame->comp_ctx = comp_ctx;
    aot_frame->func_ctx = func_ctx;

    aot_frame->max_local_cell_num = max_local_cell_num;
    aot_frame->max_stack_cell_num = max_stack_cell_num;
    aot_frame->cur_frame_size =
        get_cur_frame_size(comp_ctx, max_local_cell_num, max_stack_cell_num);

    aot_frame->sp = aot_frame->lp + max_local_cell_num;

    /* Init the frame_sp_begin and frame_sp_max_reached
       of the function block */
    block->frame_sp_begin = block->frame_sp_max_reached = aot_frame->sp;

    n = 0;

    /* Set all params dirty since they were set to llvm value but
       haven't been committed to the AOT/JIT stack frame */
    for (i = 0; i < func_type->param_count; i++) {
        local_type = func_type->types[i];
        local_value = LLVMGetParam(func_ctx->func, i + 1);

        switch (local_type) {
            case VALUE_TYPE_I32:
                set_local_i32(comp_ctx->aot_frame, n, local_value);
                n++;
                break;
            case VALUE_TYPE_I64:
                set_local_i64(comp_ctx->aot_frame, n, local_value);
                n += 2;
                break;
            case VALUE_TYPE_F32:
                set_local_f32(comp_ctx->aot_frame, n, local_value);
                n++;
                break;
            case VALUE_TYPE_F64:
                set_local_f64(comp_ctx->aot_frame, n, local_value);
                n += 2;
                break;
            case VALUE_TYPE_V128:
                set_local_v128(comp_ctx->aot_frame, n, local_value);
                n += 4;
                break;
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
            {
                if (comp_ctx->enable_ref_types) {
                    set_local_ref(comp_ctx->aot_frame, n, local_value,
                                  local_type);
                    n++;
                }
#if WASM_ENABLE_GC != 0
                else if (comp_ctx->enable_gc) {
                    set_local_gc_ref(comp_ctx->aot_frame, n, local_value,
                                     VALUE_TYPE_GC_REF);
                    n += comp_ctx->pointer_size / sizeof(uint32);
                }
#endif
                else {
                    bh_assert(0);
                }
                break;
            }
#if WASM_ENABLE_GC != 0
            case REF_TYPE_NULLFUNCREF:
            case REF_TYPE_NULLEXTERNREF:
            case REF_TYPE_NULLREF:
            /* case REF_TYPE_FUNCREF: */
            /* case REF_TYPE_EXTERNREF: */
            case REF_TYPE_ANYREF:
            case REF_TYPE_EQREF:
            case REF_TYPE_HT_NULLABLE:
            case REF_TYPE_HT_NON_NULLABLE:
            case REF_TYPE_I31REF:
            case REF_TYPE_STRUCTREF:
            case REF_TYPE_ARRAYREF:
#if WASM_ENABLE_STRINGREF != 0
            case REF_TYPE_STRINGREF:
            case REF_TYPE_STRINGVIEWWTF8:
            case REF_TYPE_STRINGVIEWWTF16:
            case REF_TYPE_STRINGVIEWITER:
#endif
                bh_assert(comp_ctx->enable_gc);
                set_local_gc_ref(comp_ctx->aot_frame, n, local_value,
                                 VALUE_TYPE_GC_REF);
                n += comp_ctx->pointer_size / sizeof(uint32);
                break;
#endif
            default:
                bh_assert(0);
                break;
        }
    }

    /* TODO: re-calculate param_cell_num according to the build target
             after creating comp_ctx */
    /* bh_assert(n == aot_func->param_cell_num); */

    /* Set all locals dirty since they were set to llvm value but
       haven't been committed to the AOT/JIT stack frame */
    for (i = 0; i < aot_func->local_count; i++) {
        local_type = aot_func->local_types_wp[i];

        switch (local_type) {
            case VALUE_TYPE_I32:
                set_local_i32(comp_ctx->aot_frame, n, I32_ZERO);
                n++;
                break;
            case VALUE_TYPE_I64:
                set_local_i64(comp_ctx->aot_frame, n, I64_ZERO);
                n += 2;
                break;
            case VALUE_TYPE_F32:
                set_local_f32(comp_ctx->aot_frame, n, F32_ZERO);
                n++;
                break;
            case VALUE_TYPE_F64:
                set_local_f64(comp_ctx->aot_frame, n, F64_ZERO);
                n += 2;
                break;
            case VALUE_TYPE_V128:
                set_local_v128(comp_ctx->aot_frame, n, V128_f64x2_ZERO);
                n += 4;
                break;
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
            {
                if (comp_ctx->enable_ref_types) {
                    set_local_ref(comp_ctx->aot_frame, n, I32_ZERO, local_type);
                    n++;
                }
#if WASM_ENABLE_GC != 0
                else if (comp_ctx->enable_gc) {
                    set_local_gc_ref(comp_ctx->aot_frame, n, GC_REF_NULL,
                                     VALUE_TYPE_GC_REF);
                    n += comp_ctx->pointer_size / sizeof(uint32);
                }
#endif
                else {
                    bh_assert(0);
                }
                break;
            }
#if WASM_ENABLE_GC != 0
            case REF_TYPE_NULLFUNCREF:
            case REF_TYPE_NULLEXTERNREF:
            case REF_TYPE_NULLREF:
            /* case REF_TYPE_FUNCREF: */
            /* case REF_TYPE_EXTERNREF: */
            case REF_TYPE_ANYREF:
            case REF_TYPE_EQREF:
            case REF_TYPE_HT_NULLABLE:
            case REF_TYPE_HT_NON_NULLABLE:
            case REF_TYPE_I31REF:
            case REF_TYPE_STRUCTREF:
            case REF_TYPE_ARRAYREF:
#if WASM_ENABLE_STRINGREF != 0
            case REF_TYPE_STRINGREF:
            case REF_TYPE_STRINGVIEWWTF8:
            case REF_TYPE_STRINGVIEWWTF16:
            case REF_TYPE_STRINGVIEWITER:
#endif
                bh_assert(comp_ctx->enable_gc);
                set_local_gc_ref(comp_ctx->aot_frame, n, GC_REF_NULL,
                                 VALUE_TYPE_GC_REF);
                n += comp_ctx->pointer_size / sizeof(uint32);
                break;
#endif
            default:
                bh_assert(0);
                break;
        }
    }

    /* TODO: re-calculate local_cell_num according to the build target
             after creating comp_ctx */
    /* bh_assert(n == aot_func->param_cell_num + aot_func->local_cell_num); */

    /* No need to initialize aot_frame all cells' committed_ref flags
       and all stack cells' ref flags since they have been initialized
       as 0 (uncommitted and not-reference) by the memset above */

    return true;
}

static bool
aot_compile_func(AOTCompContext *comp_ctx, uint32 func_index)
{
    AOTFuncContext *func_ctx = comp_ctx->func_ctxes[func_index];
    LLVMValueRef func_index_ref;
    uint8 *frame_ip = func_ctx->aot_func->code, opcode, *p_f32, *p_f64;
    uint8 *frame_ip_end = frame_ip + func_ctx->aot_func->code_size;
    uint8 *param_types = NULL;
    uint8 *result_types = NULL;
    uint8 value_type;
    uint16 param_count;
    uint16 result_count;
    uint32 br_depth, *br_depths, br_count;
    uint32 func_idx, type_idx, mem_idx, local_idx, global_idx, i;
    uint32 bytes = 4, align;
    mem_offset_t offset;
    uint32 type_index;
    bool sign = true;
    int32 i32_const;
    int64 i64_const;
    float32 f32_const;
    float64 f64_const;
    AOTFuncType *func_type = NULL;
#if WASM_ENABLE_DEBUG_AOT != 0
    LLVMMetadataRef location;
#endif

    /* Start to translate the opcodes */
    LLVMPositionBuilderAtEnd(
        comp_ctx->builder,
        func_ctx->block_stack.block_list_head->llvm_entry_block);

    if (comp_ctx->aux_stack_frame_type
        && comp_ctx->call_stack_features.frame_per_function) {
        INT_CONST(func_index_ref,
                  func_index + comp_ctx->comp_data->import_func_count, I32_TYPE,
                  true);
        if (!aot_alloc_frame_per_function_frame_for_aot_func(comp_ctx, func_ctx,
                                                             func_index_ref)) {
            return false;
        }
    }
    if (comp_ctx->aux_stack_frame_type) {
        if (!init_comp_frame(comp_ctx, func_ctx, func_index)) {
            return false;
        }
    }

    while (frame_ip < frame_ip_end) {
        opcode = *frame_ip++;

        if (comp_ctx->aot_frame) {
            comp_ctx->aot_frame->frame_ip = frame_ip - 1;
        }

#if WASM_ENABLE_DEBUG_AOT != 0
        location = dwarf_gen_location(
            comp_ctx, func_ctx,
            (frame_ip - 1) - comp_ctx->comp_data->wasm_module->buf_code);
        if (location != NULL) {
            LLVMSetCurrentDebugLocation2(comp_ctx->builder, location);
        }
#endif

        switch (opcode) {
            case WASM_OP_UNREACHABLE:
                if (!aot_compile_op_unreachable(comp_ctx, func_ctx, &frame_ip))
                    return false;
                break;

            case WASM_OP_NOP:
                break;

            case WASM_OP_BLOCK:
            case WASM_OP_LOOP:
            case WASM_OP_IF:
            {
                value_type = *frame_ip++;
                if (value_type == VALUE_TYPE_I32 || value_type == VALUE_TYPE_I64
                    || value_type == VALUE_TYPE_F32
                    || value_type == VALUE_TYPE_F64
                    || value_type == VALUE_TYPE_V128
                    || value_type == VALUE_TYPE_VOID
                    || (comp_ctx->enable_ref_types
                        && (value_type == VALUE_TYPE_FUNCREF
                            || value_type == VALUE_TYPE_EXTERNREF))
                    || (comp_ctx->enable_gc /* single byte type */
                        && aot_is_type_gc_reftype(value_type))) {
                    param_count = 0;
                    param_types = NULL;
                    if (value_type == VALUE_TYPE_VOID) {
                        result_count = 0;
                        result_types = NULL;
                    }
                    else {
                        if (comp_ctx->enable_gc
                            && aot_is_type_gc_reftype(value_type))
                            value_type = VALUE_TYPE_GC_REF;
                        result_count = 1;
                        result_types = &value_type;
                    }
                }
                else {
                    frame_ip--;
                    read_leb_int32(frame_ip, frame_ip_end, type_index);
                    /* type index was checked in wasm loader */
                    bh_assert(type_index < comp_ctx->comp_data->type_count);
                    func_type =
                        (AOTFuncType *)comp_ctx->comp_data->types[type_index];
                    param_count = func_type->param_count;
                    param_types = func_type->types;
                    result_count = func_type->result_count;
                    result_types = func_type->types + param_count;
                }
                if (!aot_compile_op_block(
                        comp_ctx, func_ctx, &frame_ip, frame_ip_end,
                        (uint32)(LABEL_TYPE_BLOCK + opcode - WASM_OP_BLOCK),
                        param_count, param_types, result_count, result_types))
                    return false;
                break;
            }

            case EXT_OP_BLOCK:
            case EXT_OP_LOOP:
            case EXT_OP_IF:
            {
                read_leb_int32(frame_ip, frame_ip_end, type_index);
                /* type index was checked in wasm loader */
                bh_assert(type_index < comp_ctx->comp_data->type_count);
                func_type =
                    (AOTFuncType *)comp_ctx->comp_data->types[type_index];
                param_count = func_type->param_count;
                param_types = func_type->types;
                result_count = func_type->result_count;
                result_types = func_type->types + param_count;
                if (!aot_compile_op_block(
                        comp_ctx, func_ctx, &frame_ip, frame_ip_end,
                        (uint32)(LABEL_TYPE_BLOCK + opcode - EXT_OP_BLOCK),
                        param_count, param_types, result_count, result_types))
                    return false;
                break;
            }

            case WASM_OP_ELSE:
                if (!aot_compile_op_else(comp_ctx, func_ctx, &frame_ip))
                    return false;
                break;

            case WASM_OP_END:
                if (!aot_compile_op_end(comp_ctx, func_ctx, &frame_ip))
                    return false;
                break;

            case WASM_OP_BR:
            {
                read_leb_uint32(frame_ip, frame_ip_end, br_depth);
                if (!aot_compile_op_br(comp_ctx, func_ctx, br_depth, &frame_ip))
                    return false;
                break;
            }

            case WASM_OP_BR_IF:
            {
                read_leb_uint32(frame_ip, frame_ip_end, br_depth);
                if (!aot_compile_op_br_if(comp_ctx, func_ctx, br_depth,
                                          &frame_ip))
                    return false;
                break;
            }

            case WASM_OP_BR_TABLE:
            {
                read_leb_uint32(frame_ip, frame_ip_end, br_count);
                if (!(br_depths = wasm_runtime_malloc((uint32)sizeof(uint32)
                                                      * (br_count + 1)))) {
                    aot_set_last_error("allocate memory failed.");
                    goto fail;
                }
#if WASM_ENABLE_FAST_INTERP != 0
                for (i = 0; i <= br_count; i++)
                    read_leb_uint32(frame_ip, frame_ip_end, br_depths[i]);
#else
                for (i = 0; i <= br_count; i++)
                    br_depths[i] = *frame_ip++;
#endif

                if (!aot_compile_op_br_table(comp_ctx, func_ctx, br_depths,
                                             br_count, &frame_ip)) {
                    wasm_runtime_free(br_depths);
                    return false;
                }

                wasm_runtime_free(br_depths);
                break;
            }

#if WASM_ENABLE_FAST_INTERP == 0
            case EXT_OP_BR_TABLE_CACHE:
            {
                BrTableCache *node = bh_list_first_elem(
                    comp_ctx->comp_data->wasm_module->br_table_cache_list);
                BrTableCache *node_next;
                const uint8 *frame_ip_org = frame_ip - 1;

                read_leb_uint32(frame_ip, frame_ip_end, br_count);

                while (node) {
                    node_next = bh_list_elem_next(node);
                    if (node->br_table_op_addr == frame_ip_org) {
                        br_depths = node->br_depths;
                        if (!aot_compile_op_br_table(comp_ctx, func_ctx,
                                                     br_depths, br_count,
                                                     &frame_ip)) {
                            return false;
                        }
                        break;
                    }
                    node = node_next;
                }
                bh_assert(node);

                break;
            }
#endif

            case WASM_OP_RETURN:
                if (!aot_compile_op_return(comp_ctx, func_ctx, &frame_ip))
                    return false;
                break;

            case WASM_OP_CALL:
            {
                read_leb_uint32(frame_ip, frame_ip_end, func_idx);
                if (!aot_compile_op_call(comp_ctx, func_ctx, func_idx, false))
                    return false;
                break;
            }

            case WASM_OP_CALL_INDIRECT:
            {
                uint32 tbl_idx;

                read_leb_uint32(frame_ip, frame_ip_end, type_idx);

                if (comp_ctx->enable_gc || comp_ctx->enable_ref_types) {
                    read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                }
                else {
                    frame_ip++;
                    tbl_idx = 0;
                }

                if (!aot_compile_op_call_indirect(comp_ctx, func_ctx, type_idx,
                                                  tbl_idx))
                    return false;
                break;
            }

#if WASM_ENABLE_TAIL_CALL != 0
            case WASM_OP_RETURN_CALL:
            {
                if (!comp_ctx->enable_tail_call) {
                    aot_set_last_error("unsupported opcode");
                    return false;
                }

                read_leb_uint32(frame_ip, frame_ip_end, func_idx);
                if (!aot_compile_op_call(comp_ctx, func_ctx, func_idx, true))
                    return false;
                if (!aot_compile_op_return(comp_ctx, func_ctx, &frame_ip))
                    return false;
                break;
            }

            case WASM_OP_RETURN_CALL_INDIRECT:
            {
                uint32 tbl_idx;

                if (!comp_ctx->enable_tail_call) {
                    aot_set_last_error("unsupported opcode");
                    return false;
                }

                read_leb_uint32(frame_ip, frame_ip_end, type_idx);
                if (comp_ctx->enable_gc || comp_ctx->enable_ref_types) {
                    read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                }
                else {
                    frame_ip++;
                    tbl_idx = 0;
                }

                if (!aot_compile_op_call_indirect(comp_ctx, func_ctx, type_idx,
                                                  tbl_idx))
                    return false;
                if (!aot_compile_op_return(comp_ctx, func_ctx, &frame_ip))
                    return false;
                break;
            }
#endif /* end of WASM_ENABLE_TAIL_CALL */

            case WASM_OP_DROP:
                if (!aot_compile_op_drop(comp_ctx, func_ctx, true))
                    return false;
                break;

            case WASM_OP_DROP_64:
                if (!aot_compile_op_drop(comp_ctx, func_ctx, false))
                    return false;
                break;

            case WASM_OP_SELECT:
                if (!aot_compile_op_select(comp_ctx, func_ctx, true))
                    return false;
                break;

            case WASM_OP_SELECT_64:
                if (!aot_compile_op_select(comp_ctx, func_ctx, false))
                    return false;
                break;

#if WASM_ENABLE_REF_TYPES != 0 || WASM_ENABLE_GC != 0
            case WASM_OP_SELECT_T:
            {
                uint32 vec_len;

                if (!comp_ctx->enable_ref_types && !comp_ctx->enable_gc) {
                    goto unsupport_gc_and_ref_types;
                }

                read_leb_uint32(frame_ip, frame_ip_end, vec_len);
                bh_assert(vec_len == 1);
                (void)vec_len;

                type_idx = *frame_ip++;
                if (!aot_compile_op_select(
                        comp_ctx, func_ctx,
                        (type_idx != VALUE_TYPE_I64)
                            && (type_idx != VALUE_TYPE_F64)
#if WASM_ENABLE_GC != 0
                            && !(comp_ctx->enable_gc
                                 && comp_ctx->pointer_size == sizeof(uint64)
                                 && wasm_is_type_reftype(type_idx))
#endif
                            ))
                    return false;

                break;
            }
            case WASM_OP_TABLE_GET:
            {
                uint32 tbl_idx;

                if (!comp_ctx->enable_ref_types && !comp_ctx->enable_gc) {
                    goto unsupport_gc_and_ref_types;
                }

                read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                if (!aot_compile_op_table_get(comp_ctx, func_ctx, tbl_idx))
                    return false;
                break;
            }
            case WASM_OP_TABLE_SET:
            {
                uint32 tbl_idx;

                if (!comp_ctx->enable_ref_types && !comp_ctx->enable_gc) {
                    goto unsupport_gc_and_ref_types;
                }

                read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                if (!aot_compile_op_table_set(comp_ctx, func_ctx, tbl_idx))
                    return false;
                break;
            }
            case WASM_OP_REF_NULL:
            {
                uint32 type;

                if (!comp_ctx->enable_ref_types && !comp_ctx->enable_gc) {
                    goto unsupport_gc_and_ref_types;
                }

                read_leb_uint32(frame_ip, frame_ip_end, type);

                if (!aot_compile_op_ref_null(comp_ctx, func_ctx))
                    return false;

                (void)type;
                break;
            }
            case WASM_OP_REF_IS_NULL:
            {
                if (!comp_ctx->enable_ref_types && !comp_ctx->enable_gc) {
                    goto unsupport_gc_and_ref_types;
                }

                if (!aot_compile_op_ref_is_null(comp_ctx, func_ctx))
                    return false;
                break;
            }
            case WASM_OP_REF_FUNC:
            {
                if (!comp_ctx->enable_ref_types && !comp_ctx->enable_gc) {
                    goto unsupport_gc_and_ref_types;
                }

                read_leb_uint32(frame_ip, frame_ip_end, func_idx);
                if (!aot_compile_op_ref_func(comp_ctx, func_ctx, func_idx))
                    return false;
                break;
            }
#endif /* end of WASM_ENABLE_REF_TYPES != 0 || WASM_ENABLE_GC != 0 */

#if WASM_ENABLE_GC != 0
            case WASM_OP_CALL_REF:
            {
                if (!comp_ctx->enable_gc) {
                    goto unsupport_gc;
                }

                read_leb_uint32(frame_ip, frame_ip_end, type_idx);
                if (!aot_compile_op_call_ref(comp_ctx, func_ctx, type_idx,
                                             false))
                    return false;
                break;
            }

            case WASM_OP_RETURN_CALL_REF:
            {
                if (!comp_ctx->enable_gc) {
                    goto unsupport_gc;
                }

                read_leb_uint32(frame_ip, frame_ip_end, type_idx);
                if (!aot_compile_op_call_ref(comp_ctx, func_ctx, type_idx,
                                             true))
                    return false;
                if (!aot_compile_op_return(comp_ctx, func_ctx, &frame_ip))
                    return false;
                break;
            }

            case WASM_OP_REF_EQ:
                if (!comp_ctx->enable_gc) {
                    goto unsupport_gc;
                }

                if (!aot_compile_op_ref_eq(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_REF_AS_NON_NULL:
                if (!comp_ctx->enable_gc) {
                    goto unsupport_gc;
                }

                if (!aot_compile_op_ref_as_non_null(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_BR_ON_NULL:
            {
                if (!comp_ctx->enable_gc) {
                    goto unsupport_gc;
                }

                read_leb_uint32(frame_ip, frame_ip_end, br_depth);
                if (!aot_compile_op_br_on_null(comp_ctx, func_ctx, br_depth,
                                               &frame_ip))
                    return false;
                break;
            }

            case WASM_OP_BR_ON_NON_NULL:
            {
                if (!comp_ctx->enable_gc) {
                    goto unsupport_gc;
                }

                read_leb_uint32(frame_ip, frame_ip_end, br_depth);
                if (!aot_compile_op_br_on_non_null(comp_ctx, func_ctx, br_depth,
                                                   &frame_ip))
                    return false;
                break;
            }

            case WASM_OP_GC_PREFIX:
            {
                uint32 opcode1, field_idx, data_seg_idx, array_len;

                if (!comp_ctx->enable_gc) {
                    goto unsupport_gc;
                }

                read_leb_uint32(frame_ip, frame_ip_end, opcode1);
                /* opcode1 was checked in loader and is no larger than
                   UINT8_MAX */
                opcode = (uint8)opcode1;

                switch (opcode) {
                    case WASM_OP_STRUCT_NEW:
                    case WASM_OP_STRUCT_NEW_DEFAULT:
                        read_leb_uint32(frame_ip, frame_ip_end, type_index);
                        if (!aot_compile_op_struct_new(
                                comp_ctx, func_ctx, type_index,
                                opcode == WASM_OP_STRUCT_NEW_DEFAULT))
                            return false;
                        break;

                    case WASM_OP_STRUCT_GET:
                    case WASM_OP_STRUCT_GET_S:
                    case WASM_OP_STRUCT_GET_U:
                        read_leb_uint32(frame_ip, frame_ip_end, type_index);
                        read_leb_uint32(frame_ip, frame_ip_end, field_idx);
                        if (!aot_compile_op_struct_get(
                                comp_ctx, func_ctx, type_index, field_idx,
                                opcode == WASM_OP_STRUCT_GET_S))
                            return false;
                        break;

                    case WASM_OP_STRUCT_SET:
                        read_leb_uint32(frame_ip, frame_ip_end, type_index);
                        read_leb_uint32(frame_ip, frame_ip_end, field_idx);
                        if (!aot_compile_op_struct_set(comp_ctx, func_ctx,
                                                       type_index, field_idx))
                            return false;
                        break;

                    case WASM_OP_ARRAY_NEW:
                    case WASM_OP_ARRAY_NEW_DEFAULT:
                    case WASM_OP_ARRAY_NEW_FIXED:
                        read_leb_uint32(frame_ip, frame_ip_end, type_index);
                        if (opcode == WASM_OP_ARRAY_NEW_FIXED)
                            read_leb_uint32(frame_ip, frame_ip_end, array_len);
                        else
                            array_len = 0;
                        if (!aot_compile_op_array_new(
                                comp_ctx, func_ctx, type_index,
                                opcode == WASM_OP_ARRAY_NEW_DEFAULT,
                                opcode == WASM_OP_ARRAY_NEW_FIXED, array_len))
                            return false;
                        break;

                    case WASM_OP_ARRAY_NEW_DATA:
                        read_leb_uint32(frame_ip, frame_ip_end, type_index);
                        read_leb_uint32(frame_ip, frame_ip_end, data_seg_idx);
                        if (!aot_compile_op_array_new_data(
                                comp_ctx, func_ctx, type_index, data_seg_idx))
                            return false;
                        break;

                    case WASM_OP_ARRAY_NEW_ELEM:
                        /* TODO */
                        aot_set_last_error("unsupported opcode");
                        return false;

                    case WASM_OP_ARRAY_GET:
                    case WASM_OP_ARRAY_GET_S:
                    case WASM_OP_ARRAY_GET_U:
                        read_leb_uint32(frame_ip, frame_ip_end, type_index);
                        if (!aot_compile_op_array_get(
                                comp_ctx, func_ctx, type_index,
                                opcode == WASM_OP_ARRAY_GET_S))
                            return false;
                        break;

                    case WASM_OP_ARRAY_SET:
                        read_leb_uint32(frame_ip, frame_ip_end, type_index);
                        if (!aot_compile_op_array_set(comp_ctx, func_ctx,
                                                      type_index))
                            return false;
                        break;

                    case WASM_OP_ARRAY_FILL:
                        read_leb_uint32(frame_ip, frame_ip_end, type_index);
                        if (!aot_compile_op_array_fill(comp_ctx, func_ctx,
                                                       type_index))
                            return false;
                        break;

                    case WASM_OP_ARRAY_COPY:
                    {
                        uint32 src_type_index;

                        read_leb_uint32(frame_ip, frame_ip_end, type_index);
                        read_leb_uint32(frame_ip, frame_ip_end, src_type_index);
                        if (!aot_compile_op_array_copy(
                                comp_ctx, func_ctx, type_index, src_type_index))
                            return false;
                        break;
                    }

                    case WASM_OP_ARRAY_LEN:
                        if (!aot_compile_op_array_len(comp_ctx, func_ctx))
                            return false;
                        break;

                    case WASM_OP_REF_I31:
                        if (!aot_compile_op_i31_new(comp_ctx, func_ctx))
                            return false;
                        break;

                    case WASM_OP_I31_GET_S:
                    case WASM_OP_I31_GET_U:
                        if (!aot_compile_op_i31_get(
                                comp_ctx, func_ctx,
                                opcode == WASM_OP_I31_GET_S ? true : false))
                            return false;
                        break;

                    case WASM_OP_REF_TEST:
                    case WASM_OP_REF_TEST_NULLABLE:
                    {
                        int32 heap_type;

                        read_leb_int32(frame_ip, frame_ip_end, heap_type);
                        if (!aot_compile_op_ref_test(
                                comp_ctx, func_ctx, heap_type,
                                opcode == WASM_OP_REF_TEST_NULLABLE ? true
                                                                    : false))
                            return false;
                        break;
                    }

                    case WASM_OP_REF_CAST:
                    case WASM_OP_REF_CAST_NULLABLE:
                    {
                        int32 heap_type;

                        read_leb_int32(frame_ip, frame_ip_end, heap_type);
                        if (!aot_compile_op_ref_cast(
                                comp_ctx, func_ctx, heap_type,
                                opcode == WASM_OP_REF_CAST_NULLABLE ? true
                                                                    : false))
                            return false;
                        break;
                    }

                    case WASM_OP_BR_ON_CAST:
                    case WASM_OP_BR_ON_CAST_FAIL:
                    {
                        uint8 castflags;
                        int32 heap_type, dst_heap_type;

                        CHECK_BUF(frame_ip, frame_ip_end, 1);
                        castflags = *frame_ip++;
                        read_leb_uint32(frame_ip, frame_ip_end, br_depth);
                        read_leb_int32(frame_ip, frame_ip_end, heap_type);
                        read_leb_int32(frame_ip, frame_ip_end, dst_heap_type);

                        /*
                         * castflags should be 0~3:
                         *  0: (non-null, non-null)
                         *  1: (null, non-null)
                         *  2: (non-null, null)
                         *  3: (null, null)
                         * The nullability of source type has been checked in
                         * wasm loader, here we just need the dst nullability
                         */
                        if (!aot_compile_op_br_on_cast(
                                comp_ctx, func_ctx, dst_heap_type,
                                castflags & 0x02,
                                opcode == WASM_OP_BR_ON_CAST_FAIL, br_depth,
                                &frame_ip))
                            return false;

                        (void)heap_type;
                        break;
                    }

                    case WASM_OP_ANY_CONVERT_EXTERN:
                        if (!aot_compile_op_extern_internalize(comp_ctx,
                                                               func_ctx))
                            return false;
                        break;

                    case WASM_OP_EXTERN_CONVERT_ANY:
                        if (!aot_compile_op_extern_externalize(comp_ctx,
                                                               func_ctx))
                            return false;
                        break;

#if WASM_ENABLE_STRINGREF != 0
                    case WASM_OP_STRING_NEW_UTF8:
                    case WASM_OP_STRING_NEW_WTF16:
                    case WASM_OP_STRING_NEW_LOSSY_UTF8:
                    case WASM_OP_STRING_NEW_WTF8:
                    {
                        EncodingFlag flag = WTF8;

                        read_leb_uint32(frame_ip, frame_ip_end, mem_idx);
                        bh_assert(mem_idx == 0);

                        if (opcode == WASM_OP_STRING_NEW_WTF16) {
                            flag = WTF16;
                        }
                        else if (opcode == WASM_OP_STRING_NEW_UTF8) {
                            flag = UTF8;
                        }
                        else if (opcode == WASM_OP_STRING_NEW_LOSSY_UTF8) {
                            flag = LOSSY_UTF8;
                        }
                        else if (opcode == WASM_OP_STRING_NEW_WTF8) {
                            flag = WTF8;
                        }

                        if (!aot_compile_op_string_new(comp_ctx, func_ctx,
                                                       flag))
                            return false;
                        break;
                    }
                    case WASM_OP_STRING_CONST:
                    {
                        uint32 contents;
                        read_leb_uint32(frame_ip, frame_ip_end, contents);

                        if (!aot_compile_op_string_const(comp_ctx, func_ctx,
                                                         contents))
                            return false;
                        break;
                    }
                    case WASM_OP_STRING_MEASURE_UTF8:
                    case WASM_OP_STRING_MEASURE_WTF8:
                    case WASM_OP_STRING_MEASURE_WTF16:
                    {
                        EncodingFlag flag = WTF8;

                        if (opcode == WASM_OP_STRING_MEASURE_WTF16) {
                            flag = WTF16;
                        }
                        else if (opcode == WASM_OP_STRING_MEASURE_UTF8) {
                            flag = UTF8;
                        }
                        else if (opcode == WASM_OP_STRING_MEASURE_WTF8) {
                            flag = LOSSY_UTF8;
                        }

                        if (!aot_compile_op_string_measure(comp_ctx, func_ctx,
                                                           flag))
                            return false;
                        break;
                    }
                    case WASM_OP_STRING_ENCODE_UTF8:
                    case WASM_OP_STRING_ENCODE_WTF16:
                    case WASM_OP_STRING_ENCODE_LOSSY_UTF8:
                    case WASM_OP_STRING_ENCODE_WTF8:
                    {
                        EncodingFlag flag = WTF8;

                        read_leb_uint32(frame_ip, frame_ip_end, mem_idx);
                        bh_assert(mem_idx == 0);

                        if (opcode == WASM_OP_STRING_ENCODE_WTF16) {
                            flag = WTF16;
                        }
                        else if (opcode == WASM_OP_STRING_ENCODE_UTF8) {
                            flag = UTF8;
                        }
                        else if (opcode == WASM_OP_STRING_ENCODE_LOSSY_UTF8) {
                            flag = LOSSY_UTF8;
                        }
                        else if (opcode == WASM_OP_STRING_ENCODE_WTF8) {
                            flag = WTF8;
                        }

                        if (!aot_compile_op_string_encode(comp_ctx, func_ctx,
                                                          mem_idx, flag))
                            return false;
                        break;
                    }
                    case WASM_OP_STRING_CONCAT:
                        if (!aot_compile_op_string_concat(comp_ctx, func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRING_EQ:
                        if (!aot_compile_op_string_eq(comp_ctx, func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRING_IS_USV_SEQUENCE:
                        if (!aot_compile_op_string_is_usv_sequence(comp_ctx,
                                                                   func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRING_AS_WTF8:
                        if (!aot_compile_op_string_as_wtf8(comp_ctx, func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRINGVIEW_WTF8_ADVANCE:
                        if (!aot_compile_op_stringview_wtf8_advance(comp_ctx,
                                                                    func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRINGVIEW_WTF8_ENCODE_UTF8:
                    case WASM_OP_STRINGVIEW_WTF8_ENCODE_LOSSY_UTF8:
                    case WASM_OP_STRINGVIEW_WTF8_ENCODE_WTF8:
                    {
                        EncodingFlag flag = WTF8;

                        read_leb_uint32(frame_ip, frame_ip_end, mem_idx);
                        bh_assert(mem_idx == 0);

                        if (opcode == WASM_OP_STRINGVIEW_WTF8_ENCODE_UTF8) {
                            flag = UTF8;
                        }
                        else if (opcode
                                 == WASM_OP_STRINGVIEW_WTF8_ENCODE_LOSSY_UTF8) {
                            flag = LOSSY_UTF8;
                        }
                        else if (opcode
                                 == WASM_OP_STRINGVIEW_WTF8_ENCODE_WTF8) {
                            flag = WTF8;
                        }

                        if (!aot_compile_op_stringview_wtf8_encode(
                                comp_ctx, func_ctx, mem_idx, flag))
                            return false;
                        break;
                    }
                    case WASM_OP_STRINGVIEW_WTF8_SLICE:
                        if (!aot_compile_op_stringview_wtf8_slice(comp_ctx,
                                                                  func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRING_AS_WTF16:
                        if (!aot_compile_op_string_as_wtf16(comp_ctx, func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRINGVIEW_WTF16_LENGTH:
                        if (!aot_compile_op_stringview_wtf16_length(comp_ctx,
                                                                    func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRINGVIEW_WTF16_GET_CODEUNIT:
                        if (!aot_compile_op_stringview_wtf16_get_codeunit(
                                comp_ctx, func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRINGVIEW_WTF16_ENCODE:
                    {
                        read_leb_uint32(frame_ip, frame_ip_end, mem_idx);
                        bh_assert(mem_idx == 0);

                        if (!aot_compile_op_stringview_wtf16_encode(
                                comp_ctx, func_ctx, mem_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_STRINGVIEW_WTF16_SLICE:
                        if (!aot_compile_op_stringview_wtf16_slice(comp_ctx,
                                                                   func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRING_AS_ITER:
                        if (!aot_compile_op_string_as_iter(comp_ctx, func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRINGVIEW_ITER_NEXT:
                        if (!aot_compile_op_stringview_iter_next(comp_ctx,
                                                                 func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRINGVIEW_ITER_ADVANCE:
                        if (!aot_compile_op_stringview_iter_advance(comp_ctx,
                                                                    func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRINGVIEW_ITER_REWIND:
                        if (!aot_compile_op_stringview_iter_rewind(comp_ctx,
                                                                   func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRINGVIEW_ITER_SLICE:
                        if (!aot_compile_op_stringview_iter_slice(comp_ctx,
                                                                  func_ctx))
                            return false;
                        break;
                    case WASM_OP_STRING_NEW_UTF8_ARRAY:
                    case WASM_OP_STRING_NEW_WTF16_ARRAY:
                    case WASM_OP_STRING_NEW_LOSSY_UTF8_ARRAY:
                    case WASM_OP_STRING_NEW_WTF8_ARRAY:
                    {
                        EncodingFlag flag = WTF8;

                        if (opcode == WASM_OP_STRING_NEW_WTF16) {
                            flag = WTF16;
                        }
                        else if (opcode == WASM_OP_STRING_NEW_UTF8) {
                            flag = UTF8;
                        }
                        else if (opcode == WASM_OP_STRING_NEW_LOSSY_UTF8) {
                            flag = LOSSY_UTF8;
                        }
                        else if (opcode == WASM_OP_STRING_NEW_WTF8) {
                            flag = WTF8;
                        }

                        if (!aot_compile_op_string_new_array(comp_ctx, func_ctx,
                                                             flag))
                            return false;

                        break;
                    }
                    case WASM_OP_STRING_ENCODE_UTF8_ARRAY:
                    case WASM_OP_STRING_ENCODE_WTF16_ARRAY:
                    case WASM_OP_STRING_ENCODE_LOSSY_UTF8_ARRAY:
                    case WASM_OP_STRING_ENCODE_WTF8_ARRAY:
                    {
                        EncodingFlag flag = WTF8;

                        if (opcode == WASM_OP_STRING_ENCODE_WTF16) {
                            flag = WTF16;
                        }
                        else if (opcode == WASM_OP_STRING_ENCODE_UTF8) {
                            flag = UTF8;
                        }
                        else if (opcode == WASM_OP_STRING_ENCODE_LOSSY_UTF8) {
                            flag = LOSSY_UTF8;
                        }
                        else if (opcode == WASM_OP_STRING_ENCODE_WTF8) {
                            flag = WTF8;
                        }

                        if (!aot_compile_op_string_encode_array(comp_ctx,
                                                                func_ctx, flag))
                            return false;
                        break;
                    }
#endif /* end of WASM_ENABLE_STRINGREF != 0 */

                    default:
                        aot_set_last_error("unsupported opcode");
                        return false;
                }
                break;
            }

#endif /* end of WASM_ENABLE_GC != 0 */

            case WASM_OP_GET_LOCAL:
                read_leb_uint32(frame_ip, frame_ip_end, local_idx);
                if (!aot_compile_op_get_local(comp_ctx, func_ctx, local_idx))
                    return false;
                break;

            case WASM_OP_SET_LOCAL:
                read_leb_uint32(frame_ip, frame_ip_end, local_idx);
                if (!aot_compile_op_set_local(comp_ctx, func_ctx, local_idx))
                    return false;
                break;

            case WASM_OP_TEE_LOCAL:
                read_leb_uint32(frame_ip, frame_ip_end, local_idx);
                if (!aot_compile_op_tee_local(comp_ctx, func_ctx, local_idx))
                    return false;
                break;

            case WASM_OP_GET_GLOBAL:
            case WASM_OP_GET_GLOBAL_64:
                read_leb_uint32(frame_ip, frame_ip_end, global_idx);
                if (!aot_compile_op_get_global(comp_ctx, func_ctx, global_idx))
                    return false;
                break;

            case WASM_OP_SET_GLOBAL:
            case WASM_OP_SET_GLOBAL_64:
            case WASM_OP_SET_GLOBAL_AUX_STACK:
                read_leb_uint32(frame_ip, frame_ip_end, global_idx);
                if (!aot_compile_op_set_global(
                        comp_ctx, func_ctx, global_idx,
                        opcode == WASM_OP_SET_GLOBAL_AUX_STACK ? true : false))
                    return false;
                break;

            case WASM_OP_I32_LOAD:
                bytes = 4;
                sign = true;
                goto op_i32_load;
            case WASM_OP_I32_LOAD8_S:
            case WASM_OP_I32_LOAD8_U:
                bytes = 1;
                sign = (opcode == WASM_OP_I32_LOAD8_S) ? true : false;
                goto op_i32_load;
            case WASM_OP_I32_LOAD16_S:
            case WASM_OP_I32_LOAD16_U:
                bytes = 2;
                sign = (opcode == WASM_OP_I32_LOAD16_S) ? true : false;
            op_i32_load:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                if (!aot_compile_op_i32_load(comp_ctx, func_ctx, align, offset,
                                             bytes, sign, false))
                    return false;
                break;

            case WASM_OP_I64_LOAD:
                bytes = 8;
                sign = true;
                goto op_i64_load;
            case WASM_OP_I64_LOAD8_S:
            case WASM_OP_I64_LOAD8_U:
                bytes = 1;
                sign = (opcode == WASM_OP_I64_LOAD8_S) ? true : false;
                goto op_i64_load;
            case WASM_OP_I64_LOAD16_S:
            case WASM_OP_I64_LOAD16_U:
                bytes = 2;
                sign = (opcode == WASM_OP_I64_LOAD16_S) ? true : false;
                goto op_i64_load;
            case WASM_OP_I64_LOAD32_S:
            case WASM_OP_I64_LOAD32_U:
                bytes = 4;
                sign = (opcode == WASM_OP_I64_LOAD32_S) ? true : false;
            op_i64_load:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                if (!aot_compile_op_i64_load(comp_ctx, func_ctx, align, offset,
                                             bytes, sign, false))
                    return false;
                break;

            case WASM_OP_F32_LOAD:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                if (!aot_compile_op_f32_load(comp_ctx, func_ctx, align, offset))
                    return false;
                break;

            case WASM_OP_F64_LOAD:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                if (!aot_compile_op_f64_load(comp_ctx, func_ctx, align, offset))
                    return false;
                break;

            case WASM_OP_I32_STORE:
                bytes = 4;
                goto op_i32_store;
            case WASM_OP_I32_STORE8:
                bytes = 1;
                goto op_i32_store;
            case WASM_OP_I32_STORE16:
                bytes = 2;
            op_i32_store:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                if (!aot_compile_op_i32_store(comp_ctx, func_ctx, align, offset,
                                              bytes, false))
                    return false;
                break;

            case WASM_OP_I64_STORE:
                bytes = 8;
                goto op_i64_store;
            case WASM_OP_I64_STORE8:
                bytes = 1;
                goto op_i64_store;
            case WASM_OP_I64_STORE16:
                bytes = 2;
                goto op_i64_store;
            case WASM_OP_I64_STORE32:
                bytes = 4;
            op_i64_store:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                if (!aot_compile_op_i64_store(comp_ctx, func_ctx, align, offset,
                                              bytes, false))
                    return false;
                break;

            case WASM_OP_F32_STORE:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                if (!aot_compile_op_f32_store(comp_ctx, func_ctx, align,
                                              offset))
                    return false;
                break;

            case WASM_OP_F64_STORE:
                read_leb_uint32(frame_ip, frame_ip_end, align);
                read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                if (!aot_compile_op_f64_store(comp_ctx, func_ctx, align,
                                              offset))
                    return false;
                break;

            case WASM_OP_MEMORY_SIZE:
                read_leb_uint32(frame_ip, frame_ip_end, mem_idx);
                if (!aot_compile_op_memory_size(comp_ctx, func_ctx))
                    return false;
                (void)mem_idx;
                break;

            case WASM_OP_MEMORY_GROW:
                read_leb_uint32(frame_ip, frame_ip_end, mem_idx);
                if (!aot_compile_op_memory_grow(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I32_CONST:
                read_leb_int32(frame_ip, frame_ip_end, i32_const);
                if (!aot_compile_op_i32_const(comp_ctx, func_ctx, i32_const))
                    return false;
                break;

            case WASM_OP_I64_CONST:
                read_leb_int64(frame_ip, frame_ip_end, i64_const);
                if (!aot_compile_op_i64_const(comp_ctx, func_ctx, i64_const))
                    return false;
                break;

            case WASM_OP_F32_CONST:
                p_f32 = (uint8 *)&f32_const;
                for (i = 0; i < sizeof(float32); i++)
                    *p_f32++ = *frame_ip++;
                if (!aot_compile_op_f32_const(comp_ctx, func_ctx, f32_const))
                    return false;
                break;

            case WASM_OP_F64_CONST:
                p_f64 = (uint8 *)&f64_const;
                for (i = 0; i < sizeof(float64); i++)
                    *p_f64++ = *frame_ip++;
                if (!aot_compile_op_f64_const(comp_ctx, func_ctx, f64_const))
                    return false;
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
                if (!aot_compile_op_i32_compare(
                        comp_ctx, func_ctx, INT_EQZ + opcode - WASM_OP_I32_EQZ))
                    return false;
                break;

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
                if (!aot_compile_op_i64_compare(
                        comp_ctx, func_ctx, INT_EQZ + opcode - WASM_OP_I64_EQZ))
                    return false;
                break;

            case WASM_OP_F32_EQ:
            case WASM_OP_F32_NE:
            case WASM_OP_F32_LT:
            case WASM_OP_F32_GT:
            case WASM_OP_F32_LE:
            case WASM_OP_F32_GE:
                if (!aot_compile_op_f32_compare(
                        comp_ctx, func_ctx, FLOAT_EQ + opcode - WASM_OP_F32_EQ))
                    return false;
                break;

            case WASM_OP_F64_EQ:
            case WASM_OP_F64_NE:
            case WASM_OP_F64_LT:
            case WASM_OP_F64_GT:
            case WASM_OP_F64_LE:
            case WASM_OP_F64_GE:
                if (!aot_compile_op_f64_compare(
                        comp_ctx, func_ctx, FLOAT_EQ + opcode - WASM_OP_F64_EQ))
                    return false;
                break;

            case WASM_OP_I32_CLZ:
                if (!aot_compile_op_i32_clz(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I32_CTZ:
                if (!aot_compile_op_i32_ctz(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I32_POPCNT:
                if (!aot_compile_op_i32_popcnt(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I32_ADD:
            case WASM_OP_I32_SUB:
            case WASM_OP_I32_MUL:
            case WASM_OP_I32_DIV_S:
            case WASM_OP_I32_DIV_U:
            case WASM_OP_I32_REM_S:
            case WASM_OP_I32_REM_U:
                if (!aot_compile_op_i32_arithmetic(
                        comp_ctx, func_ctx, INT_ADD + opcode - WASM_OP_I32_ADD,
                        &frame_ip))
                    return false;
                break;

            case WASM_OP_I32_AND:
            case WASM_OP_I32_OR:
            case WASM_OP_I32_XOR:
                if (!aot_compile_op_i32_bitwise(
                        comp_ctx, func_ctx, INT_SHL + opcode - WASM_OP_I32_AND))
                    return false;
                break;

            case WASM_OP_I32_SHL:
            case WASM_OP_I32_SHR_S:
            case WASM_OP_I32_SHR_U:
            case WASM_OP_I32_ROTL:
            case WASM_OP_I32_ROTR:
                if (!aot_compile_op_i32_shift(
                        comp_ctx, func_ctx, INT_SHL + opcode - WASM_OP_I32_SHL))
                    return false;
                break;

            case WASM_OP_I64_CLZ:
                if (!aot_compile_op_i64_clz(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I64_CTZ:
                if (!aot_compile_op_i64_ctz(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I64_POPCNT:
                if (!aot_compile_op_i64_popcnt(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I64_ADD:
            case WASM_OP_I64_SUB:
            case WASM_OP_I64_MUL:
            case WASM_OP_I64_DIV_S:
            case WASM_OP_I64_DIV_U:
            case WASM_OP_I64_REM_S:
            case WASM_OP_I64_REM_U:
                if (!aot_compile_op_i64_arithmetic(
                        comp_ctx, func_ctx, INT_ADD + opcode - WASM_OP_I64_ADD,
                        &frame_ip))
                    return false;
                break;

            case WASM_OP_I64_AND:
            case WASM_OP_I64_OR:
            case WASM_OP_I64_XOR:
                if (!aot_compile_op_i64_bitwise(
                        comp_ctx, func_ctx, INT_SHL + opcode - WASM_OP_I64_AND))
                    return false;
                break;

            case WASM_OP_I64_SHL:
            case WASM_OP_I64_SHR_S:
            case WASM_OP_I64_SHR_U:
            case WASM_OP_I64_ROTL:
            case WASM_OP_I64_ROTR:
                if (!aot_compile_op_i64_shift(
                        comp_ctx, func_ctx, INT_SHL + opcode - WASM_OP_I64_SHL))
                    return false;
                break;

            case WASM_OP_F32_ABS:
            case WASM_OP_F32_NEG:
            case WASM_OP_F32_CEIL:
            case WASM_OP_F32_FLOOR:
            case WASM_OP_F32_TRUNC:
            case WASM_OP_F32_NEAREST:
            case WASM_OP_F32_SQRT:
                if (!aot_compile_op_f32_math(comp_ctx, func_ctx,
                                             FLOAT_ABS + opcode
                                                 - WASM_OP_F32_ABS))
                    return false;
                break;

            case WASM_OP_F32_ADD:
            case WASM_OP_F32_SUB:
            case WASM_OP_F32_MUL:
            case WASM_OP_F32_DIV:
            case WASM_OP_F32_MIN:
            case WASM_OP_F32_MAX:
                if (!aot_compile_op_f32_arithmetic(comp_ctx, func_ctx,
                                                   FLOAT_ADD + opcode
                                                       - WASM_OP_F32_ADD))
                    return false;
                break;

            case WASM_OP_F32_COPYSIGN:
                if (!aot_compile_op_f32_copysign(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_F64_ABS:
            case WASM_OP_F64_NEG:
            case WASM_OP_F64_CEIL:
            case WASM_OP_F64_FLOOR:
            case WASM_OP_F64_TRUNC:
            case WASM_OP_F64_NEAREST:
            case WASM_OP_F64_SQRT:
                if (!aot_compile_op_f64_math(comp_ctx, func_ctx,
                                             FLOAT_ABS + opcode
                                                 - WASM_OP_F64_ABS))
                    return false;
                break;

            case WASM_OP_F64_ADD:
            case WASM_OP_F64_SUB:
            case WASM_OP_F64_MUL:
            case WASM_OP_F64_DIV:
            case WASM_OP_F64_MIN:
            case WASM_OP_F64_MAX:
                if (!aot_compile_op_f64_arithmetic(comp_ctx, func_ctx,
                                                   FLOAT_ADD + opcode
                                                       - WASM_OP_F64_ADD))
                    return false;
                break;

            case WASM_OP_F64_COPYSIGN:
                if (!aot_compile_op_f64_copysign(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I32_WRAP_I64:
                if (!aot_compile_op_i32_wrap_i64(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I32_TRUNC_S_F32:
            case WASM_OP_I32_TRUNC_U_F32:
                sign = (opcode == WASM_OP_I32_TRUNC_S_F32) ? true : false;
                if (!aot_compile_op_i32_trunc_f32(comp_ctx, func_ctx, sign,
                                                  false))
                    return false;
                break;

            case WASM_OP_I32_TRUNC_S_F64:
            case WASM_OP_I32_TRUNC_U_F64:
                sign = (opcode == WASM_OP_I32_TRUNC_S_F64) ? true : false;
                if (!aot_compile_op_i32_trunc_f64(comp_ctx, func_ctx, sign,
                                                  false))
                    return false;
                break;

            case WASM_OP_I64_EXTEND_S_I32:
            case WASM_OP_I64_EXTEND_U_I32:
                sign = (opcode == WASM_OP_I64_EXTEND_S_I32) ? true : false;
                if (!aot_compile_op_i64_extend_i32(comp_ctx, func_ctx, sign))
                    return false;
                break;

            case WASM_OP_I64_TRUNC_S_F32:
            case WASM_OP_I64_TRUNC_U_F32:
                sign = (opcode == WASM_OP_I64_TRUNC_S_F32) ? true : false;
                if (!aot_compile_op_i64_trunc_f32(comp_ctx, func_ctx, sign,
                                                  false))
                    return false;
                break;

            case WASM_OP_I64_TRUNC_S_F64:
            case WASM_OP_I64_TRUNC_U_F64:
                sign = (opcode == WASM_OP_I64_TRUNC_S_F64) ? true : false;
                if (!aot_compile_op_i64_trunc_f64(comp_ctx, func_ctx, sign,
                                                  false))
                    return false;
                break;

            case WASM_OP_F32_CONVERT_S_I32:
            case WASM_OP_F32_CONVERT_U_I32:
                sign = (opcode == WASM_OP_F32_CONVERT_S_I32) ? true : false;
                if (!aot_compile_op_f32_convert_i32(comp_ctx, func_ctx, sign))
                    return false;
                break;

            case WASM_OP_F32_CONVERT_S_I64:
            case WASM_OP_F32_CONVERT_U_I64:
                sign = (opcode == WASM_OP_F32_CONVERT_S_I64) ? true : false;
                if (!aot_compile_op_f32_convert_i64(comp_ctx, func_ctx, sign))
                    return false;
                break;

            case WASM_OP_F32_DEMOTE_F64:
                if (!aot_compile_op_f32_demote_f64(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_F64_CONVERT_S_I32:
            case WASM_OP_F64_CONVERT_U_I32:
                sign = (opcode == WASM_OP_F64_CONVERT_S_I32) ? true : false;
                if (!aot_compile_op_f64_convert_i32(comp_ctx, func_ctx, sign))
                    return false;
                break;

            case WASM_OP_F64_CONVERT_S_I64:
            case WASM_OP_F64_CONVERT_U_I64:
                sign = (opcode == WASM_OP_F64_CONVERT_S_I64) ? true : false;
                if (!aot_compile_op_f64_convert_i64(comp_ctx, func_ctx, sign))
                    return false;
                break;

            case WASM_OP_F64_PROMOTE_F32:
                if (!aot_compile_op_f64_promote_f32(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I32_REINTERPRET_F32:
                if (!aot_compile_op_i32_reinterpret_f32(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I64_REINTERPRET_F64:
                if (!aot_compile_op_i64_reinterpret_f64(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_F32_REINTERPRET_I32:
                if (!aot_compile_op_f32_reinterpret_i32(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_F64_REINTERPRET_I64:
                if (!aot_compile_op_f64_reinterpret_i64(comp_ctx, func_ctx))
                    return false;
                break;

            case WASM_OP_I32_EXTEND8_S:
                if (!aot_compile_op_i32_extend_i32(comp_ctx, func_ctx, 8))
                    return false;
                break;

            case WASM_OP_I32_EXTEND16_S:
                if (!aot_compile_op_i32_extend_i32(comp_ctx, func_ctx, 16))
                    return false;
                break;

            case WASM_OP_I64_EXTEND8_S:
                if (!aot_compile_op_i64_extend_i64(comp_ctx, func_ctx, 8))
                    return false;
                break;

            case WASM_OP_I64_EXTEND16_S:
                if (!aot_compile_op_i64_extend_i64(comp_ctx, func_ctx, 16))
                    return false;
                break;

            case WASM_OP_I64_EXTEND32_S:
                if (!aot_compile_op_i64_extend_i64(comp_ctx, func_ctx, 32))
                    return false;
                break;

            case WASM_OP_MISC_PREFIX:
            {
                uint32 opcode1;

                read_leb_uint32(frame_ip, frame_ip_end, opcode1);
                /* opcode1 was checked in loader and is no larger than
                   UINT8_MAX */
                opcode = (uint8)opcode1;

#if WASM_ENABLE_BULK_MEMORY != 0
                if (WASM_OP_MEMORY_INIT <= opcode
                    && opcode <= WASM_OP_MEMORY_FILL
                    && !comp_ctx->enable_bulk_memory) {
                    goto unsupport_bulk_memory;
                }
#endif

#if WASM_ENABLE_REF_TYPES != 0 || WASM_ENABLE_GC != 0
                if (WASM_OP_TABLE_INIT <= opcode && opcode <= WASM_OP_TABLE_FILL
                    && (!comp_ctx->enable_ref_types && !comp_ctx->enable_gc)) {
                    goto unsupport_ref_types;
                }
#endif

                switch (opcode) {
                    case WASM_OP_I32_TRUNC_SAT_S_F32:
                    case WASM_OP_I32_TRUNC_SAT_U_F32:
                        sign = (opcode == WASM_OP_I32_TRUNC_SAT_S_F32) ? true
                                                                       : false;
                        if (!aot_compile_op_i32_trunc_f32(comp_ctx, func_ctx,
                                                          sign, true))
                            return false;
                        break;
                    case WASM_OP_I32_TRUNC_SAT_S_F64:
                    case WASM_OP_I32_TRUNC_SAT_U_F64:
                        sign = (opcode == WASM_OP_I32_TRUNC_SAT_S_F64) ? true
                                                                       : false;
                        if (!aot_compile_op_i32_trunc_f64(comp_ctx, func_ctx,
                                                          sign, true))
                            return false;
                        break;
                    case WASM_OP_I64_TRUNC_SAT_S_F32:
                    case WASM_OP_I64_TRUNC_SAT_U_F32:
                        sign = (opcode == WASM_OP_I64_TRUNC_SAT_S_F32) ? true
                                                                       : false;
                        if (!aot_compile_op_i64_trunc_f32(comp_ctx, func_ctx,
                                                          sign, true))
                            return false;
                        break;
                    case WASM_OP_I64_TRUNC_SAT_S_F64:
                    case WASM_OP_I64_TRUNC_SAT_U_F64:
                        sign = (opcode == WASM_OP_I64_TRUNC_SAT_S_F64) ? true
                                                                       : false;
                        if (!aot_compile_op_i64_trunc_f64(comp_ctx, func_ctx,
                                                          sign, true))
                            return false;
                        break;
#if WASM_ENABLE_BULK_MEMORY != 0
                    case WASM_OP_MEMORY_INIT:
                    {
                        uint32 seg_index;
                        read_leb_uint32(frame_ip, frame_ip_end, seg_index);
                        frame_ip++;
                        if (!aot_compile_op_memory_init(comp_ctx, func_ctx,
                                                        seg_index))
                            return false;
                        break;
                    }
                    case WASM_OP_DATA_DROP:
                    {
                        uint32 seg_index;
                        read_leb_uint32(frame_ip, frame_ip_end, seg_index);
                        if (!aot_compile_op_data_drop(comp_ctx, func_ctx,
                                                      seg_index))
                            return false;
                        break;
                    }
                    case WASM_OP_MEMORY_COPY:
                    {
                        frame_ip += 2;
                        if (!aot_compile_op_memory_copy(comp_ctx, func_ctx))
                            return false;
                        break;
                    }
                    case WASM_OP_MEMORY_FILL:
                    {
                        frame_ip++;
                        if (!aot_compile_op_memory_fill(comp_ctx, func_ctx))
                            return false;
                        break;
                    }
#endif /* WASM_ENABLE_BULK_MEMORY */
#if WASM_ENABLE_REF_TYPES != 0 || WASM_ENABLE_GC != 0
                    case WASM_OP_TABLE_INIT:
                    {
                        uint32 tbl_idx, tbl_seg_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_seg_idx);
                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        if (!aot_compile_op_table_init(comp_ctx, func_ctx,
                                                       tbl_idx, tbl_seg_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_ELEM_DROP:
                    {
                        uint32 tbl_seg_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_seg_idx);
                        if (!aot_compile_op_elem_drop(comp_ctx, func_ctx,
                                                      tbl_seg_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_TABLE_COPY:
                    {
                        uint32 src_tbl_idx, dst_tbl_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, dst_tbl_idx);
                        read_leb_uint32(frame_ip, frame_ip_end, src_tbl_idx);
                        if (!aot_compile_op_table_copy(
                                comp_ctx, func_ctx, src_tbl_idx, dst_tbl_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_TABLE_GROW:
                    {
                        uint32 tbl_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        if (!aot_compile_op_table_grow(comp_ctx, func_ctx,
                                                       tbl_idx))
                            return false;
                        break;
                    }

                    case WASM_OP_TABLE_SIZE:
                    {
                        uint32 tbl_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        if (!aot_compile_op_table_size(comp_ctx, func_ctx,
                                                       tbl_idx))
                            return false;
                        break;
                    }
                    case WASM_OP_TABLE_FILL:
                    {
                        uint32 tbl_idx;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        if (!aot_compile_op_table_fill(comp_ctx, func_ctx,
                                                       tbl_idx))
                            return false;
                        break;
                    }
#endif /* WASM_ENABLE_REF_TYPES || WASM_ENABLE_GC */
                    default:
                        aot_set_last_error("unsupported opcode");
                        return false;
                }
                break;
            }

#if WASM_ENABLE_SHARED_MEMORY != 0
            case WASM_OP_ATOMIC_PREFIX:
            {
                uint8 bin_op, op_type;
                uint32 opcode1;

                read_leb_uint32(frame_ip, frame_ip_end, opcode1);
                /* opcode1 was checked in loader and is no larger than
                   UINT8_MAX */
                opcode = (uint8)opcode1;

                if (opcode != WASM_OP_ATOMIC_FENCE) {
                    read_leb_uint32(frame_ip, frame_ip_end, align);
                    read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                }
                switch (opcode) {
                    case WASM_OP_ATOMIC_WAIT32:
                        if (!aot_compile_op_atomic_wait(comp_ctx, func_ctx,
                                                        VALUE_TYPE_I32, align,
                                                        offset, 4))
                            return false;
                        break;
                    case WASM_OP_ATOMIC_WAIT64:
                        if (!aot_compile_op_atomic_wait(comp_ctx, func_ctx,
                                                        VALUE_TYPE_I64, align,
                                                        offset, 8))
                            return false;
                        break;
                    case WASM_OP_ATOMIC_NOTIFY:
                        if (!aot_compiler_op_atomic_notify(
                                comp_ctx, func_ctx, align, offset, bytes))
                            return false;
                        break;
                    case WASM_OP_ATOMIC_FENCE:
                        /* Skip memory index */
                        frame_ip++;
                        if (!aot_compiler_op_atomic_fence(comp_ctx, func_ctx))
                            return false;
                        break;
                    case WASM_OP_ATOMIC_I32_LOAD:
                        bytes = 4;
                        goto op_atomic_i32_load;
                    case WASM_OP_ATOMIC_I32_LOAD8_U:
                        bytes = 1;
                        goto op_atomic_i32_load;
                    case WASM_OP_ATOMIC_I32_LOAD16_U:
                        bytes = 2;
                    op_atomic_i32_load:
                        if (!aot_compile_op_i32_load(comp_ctx, func_ctx, align,
                                                     offset, bytes, sign, true))
                            return false;
                        break;

                    case WASM_OP_ATOMIC_I64_LOAD:
                        bytes = 8;
                        goto op_atomic_i64_load;
                    case WASM_OP_ATOMIC_I64_LOAD8_U:
                        bytes = 1;
                        goto op_atomic_i64_load;
                    case WASM_OP_ATOMIC_I64_LOAD16_U:
                        bytes = 2;
                        goto op_atomic_i64_load;
                    case WASM_OP_ATOMIC_I64_LOAD32_U:
                        bytes = 4;
                    op_atomic_i64_load:
                        if (!aot_compile_op_i64_load(comp_ctx, func_ctx, align,
                                                     offset, bytes, sign, true))
                            return false;
                        break;

                    case WASM_OP_ATOMIC_I32_STORE:
                        bytes = 4;
                        goto op_atomic_i32_store;
                    case WASM_OP_ATOMIC_I32_STORE8:
                        bytes = 1;
                        goto op_atomic_i32_store;
                    case WASM_OP_ATOMIC_I32_STORE16:
                        bytes = 2;
                    op_atomic_i32_store:
                        if (!aot_compile_op_i32_store(comp_ctx, func_ctx, align,
                                                      offset, bytes, true))
                            return false;
                        break;

                    case WASM_OP_ATOMIC_I64_STORE:
                        bytes = 8;
                        goto op_atomic_i64_store;
                    case WASM_OP_ATOMIC_I64_STORE8:
                        bytes = 1;
                        goto op_atomic_i64_store;
                    case WASM_OP_ATOMIC_I64_STORE16:
                        bytes = 2;
                        goto op_atomic_i64_store;
                    case WASM_OP_ATOMIC_I64_STORE32:
                        bytes = 4;
                    op_atomic_i64_store:
                        if (!aot_compile_op_i64_store(comp_ctx, func_ctx, align,
                                                      offset, bytes, true))
                            return false;
                        break;

                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG:
                        bytes = 4;
                        op_type = VALUE_TYPE_I32;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG:
                        bytes = 8;
                        op_type = VALUE_TYPE_I64;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG8_U:
                        bytes = 1;
                        op_type = VALUE_TYPE_I32;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG16_U:
                        bytes = 2;
                        op_type = VALUE_TYPE_I32;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG8_U:
                        bytes = 1;
                        op_type = VALUE_TYPE_I64;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG16_U:
                        bytes = 2;
                        op_type = VALUE_TYPE_I64;
                        goto op_atomic_cmpxchg;
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG32_U:
                        bytes = 4;
                        op_type = VALUE_TYPE_I64;
                    op_atomic_cmpxchg:
                        if (!aot_compile_op_atomic_cmpxchg(comp_ctx, func_ctx,
                                                           op_type, align,
                                                           offset, bytes))
                            return false;
                        break;

                        COMPILE_ATOMIC_RMW(Add, ADD);
                        COMPILE_ATOMIC_RMW(Sub, SUB);
                        COMPILE_ATOMIC_RMW(And, AND);
                        COMPILE_ATOMIC_RMW(Or, OR);
                        COMPILE_ATOMIC_RMW(Xor, XOR);
                        COMPILE_ATOMIC_RMW(Xchg, XCHG);

                    build_atomic_rmw:
                        if (!aot_compile_op_atomic_rmw(comp_ctx, func_ctx,
                                                       bin_op, op_type, align,
                                                       offset, bytes))
                            return false;
                        break;

                    default:
                        aot_set_last_error("unsupported opcode");
                        return false;
                }
                break;
            }
#endif /* end of WASM_ENABLE_SHARED_MEMORY */

#if WASM_ENABLE_SIMD != 0
            case WASM_OP_SIMD_PREFIX:
            {
                uint32 opcode1;

                if (!comp_ctx->enable_simd) {
                    goto unsupport_simd;
                }

                read_leb_uint32(frame_ip, frame_ip_end, opcode1);
                /* opcode1 was checked in loader and is no larger than
                   UINT8_MAX */
                opcode = (uint8)opcode1;

                /* follow the order of enum WASMSimdEXTOpcode in
                   wasm_opcode.h */
                switch (opcode) {
                    /* Memory instruction */
                    case SIMD_v128_load:
                    {
                        read_leb_uint32(frame_ip, frame_ip_end, align);
                        read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                        if (!aot_compile_simd_v128_load(comp_ctx, func_ctx,
                                                        align, offset))
                            return false;
                        break;
                    }

                    case SIMD_v128_load8x8_s:
                    case SIMD_v128_load8x8_u:
                    case SIMD_v128_load16x4_s:
                    case SIMD_v128_load16x4_u:
                    case SIMD_v128_load32x2_s:
                    case SIMD_v128_load32x2_u:
                    {
                        read_leb_uint32(frame_ip, frame_ip_end, align);
                        read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                        if (!aot_compile_simd_load_extend(
                                comp_ctx, func_ctx, opcode, align, offset))
                            return false;
                        break;
                    }

                    case SIMD_v128_load8_splat:
                    case SIMD_v128_load16_splat:
                    case SIMD_v128_load32_splat:
                    case SIMD_v128_load64_splat:
                    {
                        read_leb_uint32(frame_ip, frame_ip_end, align);
                        read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                        if (!aot_compile_simd_load_splat(comp_ctx, func_ctx,
                                                         opcode, align, offset))
                            return false;
                        break;
                    }

                    case SIMD_v128_store:
                    {
                        read_leb_uint32(frame_ip, frame_ip_end, align);
                        read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                        if (!aot_compile_simd_v128_store(comp_ctx, func_ctx,
                                                         align, offset))
                            return false;
                        break;
                    }

                    /* Basic operation */
                    case SIMD_v128_const:
                    {
                        if (!aot_compile_simd_v128_const(comp_ctx, func_ctx,
                                                         frame_ip))
                            return false;
                        frame_ip += 16;
                        break;
                    }

                    case SIMD_v8x16_shuffle:
                    {
                        if (!aot_compile_simd_shuffle(comp_ctx, func_ctx,
                                                      frame_ip))
                            return false;
                        frame_ip += 16;
                        break;
                    }

                    case SIMD_v8x16_swizzle:
                    {
                        if (!aot_compile_simd_swizzle(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    /* Splat operation */
                    case SIMD_i8x16_splat:
                    case SIMD_i16x8_splat:
                    case SIMD_i32x4_splat:
                    case SIMD_i64x2_splat:
                    case SIMD_f32x4_splat:
                    case SIMD_f64x2_splat:
                    {
                        if (!aot_compile_simd_splat(comp_ctx, func_ctx, opcode))
                            return false;
                        break;
                    }

                    /* Lane operation */
                    case SIMD_i8x16_extract_lane_s:
                    case SIMD_i8x16_extract_lane_u:
                    {
                        if (!aot_compile_simd_extract_i8x16(
                                comp_ctx, func_ctx, *frame_ip++,
                                SIMD_i8x16_extract_lane_s == opcode))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_replace_lane:
                    {
                        if (!aot_compile_simd_replace_i8x16(comp_ctx, func_ctx,
                                                            *frame_ip++))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_extract_lane_s:
                    case SIMD_i16x8_extract_lane_u:
                    {
                        if (!aot_compile_simd_extract_i16x8(
                                comp_ctx, func_ctx, *frame_ip++,
                                SIMD_i16x8_extract_lane_s == opcode))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_replace_lane:
                    {
                        if (!aot_compile_simd_replace_i16x8(comp_ctx, func_ctx,
                                                            *frame_ip++))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_extract_lane:
                    {
                        if (!aot_compile_simd_extract_i32x4(comp_ctx, func_ctx,
                                                            *frame_ip++))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_replace_lane:
                    {
                        if (!aot_compile_simd_replace_i32x4(comp_ctx, func_ctx,
                                                            *frame_ip++))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_extract_lane:
                    {
                        if (!aot_compile_simd_extract_i64x2(comp_ctx, func_ctx,
                                                            *frame_ip++))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_replace_lane:
                    {
                        if (!aot_compile_simd_replace_i64x2(comp_ctx, func_ctx,
                                                            *frame_ip++))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_extract_lane:
                    {
                        if (!aot_compile_simd_extract_f32x4(comp_ctx, func_ctx,
                                                            *frame_ip++))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_replace_lane:
                    {
                        if (!aot_compile_simd_replace_f32x4(comp_ctx, func_ctx,
                                                            *frame_ip++))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_extract_lane:
                    {
                        if (!aot_compile_simd_extract_f64x2(comp_ctx, func_ctx,
                                                            *frame_ip++))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_replace_lane:
                    {
                        if (!aot_compile_simd_replace_f64x2(comp_ctx, func_ctx,
                                                            *frame_ip++))
                            return false;
                        break;
                    }

                    /* i8x16 Cmp */
                    case SIMD_i8x16_eq:
                    case SIMD_i8x16_ne:
                    case SIMD_i8x16_lt_s:
                    case SIMD_i8x16_lt_u:
                    case SIMD_i8x16_gt_s:
                    case SIMD_i8x16_gt_u:
                    case SIMD_i8x16_le_s:
                    case SIMD_i8x16_le_u:
                    case SIMD_i8x16_ge_s:
                    case SIMD_i8x16_ge_u:
                    {
                        if (!aot_compile_simd_i8x16_compare(
                                comp_ctx, func_ctx,
                                INT_EQ + opcode - SIMD_i8x16_eq))
                            return false;
                        break;
                    }

                    /* i16x8 Cmp */
                    case SIMD_i16x8_eq:
                    case SIMD_i16x8_ne:
                    case SIMD_i16x8_lt_s:
                    case SIMD_i16x8_lt_u:
                    case SIMD_i16x8_gt_s:
                    case SIMD_i16x8_gt_u:
                    case SIMD_i16x8_le_s:
                    case SIMD_i16x8_le_u:
                    case SIMD_i16x8_ge_s:
                    case SIMD_i16x8_ge_u:
                    {
                        if (!aot_compile_simd_i16x8_compare(
                                comp_ctx, func_ctx,
                                INT_EQ + opcode - SIMD_i16x8_eq))
                            return false;
                        break;
                    }

                    /* i32x4 Cmp */
                    case SIMD_i32x4_eq:
                    case SIMD_i32x4_ne:
                    case SIMD_i32x4_lt_s:
                    case SIMD_i32x4_lt_u:
                    case SIMD_i32x4_gt_s:
                    case SIMD_i32x4_gt_u:
                    case SIMD_i32x4_le_s:
                    case SIMD_i32x4_le_u:
                    case SIMD_i32x4_ge_s:
                    case SIMD_i32x4_ge_u:
                    {
                        if (!aot_compile_simd_i32x4_compare(
                                comp_ctx, func_ctx,
                                INT_EQ + opcode - SIMD_i32x4_eq))
                            return false;
                        break;
                    }

                    /* f32x4 Cmp */
                    case SIMD_f32x4_eq:
                    case SIMD_f32x4_ne:
                    case SIMD_f32x4_lt:
                    case SIMD_f32x4_gt:
                    case SIMD_f32x4_le:
                    case SIMD_f32x4_ge:
                    {
                        if (!aot_compile_simd_f32x4_compare(
                                comp_ctx, func_ctx,
                                FLOAT_EQ + opcode - SIMD_f32x4_eq))
                            return false;
                        break;
                    }

                    /* f64x2 Cmp */
                    case SIMD_f64x2_eq:
                    case SIMD_f64x2_ne:
                    case SIMD_f64x2_lt:
                    case SIMD_f64x2_gt:
                    case SIMD_f64x2_le:
                    case SIMD_f64x2_ge:
                    {
                        if (!aot_compile_simd_f64x2_compare(
                                comp_ctx, func_ctx,
                                FLOAT_EQ + opcode - SIMD_f64x2_eq))
                            return false;
                        break;
                    }

                    /* v128 Op */
                    case SIMD_v128_not:
                    case SIMD_v128_and:
                    case SIMD_v128_andnot:
                    case SIMD_v128_or:
                    case SIMD_v128_xor:
                    case SIMD_v128_bitselect:
                    {
                        if (!aot_compile_simd_v128_bitwise(comp_ctx, func_ctx,
                                                           V128_NOT + opcode
                                                               - SIMD_v128_not))
                            return false;
                        break;
                    }

                    case SIMD_v128_any_true:
                    {
                        if (!aot_compile_simd_v128_any_true(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    /* Load Lane Op */
                    case SIMD_v128_load8_lane:
                    case SIMD_v128_load16_lane:
                    case SIMD_v128_load32_lane:
                    case SIMD_v128_load64_lane:
                    {
                        read_leb_uint32(frame_ip, frame_ip_end, align);
                        read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                        if (!aot_compile_simd_load_lane(comp_ctx, func_ctx,
                                                        opcode, align, offset,
                                                        *frame_ip++))
                            return false;
                        break;
                    }

                    case SIMD_v128_store8_lane:
                    case SIMD_v128_store16_lane:
                    case SIMD_v128_store32_lane:
                    case SIMD_v128_store64_lane:
                    {
                        read_leb_uint32(frame_ip, frame_ip_end, align);
                        read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                        if (!aot_compile_simd_store_lane(comp_ctx, func_ctx,
                                                         opcode, align, offset,
                                                         *frame_ip++))
                            return false;
                        break;
                    }

                    case SIMD_v128_load32_zero:
                    case SIMD_v128_load64_zero:
                    {
                        read_leb_uint32(frame_ip, frame_ip_end, align);
                        read_leb_mem_offset(frame_ip, frame_ip_end, offset);
                        if (!aot_compile_simd_load_zero(comp_ctx, func_ctx,
                                                        opcode, align, offset))
                            return false;
                        break;
                    }

                    /* Float conversion */
                    case SIMD_f32x4_demote_f64x2_zero:
                    {
                        if (!aot_compile_simd_f64x2_demote(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_promote_low_f32x4_zero:
                    {
                        if (!aot_compile_simd_f32x4_promote(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    /* i8x16 Op */
                    case SIMD_i8x16_abs:
                    {
                        if (!aot_compile_simd_i8x16_abs(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_neg:
                    {
                        if (!aot_compile_simd_i8x16_neg(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_popcnt:
                    {
                        if (!aot_compile_simd_i8x16_popcnt(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_all_true:
                    {
                        if (!aot_compile_simd_i8x16_all_true(comp_ctx,
                                                             func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_bitmask:
                    {
                        if (!aot_compile_simd_i8x16_bitmask(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_narrow_i16x8_s:
                    case SIMD_i8x16_narrow_i16x8_u:
                    {
                        if (!aot_compile_simd_i8x16_narrow_i16x8(
                                comp_ctx, func_ctx,
                                (opcode == SIMD_i8x16_narrow_i16x8_s)))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_ceil:
                    {
                        if (!aot_compile_simd_f32x4_ceil(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_floor:
                    {
                        if (!aot_compile_simd_f32x4_floor(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_trunc:
                    {
                        if (!aot_compile_simd_f32x4_trunc(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_nearest:
                    {
                        if (!aot_compile_simd_f32x4_nearest(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_shl:
                    case SIMD_i8x16_shr_s:
                    case SIMD_i8x16_shr_u:
                    {
                        if (!aot_compile_simd_i8x16_shift(comp_ctx, func_ctx,
                                                          INT_SHL + opcode
                                                              - SIMD_i8x16_shl))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_add:
                    {
                        if (!aot_compile_simd_i8x16_arith(comp_ctx, func_ctx,
                                                          V128_ADD))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_add_sat_s:
                    case SIMD_i8x16_add_sat_u:
                    {
                        if (!aot_compile_simd_i8x16_saturate(
                                comp_ctx, func_ctx, V128_ADD,
                                opcode == SIMD_i8x16_add_sat_s))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_sub:
                    {
                        if (!aot_compile_simd_i8x16_arith(comp_ctx, func_ctx,
                                                          V128_SUB))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_sub_sat_s:
                    case SIMD_i8x16_sub_sat_u:
                    {
                        if (!aot_compile_simd_i8x16_saturate(
                                comp_ctx, func_ctx, V128_SUB,
                                opcode == SIMD_i8x16_sub_sat_s))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_ceil:
                    {
                        if (!aot_compile_simd_f64x2_ceil(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_floor:
                    {
                        if (!aot_compile_simd_f64x2_floor(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_min_s:
                    case SIMD_i8x16_min_u:
                    {
                        if (!aot_compile_simd_i8x16_cmp(
                                comp_ctx, func_ctx, V128_MIN,
                                opcode == SIMD_i8x16_min_s))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_max_s:
                    case SIMD_i8x16_max_u:
                    {
                        if (!aot_compile_simd_i8x16_cmp(
                                comp_ctx, func_ctx, V128_MAX,
                                opcode == SIMD_i8x16_max_s))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_trunc:
                    {
                        if (!aot_compile_simd_f64x2_trunc(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i8x16_avgr_u:
                    {
                        if (!aot_compile_simd_i8x16_avgr_u(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_extadd_pairwise_i8x16_s:
                    case SIMD_i16x8_extadd_pairwise_i8x16_u:
                    {
                        if (!aot_compile_simd_i16x8_extadd_pairwise_i8x16(
                                comp_ctx, func_ctx,
                                SIMD_i16x8_extadd_pairwise_i8x16_s == opcode))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_extadd_pairwise_i16x8_s:
                    case SIMD_i32x4_extadd_pairwise_i16x8_u:
                    {
                        if (!aot_compile_simd_i32x4_extadd_pairwise_i16x8(
                                comp_ctx, func_ctx,
                                SIMD_i32x4_extadd_pairwise_i16x8_s == opcode))
                            return false;
                        break;
                    }

                    /* i16x8 Op */
                    case SIMD_i16x8_abs:
                    {
                        if (!aot_compile_simd_i16x8_abs(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_neg:
                    {
                        if (!aot_compile_simd_i16x8_neg(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_q15mulr_sat_s:
                    {
                        if (!aot_compile_simd_i16x8_q15mulr_sat(comp_ctx,
                                                                func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_all_true:
                    {
                        if (!aot_compile_simd_i16x8_all_true(comp_ctx,
                                                             func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_bitmask:
                    {
                        if (!aot_compile_simd_i16x8_bitmask(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_narrow_i32x4_s:
                    case SIMD_i16x8_narrow_i32x4_u:
                    {
                        if (!aot_compile_simd_i16x8_narrow_i32x4(
                                comp_ctx, func_ctx,
                                SIMD_i16x8_narrow_i32x4_s == opcode))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_extend_low_i8x16_s:
                    case SIMD_i16x8_extend_high_i8x16_s:
                    {
                        if (!aot_compile_simd_i16x8_extend_i8x16(
                                comp_ctx, func_ctx,
                                SIMD_i16x8_extend_low_i8x16_s == opcode, true))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_extend_low_i8x16_u:
                    case SIMD_i16x8_extend_high_i8x16_u:
                    {
                        if (!aot_compile_simd_i16x8_extend_i8x16(
                                comp_ctx, func_ctx,
                                SIMD_i16x8_extend_low_i8x16_u == opcode, false))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_shl:
                    case SIMD_i16x8_shr_s:
                    case SIMD_i16x8_shr_u:
                    {
                        if (!aot_compile_simd_i16x8_shift(comp_ctx, func_ctx,
                                                          INT_SHL + opcode
                                                              - SIMD_i16x8_shl))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_add:
                    {
                        if (!aot_compile_simd_i16x8_arith(comp_ctx, func_ctx,
                                                          V128_ADD))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_add_sat_s:
                    case SIMD_i16x8_add_sat_u:
                    {
                        if (!aot_compile_simd_i16x8_saturate(
                                comp_ctx, func_ctx, V128_ADD,
                                opcode == SIMD_i16x8_add_sat_s ? true : false))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_sub:
                    {
                        if (!aot_compile_simd_i16x8_arith(comp_ctx, func_ctx,
                                                          V128_SUB))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_sub_sat_s:
                    case SIMD_i16x8_sub_sat_u:
                    {
                        if (!aot_compile_simd_i16x8_saturate(
                                comp_ctx, func_ctx, V128_SUB,
                                opcode == SIMD_i16x8_sub_sat_s ? true : false))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_nearest:
                    {
                        if (!aot_compile_simd_f64x2_nearest(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_mul:
                    {
                        if (!aot_compile_simd_i16x8_arith(comp_ctx, func_ctx,
                                                          V128_MUL))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_min_s:
                    case SIMD_i16x8_min_u:
                    {
                        if (!aot_compile_simd_i16x8_cmp(
                                comp_ctx, func_ctx, V128_MIN,
                                opcode == SIMD_i16x8_min_s))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_max_s:
                    case SIMD_i16x8_max_u:
                    {
                        if (!aot_compile_simd_i16x8_cmp(
                                comp_ctx, func_ctx, V128_MAX,
                                opcode == SIMD_i16x8_max_s))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_avgr_u:
                    {
                        if (!aot_compile_simd_i16x8_avgr_u(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_extmul_low_i8x16_s:
                    case SIMD_i16x8_extmul_high_i8x16_s:
                    {
                        if (!(aot_compile_simd_i16x8_extmul_i8x16(
                                comp_ctx, func_ctx,
                                SIMD_i16x8_extmul_low_i8x16_s == opcode, true)))
                            return false;
                        break;
                    }

                    case SIMD_i16x8_extmul_low_i8x16_u:
                    case SIMD_i16x8_extmul_high_i8x16_u:
                    {
                        if (!(aot_compile_simd_i16x8_extmul_i8x16(
                                comp_ctx, func_ctx,
                                SIMD_i16x8_extmul_low_i8x16_u == opcode,
                                false)))
                            return false;
                        break;
                    }

                    /* i32x4 Op */
                    case SIMD_i32x4_abs:
                    {
                        if (!aot_compile_simd_i32x4_abs(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_neg:
                    {
                        if (!aot_compile_simd_i32x4_neg(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_all_true:
                    {
                        if (!aot_compile_simd_i32x4_all_true(comp_ctx,
                                                             func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_bitmask:
                    {
                        if (!aot_compile_simd_i32x4_bitmask(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_extend_low_i16x8_s:
                    case SIMD_i32x4_extend_high_i16x8_s:
                    {
                        if (!aot_compile_simd_i32x4_extend_i16x8(
                                comp_ctx, func_ctx,
                                SIMD_i32x4_extend_low_i16x8_s == opcode, true))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_extend_low_i16x8_u:
                    case SIMD_i32x4_extend_high_i16x8_u:
                    {
                        if (!aot_compile_simd_i32x4_extend_i16x8(
                                comp_ctx, func_ctx,
                                SIMD_i32x4_extend_low_i16x8_u == opcode, false))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_shl:
                    case SIMD_i32x4_shr_s:
                    case SIMD_i32x4_shr_u:
                    {
                        if (!aot_compile_simd_i32x4_shift(comp_ctx, func_ctx,
                                                          INT_SHL + opcode
                                                              - SIMD_i32x4_shl))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_add:
                    {
                        if (!aot_compile_simd_i32x4_arith(comp_ctx, func_ctx,
                                                          V128_ADD))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_sub:
                    {
                        if (!aot_compile_simd_i32x4_arith(comp_ctx, func_ctx,
                                                          V128_SUB))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_mul:
                    {
                        if (!aot_compile_simd_i32x4_arith(comp_ctx, func_ctx,
                                                          V128_MUL))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_min_s:
                    case SIMD_i32x4_min_u:
                    {
                        if (!aot_compile_simd_i32x4_cmp(
                                comp_ctx, func_ctx, V128_MIN,
                                SIMD_i32x4_min_s == opcode))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_max_s:
                    case SIMD_i32x4_max_u:
                    {
                        if (!aot_compile_simd_i32x4_cmp(
                                comp_ctx, func_ctx, V128_MAX,
                                SIMD_i32x4_max_s == opcode))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_dot_i16x8_s:
                    {
                        if (!aot_compile_simd_i32x4_dot_i16x8(comp_ctx,
                                                              func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_extmul_low_i16x8_s:
                    case SIMD_i32x4_extmul_high_i16x8_s:
                    {
                        if (!aot_compile_simd_i32x4_extmul_i16x8(
                                comp_ctx, func_ctx,
                                SIMD_i32x4_extmul_low_i16x8_s == opcode, true))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_extmul_low_i16x8_u:
                    case SIMD_i32x4_extmul_high_i16x8_u:
                    {
                        if (!aot_compile_simd_i32x4_extmul_i16x8(
                                comp_ctx, func_ctx,
                                SIMD_i32x4_extmul_low_i16x8_u == opcode, false))
                            return false;
                        break;
                    }

                    /* i64x2 Op */
                    case SIMD_i64x2_abs:
                    {
                        if (!aot_compile_simd_i64x2_abs(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_neg:
                    {
                        if (!aot_compile_simd_i64x2_neg(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_all_true:
                    {
                        if (!aot_compile_simd_i64x2_all_true(comp_ctx,
                                                             func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_bitmask:
                    {
                        if (!aot_compile_simd_i64x2_bitmask(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_extend_low_i32x4_s:
                    case SIMD_i64x2_extend_high_i32x4_s:
                    {
                        if (!aot_compile_simd_i64x2_extend_i32x4(
                                comp_ctx, func_ctx,
                                SIMD_i64x2_extend_low_i32x4_s == opcode, true))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_extend_low_i32x4_u:
                    case SIMD_i64x2_extend_high_i32x4_u:
                    {
                        if (!aot_compile_simd_i64x2_extend_i32x4(
                                comp_ctx, func_ctx,
                                SIMD_i64x2_extend_low_i32x4_u == opcode, false))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_shl:
                    case SIMD_i64x2_shr_s:
                    case SIMD_i64x2_shr_u:
                    {
                        if (!aot_compile_simd_i64x2_shift(comp_ctx, func_ctx,
                                                          INT_SHL + opcode
                                                              - SIMD_i64x2_shl))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_add:
                    {
                        if (!aot_compile_simd_i64x2_arith(comp_ctx, func_ctx,
                                                          V128_ADD))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_sub:
                    {
                        if (!aot_compile_simd_i64x2_arith(comp_ctx, func_ctx,
                                                          V128_SUB))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_mul:
                    {
                        if (!aot_compile_simd_i64x2_arith(comp_ctx, func_ctx,
                                                          V128_MUL))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_eq:
                    case SIMD_i64x2_ne:
                    case SIMD_i64x2_lt_s:
                    case SIMD_i64x2_gt_s:
                    case SIMD_i64x2_le_s:
                    case SIMD_i64x2_ge_s:
                    {
                        IntCond icond[] = { INT_EQ,   INT_NE,   INT_LT_S,
                                            INT_GT_S, INT_LE_S, INT_GE_S };
                        if (!aot_compile_simd_i64x2_compare(
                                comp_ctx, func_ctx,
                                icond[opcode - SIMD_i64x2_eq]))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_extmul_low_i32x4_s:
                    case SIMD_i64x2_extmul_high_i32x4_s:
                    {
                        if (!aot_compile_simd_i64x2_extmul_i32x4(
                                comp_ctx, func_ctx,
                                SIMD_i64x2_extmul_low_i32x4_s == opcode, true))
                            return false;
                        break;
                    }

                    case SIMD_i64x2_extmul_low_i32x4_u:
                    case SIMD_i64x2_extmul_high_i32x4_u:
                    {
                        if (!aot_compile_simd_i64x2_extmul_i32x4(
                                comp_ctx, func_ctx,
                                SIMD_i64x2_extmul_low_i32x4_u == opcode, false))
                            return false;
                        break;
                    }

                    /* f32x4 Op */
                    case SIMD_f32x4_abs:
                    {
                        if (!aot_compile_simd_f32x4_abs(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_neg:
                    {
                        if (!aot_compile_simd_f32x4_neg(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_sqrt:
                    {
                        if (!aot_compile_simd_f32x4_sqrt(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_add:
                    case SIMD_f32x4_sub:
                    case SIMD_f32x4_mul:
                    case SIMD_f32x4_div:
                    {
                        if (!aot_compile_simd_f32x4_arith(comp_ctx, func_ctx,
                                                          FLOAT_ADD + opcode
                                                              - SIMD_f32x4_add))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_min:
                    case SIMD_f32x4_max:
                    {
                        if (!aot_compile_simd_f32x4_min_max(
                                comp_ctx, func_ctx, SIMD_f32x4_min == opcode))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_pmin:
                    case SIMD_f32x4_pmax:
                    {
                        if (!aot_compile_simd_f32x4_pmin_pmax(
                                comp_ctx, func_ctx, SIMD_f32x4_pmin == opcode))
                            return false;
                        break;
                    }

                        /* f64x2 Op */

                    case SIMD_f64x2_abs:
                    {
                        if (!aot_compile_simd_f64x2_abs(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_neg:
                    {
                        if (!aot_compile_simd_f64x2_neg(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_sqrt:
                    {
                        if (!aot_compile_simd_f64x2_sqrt(comp_ctx, func_ctx))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_add:
                    case SIMD_f64x2_sub:
                    case SIMD_f64x2_mul:
                    case SIMD_f64x2_div:
                    {
                        if (!aot_compile_simd_f64x2_arith(comp_ctx, func_ctx,
                                                          FLOAT_ADD + opcode
                                                              - SIMD_f64x2_add))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_min:
                    case SIMD_f64x2_max:
                    {
                        if (!aot_compile_simd_f64x2_min_max(
                                comp_ctx, func_ctx, SIMD_f64x2_min == opcode))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_pmin:
                    case SIMD_f64x2_pmax:
                    {
                        if (!aot_compile_simd_f64x2_pmin_pmax(
                                comp_ctx, func_ctx, SIMD_f64x2_pmin == opcode))
                            return false;
                        break;
                    }

                    /* Conversion Op */
                    case SIMD_i32x4_trunc_sat_f32x4_s:
                    case SIMD_i32x4_trunc_sat_f32x4_u:
                    {
                        if (!aot_compile_simd_i32x4_trunc_sat_f32x4(
                                comp_ctx, func_ctx,
                                SIMD_i32x4_trunc_sat_f32x4_s == opcode))
                            return false;
                        break;
                    }

                    case SIMD_f32x4_convert_i32x4_s:
                    case SIMD_f32x4_convert_i32x4_u:
                    {
                        if (!aot_compile_simd_f32x4_convert_i32x4(
                                comp_ctx, func_ctx,
                                SIMD_f32x4_convert_i32x4_s == opcode))
                            return false;
                        break;
                    }

                    case SIMD_i32x4_trunc_sat_f64x2_s_zero:
                    case SIMD_i32x4_trunc_sat_f64x2_u_zero:
                    {
                        if (!aot_compile_simd_i32x4_trunc_sat_f64x2(
                                comp_ctx, func_ctx,
                                SIMD_i32x4_trunc_sat_f64x2_s_zero == opcode))
                            return false;
                        break;
                    }

                    case SIMD_f64x2_convert_low_i32x4_s:
                    case SIMD_f64x2_convert_low_i32x4_u:
                    {
                        if (!aot_compile_simd_f64x2_convert_i32x4(
                                comp_ctx, func_ctx,
                                SIMD_f64x2_convert_low_i32x4_s == opcode))
                            return false;
                        break;
                    }

                    default:
                        aot_set_last_error("unsupported SIMD opcode");
                        return false;
                }
                break;
            }
#endif /* end of WASM_ENABLE_SIMD */

            default:
                aot_set_last_error("unsupported opcode");
                return false;
        }
    }

    /* Move func_return block to the bottom */
    if (func_ctx->func_return_block) {
        LLVMBasicBlockRef last_block = LLVMGetLastBasicBlock(func_ctx->func);
        if (last_block != func_ctx->func_return_block)
            LLVMMoveBasicBlockAfter(func_ctx->func_return_block, last_block);
    }

    /* Move got_exception block to the bottom */
    if (func_ctx->got_exception_block) {
        LLVMBasicBlockRef last_block = LLVMGetLastBasicBlock(func_ctx->func);
        if (last_block != func_ctx->got_exception_block)
            LLVMMoveBasicBlockAfter(func_ctx->got_exception_block, last_block);
    }
    return true;

#if WASM_ENABLE_SIMD != 0
unsupport_simd:
    aot_set_last_error("SIMD instruction was found, "
                       "try removing --disable-simd option");
    return false;
#endif

#if WASM_ENABLE_REF_TYPES != 0 || WASM_ENABLE_GC != 0
unsupport_ref_types:
    aot_set_last_error("reference type instruction was found, "
                       "try removing --disable-ref-types option "
                       "or adding --enable-gc option");
    return false;
#endif

#if WASM_ENABLE_GC != 0
unsupport_gc:
    aot_set_last_error("GC instruction was found, "
                       "try adding --enable-gc option");
    return false;
#endif

#if WASM_ENABLE_REF_TYPES != 0 || WASM_ENABLE_GC != 0
unsupport_gc_and_ref_types:
    aot_set_last_error(
        "reference type or gc instruction was found, try removing "
        "--disable-ref-types option or adding --enable-gc option");
    return false;
#endif

#if WASM_ENABLE_BULK_MEMORY != 0
unsupport_bulk_memory:
    aot_set_last_error("bulk memory instruction was found, "
                       "try removing --disable-bulk-memory option");
    return false;
#endif

fail:
    return false;
}

static bool
verify_module(AOTCompContext *comp_ctx)
{
    char *msg = NULL;
    bool ret;

    ret = LLVMVerifyModule(comp_ctx->module, LLVMPrintMessageAction, &msg);
    if (!ret && msg) {
        if (msg[0] != '\0') {
            aot_set_last_error(msg);
            LLVMDisposeMessage(msg);
            return false;
        }
        LLVMDisposeMessage(msg);
    }

    return true;
}

bool
aot_compile_wasm(AOTCompContext *comp_ctx)
{
    uint32 i;

    if (!aot_validate_wasm(comp_ctx)) {
        return false;
    }

    bh_print_time("Begin to compile WASM bytecode to LLVM IR");
    for (i = 0; i < comp_ctx->func_ctx_count; i++) {
        if (!aot_compile_func(comp_ctx, i)) {
            return false;
        }
    }

#if WASM_ENABLE_DEBUG_AOT != 0
    LLVMDIBuilderFinalize(comp_ctx->debug_builder);
#endif

    /* Disable LLVM module verification for jit mode to speedup
       the compilation process */
    if (!comp_ctx->is_jit_mode) {
        bh_print_time("Begin to verify LLVM module");
        if (!verify_module(comp_ctx)) {
            return false;
        }
    }

    /* Run IR optimization before feeding in ORCJIT and AOT codegen */
    if (comp_ctx->optimize) {
        /* Run passes for AOT/JIT mode.
           TODO: Apply these passes in the do_ir_transform callback of
           TransformLayer when compiling each jit function, so as to
           speedup the launch process. Now there are two issues in the
           JIT: one is memory leak in do_ir_transform, the other is
           possible core dump. */
        bh_print_time("Begin to run llvm optimization passes");
        aot_apply_llvm_new_pass_manager(comp_ctx, comp_ctx->module);
        bh_print_time("Finish llvm optimization passes");
    }

#ifdef DUMP_MODULE
    LLVMDumpModule(comp_ctx->module);
    os_printf("\n");
#endif

    if (comp_ctx->is_jit_mode) {
        LLVMErrorRef err;
        LLVMOrcJITDylibRef orc_main_dylib;
        LLVMOrcThreadSafeModuleRef orc_thread_safe_module;

        orc_main_dylib = LLVMOrcLLLazyJITGetMainJITDylib(comp_ctx->orc_jit);
        if (!orc_main_dylib) {
            aot_set_last_error(
                "failed to get orc orc_jit main dynamic library");
            return false;
        }

        orc_thread_safe_module = LLVMOrcCreateNewThreadSafeModule(
            comp_ctx->module, comp_ctx->orc_thread_safe_context);
        if (!orc_thread_safe_module) {
            aot_set_last_error("failed to create thread safe module");
            return false;
        }

        if ((err = LLVMOrcLLLazyJITAddLLVMIRModule(
                 comp_ctx->orc_jit, orc_main_dylib, orc_thread_safe_module))) {
            /* If adding the ThreadSafeModule fails then we need to clean it up
               by ourselves, otherwise the orc orc_jit will manage the memory.
             */
            LLVMOrcDisposeThreadSafeModule(orc_thread_safe_module);
            aot_handle_llvm_errmsg("failed to addIRModule", err);
            return false;
        }

        if (comp_ctx->stack_sizes != NULL) {
            LLVMOrcJITTargetAddress addr;
            if ((err = LLVMOrcLLLazyJITLookup(comp_ctx->orc_jit, &addr,
                                              aot_stack_sizes_alias_name))) {
                aot_handle_llvm_errmsg("failed to look up stack_sizes", err);
                return false;
            }
            comp_ctx->jit_stack_sizes = (uint32 *)addr;
        }
    }

    return true;
}

char *
aot_generate_tempfile_name(const char *prefix, const char *extension,
                           char *buffer, uint32 len)
{
    int name_len;

    name_len = snprintf(buffer, len, "%s-XXXXXX", prefix);

    if (!bh_mkstemp(buffer, name_len + 1)) {
        aot_set_last_error("make temp file failed.");
        return NULL;
    }

    /* Check if buffer length is enough */
    /* name_len + '.' + extension + '\0' */
    if (name_len + 1 + strlen(extension) + 1 > len) {
        aot_set_last_error("temp file name too long.");
        return NULL;
    }

    snprintf(buffer + name_len, len - name_len, ".%s", extension);
    return buffer;
}

bool
aot_emit_llvm_file(AOTCompContext *comp_ctx, const char *file_name)
{
    char *err = NULL;

    bh_print_time("Begin to emit LLVM IR file");

    if (LLVMPrintModuleToFile(comp_ctx->module, file_name, &err) != 0) {
        if (err) {
            LLVMDisposeMessage(err);
            err = NULL;
        }
        aot_set_last_error("emit llvm ir to file failed.");
        return false;
    }

    return true;
}

static bool
aot_move_file(const char *dest, const char *src)
{
    FILE *dfp = fopen(dest, "w");
    FILE *sfp = fopen(src, "r");
    size_t rsz;
    char buf[128];
    bool success = false;

    if (dfp == NULL || sfp == NULL) {
        LOG_DEBUG("open error %s %s", dest, src);
        goto fail;
    }
    do {
        rsz = fread(buf, 1, sizeof(buf), sfp);
        if (rsz > 0) {
            size_t wsz = fwrite(buf, 1, rsz, dfp);
            if (wsz < rsz) {
                LOG_DEBUG("write error");
                goto fail;
            }
        }
        if (rsz < sizeof(buf)) {
            if (ferror(sfp)) {
                LOG_DEBUG("read error");
                goto fail;
            }
        }
    } while (rsz > 0);
    success = true;
fail:
    if (dfp != NULL) {
        if (fclose(dfp)) {
            LOG_DEBUG("close error");
            success = false;
        }
        if (!success) {
            (void)unlink(dest);
        }
    }
    if (sfp != NULL) {
        (void)fclose(sfp);
    }
    if (success) {
        (void)unlink(src);
    }
    return success;
}

bool
aot_emit_object_file(AOTCompContext *comp_ctx, char *file_name)
{
    char *err = NULL;
    LLVMCodeGenFileType file_type = LLVMObjectFile;
    LLVMTargetRef target = LLVMGetTargetMachineTarget(comp_ctx->target_machine);

    bh_print_time("Begin to emit object file");

    if (comp_ctx->external_llc_compiler || comp_ctx->external_asm_compiler) {
        char cmd[1024];
        int ret;

        if (comp_ctx->external_llc_compiler) {
            const char *stack_usage_flag = "";
            char bc_file_name[64];
            char su_file_name[65]; /* See the comment below */

            if (comp_ctx->stack_usage_file != NULL) {
                /*
                 * Note: we know the caller uses 64 byte buffer for
                 * file_name. It will get 1 byte longer because we
                 * replace ".o" with ".su".
                 */
                size_t len = strlen(file_name);
                bh_assert(len + 1 <= sizeof(su_file_name));
                bh_assert(len > 3);
                bh_assert(file_name[len - 2] == '.');
                bh_assert(file_name[len - 1] == 'o');
                snprintf(su_file_name, sizeof(su_file_name), "%.*s.su",
                         (int)(len - 2), file_name);
                stack_usage_flag = " -fstack-usage";
            }

            if (!aot_generate_tempfile_name("wamrc-bc", "bc", bc_file_name,
                                            sizeof(bc_file_name))) {
                return false;
            }

            if (LLVMWriteBitcodeToFile(comp_ctx->module, bc_file_name) != 0) {
                aot_set_last_error("emit llvm bitcode file failed.");
                return false;
            }

            snprintf(cmd, sizeof(cmd), "%s%s %s -o %s %s",
                     comp_ctx->external_llc_compiler, stack_usage_flag,
                     comp_ctx->llc_compiler_flags ? comp_ctx->llc_compiler_flags
                                                  : "-O3 -c",
                     file_name, bc_file_name);
            LOG_VERBOSE("invoking external LLC compiler:\n\t%s", cmd);

            ret = bh_system(cmd);
            /* remove temp bitcode file */
            unlink(bc_file_name);

            if (ret != 0) {
                aot_set_last_error("failed to compile LLVM bitcode to obj file "
                                   "with external LLC compiler.");
                return false;
            }
            if (comp_ctx->stack_usage_file != NULL) {
                /*
                 * move the temporary .su file to the specified location.
                 *
                 * Note: the former is automatically inferred from the output
                 * filename (file_name here) by clang.
                 *
                 * Note: the latter might be user-specified.
                 * (wamrc --stack-usage=<file>)
                 */
                if (!aot_move_file(comp_ctx->stack_usage_file, su_file_name)) {
                    aot_set_last_error("failed to move su file.");
                    (void)unlink(su_file_name);
                    return false;
                }
            }
        }
        else if (comp_ctx->external_asm_compiler) {
            char asm_file_name[64];

            if (!aot_generate_tempfile_name("wamrc-asm", "s", asm_file_name,
                                            sizeof(asm_file_name))) {
                return false;
            }

            if (LLVMTargetMachineEmitToFile(comp_ctx->target_machine,
                                            comp_ctx->module, asm_file_name,
                                            LLVMAssemblyFile, &err)
                != 0) {
                if (err) {
                    LLVMDisposeMessage(err);
                    err = NULL;
                }
                aot_set_last_error("emit elf to assembly file failed.");
                return false;
            }

            snprintf(cmd, sizeof(cmd), "%s %s -o %s %s",
                     comp_ctx->external_asm_compiler,
                     comp_ctx->asm_compiler_flags ? comp_ctx->asm_compiler_flags
                                                  : "-O3 -c",
                     file_name, asm_file_name);
            LOG_VERBOSE("invoking external ASM compiler:\n\t%s", cmd);

            ret = bh_system(cmd);
            /* remove temp assembly file */
            unlink(asm_file_name);

            if (ret != 0) {
                aot_set_last_error("failed to compile Assembly file to obj "
                                   "file with external ASM compiler.");
                return false;
            }
        }

        return true;
    }

    if (!strncmp(LLVMGetTargetName(target), "arc", 3))
        /* Emit to assembly file instead for arc target
           as it cannot emit to object file */
        file_type = LLVMAssemblyFile;

    if (LLVMTargetMachineEmitToFile(comp_ctx->target_machine, comp_ctx->module,
                                    file_name, file_type, &err)
        != 0) {
        if (err) {
            LLVMDisposeMessage(err);
            err = NULL;
        }
        aot_set_last_error("emit elf to object file failed.");
        return false;
    }

    return true;
}
