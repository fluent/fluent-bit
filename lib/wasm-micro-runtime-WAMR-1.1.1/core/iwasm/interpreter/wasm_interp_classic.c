/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "wasm_interp.h"
#include "bh_log.h"
#include "wasm_runtime.h"
#include "wasm_opcode.h"
#include "wasm_loader.h"
#include "../common/wasm_exec_env.h"
#if WASM_ENABLE_SHARED_MEMORY != 0
#include "../common/wasm_shared_memory.h"
#endif
#if WASM_ENABLE_THREAD_MGR != 0 && WASM_ENABLE_DEBUG_INTERP != 0
#include "../libraries/thread-mgr/thread_manager.h"
#include "../libraries/debug-engine/debug_engine.h"
#endif
#if WASM_ENABLE_FAST_JIT != 0
#include "../fast-jit/jit_compiler.h"
#endif

typedef int32 CellType_I32;
typedef int64 CellType_I64;
typedef float32 CellType_F32;
typedef float64 CellType_F64;

#define BR_TABLE_TMP_BUF_LEN 32

#if !defined(OS_ENABLE_HW_BOUND_CHECK) \
    || WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0
#define CHECK_MEMORY_OVERFLOW(bytes)                            \
    do {                                                        \
        uint64 offset1 = (uint64)offset + (uint64)addr;         \
        if (offset1 + bytes <= (uint64)linear_mem_size)         \
            /* If offset1 is in valid range, maddr must also    \
               be in valid range, no need to check it again. */ \
            maddr = memory->memory_data + offset1;              \
        else                                                    \
            goto out_of_bounds;                                 \
    } while (0)

#define CHECK_BULK_MEMORY_OVERFLOW(start, bytes, maddr) \
    do {                                                \
        uint64 offset1 = (uint32)(start);               \
        if (offset1 + bytes <= (uint64)linear_mem_size) \
            /* App heap space is not valid space for    \
             bulk memory operation */                   \
            maddr = memory->memory_data + offset1;      \
        else                                            \
            goto out_of_bounds;                         \
    } while (0)
#else
#define CHECK_MEMORY_OVERFLOW(bytes)                    \
    do {                                                \
        uint64 offset1 = (uint64)offset + (uint64)addr; \
        maddr = memory->memory_data + offset1;          \
    } while (0)

#define CHECK_BULK_MEMORY_OVERFLOW(start, bytes, maddr) \
    do {                                                \
        maddr = memory->memory_data + (uint32)(start);  \
    } while (0)
#endif /* !defined(OS_ENABLE_HW_BOUND_CHECK) \
          || WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0 */

#define CHECK_ATOMIC_MEMORY_ACCESS()                                 \
    do {                                                             \
        if (((uintptr_t)maddr & (((uintptr_t)1 << align) - 1)) != 0) \
            goto unaligned_atomic;                                   \
    } while (0)

static inline uint32
rotl32(uint32 n, uint32 c)
{
    const uint32 mask = (31);
    c = c % 32;
    c &= mask;
    return (n << c) | (n >> ((0 - c) & mask));
}

static inline uint32
rotr32(uint32 n, uint32 c)
{
    const uint32 mask = (31);
    c = c % 32;
    c &= mask;
    return (n >> c) | (n << ((0 - c) & mask));
}

static inline uint64
rotl64(uint64 n, uint64 c)
{
    const uint64 mask = (63);
    c = c % 64;
    c &= mask;
    return (n << c) | (n >> ((0 - c) & mask));
}

static inline uint64
rotr64(uint64 n, uint64 c)
{
    const uint64 mask = (63);
    c = c % 64;
    c &= mask;
    return (n >> c) | (n << ((0 - c) & mask));
}

static inline double
wa_fmax(double a, double b)
{
    double c = fmax(a, b);
    if (c == 0 && a == b)
        return signbit(a) ? b : a;
    return c;
}

static inline double
wa_fmin(double a, double b)
{
    double c = fmin(a, b);
    if (c == 0 && a == b)
        return signbit(a) ? a : b;
    return c;
}

static inline uint32
clz32(uint32 type)
{
    uint32 num = 0;
    if (type == 0)
        return 32;
    while (!(type & 0x80000000)) {
        num++;
        type <<= 1;
    }
    return num;
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

static inline uint32
ctz32(uint32 type)
{
    uint32 num = 0;
    if (type == 0)
        return 32;
    while (!(type & 1)) {
        num++;
        type >>= 1;
    }
    return num;
}

static inline uint32
ctz64(uint64 type)
{
    uint32 num = 0;
    if (type == 0)
        return 64;
    while (!(type & 1)) {
        num++;
        type >>= 1;
    }
    return num;
}

static inline uint32
popcount32(uint32 u)
{
    uint32 ret = 0;
    while (u) {
        u = (u & (u - 1));
        ret++;
    }
    return ret;
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

static float
local_copysignf(float x, float y)
{
    union {
        float f;
        uint32_t i;
    } ux = { x }, uy = { y };
    ux.i &= 0x7fffffff;
    ux.i |= uy.i & 0x80000000;
    return ux.f;
}

static double
local_copysign(double x, double y)
{
    union {
        double f;
        uint64_t i;
    } ux = { x }, uy = { y };
    ux.i &= -1ULL / 2;
    ux.i |= uy.i & 1ULL << 63;
    return ux.f;
}

static uint64
read_leb(const uint8 *buf, uint32 *p_offset, uint32 maxbits, bool sign)
{
    uint64 result = 0, byte;
    uint32 offset = *p_offset;
    uint32 shift = 0;

    while (true) {
        byte = buf[offset++];
        result |= ((byte & 0x7f) << shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            break;
        }
    }
    if (sign && (shift < maxbits) && (byte & 0x40)) {
        /* Sign extend */
        result |= (~((uint64)0)) << shift;
    }
    *p_offset = offset;
    return result;
}

#define skip_leb(p) while (*p++ & 0x80)

#define PUSH_I32(value)                        \
    do {                                       \
        *(int32 *)frame_sp++ = (int32)(value); \
    } while (0)

#define PUSH_F32(value)                            \
    do {                                           \
        *(float32 *)frame_sp++ = (float32)(value); \
    } while (0)

#define PUSH_I64(value)                   \
    do {                                  \
        PUT_I64_TO_ADDR(frame_sp, value); \
        frame_sp += 2;                    \
    } while (0)

#define PUSH_F64(value)                   \
    do {                                  \
        PUT_F64_TO_ADDR(frame_sp, value); \
        frame_sp += 2;                    \
    } while (0)

#define PUSH_CSP(_label_type, param_cell_num, cell_num, _target_addr) \
    do {                                                              \
        bh_assert(frame_csp < frame->csp_boundary);                   \
        /* frame_csp->label_type = _label_type; */                    \
        frame_csp->cell_num = cell_num;                               \
        frame_csp->begin_addr = frame_ip;                             \
        frame_csp->target_addr = _target_addr;                        \
        frame_csp->frame_sp = frame_sp - param_cell_num;              \
        frame_csp++;                                                  \
    } while (0)

#define POP_I32() (--frame_sp, *(int32 *)frame_sp)

#define POP_F32() (--frame_sp, *(float32 *)frame_sp)

#define POP_I64() (frame_sp -= 2, GET_I64_FROM_ADDR(frame_sp))

#define POP_F64() (frame_sp -= 2, GET_F64_FROM_ADDR(frame_sp))

#define POP_CSP_CHECK_OVERFLOW(n)                      \
    do {                                               \
        bh_assert(frame_csp - n >= frame->csp_bottom); \
    } while (0)

#define POP_CSP()                  \
    do {                           \
        POP_CSP_CHECK_OVERFLOW(1); \
        --frame_csp;               \
    } while (0)

#define POP_CSP_N(n)                                             \
    do {                                                         \
        uint32 *frame_sp_old = frame_sp;                         \
        uint32 cell_num_to_copy;                                 \
        POP_CSP_CHECK_OVERFLOW(n + 1);                           \
        frame_csp -= n;                                          \
        frame_ip = (frame_csp - 1)->target_addr;                 \
        /* copy arity values of block */                         \
        frame_sp = (frame_csp - 1)->frame_sp;                    \
        cell_num_to_copy = (frame_csp - 1)->cell_num;            \
        if (cell_num_to_copy > 0) {                              \
            word_copy(frame_sp, frame_sp_old - cell_num_to_copy, \
                      cell_num_to_copy);                         \
        }                                                        \
        frame_sp += cell_num_to_copy;                            \
    } while (0)

/* Pop the given number of elements from the given frame's stack.  */
#define POP(N)         \
    do {               \
        int n = (N);   \
        frame_sp -= n; \
    } while (0)

#define SYNC_ALL_TO_FRAME()     \
    do {                        \
        frame->sp = frame_sp;   \
        frame->ip = frame_ip;   \
        frame->csp = frame_csp; \
    } while (0)

#define UPDATE_ALL_FROM_FRAME() \
    do {                        \
        frame_sp = frame->sp;   \
        frame_ip = frame->ip;   \
        frame_csp = frame->csp; \
    } while (0)

#define read_leb_int64(p, p_end, res)              \
    do {                                           \
        uint8 _val = *p;                           \
        if (!(_val & 0x80)) {                      \
            res = (int64)_val;                     \
            if (_val & 0x40)                       \
                /* sign extend */                  \
                res |= 0xFFFFFFFFFFFFFF80LL;       \
            p++;                                   \
            break;                                 \
        }                                          \
        uint32 _off = 0;                           \
        res = (int64)read_leb(p, &_off, 64, true); \
        p += _off;                                 \
    } while (0)

#define read_leb_uint32(p, p_end, res)               \
    do {                                             \
        uint8 _val = *p;                             \
        if (!(_val & 0x80)) {                        \
            res = _val;                              \
            p++;                                     \
            break;                                   \
        }                                            \
        uint32 _off = 0;                             \
        res = (uint32)read_leb(p, &_off, 32, false); \
        p += _off;                                   \
    } while (0)

#define read_leb_int32(p, p_end, res)              \
    do {                                           \
        uint8 _val = *p;                           \
        if (!(_val & 0x80)) {                      \
            res = (int32)_val;                     \
            if (_val & 0x40)                       \
                /* sign extend */                  \
                res |= 0xFFFFFF80;                 \
            p++;                                   \
            break;                                 \
        }                                          \
        uint32 _off = 0;                           \
        res = (int32)read_leb(p, &_off, 32, true); \
        p += _off;                                 \
    } while (0)

#if WASM_ENABLE_LABELS_AS_VALUES == 0
#define RECOVER_FRAME_IP_END() frame_ip_end = wasm_get_func_code_end(cur_func)
#else
#define RECOVER_FRAME_IP_END() (void)0
#endif

#define RECOVER_CONTEXT(new_frame)      \
    do {                                \
        frame = (new_frame);            \
        cur_func = frame->function;     \
        prev_frame = frame->prev_frame; \
        frame_ip = frame->ip;           \
        RECOVER_FRAME_IP_END();         \
        frame_lp = frame->lp;           \
        frame_sp = frame->sp;           \
        frame_csp = frame->csp;         \
    } while (0)

#if WASM_ENABLE_LABELS_AS_VALUES != 0
#define GET_OPCODE() opcode = *(frame_ip - 1);
#else
#define GET_OPCODE() (void)0
#endif

#define DEF_OP_I_CONST(ctype, src_op_type)              \
    do {                                                \
        ctype cval;                                     \
        read_leb_##ctype(frame_ip, frame_ip_end, cval); \
        PUSH_##src_op_type(cval);                       \
    } while (0)

#define DEF_OP_EQZ(src_op_type)             \
    do {                                    \
        int32 pop_val;                      \
        pop_val = POP_##src_op_type() == 0; \
        PUSH_I32(pop_val);                  \
    } while (0)

#define DEF_OP_CMP(src_type, src_op_type, cond) \
    do {                                        \
        uint32 res;                             \
        src_type val1, val2;                    \
        val2 = (src_type)POP_##src_op_type();   \
        val1 = (src_type)POP_##src_op_type();   \
        res = val1 cond val2;                   \
        PUSH_I32(res);                          \
    } while (0)

#define DEF_OP_BIT_COUNT(src_type, src_op_type, operation) \
    do {                                                   \
        src_type val1, val2;                               \
        val1 = (src_type)POP_##src_op_type();              \
        val2 = (src_type)operation(val1);                  \
        PUSH_##src_op_type(val2);                          \
    } while (0)

#define DEF_OP_NUMERIC(src_type1, src_type2, src_op_type, operation)  \
    do {                                                              \
        frame_sp -= sizeof(src_type2) / sizeof(uint32);               \
        *(src_type1 *)(frame_sp - sizeof(src_type1) / sizeof(uint32)) \
            operation## = *(src_type2 *)(frame_sp);                   \
    } while (0)

#if WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS != 0
#define DEF_OP_NUMERIC_64 DEF_OP_NUMERIC
#else
#define DEF_OP_NUMERIC_64(src_type1, src_type2, src_op_type, operation) \
    do {                                                                \
        src_type1 val1;                                                 \
        src_type2 val2;                                                 \
        frame_sp -= 2;                                                  \
        val1 = (src_type1)GET_##src_op_type##_FROM_ADDR(frame_sp - 2);  \
        val2 = (src_type2)GET_##src_op_type##_FROM_ADDR(frame_sp);      \
        val1 operation## = val2;                                        \
        PUT_##src_op_type##_TO_ADDR(frame_sp - 2, val1);                \
    } while (0)
#endif

#define DEF_OP_NUMERIC2(src_type1, src_type2, src_op_type, operation) \
    do {                                                              \
        frame_sp -= sizeof(src_type2) / sizeof(uint32);               \
        *(src_type1 *)(frame_sp - sizeof(src_type1) / sizeof(uint32)) \
            operation## = (*(src_type2 *)(frame_sp) % 32);            \
    } while (0)

#define DEF_OP_NUMERIC2_64(src_type1, src_type2, src_op_type, operation) \
    do {                                                                 \
        src_type1 val1;                                                  \
        src_type2 val2;                                                  \
        frame_sp -= 2;                                                   \
        val1 = (src_type1)GET_##src_op_type##_FROM_ADDR(frame_sp - 2);   \
        val2 = (src_type2)GET_##src_op_type##_FROM_ADDR(frame_sp);       \
        val1 operation## = (val2 % 64);                                  \
        PUT_##src_op_type##_TO_ADDR(frame_sp - 2, val1);                 \
    } while (0)

#define DEF_OP_MATH(src_type, src_op_type, method) \
    do {                                           \
        src_type src_val;                          \
        src_val = POP_##src_op_type();             \
        PUSH_##src_op_type(method(src_val));       \
    } while (0)

#define TRUNC_FUNCTION(func_name, src_type, dst_type, signed_type)  \
    static dst_type func_name(src_type src_value, src_type src_min, \
                              src_type src_max, dst_type dst_min,   \
                              dst_type dst_max, bool is_sign)       \
    {                                                               \
        dst_type dst_value = 0;                                     \
        if (!isnan(src_value)) {                                    \
            if (src_value <= src_min)                               \
                dst_value = dst_min;                                \
            else if (src_value >= src_max)                          \
                dst_value = dst_max;                                \
            else {                                                  \
                if (is_sign)                                        \
                    dst_value = (dst_type)(signed_type)src_value;   \
                else                                                \
                    dst_value = (dst_type)src_value;                \
            }                                                       \
        }                                                           \
        return dst_value;                                           \
    }

TRUNC_FUNCTION(trunc_f32_to_i32, float32, uint32, int32)
TRUNC_FUNCTION(trunc_f32_to_i64, float32, uint64, int64)
TRUNC_FUNCTION(trunc_f64_to_i32, float64, uint32, int32)
TRUNC_FUNCTION(trunc_f64_to_i64, float64, uint64, int64)

static bool
trunc_f32_to_int(WASMModuleInstance *module, uint32 *frame_sp, float32 src_min,
                 float32 src_max, bool saturating, bool is_i32, bool is_sign)
{
    float32 src_value = POP_F32();
    uint64 dst_value_i64;
    uint32 dst_value_i32;

    if (!saturating) {
        if (isnan(src_value)) {
            wasm_set_exception(module, "invalid conversion to integer");
            return true;
        }
        else if (src_value <= src_min || src_value >= src_max) {
            wasm_set_exception(module, "integer overflow");
            return true;
        }
    }

    if (is_i32) {
        uint32 dst_min = is_sign ? INT32_MIN : 0;
        uint32 dst_max = is_sign ? INT32_MAX : UINT32_MAX;
        dst_value_i32 = trunc_f32_to_i32(src_value, src_min, src_max, dst_min,
                                         dst_max, is_sign);
        PUSH_I32(dst_value_i32);
    }
    else {
        uint64 dst_min = is_sign ? INT64_MIN : 0;
        uint64 dst_max = is_sign ? INT64_MAX : UINT64_MAX;
        dst_value_i64 = trunc_f32_to_i64(src_value, src_min, src_max, dst_min,
                                         dst_max, is_sign);
        PUSH_I64(dst_value_i64);
    }
    return false;
}

static bool
trunc_f64_to_int(WASMModuleInstance *module, uint32 *frame_sp, float64 src_min,
                 float64 src_max, bool saturating, bool is_i32, bool is_sign)
{
    float64 src_value = POP_F64();
    uint64 dst_value_i64;
    uint32 dst_value_i32;

    if (!saturating) {
        if (isnan(src_value)) {
            wasm_set_exception(module, "invalid conversion to integer");
            return true;
        }
        else if (src_value <= src_min || src_value >= src_max) {
            wasm_set_exception(module, "integer overflow");
            return true;
        }
    }

    if (is_i32) {
        uint32 dst_min = is_sign ? INT32_MIN : 0;
        uint32 dst_max = is_sign ? INT32_MAX : UINT32_MAX;
        dst_value_i32 = trunc_f64_to_i32(src_value, src_min, src_max, dst_min,
                                         dst_max, is_sign);
        PUSH_I32(dst_value_i32);
    }
    else {
        uint64 dst_min = is_sign ? INT64_MIN : 0;
        uint64 dst_max = is_sign ? INT64_MAX : UINT64_MAX;
        dst_value_i64 = trunc_f64_to_i64(src_value, src_min, src_max, dst_min,
                                         dst_max, is_sign);
        PUSH_I64(dst_value_i64);
    }
    return false;
}

#define DEF_OP_TRUNC_F32(min, max, is_i32, is_sign)                     \
    do {                                                                \
        if (trunc_f32_to_int(module, frame_sp, min, max, false, is_i32, \
                             is_sign))                                  \
            goto got_exception;                                         \
    } while (0)

#define DEF_OP_TRUNC_F64(min, max, is_i32, is_sign)                     \
    do {                                                                \
        if (trunc_f64_to_int(module, frame_sp, min, max, false, is_i32, \
                             is_sign))                                  \
            goto got_exception;                                         \
    } while (0)

#define DEF_OP_TRUNC_SAT_F32(min, max, is_i32, is_sign)                  \
    do {                                                                 \
        (void)trunc_f32_to_int(module, frame_sp, min, max, true, is_i32, \
                               is_sign);                                 \
    } while (0)

#define DEF_OP_TRUNC_SAT_F64(min, max, is_i32, is_sign)                  \
    do {                                                                 \
        (void)trunc_f64_to_int(module, frame_sp, min, max, true, is_i32, \
                               is_sign);                                 \
    } while (0)

#define DEF_OP_CONVERT(dst_type, dst_op_type, src_type, src_op_type) \
    do {                                                             \
        dst_type value = (dst_type)(src_type)POP_##src_op_type();    \
        PUSH_##dst_op_type(value);                                   \
    } while (0)

#define GET_LOCAL_INDEX_TYPE_AND_OFFSET()                                \
    do {                                                                 \
        uint32 param_count = cur_func->param_count;                      \
        read_leb_uint32(frame_ip, frame_ip_end, local_idx);              \
        bh_assert(local_idx < param_count + cur_func->local_count);      \
        local_offset = cur_func->local_offsets[local_idx];               \
        if (local_idx < param_count)                                     \
            local_type = cur_func->param_types[local_idx];               \
        else                                                             \
            local_type = cur_func->local_types[local_idx - param_count]; \
    } while (0)

#define DEF_ATOMIC_RMW_OPCODE(OP_NAME, op)                           \
    case WASM_OP_ATOMIC_RMW_I32_##OP_NAME:                           \
    case WASM_OP_ATOMIC_RMW_I32_##OP_NAME##8_U:                      \
    case WASM_OP_ATOMIC_RMW_I32_##OP_NAME##16_U:                     \
    {                                                                \
        uint32 readv, sval;                                          \
                                                                     \
        sval = POP_I32();                                            \
        addr = POP_I32();                                            \
                                                                     \
        if (opcode == WASM_OP_ATOMIC_RMW_I32_##OP_NAME##8_U) {       \
            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 1, maddr);     \
            CHECK_ATOMIC_MEMORY_ACCESS();                            \
                                                                     \
            os_mutex_lock(&memory->mem_lock);                        \
            readv = (uint32)(*(uint8 *)maddr);                       \
            *(uint8 *)maddr = (uint8)(readv op sval);                \
            os_mutex_unlock(&memory->mem_lock);                      \
        }                                                            \
        else if (opcode == WASM_OP_ATOMIC_RMW_I32_##OP_NAME##16_U) { \
            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 2, maddr);     \
            CHECK_ATOMIC_MEMORY_ACCESS();                            \
                                                                     \
            os_mutex_lock(&memory->mem_lock);                        \
            readv = (uint32)LOAD_U16(maddr);                         \
            STORE_U16(maddr, (uint16)(readv op sval));               \
            os_mutex_unlock(&memory->mem_lock);                      \
        }                                                            \
        else {                                                       \
            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 4, maddr);     \
            CHECK_ATOMIC_MEMORY_ACCESS();                            \
                                                                     \
            os_mutex_lock(&memory->mem_lock);                        \
            readv = LOAD_I32(maddr);                                 \
            STORE_U32(maddr, readv op sval);                         \
            os_mutex_unlock(&memory->mem_lock);                      \
        }                                                            \
        PUSH_I32(readv);                                             \
        break;                                                       \
    }                                                                \
    case WASM_OP_ATOMIC_RMW_I64_##OP_NAME:                           \
    case WASM_OP_ATOMIC_RMW_I64_##OP_NAME##8_U:                      \
    case WASM_OP_ATOMIC_RMW_I64_##OP_NAME##16_U:                     \
    case WASM_OP_ATOMIC_RMW_I64_##OP_NAME##32_U:                     \
    {                                                                \
        uint64 readv, sval;                                          \
                                                                     \
        sval = (uint64)POP_I64();                                    \
        addr = POP_I32();                                            \
                                                                     \
        if (opcode == WASM_OP_ATOMIC_RMW_I64_##OP_NAME##8_U) {       \
            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 1, maddr);     \
            CHECK_ATOMIC_MEMORY_ACCESS();                            \
                                                                     \
            os_mutex_lock(&memory->mem_lock);                        \
            readv = (uint64)(*(uint8 *)maddr);                       \
            *(uint8 *)maddr = (uint8)(readv op sval);                \
            os_mutex_unlock(&memory->mem_lock);                      \
        }                                                            \
        else if (opcode == WASM_OP_ATOMIC_RMW_I64_##OP_NAME##16_U) { \
            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 2, maddr);     \
            CHECK_ATOMIC_MEMORY_ACCESS();                            \
                                                                     \
            os_mutex_lock(&memory->mem_lock);                        \
            readv = (uint64)LOAD_U16(maddr);                         \
            STORE_U16(maddr, (uint16)(readv op sval));               \
            os_mutex_unlock(&memory->mem_lock);                      \
        }                                                            \
        else if (opcode == WASM_OP_ATOMIC_RMW_I64_##OP_NAME##32_U) { \
            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 4, maddr);     \
            CHECK_ATOMIC_MEMORY_ACCESS();                            \
                                                                     \
            os_mutex_lock(&memory->mem_lock);                        \
            readv = (uint64)LOAD_U32(maddr);                         \
            STORE_U32(maddr, (uint32)(readv op sval));               \
            os_mutex_unlock(&memory->mem_lock);                      \
        }                                                            \
        else {                                                       \
            uint64 op_result;                                        \
            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 8, maddr);     \
            CHECK_ATOMIC_MEMORY_ACCESS();                            \
                                                                     \
            os_mutex_lock(&memory->mem_lock);                        \
            readv = (uint64)LOAD_I64(maddr);                         \
            op_result = readv op sval;                               \
            STORE_I64(maddr, op_result);                             \
            os_mutex_unlock(&memory->mem_lock);                      \
        }                                                            \
        PUSH_I64(readv);                                             \
        break;                                                       \
    }

static inline int32
sign_ext_8_32(int8 val)
{
    if (val & 0x80)
        return (int32)val | (int32)0xffffff00;
    return val;
}

static inline int32
sign_ext_16_32(int16 val)
{
    if (val & 0x8000)
        return (int32)val | (int32)0xffff0000;
    return val;
}

static inline int64
sign_ext_8_64(int8 val)
{
    if (val & 0x80)
        return (int64)val | (int64)0xffffffffffffff00LL;
    return val;
}

static inline int64
sign_ext_16_64(int16 val)
{
    if (val & 0x8000)
        return (int64)val | (int64)0xffffffffffff0000LL;
    return val;
}

static inline int64
sign_ext_32_64(int32 val)
{
    if (val & (int32)0x80000000)
        return (int64)val | (int64)0xffffffff00000000LL;
    return val;
}

static inline void
word_copy(uint32 *dest, uint32 *src, unsigned num)
{
    bh_assert(dest != NULL);
    bh_assert(src != NULL);
    bh_assert(num > 0);
    if (dest != src) {
        /* No overlap buffer */
        bh_assert(!((src < dest) && (dest < src + num)));
        for (; num > 0; num--)
            *dest++ = *src++;
    }
}

static inline WASMInterpFrame *
ALLOC_FRAME(WASMExecEnv *exec_env, uint32 size, WASMInterpFrame *prev_frame)
{
    WASMInterpFrame *frame = wasm_exec_env_alloc_wasm_frame(exec_env, size);

    if (frame) {
        frame->prev_frame = prev_frame;
#if WASM_ENABLE_PERF_PROFILING != 0
        frame->time_started = os_time_get_boot_microsecond();
#endif
    }
    else {
        wasm_set_exception((WASMModuleInstance *)exec_env->module_inst,
                           "wasm operand stack overflow");
    }

    return frame;
}

static inline void
FREE_FRAME(WASMExecEnv *exec_env, WASMInterpFrame *frame)
{
#if WASM_ENABLE_PERF_PROFILING != 0
    if (frame->function) {
        frame->function->total_exec_time +=
            os_time_get_boot_microsecond() - frame->time_started;
        frame->function->total_exec_cnt++;
    }
#endif
    wasm_exec_env_free_wasm_frame(exec_env, frame);
}

void
wasm_interp_restore_wasm_frame(WASMExecEnv *exec_env)
{
    WASMInterpFrame *cur_frame, *prev_frame;

    cur_frame = wasm_exec_env_get_cur_frame(exec_env);
    while (cur_frame) {
        prev_frame = cur_frame->prev_frame;
        if (cur_frame->ip) {
            /* FREE_FRAME just set the wasm_stack.s.top pointer, we only need to
             * call it once */
            FREE_FRAME(exec_env, cur_frame);
            break;
        }
        cur_frame = prev_frame;
    }

    wasm_exec_env_set_cur_frame(exec_env, cur_frame);
}

static void
wasm_interp_call_func_native(WASMModuleInstance *module_inst,
                             WASMExecEnv *exec_env,
                             WASMFunctionInstance *cur_func,
                             WASMInterpFrame *prev_frame)
{
    WASMFunctionImport *func_import = cur_func->u.func_import;
    unsigned local_cell_num = 2;
    WASMInterpFrame *frame;
    uint32 argv_ret[2], cur_func_index;
    void *native_func_pointer = NULL;
    char buf[128];
    bool ret;

    if (!(frame = ALLOC_FRAME(exec_env,
                              wasm_interp_interp_frame_size(local_cell_num),
                              prev_frame)))
        return;

    frame->function = cur_func;
    frame->ip = NULL;
    frame->sp = frame->lp + local_cell_num;

    wasm_exec_env_set_cur_frame(exec_env, frame);

    cur_func_index = (uint32)(cur_func - module_inst->functions);
    bh_assert(cur_func_index < module_inst->module->import_function_count);
    native_func_pointer = module_inst->import_func_ptrs[cur_func_index];

    if (!native_func_pointer) {
        snprintf(buf, sizeof(buf),
                 "failed to call unlinked import function (%s, %s)",
                 func_import->module_name, func_import->field_name);
        wasm_set_exception(module_inst, buf);
        return;
    }

    if (func_import->call_conv_wasm_c_api) {
        ret = wasm_runtime_invoke_c_api_native(
            (WASMModuleInstanceCommon *)module_inst, native_func_pointer,
            func_import->func_type, cur_func->param_cell_num, frame->lp,
            func_import->wasm_c_api_with_env, func_import->attachment);
        if (ret) {
            argv_ret[0] = frame->lp[0];
            argv_ret[1] = frame->lp[1];
        }
    }
    else if (!func_import->call_conv_raw) {
        ret = wasm_runtime_invoke_native(
            exec_env, native_func_pointer, func_import->func_type,
            func_import->signature, func_import->attachment, frame->lp,
            cur_func->param_cell_num, argv_ret);
    }
    else {
        ret = wasm_runtime_invoke_native_raw(
            exec_env, native_func_pointer, func_import->func_type,
            func_import->signature, func_import->attachment, frame->lp,
            cur_func->param_cell_num, argv_ret);
    }

    if (!ret)
        return;

    if (cur_func->ret_cell_num == 1) {
        prev_frame->sp[0] = argv_ret[0];
        prev_frame->sp++;
    }
    else if (cur_func->ret_cell_num == 2) {
        prev_frame->sp[0] = argv_ret[0];
        prev_frame->sp[1] = argv_ret[1];
        prev_frame->sp += 2;
    }

    FREE_FRAME(exec_env, frame);
    wasm_exec_env_set_cur_frame(exec_env, prev_frame);
}

#if WASM_ENABLE_FAST_JIT != 0
bool
jit_invoke_native(WASMExecEnv *exec_env, uint32 func_idx,
                  WASMInterpFrame *prev_frame)
{
    WASMModuleInstance *module_inst =
        (WASMModuleInstance *)exec_env->module_inst;
    WASMFunctionInstance *cur_func = module_inst->functions + func_idx;

    wasm_interp_call_func_native(module_inst, exec_env, cur_func, prev_frame);
    return wasm_get_exception(module_inst) ? false : true;
}
#endif

#if WASM_ENABLE_MULTI_MODULE != 0
static void
wasm_interp_call_func_bytecode(WASMModuleInstance *module,
                               WASMExecEnv *exec_env,
                               WASMFunctionInstance *cur_func,
                               WASMInterpFrame *prev_frame);

static void
wasm_interp_call_func_import(WASMModuleInstance *module_inst,
                             WASMExecEnv *exec_env,
                             WASMFunctionInstance *cur_func,
                             WASMInterpFrame *prev_frame)
{
    WASMModuleInstance *sub_module_inst = cur_func->import_module_inst;
    WASMFunctionInstance *sub_func_inst = cur_func->import_func_inst;
    WASMFunctionImport *func_import = cur_func->u.func_import;
    uint8 *ip = prev_frame->ip;
    char buf[128];
    WASMExecEnv *sub_module_exec_env = NULL;
    uint32 aux_stack_origin_boundary = 0;
    uint32 aux_stack_origin_bottom = 0;

    if (!sub_func_inst) {
        snprintf(buf, sizeof(buf),
                 "failed to call unlinked import function (%s, %s)",
                 func_import->module_name, func_import->field_name);
        wasm_set_exception(module_inst, buf);
        return;
    }

    /* Switch exec_env but keep using the same one by replacing necessary
     * variables */
    sub_module_exec_env = wasm_runtime_get_exec_env_singleton(
        (WASMModuleInstanceCommon *)sub_module_inst);
    if (!sub_module_exec_env) {
        wasm_set_exception(module_inst, "create singleton exec_env failed");
        return;
    }

    /* - module_inst */
    exec_env->module_inst = (WASMModuleInstanceCommon *)sub_module_inst;
    /* - aux_stack_boundary */
    aux_stack_origin_boundary = exec_env->aux_stack_boundary.boundary;
    exec_env->aux_stack_boundary.boundary =
        sub_module_exec_env->aux_stack_boundary.boundary;
    /* - aux_stack_bottom */
    aux_stack_origin_bottom = exec_env->aux_stack_bottom.bottom;
    exec_env->aux_stack_bottom.bottom =
        sub_module_exec_env->aux_stack_bottom.bottom;

    /* set ip NULL to make call_func_bytecode return after executing
       this function */
    prev_frame->ip = NULL;

    /* call function of sub-module*/
    wasm_interp_call_func_bytecode(sub_module_inst, exec_env, sub_func_inst,
                                   prev_frame);

    /* restore ip and other replaced */
    prev_frame->ip = ip;
    exec_env->aux_stack_boundary.boundary = aux_stack_origin_boundary;
    exec_env->aux_stack_bottom.bottom = aux_stack_origin_bottom;
    exec_env->module_inst = (WASMModuleInstanceCommon *)module_inst;

    /* transfer exception if it is thrown */
    if (wasm_get_exception(sub_module_inst)) {
        bh_memcpy_s(module_inst->cur_exception,
                    sizeof(module_inst->cur_exception),
                    sub_module_inst->cur_exception,
                    sizeof(sub_module_inst->cur_exception));
    }
}
#endif

#if WASM_ENABLE_THREAD_MGR != 0
#if WASM_ENABLE_DEBUG_INTERP != 0
#define CHECK_SUSPEND_FLAGS()                                          \
    do {                                                               \
        if (IS_WAMR_TERM_SIG(exec_env->current_status->signal_flag)) { \
            return;                                                    \
        }                                                              \
        if (IS_WAMR_STOP_SIG(exec_env->current_status->signal_flag)) { \
            SYNC_ALL_TO_FRAME();                                       \
            wasm_cluster_thread_stopped(exec_env);                     \
            wasm_cluster_thread_waiting_run(exec_env);                 \
        }                                                              \
    } while (0)
#else
#define CHECK_SUSPEND_FLAGS()                                             \
    do {                                                                  \
        if (exec_env->suspend_flags.flags != 0) {                         \
            if (exec_env->suspend_flags.flags & 0x01) {                   \
                /* terminate current thread */                            \
                return;                                                   \
            }                                                             \
            while (exec_env->suspend_flags.flags & 0x02) {                \
                /* suspend current thread */                              \
                os_cond_wait(&exec_env->wait_cond, &exec_env->wait_lock); \
            }                                                             \
        }                                                                 \
    } while (0)
#endif /* WASM_ENABLE_DEBUG_INTERP */
#endif /* WASM_ENABLE_THREAD_MGR */

#if WASM_ENABLE_LABELS_AS_VALUES != 0

#define HANDLE_OP(opcode) HANDLE_##opcode:
#define FETCH_OPCODE_AND_DISPATCH() goto *handle_table[*frame_ip++]

#if WASM_ENABLE_THREAD_MGR != 0 && WASM_ENABLE_DEBUG_INTERP != 0
#define HANDLE_OP_END()                                                   \
    do {                                                                  \
        /* Record the current frame_ip, so when exception occurs,         \
           debugger can know the exact opcode who caused the exception */ \
        frame_ip_orig = frame_ip;                                         \
        while (exec_env->current_status->signal_flag == WAMR_SIG_SINGSTEP \
               && exec_env->current_status->step_count++ == 1) {          \
            exec_env->current_status->step_count = 0;                     \
            SYNC_ALL_TO_FRAME();                                          \
            wasm_cluster_thread_stopped(exec_env);                        \
            wasm_cluster_thread_waiting_run(exec_env);                    \
        }                                                                 \
        goto *handle_table[*frame_ip++];                                  \
    } while (0)
#else
#define HANDLE_OP_END() FETCH_OPCODE_AND_DISPATCH()
#endif

#else /* else of WASM_ENABLE_LABELS_AS_VALUES */
#define HANDLE_OP(opcode) case opcode:
#if WASM_ENABLE_THREAD_MGR != 0 && WASM_ENABLE_DEBUG_INTERP != 0
#define HANDLE_OP_END()                                            \
    if (exec_env->current_status->signal_flag == WAMR_SIG_SINGSTEP \
        && exec_env->current_status->step_count++ == 2) {          \
        exec_env->current_status->step_count = 0;                  \
        SYNC_ALL_TO_FRAME();                                       \
        wasm_cluster_thread_stopped(exec_env);                     \
        wasm_cluster_thread_waiting_run(exec_env);                 \
    }                                                              \
    continue
#else
#define HANDLE_OP_END() continue
#endif

#endif /* end of WASM_ENABLE_LABELS_AS_VALUES */

static inline uint8 *
get_global_addr(uint8 *global_data, WASMGlobalInstance *global)
{
#if WASM_ENABLE_MULTI_MODULE == 0
    return global_data + global->data_offset;
#else
    return global->import_global_inst
               ? global->import_module_inst->global_data
                     + global->import_global_inst->data_offset
               : global_data + global->data_offset;
#endif
}

static void
wasm_interp_call_func_bytecode(WASMModuleInstance *module,
                               WASMExecEnv *exec_env,
                               WASMFunctionInstance *cur_func,
                               WASMInterpFrame *prev_frame)
{
    WASMMemoryInstance *memory = module->default_memory;
    uint8 *global_data = module->global_data;
#if !defined(OS_ENABLE_HW_BOUND_CHECK)              \
    || WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0 \
    || WASM_ENABLE_BULK_MEMORY != 0
    uint32 num_bytes_per_page = memory ? memory->num_bytes_per_page : 0;
    uint32 linear_mem_size =
        memory ? num_bytes_per_page * memory->cur_page_count : 0;
#endif
    WASMType **wasm_types = module->module->types;
    WASMGlobalInstance *globals = module->globals, *global;
    uint8 opcode_IMPDEP = WASM_OP_IMPDEP;
    WASMInterpFrame *frame = NULL;
    /* Points to this special opcode so as to jump to the
     * call_method_from_entry.  */
    register uint8 *frame_ip = &opcode_IMPDEP; /* cache of frame->ip */
    register uint32 *frame_lp = NULL;          /* cache of frame->lp */
    register uint32 *frame_sp = NULL;          /* cache of frame->sp */
    WASMBranchBlock *frame_csp = NULL;
    BlockAddr *cache_items;
    uint8 *frame_ip_end = frame_ip + 1;
    uint8 opcode;
    uint32 i, depth, cond, count, fidx, tidx, lidx, frame_size = 0;
    uint64 all_cell_num = 0;
    int32 val;
    uint8 *else_addr, *end_addr, *maddr = NULL;
    uint32 local_idx, local_offset, global_idx;
    uint8 local_type, *global_addr;
    uint32 cache_index, type_index, param_cell_num, cell_num;
    uint8 value_type;

#if WASM_ENABLE_DEBUG_INTERP != 0
    uint8 *frame_ip_orig = NULL;
#endif

#if WASM_ENABLE_LABELS_AS_VALUES != 0
#define HANDLE_OPCODE(op) &&HANDLE_##op
    DEFINE_GOTO_TABLE(const void *, handle_table);
#undef HANDLE_OPCODE
#endif

#if WASM_ENABLE_LABELS_AS_VALUES == 0
    while (frame_ip < frame_ip_end) {
        opcode = *frame_ip++;
        switch (opcode) {
#else
    FETCH_OPCODE_AND_DISPATCH();
#endif
            /* control instructions */
            HANDLE_OP(WASM_OP_UNREACHABLE)
            {
                wasm_set_exception(module, "unreachable");
                goto got_exception;
            }

            HANDLE_OP(WASM_OP_NOP) { HANDLE_OP_END(); }

            HANDLE_OP(EXT_OP_BLOCK)
            {
                read_leb_uint32(frame_ip, frame_ip_end, type_index);
                param_cell_num = wasm_types[type_index]->param_cell_num;
                cell_num = wasm_types[type_index]->ret_cell_num;
                goto handle_op_block;
            }

            HANDLE_OP(WASM_OP_BLOCK)
            {
                value_type = *frame_ip++;
                param_cell_num = 0;
                cell_num = wasm_value_type_cell_num(value_type);
            handle_op_block:
                cache_index = ((uintptr_t)frame_ip)
                              & (uintptr_t)(BLOCK_ADDR_CACHE_SIZE - 1);
                cache_items = exec_env->block_addr_cache[cache_index];
                if (cache_items[0].start_addr == frame_ip) {
                    end_addr = cache_items[0].end_addr;
                }
                else if (cache_items[1].start_addr == frame_ip) {
                    end_addr = cache_items[1].end_addr;
                }
#if WASM_ENABLE_DEBUG_INTERP != 0
                else if (!wasm_loader_find_block_addr(
                             exec_env, (BlockAddr *)exec_env->block_addr_cache,
                             frame_ip, (uint8 *)-1, LABEL_TYPE_BLOCK,
                             &else_addr, &end_addr)) {
                    wasm_set_exception(module, "find block address failed");
                    goto got_exception;
                }
#endif
                else {
                    end_addr = NULL;
                }
                PUSH_CSP(LABEL_TYPE_BLOCK, param_cell_num, cell_num, end_addr);
                HANDLE_OP_END();
            }

            HANDLE_OP(EXT_OP_LOOP)
            {
                read_leb_uint32(frame_ip, frame_ip_end, type_index);
                param_cell_num = wasm_types[type_index]->param_cell_num;
                cell_num = wasm_types[type_index]->param_cell_num;
                goto handle_op_loop;
            }

            HANDLE_OP(WASM_OP_LOOP)
            {
                value_type = *frame_ip++;
                param_cell_num = 0;
                cell_num = 0;
            handle_op_loop:
                PUSH_CSP(LABEL_TYPE_LOOP, param_cell_num, cell_num, frame_ip);
                HANDLE_OP_END();
            }

            HANDLE_OP(EXT_OP_IF)
            {
                read_leb_uint32(frame_ip, frame_ip_end, type_index);
                param_cell_num = wasm_types[type_index]->param_cell_num;
                cell_num = wasm_types[type_index]->ret_cell_num;
                goto handle_op_if;
            }

            HANDLE_OP(WASM_OP_IF)
            {
                value_type = *frame_ip++;
                param_cell_num = 0;
                cell_num = wasm_value_type_cell_num(value_type);
            handle_op_if:
                cache_index = ((uintptr_t)frame_ip)
                              & (uintptr_t)(BLOCK_ADDR_CACHE_SIZE - 1);
                cache_items = exec_env->block_addr_cache[cache_index];
                if (cache_items[0].start_addr == frame_ip) {
                    else_addr = cache_items[0].else_addr;
                    end_addr = cache_items[0].end_addr;
                }
                else if (cache_items[1].start_addr == frame_ip) {
                    else_addr = cache_items[1].else_addr;
                    end_addr = cache_items[1].end_addr;
                }
                else if (!wasm_loader_find_block_addr(
                             exec_env, (BlockAddr *)exec_env->block_addr_cache,
                             frame_ip, (uint8 *)-1, LABEL_TYPE_IF, &else_addr,
                             &end_addr)) {
                    wasm_set_exception(module, "find block address failed");
                    goto got_exception;
                }

                cond = (uint32)POP_I32();

                if (cond) { /* if branch is met */
                    PUSH_CSP(LABEL_TYPE_IF, param_cell_num, cell_num, end_addr);
                }
                else { /* if branch is not met */
                    /* if there is no else branch, go to the end addr */
                    if (else_addr == NULL) {
                        frame_ip = end_addr + 1;
                    }
                    /* if there is an else branch, go to the else addr */
                    else {
                        PUSH_CSP(LABEL_TYPE_IF, param_cell_num, cell_num,
                                 end_addr);
                        frame_ip = else_addr + 1;
                    }
                }
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_ELSE)
            {
                /* comes from the if branch in WASM_OP_IF */
                frame_ip = (frame_csp - 1)->target_addr;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_END)
            {
                if (frame_csp > frame->csp_bottom + 1) {
                    POP_CSP();
                }
                else { /* end of function, treat as WASM_OP_RETURN */
                    frame_sp -= cur_func->ret_cell_num;
                    for (i = 0; i < cur_func->ret_cell_num; i++) {
                        *prev_frame->sp++ = frame_sp[i];
                    }
                    goto return_func;
                }
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_BR)
            {
#if WASM_ENABLE_THREAD_MGR != 0
                CHECK_SUSPEND_FLAGS();
#endif
                read_leb_uint32(frame_ip, frame_ip_end, depth);
            label_pop_csp_n:
                POP_CSP_N(depth);
                if (!frame_ip) { /* must be label pushed by WASM_OP_BLOCK */
                    if (!wasm_loader_find_block_addr(
                            exec_env, (BlockAddr *)exec_env->block_addr_cache,
                            (frame_csp - 1)->begin_addr, (uint8 *)-1,
                            LABEL_TYPE_BLOCK, &else_addr, &end_addr)) {
                        wasm_set_exception(module, "find block address failed");
                        goto got_exception;
                    }
                    frame_ip = end_addr;
                }
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_BR_IF)
            {
#if WASM_ENABLE_THREAD_MGR != 0
                CHECK_SUSPEND_FLAGS();
#endif
                read_leb_uint32(frame_ip, frame_ip_end, depth);
                cond = (uint32)POP_I32();
                if (cond)
                    goto label_pop_csp_n;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_BR_TABLE)
            {
#if WASM_ENABLE_THREAD_MGR != 0
                CHECK_SUSPEND_FLAGS();
#endif
                read_leb_uint32(frame_ip, frame_ip_end, count);
                lidx = POP_I32();
                if (lidx > count)
                    lidx = count;
                depth = frame_ip[lidx];
                goto label_pop_csp_n;
            }

            HANDLE_OP(EXT_OP_BR_TABLE_CACHE)
            {
                BrTableCache *node =
                    bh_list_first_elem(module->module->br_table_cache_list);
                BrTableCache *node_next;

#if WASM_ENABLE_THREAD_MGR != 0
                CHECK_SUSPEND_FLAGS();
#endif
                lidx = POP_I32();

                while (node) {
                    node_next = bh_list_elem_next(node);
                    if (node->br_table_op_addr == frame_ip - 1) {
                        depth = node->br_depths[lidx];
                        goto label_pop_csp_n;
                    }
                    node = node_next;
                }
                bh_assert(0);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_RETURN)
            {
                frame_sp -= cur_func->ret_cell_num;
                for (i = 0; i < cur_func->ret_cell_num; i++) {
                    *prev_frame->sp++ = frame_sp[i];
                }
                goto return_func;
            }

            HANDLE_OP(WASM_OP_CALL)
            {
#if WASM_ENABLE_THREAD_MGR != 0
                CHECK_SUSPEND_FLAGS();
#endif
                read_leb_uint32(frame_ip, frame_ip_end, fidx);
#if WASM_ENABLE_MULTI_MODULE != 0
                if (fidx >= module->function_count) {
                    wasm_set_exception(module, "unknown function");
                    goto got_exception;
                }
#endif

                cur_func = module->functions + fidx;
                goto call_func_from_interp;
            }

#if WASM_ENABLE_TAIL_CALL != 0
            HANDLE_OP(WASM_OP_RETURN_CALL)
            {
#if WASM_ENABLE_THREAD_MGR != 0
                CHECK_SUSPEND_FLAGS();
#endif
                read_leb_uint32(frame_ip, frame_ip_end, fidx);
#if WASM_ENABLE_MULTI_MODULE != 0
                if (fidx >= module->function_count) {
                    wasm_set_exception(module, "unknown function");
                    goto got_exception;
                }
#endif
                cur_func = module->functions + fidx;

                goto call_func_from_return_call;
            }
#endif /* WASM_ENABLE_TAIL_CALL */

            HANDLE_OP(WASM_OP_CALL_INDIRECT)
#if WASM_ENABLE_TAIL_CALL != 0
            HANDLE_OP(WASM_OP_RETURN_CALL_INDIRECT)
#endif
            {
                WASMType *cur_type, *cur_func_type;
                WASMTableInstance *tbl_inst;
                uint32 tbl_idx;
#if WASM_ENABLE_TAIL_CALL != 0
                opcode = *(frame_ip - 1);
#endif
#if WASM_ENABLE_THREAD_MGR != 0
                CHECK_SUSPEND_FLAGS();
#endif

                /**
                 * type check. compiler will make sure all like
                 * (call_indirect (type $x) (i32.const 1))
                 * the function type has to be defined in the module also
                 * no matter it is used or not
                 */
                read_leb_uint32(frame_ip, frame_ip_end, tidx);
                bh_assert(tidx < module->module->type_count);
                cur_type = wasm_types[tidx];

                read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                bh_assert(tbl_idx < module->table_count);

                tbl_inst = wasm_get_table_inst(module, tbl_idx);

                val = POP_I32();
                if ((uint32)val >= tbl_inst->cur_size) {
                    wasm_set_exception(module, "undefined element");
                    goto got_exception;
                }

                fidx = ((uint32 *)tbl_inst->base_addr)[val];
                if (fidx == (uint32)-1) {
                    wasm_set_exception(module, "uninitialized element");
                    goto got_exception;
                }

                /*
                 * we might be using a table injected by host or
                 * another module. In that case, we don't validate
                 * the elem value while loading
                 */
                if (fidx >= module->function_count) {
                    wasm_set_exception(module, "unknown function");
                    goto got_exception;
                }

                /* always call module own functions */
                cur_func = module->functions + fidx;

                if (cur_func->is_import_func)
                    cur_func_type = cur_func->u.func_import->func_type;
                else
                    cur_func_type = cur_func->u.func->func_type;

                if (cur_type != cur_func_type) {
                    wasm_set_exception(module, "indirect call type mismatch");
                    goto got_exception;
                }

#if WASM_ENABLE_TAIL_CALL != 0
                if (opcode == WASM_OP_RETURN_CALL_INDIRECT)
                    goto call_func_from_return_call;
#endif
                goto call_func_from_interp;
            }

            /* parametric instructions */
            HANDLE_OP(WASM_OP_DROP)
            {
                frame_sp--;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_DROP_64)
            {
                frame_sp -= 2;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_SELECT)
            {
                cond = (uint32)POP_I32();
                frame_sp--;
                if (!cond)
                    *(frame_sp - 1) = *frame_sp;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_SELECT_64)
            {
                cond = (uint32)POP_I32();
                frame_sp -= 2;
                if (!cond) {
                    *(frame_sp - 2) = *frame_sp;
                    *(frame_sp - 1) = *(frame_sp + 1);
                }
                HANDLE_OP_END();
            }

#if WASM_ENABLE_REF_TYPES != 0
            HANDLE_OP(WASM_OP_SELECT_T)
            {
                uint32 vec_len;
                uint8 type;

                read_leb_uint32(frame_ip, frame_ip_end, vec_len);
                type = *frame_ip++;

                cond = (uint32)POP_I32();
                if (type == VALUE_TYPE_I64 || type == VALUE_TYPE_F64) {
                    frame_sp -= 2;
                    if (!cond) {
                        *(frame_sp - 2) = *frame_sp;
                        *(frame_sp - 1) = *(frame_sp + 1);
                    }
                }
                else {
                    frame_sp--;
                    if (!cond)
                        *(frame_sp - 1) = *frame_sp;
                }

                (void)vec_len;
                HANDLE_OP_END();
            }
            HANDLE_OP(WASM_OP_TABLE_GET)
            {
                uint32 tbl_idx, elem_idx;
                WASMTableInstance *tbl_inst;

                read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                bh_assert(tbl_idx < module->table_count);

                tbl_inst = wasm_get_table_inst(module, tbl_idx);

                elem_idx = POP_I32();
                if (elem_idx >= tbl_inst->cur_size) {
                    wasm_set_exception(module, "out of bounds table access");
                    goto got_exception;
                }

                PUSH_I32(((uint32 *)tbl_inst->base_addr)[elem_idx]);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_TABLE_SET)
            {
                uint32 tbl_idx, elem_idx, elem_val;
                WASMTableInstance *tbl_inst;

                read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                bh_assert(tbl_idx < module->table_count);

                tbl_inst = wasm_get_table_inst(module, tbl_idx);

                elem_val = POP_I32();
                elem_idx = POP_I32();
                if (elem_idx >= tbl_inst->cur_size) {
                    wasm_set_exception(module, "out of bounds table access");
                    goto got_exception;
                }

                ((uint32 *)(tbl_inst->base_addr))[elem_idx] = elem_val;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_REF_NULL)
            {
                uint32 ref_type;
                read_leb_uint32(frame_ip, frame_ip_end, ref_type);
                PUSH_I32(NULL_REF);
                (void)ref_type;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_REF_IS_NULL)
            {
                uint32 ref_val;
                ref_val = POP_I32();
                PUSH_I32(ref_val == NULL_REF ? 1 : 0);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_REF_FUNC)
            {
                uint32 func_idx;
                read_leb_uint32(frame_ip, frame_ip_end, func_idx);
                PUSH_I32(func_idx);
                HANDLE_OP_END();
            }
#endif /* WASM_ENABLE_REF_TYPES */

            /* variable instructions */
            HANDLE_OP(WASM_OP_GET_LOCAL)
            {
                GET_LOCAL_INDEX_TYPE_AND_OFFSET();

                switch (local_type) {
                    case VALUE_TYPE_I32:
                    case VALUE_TYPE_F32:
#if WASM_ENABLE_REF_TYPES != 0
                    case VALUE_TYPE_FUNCREF:
                    case VALUE_TYPE_EXTERNREF:
#endif
                        PUSH_I32(*(int32 *)(frame_lp + local_offset));
                        break;
                    case VALUE_TYPE_I64:
                    case VALUE_TYPE_F64:
                        PUSH_I64(GET_I64_FROM_ADDR(frame_lp + local_offset));
                        break;
                    default:
                        wasm_set_exception(module, "invalid local type");
                        goto got_exception;
                }

                HANDLE_OP_END();
            }

            HANDLE_OP(EXT_OP_GET_LOCAL_FAST)
            {
                local_offset = *frame_ip++;
                if (local_offset & 0x80)
                    PUSH_I64(
                        GET_I64_FROM_ADDR(frame_lp + (local_offset & 0x7F)));
                else
                    PUSH_I32(*(int32 *)(frame_lp + local_offset));
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_SET_LOCAL)
            {
                GET_LOCAL_INDEX_TYPE_AND_OFFSET();

                switch (local_type) {
                    case VALUE_TYPE_I32:
                    case VALUE_TYPE_F32:
#if WASM_ENABLE_REF_TYPES != 0
                    case VALUE_TYPE_FUNCREF:
                    case VALUE_TYPE_EXTERNREF:
#endif
                        *(int32 *)(frame_lp + local_offset) = POP_I32();
                        break;
                    case VALUE_TYPE_I64:
                    case VALUE_TYPE_F64:
                        PUT_I64_TO_ADDR((uint32 *)(frame_lp + local_offset),
                                        POP_I64());
                        break;
                    default:
                        wasm_set_exception(module, "invalid local type");
                        goto got_exception;
                }

                HANDLE_OP_END();
            }

            HANDLE_OP(EXT_OP_SET_LOCAL_FAST)
            {
                local_offset = *frame_ip++;
                if (local_offset & 0x80)
                    PUT_I64_TO_ADDR(
                        (uint32 *)(frame_lp + (local_offset & 0x7F)),
                        POP_I64());
                else
                    *(int32 *)(frame_lp + local_offset) = POP_I32();
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_TEE_LOCAL)
            {
                GET_LOCAL_INDEX_TYPE_AND_OFFSET();

                switch (local_type) {
                    case VALUE_TYPE_I32:
                    case VALUE_TYPE_F32:
#if WASM_ENABLE_REF_TYPES != 0
                    case VALUE_TYPE_FUNCREF:
                    case VALUE_TYPE_EXTERNREF:
#endif
                        *(int32 *)(frame_lp + local_offset) =
                            *(int32 *)(frame_sp - 1);
                        break;
                    case VALUE_TYPE_I64:
                    case VALUE_TYPE_F64:
                        PUT_I64_TO_ADDR((uint32 *)(frame_lp + local_offset),
                                        GET_I64_FROM_ADDR(frame_sp - 2));
                        break;
                    default:
                        wasm_set_exception(module, "invalid local type");
                        goto got_exception;
                }

                HANDLE_OP_END();
            }

            HANDLE_OP(EXT_OP_TEE_LOCAL_FAST)
            {
                local_offset = *frame_ip++;
                if (local_offset & 0x80)
                    PUT_I64_TO_ADDR(
                        (uint32 *)(frame_lp + (local_offset & 0x7F)),
                        GET_I64_FROM_ADDR(frame_sp - 2));
                else
                    *(int32 *)(frame_lp + local_offset) =
                        *(int32 *)(frame_sp - 1);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_GET_GLOBAL)
            {
                read_leb_uint32(frame_ip, frame_ip_end, global_idx);
                bh_assert(global_idx < module->global_count);
                global = globals + global_idx;
                global_addr = get_global_addr(global_data, global);
                PUSH_I32(*(uint32 *)global_addr);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_GET_GLOBAL_64)
            {
                read_leb_uint32(frame_ip, frame_ip_end, global_idx);
                bh_assert(global_idx < module->global_count);
                global = globals + global_idx;
                global_addr = get_global_addr(global_data, global);
                PUSH_I64(GET_I64_FROM_ADDR((uint32 *)global_addr));
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_SET_GLOBAL)
            {
                read_leb_uint32(frame_ip, frame_ip_end, global_idx);
                bh_assert(global_idx < module->global_count);
                global = globals + global_idx;
                global_addr = get_global_addr(global_data, global);
                *(int32 *)global_addr = POP_I32();
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_SET_GLOBAL_AUX_STACK)
            {
                uint32 aux_stack_top;

                read_leb_uint32(frame_ip, frame_ip_end, global_idx);
                bh_assert(global_idx < module->global_count);
                global = globals + global_idx;
                global_addr = get_global_addr(global_data, global);
                aux_stack_top = *(uint32 *)(frame_sp - 1);
                if (aux_stack_top <= exec_env->aux_stack_boundary.boundary) {
                    wasm_set_exception(module, "wasm auxiliary stack overflow");
                    goto got_exception;
                }
                if (aux_stack_top > exec_env->aux_stack_bottom.bottom) {
                    wasm_set_exception(module,
                                       "wasm auxiliary stack underflow");
                    goto got_exception;
                }
                *(int32 *)global_addr = aux_stack_top;
                frame_sp--;
#if WASM_ENABLE_MEMORY_PROFILING != 0
                if (module->module->aux_stack_top_global_index != (uint32)-1) {
                    uint32 aux_stack_used = module->module->aux_stack_bottom
                                            - *(uint32 *)global_addr;
                    if (aux_stack_used > module->max_aux_stack_used)
                        module->max_aux_stack_used = aux_stack_used;
                }
#endif
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_SET_GLOBAL_64)
            {
                read_leb_uint32(frame_ip, frame_ip_end, global_idx);
                bh_assert(global_idx < module->global_count);
                global = globals + global_idx;
                global_addr = get_global_addr(global_data, global);
                PUT_I64_TO_ADDR((uint32 *)global_addr, POP_I64());
                HANDLE_OP_END();
            }

            /* memory load instructions */
            HANDLE_OP(WASM_OP_I32_LOAD)
            HANDLE_OP(WASM_OP_F32_LOAD)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(4);
                PUSH_I32(LOAD_I32(maddr));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_LOAD)
            HANDLE_OP(WASM_OP_F64_LOAD)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(8);
                PUSH_I64(LOAD_I64(maddr));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_LOAD8_S)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(1);
                PUSH_I32(sign_ext_8_32(*(int8 *)maddr));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_LOAD8_U)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(1);
                PUSH_I32((uint32)(*(uint8 *)maddr));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_LOAD16_S)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(2);
                PUSH_I32(sign_ext_16_32(LOAD_I16(maddr)));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_LOAD16_U)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(2);
                PUSH_I32((uint32)(LOAD_U16(maddr)));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_LOAD8_S)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(1);
                PUSH_I64(sign_ext_8_64(*(int8 *)maddr));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_LOAD8_U)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(1);
                PUSH_I64((uint64)(*(uint8 *)maddr));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_LOAD16_S)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(2);
                PUSH_I64(sign_ext_16_64(LOAD_I16(maddr)));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_LOAD16_U)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(2);
                PUSH_I64((uint64)(LOAD_U16(maddr)));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_LOAD32_S)
            {
                uint32 offset, flags, addr;

                opcode = *(frame_ip - 1);
                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(4);
                PUSH_I64(sign_ext_32_64(LOAD_I32(maddr)));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_LOAD32_U)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(4);
                PUSH_I64((uint64)(LOAD_U32(maddr)));
                (void)flags;
                HANDLE_OP_END();
            }

            /* memory store instructions */
            HANDLE_OP(WASM_OP_I32_STORE)
            HANDLE_OP(WASM_OP_F32_STORE)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                frame_sp--;
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(4);
                STORE_U32(maddr, frame_sp[1]);
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_STORE)
            HANDLE_OP(WASM_OP_F64_STORE)
            {
                uint32 offset, flags, addr;

                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                frame_sp -= 2;
                addr = POP_I32();
                CHECK_MEMORY_OVERFLOW(8);
                PUT_I64_TO_ADDR((uint32 *)maddr,
                                GET_I64_FROM_ADDR(frame_sp + 1));
                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_STORE8)
            HANDLE_OP(WASM_OP_I32_STORE16)
            {
                uint32 offset, flags, addr;
                uint32 sval;

                opcode = *(frame_ip - 1);
                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                sval = (uint32)POP_I32();
                addr = POP_I32();

                if (opcode == WASM_OP_I32_STORE8) {
                    CHECK_MEMORY_OVERFLOW(1);
                    *(uint8 *)maddr = (uint8)sval;
                }
                else {
                    CHECK_MEMORY_OVERFLOW(2);
                    STORE_U16(maddr, (uint16)sval);
                }

                (void)flags;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_STORE8)
            HANDLE_OP(WASM_OP_I64_STORE16)
            HANDLE_OP(WASM_OP_I64_STORE32)
            {
                uint32 offset, flags, addr;
                uint64 sval;

                opcode = *(frame_ip - 1);
                read_leb_uint32(frame_ip, frame_ip_end, flags);
                read_leb_uint32(frame_ip, frame_ip_end, offset);
                sval = (uint64)POP_I64();
                addr = POP_I32();

                if (opcode == WASM_OP_I64_STORE8) {
                    CHECK_MEMORY_OVERFLOW(1);
                    *(uint8 *)maddr = (uint8)sval;
                }
                else if (opcode == WASM_OP_I64_STORE16) {
                    CHECK_MEMORY_OVERFLOW(2);
                    STORE_U16(maddr, (uint16)sval);
                }
                else {
                    CHECK_MEMORY_OVERFLOW(4);
                    STORE_U32(maddr, (uint32)sval);
                }
                (void)flags;
                HANDLE_OP_END();
            }

            /* memory size and memory grow instructions */
            HANDLE_OP(WASM_OP_MEMORY_SIZE)
            {
                uint32 reserved;
                read_leb_uint32(frame_ip, frame_ip_end, reserved);
                PUSH_I32(memory->cur_page_count);
                (void)reserved;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_MEMORY_GROW)
            {
                uint32 reserved, delta,
                    prev_page_count = memory->cur_page_count;

                read_leb_uint32(frame_ip, frame_ip_end, reserved);
                delta = (uint32)POP_I32();

                if (!wasm_enlarge_memory(module, delta)) {
                    /* failed to memory.grow, return -1 */
                    PUSH_I32(-1);
                }
                else {
                    /* success, return previous page count */
                    PUSH_I32(prev_page_count);
                    /* update memory instance ptr and memory size */
                    memory = module->default_memory;
#if !defined(OS_ENABLE_HW_BOUND_CHECK)              \
    || WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0 \
    || WASM_ENABLE_BULK_MEMORY != 0
                    linear_mem_size =
                        num_bytes_per_page * memory->cur_page_count;
#endif
                }

                (void)reserved;
                HANDLE_OP_END();
            }

            /* constant instructions */
            HANDLE_OP(WASM_OP_I32_CONST)
            DEF_OP_I_CONST(int32, I32);
            HANDLE_OP_END();

            HANDLE_OP(WASM_OP_I64_CONST)
            DEF_OP_I_CONST(int64, I64);
            HANDLE_OP_END();

            HANDLE_OP(WASM_OP_F32_CONST)
            {
                uint8 *p_float = (uint8 *)frame_sp++;
                for (i = 0; i < sizeof(float32); i++)
                    *p_float++ = *frame_ip++;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_CONST)
            {
                uint8 *p_float = (uint8 *)frame_sp++;
                frame_sp++;
                for (i = 0; i < sizeof(float64); i++)
                    *p_float++ = *frame_ip++;
                HANDLE_OP_END();
            }

            /* comparison instructions of i32 */
            HANDLE_OP(WASM_OP_I32_EQZ)
            {
                DEF_OP_EQZ(I32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_EQ)
            {
                DEF_OP_CMP(uint32, I32, ==);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_NE)
            {
                DEF_OP_CMP(uint32, I32, !=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_LT_S)
            {
                DEF_OP_CMP(int32, I32, <);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_LT_U)
            {
                DEF_OP_CMP(uint32, I32, <);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_GT_S)
            {
                DEF_OP_CMP(int32, I32, >);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_GT_U)
            {
                DEF_OP_CMP(uint32, I32, >);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_LE_S)
            {
                DEF_OP_CMP(int32, I32, <=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_LE_U)
            {
                DEF_OP_CMP(uint32, I32, <=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_GE_S)
            {
                DEF_OP_CMP(int32, I32, >=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_GE_U)
            {
                DEF_OP_CMP(uint32, I32, >=);
                HANDLE_OP_END();
            }

            /* comparison instructions of i64 */
            HANDLE_OP(WASM_OP_I64_EQZ)
            {
                DEF_OP_EQZ(I64);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_EQ)
            {
                DEF_OP_CMP(uint64, I64, ==);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_NE)
            {
                DEF_OP_CMP(uint64, I64, !=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_LT_S)
            {
                DEF_OP_CMP(int64, I64, <);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_LT_U)
            {
                DEF_OP_CMP(uint64, I64, <);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_GT_S)
            {
                DEF_OP_CMP(int64, I64, >);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_GT_U)
            {
                DEF_OP_CMP(uint64, I64, >);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_LE_S)
            {
                DEF_OP_CMP(int64, I64, <=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_LE_U)
            {
                DEF_OP_CMP(uint64, I64, <=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_GE_S)
            {
                DEF_OP_CMP(int64, I64, >=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_GE_U)
            {
                DEF_OP_CMP(uint64, I64, >=);
                HANDLE_OP_END();
            }

            /* comparison instructions of f32 */
            HANDLE_OP(WASM_OP_F32_EQ)
            {
                DEF_OP_CMP(float32, F32, ==);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_NE)
            {
                DEF_OP_CMP(float32, F32, !=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_LT)
            {
                DEF_OP_CMP(float32, F32, <);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_GT)
            {
                DEF_OP_CMP(float32, F32, >);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_LE)
            {
                DEF_OP_CMP(float32, F32, <=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_GE)
            {
                DEF_OP_CMP(float32, F32, >=);
                HANDLE_OP_END();
            }

            /* comparison instructions of f64 */
            HANDLE_OP(WASM_OP_F64_EQ)
            {
                DEF_OP_CMP(float64, F64, ==);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_NE)
            {
                DEF_OP_CMP(float64, F64, !=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_LT)
            {
                DEF_OP_CMP(float64, F64, <);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_GT)
            {
                DEF_OP_CMP(float64, F64, >);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_LE)
            {
                DEF_OP_CMP(float64, F64, <=);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_GE)
            {
                DEF_OP_CMP(float64, F64, >=);
                HANDLE_OP_END();
            }

            /* numberic instructions of i32 */
            HANDLE_OP(WASM_OP_I32_CLZ)
            {
                DEF_OP_BIT_COUNT(uint32, I32, clz32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_CTZ)
            {
                DEF_OP_BIT_COUNT(uint32, I32, ctz32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_POPCNT)
            {
                DEF_OP_BIT_COUNT(uint32, I32, popcount32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_ADD)
            {
                DEF_OP_NUMERIC(uint32, uint32, I32, +);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_SUB)
            {
                DEF_OP_NUMERIC(uint32, uint32, I32, -);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_MUL)
            {
                DEF_OP_NUMERIC(uint32, uint32, I32, *);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_DIV_S)
            {
                int32 a, b;

                b = POP_I32();
                a = POP_I32();
                if (a == (int32)0x80000000 && b == -1) {
                    wasm_set_exception(module, "integer overflow");
                    goto got_exception;
                }
                if (b == 0) {
                    wasm_set_exception(module, "integer divide by zero");
                    goto got_exception;
                }
                PUSH_I32(a / b);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_DIV_U)
            {
                uint32 a, b;

                b = (uint32)POP_I32();
                a = (uint32)POP_I32();
                if (b == 0) {
                    wasm_set_exception(module, "integer divide by zero");
                    goto got_exception;
                }
                PUSH_I32(a / b);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_REM_S)
            {
                int32 a, b;

                b = POP_I32();
                a = POP_I32();
                if (a == (int32)0x80000000 && b == -1) {
                    PUSH_I32(0);
                    HANDLE_OP_END();
                }
                if (b == 0) {
                    wasm_set_exception(module, "integer divide by zero");
                    goto got_exception;
                }
                PUSH_I32(a % b);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_REM_U)
            {
                uint32 a, b;

                b = (uint32)POP_I32();
                a = (uint32)POP_I32();
                if (b == 0) {
                    wasm_set_exception(module, "integer divide by zero");
                    goto got_exception;
                }
                PUSH_I32(a % b);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_AND)
            {
                DEF_OP_NUMERIC(uint32, uint32, I32, &);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_OR)
            {
                DEF_OP_NUMERIC(uint32, uint32, I32, |);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_XOR)
            {
                DEF_OP_NUMERIC(uint32, uint32, I32, ^);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_SHL)
            {
                DEF_OP_NUMERIC2(uint32, uint32, I32, <<);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_SHR_S)
            {
                DEF_OP_NUMERIC2(int32, uint32, I32, >>);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_SHR_U)
            {
                DEF_OP_NUMERIC2(uint32, uint32, I32, >>);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_ROTL)
            {
                uint32 a, b;

                b = (uint32)POP_I32();
                a = (uint32)POP_I32();
                PUSH_I32(rotl32(a, b));
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_ROTR)
            {
                uint32 a, b;

                b = (uint32)POP_I32();
                a = (uint32)POP_I32();
                PUSH_I32(rotr32(a, b));
                HANDLE_OP_END();
            }

            /* numberic instructions of i64 */
            HANDLE_OP(WASM_OP_I64_CLZ)
            {
                DEF_OP_BIT_COUNT(uint64, I64, clz64);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_CTZ)
            {
                DEF_OP_BIT_COUNT(uint64, I64, ctz64);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_POPCNT)
            {
                DEF_OP_BIT_COUNT(uint64, I64, popcount64);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_ADD)
            {
                DEF_OP_NUMERIC_64(uint64, uint64, I64, +);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_SUB)
            {
                DEF_OP_NUMERIC_64(uint64, uint64, I64, -);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_MUL)
            {
                DEF_OP_NUMERIC_64(uint64, uint64, I64, *);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_DIV_S)
            {
                int64 a, b;

                b = POP_I64();
                a = POP_I64();
                if (a == (int64)0x8000000000000000LL && b == -1) {
                    wasm_set_exception(module, "integer overflow");
                    goto got_exception;
                }
                if (b == 0) {
                    wasm_set_exception(module, "integer divide by zero");
                    goto got_exception;
                }
                PUSH_I64(a / b);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_DIV_U)
            {
                uint64 a, b;

                b = (uint64)POP_I64();
                a = (uint64)POP_I64();
                if (b == 0) {
                    wasm_set_exception(module, "integer divide by zero");
                    goto got_exception;
                }
                PUSH_I64(a / b);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_REM_S)
            {
                int64 a, b;

                b = POP_I64();
                a = POP_I64();
                if (a == (int64)0x8000000000000000LL && b == -1) {
                    PUSH_I64(0);
                    HANDLE_OP_END();
                }
                if (b == 0) {
                    wasm_set_exception(module, "integer divide by zero");
                    goto got_exception;
                }
                PUSH_I64(a % b);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_REM_U)
            {
                uint64 a, b;

                b = (uint64)POP_I64();
                a = (uint64)POP_I64();
                if (b == 0) {
                    wasm_set_exception(module, "integer divide by zero");
                    goto got_exception;
                }
                PUSH_I64(a % b);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_AND)
            {
                DEF_OP_NUMERIC_64(uint64, uint64, I64, &);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_OR)
            {
                DEF_OP_NUMERIC_64(uint64, uint64, I64, |);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_XOR)
            {
                DEF_OP_NUMERIC_64(uint64, uint64, I64, ^);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_SHL)
            {
                DEF_OP_NUMERIC2_64(uint64, uint64, I64, <<);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_SHR_S)
            {
                DEF_OP_NUMERIC2_64(int64, uint64, I64, >>);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_SHR_U)
            {
                DEF_OP_NUMERIC2_64(uint64, uint64, I64, >>);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_ROTL)
            {
                uint64 a, b;

                b = (uint64)POP_I64();
                a = (uint64)POP_I64();
                PUSH_I64(rotl64(a, b));
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_ROTR)
            {
                uint64 a, b;

                b = (uint64)POP_I64();
                a = (uint64)POP_I64();
                PUSH_I64(rotr64(a, b));
                HANDLE_OP_END();
            }

            /* numberic instructions of f32 */
            HANDLE_OP(WASM_OP_F32_ABS)
            {
                DEF_OP_MATH(float32, F32, fabsf);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_NEG)
            {
                uint32 u32 = frame_sp[-1];
                uint32 sign_bit = u32 & ((uint32)1 << 31);
                if (sign_bit)
                    frame_sp[-1] = u32 & ~((uint32)1 << 31);
                else
                    frame_sp[-1] = u32 | ((uint32)1 << 31);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_CEIL)
            {
                DEF_OP_MATH(float32, F32, ceilf);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_FLOOR)
            {
                DEF_OP_MATH(float32, F32, floorf);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_TRUNC)
            {
                DEF_OP_MATH(float32, F32, truncf);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_NEAREST)
            {
                DEF_OP_MATH(float32, F32, rintf);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_SQRT)
            {
                DEF_OP_MATH(float32, F32, sqrtf);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_ADD)
            {
                DEF_OP_NUMERIC(float32, float32, F32, +);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_SUB)
            {
                DEF_OP_NUMERIC(float32, float32, F32, -);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_MUL)
            {
                DEF_OP_NUMERIC(float32, float32, F32, *);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_DIV)
            {
                DEF_OP_NUMERIC(float32, float32, F32, /);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_MIN)
            {
                float32 a, b;

                b = POP_F32();
                a = POP_F32();

                if (isnan(a))
                    PUSH_F32(a);
                else if (isnan(b))
                    PUSH_F32(b);
                else
                    PUSH_F32(wa_fmin(a, b));
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_MAX)
            {
                float32 a, b;

                b = POP_F32();
                a = POP_F32();

                if (isnan(a))
                    PUSH_F32(a);
                else if (isnan(b))
                    PUSH_F32(b);
                else
                    PUSH_F32(wa_fmax(a, b));
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_COPYSIGN)
            {
                float32 a, b;

                b = POP_F32();
                a = POP_F32();
                PUSH_F32(local_copysignf(a, b));
                HANDLE_OP_END();
            }

            /* numberic instructions of f64 */
            HANDLE_OP(WASM_OP_F64_ABS)
            {
                DEF_OP_MATH(float64, F64, fabs);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_NEG)
            {
                uint64 u64 = GET_I64_FROM_ADDR(frame_sp - 2);
                uint64 sign_bit = u64 & (((uint64)1) << 63);
                if (sign_bit)
                    PUT_I64_TO_ADDR(frame_sp - 2, (u64 & ~(((uint64)1) << 63)));
                else
                    PUT_I64_TO_ADDR(frame_sp - 2, (u64 | (((uint64)1) << 63)));
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_CEIL)
            {
                DEF_OP_MATH(float64, F64, ceil);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_FLOOR)
            {
                DEF_OP_MATH(float64, F64, floor);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_TRUNC)
            {
                DEF_OP_MATH(float64, F64, trunc);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_NEAREST)
            {
                DEF_OP_MATH(float64, F64, rint);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_SQRT)
            {
                DEF_OP_MATH(float64, F64, sqrt);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_ADD)
            {
                DEF_OP_NUMERIC_64(float64, float64, F64, +);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_SUB)
            {
                DEF_OP_NUMERIC_64(float64, float64, F64, -);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_MUL)
            {
                DEF_OP_NUMERIC_64(float64, float64, F64, *);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_DIV)
            {
                DEF_OP_NUMERIC_64(float64, float64, F64, /);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_MIN)
            {
                float64 a, b;

                b = POP_F64();
                a = POP_F64();

                if (isnan(a))
                    PUSH_F64(a);
                else if (isnan(b))
                    PUSH_F64(b);
                else
                    PUSH_F64(wa_fmin(a, b));
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_MAX)
            {
                float64 a, b;

                b = POP_F64();
                a = POP_F64();

                if (isnan(a))
                    PUSH_F64(a);
                else if (isnan(b))
                    PUSH_F64(b);
                else
                    PUSH_F64(wa_fmax(a, b));
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_COPYSIGN)
            {
                float64 a, b;

                b = POP_F64();
                a = POP_F64();
                PUSH_F64(local_copysign(a, b));
                HANDLE_OP_END();
            }

            /* conversions of i32 */
            HANDLE_OP(WASM_OP_I32_WRAP_I64)
            {
                int32 value = (int32)(POP_I64() & 0xFFFFFFFFLL);
                PUSH_I32(value);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_TRUNC_S_F32)
            {
                /* We don't use INT32_MIN/INT32_MAX/UINT32_MIN/UINT32_MAX,
                   since float/double values of ieee754 cannot precisely
                   represent all int32/uint32/int64/uint64 values, e.g.
                   UINT32_MAX is 4294967295, but (float32)4294967295 is
                   4294967296.0f, but not 4294967295.0f. */
                DEF_OP_TRUNC_F32(-2147483904.0f, 2147483648.0f, true, true);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_TRUNC_U_F32)
            {
                DEF_OP_TRUNC_F32(-1.0f, 4294967296.0f, true, false);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_TRUNC_S_F64)
            {
                DEF_OP_TRUNC_F64(-2147483649.0, 2147483648.0, true, true);
                /* frame_sp can't be moved in trunc function, we need to
                  manually adjust it if src and dst op's cell num is
                  different */
                frame_sp--;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_TRUNC_U_F64)
            {
                DEF_OP_TRUNC_F64(-1.0, 4294967296.0, true, false);
                frame_sp--;
                HANDLE_OP_END();
            }

            /* conversions of i64 */
            HANDLE_OP(WASM_OP_I64_EXTEND_S_I32)
            {
                DEF_OP_CONVERT(int64, I64, int32, I32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_EXTEND_U_I32)
            {
                DEF_OP_CONVERT(int64, I64, uint32, I32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_TRUNC_S_F32)
            {
                DEF_OP_TRUNC_F32(-9223373136366403584.0f,
                                 9223372036854775808.0f, false, true);
                frame_sp++;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_TRUNC_U_F32)
            {
                DEF_OP_TRUNC_F32(-1.0f, 18446744073709551616.0f, false, false);
                frame_sp++;
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_TRUNC_S_F64)
            {
                DEF_OP_TRUNC_F64(-9223372036854777856.0, 9223372036854775808.0,
                                 false, true);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_TRUNC_U_F64)
            {
                DEF_OP_TRUNC_F64(-1.0, 18446744073709551616.0, false, false);
                HANDLE_OP_END();
            }

            /* conversions of f32 */
            HANDLE_OP(WASM_OP_F32_CONVERT_S_I32)
            {
                DEF_OP_CONVERT(float32, F32, int32, I32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_CONVERT_U_I32)
            {
                DEF_OP_CONVERT(float32, F32, uint32, I32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_CONVERT_S_I64)
            {
                DEF_OP_CONVERT(float32, F32, int64, I64);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_CONVERT_U_I64)
            {
                DEF_OP_CONVERT(float32, F32, uint64, I64);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F32_DEMOTE_F64)
            {
                DEF_OP_CONVERT(float32, F32, float64, F64);
                HANDLE_OP_END();
            }

            /* conversions of f64 */
            HANDLE_OP(WASM_OP_F64_CONVERT_S_I32)
            {
                DEF_OP_CONVERT(float64, F64, int32, I32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_CONVERT_U_I32)
            {
                DEF_OP_CONVERT(float64, F64, uint32, I32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_CONVERT_S_I64)
            {
                DEF_OP_CONVERT(float64, F64, int64, I64);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_CONVERT_U_I64)
            {
                DEF_OP_CONVERT(float64, F64, uint64, I64);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_F64_PROMOTE_F32)
            {
                DEF_OP_CONVERT(float64, F64, float32, F32);
                HANDLE_OP_END();
            }

            /* reinterpretations */
            HANDLE_OP(WASM_OP_I32_REINTERPRET_F32)
            HANDLE_OP(WASM_OP_I64_REINTERPRET_F64)
            HANDLE_OP(WASM_OP_F32_REINTERPRET_I32)
            HANDLE_OP(WASM_OP_F64_REINTERPRET_I64) { HANDLE_OP_END(); }

            HANDLE_OP(WASM_OP_I32_EXTEND8_S)
            {
                DEF_OP_CONVERT(int32, I32, int8, I32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I32_EXTEND16_S)
            {
                DEF_OP_CONVERT(int32, I32, int16, I32);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_EXTEND8_S)
            {
                DEF_OP_CONVERT(int64, I64, int8, I64);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_EXTEND16_S)
            {
                DEF_OP_CONVERT(int64, I64, int16, I64);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_I64_EXTEND32_S)
            {
                DEF_OP_CONVERT(int64, I64, int32, I64);
                HANDLE_OP_END();
            }

            HANDLE_OP(WASM_OP_MISC_PREFIX)
            {
                uint32 opcode1;

                read_leb_uint32(frame_ip, frame_ip_end, opcode1);
                opcode = (uint8)opcode1;

                switch (opcode) {
                    case WASM_OP_I32_TRUNC_SAT_S_F32:
                        DEF_OP_TRUNC_SAT_F32(-2147483904.0f, 2147483648.0f,
                                             true, true);
                        break;
                    case WASM_OP_I32_TRUNC_SAT_U_F32:
                        DEF_OP_TRUNC_SAT_F32(-1.0f, 4294967296.0f, true, false);
                        break;
                    case WASM_OP_I32_TRUNC_SAT_S_F64:
                        DEF_OP_TRUNC_SAT_F64(-2147483649.0, 2147483648.0, true,
                                             true);
                        frame_sp--;
                        break;
                    case WASM_OP_I32_TRUNC_SAT_U_F64:
                        DEF_OP_TRUNC_SAT_F64(-1.0, 4294967296.0, true, false);
                        frame_sp--;
                        break;
                    case WASM_OP_I64_TRUNC_SAT_S_F32:
                        DEF_OP_TRUNC_SAT_F32(-9223373136366403584.0f,
                                             9223372036854775808.0f, false,
                                             true);
                        frame_sp++;
                        break;
                    case WASM_OP_I64_TRUNC_SAT_U_F32:
                        DEF_OP_TRUNC_SAT_F32(-1.0f, 18446744073709551616.0f,
                                             false, false);
                        frame_sp++;
                        break;
                    case WASM_OP_I64_TRUNC_SAT_S_F64:
                        DEF_OP_TRUNC_SAT_F64(-9223372036854777856.0,
                                             9223372036854775808.0, false,
                                             true);
                        break;
                    case WASM_OP_I64_TRUNC_SAT_U_F64:
                        DEF_OP_TRUNC_SAT_F64(-1.0f, 18446744073709551616.0,
                                             false, false);
                        break;
#if WASM_ENABLE_BULK_MEMORY != 0
                    case WASM_OP_MEMORY_INIT:
                    {
                        uint32 addr, segment;
                        uint64 bytes, offset, seg_len;
                        uint8 *data;

                        read_leb_uint32(frame_ip, frame_ip_end, segment);
                        /* skip memory index */
                        frame_ip++;

                        bytes = (uint64)(uint32)POP_I32();
                        offset = (uint64)(uint32)POP_I32();
                        addr = (uint32)POP_I32();

#ifndef OS_ENABLE_HW_BOUND_CHECK
                        CHECK_BULK_MEMORY_OVERFLOW(addr, bytes, maddr);
#else
                        if ((uint64)(uint32)addr + bytes
                            > (uint64)linear_mem_size)
                            goto out_of_bounds;
                        maddr = memory->memory_data + (uint32)addr;
#endif

                        seg_len = (uint64)module->module->data_segments[segment]
                                      ->data_length;
                        data = module->module->data_segments[segment]->data;
                        if (offset + bytes > seg_len)
                            goto out_of_bounds;

                        bh_memcpy_s(maddr, linear_mem_size - addr,
                                    data + offset, (uint32)bytes);
                        break;
                    }
                    case WASM_OP_DATA_DROP:
                    {
                        uint32 segment;

                        read_leb_uint32(frame_ip, frame_ip_end, segment);
                        module->module->data_segments[segment]->data_length = 0;
                        break;
                    }
                    case WASM_OP_MEMORY_COPY:
                    {
                        uint32 dst, src, len;
                        uint8 *mdst, *msrc;

                        frame_ip += 2;

                        len = POP_I32();
                        src = POP_I32();
                        dst = POP_I32();

#ifndef OS_ENABLE_HW_BOUND_CHECK
                        CHECK_BULK_MEMORY_OVERFLOW(src, len, msrc);
                        CHECK_BULK_MEMORY_OVERFLOW(dst, len, mdst);
#else
                        if ((uint64)(uint32)src + len > (uint64)linear_mem_size)
                            goto out_of_bounds;
                        msrc = memory->memory_data + (uint32)src;

                        if ((uint64)(uint32)dst + len > (uint64)linear_mem_size)
                            goto out_of_bounds;
                        mdst = memory->memory_data + (uint32)dst;
#endif

                        /* allowing the destination and source to overlap */
                        bh_memmove_s(mdst, linear_mem_size - dst, msrc, len);
                        break;
                    }
                    case WASM_OP_MEMORY_FILL:
                    {
                        uint32 dst, len;
                        uint8 fill_val, *mdst;
                        frame_ip++;

                        len = POP_I32();
                        fill_val = POP_I32();
                        dst = POP_I32();

#ifndef OS_ENABLE_HW_BOUND_CHECK
                        CHECK_BULK_MEMORY_OVERFLOW(dst, len, mdst);
#else
                        if ((uint64)(uint32)dst + len > (uint64)linear_mem_size)
                            goto out_of_bounds;
                        mdst = memory->memory_data + (uint32)dst;
#endif

                        memset(mdst, fill_val, len);
                        break;
                    }
#endif /* WASM_ENABLE_BULK_MEMORY */
#if WASM_ENABLE_REF_TYPES != 0
                    case WASM_OP_TABLE_INIT:
                    {
                        uint32 tbl_idx, elem_idx;
                        uint64 n, s, d;
                        WASMTableInstance *tbl_inst;

                        read_leb_uint32(frame_ip, frame_ip_end, elem_idx);
                        bh_assert(elem_idx < module->module->table_seg_count);

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        bh_assert(tbl_idx < module->module->table_count);

                        tbl_inst = wasm_get_table_inst(module, tbl_idx);

                        n = (uint32)POP_I32();
                        s = (uint32)POP_I32();
                        d = (uint32)POP_I32();

                        /* TODO: what if the element is not passive? */

                        if (!n) {
                            break;
                        }

                        if (n + s > module->module->table_segments[elem_idx]
                                        .function_count
                            || d + n > tbl_inst->cur_size) {
                            wasm_set_exception(module,
                                               "out of bounds table access");
                            goto got_exception;
                        }

                        if (module->module->table_segments[elem_idx]
                                .is_dropped) {
                            wasm_set_exception(module,
                                               "out of bounds table access");
                            goto got_exception;
                        }

                        if (!wasm_elem_is_passive(
                                module->module->table_segments[elem_idx]
                                    .mode)) {
                            wasm_set_exception(module,
                                               "out of bounds table access");
                            goto got_exception;
                        }

                        bh_memcpy_s(
                            (uint8 *)(tbl_inst)
                                + offsetof(WASMTableInstance, base_addr)
                                + d * sizeof(uint32),
                            (uint32)((tbl_inst->cur_size - d) * sizeof(uint32)),
                            module->module->table_segments[elem_idx]
                                    .func_indexes
                                + s,
                            (uint32)(n * sizeof(uint32)));

                        break;
                    }
                    case WASM_OP_ELEM_DROP:
                    {
                        uint32 elem_idx;
                        read_leb_uint32(frame_ip, frame_ip_end, elem_idx);
                        bh_assert(elem_idx < module->module->table_seg_count);

                        module->module->table_segments[elem_idx].is_dropped =
                            true;
                        break;
                    }
                    case WASM_OP_TABLE_COPY:
                    {
                        uint32 src_tbl_idx, dst_tbl_idx;
                        uint64 n, s, d;
                        WASMTableInstance *src_tbl_inst, *dst_tbl_inst;

                        read_leb_uint32(frame_ip, frame_ip_end, dst_tbl_idx);
                        bh_assert(dst_tbl_idx < module->table_count);

                        dst_tbl_inst = wasm_get_table_inst(module, dst_tbl_idx);

                        read_leb_uint32(frame_ip, frame_ip_end, src_tbl_idx);
                        bh_assert(src_tbl_idx < module->table_count);

                        src_tbl_inst = wasm_get_table_inst(module, src_tbl_idx);

                        n = (uint32)POP_I32();
                        s = (uint32)POP_I32();
                        d = (uint32)POP_I32();

                        if (d + n > dst_tbl_inst->cur_size
                            || s + n > src_tbl_inst->cur_size) {
                            wasm_set_exception(module,
                                               "out of bounds table access");
                            goto got_exception;
                        }

                        /* if s >= d, copy from front to back */
                        /* if s < d, copy from back to front */
                        /* merge all together */
                        bh_memmove_s(
                            (uint8 *)(dst_tbl_inst)
                                + offsetof(WASMTableInstance, base_addr)
                                + d * sizeof(uint32),
                            (uint32)((dst_tbl_inst->cur_size - d)
                                     * sizeof(uint32)),
                            (uint8 *)(src_tbl_inst)
                                + offsetof(WASMTableInstance, base_addr)
                                + s * sizeof(uint32),
                            (uint32)(n * sizeof(uint32)));
                        break;
                    }
                    case WASM_OP_TABLE_GROW:
                    {
                        uint32 tbl_idx, n, init_val, orig_tbl_sz;
                        WASMTableInstance *tbl_inst;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        bh_assert(tbl_idx < module->table_count);

                        tbl_inst = wasm_get_table_inst(module, tbl_idx);

                        orig_tbl_sz = tbl_inst->cur_size;

                        n = POP_I32();
                        init_val = POP_I32();

                        if (!wasm_enlarge_table(module, tbl_idx, n, init_val)) {
                            PUSH_I32(-1);
                        }
                        else {
                            PUSH_I32(orig_tbl_sz);
                        }
                        break;
                    }
                    case WASM_OP_TABLE_SIZE:
                    {
                        uint32 tbl_idx;
                        WASMTableInstance *tbl_inst;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        bh_assert(tbl_idx < module->table_count);

                        tbl_inst = wasm_get_table_inst(module, tbl_idx);

                        PUSH_I32(tbl_inst->cur_size);
                        break;
                    }
                    case WASM_OP_TABLE_FILL:
                    {
                        uint32 tbl_idx, n, fill_val;
                        WASMTableInstance *tbl_inst;

                        read_leb_uint32(frame_ip, frame_ip_end, tbl_idx);
                        bh_assert(tbl_idx < module->table_count);

                        tbl_inst = wasm_get_table_inst(module, tbl_idx);

                        n = POP_I32();
                        fill_val = POP_I32();
                        i = POP_I32();

                        /* TODO: what if the element is not passive? */
                        /* TODO: what if the element is dropped? */

                        if (i + n > tbl_inst->cur_size) {
                            /* TODO: verify warning content */
                            wasm_set_exception(module,
                                               "out of bounds table access");
                            goto got_exception;
                        }

                        for (; n != 0; i++, n--) {
                            ((uint32 *)(tbl_inst->base_addr))[i] = fill_val;
                        }

                        break;
                    }
#endif /* WASM_ENABLE_REF_TYPES */
                    default:
                        wasm_set_exception(module, "unsupported opcode");
                        goto got_exception;
                }
                HANDLE_OP_END();
            }

#if WASM_ENABLE_SHARED_MEMORY != 0
            HANDLE_OP(WASM_OP_ATOMIC_PREFIX)
            {
                uint32 offset = 0, align, addr;

                opcode = *frame_ip++;

                if (opcode != WASM_OP_ATOMIC_FENCE) {
                    read_leb_uint32(frame_ip, frame_ip_end, align);
                    read_leb_uint32(frame_ip, frame_ip_end, offset);
                }

                switch (opcode) {
                    case WASM_OP_ATOMIC_NOTIFY:
                    {
                        uint32 notify_count, ret;

                        notify_count = POP_I32();
                        addr = POP_I32();
                        CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 4, maddr);
                        CHECK_ATOMIC_MEMORY_ACCESS();

                        ret = wasm_runtime_atomic_notify(
                            (WASMModuleInstanceCommon *)module, maddr,
                            notify_count);
                        bh_assert((int32)ret >= 0);

                        PUSH_I32(ret);
                        break;
                    }
                    case WASM_OP_ATOMIC_WAIT32:
                    {
                        uint64 timeout;
                        uint32 expect, ret;

                        timeout = POP_I64();
                        expect = POP_I32();
                        addr = POP_I32();
                        CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 4, maddr);
                        CHECK_ATOMIC_MEMORY_ACCESS();

                        ret = wasm_runtime_atomic_wait(
                            (WASMModuleInstanceCommon *)module, maddr,
                            (uint64)expect, timeout, false);
                        if (ret == (uint32)-1)
                            goto got_exception;

                        PUSH_I32(ret);
                        break;
                    }
                    case WASM_OP_ATOMIC_WAIT64:
                    {
                        uint64 timeout, expect;
                        uint32 ret;

                        timeout = POP_I64();
                        expect = POP_I64();
                        addr = POP_I32();
                        CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 8, maddr);
                        CHECK_ATOMIC_MEMORY_ACCESS();

                        ret = wasm_runtime_atomic_wait(
                            (WASMModuleInstanceCommon *)module, maddr, expect,
                            timeout, true);
                        if (ret == (uint32)-1)
                            goto got_exception;

                        PUSH_I32(ret);
                        break;
                    }
                    case WASM_OP_ATOMIC_FENCE:
                    {
                        /* Skip the memory index */
                        frame_ip++;
                        break;
                    }

                    case WASM_OP_ATOMIC_I32_LOAD:
                    case WASM_OP_ATOMIC_I32_LOAD8_U:
                    case WASM_OP_ATOMIC_I32_LOAD16_U:
                    {
                        uint32 readv;

                        addr = POP_I32();

                        if (opcode == WASM_OP_ATOMIC_I32_LOAD8_U) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 1, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            readv = (uint32)(*(uint8 *)maddr);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else if (opcode == WASM_OP_ATOMIC_I32_LOAD16_U) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 2, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            readv = (uint32)LOAD_U16(maddr);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 4, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            readv = LOAD_I32(maddr);
                            os_mutex_unlock(&memory->mem_lock);
                        }

                        PUSH_I32(readv);
                        break;
                    }

                    case WASM_OP_ATOMIC_I64_LOAD:
                    case WASM_OP_ATOMIC_I64_LOAD8_U:
                    case WASM_OP_ATOMIC_I64_LOAD16_U:
                    case WASM_OP_ATOMIC_I64_LOAD32_U:
                    {
                        uint64 readv;

                        addr = POP_I32();

                        if (opcode == WASM_OP_ATOMIC_I64_LOAD8_U) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 1, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            readv = (uint64)(*(uint8 *)maddr);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else if (opcode == WASM_OP_ATOMIC_I64_LOAD16_U) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 2, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            readv = (uint64)LOAD_U16(maddr);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else if (opcode == WASM_OP_ATOMIC_I64_LOAD32_U) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 4, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            readv = (uint64)LOAD_U32(maddr);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 8, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            readv = LOAD_I64(maddr);
                            os_mutex_unlock(&memory->mem_lock);
                        }

                        PUSH_I64(readv);
                        break;
                    }

                    case WASM_OP_ATOMIC_I32_STORE:
                    case WASM_OP_ATOMIC_I32_STORE8:
                    case WASM_OP_ATOMIC_I32_STORE16:
                    {
                        uint32 sval;

                        sval = (uint32)POP_I32();
                        addr = POP_I32();

                        if (opcode == WASM_OP_ATOMIC_I32_STORE8) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 1, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            *(uint8 *)maddr = (uint8)sval;
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else if (opcode == WASM_OP_ATOMIC_I32_STORE16) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 2, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            STORE_U16(maddr, (uint16)sval);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 4, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            STORE_U32(maddr, frame_sp[1]);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        break;
                    }

                    case WASM_OP_ATOMIC_I64_STORE:
                    case WASM_OP_ATOMIC_I64_STORE8:
                    case WASM_OP_ATOMIC_I64_STORE16:
                    case WASM_OP_ATOMIC_I64_STORE32:
                    {
                        uint64 sval;

                        sval = (uint64)POP_I64();
                        addr = POP_I32();

                        if (opcode == WASM_OP_ATOMIC_I64_STORE8) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 1, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            *(uint8 *)maddr = (uint8)sval;
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else if (opcode == WASM_OP_ATOMIC_I64_STORE16) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 2, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            STORE_U16(maddr, (uint16)sval);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else if (opcode == WASM_OP_ATOMIC_I64_STORE32) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 4, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            STORE_U32(maddr, (uint32)sval);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 8, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();
                            os_mutex_lock(&memory->mem_lock);
                            PUT_I64_TO_ADDR((uint32 *)maddr,
                                            GET_I64_FROM_ADDR(frame_sp + 1));
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        break;
                    }

                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG:
                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG8_U:
                    case WASM_OP_ATOMIC_RMW_I32_CMPXCHG16_U:
                    {
                        uint32 readv, sval, expect;

                        sval = POP_I32();
                        expect = POP_I32();
                        addr = POP_I32();

                        if (opcode == WASM_OP_ATOMIC_RMW_I32_CMPXCHG8_U) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 1, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();

                            expect = (uint8)expect;
                            os_mutex_lock(&memory->mem_lock);
                            readv = (uint32)(*(uint8 *)maddr);
                            if (readv == expect)
                                *(uint8 *)maddr = (uint8)(sval);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else if (opcode == WASM_OP_ATOMIC_RMW_I32_CMPXCHG16_U) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 2, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();

                            expect = (uint16)expect;
                            os_mutex_lock(&memory->mem_lock);
                            readv = (uint32)LOAD_U16(maddr);
                            if (readv == expect)
                                STORE_U16(maddr, (uint16)(sval));
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 4, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();

                            os_mutex_lock(&memory->mem_lock);
                            readv = LOAD_I32(maddr);
                            if (readv == expect)
                                STORE_U32(maddr, sval);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        PUSH_I32(readv);
                        break;
                    }
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG:
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG8_U:
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG16_U:
                    case WASM_OP_ATOMIC_RMW_I64_CMPXCHG32_U:
                    {
                        uint64 readv, sval, expect;

                        sval = (uint64)POP_I64();
                        expect = (uint64)POP_I64();
                        addr = POP_I32();

                        if (opcode == WASM_OP_ATOMIC_RMW_I64_CMPXCHG8_U) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 1, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();

                            expect = (uint8)expect;
                            os_mutex_lock(&memory->mem_lock);
                            readv = (uint64)(*(uint8 *)maddr);
                            if (readv == expect)
                                *(uint8 *)maddr = (uint8)(sval);
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else if (opcode == WASM_OP_ATOMIC_RMW_I64_CMPXCHG16_U) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 2, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();

                            expect = (uint16)expect;
                            os_mutex_lock(&memory->mem_lock);
                            readv = (uint64)LOAD_U16(maddr);
                            if (readv == expect)
                                STORE_U16(maddr, (uint16)(sval));
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else if (opcode == WASM_OP_ATOMIC_RMW_I64_CMPXCHG32_U) {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 4, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();

                            expect = (uint32)expect;
                            os_mutex_lock(&memory->mem_lock);
                            readv = (uint64)LOAD_U32(maddr);
                            if (readv == expect)
                                STORE_U32(maddr, (uint32)(sval));
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        else {
                            CHECK_BULK_MEMORY_OVERFLOW(addr + offset, 8, maddr);
                            CHECK_ATOMIC_MEMORY_ACCESS();

                            os_mutex_lock(&memory->mem_lock);
                            readv = (uint64)LOAD_I64(maddr);
                            if (readv == expect) {
                                STORE_I64(maddr, sval);
                            }
                            os_mutex_unlock(&memory->mem_lock);
                        }
                        PUSH_I64(readv);
                        break;
                    }

                        DEF_ATOMIC_RMW_OPCODE(ADD, +);
                        DEF_ATOMIC_RMW_OPCODE(SUB, -);
                        DEF_ATOMIC_RMW_OPCODE(AND, &);
                        DEF_ATOMIC_RMW_OPCODE(OR, |);
                        DEF_ATOMIC_RMW_OPCODE(XOR, ^);
                        /* xchg, ignore the read value, and store the given
                          value: readv * 0 + sval */
                        DEF_ATOMIC_RMW_OPCODE(XCHG, *0 +);
                }

                HANDLE_OP_END();
            }
#endif

            HANDLE_OP(WASM_OP_IMPDEP)
            {
                frame = prev_frame;
                frame_ip = frame->ip;
                frame_sp = frame->sp;
                frame_csp = frame->csp;
                goto call_func_from_entry;
            }

#if WASM_ENABLE_DEBUG_INTERP != 0
            HANDLE_OP(DEBUG_OP_BREAK)
            {
                wasm_cluster_thread_send_signal(exec_env, WAMR_SIG_TRAP);
                exec_env->suspend_flags.flags |= 2;
                frame_ip--;
                SYNC_ALL_TO_FRAME();
                CHECK_SUSPEND_FLAGS();
                HANDLE_OP_END();
            }
#endif
#if WASM_ENABLE_LABELS_AS_VALUES == 0
            default:
                wasm_set_exception(module, "unsupported opcode");
                goto got_exception;
        }
#endif

#if WASM_ENABLE_LABELS_AS_VALUES != 0
        HANDLE_OP(WASM_OP_UNUSED_0x06)
        HANDLE_OP(WASM_OP_UNUSED_0x07)
        HANDLE_OP(WASM_OP_UNUSED_0x08)
        HANDLE_OP(WASM_OP_UNUSED_0x09)
        HANDLE_OP(WASM_OP_UNUSED_0x0a)
#if WASM_ENABLE_TAIL_CALL == 0
        HANDLE_OP(WASM_OP_RETURN_CALL)
        HANDLE_OP(WASM_OP_RETURN_CALL_INDIRECT)
#endif
#if WASM_ENABLE_SHARED_MEMORY == 0
        HANDLE_OP(WASM_OP_ATOMIC_PREFIX)
#endif
#if WASM_ENABLE_REF_TYPES == 0
        HANDLE_OP(WASM_OP_SELECT_T)
        HANDLE_OP(WASM_OP_TABLE_GET)
        HANDLE_OP(WASM_OP_TABLE_SET)
        HANDLE_OP(WASM_OP_REF_NULL)
        HANDLE_OP(WASM_OP_REF_IS_NULL)
        HANDLE_OP(WASM_OP_REF_FUNC)
#endif
        HANDLE_OP(WASM_OP_UNUSED_0x14)
        HANDLE_OP(WASM_OP_UNUSED_0x15)
        HANDLE_OP(WASM_OP_UNUSED_0x16)
        HANDLE_OP(WASM_OP_UNUSED_0x17)
        HANDLE_OP(WASM_OP_UNUSED_0x18)
        HANDLE_OP(WASM_OP_UNUSED_0x19)
        HANDLE_OP(WASM_OP_UNUSED_0x27)
        /* Used by fast interpreter */
        HANDLE_OP(EXT_OP_SET_LOCAL_FAST_I64)
        HANDLE_OP(EXT_OP_TEE_LOCAL_FAST_I64)
        HANDLE_OP(EXT_OP_COPY_STACK_TOP)
        HANDLE_OP(EXT_OP_COPY_STACK_TOP_I64)
        HANDLE_OP(EXT_OP_COPY_STACK_VALUES)
        {
            wasm_set_exception(module, "unsupported opcode");
            goto got_exception;
        }
#endif

#if WASM_ENABLE_LABELS_AS_VALUES == 0
        continue;
#else
    FETCH_OPCODE_AND_DISPATCH();
#endif

#if WASM_ENABLE_TAIL_CALL != 0
    call_func_from_return_call:
    {
        POP(cur_func->param_cell_num);
        if (cur_func->param_cell_num > 0) {
            word_copy(frame->lp, frame_sp, cur_func->param_cell_num);
        }
        FREE_FRAME(exec_env, frame);
        wasm_exec_env_set_cur_frame(exec_env, (WASMRuntimeFrame *)prev_frame);
        goto call_func_from_entry;
    }
#endif
    call_func_from_interp:
    {
        /* Only do the copy when it's called from interpreter.  */
        WASMInterpFrame *outs_area = wasm_exec_env_wasm_stack_top(exec_env);
        POP(cur_func->param_cell_num);
        SYNC_ALL_TO_FRAME();
        if (cur_func->param_cell_num > 0) {
            word_copy(outs_area->lp, frame_sp, cur_func->param_cell_num);
        }
        prev_frame = frame;
    }

    call_func_from_entry:
    {
        if (cur_func->is_import_func) {
#if WASM_ENABLE_MULTI_MODULE != 0
            if (cur_func->import_func_inst) {
                wasm_interp_call_func_import(module, exec_env, cur_func,
                                             prev_frame);
            }
            else
#endif
            {
                wasm_interp_call_func_native(module, exec_env, cur_func,
                                             prev_frame);
            }

            prev_frame = frame->prev_frame;
            cur_func = frame->function;
            UPDATE_ALL_FROM_FRAME();

            /* update memory instance ptr and memory size */
            memory = module->default_memory;
#if !defined(OS_ENABLE_HW_BOUND_CHECK)              \
    || WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0 \
    || WASM_ENABLE_BULK_MEMORY != 0
            if (memory)
                linear_mem_size = num_bytes_per_page * memory->cur_page_count;
#endif
            if (wasm_get_exception(module))
                goto got_exception;
        }
        else {
            WASMFunction *cur_wasm_func = cur_func->u.func;
            WASMType *func_type;

            func_type = cur_wasm_func->func_type;

            all_cell_num = (uint64)cur_func->param_cell_num
                           + (uint64)cur_func->local_cell_num
                           + (uint64)cur_wasm_func->max_stack_cell_num
                           + ((uint64)cur_wasm_func->max_block_num)
                                 * sizeof(WASMBranchBlock) / 4;
            if (all_cell_num >= UINT32_MAX) {
                wasm_set_exception(module, "wasm operand stack overflow");
                goto got_exception;
            }

            frame_size = wasm_interp_interp_frame_size((uint32)all_cell_num);
            if (!(frame = ALLOC_FRAME(exec_env, frame_size, prev_frame))) {
                frame = prev_frame;
                goto got_exception;
            }

            /* Initialize the interpreter context. */
            frame->function = cur_func;
            frame_ip = wasm_get_func_code(cur_func);
            frame_ip_end = wasm_get_func_code_end(cur_func);
            frame_lp = frame->lp;

            frame_sp = frame->sp_bottom =
                frame_lp + cur_func->param_cell_num + cur_func->local_cell_num;
            frame->sp_boundary =
                frame->sp_bottom + cur_wasm_func->max_stack_cell_num;

            frame_csp = frame->csp_bottom =
                (WASMBranchBlock *)frame->sp_boundary;
            frame->csp_boundary =
                frame->csp_bottom + cur_wasm_func->max_block_num;

            /* Initialize the local variables */
            memset(frame_lp + cur_func->param_cell_num, 0,
                   (uint32)(cur_func->local_cell_num * 4));

            /* Push function block as first block */
            cell_num = func_type->ret_cell_num;
            PUSH_CSP(LABEL_TYPE_FUNCTION, 0, cell_num, frame_ip_end - 1);

            wasm_exec_env_set_cur_frame(exec_env, (WASMRuntimeFrame *)frame);
#if WASM_ENABLE_THREAD_MGR != 0
            CHECK_SUSPEND_FLAGS();
#endif
        }
        HANDLE_OP_END();
    }

    return_func:
    {
        FREE_FRAME(exec_env, frame);
        wasm_exec_env_set_cur_frame(exec_env, (WASMRuntimeFrame *)prev_frame);

        if (!prev_frame->ip)
            /* Called from native. */
            return;

        RECOVER_CONTEXT(prev_frame);
        HANDLE_OP_END();
    }

#if WASM_ENABLE_SHARED_MEMORY != 0
    unaligned_atomic:
        wasm_set_exception(module, "unaligned atomic");
        goto got_exception;
#endif

#if !defined(OS_ENABLE_HW_BOUND_CHECK)              \
    || WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS == 0 \
    || WASM_ENABLE_BULK_MEMORY != 0
    out_of_bounds:
        wasm_set_exception(module, "out of bounds memory access");
#endif

    got_exception:
#if WASM_ENABLE_DEBUG_INTERP != 0
        if (wasm_exec_env_get_instance(exec_env) != NULL) {
            uint8 *frame_ip_temp = frame_ip;
            frame_ip = frame_ip_orig;
            wasm_cluster_thread_send_signal(exec_env, WAMR_SIG_TRAP);
            CHECK_SUSPEND_FLAGS();
            frame_ip = frame_ip_temp;
        }
#endif
        SYNC_ALL_TO_FRAME();
        return;

#if WASM_ENABLE_LABELS_AS_VALUES == 0
    }
#else
    FETCH_OPCODE_AND_DISPATCH();
#endif
}

void
wasm_interp_call_wasm(WASMModuleInstance *module_inst, WASMExecEnv *exec_env,
                      WASMFunctionInstance *function, uint32 argc,
                      uint32 argv[])
{
    WASMRuntimeFrame *prev_frame = wasm_exec_env_get_cur_frame(exec_env);
    WASMInterpFrame *frame, *outs_area;

    /* Allocate sufficient cells for all kinds of return values.  */
    unsigned all_cell_num =
                 function->ret_cell_num > 2 ? function->ret_cell_num : 2,
             i;
    /* This frame won't be used by JITed code, so only allocate interp
       frame here.  */
    unsigned frame_size = wasm_interp_interp_frame_size(all_cell_num);

    if (argc < function->param_cell_num) {
        char buf[128];
        snprintf(buf, sizeof(buf),
                 "invalid argument count %u, must be no smaller than %u", argc,
                 function->param_cell_num);
        wasm_set_exception(module_inst, buf);
        return;
    }
    argc = function->param_cell_num;

#ifndef OS_ENABLE_HW_BOUND_CHECK
    if ((uint8 *)&prev_frame < exec_env->native_stack_boundary) {
        wasm_set_exception((WASMModuleInstance *)exec_env->module_inst,
                           "native stack overflow");
        return;
    }
#endif

    if (!(frame =
              ALLOC_FRAME(exec_env, frame_size, (WASMInterpFrame *)prev_frame)))
        return;

    outs_area = wasm_exec_env_wasm_stack_top(exec_env);
    frame->function = NULL;
    frame->ip = NULL;
    /* There is no local variable. */
    frame->sp = frame->lp + 0;

    if (argc > 0)
        word_copy(outs_area->lp, argv, argc);

    wasm_exec_env_set_cur_frame(exec_env, frame);

    if (function->is_import_func) {
#if WASM_ENABLE_MULTI_MODULE != 0
        if (function->import_module_inst) {
            wasm_interp_call_func_import(module_inst, exec_env, function,
                                         frame);
        }
        else
#endif
        {
            /* it is a native function */
            wasm_interp_call_func_native(module_inst, exec_env, function,
                                         frame);
        }
    }
    else {
#if WASM_ENABLE_FAST_JIT == 0
        wasm_interp_call_func_bytecode(module_inst, exec_env, function, frame);
#else
        JitGlobals *jit_globals = jit_compiler_get_jit_globals();
        JitInterpSwitchInfo info;
        WASMType *func_type = function->u.func->func_type;
        uint8 type = func_type->result_count
                         ? func_type->types[func_type->param_count]
                         : VALUE_TYPE_VOID;

#if WASM_ENABLE_REF_TYPES != 0
        if (type == VALUE_TYPE_EXTERNREF || type == VALUE_TYPE_FUNCREF)
            type = VALUE_TYPE_I32;
#endif

        info.out.ret.last_return_type = type;
        info.frame = frame;
        frame->jitted_return_addr =
            (uint8 *)jit_globals->return_to_interp_from_jitted;
        jit_interp_switch_to_jitted(exec_env, &info,
                                    function->u.func->fast_jit_jitted_code);
        if (func_type->result_count) {
            switch (type) {
                case VALUE_TYPE_I32:
                    *(frame->sp - function->ret_cell_num) =
                        info.out.ret.ival[0];
                    break;
                case VALUE_TYPE_I64:
                    *(frame->sp - function->ret_cell_num) =
                        info.out.ret.ival[0];
                    *(frame->sp - function->ret_cell_num + 1) =
                        info.out.ret.ival[1];
                    break;
                case VALUE_TYPE_F32:
                    *(frame->sp - function->ret_cell_num) =
                        info.out.ret.fval[0];
                    break;
                case VALUE_TYPE_F64:
                    *(frame->sp - function->ret_cell_num) =
                        info.out.ret.fval[0];
                    *(frame->sp - function->ret_cell_num + 1) =
                        info.out.ret.fval[1];
                    break;
                default:
                    bh_assert(0);
                    break;
            }
        }
        (void)wasm_interp_call_func_bytecode;
#endif
    }

    /* Output the return value to the caller */
    if (!wasm_get_exception(module_inst)) {
        for (i = 0; i < function->ret_cell_num; i++) {
            argv[i] = *(frame->sp + i - function->ret_cell_num);
        }
    }
    else {
#if WASM_ENABLE_DUMP_CALL_STACK != 0
        if (wasm_interp_create_call_stack(exec_env)) {
            wasm_interp_dump_call_stack(exec_env, true, NULL, 0);
        }
#endif
        LOG_DEBUG("meet an exception %s", wasm_get_exception(module_inst));
    }

    wasm_exec_env_set_cur_frame(exec_env, prev_frame);
    FREE_FRAME(exec_env, frame);
}
