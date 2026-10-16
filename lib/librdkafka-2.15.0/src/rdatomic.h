/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2014-2022, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _RDATOMIC_H_
#define _RDATOMIC_H_

#include "tinycthread.h"

typedef struct {
        int32_t val;
#if !defined(_WIN32) && !HAVE_ATOMICS_32
        mtx_t lock;
#endif
} rd_atomic32_t;

typedef struct {
        int64_t val;
#if !defined(_WIN32) && !HAVE_ATOMICS_64
        mtx_t lock;
#endif
} rd_atomic64_t;


static RD_INLINE RD_UNUSED void rd_atomic32_init(rd_atomic32_t *ra, int32_t v) {
        ra->val = v;
#if !defined(_WIN32) && !HAVE_ATOMICS_32
        mtx_init(&ra->lock, mtx_plain);
#endif
}


static RD_INLINE int32_t RD_UNUSED rd_atomic32_add(rd_atomic32_t *ra,
                                                   int32_t v) {
#ifdef __SUNPRO_C
        return atomic_add_32_nv(&ra->val, v);
#elif defined(_WIN32)
        return InterlockedAdd((LONG *)&ra->val, v);
#elif !HAVE_ATOMICS_32
        int32_t r;
        mtx_lock(&ra->lock);
        ra->val += v;
        r = ra->val;
        mtx_unlock(&ra->lock);
        return r;
#else
        return ATOMIC_OP32(add, fetch, &ra->val, v);
#endif
}

static RD_INLINE int32_t RD_UNUSED rd_atomic32_sub(rd_atomic32_t *ra,
                                                   int32_t v) {
#ifdef __SUNPRO_C
        return atomic_add_32_nv(&ra->val, -v);
#elif defined(_WIN32)
        return InterlockedAdd((LONG *)&ra->val, -v);
#elif !HAVE_ATOMICS_32
        int32_t r;
        mtx_lock(&ra->lock);
        ra->val -= v;
        r = ra->val;
        mtx_unlock(&ra->lock);
        return r;
#else
        return ATOMIC_OP32(sub, fetch, &ra->val, v);
#endif
}

/**
 * @warning The returned value is the nominal value and will be outdated
 *          by the time the application reads it.
 *          It should not be used for exact arithmetics, any correlation
 *          with other data is unsynchronized, meaning that two atomics,
 *          or one atomic and a mutex-protected piece of data have no
 *          common synchronization and can't be relied on.
 */
static RD_INLINE int32_t RD_UNUSED rd_atomic32_get(rd_atomic32_t *ra) {
#if defined(_WIN32) || defined(__SUNPRO_C)
        return ra->val;
#elif !HAVE_ATOMICS_32
        int32_t r;
        mtx_lock(&ra->lock);
        r = ra->val;
        mtx_unlock(&ra->lock);
        return r;
#else
        return ATOMIC_OP32(fetch, add, &ra->val, 0);
#endif
}

/**
 * @brief Set the atomic value to \p v and return the previous value to
 *        that can be used to determine if the value was changed.
 */
static RD_INLINE int32_t RD_UNUSED rd_atomic32_set(rd_atomic32_t *ra,
                                                   int32_t v) {
#ifdef _WIN32
        return InterlockedExchange((LONG *)&ra->val, v);
#elif HAVE_ATOMICS_32 && HAVE_ATOMICS_32_ATOMIC
        return __atomic_exchange_n(&ra->val, v, __ATOMIC_SEQ_CST);
#elif HAVE_ATOMICS_32 && HAVE_ATOMICS_32_SYNC
        return __sync_lock_test_and_set(&ra->val, v);
#else
        int32_t r;
        mtx_lock(&ra->lock);
        r       = ra->val;
        ra->val = v;
        mtx_unlock(&ra->lock);
        return r;
#endif
}



static RD_INLINE RD_UNUSED void rd_atomic64_init(rd_atomic64_t *ra, int64_t v) {
        ra->val = v;
#if !defined(_WIN32) && !HAVE_ATOMICS_64
        mtx_init(&ra->lock, mtx_plain);
#endif
}

static RD_INLINE int64_t RD_UNUSED rd_atomic64_add(rd_atomic64_t *ra,
                                                   int64_t v) {
#ifdef __SUNPRO_C
        return atomic_add_64_nv(&ra->val, v);
#elif defined(_WIN32)
        return InterlockedAdd64(&ra->val, v);
#elif !HAVE_ATOMICS_64
        int64_t r;
        mtx_lock(&ra->lock);
        ra->val += v;
        r = ra->val;
        mtx_unlock(&ra->lock);
        return r;
#else
        return ATOMIC_OP64(add, fetch, &ra->val, v);
#endif
}

static RD_INLINE int64_t RD_UNUSED rd_atomic64_sub(rd_atomic64_t *ra,
                                                   int64_t v) {
#ifdef __SUNPRO_C
        return atomic_add_64_nv(&ra->val, -v);
#elif defined(_WIN32)
        return InterlockedAdd64(&ra->val, -v);
#elif !HAVE_ATOMICS_64
        int64_t r;
        mtx_lock(&ra->lock);
        ra->val -= v;
        r = ra->val;
        mtx_unlock(&ra->lock);
        return r;
#else
        return ATOMIC_OP64(sub, fetch, &ra->val, v);
#endif
}

/**
 * @warning The returned value is the nominal value and will be outdated
 *          by the time the application reads it.
 *          It should not be used for exact arithmetics, any correlation
 *          with other data is unsynchronized, meaning that two atomics,
 *          or one atomic and a mutex-protected piece of data have no
 *          common synchronization and can't be relied on.
 *          Use with care.
 */
static RD_INLINE int64_t RD_UNUSED rd_atomic64_get(rd_atomic64_t *ra) {
#if defined(_WIN32) || defined(__SUNPRO_C)
        return InterlockedCompareExchange64(&ra->val, 0, 0);
#elif !HAVE_ATOMICS_64
        int64_t r;
        mtx_lock(&ra->lock);
        r = ra->val;
        mtx_unlock(&ra->lock);
        return r;
#else
        return ATOMIC_OP64(fetch, add, &ra->val, 0);
#endif
}

/**
 * @brief Set the atomic value to \p v and return the previous value to
 *        that can be used to determine if the value was changed.
 */
static RD_INLINE int64_t RD_UNUSED rd_atomic64_set(rd_atomic64_t *ra,
                                                   int64_t v) {
#ifdef _WIN32
        return InterlockedExchange64(&ra->val, v);
#elif HAVE_ATOMICS_64 && HAVE_ATOMICS_64_ATOMIC
        return __atomic_exchange_n(&ra->val, v, __ATOMIC_SEQ_CST);
#elif HAVE_ATOMICS_64 && HAVE_ATOMICS_64_SYNC
        return __sync_lock_test_and_set(&ra->val, v);
#else
        int64_t r;
        mtx_lock(&ra->lock);
        r       = ra->val;
        ra->val = v;
        mtx_unlock(&ra->lock);
        return r;
#endif
}

/**
 * @brief Atomic compare-and-swap on a 64-bit value.
 *
 *        If *ra == @p expected, atomically replace it with @p desired
 *        and return 1. Otherwise leave *ra unchanged and return 0.
 */
static RD_INLINE int RD_UNUSED rd_atomic64_cas(rd_atomic64_t *ra,
                                               int64_t expected,
                                               int64_t desired) {
#ifdef __SUNPRO_C
        return atomic_cas_64((volatile uint64_t *)&ra->val, (uint64_t)expected,
                             (uint64_t)desired) == (uint64_t)expected;
#elif defined(_WIN32)
        return InterlockedCompareExchange64((LONG64 *)&ra->val, (LONG64)desired,
                                            (LONG64)expected) ==
               (LONG64)expected;
#elif HAVE_ATOMICS_64 && HAVE_ATOMICS_64_ATOMIC
        return __atomic_compare_exchange_n(&ra->val, &expected, desired,
                                           0 /* strong */, __ATOMIC_SEQ_CST,
                                           __ATOMIC_SEQ_CST);
#elif HAVE_ATOMICS_64 && HAVE_ATOMICS_64_SYNC
        return __sync_bool_compare_and_swap(&ra->val, expected, desired);
#else
        int r;
        mtx_lock(&ra->lock);
        if (ra->val == expected) {
                ra->val = desired;
                r       = 1;
        } else {
                r = 0;
        }
        mtx_unlock(&ra->lock);
        return r;
#endif
}

#endif /* _RDATOMIC_H_ */
