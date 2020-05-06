/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2014-2016 Magnus Edenhill
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
#if !HAVE_ATOMICS_32
	mtx_t lock;
#endif
} rd_atomic32_t;

typedef struct {
	int64_t val;
#if !HAVE_ATOMICS_64
	mtx_t lock;
#endif
} rd_atomic64_t;


static RD_INLINE RD_UNUSED void rd_atomic32_init (rd_atomic32_t *ra, int32_t v) {
	ra->val = v;
#if !defined(_MSC_VER) && !HAVE_ATOMICS_32
	mtx_init(&ra->lock, mtx_plain);
#endif
}


static RD_INLINE int32_t RD_UNUSED rd_atomic32_add (rd_atomic32_t *ra, int32_t v) {
#ifdef __SUNPRO_C
	return atomic_add_32_nv(&ra->val, v);
#elif defined(_MSC_VER)
	return InterlockedAdd(&ra->val, v);
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

static RD_INLINE int32_t RD_UNUSED rd_atomic32_sub(rd_atomic32_t *ra, int32_t v) {
#ifdef __SUNPRO_C
	return atomic_add_32_nv(&ra->val, -v);
#elif defined(_MSC_VER)
	return InterlockedAdd(&ra->val, -v);
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

static RD_INLINE int32_t RD_UNUSED rd_atomic32_get(rd_atomic32_t *ra) {
#if defined(_MSC_VER) || defined(__SUNPRO_C)
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

static RD_INLINE int32_t RD_UNUSED rd_atomic32_set(rd_atomic32_t *ra, int32_t v) {
#ifdef _MSC_VER
	return InterlockedExchange(&ra->val, v);
#elif !HAVE_ATOMICS_32
	int32_t r;
	mtx_lock(&ra->lock);
	r = ra->val = v;
	mtx_unlock(&ra->lock);
	return r;
#elif HAVE_ATOMICS_32_ATOMIC
        __atomic_store_n(&ra->val, v, __ATOMIC_SEQ_CST);
        return v;
#elif HAVE_ATOMICS_32_SYNC
        (void)__sync_lock_test_and_set(&ra->val, v);
        return v;
#else
	return ra->val = v; // FIXME
#endif
}



static RD_INLINE RD_UNUSED void rd_atomic64_init (rd_atomic64_t *ra, int64_t v) {
	ra->val = v;
#if !defined(_MSC_VER) && !HAVE_ATOMICS_64
	mtx_init(&ra->lock, mtx_plain);
#endif
}

static RD_INLINE int64_t RD_UNUSED rd_atomic64_add (rd_atomic64_t *ra, int64_t v) {
#ifdef __SUNPRO_C
	return atomic_add_64_nv(&ra->val, v);
#elif defined(_MSC_VER)
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

static RD_INLINE int64_t RD_UNUSED rd_atomic64_sub(rd_atomic64_t *ra, int64_t v) {
#ifdef __SUNPRO_C
	return atomic_add_64_nv(&ra->val, -v);
#elif defined(_MSC_VER)
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

static RD_INLINE int64_t RD_UNUSED rd_atomic64_get(rd_atomic64_t *ra) {
#if defined(_MSC_VER) || defined(__SUNPRO_C)
	return ra->val;
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


static RD_INLINE int64_t RD_UNUSED rd_atomic64_set(rd_atomic64_t *ra, int64_t v) {
#ifdef _MSC_VER
	return InterlockedExchange64(&ra->val, v);
#elif !HAVE_ATOMICS_64
	int64_t r;
	mtx_lock(&ra->lock);
	ra->val = v;
	r = ra->val;
	mtx_unlock(&ra->lock);
	return r;
#elif HAVE_ATOMICS_64_ATOMIC
        __atomic_store_n(&ra->val, v, __ATOMIC_SEQ_CST);
        return v;
#elif HAVE_ATOMICS_64_SYNC
        (void)__sync_lock_test_and_set(&ra->val, v);
        return v;
#else
	return ra->val = v; // FIXME
#endif
}

#endif /* _RDATOMIC_H_ */
