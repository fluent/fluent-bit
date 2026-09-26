/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_ATOMIC_H
#define FLB_ATOMIC_H

/*
 * Minimal relaxed-atomic helpers for scalar values that are read and written
 * by more than one thread (e.g. counters and one-shot status fields shared
 * between a threaded input worker and the main engine).
 *
 * Aligned word-sized loads/stores are already atomic on every platform Fluent
 * Bit targets, but accessing them from multiple threads with plain operators is
 * a C-level data race (undefined behavior, and flagged by ThreadSanitizer).
 * These helpers make such accesses well defined. Relaxed ordering is used on
 * purpose: callers only require atomicity of the individual value, not ordering
 * relative to other memory (for ordered hand-offs use a mutex instead).
 *
 * The helpers are type-generic (int, size_t, uint64_t, ...).
 */

#if defined(__GNUC__) || defined(__clang__)

#define flb_atomic_load(ptr)         __atomic_load_n((ptr), __ATOMIC_RELAXED)
#define flb_atomic_store(ptr, val)   __atomic_store_n((ptr), (val), __ATOMIC_RELAXED)
#define flb_atomic_fetch_add(ptr, v) __atomic_fetch_add((ptr), (v), __ATOMIC_RELAXED)

#elif defined(_MSC_VER)

/*
 * MSVC backend: the Interlocked intrinsics are atomic (full barrier, which is
 * stronger than the relaxed ordering we need but always correct). The helpers
 * dispatch on the operand width so they work for both 32-bit and 64-bit scalars
 * on 32-bit and 64-bit targets.
 */
#include <intrin.h>

static __forceinline long long flb_atomic_load_n(volatile void *ptr, size_t width)
{
#ifdef _WIN64
    if (width == 8) {
        return (long long) _InterlockedOr64((volatile __int64 *) ptr, 0);
    }
#endif
    (void) width;
    return (long long) _InterlockedOr((volatile long *) ptr, 0);
}

static __forceinline void flb_atomic_store_n(volatile void *ptr, long long val,
                                             size_t width)
{
#ifdef _WIN64
    if (width == 8) {
        (void) _InterlockedExchange64((volatile __int64 *) ptr, (__int64) val);
        return;
    }
#endif
    (void) width;
    (void) _InterlockedExchange((volatile long *) ptr, (long) val);
}

static __forceinline long long flb_atomic_fetch_add_n(volatile void *ptr,
                                                      long long val, size_t width)
{
#ifdef _WIN64
    if (width == 8) {
        return (long long) _InterlockedExchangeAdd64((volatile __int64 *) ptr,
                                                     (__int64) val);
    }
#endif
    (void) width;
    return (long long) _InterlockedExchangeAdd((volatile long *) ptr, (long) val);
}

#define flb_atomic_load(ptr)         flb_atomic_load_n((ptr), sizeof(*(ptr)))
#define flb_atomic_store(ptr, val)   flb_atomic_store_n((ptr), (long long) (val), \
                                                        sizeof(*(ptr)))
#define flb_atomic_fetch_add(ptr, v) flb_atomic_fetch_add_n((ptr), (long long) (v), \
                                                            sizeof(*(ptr)))

#else
#error "flb_atomic.h: no atomic backend available for this compiler"
#endif

#endif
