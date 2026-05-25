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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#ifdef FLB_HAVE_TESTS_OSSFUZZ
int flb_malloc_p;
int flb_malloc_mod;
#endif

static size_t flb_global_heap_usage = 0;

FLB_EXPORT void flb_mem_account_add(size_t size) {
#if defined(__GNUC__) || defined(__clang__)
    __atomic_fetch_add(&flb_global_heap_usage, size, __ATOMIC_RELAXED);
#elif defined(_WIN32)
    InterlockedExchangeAdd64((LONG64*)&flb_global_heap_usage, size);
#else
    flb_global_heap_usage += size;
#endif
}

FLB_EXPORT void flb_mem_account_sub(size_t size) {
#if defined(__GNUC__) || defined(__clang__)
    size_t current;
    size_t updated;

    current = __atomic_load_n(&flb_global_heap_usage, __ATOMIC_RELAXED);

    do {
        updated = current > size ? current - size : 0;
    } while (!__atomic_compare_exchange_n(&flb_global_heap_usage, &current,
                                           updated, 0, __ATOMIC_RELAXED,
                                           __ATOMIC_RELAXED));
#elif defined(_WIN32)
    LONG64 current;
    LONG64 updated;

    current = InterlockedCompareExchange64((LONG64 *) &flb_global_heap_usage,
                                           0, 0);

    do {
        updated = (LONG64) ((size_t) current > size ? (size_t) current - size : 0);
    } while (InterlockedCompareExchange64((LONG64 *) &flb_global_heap_usage,
                                          updated, current) != current);
#else
    if (flb_global_heap_usage > size) {
        flb_global_heap_usage -= size;
    }
    else {
        flb_global_heap_usage = 0;
    }
#endif
}

FLB_EXPORT size_t flb_mem_usage_get(void)
{
#if defined(__GNUC__) || defined(__clang__)
    return (size_t) __atomic_load_n(&flb_global_heap_usage, __ATOMIC_RELAXED);
#elif defined(_WIN32)
    return (size_t) InterlockedCompareExchange64(
            (LONG64 *) &flb_global_heap_usage, 0, 0);
#else
    return (size_t) flb_global_heap_usage;
#endif
}
