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

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>

#define MAX_CACHE_ENTRIES 8

#ifdef FLB_HAVE_TESTS_OSSFUZZ
static void silence_expected_allocation_errors(void)
{
    static struct flb_log log;
    static struct flb_worker worker;

    log.level = FLB_LOG_OFF;
    worker.log_ctx = &log;

    FLB_TLS_INIT(flb_worker_ctx);
    FLB_TLS_SET(flb_worker_ctx, &worker);
}

static void reset_fuzz_allocator(void)
{
    flb_malloc_p = 0;
    flb_malloc_mod = INT_MAX;
}

static void exercise_cache_create_allocation_failures(int timeout, int entries)
{
    int i;
    int allocation_count;
    struct flb_log_cache *cache;

    /* The cache and each entry and its buffer require one allocation each. */
    allocation_count = 1 + (entries * 2);

    for (i = 1; i <= allocation_count; i++) {
        flb_malloc_mod = allocation_count + 1;
        flb_malloc_p = flb_malloc_mod - i;

        cache = flb_log_cache_create(timeout, entries);

        reset_fuzz_allocator();
        if (cache != NULL) {
            flb_log_cache_destroy(cache);
            abort();
        }
    }
}

static void exercise_message_allocation_failure(struct flb_log_cache *cache,
                                                uint8_t value)
{
    char message[FLB_LOG_CACHE_TEXT_BUF_SIZE + 1];
    struct flb_log_cache_entry *entry;

    memset(message, value, sizeof(message));

    /* Force the next allocation, used to grow the message buffer, to fail. */
    flb_malloc_mod = 2;
    flb_malloc_p = 1;
    flb_log_cache_check_suppress(cache, message, sizeof(message));
    reset_fuzz_allocator();

    entry = flb_log_cache_exists(cache, message, sizeof(message));
    if (entry != NULL) {
        abort();
    }

    /* A failed growth must leave the cache entry valid for a later retry. */
    flb_log_cache_check_suppress(cache, message, sizeof(message));
    entry = flb_log_cache_exists(cache, message, sizeof(message));
    if (entry == NULL) {
        abort();
    }
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int entries;
    int timeout;
    struct flb_log_cache *cache;

    if (size == 0) {
        return 0;
    }

    entries = (data[0] % MAX_CACHE_ENTRIES) + 1;
    timeout = data[0];

#ifdef FLB_HAVE_TESTS_OSSFUZZ
    silence_expected_allocation_errors();
    exercise_cache_create_allocation_failures(timeout, entries);
    reset_fuzz_allocator();
#endif

    cache = flb_log_cache_create(timeout, entries);
    if (cache == NULL) {
        return 0;
    }

#ifdef FLB_HAVE_TESTS_OSSFUZZ
    exercise_message_allocation_failure(cache, data[0]);
#endif

    if (size > 1) {
        flb_log_cache_check_suppress(cache, (char *) &data[1], size - 1);
        flb_log_cache_check_suppress(cache, (char *) &data[1], size - 1);
    }

#if SIZE_MAX > INT_MAX
    flb_log_cache_check_suppress(cache, (char *) data, (size_t) INT_MAX + 1);
#endif

    flb_log_cache_destroy(cache);
    return 0;
}
