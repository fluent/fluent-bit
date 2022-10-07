/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_atomic.h>

#if defined (_WIN32) || defined (_WIN64)
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "cmt_tests.h"

#define THREAD_COUNT 100
#define CYCLE_COUNT  10000
#define EXPECTED_VALUE (THREAD_COUNT * CYCLE_COUNT)

uint64_t global_counter;

static inline void add_through_compare_exchange(uint64_t val)
{
    uint64_t old;
    uint64_t new;
    int      result;

    do {
        old = global_counter;
        new = old + val;

        result = cmt_atomic_compare_exchange(&global_counter, old, new);
    }
    while(0 == result);
}

void *worker_thread_add_through_compare_exchange(void *ptr)
{
    int local_counter;

    for (local_counter = 0 ; local_counter < CYCLE_COUNT ; local_counter++) {
        add_through_compare_exchange(1);
    }

    return NULL;
}

#if defined (_WIN32) || defined (_WIN64)

void test_atomic_operations()
{
    HANDLE threads[THREAD_COUNT];
    DWORD  thread_ids[THREAD_COUNT];
    int    thread_index;
    DWORD  result;

    cmt_initialize();

    global_counter = 0;

    for(thread_index = 0 ; thread_index < THREAD_COUNT ; thread_index++)
    {
        threads[thread_index] = CreateThread(NULL, 0,
                                             (LPTHREAD_START_ROUTINE) worker_thread_add_through_compare_exchange,
                                             NULL, 0, &thread_ids[thread_index]);
    }

    for(thread_index = 0 ; thread_index < THREAD_COUNT ; thread_index++)
    {
        result = WaitForSingleObject(threads[thread_index], INFINITE);
    }

    TEST_CHECK(global_counter == EXPECTED_VALUE);
}

#else

void test_atomic_operations()
{
    pthread_t threads[THREAD_COUNT];
    int       thread_index;

    cmt_initialize();

    global_counter = 0;

    for(thread_index = 0 ; thread_index < THREAD_COUNT ; thread_index++)
    {
        pthread_create(&threads[thread_index], NULL,
                       worker_thread_add_through_compare_exchange, NULL);
    }

    for(thread_index = 0 ; thread_index < THREAD_COUNT ; thread_index++)
    {
        pthread_join(threads[thread_index], NULL);
    }

    TEST_CHECK(global_counter == EXPECTED_VALUE);
}
#endif

TEST_LIST = {
    {"atomic_operations", test_atomic_operations},
    { 0 }
};
