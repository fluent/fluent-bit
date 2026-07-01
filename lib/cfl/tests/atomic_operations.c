/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
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

#include <cfl/cfl.h>

#if defined (_WIN32) || defined (_WIN64)
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "cfl_tests_internal.h"

#define THREAD_COUNT   100
#define CYCLE_COUNT    10000
#define EXPECTED_VALUE (THREAD_COUNT * CYCLE_COUNT)

static uint64_t global_counter;

static void test_atomic_initialize()
{
    TEST_CHECK(cfl_atomic_initialize() == 0);
    TEST_CHECK(cfl_atomic_initialize() == 0);
    TEST_CHECK(cfl_init() == 0);
}

static void test_atomic_basic_operations()
{
    TEST_CHECK(cfl_init() == 0);

    cfl_atomic_store(&global_counter, 10);
    TEST_CHECK(cfl_atomic_load(&global_counter) == 10);

    TEST_CHECK(cfl_atomic_compare_exchange(&global_counter, 5, 20) == 0);
    TEST_CHECK(cfl_atomic_load(&global_counter) == 10);

    TEST_CHECK(cfl_atomic_compare_exchange(&global_counter, 10, 20) == 1);
    TEST_CHECK(cfl_atomic_load(&global_counter) == 20);
}

static void test_atomic_full_width_values()
{
    uint64_t value;
    uint64_t high_bit;

    high_bit = UINT64_C(1) << 63;

    TEST_CHECK(cfl_atomic_initialize() == 0);

    value = 0;
    cfl_atomic_store(&value, UINT64_MAX);
    TEST_CHECK(cfl_atomic_load(&value) == UINT64_MAX);

    TEST_CHECK(cfl_atomic_compare_exchange(&value, high_bit, 1) == 0);
    TEST_CHECK(cfl_atomic_load(&value) == UINT64_MAX);

    TEST_CHECK(cfl_atomic_compare_exchange(&value, UINT64_MAX, high_bit) == 1);
    TEST_CHECK(cfl_atomic_load(&value) == high_bit);

    TEST_CHECK(cfl_atomic_compare_exchange(&value, high_bit, 0) == 1);
    TEST_CHECK(cfl_atomic_load(&value) == 0);
}

static void add_through_compare_exchange(uint64_t val)
{
    uint64_t old;
    uint64_t new;
    int      result;

    do {
        old = cfl_atomic_load(&global_counter);
        new = old + val;

        result = cfl_atomic_compare_exchange(&global_counter, old, new);
    }
    while (result == 0);
}

#if defined (_WIN32) || defined (_WIN64)
static DWORD WINAPI worker_thread_add_through_compare_exchange(LPVOID ptr)
#else
static void *worker_thread_add_through_compare_exchange(void *ptr)
#endif
{
    int local_counter;

    (void) ptr;

    for (local_counter = 0; local_counter < CYCLE_COUNT; local_counter++) {
        add_through_compare_exchange(1);
    }

#if defined (_WIN32) || defined (_WIN64)
    return 0;
#else
    return NULL;
#endif
}

#if defined (_WIN32) || defined (_WIN64)

static void test_atomic_operations()
{
    HANDLE threads[THREAD_COUNT];
    DWORD  thread_ids[THREAD_COUNT];
    int    thread_index;
    DWORD  result;

    TEST_CHECK(cfl_init() == 0);

    cfl_atomic_store(&global_counter, 0);

    for (thread_index = 0; thread_index < THREAD_COUNT; thread_index++) {
        threads[thread_index] = CreateThread(NULL, 0,
                                             worker_thread_add_through_compare_exchange,
                                             NULL, 0, &thread_ids[thread_index]);
    }

    for (thread_index = 0; thread_index < THREAD_COUNT; thread_index++) {
        result = WaitForSingleObject(threads[thread_index], INFINITE);
        TEST_CHECK(result == WAIT_OBJECT_0);
        CloseHandle(threads[thread_index]);
    }

    TEST_CHECK(cfl_atomic_load(&global_counter) == EXPECTED_VALUE);
}

#else

static void test_atomic_operations()
{
    pthread_t threads[THREAD_COUNT];
    int       thread_index;
    int       result;

    TEST_CHECK(cfl_init() == 0);

    cfl_atomic_store(&global_counter, 0);

    for (thread_index = 0; thread_index < THREAD_COUNT; thread_index++) {
        result = pthread_create(&threads[thread_index], NULL,
                                worker_thread_add_through_compare_exchange, NULL);
        TEST_CHECK(result == 0);
    }

    for (thread_index = 0; thread_index < THREAD_COUNT; thread_index++) {
        result = pthread_join(threads[thread_index], NULL);
        TEST_CHECK(result == 0);
    }

    TEST_CHECK(cfl_atomic_load(&global_counter) == EXPECTED_VALUE);
}
#endif

TEST_LIST = {
    { "atomic_initialize", test_atomic_initialize },
    { "atomic_basic_operations", test_atomic_basic_operations },
    { "atomic_full_width_values", test_atomic_full_width_values },
    { "atomic_operations", test_atomic_operations },
    { 0 }
};
