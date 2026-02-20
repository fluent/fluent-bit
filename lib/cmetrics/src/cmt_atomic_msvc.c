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

#include <cmetrics/cmt_atomic.h>
#include <windows.h>

/* This allows cmt_atomic_initialize to be automatically called 
 * as soon as the program starts if enabled.
 */

#ifndef _WIN64
CRITICAL_SECTION atomic_operation_lock;
static INIT_ONCE atomic_operation_system_once = INIT_ONCE_STATIC_INIT;
static int       atomic_operation_system_initialized = 0;
static int       atomic_operation_system_status = 0;

static BOOL CALLBACK cmt_atomic_bootstrap(PINIT_ONCE once, PVOID parameter,
                                          PVOID *context)
{
    (void) once;
    (void) parameter;
    (void) context;

    InitializeCriticalSection(&atomic_operation_lock);
    atomic_operation_system_initialized = 1;

    return TRUE;
}

int cmt_atomic_initialize()
{
    if (!InitOnceExecuteOnce(&atomic_operation_system_once,
                             cmt_atomic_bootstrap, NULL, NULL)) {
        atomic_operation_system_status = 1;
        return 1;
    }

    atomic_operation_system_status = 0;

    return 0;
}

int cmt_atomic_compare_exchange(uint64_t *storage, 
                                uint64_t old_value, uint64_t new_value)
{
    uint64_t result;

    if (cmt_atomic_initialize() != 0 ||
        atomic_operation_system_initialized == 0 ||
        atomic_operation_system_status != 0) {
        return 0;
    }

    EnterCriticalSection(&atomic_operation_lock);

    if (*storage == old_value) {
        *storage = new_value;

        result = 1;
    }
    else {
        result = 0;
    }

    LeaveCriticalSection(&atomic_operation_lock);

    return result;
}

void cmt_atomic_store(uint64_t *storage, uint64_t new_value)
{
    if (cmt_atomic_initialize() != 0 ||
        atomic_operation_system_initialized == 0 ||
        atomic_operation_system_status != 0) {
        return;
    }

    EnterCriticalSection(&atomic_operation_lock);

    *storage = new_value;
    
    LeaveCriticalSection(&atomic_operation_lock);
}

uint64_t cmt_atomic_load(uint64_t *storage)
{
    uint64_t result;

    if (cmt_atomic_initialize() != 0 ||
        atomic_operation_system_initialized == 0 ||
        atomic_operation_system_status != 0) {
        return 0;
    }

    EnterCriticalSection(&atomic_operation_lock);

    result = *storage;
    
    LeaveCriticalSection(&atomic_operation_lock);

    return result;
}

#else /* _WIN64 */

int cmt_atomic_initialize()
{
    return 0;
}

int cmt_atomic_compare_exchange(uint64_t *storage, 
                                       uint64_t old_value, uint64_t new_value)
{
    uint64_t result;

    result = _InterlockedCompareExchange64(storage, new_value, old_value);

    if (result != old_value) {
        return 0;
    }

    return 1;
}

void cmt_atomic_store(uint64_t *storage, uint64_t new_value)
{
    _InterlockedExchange64(storage, new_value);
}

uint64_t cmt_atomic_load(uint64_t *storage)
{
    return _InterlockedOr64(storage, 0);
}

#endif
