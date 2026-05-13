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

#include <cfl/cfl_atomic.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#else
#include <windows.h>
#endif

#ifdef _WIN64
#include <intrin.h>
#endif

#ifndef _WIN64
static CRITICAL_SECTION cfl_atomic_operation_lock;
static INIT_ONCE        cfl_atomic_operation_system_once = INIT_ONCE_STATIC_INIT;
static int              cfl_atomic_operation_system_initialized = 0;
static int              cfl_atomic_operation_system_status = 0;

static BOOL CALLBACK cfl_atomic_bootstrap(PINIT_ONCE once, PVOID parameter,
                                          PVOID *context)
{
    (void) once;
    (void) parameter;
    (void) context;

    InitializeCriticalSection(&cfl_atomic_operation_lock);
    cfl_atomic_operation_system_initialized = 1;

    return TRUE;
}

int cfl_atomic_initialize()
{
    if (!InitOnceExecuteOnce(&cfl_atomic_operation_system_once,
                             cfl_atomic_bootstrap, NULL, NULL)) {
        cfl_atomic_operation_system_status = 1;
        return 1;
    }

    cfl_atomic_operation_system_status = 0;

    return 0;
}

int cfl_atomic_compare_exchange(uint64_t *storage,
                                uint64_t old_value, uint64_t new_value)
{
    int result;

    if (cfl_atomic_initialize() != 0 ||
        cfl_atomic_operation_system_initialized == 0 ||
        cfl_atomic_operation_system_status != 0) {
        return 0;
    }

    EnterCriticalSection(&cfl_atomic_operation_lock);

    if (*storage == old_value) {
        *storage = new_value;

        result = 1;
    }
    else {
        result = 0;
    }

    LeaveCriticalSection(&cfl_atomic_operation_lock);

    return result;
}

void cfl_atomic_store(uint64_t *storage, uint64_t new_value)
{
    if (cfl_atomic_initialize() != 0 ||
        cfl_atomic_operation_system_initialized == 0 ||
        cfl_atomic_operation_system_status != 0) {
        return;
    }

    EnterCriticalSection(&cfl_atomic_operation_lock);

    *storage = new_value;

    LeaveCriticalSection(&cfl_atomic_operation_lock);
}

uint64_t cfl_atomic_load(uint64_t *storage)
{
    uint64_t result;

    if (cfl_atomic_initialize() != 0 ||
        cfl_atomic_operation_system_initialized == 0 ||
        cfl_atomic_operation_system_status != 0) {
        return 0;
    }

    EnterCriticalSection(&cfl_atomic_operation_lock);

    result = *storage;

    LeaveCriticalSection(&cfl_atomic_operation_lock);

    return result;
}

#else /* _WIN64 */

int cfl_atomic_initialize()
{
    return 0;
}

int cfl_atomic_compare_exchange(uint64_t *storage,
                                uint64_t old_value, uint64_t new_value)
{
    __int64 result;

    result = _InterlockedCompareExchange64((volatile __int64 *) storage,
                                           (__int64) new_value,
                                           (__int64) old_value);

    if ((uint64_t) result != old_value) {
        return 0;
    }

    return 1;
}

void cfl_atomic_store(uint64_t *storage, uint64_t new_value)
{
    _InterlockedExchange64((volatile __int64 *) storage, (__int64) new_value);
}

uint64_t cfl_atomic_load(uint64_t *storage)
{
    return (uint64_t) _InterlockedOr64((volatile __int64 *) storage, 0);
}

#endif
