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

#include <pthread.h>

#include <cfl/cfl_atomic.h>

static pthread_mutex_t cfl_atomic_operation_lock;
static pthread_once_t  cfl_atomic_operation_system_once = PTHREAD_ONCE_INIT;
static int             cfl_atomic_operation_system_initialized = 0;
static int             cfl_atomic_operation_system_status = 0;

static void cfl_atomic_bootstrap()
{
    cfl_atomic_operation_system_status =
        pthread_mutex_init(&cfl_atomic_operation_lock, NULL);

    if (cfl_atomic_operation_system_status == 0) {
        cfl_atomic_operation_system_initialized = 1;
    }
}

int cfl_atomic_initialize()
{
    pthread_once(&cfl_atomic_operation_system_once, cfl_atomic_bootstrap);

    if (cfl_atomic_operation_system_status != 0) {
        return 1;
    }

    return 0;
}

int cfl_atomic_compare_exchange(uint64_t *storage,
                                uint64_t old_value, uint64_t new_value)
{
    int result;

    if (cfl_atomic_initialize() != 0 ||
        cfl_atomic_operation_system_initialized == 0) {
        return 0;
    }

    result = pthread_mutex_lock(&cfl_atomic_operation_lock);

    if (result != 0) {
        return 0;
    }

    if (*storage == old_value) {
        *storage = new_value;

        result = 1;
    }
    else {
        result = 0;
    }

    pthread_mutex_unlock(&cfl_atomic_operation_lock);

    return result;
}

void cfl_atomic_store(uint64_t *storage, uint64_t new_value)
{
    int result;

    if (cfl_atomic_initialize() != 0 ||
        cfl_atomic_operation_system_initialized == 0) {
        return;
    }

    result = pthread_mutex_lock(&cfl_atomic_operation_lock);

    if (result != 0) {
        return;
    }

    *storage = new_value;

    pthread_mutex_unlock(&cfl_atomic_operation_lock);
}

uint64_t cfl_atomic_load(uint64_t *storage)
{
    int      result;
    uint64_t retval;

    if (cfl_atomic_initialize() != 0 ||
        cfl_atomic_operation_system_initialized == 0) {
        return 0;
    }

    result = pthread_mutex_lock(&cfl_atomic_operation_lock);

    if (result != 0) {
        return 0;
    }

    retval = *storage;

    pthread_mutex_unlock(&cfl_atomic_operation_lock);

    return retval;
}
