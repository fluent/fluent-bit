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

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <cmetrics/cmt_atomic.h>

pthread_mutex_t atomic_operation_lock;
static int      atomic_operation_system_initialized = 0;

/* TODO: Determne if we want to keep this backend as well as how / if we want to handle
 *       pthread_mutex_unlock errors (investigate and understand what could cause them),
 *       as well as pthread_mutex_lock (determine if we want to apply some sort of retry
 *       limit there as well)
 *
 */

inline int cmt_atomic_initialize()
{
    int result;

    if (0 == atomic_operation_system_initialized) {
        result = pthread_mutex_init(&atomic_operation_lock, NULL);

        if (0 != result) {
            return 1;
        }

        atomic_operation_system_initialized = 1;
    }

    return 0;
}

inline int cmt_atomic_compare_exchange(uint64_t *storage, 
                                       uint64_t old_value, uint64_t new_value)
{
    int result;

    if (0 == atomic_operation_system_initialized) {
        printf("CMT ATOMIC : Atomic operation backend not initalized\n");
        exit(1);
    }

    result = pthread_mutex_lock(&atomic_operation_lock);

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

    pthread_mutex_unlock(&atomic_operation_lock);        
    
    return result;
}

inline void cmt_atomic_store(uint64_t *storage, uint64_t new_value)
{
    int result;

    if (0 == atomic_operation_system_initialized) {
        printf("CMT ATOMIC : Atomic operation backend not initalized\n");
        exit(1);
    }

    result = pthread_mutex_lock(&atomic_operation_lock);

    if (result != 0) {
        /* We should notify the user somehow */
    }

    *storage = new_value;

    pthread_mutex_unlock(&atomic_operation_lock);        
}

inline uint64_t cmt_atomic_load(uint64_t *storage)
{
    int result;
    uint64_t retval;

    if (0 == atomic_operation_system_initialized) {
        printf("CMT ATOMIC : Atomic operation backend not initalized\n");
        exit(1);
    }

    result = pthread_mutex_lock(&atomic_operation_lock);

    if (result != 0) {
        /* We should notify the user somehow */
    }

    retval = *storage;

    pthread_mutex_unlock(&atomic_operation_lock);        

    return retval;
}
