/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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
 * TODO 2: Find out how are catastrophic errors handled in cmetrics and apply the same 
 *         method here
 */

#ifdef CMT_ATOMIC_HAVE_AUTO_INITIALIZE

__attribute__((constructor))
static void cmt_atomic_constructor(void)
{
    int result;

    result = cmt_atomic_initialize();

    if (0 != result) {
        /* TODO : Determine if we want to enable automatic initialization for this case
         *        or not, the things to keep in mind are that this could fail in 
         *        catastrophic situations (OOM on startup?) and we need to handle that 
         */
        printf("CMT ATOMIC : Unrecoverable error initializing atomic operation lock\n");
        exit(1);
    } 
}

#endif

inline int cmt_atomic_initialize()
{
    int result;

    result = pthread_mutex_init(&atomic_operation_lock, NULL);

    if (0 != result) {
        return 1;
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
    else
    {
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

    do {
        result = pthread_mutex_lock(&atomic_operation_lock);
    }
    while (result != 0);

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

    do {
        result = pthread_mutex_lock(&atomic_operation_lock);
    }
    while (result != 0);

    retval = *storage;

    pthread_mutex_unlock(&atomic_operation_lock);        

    return retval;
}
