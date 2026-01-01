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

#ifndef FLB_LOCK_H
#define FLB_LOCK_H

#include <fluent-bit/flb_pthread.h>
#include <stddef.h>

/* The current values mean the system will
 * wait for 100 seconds at most in 50 millisecond increments.
 *
 * This is the worst case scenario and in reality there will
 * be no wait in 99.9% of the cases.
 */

#define FLB_LOCK_INFINITE_RETRY_LIMIT 0
#define FLB_LOCK_DEFAULT_RETRY_LIMIT  100
#define FLB_LOCK_DEFAULT_RETRY_DELAY  50000

typedef pthread_mutex_t flb_lock_t;

int flb_lock_init(flb_lock_t *lock);

int flb_lock_destroy(flb_lock_t *lock);

int flb_lock_acquire(flb_lock_t *lock,
                     size_t retry_limit,
                     size_t retry_delay);

int flb_lock_release(flb_lock_t *lock,
                     size_t retry_limit,
                     size_t retry_delay);

#endif
