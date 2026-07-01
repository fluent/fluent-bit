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

#ifndef FLB_THREAD_STORAGE_H
#define FLB_THREAD_STORAGE_H

#include <fluent-bit/flb_info.h>

#ifdef FLB_SYSTEM_WINDOWS
#include <monkey/mk_core/external/winpthreads.h>
#else
#include <pthread.h>
#endif

/* Ideal case when the compiler support direct storage through __thread */
#ifdef FLB_HAVE_C_TLS
#define FLB_TLS_SET(key, val)      key=val
#define FLB_TLS_GET(key)           key
#define FLB_TLS_INIT(key)          do {} while (0)
#define FLB_TLS_DEFINE(type, name) __thread type *name;

#else

/* Fallback mode using pthread_*() for Thread-Local-Storage usage */
#define FLB_TLS_SET(key, val)      pthread_setspecific(key, (void *) val)
#define FLB_TLS_GET(key)           pthread_getspecific(key)

/*
 * Thread-safe idempotent initialization using pthread_once.
 * This ensures pthread_key_create is only called once even if FLB_TLS_INIT
 * is called from multiple locations (different compilation units, hot reload, etc).
 */
#define FLB_TLS_INIT(key) \
    do { \
        extern pthread_once_t key##_once; \
        void key##_init_func(void); \
        pthread_once(&key##_once, key##_init_func); \
    } while(0)

/* Define a TLS key with its pthread_once control and init function */
#define FLB_TLS_DEFINE(type, name) \
    pthread_key_t name; \
    pthread_once_t name##_once = PTHREAD_ONCE_INIT; \
    void name##_init_func(void) { \
        pthread_key_create(&name, NULL); \
    }

/* Declare a TLS key that's defined elsewhere */
#define FLB_TLS_DECLARE(type, name) \
    extern pthread_key_t name; \
    extern pthread_once_t name##_once; \
    void name##_init_func(void);
#endif


/* FIXME: this extern should be auto-populated from flb_thread_storage.h */
#ifndef FLB_HAVE_C_TLS
FLB_TLS_DECLARE(struct flb_worker, flb_worker_ctx);
#else
extern FLB_TLS_DEFINE(struct flb_worker, flb_worker_ctx);
#endif


#endif /* !FLB_THREAD_STORAGE_H */
