/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#define FLB_TLS_INIT(key)          pthread_key_create(&key, NULL)
#define FLB_TLS_DEFINE(type, name) pthread_key_t name;
#endif


/* FIXME: this extern should be auto-populated from flb_thread_storage.h */
extern FLB_TLS_DEFINE(struct flb_worker, flb_worker_ctx)


#endif /* !FLB_THREAD_STORAGE_H */
