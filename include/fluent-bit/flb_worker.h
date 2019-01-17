/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_WORKER_H
#define FLB_WORKER_H

#include <fluent-bit/flb_config.h>

struct flb_config;

struct flb_worker {
    struct mk_event event;

    /* Callback data */
    void (*func) (void *);     /* function    */
    void *data;                /* opaque data */
    pthread_t tid;             /* thread ID   */

    /* Logging */
#ifdef _WIN32
    intptr_t log[2];
#else
    int log[2];
#endif

    /* Runtime context */
    void *config;
    void *log_ctx;

    struct mk_list _head;    /* link to head at config->workers */
};

int flb_worker_init(struct flb_config *config);
struct flb_worker *flb_worker_get();
int flb_worker_create(void (*func) (void *), void *arg, pthread_t *tid,
                      struct flb_config *config);
struct flb_worker *flb_worker_lookup(pthread_t tid, struct flb_config *config);
int flb_worker_exit(struct flb_config *config);
int flb_worker_log_level(struct flb_worker *worker);

#endif
