/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_OUT_DORIS_H
#define FLB_OUT_DORIS_H

#include <fluent-bit/flb_pthread.h>

struct flb_upstream;
struct flb_output_instance;
struct mk_list;

struct flb_doris_progress_reporter {
    volatile int running;
    size_t total_bytes;
    size_t total_rows;
    size_t failed_rows;
};

struct flb_out_doris {
    char *host;
    int port;
    char uri[256];
    char *endpoint_type;

    char *user;
    char *password;

    flb_sds_t database;
    flb_sds_t table;

    flb_sds_t label_prefix;
    int add_label;

    flb_sds_t time_key;
    flb_sds_t date_key;        /* internal use */

    /* Output format */
    int out_format;

    /* doris stream load headers */
    struct mk_list *headers;

    int log_request;
    int log_progress_interval;

    struct flb_doris_progress_reporter *reporter;
    pthread_t reporter_thread;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* doris be connection pool, key: string* be_address, value: flb_upstream* u */
    struct flb_hash_table *u_pool;
    pthread_mutex_t mutex;
    int mutex_initialized;

    /* Plugin instance */
    struct flb_output_instance *ins;
};

#endif
