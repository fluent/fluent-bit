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

#ifndef FLB_SIZE_FILTER_THROTTLE_H
#define FLB_SIZE_FILTER_THROTTLE_H

/* actions */
#define throttle_size_RET_KEEP  0
#define throttle_size_RET_DROP  1

/* defaults */
#define throttle_size_DEFAULT_RATE  1024*1024   /* bytes */
#define throttle_size_DEFAULT_WINDOW  5
#define throttle_size_DEFAULT_INTERVAL  1
#define throttle_size_DEFAULT_STATUS FLB_FALSE;
#define throttle_size_DEFAULT_LOG_FIELD  "*"
#define throttle_size_DEFAULT_NAME_FIELD  "*"
#define throttle_size_DEFAULT_WINDOW_DURATION 60
#define throttle_size_WINDOW_TABLE_DEFAULT_SIZE 256

#include "size_window.h"

struct flb_filter_throttle_size_ctx
{
    int slide_interval;
    int window_time_duration;
    double max_size_rate;
    unsigned int window_size;
    size_t log_fields_depth;
    size_t name_fields_depth;
    void *ticker_id;
    int print_status;

    volatile bool done;

    struct mk_list name_fields;
    struct mk_list log_fields;

    /* internal */
    struct throttle_size_table *hash;
    struct flb_filter_instance *ins;
};

#endif
