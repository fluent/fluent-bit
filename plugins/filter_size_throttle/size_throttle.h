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

#ifndef FLB_SIZE_FILTER_THROTTLE_H
#define FLB_SIZE_FILTER_THROTTLE_H

/* actions */
#define SIZE_THROTTLE_RET_KEEP  0
#define SIZE_THROTTLE_RET_DROP  1

/* defaults */
#define SIZE_THROTTLE_DEFAULT_RATE  1024*1024   //bytes
#define SIZE_THROTTLE_DEFAULT_WINDOW  5
#define SIZE_THROTTLE_DEFAULT_INTERVAL  1
#define SIZE_THROTTLE_DEFAULT_STATUS FLB_FALSE;
#define SIZE_THROTTLE_DEFAULT_LOG_FIELD  "*"
#define SIZE_THROTTLE_DEFAULT_NAME_FIELD  "*"
#define SIZE_THROTTLE_DEFAULT_WINDOW_DURATION 60

#include "size_window.h"

struct flb_filter_size_throttle_ctx
{
    double max_size_rate;
    unsigned int window_size;
    int slide_interval;
    int window_time_duration;
    struct mk_list name_fields;
    struct mk_list log_fields;
    size_t log_fields_depth;
    size_t name_fields_depth;
    void *ticker_id;
    volatile bool done;
    int print_status;
    /* internal */
    struct size_throttle_table *hash;
};

#endif
