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

#ifndef FLB_FILTER_THROTTLE_TAG_H
#define FLB_FILTER_THROTTLE_TAG_H

/* actions */
#define throttle_tag_RET_KEEP  0
#define throttle_tag_RET_DROP  1

/* defaults */
#define THROTTLE_TAG_DEFAULT_RATE  "100.0"
#define THROTTLE_TAG_DEFAULT_GLOBAL_RATE  "0.0"
#define THROTTLE_TAG_DEFAULT_GLOBAL_WINDOW_NAME  "__global_window__"
#define THROTTLE_TAG_DEFAULT_WINDOW  "5"
#define THROTTLE_TAG_DEFAULT_INTERVAL  "1"
#define THROTTLE_TAG_DEFAULT_STATUS "false"
#define THROTTLE_TAG_DEFAULT_STARTUP_WAIT "1m"
#define THROTTLE_TAG_DEFAULT_WINDOW_DURATION "60"
#define THROTTLE_TAG_WINDOW_TABLE_DEFAULT_SIZE "256"

#include "window_tag.h"

struct flb_filter_throttle_tag_ctx
{
    int slide_interval;
    int window_time_duration;
    double max_tag_rate;
    double max_global_rate;
    unsigned int window_size;
    unsigned int hash_table_size;
    bool throttle_per_tag;
    size_t log_fields_depth;
    size_t name_fields_depth;
    void *ticker_id;
    int print_status;
    int startup_wait;
    int startup_time;

    volatile bool done;

    struct mk_list name_fields;
    struct mk_list log_fields;

    /* internal */
    struct throttle_tag_table *hash;
    struct flb_filter_instance *ins;
};

#endif
