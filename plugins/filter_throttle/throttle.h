/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Throttling
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

#ifndef FLB_FILTER_THROTTLE_H
#define FLB_FILTER_THROTTLE_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_pthread.h>

/* actions */
#define THROTTLE_RET_KEEP  0
#define THROTTLE_RET_DROP  1

/* defaults */
#define THROTTLE_DEFAULT_RATE "1"
#define THROTTLE_DEFAULT_WINDOW  "5"
#define THROTTLE_DEFAULT_INTERVAL  "1"
#define THROTTLE_DEFAULT_STATUS "false"
#define THROTTLE_DEFAULT_RETAIN "false"

struct ticker {
    pthread_t thr;
    double seconds;
};

struct flb_filter_throttle_ctx {
    double    max_rate;
    unsigned int    window_size;
    const char  *slide_interval;
    int print_status;
    int retain_data;

    /* internal */
    struct throttle_window *hash;
    struct flb_filter_instance *ins;
    struct ticker ticker_data;
};



#endif