/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Throttling
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

#ifndef FLB_FILTER_THROTTLE_H
#define FLB_FILTER_THROTTLE_H

/* actions */
#define THROTTLE_RET_KEEP  0
#define THROTTLE_RET_DROP  1

/* defaults */
#define THROTTLE_DEFAULT_RATE  1
#define THROTTLE_DEFAULT_WINDOW  5
#define THROTTLE_DEFAULT_INTERVAL  "1"
#define THROTTLE_DEFAULT_STATUS FLB_FALSE;

struct flb_filter_throttle_ctx {
    double    max_rate;
    unsigned int    window_size;
    char  *slide_interval;
    int print_status;

    /* internal */
    struct throttle_window *hash;
};

struct ticker {
    struct flb_filter_throttle_ctx *ctx;
    bool done;
    double seconds;
};

#endif
