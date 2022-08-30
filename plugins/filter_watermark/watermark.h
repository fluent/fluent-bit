/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Throttling
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

#ifndef FLB_FILTER_WATERMARK_H
#define FLB_FILTER_WATERMARK_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>

#define WATERMARK_DEFAULT_VALUE 3
#define WINDOW_SIZE_DEFAULT_VALUE 10
#define CACHE_SIZE_DEFAULT_VALUE 100

struct flb_filter_watermark_record {
    struct tm time_stamp;
    msgpack_sbuffer *sbuffer;
    size_t bytes;
};

struct flb_filter_watermark_ctx {
    int watermark;
    time_t win_right_edge;
    time_t win_left_edge;
    int init_flag;
    int window_size;
    struct c_heap_t *h;
    flb_sds_t time_field;
    struct flb_filter_watermark_record * record_pointer_cache_out_array[CACHE_SIZE_DEFAULT_VALUE];
    int record_count;
    struct flb_filter_instance *ins;
};
#endif
