/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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


#ifndef CMT_DECODE_STATSD_H
#define CMT_DECODE_STATSD_H

#include <cmetrics/cmetrics.h>

#define CMT_DECODE_STATSD_TYPE_COUNTER 1
#define CMT_DECODE_STATSD_TYPE_GAUGE   2
#define CMT_DECODE_STATSD_TYPE_TIMER   3
#define CMT_DECODE_STATSD_TYPE_SET     4

#define CMT_DECODE_STATSD_SUCCESS                  0
#define CMT_DECODE_STATSD_ALLOCATION_ERROR         1
#define CMT_DECODE_STATSD_UNEXPECTED_ERROR         2
#define CMT_DECODE_STATSD_INVALID_ARGUMENT_ERROR   3
#define CMT_DECODE_STATSD_UNEXPECTED_METRIC_TYPE   4
#define CMT_DECODE_STATSD_DECODE_ERROR             5
#define CMT_DECODE_STATSD_UNPACK_ERROR             6
#define CMT_DECODE_STATSD_UNSUPPORTED_METRIC_TYPE  7
#define CMT_DECODE_STATSD_INVALID_TAG_FORMAT_ERROR 8

#define CMT_DECODE_STATSD_GAUGE_OBSERVER     1 << 0

/*
 * The "cmt_statsd_message" represents a single line in UDP packet.
 * It's just a bunch of pointers to ephemeral buffer.
 */
struct cmt_statsd_message {
    char *bucket;
    int bucket_len;
    char *value;
    char *labels;
    int value_len;
    int type;
    double sample_rate;
};

int cmt_decode_statsd_create(struct cmt **out_cmt, char *in_buf, size_t in_size, int flags);
void cmt_decode_statsd_destroy(struct cmt *cmt);

#endif
