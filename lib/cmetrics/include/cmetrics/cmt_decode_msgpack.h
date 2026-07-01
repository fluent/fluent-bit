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


#ifndef CMT_DECODE_MSGPACK_H
#define CMT_DECODE_MSGPACK_H

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_mpack_utils_defs.h>

#define CMT_DECODE_MSGPACK_SUCCESS                    CMT_MPACK_SUCCESS
#define CMT_DECODE_MSGPACK_INSUFFICIENT_DATA          CMT_MPACK_INSUFFICIENT_DATA
#define CMT_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR     CMT_MPACK_INVALID_ARGUMENT_ERROR
#define CMT_DECODE_MSGPACK_ALLOCATION_ERROR           CMT_MPACK_ALLOCATION_ERROR
#define CMT_DECODE_MSGPACK_CORRUPT_INPUT_DATA_ERROR   CMT_MPACK_CORRUPT_INPUT_DATA_ERROR
#define CMT_DECODE_MSGPACK_CONSUME_ERROR              CMT_MPACK_CONSUME_ERROR
#define CMT_DECODE_MSGPACK_ENGINE_ERROR               CMT_MPACK_ENGINE_ERROR
#define CMT_DECODE_MSGPACK_PENDING_MAP_ENTRIES        CMT_MPACK_PENDING_MAP_ENTRIES
#define CMT_DECODE_MSGPACK_PENDING_ARRAY_ENTRIES      CMT_MPACK_PENDING_ARRAY_ENTRIES
#define CMT_DECODE_MSGPACK_UNEXPECTED_KEY_ERROR       CMT_MPACK_UNEXPECTED_KEY_ERROR
#define CMT_DECODE_MSGPACK_UNEXPECTED_DATA_TYPE_ERROR CMT_MPACK_UNEXPECTED_DATA_TYPE_ERROR

#define CMT_DECODE_MSGPACK_DICTIONARY_LOOKUP_ERROR    CMT_MPACK_ERROR_CUTOFF + 1
#define CMT_DECODE_MSGPACK_VERSION_ERROR              CMT_MPACK_ERROR_CUTOFF + 2

struct cmt_msgpack_temporary_bucket {
    double upper_bound;
    struct cfl_list _head;
};

struct cmt_msgpack_decode_context {
    struct cmt        *cmt;
    struct cmt_map    *map;
    struct cmt_metric *metric;
    double            *bucket_list;
    size_t             bucket_count;
    double            *quantile_list;
    size_t             quantile_count;
    uint64_t           *summary_quantiles;
    size_t             summary_quantiles_count;
    int                aggregation_type;
    int                metric_value_type_set;
};

int cmt_decode_msgpack_create(struct cmt **out_cmt, char *in_buf, size_t in_size, 
                              size_t *offset);
void cmt_decode_msgpack_destroy(struct cmt *cmt);

#endif
