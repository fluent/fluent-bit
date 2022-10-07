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


#ifndef CMT_DECODE_OPENTELEMETRY_H
#define CMT_DECODE_OPENTELEMETRY_H

#include <cmetrics/cmetrics.h>
#include <opentelemetry/proto/metrics/v1/metrics.pb-c.h>
#include <opentelemetry/proto/collector/metrics/v1/metrics_service.pb-c.h>

#define CMT_DECODE_OPENTELEMETRY_SUCCESS                0
#define CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR       1
#define CMT_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR 2
#define CMT_DECODE_OPENTELEMETRY_KVLIST_ACCESS_ERROR    3
#define CMT_DECODE_OPENTELEMETRY_ARRAY_ACCESS_ERROR     4

struct cmt_opentelemetry_decode_context {
    struct cmt        *cmt;
    struct cmt_map    *map;
    struct cmt_metric *metric;
    char             **namespace_identifiers;
    char             **subsystem_identifiers;
};

int cmt_decode_opentelemetry_create(struct cfl_list *result_context_list,
                                    char *in_buf, size_t in_size,
                                    size_t *offset);

void cmt_decode_opentelemetry_destroy(struct cfl_list *context_list);

#endif
