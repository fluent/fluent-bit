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


#ifndef CMT_ENCODE_OPENTELEMETRY_H
#define CMT_ENCODE_OPENTELEMETRY_H

#include <cmetrics/cmetrics.h>
#include <opentelemetry/proto/metrics/v1/metrics.pb-c.h>
#include <opentelemetry/proto/collector/metrics/v1/metrics_service.pb-c.h>

#define CMT_ENCODE_OPENTELEMETRY_SUCCESS                0
#define CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR       1
#define CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR 2
#define CMT_ENCODE_OPENTELEMETRY_UNEXPECTED_METRIC_TYPE 3
#define CMT_ENCODE_OPENTELEMETRY_DATA_POINT_INIT_ERROR  4

struct cmt_opentelemetry_context
{
    size_t                                          resource_index;
    size_t                                          scope_metrics_count;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics **scope_metrics_list;
    Opentelemetry__Proto__Metrics__V1__MetricsData *metrics_data;
    struct cmt                                     *cmt;
};

cfl_sds_t cmt_encode_opentelemetry_create(struct cmt *cmt);
void cmt_encode_opentelemetry_destroy(cfl_sds_t text);

#endif
