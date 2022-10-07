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


#ifndef CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_H
#define CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_H

#include <cmetrics/cmetrics.h>
#include <prometheus_remote_write/remote.pb-c.h>

#define CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ADD_METADATA           CMT_FALSE

#define CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS                0
#define CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR       1
#define CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_UNEXPECTED_ERROR       2
#define CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_INVALID_ARGUMENT_ERROR 3
#define CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_UNEXPECTED_METRIC_TYPE 4

struct cmt_prometheus_metric_metadata {
    Prometheus__MetricMetadata data;
    struct cfl_list _head;
};

struct cmt_prometheus_time_series {
    uint64_t               label_set_hash;
    size_t                 entries_set;
    Prometheus__TimeSeries data;
    struct cfl_list _head;
};

struct cmt_prometheus_remote_write_context
{
    struct cfl_list           time_series_entries;
    struct cfl_list           metadata_entries;
    uint64_t                 sequence_number;
    Prometheus__WriteRequest write_request;
    struct cmt              *cmt;
};

cfl_sds_t cmt_encode_prometheus_remote_write_create(struct cmt *cmt);
void cmt_encode_prometheus_remote_write_destroy(cfl_sds_t text);

#endif
