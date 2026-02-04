/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
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



#ifndef FLB_HS_API_V1_HEALTH_H
#define FLB_HS_API_V1_HEALTH_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_http_server.h>

struct flb_health_check_metrics_counter {

     /*
     * health check error limit,
     * setup by customer through config: HC_Errors_Count
     */
    int error_limit;

    /* counter the error number in metrics*/
    int error_counter;

    /*
    * health check retry failed limit,
    * setup by customer through config: HC_Retry_Failure_Count
    */
    int retry_failure_limit;

    /* count the retry failed number in metrics*/
    int retry_failure_counter;

    /*period limit, setup by customer through config: HC_Period*/
    int period_limit;

    /* count the seconds in one period*/
    int period_counter;

};


/*
 * error and retry failure buffers that contains certain cached data to be used
 * by health check.
 */
struct flb_hs_hc_buf {
    int users;
    int error_count;
    int retry_failure_count;
    struct mk_list _head;
};

/*
 * in/out records sample at a certain timestamp.
 */
struct flb_hs_throughput_sample {
    uint64_t in_records;
    uint64_t out_records;
    uint64_t timestamp_seconds;
};

/* ring buffer + helper functions for storing samples */
struct flb_hs_throughput_samples {
    struct flb_hs_throughput_sample *items;
    int size;
    int count;
    int insert;
};

/* throughput health check state */
struct flb_hs_throughput_state {
    int enabled;
    struct mk_list *input_plugins;
    struct mk_list *output_plugins;
    double out_in_ratio_threshold;

    struct flb_hs_throughput_samples samples;
    int healthy;
};

/* health endpoint*/
int api_v1_health(struct flb_hs *hs);

/* clean up health resource when shutdown*/
void flb_hs_health_destroy();
#endif
