/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#ifndef FLB_IN_GPU_METRICS_H
#define FLB_IN_GPU_METRICS_H

#include <fluent-bit/flb_input_plugin.h>
#include "gpu_common.h"

struct gpu_card {
    int id;
    flb_sds_t hwmon_path;
    struct cfl_list _head;
};

struct in_gpu_metrics {
    flb_sds_t path_sysfs;
    flb_sds_t cards_include;
    flb_sds_t cards_exclude;
    int scrape_interval;
    int enable_power;
    int enable_temperature;
    int coll_fd;
    int cards_detected;

    struct cfl_list cards;

    struct cmt *cmt;
    struct cmt_gauge *g_utilization;
    struct cmt_gauge *g_mem_used;
    struct cmt_gauge *g_mem_total;
    struct cmt_gauge *g_clock;
    struct cmt_gauge *g_power;
    struct cmt_gauge *g_temp;
    struct cmt_gauge *g_fan_speed;
    struct cmt_gauge *g_fan_pwm;

    /* plugin instance */
    struct flb_input_instance *ins;

};

#endif
