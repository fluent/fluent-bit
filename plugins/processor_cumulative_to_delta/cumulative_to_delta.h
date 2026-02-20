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

#ifndef FLB_PROCESSOR_CUMULATIVE_TO_DELTA_H
#define FLB_PROCESSOR_CUMULATIVE_TO_DELTA_H

#include <cmetrics/cmetrics.h>

struct flb_cumulative_to_delta_ctx;

#define FLB_C2D_INITIAL_VALUE_AUTO 0
#define FLB_C2D_INITIAL_VALUE_KEEP 1
#define FLB_C2D_INITIAL_VALUE_DROP 2

struct flb_cumulative_to_delta_ctx *flb_cumulative_to_delta_ctx_create(
    int initial_value_mode,
    int drop_on_reset,
    uint64_t processor_start_timestamp);
void flb_cumulative_to_delta_ctx_destroy(
    struct flb_cumulative_to_delta_ctx *context);
int flb_cumulative_to_delta_ctx_process(
    struct flb_cumulative_to_delta_ctx *context,
    struct cmt *metrics_context);
int flb_cumulative_to_delta_ctx_configure(
    struct flb_cumulative_to_delta_ctx *context,
    int max_staleness_seconds,
    int max_series);

#endif
