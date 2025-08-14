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

#ifndef FLB_PROCESSOR_LOG_SAMPLING_H
#define FLB_PROCESSOR_LOG_SAMPLING_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_processor_plugin.h>


/* Window type constants */
#define LOG_SAMPLING_WINDOW_TYPE_FIXED      "fixed"
#define LOG_SAMPLING_WINDOW_TYPE_SLIDING    "sliding"
#define LOG_SAMPLING_WINDOW_TYPE_EXPONENTIAL "exponential"

enum log_sampling_window_type {
    LOG_SAMPLING_WINDOW_FIXED,
    LOG_SAMPLING_WINDOW_SLIDING,
    LOG_SAMPLING_WINDOW_EXPONENTIAL
};

struct log_sampling_ctx {
    /* Configuration */
    enum log_sampling_window_type window_type;
    int window_size;           /* Window size in seconds */
    int max_logs_per_window;   /* Maximum logs to keep per window */
    
    /* Exponential decay settings */
    double decay_base_rate;    /* Base sampling rate (0.0-1.0) */
    double decay_factor;       /* Decay factor per interval */
    int decay_interval;        /* Decay interval in seconds */
    
    /* Window state for runtime */
    struct sampling_state {
        /* Fixed window state */
        time_t window_start;
        int current_window_count;
        
        /* Sliding window state */
        struct {
            time_t timestamp;
            int count;
        } *buckets;
        int bucket_count;
        
        /* Statistics */
        uint64_t total_logs_seen;
        uint64_t total_logs_sampled;
    } state;
    
    /* Fluent Bit context */
    struct flb_processor_instance *ins;
};

/* Exported sampling functions */
FLB_EXPORT int flb_sampling_fixed_window(struct sampling_state *state,
                                         time_t current_time,
                                         int window_size,
                                         int max_logs_per_window);

FLB_EXPORT int flb_sampling_sliding_window(struct sampling_state *state,
                                           time_t current_time,
                                           int window_size,
                                           int max_logs_per_window);

FLB_EXPORT int flb_sampling_exponential(time_t window_start,
                                        time_t current_time,
                                        double base_rate,
                                        double decay_factor,
                                        int decay_interval);

#endif