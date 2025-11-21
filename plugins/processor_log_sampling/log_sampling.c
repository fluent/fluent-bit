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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_mp_chunk.h>

#include <math.h>

#include "log_sampling.h"

static int parse_window_type(const char *str)
{
    if (strcasecmp(str, LOG_SAMPLING_WINDOW_TYPE_FIXED) == 0) {
        return LOG_SAMPLING_WINDOW_FIXED;
    }
    else if (strcasecmp(str, LOG_SAMPLING_WINDOW_TYPE_SLIDING) == 0) {
        return LOG_SAMPLING_WINDOW_SLIDING;
    }
    else if (strcasecmp(str, LOG_SAMPLING_WINDOW_TYPE_EXPONENTIAL) == 0) {
        return LOG_SAMPLING_WINDOW_EXPONENTIAL;
    }
    return -1;
}

FLB_EXPORT int flb_sampling_fixed_window(struct sampling_state *state,
                                         time_t current_time,
                                         int window_size,
                                         int max_logs_per_window)
{
    /* Check if we need to start a new window */
    if (current_time >= state->window_start + window_size) {
        state->window_start = (current_time / window_size) * window_size;
        state->current_window_count = 0;
    }
    
    /* Sample if under limit */
    if (state->current_window_count < max_logs_per_window) {
        state->current_window_count++;
        return FLB_TRUE;
    }
    
    return FLB_FALSE;
}

static int should_sample_fixed_window(struct log_sampling_ctx *ctx, struct flb_time *tm)
{
    time_t current_time = tm->tm.tv_sec;
    int result;
    
    result = flb_sampling_fixed_window(&ctx->state, current_time, 
                                       ctx->window_size, ctx->max_logs_per_window);
    
    if (result == FLB_TRUE) {
        flb_plg_trace(ctx->ins, "fixed window: sampled log %d/%d in window",
                      ctx->state.current_window_count, ctx->max_logs_per_window);
    } else {
        flb_plg_trace(ctx->ins, "fixed window: dropped log, window full (%d/%d)",
                      ctx->state.current_window_count, ctx->max_logs_per_window);
    }
    
    return result;
}

FLB_EXPORT int flb_sampling_sliding_window(struct sampling_state *state,
                                           time_t current_time,
                                           int window_size,
                                           int max_logs_per_window)
{
    int bucket_index = current_time % state->bucket_count;
    time_t cutoff_time = current_time - window_size;
    int total_in_window = 0;
    int i;
    
    /* Clear old buckets */
    for (i = 0; i < state->bucket_count; i++) {
        if (state->buckets[i].timestamp < cutoff_time) {
            state->buckets[i].count = 0;
            state->buckets[i].timestamp = 0;
        }
        total_in_window += state->buckets[i].count;
    }
    
    /* Sample if under limit */
    if (total_in_window < max_logs_per_window) {
        state->buckets[bucket_index].timestamp = current_time;
        state->buckets[bucket_index].count++;
        return FLB_TRUE;
    }
    
    return FLB_FALSE;
}

static int should_sample_sliding_window(struct log_sampling_ctx *ctx, struct flb_time *tm)
{
    time_t current_time = tm->tm.tv_sec;
    int result;
    
    result = flb_sampling_sliding_window(&ctx->state, current_time,
                                         ctx->window_size, ctx->max_logs_per_window);
    
    if (result == FLB_TRUE) {
        int bucket_index = current_time % ctx->state.bucket_count;
        flb_plg_trace(ctx->ins, "sliding window: sampled log, bucket[%d] count=%d",
                      bucket_index, ctx->state.buckets[bucket_index].count);
    } else {
        flb_plg_trace(ctx->ins, "sliding window: dropped log, window full");
    }
    
    return result;
}

FLB_EXPORT int flb_sampling_exponential(time_t window_start,
                                        time_t current_time,
                                        double base_rate,
                                        double decay_factor,
                                        int decay_interval)
{
    double current_rate;
    double random_value;
    int intervals_passed;
    
    /* Calculate time-based decay from start time */
    intervals_passed = (current_time - window_start) / decay_interval;
    
    if (intervals_passed == 0) {
        current_rate = base_rate;
    }
    else {
        current_rate = base_rate * pow(decay_factor, intervals_passed);
        /* Cap at minimum rate */
        if (current_rate < 0.001) {
            current_rate = 0.001;
        }
    }
    
    /* Random sampling with computed rate */
    random_value = (double)rand() / RAND_MAX;
    return (random_value < current_rate) ? FLB_TRUE : FLB_FALSE;
}

static int should_sample_exponential(struct log_sampling_ctx *ctx, struct flb_time *tm)
{
    time_t current_time = tm->tm.tv_sec;
    int result;
    
    result = flb_sampling_exponential(ctx->state.window_start, current_time,
                                      ctx->decay_base_rate, ctx->decay_factor,
                                      ctx->decay_interval);
    
    if (result == FLB_TRUE) {
        flb_plg_trace(ctx->ins, "exponential: sampled log");
    } else {
        flb_plg_trace(ctx->ins, "exponential: dropped log");
    }
    
    return result;
}

static int cb_log_sampling_init(struct flb_processor_instance *ins,
                                void *source_plugin_instance,
                                int source_plugin_type,
                                struct flb_config *config)
{
    struct log_sampling_ctx *ctx;
    const char *window_type_str;
    int ret;
    
    ctx = flb_calloc(1, sizeof(struct log_sampling_ctx));
    if (!ctx) {
        flb_errno();
        return FLB_PROCESSOR_FAILURE;
    }
    
    ctx->ins = ins;
    
    /* Load configuration */
    ret = flb_processor_instance_config_map_set(ins, ctx);
    if (ret < 0) {
        flb_free(ctx);
        return FLB_PROCESSOR_FAILURE;
    }
    
    /* Parse window type */
    window_type_str = flb_processor_instance_get_property("window_type", ins);
    if (window_type_str) {
        ctx->window_type = parse_window_type(window_type_str);
        if (ctx->window_type == -1) {
            flb_plg_error(ins, "invalid window_type: %s", window_type_str);
            flb_free(ctx);
            return FLB_PROCESSOR_FAILURE;
        }
    }
    else {
        ctx->window_type = LOG_SAMPLING_WINDOW_FIXED;
    }
    
    /* Initialize window state */
    if (ctx->window_type == LOG_SAMPLING_WINDOW_SLIDING) {
        ctx->state.bucket_count = ctx->window_size;
        ctx->state.buckets = flb_calloc(ctx->state.bucket_count, 
                                       sizeof(*ctx->state.buckets));
        if (!ctx->state.buckets) {
            flb_errno();
            flb_free(ctx);
            return FLB_PROCESSOR_FAILURE;
        }
        flb_plg_info(ins, "initialized sliding window with %d buckets", ctx->state.bucket_count);
    }
    
    ctx->state.window_start = time(NULL);
    
    ins->context = ctx;
    
    /* Log configuration */
    flb_plg_info(ins, "log_sampling processor initialized:");
    flb_plg_info(ins, "  window_type: %s", 
                 ctx->window_type == LOG_SAMPLING_WINDOW_FIXED ? LOG_SAMPLING_WINDOW_TYPE_FIXED :
                 ctx->window_type == LOG_SAMPLING_WINDOW_SLIDING ? LOG_SAMPLING_WINDOW_TYPE_SLIDING : 
                 LOG_SAMPLING_WINDOW_TYPE_EXPONENTIAL);
    flb_plg_info(ins, "  window_size: %d seconds", ctx->window_size);
    flb_plg_info(ins, "  max_logs_per_window: %d", ctx->max_logs_per_window);
    if (ctx->window_type == LOG_SAMPLING_WINDOW_EXPONENTIAL) {
        flb_plg_info(ins, "  decay_base_rate: %.2f", ctx->decay_base_rate);
        flb_plg_info(ins, "  decay_factor: %.2f", ctx->decay_factor);
        flb_plg_info(ins, "  decay_interval: %d seconds", ctx->decay_interval);
    }
    
    return FLB_PROCESSOR_SUCCESS;
}

static int cb_log_sampling_process_logs(struct flb_processor_instance *ins,
                                        void *chunk_data,
                                        const char *tag, int tag_len)
{
    struct log_sampling_ctx *ctx = ins->context;
    struct flb_mp_chunk_cobj *chunk_cobj;
    struct flb_mp_chunk_record *record;
    struct flb_time timestamp;
    int should_sample;
    size_t total_records = 0;
    size_t sampled_records = 0;
    
    chunk_cobj = (struct flb_mp_chunk_cobj *) chunk_data;
    
    /* Process each log event */
    while (flb_mp_chunk_cobj_record_next(chunk_cobj, &record) == FLB_MP_CHUNK_RECORD_OK) {
        total_records++;
        ctx->state.total_logs_seen++;
        
        /* Get timestamp from the record's event */
        timestamp = record->event.timestamp;
        
        /* Apply window-based sampling */
        switch (ctx->window_type) {
        case LOG_SAMPLING_WINDOW_FIXED:
            should_sample = should_sample_fixed_window(ctx, &timestamp);
            break;
        case LOG_SAMPLING_WINDOW_SLIDING:
            should_sample = should_sample_sliding_window(ctx, &timestamp);
            break;
        case LOG_SAMPLING_WINDOW_EXPONENTIAL:
            should_sample = should_sample_exponential(ctx, &timestamp);
            break;
        default:
            should_sample = FLB_TRUE;
        }
        
        if (!should_sample) {
            /* Remove this record */
            flb_mp_chunk_cobj_record_destroy(chunk_cobj, record);
        }
        else {
            ctx->state.total_logs_sampled++;
            sampled_records++;
        }
    }
    
    /* Log sampling statistics at trace level */
    flb_plg_trace(ins, "sampling stats: seen=%" PRIu64 " sampled=%" PRIu64 " rate=%.2f%%",
                  ctx->state.total_logs_seen,
                  ctx->state.total_logs_sampled,
                  ctx->state.total_logs_seen > 0 ? 
                      (double)ctx->state.total_logs_sampled / ctx->state.total_logs_seen * 100.0 : 0.0);
    
    if (total_records > 0) {
        flb_plg_debug(ins, "processed %zu records: sampled=%zu, dropped=%zu (%.1f%% kept)",
                      total_records, sampled_records, total_records - sampled_records,
                      (double)sampled_records / total_records * 100.0);
    }
    
    return FLB_PROCESSOR_SUCCESS;
}

static int cb_log_sampling_exit(struct flb_processor_instance *ins, void *data)
{
    struct log_sampling_ctx *ctx = data;
    
    if (!ctx) {
        return FLB_PROCESSOR_SUCCESS;
    }
    
    if (ctx->state.buckets) {
        flb_free(ctx->state.buckets);
    }
    
    flb_free(ctx);
    
    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "window_type", LOG_SAMPLING_WINDOW_TYPE_FIXED,
        0, FLB_TRUE, offsetof(struct log_sampling_ctx, window_type),
        "Window type: fixed, sliding, or exponential"
    },
    {
        FLB_CONFIG_MAP_INT, "window_size", "60",
        0, FLB_TRUE, offsetof(struct log_sampling_ctx, window_size),
        "Window size in seconds"
    },
    {
        FLB_CONFIG_MAP_INT, "max_logs_per_window", "1000",
        0, FLB_TRUE, offsetof(struct log_sampling_ctx, max_logs_per_window),
        "Maximum logs to keep per window"
    },
    {
        FLB_CONFIG_MAP_DOUBLE, "decay_base_rate", "0.1",
        0, FLB_TRUE, offsetof(struct log_sampling_ctx, decay_base_rate),
        "Base sampling rate for exponential decay (0.0-1.0)"
    },
    {
        FLB_CONFIG_MAP_DOUBLE, "decay_factor", "0.95",
        0, FLB_TRUE, offsetof(struct log_sampling_ctx, decay_factor),
        "Decay factor per interval"
    },
    {
        FLB_CONFIG_MAP_INT, "decay_interval", "60",
        0, FLB_TRUE, offsetof(struct log_sampling_ctx, decay_interval),
        "Decay interval in seconds"
    },
    /* EOF */
    {0}
};

struct flb_processor_plugin processor_log_sampling_plugin = {
    .name               = "log_sampling",
    .description        = "Log sampling based on window strategies",
    .cb_init            = cb_log_sampling_init,
    .cb_process_logs    = cb_log_sampling_process_logs,
    .cb_process_metrics = NULL,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_log_sampling_exit,
    .config_map         = config_map,
    .flags              = 0
};