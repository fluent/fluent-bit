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

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_compat.h>
#include <string.h>
#include <cfl/cfl_time.h>

#include <cmetrics/cmt_cat.h>
#include <cmetrics/cmt_exp_histogram.h>

#include "cumulative_to_delta.h"

struct c2d_processor_ctx {
    char *initial_value;
    int drop_first;
    int drop_on_reset;
    int max_staleness;
    int max_series;
    int initial_value_mode;
    struct flb_cumulative_to_delta_ctx *core_context;
};

static int parse_initial_value_mode(struct c2d_processor_ctx *context)
{
    if (context->initial_value == NULL ||
        strcasecmp(context->initial_value, "unset") == 0) {
        if (context->drop_first == FLB_TRUE) {
            context->initial_value_mode = FLB_C2D_INITIAL_VALUE_DROP;
        }
        else {
            context->initial_value_mode = FLB_C2D_INITIAL_VALUE_KEEP;
        }

        return 0;
    }

    if (strcasecmp(context->initial_value, "auto") == 0) {
        context->initial_value_mode = FLB_C2D_INITIAL_VALUE_AUTO;
    }
    else if (strcasecmp(context->initial_value, "keep") == 0) {
        context->initial_value_mode = FLB_C2D_INITIAL_VALUE_KEEP;
    }
    else if (strcasecmp(context->initial_value, "drop") == 0) {
        context->initial_value_mode = FLB_C2D_INITIAL_VALUE_DROP;
    }
    else {
        return -1;
    }

    return 0;
}

static void destroy_context(struct c2d_processor_ctx *context)
{
    if (context == NULL) {
        return;
    }

    if (context->core_context != NULL) {
        flb_cumulative_to_delta_ctx_destroy(context->core_context);
    }

    flb_free(context);
}

static struct c2d_processor_ctx *create_context(struct flb_processor_instance *processor_instance)
{
    int result;
    struct c2d_processor_ctx *context;

    context = flb_calloc(1, sizeof(struct c2d_processor_ctx));
    if (context == NULL) {
        flb_errno();
        return NULL;
    }

    result = flb_processor_instance_config_map_set(processor_instance, context);
    if (result != 0) {
        destroy_context(context);
        return NULL;
    }

    result = parse_initial_value_mode(context);
    if (result != 0) {
        flb_plg_error(processor_instance,
                      "invalid 'initial_value' option: %s",
                      context->initial_value);
        destroy_context(context);
        return NULL;
    }

    context->core_context = flb_cumulative_to_delta_ctx_create(context->initial_value_mode,
                                              context->drop_on_reset,
                                              cfl_time_now());
    if (context->core_context == NULL) {
        destroy_context(context);
        return NULL;
    }

    result = flb_cumulative_to_delta_ctx_configure(context->core_context,
                                                   context->max_staleness,
                                                   context->max_series);
    if (result != 0) {
        flb_plg_error(processor_instance,
                      "invalid limits max_staleness=%d max_series=%d",
                      context->max_staleness,
                      context->max_series);
        destroy_context(context);
        return NULL;
    }

    return context;
}

static int cb_init(struct flb_processor_instance *processor_instance,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    processor_instance->context = create_context(processor_instance);
    if (processor_instance->context == NULL) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_processor_instance *processor_instance, void *data)
{
    if (processor_instance != NULL && data != NULL) {
        destroy_context(data);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_metrics(struct flb_processor_instance *processor_instance,
                              struct cmt *metrics_context,
                              struct cmt **out_context,
                              const char *tag,
                              int tag_len)
{
    int has_cumulative_metrics;
    int result;
    struct cmt *out_cmt;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct c2d_processor_ctx *context;

    context = (struct c2d_processor_ctx *) processor_instance->context;

    has_cumulative_metrics = FLB_FALSE;

    cfl_list_foreach(head, &metrics_context->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);

        if (counter->aggregation_type == CMT_AGGREGATION_TYPE_CUMULATIVE &&
            counter->allow_reset == FLB_FALSE) {
            has_cumulative_metrics = FLB_TRUE;
            break;
        }
    }

    if (has_cumulative_metrics == FLB_FALSE) {
        cfl_list_foreach(head, &metrics_context->histograms) {
            histogram = cfl_list_entry(head, struct cmt_histogram, _head);

            if (histogram->aggregation_type == CMT_AGGREGATION_TYPE_CUMULATIVE) {
                has_cumulative_metrics = FLB_TRUE;
                break;
            }
        }
    }

    if (has_cumulative_metrics == FLB_FALSE) {
        cfl_list_foreach(head, &metrics_context->exp_histograms) {
            exp_histogram = cfl_list_entry(head,
                                           struct cmt_exp_histogram,
                                           _head);

            if (exp_histogram->aggregation_type ==
                CMT_AGGREGATION_TYPE_CUMULATIVE) {
                has_cumulative_metrics = FLB_TRUE;
                break;
            }
        }
    }

    if (has_cumulative_metrics == FLB_FALSE) {
        *out_context = metrics_context;
        return FLB_PROCESSOR_SUCCESS;
    }

    out_cmt = cmt_create();
    if (out_cmt == NULL) {
        flb_plg_error(processor_instance, "could not create out_cmt context");
        return FLB_PROCESSOR_FAILURE;
    }

    result = cmt_cat(out_cmt, metrics_context);
    if (result != 0) {
        cmt_destroy(out_cmt);
        return FLB_PROCESSOR_FAILURE;
    }

    result = flb_cumulative_to_delta_ctx_process(context->core_context, out_cmt);
    if (result != 0) {
        cmt_destroy(out_cmt);
        return FLB_PROCESSOR_FAILURE;
    }

    /*
     * The processor returns a replacement context and keeps ownership
     * unchanged: the caller remains responsible for destroying both the
     * input context and any returned replacement.
     */
    *out_context = out_cmt;
    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "initial_value", "unset",
        0, FLB_TRUE, offsetof(struct c2d_processor_ctx, initial_value),
        "First point behavior: auto, keep, drop. "
        "If unset, drop_first compatibility mode is used."
    },
    {
        FLB_CONFIG_MAP_BOOL, "drop_first", "true",
        0, FLB_TRUE, offsetof(struct c2d_processor_ctx, drop_first),
        "Compatibility option. Used only when initial_value is unset."
    },
    {
        FLB_CONFIG_MAP_BOOL, "drop_on_reset", "true",
        0, FLB_TRUE, offsetof(struct c2d_processor_ctx, drop_on_reset),
        "Drop samples when monotonic sum/histogram reset is detected."
    },
    {
        FLB_CONFIG_MAP_TIME, "max_staleness", "1h",
        0, FLB_TRUE, offsetof(struct c2d_processor_ctx, max_staleness),
        "State retention window. 0 disables staleness eviction."
    },
    {
        FLB_CONFIG_MAP_INT, "max_series", "65536",
        0, FLB_TRUE, offsetof(struct c2d_processor_ctx, max_series),
        "Maximum tracked series in memory. 0 disables size-based eviction."
    },
    {0}
};

struct flb_processor_plugin processor_cumulative_to_delta_plugin = {
    .name               = "cumulative_to_delta",
    .description        = "Convert cumulative monotonic sums and histograms to delta",
    .cb_init            = cb_init,
    .cb_process_logs    = NULL,
    .cb_process_metrics = cb_process_metrics,
    .cb_process_traces  = NULL,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};
