/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <stdio.h>

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

static int cb_init(struct flb_processor_instance *p_ins,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    return FLB_PROCESSOR_SUCCESS;
}

static int add_canary_metadata_entry(struct flb_log_event_encoder *encoder)
{
    static uint64_t index = 0;
    char name[256];
    char value[256];

    index++;

    snprintf(name,
             sizeof(name),
             "metadata entry %zu name",
             index);

    snprintf(value,
             sizeof(value),
             "metadata entry %zu value",
             index);

    return flb_log_event_encoder_append_metadata_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE(name),
            FLB_LOG_EVENT_CSTRING_VALUE(value));
}


static int cb_process_logs(struct flb_processor_instance *p_ins,
                           struct flb_log_event_encoder *encoder,
                           struct flb_log_event *event,
                           const char *tag,
                           int tag_len)
{
    int result;

    result = flb_log_event_encoder_begin_record(encoder);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_timestamp(
                    encoder,
                    &event->timestamp);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = add_canary_metadata_entry(encoder);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_body_from_msgpack_object(
                    encoder,
                    event->body);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_record(encoder);
    }

    if (result != FLB_EVENT_ENCODER_SUCCESS) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_metrics(struct flb_processor_instance *p_ins,
                              struct cmt *metrics_context,
                              const char *tag,
                              int tag_len)
{
    printf("cb_process_metrics : %p\n", metrics_context);

    cmt_label_add(metrics_context, "TEST LABEL NAME", "LABEL VALUE");

    return FLB_PROCESSOR_SUCCESS;
}

static int cb_process_traces(struct flb_processor_instance *p_ins,
                             struct ctrace *trace,
                             const char *tag,
                             int tag_len)
{
    struct ctrace_span *span;

    if (!cfl_list_is_empty(&trace->span_list)) {
        span = cfl_list_entry_first(&trace->span_list, struct ctrace_span, _head_global);

        if (span  != NULL) {
            ctr_span_set_attribute_string(span, "a new attribute", "with an interesting value");
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    /* EOF */
    {0}
};

struct flb_processor_plugin processor_test_plugin = {
    .name               = "test",
    .description        = "Processor test",
    .cb_init            = cb_init,
    .cb_process_logs    = cb_process_logs,
    .cb_process_metrics = cb_process_metrics,
    .cb_process_traces  = cb_process_traces,
    .cb_exit            = NULL,
    .config_map         = config_map,
    .flags              = 0
};
