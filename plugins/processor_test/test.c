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
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

static int cb_init(struct flb_native_processor_instance *p_ins,
                          struct flb_config *config,
                          void *data)
{

    return 0;
}

static int cb_process_logs(const void *data, size_t bytes,
                           const char *tag, int tag_len,
                           void **out_buf, size_t *out_bytes,
                           struct flb_native_processor_instance *p_ins,
                           struct flb_input_instance *i_ins,
                           void *filter_context,
                           struct flb_config *config)
{
    printf("cb_process_logs : %p - %zu\n", data, bytes);
    return 0;
}

static int cb_process_metrics(struct cmt *a,
                           const char *b, int c,
                           void **d, size_t *e,
                           struct flb_native_processor_instance *f,
                           struct flb_input_instance *g,
                           void *h, struct flb_config *i)
{
    printf("cb_process_metrics : %p\n", a);
    return 0;
}

static int cb_process_traces(struct ctrace *a,
                          const char *b, int c,
                          void **d, size_t *e,
                          struct flb_native_processor_instance *f,
                          struct flb_input_instance *g,
                          void *h, struct flb_config *i)
{
    printf("cb_process_traces : %p\n", a);
    return 0;
}

static struct flb_config_map config_map[] = {
    /* EOF */
    {0}
};

struct flb_native_processor_plugin processor_test_plugin = {
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
