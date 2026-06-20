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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mp.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

static int cb_counter_init(struct flb_output_instance *ins,
                           struct flb_config *config,
                           void *data)
{
    (void) ins;
    (void) config;
    (void) data;

    return 0;
}

static void cb_counter_flush(struct flb_event_chunk *event_chunk,
                             struct flb_output_flush *out_flush,
                             struct flb_input_instance *i_ins,
                             void *out_context,
                             struct flb_config *config)
{
    (void) i_ins;
    (void) out_flush;
    (void) out_context;
    (void) config;
    size_t serialized_events;
    size_t log_records;
    size_t total;
    struct flb_time tm;

    /* Count number of serialized msgpack root objects */
    serialized_events = flb_mp_count(event_chunk->data, event_chunk->size);

    /* Count number of logical log records (group markers excluded) */
    log_records = 0;
    if (event_chunk->type == FLB_EVENT_TYPE_LOGS) {
        log_records = flb_mp_count_log_records(event_chunk->data,
                                               event_chunk->size);
    }
    total = serialized_events;

    flb_time_get(&tm);
    printf("{\"ts\":%.6f,\"serialized_events\":%zu,\"log_records\":%zu,"
           "\"total\":%zu}\n",
           flb_time_to_double(&tm),
           serialized_events,
           log_records,
           total);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_counter_exit(void *data, struct flb_config *config)
{
    (void) config;
    (void) data;
    return 0;
}

static struct flb_config_map config_map[] = {
   /* EOF */
   {0}
};

struct flb_output_plugin out_counter_plugin = {
    .name         = "counter",
    .description  = "Records counter",
    .cb_init      = cb_counter_init,
    .cb_flush     = cb_counter_flush,
    .cb_exit      = cb_counter_exit,
    .config_map   = config_map,
    .flags        = 0,
};
