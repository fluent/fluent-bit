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

#include <stdio.h>

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

static int cb_stdout_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config,
                          void *data)
{
    (void) f_ins;
    (void) config;
    (void) data;

    if (flb_filter_config_map_set(f_ins, (void *)config) == -1) {
        flb_plg_error(f_ins, "unable to load configuration");
        return -1;
    }
    return 0;
}

static int cb_stdout_filter(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            void **out_buf, size_t *out_bytes,
                            struct flb_filter_instance *f_ins,
                            struct flb_input_instance *i_ins,
                            void *filter_context,
                            struct flb_config *config)
{
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    size_t cnt;
    int ret;

    (void) out_buf;
    (void) out_bytes;
    (void) f_ins;
    (void) i_ins;
    (void) filter_context;
    (void) config;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(f_ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    cnt = 0;

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        printf("[%zd] %s: [", cnt++, tag);
        printf("%"PRIu32".%09lu, ",
               (uint32_t) log_event.timestamp.tm.tv_sec,
               log_event.timestamp.tm.tv_nsec);
        msgpack_object_print(stdout, *log_event.metadata);
        printf(", ");
        msgpack_object_print(stdout, *log_event.body);
        printf("]\n");
    }

    flb_log_event_decoder_destroy(&log_decoder);

    return FLB_FILTER_NOTOUCH;
}

static struct flb_config_map config_map[] = {
    /* EOF */
    {0}
};

struct flb_filter_plugin filter_stdout_plugin = {
    .name         = "stdout",
    .description  = "Filter events to STDOUT",
    .cb_init      = cb_stdout_init,
    .cb_filter    = cb_stdout_filter,
    .cb_exit      = NULL,
    .config_map   = config_map,
    .flags        = 0
};
