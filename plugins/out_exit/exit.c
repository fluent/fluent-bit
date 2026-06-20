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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>

#define FLB_EXIT_FLUSH_COUNT  "-1"
#define FLB_EXIT_RECORD_COUNT "-1"
#define FLB_EXIT_TIME_COUNT   "-1"

struct flb_exit {
    int is_running;
    struct flb_time start_time;

    /* config */
    int flush_count;
    int record_count;
    int time_count;
    struct flb_output_instance *ins;
};

static int cb_exit_init(struct flb_output_instance *ins, struct flb_config *config,
                        void *data)
{
    int ret;
    (void) config;
    (void) data;
    struct flb_exit *ctx;

    ctx = flb_malloc(sizeof(struct flb_exit));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->is_running = FLB_TRUE;
    flb_time_get(&ctx->start_time);

    ctx->flush_count = -1;
    ctx->record_count = -1;
    ctx->time_count = -1;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    if (ctx->flush_count == -1 &&
        ctx->record_count == -1 &&
        ctx->time_count == -1) {
        // emulate legacy behaviour by setting to a single flush.
        ctx->flush_count = 1;
    }

    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_exit_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    (void) i_ins;
    (void) out_context;
    struct flb_exit *ctx = out_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event         log_event;
    struct flb_time now;
    struct flb_time run;
    int result;

    if (ctx->is_running == FLB_TRUE) {
        if (ctx->flush_count > 0) {
            ctx->flush_count--;
        }

        if (ctx->record_count > 0 && event_chunk->type == FLB_EVENT_TYPE_LOGS) {
            result = flb_log_event_decoder_init(&log_decoder,
                                               (char *) event_chunk->data,
                                               event_chunk->size);
            if (result != FLB_EVENT_DECODER_SUCCESS) {
                flb_plg_error(ctx->ins,
                              "Log event decoder initialization error : %d", result);

                FLB_OUTPUT_RETURN(FLB_RETRY);
            }

            while (flb_log_event_decoder_next(&log_decoder,
                                              &log_event) == FLB_EVENT_DECODER_SUCCESS) {
                if (ctx->record_count > 0) {
                    ctx->record_count--;
                }
            }

            result = flb_log_event_decoder_get_last_result(&log_decoder);
            flb_log_event_decoder_destroy(&log_decoder);

            if (result != FLB_EVENT_DECODER_SUCCESS) {
                flb_plg_error(ctx->ins, "Log event decoder error : %d", result);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            FLB_OUTPUT_RETURN(FLB_OK);
        }

        if (ctx->time_count > 0) {
            flb_time_get(&now);
            flb_time_diff(&now, &ctx->start_time, &run);
        }

        if (ctx->flush_count == 0 ||
            ctx->record_count == 0 ||
            (ctx->time_count > 0 && flb_time_to_millisec(&run) > (ctx->time_count*1000))) {
            flb_engine_exit(config);
            ctx->is_running = FLB_FALSE;
        }
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_exit_exit(void *data, struct flb_config *config)
{
    struct flb_exit *ctx = data;
    (void) config;

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_INT, "flush_count", FLB_EXIT_FLUSH_COUNT,
     0, FLB_TRUE, offsetof(struct flb_exit, flush_count),
     "number of flushes before exiting"
    },
    {
     FLB_CONFIG_MAP_INT, "record_count", FLB_EXIT_RECORD_COUNT,
     0, FLB_TRUE, offsetof(struct flb_exit, record_count),
     "number of records received before exiting"
    },
    {
     FLB_CONFIG_MAP_INT, "time_count", FLB_EXIT_TIME_COUNT,
     0, FLB_TRUE, offsetof(struct flb_exit, time_count),
     "number of seconds before exiting (will trigger upon receiving a flush)"
    },

    /* EOF */
    {0}
};

struct flb_output_plugin out_exit_plugin = {
    .name         = "exit",
    .description  = "Exit after a number of flushes (test purposes)",
    .cb_init      = cb_exit_init,
    .cb_flush     = cb_exit_flush,
    .cb_exit      = cb_exit_exit,
    .config_map   = config_map,
    .flags        = 0,
};
