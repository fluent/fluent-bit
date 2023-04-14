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
#include <stdlib.h>
#include <time.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event.h>

#include "in_dummy.h"

static void generate_timestamp(struct flb_dummy *ctx,
                               struct flb_time *result)
{
    struct flb_time current_timestamp;
    struct flb_time delta;

    if (ctx->fixed_timestamp) {
        if (ctx->dummy_timestamp_set) {
            flb_time_copy(result, &ctx->dummy_timestamp);
        }
        else {
            flb_time_copy(result, &ctx->base_timestamp);
        }
    }
    else {
        if (ctx->dummy_timestamp_set) {
            flb_time_zero(&delta);

            flb_time_get(&current_timestamp);

            flb_time_diff(&current_timestamp,
                          &ctx->base_timestamp,
                          &delta);

            flb_time_add(&ctx->dummy_timestamp,
                         &delta,
                         result);
        }
        else {
            flb_time_get(result);
        }
    }
}

static int generate_event(struct flb_dummy *ctx)
{
    size_t           chunk_offset;
    size_t           body_length;
    char            *body_buffer;
    size_t           body_start;
    struct flb_time  timestamp;
    msgpack_unpacked object;
    int              result;

    result = FLB_EVENT_ENCODER_SUCCESS;
    body_start = 0;
    chunk_offset = 0;

    generate_timestamp(ctx, &timestamp);

    msgpack_unpacked_init(&object);

    while (result == FLB_EVENT_ENCODER_SUCCESS &&
           msgpack_unpack_next(&object,
                               ctx->ref_body_msgpack,
                               ctx->ref_body_msgpack_size,
                               &chunk_offset) == MSGPACK_UNPACK_SUCCESS) {
        body_buffer = &ctx->ref_body_msgpack[body_start];
        body_length = chunk_offset - body_start;

        if (object.data.type == MSGPACK_OBJECT_MAP) {
            flb_log_event_encoder_begin_record(ctx->encoder);

            flb_log_event_encoder_set_timestamp(ctx->encoder, &timestamp);

            result = flb_log_event_encoder_set_metadata_from_raw_msgpack(
                        ctx->encoder,
                        ctx->ref_metadata_msgpack,
                        ctx->ref_metadata_msgpack_size);

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = flb_log_event_encoder_set_body_from_raw_msgpack(
                            ctx->encoder,
                            body_buffer,
                            body_length);
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = flb_log_event_encoder_commit_record(ctx->encoder);
            }
        }

        body_start = chunk_offset;
    }

    msgpack_unpacked_destroy(&object);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = 0;
    }
    else {
        result = -1;
    }

    return result;
}

/* cb_collect callback */
static int in_dummy_collect(struct flb_input_instance *ins,
                            struct flb_config *config,
                            void *in_context)
{
    int               result;
    int               index;
    struct flb_dummy *ctx;

    ctx = (struct flb_dummy *) in_context;

    if (ctx->samples > 0 && (ctx->samples_count >= ctx->samples)) {
        return -1;
    }

    result = 0;

    if (ctx->samples_count == 0 || !ctx->fixed_timestamp) {
        flb_log_event_encoder_reset(ctx->encoder);

        for (index = 0 ; index < ctx->copies && result == 0 ; index++) {
            result = generate_event(ctx);
        }
    }

    if (result == 0) {
        if (ctx->encoder->output_length > 0) {
            flb_input_log_append(ins, NULL, 0,
                                 ctx->encoder->output_buffer,
                                 ctx->encoder->output_length);
        }
        else {
            flb_plg_error(ins, "log chunk size == 0");
        }
    }
    else {
        flb_plg_error(ins, "log chunk genartion error (%d)", result);
    }

    if (ctx->samples > 0) {
        ctx->samples_count++;
    }

    return 0;
}

static int config_destroy(struct flb_dummy *ctx)
{
    if (ctx->ref_body_msgpack != NULL) {
        flb_free(ctx->ref_body_msgpack);
    }

    if (ctx->ref_metadata_msgpack != NULL) {
        flb_free(ctx->ref_metadata_msgpack);
    }

    if (ctx->encoder != NULL) {
        flb_log_event_encoder_destroy(ctx->encoder);
    }

    flb_free(ctx);

    return 0;
}

/* Set plugin configuration */
static int configure(struct flb_dummy *ctx,
                     struct flb_input_instance *in,
                     struct timespec *tm)
{
    const char *msg;
    int root_type;
    int ret = -1;

    ctx->ref_metadata_msgpack = NULL;
    ctx->ref_body_msgpack = NULL;
    ctx->dummy_timestamp_set = FLB_FALSE;

    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        return -1;
    }

    /* interval settings */
    tm->tv_sec  = 1;
    tm->tv_nsec = 0;

    if (ctx->rate > 1) {
        tm->tv_sec = 0;
        tm->tv_nsec = 1000000000 / ctx->rate;
    }

    /* dummy timestamp */
    flb_time_zero(&ctx->dummy_timestamp);

    if (ctx->start_time_sec >= 0 || ctx->start_time_nsec >= 0) {
        ctx->dummy_timestamp_set = FLB_TRUE;

        if (ctx->start_time_sec >= 0) {
            ctx->dummy_timestamp.tm.tv_sec = ctx->start_time_sec;
        }
        if (ctx->start_time_nsec >= 0) {
            ctx->dummy_timestamp.tm.tv_nsec = ctx->start_time_nsec;
        }
    }

    flb_time_get(&ctx->base_timestamp);

    /* handle it explicitly since we need to validate it is valid JSON */
    msg = flb_input_get_property("dummy", in);
    if (msg == NULL) {
        msg = DEFAULT_DUMMY_MESSAGE;
    }

    ret = flb_pack_json(msg,
                        strlen(msg),
                        &ctx->ref_body_msgpack,
                        &ctx->ref_body_msgpack_size,
                        &root_type,
                        NULL);

    if (ret != 0) {
        flb_plg_warn(ctx->ins, "data is incomplete. Use default string.");

        ret = flb_pack_json(DEFAULT_DUMMY_MESSAGE,
                            strlen(DEFAULT_DUMMY_MESSAGE),
                            &ctx->ref_body_msgpack,
                            &ctx->ref_body_msgpack_size,
                            &root_type,
                            NULL);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "unexpected error");
            return -1;
        }
    }

    /* handle it explicitly since we need to validate it is valid JSON */
    msg = flb_input_get_property("metadata", in);

    if (msg == NULL) {
        msg = DEFAULT_DUMMY_METADATA;
    }

    ret = flb_pack_json(msg,
                        strlen(msg),
                        &ctx->ref_metadata_msgpack,
                        &ctx->ref_metadata_msgpack_size,
                        &root_type,
                        NULL);

    if (ret != 0) {
        flb_plg_warn(ctx->ins, "data is incomplete. Use default string.");

        ret = flb_pack_json(DEFAULT_DUMMY_METADATA,
                            strlen(DEFAULT_DUMMY_METADATA),
                            &ctx->ref_metadata_msgpack,
                            &ctx->ref_metadata_msgpack_size,
                            &root_type,
                            NULL);

        if (ret != 0) {
            flb_plg_error(ctx->ins, "unexpected error");
            return -1;
        }
    }

    return 0;
}




/* Initialize plugin */
static int in_dummy_init(struct flb_input_instance *in,
                         struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_dummy *ctx = NULL;
    struct timespec tm;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_dummy));
    if (ctx == NULL) {
        return -1;
    }
    ctx->ins = in;
    ctx->samples = 0;
    ctx->samples_count = 0;

    /* Initialize head config */
    ret = configure(ctx, in, &tm);
    if (ret < 0) {
        config_destroy(ctx);
        return -1;
    }

    ctx->encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->encoder == NULL) {
        flb_plg_error(in, "could not initialize event encoder");
        config_destroy(ctx);

        return -1;
    }

    flb_input_set_context(in, ctx);

    ret = flb_input_set_collector_time(in,
                                       in_dummy_collect,
                                       tm.tv_sec,
                                       tm.tv_nsec, config);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "could not set collector for dummy input plugin");
        config_destroy(ctx);
        return -1;
    }

    ctx->coll_fd = ret;

    flb_time_get(&ctx->base_timestamp);

    return 0;
}

static void in_dummy_pause(void *data, struct flb_config *config)
{
    struct flb_dummy *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_dummy_resume(void *data, struct flb_config *config)
{
    struct flb_dummy *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int in_dummy_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_dummy *ctx = data;

    config_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
   {
    FLB_CONFIG_MAP_INT, "samples", "0",
    0, FLB_TRUE, offsetof(struct flb_dummy, samples),
    "set a number of times to generate event."
   },
   {
    FLB_CONFIG_MAP_STR, "dummy", DEFAULT_DUMMY_MESSAGE,
    0, FLB_FALSE, 0,
    "set the sample record to be generated. It should be a JSON object."
   },
   {
    FLB_CONFIG_MAP_STR, "metadata", DEFAULT_DUMMY_METADATA,
    0, FLB_FALSE, 0,
    "set the sample metadata to be generated. It should be a JSON object."
   },
   {
    FLB_CONFIG_MAP_INT, "rate", "1",
    0, FLB_TRUE, offsetof(struct flb_dummy, rate),
    "set a number of events per second."
   },
   {
    FLB_CONFIG_MAP_INT, "copies", "1",
    0, FLB_TRUE, offsetof(struct flb_dummy, copies),
    "set the number of copies to generate per collectd."
   },
   {
    FLB_CONFIG_MAP_INT, "start_time_sec", "-1",
    0, FLB_TRUE, offsetof(struct flb_dummy, start_time_sec),
    "set a dummy base timestamp in seconds."
   },
   {
    FLB_CONFIG_MAP_INT, "start_time_nsec", "-1",
    0, FLB_TRUE, offsetof(struct flb_dummy, start_time_nsec),
    "set a dummy base timestamp in nanoseconds."
   },
   {
    FLB_CONFIG_MAP_BOOL, "fixed_timestamp", "off",
    0, FLB_TRUE, offsetof(struct flb_dummy, fixed_timestamp),
    "used a fixed timestamp, allows the message to pre-generated once."
   },
   {0}
};


struct flb_input_plugin in_dummy_plugin = {
    .name         = "dummy",
    .description  = "Generate dummy data",
    .cb_init      = in_dummy_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_dummy_collect,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_pause     = in_dummy_pause,
    .cb_resume    = in_dummy_resume,
    .cb_exit      = in_dummy_exit
};
