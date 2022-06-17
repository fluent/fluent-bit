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

#include "in_dummy.h"


static int set_dummy_timestamp(msgpack_packer *mp_pck, struct flb_dummy *ctx)
{
    struct flb_time t;
    struct flb_time diff;
    struct flb_time dummy_time;
    int ret;

    if (ctx->base_timestamp == NULL) {
        ctx->base_timestamp = flb_malloc(sizeof(struct flb_time));
        flb_time_get(ctx->base_timestamp);
        ret = flb_time_append_to_msgpack(ctx->dummy_timestamp, mp_pck, 0);
    }
    else {
        flb_time_get(&t);
        flb_time_diff(&t, ctx->base_timestamp, &diff);
        flb_time_add(ctx->dummy_timestamp, &diff, &dummy_time);
        ret = flb_time_append_to_msgpack(&dummy_time, mp_pck, 0);
    }

    return ret;
}

static int gen_msg(struct flb_input_instance *ins, void *in_context, msgpack_sbuffer *mp_sbuf)
{
    size_t off = 0;
    size_t start = 0;
    char *pack;
    int pack_size;
    msgpack_unpacked result;
    msgpack_packer mp_pck;
    struct flb_dummy *ctx = in_context;

    pack = ctx->ref_msgpack;
    pack_size = ctx->ref_msgpack_size;
    msgpack_unpacked_init(&result);

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(mp_sbuf);
    msgpack_packer_init(&mp_pck, mp_sbuf, msgpack_sbuffer_write);

    while (msgpack_unpack_next(&result, pack, pack_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            /* { map => val, map => val, map => val } */
            msgpack_pack_array(&mp_pck, 2);
            if (ctx->dummy_timestamp != NULL){
                set_dummy_timestamp(&mp_pck, ctx);
            }
            else {
                flb_pack_time_now(&mp_pck);
            }
            msgpack_pack_str_body(&mp_pck, pack + start, off - start);
        }
        start = off;
    }
    msgpack_unpacked_destroy(&result);

    return 0;
}

/* cb_collect callback */
static int in_dummy_collect(struct flb_input_instance *ins,
                            struct flb_config *config, void *in_context)
{
    struct flb_dummy *ctx = in_context;
    msgpack_sbuffer mp_sbuf;

    if (ctx->samples > 0 && (ctx->samples_count >= ctx->samples)) {
        return -1;
    }

    if (ctx->fixed_timestamp == FLB_FALSE) {
        msgpack_sbuffer_init(&mp_sbuf);
        gen_msg(ins, in_context, &mp_sbuf);
        flb_input_chunk_append_raw(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
        msgpack_sbuffer_destroy(&mp_sbuf);
    }
    else {
        flb_input_chunk_append_raw(ins, NULL, 0, ctx->mp_sbuf.data, ctx->mp_sbuf.size);
    }

    if (ctx->samples > 0) {
        ctx->samples_count++;
    }
    return 0;
}

static int config_destroy(struct flb_dummy *ctx)
{
    flb_free(ctx->dummy_timestamp);
    flb_free(ctx->base_timestamp);
    if (ctx->fixed_timestamp == FLB_TRUE) {
        msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    }
    if (ctx->dummy_message) {
        flb_free(ctx->dummy_message);
    }
    flb_free(ctx->ref_msgpack);
    flb_free(ctx);
    return 0;
}

/* Set plugin configuration */
static int configure(struct flb_dummy *ctx,
                     struct flb_input_instance *in,
                     struct timespec *tm)
{
    struct flb_time dummy_time;
    const char *msg;
    int dummy_time_enabled = FLB_FALSE;
    int root_type;
    int  ret = -1;

    ctx->dummy_message = NULL;
    ctx->dummy_message_len = 0;

    ctx->ref_msgpack = NULL;

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
    ctx->dummy_timestamp = NULL;
    ctx->base_timestamp = NULL;
    flb_time_zero(&dummy_time);

    if (ctx->start_time_sec >= 0 || ctx->start_time_nsec >= 0) {
        dummy_time_enabled = FLB_TRUE;
        if (ctx->start_time_sec >= 0) {
            dummy_time.tm.tv_sec = ctx->start_time_sec;
        }
        if (ctx->start_time_nsec >= 0) {
            dummy_time.tm.tv_nsec = ctx->start_time_nsec;
        }
    }

    if (dummy_time_enabled) {
        ctx->dummy_timestamp = flb_malloc(sizeof(struct flb_time));
        flb_time_copy(ctx->dummy_timestamp, &dummy_time);
    }

    /* handle it explicitly since we need to validate it is valid JSON */
    msg = flb_input_get_property("dummy", in);
    if (msg == NULL) {
        msg = DEFAULT_DUMMY_MESSAGE;
    }
    ret = flb_pack_json(msg, strlen(msg), &ctx->ref_msgpack,
                        &ctx->ref_msgpack_size, &root_type);
    if (ret == 0) {
        ctx->dummy_message = flb_strdup(msg);
        ctx->dummy_message_len = strlen(msg);
    }
    else {
        flb_plg_warn(ctx->ins, "data is incomplete. Use default string.");

        ctx->dummy_message = flb_strdup(DEFAULT_DUMMY_MESSAGE);
        ctx->dummy_message_len = strlen(ctx->dummy_message);

        ret = flb_pack_json(ctx->dummy_message,
                            ctx->dummy_message_len,
                            &ctx->ref_msgpack, &ctx->ref_msgpack_size,
                            &root_type);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "unexpected error");
            return -1;
        }
    }

    if (ctx->fixed_timestamp == FLB_TRUE) {
        gen_msg(in, ctx, &ctx->mp_sbuf);
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
    FLB_CONFIG_MAP_INT, "rate", "1",
    0, FLB_TRUE, offsetof(struct flb_dummy, rate),
    "set a number of events per second."
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
