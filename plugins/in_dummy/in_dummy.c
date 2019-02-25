/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>

#include "in_dummy.h"


/* cb_collect callback */
static int in_dummy_collect(struct flb_input_instance *i_ins,
                            struct flb_config *config, void *in_context)
{
    size_t off = 0;
    size_t start = 0;
    struct flb_in_dummy_config *ctx = in_context;
    char *pack = ctx->ref_msgpack;
    int pack_size = ctx->ref_msgpack_size;
    msgpack_unpacked result;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    msgpack_unpacked_init(&result);


    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    while (msgpack_unpack_next(&result, pack, pack_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            /* { map => val, map => val, map => val } */
            msgpack_pack_array(&mp_pck, 2);
            flb_pack_time_now(&mp_pck);
            msgpack_pack_str_body(&mp_pck, pack + start, off - start);
        }
        start = off;
    }
    msgpack_unpacked_destroy(&result);

    flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

static int config_destroy(struct flb_in_dummy_config *ctx)
{
    flb_free(ctx->dummy_message);
    flb_free(ctx->ref_msgpack);
    flb_free(ctx);
    return 0;
}

/* Set plugin configuration */
static int configure(struct flb_in_dummy_config *ctx,
                     struct flb_input_instance *in,
                                 struct timespec *tm)
{
    char *str = NULL;
    int root_type;
    int  ret = -1;
    long val  = 0;

    ctx->ref_msgpack = NULL;

    /* samples */
    str = flb_input_get_property("dummy", in);
    if (str != NULL) {
        ctx->dummy_message = flb_strdup(str);
    }
    else {
        ctx->dummy_message = flb_strdup(DEFAULT_DUMMY_MESSAGE);
    }
    ctx->dummy_message_len = strlen(ctx->dummy_message);

    /* interval settings */
    tm->tv_sec  = 1;
    tm->tv_nsec = 0;

    str = flb_input_get_property("rate", in);
    if (str != NULL && (val = atoi(str)) > 1) {
        tm->tv_sec = 0;
        tm->tv_nsec = 1000000000 / val;
    }

    ret = flb_pack_json(ctx->dummy_message,
                  ctx->dummy_message_len,
                        &ctx->ref_msgpack, &ctx->ref_msgpack_size, &root_type);
    if (ret != 0) {
        flb_warn("[in_dummy] Data is incomplete. Use default string.");

        flb_free(ctx->dummy_message);
        ctx->dummy_message = flb_strdup(DEFAULT_DUMMY_MESSAGE);
        ctx->dummy_message_len = strlen(ctx->dummy_message);

        ret = flb_pack_json(ctx->dummy_message,
                            ctx->dummy_message_len,
                            &ctx->ref_msgpack, &ctx->ref_msgpack_size,
                            &root_type);
        if (ret != 0) {
            flb_error("[in_dummy] Unexpected error");
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
    struct flb_in_dummy_config *ctx = NULL;
    struct timespec tm;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_in_dummy_config));
    if (ctx == NULL) {
        return -1;
    }

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
        flb_error("could not set collector for dummy input plugin");
        config_destroy(ctx);
        return -1;
    }

    return 0;
}

static int in_dummy_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_dummy_config *ctx = data;

    config_destroy(ctx);

    return 0;
}


struct flb_input_plugin in_dummy_plugin = {
    .name         = "dummy",
    .description  = "Generate dummy data",
    .cb_init      = in_dummy_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_dummy_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_dummy_exit
};
