/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_random.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0

struct flb_in_random_config {
    /* Config properties */
    int              interval_sec;
    int              interval_nsec;
    int              samples;

    /* Internal */
    int              samples_count;

    struct flb_input_instance *ins;
};

/* cb_collect callback */
static int in_random_collect(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    uint64_t val;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_in_random_config *ctx = in_context;

    if (ctx->samples == 0) {
        return -1;
    }

    if (ctx->samples > 0 && (ctx->samples_count >= ctx->samples)) {
        return -1;
    }

    if (flb_random_bytes((unsigned char *) &val, sizeof(uint64_t))) {
        val = time(NULL);
    }

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Pack data */
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, 1);

    msgpack_pack_str(&mp_pck, 10);
    msgpack_pack_str_body(&mp_pck, "rand_value", 10);
    msgpack_pack_uint64(&mp_pck, val);

    flb_input_chunk_append_raw(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);
    ctx->samples_count++;

    return 0;
}

/* Set plugin configuration */
static int in_random_config_read(struct flb_in_random_config *ctx,
                                 struct flb_input_instance *in)
{
    const char *val = NULL;

    /* samples */
    val = flb_input_get_property("samples", in);
    if (val != NULL && atoi(val) >= 0) {
        ctx->samples = atoi(val);
    }

    /* interval settings */
    val = flb_input_get_property("interval_sec", in);
    if (val != NULL && atoi(val) >= 0) {
        ctx->interval_sec = atoi(val);
    }
    else {
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    }

    val = flb_input_get_property("interval_nsec", in);
    if (val != NULL && atoi(val) >= 0) {
        ctx->interval_nsec = atoi(val);
    }
    else {
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }


    flb_plg_debug(ctx->ins, "interval_sec=%d interval_nsec=%d",
                  ctx->interval_sec, ctx->interval_nsec);

    return 0;
}

/* Initialize plugin */
static int in_random_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_in_random_config *ctx = NULL;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_in_random_config));
    if (!ctx) {
        return -1;
    }
    ctx->samples       = -1;
    ctx->samples_count = 0;
    ctx->ins = in;

    /* Initialize head config */
    ret = in_random_config_read(ctx, in);
    if (ret < 0) {
        flb_free(ctx);
        return -1;
    }

    flb_input_set_context(in, ctx);
    ret = flb_input_set_collector_time(in,
                                       in_random_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec, config);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "could not set collector for head input plugin");
        flb_free(ctx);
        return -1;
    }

    return 0;
}

static int in_random_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_random_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}


struct flb_input_plugin in_random_plugin = {
    .name         = "random",
    .description  = "Random",
    .cb_init      = in_random_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_random_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_random_exit
};
