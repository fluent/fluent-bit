/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_stats.h>

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0

struct flb_in_random_config {
    /* Config properties */
    int              interval_sec;
    int              interval_nsec;
    int              samples;

    /* Internal */
    int              samples_count;
    msgpack_packer   mp_pck;
    msgpack_sbuffer  mp_sbuf;
};

/* cb_collect callback */
static int in_random_collect(struct flb_config *config, void *in_context)
{
    int fd;
    int ret;
    uint64_t val;
    struct flb_in_random_config *ctx = in_context;

    if (ctx->samples == 0) {
        return -1;
    }

    if (ctx->samples > 0 && (ctx->samples_count >= ctx->samples)) {
        return -1;
    }

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        val = time(NULL);
    }
    else {
        ret = read(fd, &val, sizeof(val));
        if (ret == -1) {
            perror("read");
            close(fd);
            return -1;
        }
        close(fd);
    }

    msgpack_pack_array(&ctx->mp_pck, 2);
    msgpack_pack_uint64(&ctx->mp_pck, time(NULL));
    msgpack_pack_map(&ctx->mp_pck, 1);

    msgpack_pack_bin(&ctx->mp_pck, 10);
    msgpack_pack_bin_body(&ctx->mp_pck, "rand_value", 10);
    msgpack_pack_uint64(&ctx->mp_pck, val);

    ctx->samples_count++;

    return 0;
}

/* Set plugin configuration */
static int in_random_config_read(struct flb_in_random_config *random_config,
                                 struct flb_input_instance *in)
{
    char *val = NULL;

    /* samples */
    val = flb_input_get_property("samples", in);
    if (val != NULL && atoi(val) >= 0) {
        random_config->samples = atoi(val);
    }

    /* interval settings */
    val = flb_input_get_property("interval_sec", in);
    if (val != NULL && atoi(val) >= 0) {
        random_config->interval_sec = atoi(val);
    }
    else {
        random_config->interval_sec = DEFAULT_INTERVAL_SEC;
    }

    val = flb_input_get_property("interval_nsec", in);
    if (val != NULL && atoi(val) >= 0) {
        random_config->interval_nsec = atoi(val);
    }
    else {
        random_config->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    if (random_config->interval_sec <= 0 && random_config->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        random_config->interval_sec = DEFAULT_INTERVAL_SEC;
        random_config->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }


    flb_debug("[in_random] interval_sec=%d interval_nsec=%d",
              random_config->interval_sec, random_config->interval_nsec);

    return 0;
}

/* Initialize plugin */
static int in_random_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    int ret = -1;
    struct flb_in_random_config *ctx = NULL;

    /* Allocate space for the configuration */
    ctx = malloc(sizeof(struct flb_in_random_config));
    if (!ctx) {
        return -1;
    }
    ctx->samples       = 1;
    ctx->samples_count = 0;

    /* Initialize head config */
    ret = in_random_config_read(ctx, in);
    if (ret < 0) {
        free(ctx);
        return -1;
    }

    flb_input_set_context(in, ctx);
    ret = flb_input_set_collector_time(in,
                                       in_random_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec, config);

    /* Initialize msgpack buffer */
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck,
                        &ctx->mp_sbuf, msgpack_sbuffer_write);

    if (ret < 0) {
        flb_utils_error_c("could not set collector for head input plugin");
        msgpack_sbuffer_destroy(&ctx->mp_sbuf);
        free(ctx);
        return -1;
    }

    return 0;
}

/* cb_flush callback */
static void *in_random_flush(void *in_context, size_t *size)
{
    char *buf = NULL;
    struct flb_in_random_config *ctx = in_context;

    if (ctx->samples_count < ctx->samples || ctx->mp_sbuf.size == 0) {
        return NULL;
    }

    buf = malloc(ctx->mp_sbuf.size);
    if (!buf) {
        return NULL;
    }

    memcpy(buf, ctx->mp_sbuf.data, ctx->mp_sbuf.size);
    *size = ctx->mp_sbuf.size;
    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck,
                        &ctx->mp_sbuf, msgpack_sbuffer_write);

    return buf;
}

static int in_random_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_random_config *ctx = data;

    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    free(ctx);

    return 0;
}


struct flb_input_plugin in_random_plugin = {
    .name         = "random",
    .description  = "Random",
    .cb_init      = in_random_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_random_collect,
    .cb_flush_buf = in_random_flush,
    .cb_exit      = in_random_exit
};
