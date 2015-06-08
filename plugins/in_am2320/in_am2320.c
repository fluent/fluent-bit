/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 *  in_am2320: AM2320/2321 I2C Sensor device input
 *  Copyright (C) 2015 Takeshi HASEGAWA
 *
 *  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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
#include <linux/kernel.h>

#include <time.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include "in_am2320.h"
#include "am2320.h"

int in_am2320_collect(struct flb_config *config, void *in_context);

int in_am2320_init(struct flb_config *config)
{
    int ret;
    struct flb_in_am2320_config *ctx;

    ctx = malloc(sizeof(struct flb_in_am2320_config));
    if (!ctx) {
        return -1;
    }
    ctx->idx = 0;
    msgpack_sbuffer_init(&ctx->sbuf);
    msgpack_packer_init(&ctx->pckr, &ctx->sbuf, msgpack_sbuffer_write);
    ret = flb_input_set_context("am2320", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("[in_am2320] Could not set configuration for memory input plugin");
    }
    ret = flb_input_set_collector_time("am2320",
                                       in_am2320_collect,
                                       IN_AM2320_COLLECT_SEC,
                                       IN_AM2320_COLLECT_NSEC,
                                       config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for memory input plugin");
    }
    return 0;
}

int in_am2320_pre_run(void *in_context, struct flb_config *config)
{
    struct flb_in_am2320_config *ctx = in_context;

    ctx->tag_len = snprintf(ctx->tag, sizeof(ctx->tag), "%s.am2320", config->tag);
    if (ctx->tag_len == -1) {
        flb_utils_error_c("Could not set custom tag on memory input plugin");
    }
    return 0;
}

int in_am2320_collect(struct flb_config *config, void *in_context)
{
    return in_am2320_read(config, in_context);
}

void *in_am2320_flush(void *in_context, int *size)
{
    char *buf;
    struct flb_in_am2320_config *ctx = in_context;

    if (ctx->idx == 0)
        return NULL;

    buf = malloc(ctx->sbuf.size);
    if (!buf)
        return NULL;

    memcpy(buf, ctx->sbuf.data, ctx->sbuf.size);
    *size = ctx->sbuf.size;
    msgpack_sbuffer_destroy(&ctx->sbuf);
    msgpack_sbuffer_init(&ctx->sbuf);
    msgpack_packer_init(&ctx->pckr, &ctx->sbuf, msgpack_sbuffer_write);
    ctx->idx = 0;
    return buf;
}

struct flb_input_plugin in_am2320_plugin = {
    .name         = "am2320",
    .description  = "AM2320/AM2321 Sensor",
    .cb_init      = in_am2320_init,
    .cb_pre_run   = in_am2320_pre_run,
    .cb_collect   = in_am2320_collect,
    .cb_flush_buf = in_am2320_flush
};
