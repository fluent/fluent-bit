/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
#include <sys/types.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include "throttle.h"
#include "window.h"


struct ticker {
    struct flb_filter_throttle_ctx *ctx;
    bool done;
};

void *time_ticker(void *args)
{
    struct ticker *t_ctx = args;
    struct flb_time ftm;
    long timestamp;

    while (!t_ctx->done) {
        flb_time_get(&ftm);
        timestamp = flb_time_to_double(&ftm);
        window_add(t_ctx->ctx->hash, timestamp, 0);

        t_ctx->ctx->hash->current_timestamp = timestamp;

        flb_error("current time is: %i", timestamp);
        sleep(1);
    }
}

/* Given a msgpack record, do some filter action based on the defined rules */
static inline int throttle_data(struct flb_filter_throttle_ctx *ctx)
{
    if ( ctx->hash->total / ctx->hash->size > ctx->max_rate) {
        return THROTTLE_RET_DROP;
    }

    window_add(ctx->hash, ctx->hash->current_timestamp, 1);

    flb_debug("[filter_throttle] limist is %f per sec in window %i sec, current rate is: %i per sec", ctx->max_rate, ctx->window_size, ctx->hash->total / ctx->hash->size);

    return THROTTLE_RET_KEEP;
}

static int configure(struct flb_filter_throttle_ctx *ctx, struct flb_filter_instance *f_ins)
{
    char *str = NULL;
    double val  = 0;
    char *endp;

    /* rate per second */
    str = flb_filter_get_property("rate", f_ins);

    if (str != NULL && (val = strtod(str, &endp)) > 1) {
        ctx->max_rate = val;
    } else {
        ctx->max_rate = THROTTLE_DEFAULT_RATE;
    }

    /* windows size */
    str = flb_filter_get_property("window", f_ins);
    if (str != NULL && (val = strtoul(str, &endp, 10)) > 1) {
        ctx->window_size = val;
    } else {
        ctx->window_size = THROTTLE_DEFAULT_WINDOW;
    }

    return 0;
}

static int cb_throttle_init(struct flb_filter_instance *f_ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    struct flb_filter_throttle_ctx *ctx;
    pthread_t tid;
    struct ticker *ticker_ctx;

    /* Create context */
    ctx = flb_malloc(sizeof(struct flb_filter_throttle_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    /* parse plugin configuration  */
    ret = configure(ctx, f_ins);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    ctx->hash = window_create(ctx->window_size);

    /* Set our context */
    flb_filter_set_context(f_ins, ctx);

    ticker_ctx = flb_malloc(sizeof(struct ticker));
    ticker_ctx->ctx = ctx;
    ticker_ctx->done = false;
    pthread_create(&tid, NULL, &time_ticker, ticker_ctx);
    return 0;
}

static int cb_throttle_filter(void *data, size_t bytes,
                          char *tag, int tag_len,
                          void **out_buf, size_t *out_size,
                          struct flb_filter_instance *f_ins,
                          void *context,
                          struct flb_config *config)
{
    int ret;
    int old_size = 0;
    int new_size = 0;
    msgpack_unpacked result;
    msgpack_object root;
    size_t off = 0;
    (void) f_ins;
    (void) config;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);


    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        old_size++;

        ret = throttle_data(context);
        if (ret == THROTTLE_RET_KEEP) {
            msgpack_pack_object(&tmp_pck, root);
            new_size++;
        }
        else if (ret == THROTTLE_RET_DROP) {
            /* Do nothing */
        }
    }
    msgpack_unpacked_destroy(&result);

    /* we keep everything ? */
    if (old_size == new_size) {
        /* Destroy the buffer to avoid more overhead */
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return FLB_FILTER_NOTOUCH;
    }

    /* link new buffers */
    *out_buf   = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_throttle_exit(void *data, struct flb_config *config)
{
    struct flb_filter_throttle_ctx *ctx = data;

    flb_free(ctx);
    return 0;
}

struct flb_filter_plugin filter_throttle_plugin = {
    .name         = "throttle",
    .description  = "Throttle messages using sliding window algorithm",
    .cb_init      = cb_throttle_init,
    .cb_filter    = cb_throttle_filter,
    .cb_exit      = cb_throttle_exit,
    .flags        = 0
};
