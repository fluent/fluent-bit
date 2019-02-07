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
#include "stdlib.h"

#include "throttle.h"
#include "window.h"


static bool apply_suffix (double *x, char suffix_char)
{
  int multiplier;

  switch (suffix_char)
    {
    case 0:
    case 's':
      multiplier = 1;
      break;
    case 'm':
      multiplier = 60;
      break;
    case 'h':
      multiplier = 60 * 60;
      break;
    case 'd':
      multiplier = 60 * 60 * 24;
      break;
    default:
      return false;
    }

  *x *= multiplier;

  return true;
}


void *time_ticker(void *args)
{
    struct ticker *t = args;
    struct flb_time ftm;
    long timestamp;

    while (!t->done) {
        flb_time_get(&ftm);
        timestamp = flb_time_to_double(&ftm);
        window_add(t->ctx->hash, timestamp, 0);

        t->ctx->hash->current_timestamp = timestamp;

        if (t->ctx->print_status) {
            flb_info("[filter_throttle] %i: limit is %0.2f per %s with window size of %i, current rate is: %i per interval", timestamp, t->ctx->max_rate, t->ctx->slide_interval, t->ctx->window_size, t->ctx->hash->total / t->ctx->hash->size);
        }
        sleep(t->seconds);
    }

    return NULL;
}

/* Given a msgpack record, do some filter action based on the defined rules */
static inline int throttle_data(struct flb_filter_throttle_ctx *ctx)
{
    if ((ctx->hash->total / (double) ctx->hash->size) >= ctx->max_rate) {
        return THROTTLE_RET_DROP;
    }

    window_add(ctx->hash, ctx->hash->current_timestamp, 1);

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

    /* print informational status */
    str = flb_filter_get_property("print_status", f_ins);
    if (str != NULL) {
        ctx->print_status = flb_utils_bool(str);
    } else {
        ctx->print_status = THROTTLE_DEFAULT_STATUS;
    }

    /* sliding interval */
    str = flb_filter_get_property("interval", f_ins);
    if (str != NULL) {
        ctx->slide_interval = str;
    } else {
        ctx->slide_interval = THROTTLE_DEFAULT_INTERVAL;
    }
    return 0;
}

static int parse_duration(char *interval)
{
    double seconds = 0.0;
    double s;
    char *p;

    s = strtod(interval, &p);
    if  ( 0 >= s
          /* No extra chars after the number and an optional s,m,h,d char.  */
          || (*p && *(p+1))
          /* Check any suffix char and update S based on the suffix.  */
          || ! apply_suffix (&s, *p))
        {
            flb_warn("[filter_throttle] invalid time interval %s falling back to default: 1 second", interval);
        }

      seconds += s;
      return seconds;
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
    ticker_ctx->seconds = parse_duration(ctx->slide_interval);
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
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
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

    flb_free(ctx->hash->table);
    flb_free(ctx->hash);
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
