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

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_hash.h>
#include <msgpack.h>

#include "ratelimit.h"

#define RATELIMIT_RECORDS_PER_SECOND 5
#define RATELIMIT_RECORDS_BURST 20
#define RATELIMIT_INITIAL_DELAY_SECONDS 5
#define RATELIMIT_MAX_BUCKETS 256
#define RATELIMIT_KEEP 0
#define RATELIMIT_EXCLUDE 1
#define RATELIMIT_LOG_PERIOD_SECONDS 60

struct bucket {
    /* Last time this bucket was accessed */
    time_t last;
    /* Number of tokens in bucket */
    int tokens;
    /* Number of dropped records in last logging period */
    unsigned int dropped;
    /* Last time logged the dropped records */
    time_t last_logged;
};

struct ratelimit_ctx {
    /* Config values */
    char *bucket_key_field;
    int records_per_second;
    int records_burst;
    int initial_delay_seconds;
    int max_buckets;
    int log_period_seconds;

    /* Filter state */
    /* Hash table of buckets for quick lookup on each event */
    struct flb_hash *buckets;
    /* Time the filter started */
    time_t filter_start;
};

static int inline minint(int a, int b) {
    return a > b ? b : a;
}

static void ratelimit_ctx_destroy(struct ratelimit_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->bucket_key_field != NULL) {
        flb_free(ctx->bucket_key_field);
    }
    if (ctx->buckets != NULL) {
        flb_hash_destroy(ctx->buckets);
    }
    flb_free(ctx);
}

/*
 * ratelimit_limit_by_bucket uses a typical token based limit algorithm. We add 'records_per_second' tokens for
 * every second that has elapsed since we last used this bucket, up to the max of 'records_burst'.
 *
 * This has the effect of limiting events to 'records_per_second' on average, with max events in a second
 * limited to 'records_burst'.
 */
static int ratelimit_limit_by_bucket(struct ratelimit_ctx *ctx, char *bucket_key, int bucket_key_len) {
    int ret;
    int id;
    int elapsed_time;
    int limit_ret;
    size_t out_size;
    void *out;
    struct bucket *bucket;
    struct bucket *tmp_bucket;
    time_t now;

    /* Get current time */
    now = time(NULL);

    /* Retrieve bucket for this event */
    ret = flb_hash_get(ctx->buckets, bucket_key, bucket_key_len, &out, &out_size);
    bucket = out;
    if (ret == -1) {
        /* Create bucket */
        tmp_bucket = flb_malloc(sizeof(struct bucket));
        tmp_bucket->last = now;
        tmp_bucket->tokens = ctx->records_burst;
        tmp_bucket->dropped = 0;
        tmp_bucket->last_logged = now;
        id = flb_hash_add(ctx->buckets, bucket_key, bucket_key_len, tmp_bucket, sizeof(struct bucket));
        flb_free(tmp_bucket);
        flb_hash_get_by_id(ctx->buckets, id, bucket_key, bucket_key_len, &out, &out_size);
        bucket = out;
    }

    /* Add tokens */
    if (bucket->tokens < ctx->records_burst) {
        elapsed_time = (int) difftime(now, bucket->last);
        if (elapsed_time > 0) {
            bucket->tokens = minint(ctx->records_burst, bucket->tokens + elapsed_time * ctx->records_per_second);
        }
    }
    bucket->last = now;

    /* Check if we have a token to accept this event */
    if (bucket->tokens > 0) {
        bucket->tokens--;
        limit_ret = RATELIMIT_KEEP;
    } else {
        bucket->dropped++;
        limit_ret = RATELIMIT_EXCLUDE;
    }

    /* Log when messages are dropped at most once per RATELIMIT_LOG_PERIOD_SECONDS */
    if (bucket->dropped > 0 && difftime(now, bucket->last_logged) > ctx->log_period_seconds) {
        flb_info("[filter_ratelimit] %d dropped message(s) in last %ds: %s=%s",
                 bucket->dropped, (int) difftime(now, bucket->last_logged),
                 ctx->bucket_key_field, bucket_key);
        bucket->dropped = 0;
        bucket->last_logged = now;
    }

    return limit_ret;
}

static int ratelimit_limit(struct ratelimit_ctx *ctx, msgpack_object map) {
    int i;
    int klen;
    int vlen;
    int bucket_key_len;
    int ret;
    msgpack_object *k;
    msgpack_object *v;
    char *key;
    char *val;
    char *bucket_key;

    for (i = 0; i < map.via.map.size; i++) {
        k = &map.via.map.ptr[i].key;

        if (k->type != MSGPACK_OBJECT_BIN &&
            k->type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (k->type == MSGPACK_OBJECT_STR) {
            key  = (char *) k->via.str.ptr;
            klen = k->via.str.size;
        }
        else {
            key = (char *) k->via.bin.ptr;
            klen = k->via.bin.size;
        }

        if (strncmp(key, ctx->bucket_key_field, klen) == 0) {
            break;
        }

        k = NULL;
    }

    if (!k) {
        /* Bucket field doesn't exist - keep message */
        flb_debug("[filter_ratelimit] bucket_key %s isn't present on event", ctx->bucket_key_field);
        return RATELIMIT_KEEP;
    }

    v = &map.via.map.ptr[i].val;
    if (v->type == MSGPACK_OBJECT_STR) {
        val = (char *)v->via.str.ptr;
        vlen = v->via.str.size;
    }
    else if(v->type == MSGPACK_OBJECT_BIN) {
        val  = (char *)v->via.bin.ptr;
        vlen = v->via.bin.size;
    }
    else {
        flb_warn("[filter_ratelimit] bucket_key %s value isn't a string", ctx->bucket_key_field);
        return RATELIMIT_KEEP;
    }

    bucket_key = flb_strndup(val, vlen);
    bucket_key_len = vlen + 1;

    ret = ratelimit_limit_by_bucket(ctx, bucket_key, bucket_key_len);
    flb_free(bucket_key);
    return ret;
}

static int cb_ratelimit_init(struct flb_filter_instance *f_ins,
                             struct flb_config *config,
                             void *data)
{
    char *tmp;
    long int r;
    struct ratelimit_ctx *ctx;

    /* Create context */
    ctx = flb_malloc(sizeof(struct ratelimit_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->bucket_key_field = NULL;
    ctx->records_per_second = RATELIMIT_RECORDS_PER_SECOND;
    ctx->records_burst = RATELIMIT_RECORDS_BURST;
    ctx->initial_delay_seconds = RATELIMIT_INITIAL_DELAY_SECONDS;
    ctx->max_buckets = RATELIMIT_MAX_BUCKETS;
    ctx->log_period_seconds = RATELIMIT_LOG_PERIOD_SECONDS;
    ctx->buckets = NULL;

    /* Set config values */
    tmp = flb_filter_get_property("bucket_key", f_ins);
    if (tmp) {
        ctx->bucket_key_field = flb_strdup(tmp);
    } else {
        flb_error("[filter_ratelimit] bucket_key must be set");
        ratelimit_ctx_destroy(ctx);
        return -1;
    }

    tmp = flb_filter_get_property("records_per_second", f_ins);
    if (tmp) {
        r = strtol(tmp, NULL, 10);
        if (r <= 0 || INT_MAX < r) {
            flb_error("[filter_ratelimit] invalid records_per_second=%s, must be a positive integer", tmp);
            ratelimit_ctx_destroy(ctx);
            return -1;
        }
        ctx->records_per_second = (int)r;
    }

    tmp = flb_filter_get_property("records_burst", f_ins);
    if (tmp) {
        r = strtol(tmp, NULL, 10);
        if (r <= 0 || INT_MAX < r) {
            flb_error("[filter_ratelimit] invalid records_burst=%s, must be a positive integer", tmp);
            ratelimit_ctx_destroy(ctx);
            return -1;
        }
        ctx->records_burst = (int)r;
    }

    if (ctx->records_burst < ctx->records_per_second) {
        flb_info("[filter_ratelimit] records_burst is smaller than records_per_second, setting to same value");
        ctx->records_burst = ctx->records_per_second;
    }

    tmp = flb_filter_get_property("initial_delay_seconds", f_ins);
    if (tmp) {
        r = strtol(tmp, NULL, 10);
        if (r < 0 || INT_MAX < r) {
            flb_error("[filter_ratelimit] invalid initial_delay_seconds=%s, must be >= 0", tmp);
            ratelimit_ctx_destroy(ctx);
            return -1;
        }
        ctx->initial_delay_seconds = (int)r;
    }

    tmp = flb_filter_get_property("max_buckets", f_ins);
    if (tmp) {
        r = strtol(tmp, NULL, 10);
        if (r <= 0 || INT_MAX < r) {
            flb_error("[filter_ratelimit] invalid max_buckets=%s, must be a positive integer", tmp);
            ratelimit_ctx_destroy(ctx);
            return -1;
        }
        ctx->max_buckets = (int)r;
    }

    tmp = flb_filter_get_property("log_period_seconds", f_ins);
    if (tmp) {
        r = strtol(tmp, NULL, 10);
        if (r < 0 || INT_MAX < r) {
            flb_error("[filter_ratelimit] invalid log_period_seconds=%s, must be >= 0", tmp);
            ratelimit_ctx_destroy(ctx);
            return -1;
        }
        ctx->log_period_seconds = (int)r;
    }

    flb_debug("[filter_ratelimit] bucket_key_field=%s", ctx->bucket_key_field);
    flb_debug("[filter_ratelimit] records_per_second=%d", ctx->records_per_second);
    flb_debug("[filter_ratelimit] records_burst=%d", ctx->records_burst);
    flb_debug("[filter_ratelimit] initial_delay_seconds=%d", ctx->initial_delay_seconds);
    flb_debug("[filter_ratelimit] max_buckets=%d", ctx->max_buckets);
    flb_debug("[filter_ratelimit] log_period_seconds=%d", ctx->log_period_seconds);

    /* Initialize context state */
    ctx->buckets = flb_hash_create(ctx->max_buckets);
    ctx->filter_start = time(NULL);

    /* Set context */
    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_ratelimit_filter(void *data, size_t bytes,
                               char *tag, int tag_len,
                               void **out_buf, size_t *out_size,
                               struct flb_filter_instance *f_ins,
                               void *context,
                               struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_object root;
    msgpack_object map;
    int old_size = 0;
    int new_size = 0;
    int ret;
    struct ratelimit_ctx *ctx = context;

    /* Check if in the initial delay period where nothing should be rate limited */
    if (ctx->initial_delay_seconds > 0) {
        if (difftime(time(NULL), ctx->filter_start) < ctx->initial_delay_seconds) {
            return FLB_FILTER_NOTOUCH;
        } else {
            /* Don't check anymore */
            ctx->initial_delay_seconds = 0;
        }
    }

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Process each message */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        root = result.data;
        if (root.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        old_size++;

        /* get fields */
        map = root.via.array.ptr[1];

        ret = ratelimit_limit(context, map);
        if (ret == RATELIMIT_KEEP) {
            msgpack_pack_object(&tmp_pck, root);
            new_size++;
        }
        else if (ret == RATELIMIT_EXCLUDE) {
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
    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_ratelimit_exit(void *data, struct flb_config *config)
{
    struct ratelimit_ctx *ctx = data;

    ratelimit_ctx_destroy(ctx);
    return 0;
}

struct flb_filter_plugin filter_ratelimit_plugin = {
        .name         = "ratelimit",
        .description  = "ratelimit events by specified field values",
        .cb_init      = cb_ratelimit_init,
        .cb_filter    = cb_ratelimit_filter,
        .cb_exit      = cb_ratelimit_exit,
        .flags        = 0
};
