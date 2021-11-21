/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>

#include <sys/types.h>
#include <sys/stat.h>

struct em_chunk {
    flb_sds_t tag;
    struct msgpack_sbuffer mp_sbuf;  /* msgpack sbuffer        */
    struct msgpack_packer mp_pck;    /* msgpack packer         */
    struct mk_list _head;
};

struct flb_emitter {
    int coll_fd;                        /* collector id */
    int async_emit;                     /* queueing by time */

    /* function pointer to add record. It is invoked by other plugin */
    int (*add_record_func) (const char *tag, int tag_len,
                            const char *buf_data, size_t buf_size,
                            struct flb_input_instance *in);
    struct mk_list chunks;              /* list of all pending chunks */
    struct flb_input_instance *ins;     /* input instance */
};

struct em_chunk *em_chunk_create(const char *tag, int tag_len,
                                 struct flb_emitter *ctx)
{
    struct em_chunk *ec;

    ec = flb_calloc(1, sizeof(struct em_chunk));
    if (!ec) {
        flb_errno();
        return NULL;
    }

    ec->tag = flb_sds_create_len(tag, tag_len);
    if (!ec->tag) {
        flb_errno();
        flb_free(ec);
        return NULL;
    }

    msgpack_sbuffer_init(&ec->mp_sbuf);
    msgpack_packer_init(&ec->mp_pck, &ec->mp_sbuf, msgpack_sbuffer_write);

    mk_list_add(&ec->_head, &ctx->chunks);

    return ec;
}

static void em_chunk_destroy(struct em_chunk *ec)
{
    mk_list_del(&ec->_head);
    flb_sds_destroy(ec->tag);
    msgpack_sbuffer_destroy(&ec->mp_sbuf);
    flb_free(ec);
}


/*
 * Function used by filters to ingest custom records with custom tags, at the
 * moment it's only used by rewrite_tag filter.
 */
static int in_emitter_add_record_async(const char *tag, int tag_len,
                                       const char *buf_data, size_t buf_size,
                                       struct flb_input_instance *in)
{
    struct mk_list *head;
    struct em_chunk *ec = NULL;
    struct flb_emitter *ctx;

    ctx = (struct flb_emitter *) in->context;

    /* Check if any target chunk already exists */
    mk_list_foreach(head, &ctx->chunks) {
        ec = mk_list_entry(head, struct em_chunk, _head);
        if (flb_sds_cmp(ec->tag, tag, tag_len) != 0) {
            ec = NULL;
            continue;
        }
        break;
    }

    /* No candidate chunk found, so create a new one */
    if (!ec) {
        ec = em_chunk_create(tag, tag_len, ctx);
        if (!ec) {
            flb_plg_error(ctx->ins, "cannot create new chunk for tag: %s",
                      tag);
            return -1;
        }
    }

    /* Append raw msgpack data */
    msgpack_sbuffer_write(&ec->mp_sbuf, buf_data, buf_size);
    return 0;
}

static int in_emitter_add_record_sync(const char *tag, int tag_len,
                                      const char *buf_data, size_t buf_size,
                                      struct flb_input_instance *in)
{
    struct mk_list *head;
    struct em_chunk *ec = NULL;
    struct flb_emitter *ctx;
    int ret;

    ctx = (struct flb_emitter *) in->context;

    /* Check if any target chunk already exists */
    mk_list_foreach(head, &ctx->chunks) {
        ec = mk_list_entry(head, struct em_chunk, _head);
        if (flb_sds_cmp(ec->tag, tag, tag_len) != 0) {
            ec = NULL;
            continue;
        }
        break;
    }

    /* No candidate chunk found, so create a new one */
    if (!ec) {
        ec = em_chunk_create(tag, tag_len, ctx);
        if (!ec) {
            flb_plg_error(ctx->ins, "cannot create new chunk for tag: %s",
                      tag);
            return -1;
        }
    }

    /* Append raw msgpack data */
    msgpack_sbuffer_write(&ec->mp_sbuf, buf_data, buf_size);

    /* Associate this backlog chunk to this instance into the engine */
    ret = flb_input_chunk_append_raw(in,
                                     ec->tag, flb_sds_len(ec->tag),
                                     ec->mp_sbuf.data,
                                     ec->mp_sbuf.size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error registering chunk with tag: %s",
                      ec->tag);
        /* Release the echunk */
        em_chunk_destroy(ec);
        return -1;
    }
    /* Release the echunk */
    em_chunk_destroy(ec);
    return 0;
}

int in_emitter_add_record(const char *tag, int tag_len,
                          const char *buf_data, size_t buf_size,
                          struct flb_input_instance *in)
{
    struct flb_emitter *ctx;
    ctx = (struct flb_emitter *) in->context;
    return ctx->add_record_func(tag, tag_len, buf_data, buf_size, in);
}

int in_emitter_get_collector_id(struct flb_input_instance *in)
{
    struct flb_emitter *ctx = (struct flb_emitter *) in->context;
    if (ctx->async_emit == FLB_FALSE) {
        return -1;
    }
    return ctx->coll_fd;
}

/* queueing callback for async mode */
static int cb_queue_chunks(struct flb_input_instance *in,
                           struct flb_config *config, void *data)
{
    int ret;
    struct mk_list *tmp;
    struct mk_list *head;
    struct em_chunk *echunk;
    struct flb_emitter *ctx;

    /* Get context */
    ctx = (struct flb_emitter *) data;

    /* Try to enqueue chunks under our limits */
    mk_list_foreach_safe(head, tmp, &ctx->chunks) {
        echunk = mk_list_entry(head, struct em_chunk, _head);

        /* Associate this backlog chunk to this instance into the engine */
        ret = flb_input_chunk_append_raw(in,
                                         echunk->tag, flb_sds_len(echunk->tag),
                                         echunk->mp_sbuf.data,
                                         echunk->mp_sbuf.size);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error registering chunk with tag: %s",
                          echunk->tag);
            continue;
        }

        /* Release the echunk */
        em_chunk_destroy(echunk);
    }

    return 0;
}

/* Initialize plugin */
static int cb_emitter_init(struct flb_input_instance *in,
                           struct flb_config *config, void *data)
{
    int ret;
    flb_sds_t tmp;
    struct flb_emitter *ctx;

    ctx = flb_malloc(sizeof(struct flb_emitter));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;
    ctx->async_emit = FLB_FALSE;
    mk_list_init(&ctx->chunks);

    /* export plugin context */
    flb_input_set_context(in, ctx);

    tmp = (char *)flb_input_get_property("async_emit", in);
    if (tmp) {
        ctx->async_emit = flb_utils_bool(tmp);
    }

    if (ctx->async_emit) {
        /* Async mode setting */
        flb_plg_debug(ctx->ins, "async mode");
        ctx->add_record_func = in_emitter_add_record_async;

        /* Set a collector to trigger the callback to queue data every 0.5 second */
        ret = flb_input_set_collector_time(in, cb_queue_chunks, 0, 50000000, config);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "could not create collector");
            flb_free(ctx);
            return -1;
        }
        ctx->coll_fd = ret;
    }
    else {
        /* Sync mode setting */
        flb_plg_debug(ctx->ins, "sync mode");
        ctx->add_record_func = in_emitter_add_record_sync;
        ctx->coll_fd = -1;
    }
    return 0;
}

static void cb_emitter_pause(void *data, struct flb_config *config)
{
    struct flb_emitter *ctx = data;
    if (ctx->async_emit) {
        flb_input_collector_pause(ctx->coll_fd, ctx->ins);
    }
}

static void cb_emitter_resume(void *data, struct flb_config *config)
{
    struct flb_emitter *ctx = data;
    if (ctx->async_emit) {
        flb_input_collector_resume(ctx->coll_fd, ctx->ins);
    }
}

static int cb_emitter_exit(void *data, struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_emitter *ctx = data;
    struct em_chunk *echunk;
    if (ctx->async_emit) {
        flb_input_collector_pause(ctx->coll_fd, ctx->ins);
    }

    mk_list_foreach_safe(head, tmp, &ctx->chunks) {
        echunk = mk_list_entry(head, struct em_chunk, _head);
        mk_list_del(&echunk->_head);
        flb_free(echunk);
    }

    flb_free(ctx);
    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_emitter_plugin = {
    .name         = "emitter",
    .description  = "Record Emitter",
    .cb_init      = cb_emitter_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_ingest    = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = cb_emitter_pause,
    .cb_resume    = cb_emitter_resume,
    .cb_exit      = cb_emitter_exit,

    /* This plugin can only be configured and invoked by the Engine only */
    .flags        = FLB_INPUT_PRIVATE
};
