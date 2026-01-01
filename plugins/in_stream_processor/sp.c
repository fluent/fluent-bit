/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_sds.h>

struct sp_chunk {
    char *buf_data;
    size_t buf_size;
    struct mk_list _head;
};

struct sp_ctx {
    int coll_fd;                    /* collector file descriptor to flush queue */
    flb_sds_t tag;                  /* outgoing Tag name */
    struct mk_list chunks;          /* linked list with data chunks to ingest */
    struct flb_input_instance *ins;
};

/*
 * This 'special' function is used by the Stream Processor engine to register
 * data results of a query that needs to be ingested into the main pipeline.
 *
 * We usually don't do this in a plugin but for simplicity and to avoid
 * extra memory-copies we just expose this function for direct use.
 */
int in_stream_processor_add_chunk(char *buf_data, size_t buf_size,
                                  struct flb_input_instance *ins)
{
    struct sp_chunk *chunk;
    struct sp_ctx *ctx = (struct sp_ctx *) ins->context;

    chunk = flb_malloc(sizeof(struct sp_chunk));
    if (!chunk) {
        flb_errno();
        return -1;
    }

    chunk->buf_data = buf_data;
    chunk->buf_size = buf_size;
    mk_list_add(&chunk->_head, &ctx->chunks);

    return 0;
}

/* Callback used to queue pending data chunks */
static int cb_chunks_append(struct flb_input_instance *in,
                            struct flb_config *config, void *in_context)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct sp_chunk *chunk;
    struct sp_ctx *ctx = in_context;
    (void) config;

    mk_list_foreach_safe(head, tmp, &ctx->chunks) {
        chunk = mk_list_entry(head, struct sp_chunk, _head);
        flb_input_log_append(in,
                                   ctx->tag, flb_sds_len(ctx->tag),
                                   chunk->buf_data, chunk->buf_size);
        flb_free(chunk->buf_data);
        mk_list_del(&chunk->_head);
        flb_free(chunk);
    }
    return 0;
}

/* Initialize plugin */
static int cb_sp_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int ret;
    struct sp_ctx *ctx;

    /* Create plugin instance context */
    ctx = flb_malloc(sizeof(struct sp_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;
    mk_list_init(&ctx->chunks);

    /* Register context */
    flb_input_set_context(in, ctx);

    /*
     * Configure the outgoing tag: when registering records into the Engine
     * we need to specify a Tag, if we got the default name
     * stream_processor.N, just override it using the Alias set by the
     * Stream Processor interface. Otherwise if the Tag is different use
     * that one.
     */
    if (strncmp(in->tag, "stream_processor.", 17) == 0) {
        ctx->tag = flb_sds_create(in->alias);
    }
    else {
        ctx->tag = flb_sds_create(in->tag);
    }

    /* Set our collector based on time, queue chunks every 0.5 sec */
    ret = flb_input_set_collector_time(in,
                                       cb_chunks_append,
                                       0,
                                       500000000,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector");
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

static void cb_sp_pause(void *data, struct flb_config *config)
{
    struct sp_ctx *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void cb_sp_resume(void *data, struct flb_config *config)
{
    struct sp_ctx *ctx = data;

    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int cb_sp_exit(void *data, struct flb_config *config)
{
    struct sp_ctx *ctx = data;

    /* Upon exit, put in the queue all pending chunks */
    cb_chunks_append(ctx->ins, config, ctx);
    flb_sds_destroy(ctx->tag);
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_stream_processor_plugin = {
    .name         = "stream_processor",
    .description  = "Stream Processor",
    .cb_init      = cb_sp_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_ingest    = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = cb_sp_pause,
    .cb_resume    = cb_sp_resume,
    .cb_exit      = cb_sp_exit,

    /* This plugin can only be configured and invoked by the Stream Processor */
    .flags        = FLB_INPUT_PRIVATE | FLB_INPUT_NOTAG
};
