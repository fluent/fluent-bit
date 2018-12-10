/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_storage.h>

struct sb_chunk {
    struct cio_chunk *chunk;
    struct cio_stream *stream;
    struct mk_list _head;               /* link to backlog list */
};

struct flb_sb {
    int coll_fd;                        /* collector id */
    struct flb_input_instance *i_ins;   /* input instance */
    struct cio_ctx *cio;                /* chunk i/o instance */
    struct mk_list backlog;             /* list of all pending chunks */
};

/* cb_collect callback */
static int cb_queue_chunks(struct flb_input_instance *in,
                           struct flb_config *config, void *data)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct sb_chunk *sbc;
    struct flb_sb *sb;

    sb = data;
    mk_list_foreach_safe(head, tmp, &sb->backlog) {
        sbc = mk_list_entry(head, struct sb_chunk, _head);
    }

    return 0;
}

/* Append a chunk candidate to the list */
static int sb_append_chunk(struct cio_chunk *chunk, struct cio_stream *stream,
                           struct flb_sb *sb)
{
    struct sb_chunk *sbc;

    sbc = flb_malloc(sizeof(struct sb_chunk));
    if (!sbc) {
        flb_errno();
        return -1;
    }

    sbc->chunk = chunk;
    sbc->stream = stream;
    mk_list_add(&sbc->_head, &sb->backlog);

    /* lock the chunk */
    cio_chunk_lock(chunk);
    flb_info("[storage_backlog] enqueued %s/%s", stream->name, chunk->name);

    return 0;
}

static int sb_prepare_environment(struct flb_sb *sb)
{
    int ret;
    struct mk_list *head;
    struct mk_list *c_head;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct cio_ctx *cio;

    cio = sb->cio;
    mk_list_foreach(head, &cio->streams) {
        stream = mk_list_entry(head, struct cio_stream, _head);
        mk_list_foreach(c_head, &stream->files) {
            chunk = mk_list_entry(c_head, struct cio_chunk, _head);
            ret = sb_append_chunk(chunk, stream, sb);
            if (ret == -1) {
                flb_error("[storage_backlog] could not enqueue %s/%s",
                          stream->name, chunk->name);
                continue;
            }
        }
    }

    return 0;
}

/* Initialize plugin */
static int cb_sb_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int ret;
    struct flb_sb *sb;

    sb = flb_malloc(sizeof(struct flb_sb));
    if (!sb) {
        flb_errno();
        return -1;
    }

    sb->cio = data;
    sb->i_ins = in;
    mk_list_init(&sb->backlog);

    /* export plugin context */
    flb_input_set_context(in, sb);

    /* Set a collector to trigger the callback to queue data every second */
    ret = flb_input_set_collector_time(in, cb_queue_chunks, 1, 0, config);
    if (ret < 0) {
        flb_error("[storage_backlog] could not create collector");
        flb_free(sb);
        return -1;
    }
    sb->coll_fd = ret;

    /* Based on discovered chunks, create a local reference list */
    sb_prepare_environment(sb);

    return 0;
}

static void cb_sb_pause(void *data, struct flb_config *config)
{
    struct flb_sb *sb = data;
    flb_input_collector_pause(sb->coll_fd, sb->i_ins);
}

static void cb_sb_resume(void *data, struct flb_config *config)
{
    struct flb_sb *sb = data;
    flb_input_collector_resume(sb->coll_fd, sb->i_ins);
}

static int cb_sb_exit(void *data, struct flb_config *config)
{
    struct flb_sb *sb = data;

    flb_free(sb);
    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_storage_backlog_plugin = {
    .name         = "storage_backlog",
    .description  = "Storage Backlog",
    .cb_init      = cb_sb_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_ingest    = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = cb_sb_pause,
    .cb_resume    = cb_sb_resume,
    .cb_exit      = cb_sb_exit,

    /* This plugin can only be configured and invoked by the Engine */
    .flags        = FLB_INPUT_PRIVATE
};
