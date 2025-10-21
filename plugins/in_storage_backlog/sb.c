/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_utils.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_error.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifndef FLB_SYSTEM_WINDOWS
#include <unistd.h>
#endif

struct sb_out_chunk {
    struct cio_chunk  *chunk;
    struct cio_stream *stream;
    size_t             size;
    struct mk_list    _head;
};

struct sb_out_queue {
    struct flb_output_instance *ins;
    struct mk_list              chunks; /* head for every sb_out_chunk */
    struct mk_list              _head;
};

struct flb_sb {
    int coll_fd;                    /* collector id */
    size_t mem_limit;               /* memory limit */
    struct flb_input_instance *ins; /* input instance */
    struct cio_ctx *cio;            /* chunk i/o instance */
    struct mk_list backlogs;        /* list of all pending chunks segregated by output plugin */
    flb_route_mask_element *dummy_routes_mask; /* dummy route mask used when segregating events */
};


static inline struct flb_sb *sb_get_context(struct flb_config *config);

static struct sb_out_chunk *sb_allocate_chunk(struct cio_chunk *chunk,
                                              struct cio_stream *stream,
                                              size_t size);

static void sb_destroy_chunk(struct sb_out_chunk *chunk);

static void sb_destroy_backlog(struct sb_out_queue *backlog, struct flb_sb *context);

static int  sb_allocate_backlogs(struct flb_sb *ctx);

static void sb_destroy_backlogs(struct flb_sb *ctx);

static struct sb_out_queue *sb_find_segregated_backlog_by_output_plugin_instance(
                                struct flb_output_instance *output_plugin,
                                struct flb_sb              *context);

static void sb_remove_chunk_from_segregated_backlog(struct cio_chunk    *target_chunk,
                                                    struct sb_out_queue *backlog,
                                                    int                  destroy);

static void sb_remove_chunk_from_segregated_backlogs(struct cio_chunk *chunk,
                                                     struct flb_sb    *context);

static int sb_append_chunk_to_segregated_backlog(struct cio_chunk    *target_chunk,
                                                 struct cio_stream   *stream,
                                                 size_t               target_chunk_size,
                                                 struct sb_out_queue *backlog);

static int sb_append_chunk_to_segregated_backlogs(struct cio_chunk  *target_chunk,
                                                  struct cio_stream *stream,
                                                  struct flb_sb     *context);

int sb_segregate_chunks(struct flb_config *config);

int sb_release_output_queue_space(struct flb_output_instance *output_plugin,
                                  ssize_t                    *required_space);

ssize_t sb_get_releasable_output_queue_space(struct flb_output_instance *output_plugin,
                                             size_t                      required_space);


static inline struct flb_sb *sb_get_context(struct flb_config *config)
{
    if (config == NULL) {
        return NULL;
    }

    if (config->storage_input_plugin == NULL) {
        return NULL;
    }

    return ((struct flb_input_instance *) config->storage_input_plugin)->context;
}

static struct sb_out_chunk *sb_allocate_chunk(struct cio_chunk *chunk,
                                              struct cio_stream *stream,
                                              size_t size)
{
    struct sb_out_chunk *result;

    result = (struct sb_out_chunk *) flb_calloc(1, sizeof(struct sb_out_chunk));

    if (result != NULL) {
        result->chunk  = chunk;
        result->stream = stream;
        result->size   = size;
    }

    return result;
}

static void sb_destroy_chunk(struct sb_out_chunk *chunk)
{
    flb_free(chunk);
}

static void sb_destroy_backlog(struct sb_out_queue *backlog, struct flb_sb *context)
{
    struct mk_list      *chunk_iterator_tmp;
    struct mk_list      *chunk_iterator;
    struct sb_out_chunk *chunk;

    mk_list_foreach_safe(chunk_iterator, chunk_iterator_tmp, &backlog->chunks) {
        chunk = mk_list_entry(chunk_iterator, struct sb_out_chunk, _head);

        sb_remove_chunk_from_segregated_backlogs(chunk->chunk, context);
    }
}

static int sb_allocate_backlogs(struct flb_sb *context)
{
    struct mk_list             *output_plugin_iterator;
    struct flb_output_instance *output_plugin;
    struct sb_out_queue        *backlog;

    mk_list_foreach(output_plugin_iterator, &context->ins->config->outputs) {
        output_plugin = mk_list_entry(output_plugin_iterator,
                                      struct flb_output_instance,
                                      _head);

        backlog = (struct sb_out_queue *) \
                        flb_calloc(1, sizeof(struct sb_out_queue));

        if (backlog == NULL) {
            sb_destroy_backlogs(context);

            return -1;
        }

        backlog->ins = output_plugin;

        mk_list_init(&backlog->chunks);

        mk_list_add(&backlog->_head, &context->backlogs);
    }

    return 0;
}

static void sb_destroy_backlogs(struct flb_sb *context)
{
    struct mk_list      *backlog_iterator_tmp;
    struct mk_list      *backlog_iterator;
    struct sb_out_queue *backlog;

    mk_list_foreach_safe(backlog_iterator, backlog_iterator_tmp, &context->backlogs) {
        backlog = mk_list_entry(backlog_iterator, struct sb_out_queue, _head);

        mk_list_del(&backlog->_head);

        sb_destroy_backlog(backlog, context);

        flb_free(backlog);
    }
}

static struct sb_out_queue *sb_find_segregated_backlog_by_output_plugin_instance(
                                struct flb_output_instance *output_plugin,
                                struct flb_sb              *context)
{
    struct mk_list      *backlog_iterator;
    struct sb_out_queue *backlog;

    mk_list_foreach(backlog_iterator, &context->backlogs) {
        backlog = mk_list_entry(backlog_iterator, struct sb_out_queue, _head);

        if (output_plugin == backlog->ins) {
            return backlog;
        }
    }

    return NULL;
}

static void sb_remove_chunk_from_segregated_backlog(struct cio_chunk    *target_chunk,
                                                    struct sb_out_queue *backlog,
                                                    int                  destroy)
{
    struct mk_list      *chunk_iterator_tmp;
    struct mk_list      *chunk_iterator;
    struct sb_out_chunk *chunk;

    mk_list_foreach_safe(chunk_iterator, chunk_iterator_tmp, &backlog->chunks) {
        chunk = mk_list_entry(chunk_iterator, struct sb_out_chunk, _head);

        if (chunk->chunk == target_chunk) {
            mk_list_del(&chunk->_head);

            backlog->ins->fs_backlog_chunks_size -= cio_chunk_get_real_size(target_chunk);

            if (destroy) {
                sb_destroy_chunk(chunk);
            }

            break;
        }
    }
}

static void sb_remove_chunk_from_segregated_backlogs(struct cio_chunk *target_chunk,
                                                     struct flb_sb    *context)
{
    struct mk_list      *backlog_iterator;
    struct sb_out_queue *backlog;

    mk_list_foreach(backlog_iterator, &context->backlogs) {
        backlog = mk_list_entry(backlog_iterator, struct sb_out_queue, _head);

        sb_remove_chunk_from_segregated_backlog(target_chunk, backlog, FLB_TRUE);
    }
}

static int sb_append_chunk_to_segregated_backlog(struct cio_chunk    *target_chunk,
                                                 struct cio_stream   *stream,
                                                 size_t               target_chunk_size,
                                                 struct sb_out_queue *backlog)
{
    struct sb_out_chunk *chunk;

    chunk = sb_allocate_chunk(target_chunk, stream, target_chunk_size);
    if (chunk == NULL) {
        flb_errno();
        return -1;
    }

    mk_list_add(&chunk->_head, &backlog->chunks);

    backlog->ins->fs_backlog_chunks_size += target_chunk_size;

    return 0;
}

static int sb_append_chunk_to_segregated_backlogs(struct cio_chunk  *target_chunk,
                                                  struct cio_stream *stream,
                                                  struct flb_sb     *context)
{
    struct flb_input_chunk  dummy_input_chunk;
    struct mk_list         *tmp;
    struct mk_list         *head;
    size_t                  chunk_size;
    struct sb_out_queue    *backlog;
    int                     tag_len;
    const char *            tag_buf;
    int                     result;

    memset(&dummy_input_chunk, 0, sizeof(struct flb_input_chunk));

    memset(context->dummy_routes_mask,
           0,
           context->ins->config->route_mask_slots * sizeof(flb_route_mask_element));

    dummy_input_chunk.in    = context->ins;
    dummy_input_chunk.chunk = target_chunk;
    dummy_input_chunk.routes_mask = context->dummy_routes_mask;

    chunk_size = cio_chunk_get_real_size(target_chunk);

    if (chunk_size < 0) {
        flb_warn("[storage backlog] could not get real size of chunk %s/%s",
                  stream->name, target_chunk->name);

        return -1;
    }

    result = flb_input_chunk_get_tag(&dummy_input_chunk, &tag_buf, &tag_len);
    if (result == -1) {
        flb_error("[storage backlog] could not retrieve chunk tag from %s/%s, "
                  "removing it from the queue",
                  stream->name, target_chunk->name);

        return -2;
    }

    flb_routes_mask_set_by_tag(dummy_input_chunk.routes_mask, tag_buf, tag_len,
                               context->ins);

    mk_list_foreach_safe(head, tmp, &context->backlogs) {
        backlog = mk_list_entry(head, struct sb_out_queue, _head);
        if (flb_routes_mask_get_bit(dummy_input_chunk.routes_mask,
                                    backlog->ins->id,
                                    backlog->ins->config)) {
            result = sb_append_chunk_to_segregated_backlog(target_chunk, stream,
                                                           chunk_size, backlog);
            if (result) {
                return -3;
            }
        }
    }

    return 0;
}

int sb_segregate_chunks(struct flb_config *config)
{
    int                ret;
    size_t             size;
    struct mk_list    *tmp;
    struct mk_list    *stream_iterator;
    struct mk_list    *chunk_iterator;
    int                chunk_error;
    struct flb_sb     *context;
    struct cio_stream *stream;
    struct cio_chunk  *chunk;

    context = sb_get_context(config);

    if (context == NULL) {
        return 0;
    }

    ret = sb_allocate_backlogs(context);
    if (ret) {
        return -2;
    }

    mk_list_foreach(stream_iterator, &context->cio->streams) {
        stream = mk_list_entry(stream_iterator, struct cio_stream, _head);

        mk_list_foreach_safe(chunk_iterator, tmp, &stream->chunks) {
            chunk = mk_list_entry(chunk_iterator, struct cio_chunk, _head);

            if (!cio_chunk_is_up(chunk)) {
                ret = cio_chunk_up_force(chunk);
                if (ret == CIO_CORRUPTED) {
                    if (config->storage_del_bad_chunks) {
                        chunk_error = cio_error_get(chunk);

                        if (chunk_error == CIO_ERR_BAD_FILE_SIZE ||
                            chunk_error == CIO_ERR_BAD_LAYOUT)
                        {
                            flb_plg_error(context->ins, "discarding irrecoverable chunk %s/%s", stream->name, chunk->name);

                            cio_chunk_close(chunk, CIO_TRUE);
                        }
                    }

                    continue;
                }
            }

            if (!cio_chunk_is_up(chunk)) {
                return -3;
            }

            /* try to segregate a chunk */
            ret = sb_append_chunk_to_segregated_backlogs(chunk, stream, context);
            if (ret) {
                /*
                 * if the chunk could not be segregated, just remove it from the
                 * queue, delete it and continue.
                 */

                /* If the tag cannot be read it cannot be routed, let's remove it */
                if (ret == -2) {
                    cio_chunk_close(chunk, CIO_TRUE);
                    continue;
                }

                /*
                 *
                 * if content size is zero, it's safe to 'delete it'.
                 */
                size = cio_chunk_get_content_size(chunk);
                if (size <= 0) {
                    cio_chunk_close(chunk, CIO_TRUE);
                }
                else {
                    cio_chunk_close(chunk, CIO_FALSE);
                }
                continue;
            }

            /* lock the chunk */
            flb_plg_info(context->ins, "register %s/%s", stream->name, chunk->name);

            cio_chunk_lock(chunk);
            cio_chunk_down(chunk);
        }
    }

    return 0;
}

ssize_t sb_get_releasable_output_queue_space(struct flb_output_instance *output_plugin,
                                             size_t                      required_space)
{
    ssize_t              releasable_space;
    struct mk_list      *chunk_iterator;
    struct flb_sb       *context;
    struct sb_out_queue *backlog;
    struct sb_out_chunk *chunk;

    context = sb_get_context(output_plugin->config);

    if (context == NULL) {
        return 0;
    }

    backlog = sb_find_segregated_backlog_by_output_plugin_instance(
                                output_plugin, context);

    if (backlog == NULL) {
        return 0;
    }

    releasable_space = 0;

    mk_list_foreach(chunk_iterator, &backlog->chunks) {
        chunk = mk_list_entry(chunk_iterator, struct sb_out_chunk, _head);

        releasable_space += chunk->size;

        if (releasable_space >= required_space) {
            break;
        }
    }

    return releasable_space;
}

int sb_release_output_queue_space(struct flb_output_instance *output_plugin,
                                  ssize_t                    *required_space)
{
    struct mk_list      *chunk_iterator_tmp;
    struct cio_chunk    *underlying_chunk;
    struct mk_list      *chunk_iterator;
    size_t               released_space;
    struct flb_sb       *context;
    struct sb_out_queue *backlog;
    struct sb_out_chunk *chunk;

    context = sb_get_context(output_plugin->config);

    if (context == NULL) {
        return -1;
    }

    backlog = sb_find_segregated_backlog_by_output_plugin_instance(
                                                        output_plugin, context);

    if (backlog == NULL) {
        return -2;
    }

    released_space = 0;

    mk_list_foreach_safe(chunk_iterator, chunk_iterator_tmp, &backlog->chunks) {
        chunk = mk_list_entry(chunk_iterator, struct sb_out_chunk, _head);

        released_space += chunk->size;
        underlying_chunk = chunk->chunk;

        sb_remove_chunk_from_segregated_backlogs(underlying_chunk, context);
        cio_chunk_close(underlying_chunk, FLB_TRUE);

        if (released_space >= *required_space) {
            break;
        }
    }

    *required_space -= released_space;

    return 0;
}

/* Collection callback */
static int cb_queue_chunks(struct flb_input_instance *in,
                           struct flb_config *config, void *data)
{
    size_t                  empty_output_queue_count;
    struct mk_list         *output_queue_iterator;
    struct sb_out_queue    *output_queue_instance;
    struct sb_out_chunk    *chunk_instance;
    struct flb_sb          *ctx;
    struct flb_input_chunk *ic;
    struct flb_input_chunk  tmp_ic;
    void                   *ch;
    size_t                  total = 0;
    ssize_t                 size;
    int                     ret;
    int                     event_type;
    struct cio_chunk        *underlying_chunk;

    /* Get context */
    ctx = (struct flb_sb *) data;

    /* Get the total number of bytes already enqueued */
    total = flb_input_chunk_total_size(in);

    /* If we already hitted our limit, just wait and re-check later */
    if (total >= ctx->mem_limit) {
        return 0;
    }

    empty_output_queue_count = 0;

    while (total < ctx->mem_limit &&
           empty_output_queue_count < mk_list_size(&ctx->backlogs)) {
        empty_output_queue_count = 0;

        mk_list_foreach(output_queue_iterator, &ctx->backlogs) {
            output_queue_instance = mk_list_entry(output_queue_iterator,
                                                  struct sb_out_queue,
                                                  _head);

            if (mk_list_is_empty(&output_queue_instance->chunks) != 0) {
                chunk_instance = mk_list_entry_first(&output_queue_instance->chunks,
                                                     struct sb_out_chunk,
                                                     _head);

                /* Try to enqueue one chunk */
                /*
                 * All chunks on this backlog are 'file' based, always try to set
                 * them up. We validate the status.
                 */
                ret = cio_chunk_is_up(chunk_instance->chunk);

                if (ret == CIO_FALSE) {
                    ret = cio_chunk_up_force(chunk_instance->chunk);

                    if (ret == CIO_CORRUPTED) {
                        flb_plg_error(ctx->ins, "removing corrupted chunk from the "
                                      "queue %s:%s",
                                      chunk_instance->stream->name, chunk_instance->chunk->name);
                                      underlying_chunk = chunk_instance->chunk;

                        /*
                         * sb_remove_chunk_from_segregated_backlogs() releases chunk_instance,
                         * so grab the pointer first and close the chunk afterwards.
                         */
                        sb_remove_chunk_from_segregated_backlogs(underlying_chunk, ctx);
                        cio_chunk_close(underlying_chunk, FLB_FALSE);
                        continue;
                    }
                    else if (ret == CIO_ERROR || ret == CIO_RETRY) {
                        continue;
                    }
                }

                /*
                 * Map the chunk file context into a temporary buffer since the
                 * flb_input_chunk_get_event_type() interface needs an
                 * struct fb_input_chunk argument.
                 */
                tmp_ic.chunk = chunk_instance->chunk;

                /* Retrieve the event type: FLB_INPUT_LOGS, FLB_INPUT_METRICS of FLB_INPUT_TRACES */
                ret = flb_input_chunk_get_event_type(&tmp_ic);
                if (ret == -1) {
                    flb_plg_error(ctx->ins, "removing chunk with wrong metadata "
                                  "from the queue %s:%s",
                                  chunk_instance->stream->name,
                                  chunk_instance->chunk->name);
                    underlying_chunk = chunk_instance->chunk;
                    sb_remove_chunk_from_segregated_backlogs(underlying_chunk, ctx);
                    cio_chunk_close(underlying_chunk, FLB_TRUE);
                    continue;
                }
                event_type = ret;

                /* get the number of bytes being used by the chunk */
                size = cio_chunk_get_content_size(chunk_instance->chunk);
                if (size <= 0) {
                    flb_plg_error(ctx->ins, "removing empty chunk from the "
                                  "queue %s:%s",
                                  chunk_instance->stream->name, chunk_instance->chunk->name);
                    underlying_chunk = chunk_instance->chunk;
                    sb_remove_chunk_from_segregated_backlogs(underlying_chunk, ctx);
                    cio_chunk_close(underlying_chunk, FLB_TRUE);
                    continue;
                }

                ch = chunk_instance->chunk;

                /* Associate this backlog chunk to this instance into the engine */
                ic = flb_input_chunk_map(in, event_type, ch);
                if (!ic) {
                    flb_plg_error(ctx->ins, "removing chunk %s:%s from the queue",
                                  chunk_instance->stream->name, chunk_instance->chunk->name);
                    cio_chunk_down(chunk_instance->chunk);

                    /*
                     * If the file cannot be mapped, just drop it. Failures are all
                     * associated with data corruption.
                     */
                    underlying_chunk = chunk_instance->chunk;
                    sb_remove_chunk_from_segregated_backlogs(underlying_chunk, ctx);
                    cio_chunk_close(underlying_chunk, FLB_TRUE);
                    continue;
                }

                flb_plg_info(ctx->ins, "queueing %s:%s",
                             chunk_instance->stream->name, chunk_instance->chunk->name);

                /* We are removing this chunk reference from this specific backlog
                 * queue but we need to leave it in the remainder queues.
                 */
                sb_remove_chunk_from_segregated_backlogs(chunk_instance->chunk, ctx);
                cio_chunk_down(ch);

                /* check our limits */
                total += size;
            }
            else {
                empty_output_queue_count++;
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
    char mem[32];
    struct flb_sb *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_sb));

    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->dummy_routes_mask = flb_calloc(in->config->route_mask_slots,
                                        sizeof(flb_route_mask_element));

    if (ctx->dummy_routes_mask == NULL) {
        flb_errno();
        flb_free(ctx);

        flb_error("[storage backlog] could not allocate route mask elements");

        return -1;
    }

    ctx->cio = data;
    ctx->ins = in;
    ctx->mem_limit = flb_utils_size_to_bytes(config->storage_bl_mem_limit);

    mk_list_init(&ctx->backlogs);

    flb_utils_bytes_to_human_readable_size(ctx->mem_limit, mem, sizeof(mem) - 1);
    flb_plg_info(ctx->ins, "queue memory limit: %s", mem);

    /* export plugin context */
    flb_input_set_context(in, ctx);

    /* Set a collector to trigger the callback to queue data every second */
    ret = flb_input_set_collector_time(in, cb_queue_chunks, 1, 0, config);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "could not create collector");
        flb_free(ctx->dummy_routes_mask);
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

static void cb_sb_pause(void *data, struct flb_config *config)
{
    struct flb_sb *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void cb_sb_resume(void *data, struct flb_config *config)
{
    struct flb_sb *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static int cb_sb_exit(void *data, struct flb_config *config)
{
    struct flb_sb *ctx = data;

    flb_input_collector_pause(ctx->coll_fd, ctx->ins);

    sb_destroy_backlogs(ctx);

    if (ctx->dummy_routes_mask != NULL) {
        flb_free(ctx->dummy_routes_mask);
    }

    flb_free(ctx);

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
