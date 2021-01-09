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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_server.h>

static void metrics_append_general(msgpack_packer *mp_pck,
                                   struct flb_config *ctx,
                                   struct flb_storage_metrics *sm)
{
    struct cio_stats storage_st;

    /* Retrieve general stats from the storage layer */
    cio_stats_get(ctx->cio, &storage_st);

    msgpack_pack_str(mp_pck, 13);
    msgpack_pack_str_body(mp_pck, "storage_layer", 13);
    msgpack_pack_map(mp_pck, 1);

    /* Chunks */
    msgpack_pack_str(mp_pck, 6);
    msgpack_pack_str_body(mp_pck, "chunks", 6);
    msgpack_pack_map(mp_pck, 5);

    /* chunks['total_chunks'] */
    msgpack_pack_str(mp_pck, 12);
    msgpack_pack_str_body(mp_pck, "total_chunks", 12);
    msgpack_pack_uint64(mp_pck, storage_st.chunks_total);

    /* chunks['mem_chunks'] */
    msgpack_pack_str(mp_pck, 10);
    msgpack_pack_str_body(mp_pck, "mem_chunks", 10);
    msgpack_pack_uint64(mp_pck, storage_st.chunks_mem);

    /* chunks['fs_chunks'] */
    msgpack_pack_str(mp_pck, 9);
    msgpack_pack_str_body(mp_pck, "fs_chunks", 9);
    msgpack_pack_uint64(mp_pck, storage_st.chunks_fs);

    /* chunks['fs_up_chunks'] */
    msgpack_pack_str(mp_pck, 12);
    msgpack_pack_str_body(mp_pck, "fs_chunks_up", 12);
    msgpack_pack_uint64(mp_pck, storage_st.chunks_fs_up);

    /* chunks['fs_down_chunks'] */
    msgpack_pack_str(mp_pck, 14);
    msgpack_pack_str_body(mp_pck, "fs_chunks_down", 14);
    msgpack_pack_uint64(mp_pck, storage_st.chunks_fs_down);
}

static void metrics_append_input(msgpack_packer *mp_pck,
                                 struct flb_config *ctx,
                                 struct flb_storage_metrics *sm)
{
    int len;
    int ret;
    const char *tmp;
    char buf[32];
    ssize_t size;

    /* chunks */
    int up;
    int down;
    int busy;
    int busy_size_err;
    ssize_t busy_size;
    struct mk_list *head;
    struct mk_list *h_chunks;
    struct flb_input_instance *i;
    struct flb_input_chunk *ic;

    msgpack_pack_str(mp_pck, 12);
    msgpack_pack_str_body(mp_pck, "input_chunks", 12);
    msgpack_pack_map(mp_pck, mk_list_size(&ctx->inputs));

    /* Input Plugins Ingestion */
    mk_list_foreach(head, &ctx->inputs) {
        i = mk_list_entry(head, struct flb_input_instance, _head);

        tmp = flb_input_name(i);
        len = strlen(tmp);

        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, tmp, len);

        /* Map for 'status' and 'chunks' */
        msgpack_pack_map(mp_pck, 2);

        /*
         * Status
         * ======
         */
        msgpack_pack_str(mp_pck, 6);
        msgpack_pack_str_body(mp_pck, "status", 6);

        /* 'status' map has 2 keys: overlimit and chunks */
        msgpack_pack_map(mp_pck, 3);

        /* status['overlimit'] */
        msgpack_pack_str(mp_pck, 9);
        msgpack_pack_str_body(mp_pck, "overlimit", 9);

        ret = FLB_FALSE;
        if (i->mem_buf_limit > 0) {
            if (i->mem_chunks_size >= i->mem_buf_limit) {
                ret = FLB_TRUE;
            }
        }
        if (ret == FLB_TRUE) {
            msgpack_pack_true(mp_pck);
        }
        else {
            msgpack_pack_false(mp_pck);
        }

        /* status['mem_size'] */
        msgpack_pack_str(mp_pck, 8);
        msgpack_pack_str_body(mp_pck, "mem_size", 8);

        /* Current memory size used based on last ingestion */
        flb_utils_bytes_to_human_readable_size(i->mem_chunks_size,
                                               buf, sizeof(buf) - 1);
        len = strlen(buf);
        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, buf, len);

        /* status['mem_limit'] */
        msgpack_pack_str(mp_pck, 9);
        msgpack_pack_str_body(mp_pck, "mem_limit", 9);

        flb_utils_bytes_to_human_readable_size(i->mem_buf_limit,
                                               buf, sizeof(buf) - 1);
        len = strlen(buf);
        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, buf, len);

        /*
         * Chunks
         * ======
         */
        msgpack_pack_str(mp_pck, 6);
        msgpack_pack_str_body(mp_pck, "chunks", 6);

        /* 'chunks' has 3 keys: total, up, down, busy and busy_size */
        msgpack_pack_map(mp_pck, 5);

        /* chunks['total_chunks'] */
        msgpack_pack_str(mp_pck, 5);
        msgpack_pack_str_body(mp_pck, "total", 5);
        msgpack_pack_uint64(mp_pck, mk_list_size(&i->chunks));

        /*
         * chunks Details: chunks marked as 'busy' are 'locked' since they are in
         * a 'flush' state. No more data can be appended to a busy chunk.
         */
        busy = 0;
        busy_size = 0;
        busy_size_err = 0;

        /* up/down */
        up = 0;
        down = 0;

        /* Iterate chunks for the input instance in question */
        mk_list_foreach(h_chunks, &i->chunks) {
            ic = mk_list_entry(h_chunks, struct flb_input_chunk, _head);
            if (ic->busy == FLB_TRUE) {
                busy++;
                size = cio_chunk_get_content_size(ic->chunk);
                if (size >= 0) {
                    busy_size += size;
                }
                else {
                    busy_size_err++;
                }
            }

            if (cio_chunk_is_up(ic->chunk) == CIO_TRUE) {
                up++;
            }
            else {
                down++;
            }

        }

        /* chunks['up'] */
        msgpack_pack_str(mp_pck, 2);
        msgpack_pack_str_body(mp_pck, "up", 2);
        msgpack_pack_uint64(mp_pck, up);

        /* chunks['down'] */
        msgpack_pack_str(mp_pck, 4);
        msgpack_pack_str_body(mp_pck, "down", 4);
        msgpack_pack_uint64(mp_pck, down);

        /* chunks['busy'] */
        msgpack_pack_str(mp_pck, 4);
        msgpack_pack_str_body(mp_pck, "busy", 4);
        msgpack_pack_uint64(mp_pck, busy);

        /* chunks['busy_size'] */
        msgpack_pack_str(mp_pck, 9);
        msgpack_pack_str_body(mp_pck, "busy_size", 9);

        flb_utils_bytes_to_human_readable_size(busy_size, buf, sizeof(buf) - 1);
        len = strlen(buf);
        msgpack_pack_str(mp_pck, len);
        msgpack_pack_str_body(mp_pck, buf, len);
    }
}

static void cb_storage_metrics_collect(struct flb_config *ctx, void *data)
{
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    /* Prepare new outgoing buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Pack main map and append relevant data */
    msgpack_pack_map(&mp_pck, 2);
    metrics_append_general(&mp_pck, ctx, data);
    metrics_append_input(&mp_pck, ctx, data);

#ifdef FLB_HAVE_HTTP_SERVER
    if (ctx->http_server == FLB_TRUE) {
        flb_hs_push_storage_metrics(ctx->http_ctx, mp_sbuf.data, mp_sbuf.size);
    }
#endif
    msgpack_sbuffer_destroy(&mp_sbuf);
}

struct flb_storage_metrics *flb_storage_metrics_create(struct flb_config *ctx)
{
    int ret;
    struct flb_storage_metrics *sm;

    sm = flb_malloc(sizeof(struct flb_storage_metrics));
    if (!sm) {
        flb_errno();
        return NULL;
    }

    ret = flb_sched_timer_cb_create(ctx->sched, FLB_SCHED_TIMER_CB_PERM, 5000,
                                    cb_storage_metrics_collect,
                                    ctx->storage_metrics_ctx);
    if (ret == -1) {
        flb_error("[storage metrics] cannot create timer to collect metrics");
        flb_free(sm);
        return NULL;
    }

    return sm;
}

static int sort_chunk_cmp(const void *a_arg, const void *b_arg)
{
    char *p;
    struct cio_chunk *chunk_a = *(struct cio_chunk **) a_arg;
    struct cio_chunk *chunk_b = *(struct cio_chunk **) b_arg;
    struct timespec tm_a;
    struct timespec tm_b;

    /* Scan Chunk A */
    p = strchr(chunk_a->name, '-');
    if (!p) {
        return -1;
    }
    p++;

    sscanf(p, "%lu.%lu.flb", &tm_a.tv_sec, &tm_a.tv_nsec);

    /* Scan Chunk B */
    p = strchr(chunk_b->name, '-');
    if (!p) {
        return -1;
    }
    p++;
    sscanf(p, "%lu.%lu.flb", &tm_b.tv_sec, &tm_b.tv_nsec);

    /* Compare */
    if (tm_a.tv_sec != tm_b.tv_sec) {
        if (tm_a.tv_sec > tm_b.tv_sec) {
            return 1;
        }
        else {
            return -1;
        }
    }
    else {
        if (tm_a.tv_nsec > tm_b.tv_nsec) {
            return 1;
        }
        else if (tm_a.tv_nsec < tm_b.tv_nsec) {
            return -1;
        }
    }

    return 0;
}

static void print_storage_info(struct flb_config *ctx, struct cio_ctx *cio)
{
    char *sync;
    char *checksum;
    struct flb_input_instance *in;

    flb_info("[storage] version=%s, initializing...", cio_version());

    if (cio->root_path) {
        flb_info("[storage] root path '%s'", cio->root_path);
    }
    else {
        flb_info("[storage] in-memory");
    }

    if (cio->flags & CIO_FULL_SYNC) {
        sync = "full";
    }
    else {
        sync = "normal";
    }

    if (cio->flags & CIO_CHECKSUM) {
        checksum = "enabled";
    }
    else {
        checksum = "disabled";
    }

    flb_info("[storage] %s synchronization mode, checksum %s, max_chunks_up=%i",
             sync, checksum, ctx->storage_max_chunks_up);

    /* Storage input plugin */
    if (ctx->storage_input_plugin) {
        in = (struct flb_input_instance *) ctx->storage_input_plugin;
        flb_info("[storage] backlog input plugin: %s", in->name);
    }
}

static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    if (level == CIO_LOG_ERROR) {
        flb_error("[storage] %s", str);
    }
    else if (level == CIO_LOG_WARN) {
        flb_warn("[storage] %s", str);
    }
    else if (level == CIO_LOG_INFO) {
        flb_info("[storage] %s", str);
    }
    else if (level == CIO_LOG_DEBUG) {
        flb_debug("[storage] %s", str);
    }

    return 0;
}

int flb_storage_input_create(struct cio_ctx *cio,
                             struct flb_input_instance *in)
{
    const char *name;
    struct flb_storage_input *si;
    struct cio_stream *stream;

    /* storage config: get stream type */
    if (in->storage_type == -1) {
        in->storage_type = CIO_STORE_MEM;
    }

    if (in->storage_type == CIO_STORE_FS && cio->root_path == NULL) {
        flb_error("[storage] instance '%s' requested filesystem storage "
                  "but no filesystem path was defined.",
                  flb_input_name(in));
        return -1;
    }

    /* allocate storage context for the input instance */
    si = flb_malloc(sizeof(struct flb_storage_input));
    if (!si) {
        flb_errno();
        return -1;
    }

    /* get stream name */
    name = flb_input_name(in);

    /* create stream for input instance */
    stream = cio_stream_create(cio, name, in->storage_type);
    if (!stream) {
        flb_error("[storage] cannot create stream for instance %s",
                  name);
        flb_free(si);
        return -1;
    }

    si->stream = stream;
    si->cio = cio;
    si->type = in->storage_type;
    in->storage = si;

    return 0;
}

void flb_storage_input_destroy(struct flb_input_instance *in)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_chunk *ic;

    /* Save current temporary data and destroy chunk references */
    mk_list_foreach_safe(head, tmp, &in->chunks) {
        ic = mk_list_entry(head, struct flb_input_chunk, _head);
        flb_input_chunk_destroy(ic, FLB_FALSE);
    }

    flb_free(in->storage);
    in->storage = NULL;
}

static int storage_contexts_create(struct flb_config *config)
{
    int c = 0;
    int ret;
    struct mk_list *head;
    struct flb_input_instance *in;

    /* Iterate each input instance and create a stream for it */
    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        ret = flb_storage_input_create(config->cio, in);
        if (ret == -1) {
            flb_error("[storage] could not create storage for instance: %s",
                      in->name);
            return -1;
        }
        c++;
    }

    return c;
}

static void storage_contexts_destroy(struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_instance *in;

    /* Iterate each input instance and destroy the context */
    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        flb_storage_input_destroy(in);
    }
}

int flb_storage_create(struct flb_config *ctx)
{
    int ret;
    int flags;
    struct flb_input_instance *in = NULL;
    struct cio_ctx *cio;

    /* always use read/write mode */
    flags = CIO_OPEN;

    /* synchronization mode */
    if (ctx->storage_sync) {
        if (strcasecmp(ctx->storage_sync, "normal") == 0) {
            /* do nothing, keep the default */
        }
        else if (strcasecmp(ctx->storage_sync, "full") == 0) {
            flags |= CIO_FULL_SYNC;
        }
        else {
            flb_error("[storage] invalid synchronization mode");
            return -1;
        }
    }

    /* checksum */
    if (ctx->storage_checksum == FLB_TRUE) {
        flags |= CIO_CHECKSUM;
    }

    /* Create chunkio context */
    cio = cio_create(ctx->storage_path, log_cb, CIO_LOG_DEBUG, flags);
    if (!cio) {
        flb_error("[storage] error initializing storage engine");
        return -1;
    }
    ctx->cio = cio;

    /* Set Chunk I/O maximum number of chunks up */
    if (ctx->storage_max_chunks_up == 0) {
        ctx->storage_max_chunks_up = FLB_STORAGE_MAX_CHUNKS_UP;
    }
    cio_set_max_chunks_up(ctx->cio, ctx->storage_max_chunks_up);

    /* Load content from the file system if any */
    ret = cio_load(ctx->cio, NULL);
    if (ret == -1) {
        flb_error("[storage] error scanning root path content: %s",
                  ctx->storage_path);
        cio_destroy(ctx->cio);
        return -1;
    }

    /* Sort chunks */
    cio_qsort(ctx->cio, sort_chunk_cmp);

    /*
     * If we have a filesystem storage path, create an instance of the
     * storage_backlog input plugin to consume any possible pending
     * chunks.
     */
    if (ctx->storage_path) {
        in = flb_input_new(ctx, "storage_backlog", cio, FLB_FALSE);
        if (!in) {
            flb_error("[storage] cannot init storage backlog input plugin");
            cio_destroy(cio);
            ctx->cio = NULL;
            return -1;
        }
        ctx->storage_input_plugin = in;

        /* Set a queue memory limit */
        if (!ctx->storage_bl_mem_limit) {
            ctx->storage_bl_mem_limit = flb_strdup(FLB_STORAGE_BL_MEM_LIMIT);
        }
    }

    /* Create streams for input instances */
    ret = storage_contexts_create(ctx);
    if (ret == -1) {
        return -1;
    }

    /* print storage info */
    print_storage_info(ctx, cio);

    return 0;
}

void flb_storage_destroy(struct flb_config *ctx)
{
    struct cio_ctx *cio;

    /* Destroy Chunk I/O context */
    cio = (struct cio_ctx *) ctx->cio;

    if (!cio) {
        return;
    }

    if (ctx->storage_metrics == FLB_TRUE &&
        ctx->storage_metrics_ctx != NULL) {
        flb_free(ctx->storage_metrics_ctx);
    }

    cio_destroy(cio);

    /* Delete references from input instances */
    storage_contexts_destroy(ctx);
    ctx->cio = NULL;
}
