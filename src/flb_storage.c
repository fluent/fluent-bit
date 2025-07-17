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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_server.h>
#include <limits.h>

static struct cmt *metrics_context_create(struct flb_storage_metrics *sm)
{
    struct cmt *cmt;

    cmt = cmt_create();
    if (!cmt) {
        return NULL;
    }

    sm->cmt_chunks = cmt_gauge_create(cmt,
                                      "fluentbit", "storage", "chunks",
                                      "Total number of chunks in the storage layer.",
                                      0, (char *[]) { NULL });

    sm->cmt_mem_chunks = cmt_gauge_create(cmt,
                                          "fluentbit", "storage", "mem_chunks",
                                          "Total number of memory chunks.",
                                          0, (char *[]) { NULL });

    sm->cmt_fs_chunks = cmt_gauge_create(cmt,
                                         "fluentbit", "storage", "fs_chunks",
                                         "Total number of filesystem chunks.",
                                         0, (char *[]) { NULL });

    sm->cmt_fs_chunks_up = cmt_gauge_create(cmt,
                                            "fluentbit", "storage", "fs_chunks_up",
                                            "Total number of filesystem chunks up in memory.",
                                            0, (char *[]) { NULL });

    sm->cmt_fs_chunks_down = cmt_gauge_create(cmt,
                                              "fluentbit", "storage", "fs_chunks_down",
                                              "Total number of filesystem chunks down.",
                                              0, (char *[]) { NULL });

    return cmt;
}


/* This function collect the 'global' metrics of the storage layer (cmetrics) */
int flb_storage_metrics_update(struct flb_config *ctx, struct flb_storage_metrics *sm)
{
    uint64_t ts;
    struct cio_stats st;

    /* Retrieve general stats from the storage layer */
    cio_stats_get(ctx->cio, &st);

    ts = cfl_time_now();

    cmt_gauge_set(sm->cmt_chunks, ts, st.chunks_total, 0, NULL);
    cmt_gauge_set(sm->cmt_mem_chunks, ts, st.chunks_mem, 0, NULL);
    cmt_gauge_set(sm->cmt_fs_chunks, ts, st.chunks_fs, 0, NULL);
    cmt_gauge_set(sm->cmt_fs_chunks_up, ts, st.chunks_fs_up, 0, NULL);
    cmt_gauge_set(sm->cmt_fs_chunks_down, ts, st.chunks_fs_down, 0, NULL);

    return 0;
}

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
    uint64_t ts;
    const char *tmp;
    char buf[32];
    ssize_t size;
    size_t total_chunks;

    /* chunks */
    int up;
    int down;
    int busy;
    char *name;
    ssize_t busy_size;
    struct mk_list *head;
    struct mk_list *h_chunks;
    struct flb_input_instance *i;
    struct flb_input_chunk *ic;

    /*
     * DISCLAIMER: This interface will be deprecated once we extend Chunk I/O
     * stats per stream.
     *
     * For now and to avoid duplication of iterating chunks we are adding the
     * metrics counting for CMetrics inside the same logic for the old code.
     */

    msgpack_pack_str(mp_pck, 12);
    msgpack_pack_str_body(mp_pck, "input_chunks", 12);
    msgpack_pack_map(mp_pck, mk_list_size(&ctx->inputs));

    /* current time */
    ts = cfl_time_now();

    /* Input Plugins Ingestion */
    mk_list_foreach(head, &ctx->inputs) {
        i = mk_list_entry(head, struct flb_input_instance, _head);

        name = (char *) flb_input_name(i);
        total_chunks = mk_list_size(&i->chunks);

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


        /* CMetrics */
        ret = FLB_FALSE;
        if (i->mem_buf_limit > 0) {
            if (i->mem_chunks_size >= i->mem_buf_limit) {
                ret = FLB_TRUE;
            }
        }
        if (ret == FLB_TRUE) {
            /* cmetrics */
            cmt_gauge_set(i->cmt_storage_overlimit, ts, 1,
                          1, (char *[]) {name});

            /* old code */
            msgpack_pack_true(mp_pck);
        }
        else {
            /* cmetrics */
            cmt_gauge_set(i->cmt_storage_overlimit, ts, 0,
                          1, (char *[]) {name});

            /* old code */
            msgpack_pack_false(mp_pck);
        }

        /* fluentbit_storage_memory_bytes */
        cmt_gauge_set(i->cmt_storage_memory_bytes, ts, i->mem_chunks_size,
                      1, (char *[]) {name});

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

        /* cmetrics */
        cmt_gauge_set(i->cmt_storage_chunks, ts, total_chunks,
                      1, (char *[]) {name});


        /* old code */
        msgpack_pack_str(mp_pck, 6);
        msgpack_pack_str_body(mp_pck, "chunks", 6);

        /* 'chunks' has 3 keys: total, up, down, busy and busy_size */
        msgpack_pack_map(mp_pck, 5);

        /* chunks['total_chunks'] */
        msgpack_pack_str(mp_pck, 5);
        msgpack_pack_str_body(mp_pck, "total", 5);
        msgpack_pack_uint64(mp_pck, total_chunks);

        /*
         * chunks Details: chunks marked as 'busy' are 'locked' since they are in
         * a 'flush' state. No more data can be appended to a busy chunk.
         */
        busy = 0;
        busy_size = 0;

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
            }

            if (cio_chunk_is_up(ic->chunk) == CIO_TRUE) {
                up++;
            }
            else {
                down++;
            }

        }

        /* fluentbit_storage_chunks_up */
        cmt_gauge_set(i->cmt_storage_chunks_up, ts, up,
                      1, (char *[]) {name});

        /* chunks['up'] */
        msgpack_pack_str(mp_pck, 2);
        msgpack_pack_str_body(mp_pck, "up", 2);
        msgpack_pack_uint64(mp_pck, up);

        /* fluentbit_storage_chunks_down */
        cmt_gauge_set(i->cmt_storage_chunks_down, ts, down,
                      1, (char *[]) {name});

        /* chunks['down'] */
        msgpack_pack_str(mp_pck, 4);
        msgpack_pack_str_body(mp_pck, "down", 4);
        msgpack_pack_uint64(mp_pck, down);

        /* fluentbit_storage_chunks_busy */
        cmt_gauge_set(i->cmt_storage_chunks_busy, ts, busy,
                      1, (char *[]) {name});

        /* chunks['busy'] */
        msgpack_pack_str(mp_pck, 4);
        msgpack_pack_str_body(mp_pck, "busy", 4);
        msgpack_pack_uint64(mp_pck, busy);

        /* fluentbit_storage_chunks_busy_size */
        cmt_gauge_set(i->cmt_storage_chunks_busy_bytes, ts, busy_size,
                      1, (char *[]) {name});

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
    if (ctx->http_server == FLB_TRUE && ctx->storage_metrics == FLB_TRUE) {
        flb_hs_push_storage_metrics(ctx->http_ctx, mp_sbuf.data, mp_sbuf.size);
    }
#endif
    msgpack_sbuffer_destroy(&mp_sbuf);
}

struct flb_storage_metrics *flb_storage_metrics_create(struct flb_config *ctx)
{
    int ret;
    struct flb_storage_metrics *sm;

    sm = flb_calloc(1, sizeof(struct flb_storage_metrics));
    if (!sm) {
        flb_errno();
        return NULL;
    }
    sm->cmt = metrics_context_create(sm);
    if(!sm->cmt) {
        flb_free(sm);
        return NULL;
    }

    ret = flb_sched_timer_cb_create(ctx->sched, FLB_SCHED_TIMER_CB_PERM, 5000,
                                    cb_storage_metrics_collect,
                                    ctx->storage_metrics_ctx, NULL);
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
    char *type;
    char *sync;
    char *checksum;
    struct flb_input_instance *in;

    if (cio->options.root_path) {
        type = "memory+filesystem";
    }
    else {
        type = "memory";
    }

    if (cio->options.flags & CIO_FULL_SYNC) {
        sync = "full";
    }
    else {
        sync = "normal";
    }

    if (cio->options.flags & CIO_CHECKSUM) {
        checksum = "on";
    }
    else {
        checksum = "off";
    }

    flb_info("[storage] ver=%s, type=%s, sync=%s, checksum=%s, max_chunks_up=%i",
             cio_version(), type, sync, checksum, ctx->storage_max_chunks_up);

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
    int cio_storage_type;
    struct flb_storage_input *si;
    struct cio_stream *stream;

    /* storage config: get stream type */
    if (in->storage_type == -1) {
        /* Check if storage inheritance is enabled and configured */
        if (in->config->storage_inherit == FLB_TRUE && in->config->storage_type != NULL) {
            if (strcasecmp(in->config->storage_type, "filesystem") == 0) {
                in->storage_type = FLB_STORAGE_FS;
            }
            else if (strcasecmp(in->config->storage_type, "memory") == 0) {
                in->storage_type = FLB_STORAGE_MEM;
            }
            else if (strcasecmp(in->config->storage_type, "memrb") == 0) {
                in->storage_type = FLB_STORAGE_MEMRB;
            }
            else {
                /* Invalid global storage type, fall back to default */
                flb_warn("[storage] input '%s': invalid global storage type '%s', using default 'memory'",
                         flb_input_name(in), in->config->storage_type);
                in->storage_type = FLB_STORAGE_MEM;
            }
        }
        else if (in->config->storage_inherit == FLB_TRUE && in->config->storage_type == NULL) {
            /* Storage inheritance enabled but no global storage type configured */
            flb_warn("[storage] input '%s': storage inheritance enabled but no global storage type configured, using default 'memory'",
                     flb_input_name(in));
            in->storage_type = FLB_STORAGE_MEM;
        }
        else {
            /* Use default storage type */
            in->storage_type = FLB_STORAGE_MEM;
        }
    }

    if (in->storage_type == FLB_STORAGE_FS && cio->options.root_path == NULL) {
        flb_error("[storage] instance '%s' requested filesystem storage "
                  "but no filesystem path was defined.",
                  flb_input_name(in));
        return -1;
    }

    /*
     * The input instance can define it owns storage type which is based on some
     * specific Chunk I/O storage type. We handle the proper initialization here.
     */
    cio_storage_type = in->storage_type;
    if (in->storage_type == FLB_STORAGE_MEMRB) {
        cio_storage_type = FLB_STORAGE_MEM;
    }

    /* Check for duplicates */
    stream = cio_stream_get(cio, in->name);
    if (!stream) {
        /* create stream for input instance */
        stream = cio_stream_create(cio, in->name, cio_storage_type);
        if (!stream) {
            flb_error("[storage] cannot create stream for instance %s",
                      in->name);
            return -1;
        }
    }
    else if (stream->type != cio_storage_type) {
        flb_debug("[storage] storage type mismatch. input type=%s",
                  flb_storage_get_type(in->storage_type));
        if (stream->type == FLB_STORAGE_FS) {
            flb_warn("[storage] Need to remove '%s/%s' if it is empty", cio->options.root_path, in->name);
        }

        cio_stream_destroy(stream);
        stream = cio_stream_create(cio, in->name, cio_storage_type);
        if (!stream) {
            flb_error("[storage] cannot create stream for instance %s",
                      in->name);
            return -1;
        }
        flb_info("[storage] re-create stream type=%s", flb_storage_get_type(in->storage_type));
    }

    /* allocate storage context for the input instance */
    si = flb_malloc(sizeof(struct flb_storage_input));
    if (!si) {
        flb_errno();
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

int flb_storage_create(struct flb_config *ctx)
{
    int ret;
    int flags;
    struct flb_input_instance *in = NULL;
    struct cio_ctx *cio;
    struct cio_options opts = {0};

    /* always use read/write mode */
    flags = CIO_OPEN;

    /* if explicitly stated any irrecoverably corrupted
     * chunks will be deleted */
    if (ctx->storage_del_bad_chunks) {
        flags |= CIO_DELETE_IRRECOVERABLE;
    }

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

    /* file trimming */
    if (ctx->storage_trim_files == FLB_TRUE) {
        flags |= CIO_TRIM_FILES;
    }

    /* chunkio options */
    cio_options_init(&opts);

    opts.root_path = ctx->storage_path;
    opts.flags = flags;
    opts.log_cb = log_cb;
    opts.log_level = CIO_LOG_INFO;

    /* Create chunkio context */
    cio = cio_create(&opts);
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

void flb_storage_chunk_count(struct flb_config *ctx, int *mem_chunks, int *fs_chunks)
{
    struct cio_stats storage_st;

    cio_stats_get(ctx->cio, &storage_st);

    *mem_chunks = storage_st.chunks_mem;
    *fs_chunks = storage_st.chunks_fs;
}

void flb_storage_destroy(struct flb_config *ctx)
{
    struct cio_ctx *cio;
    struct flb_storage_metrics *sm;

    /* Destroy Chunk I/O context */
    cio = (struct cio_ctx *) ctx->cio;

    if (!cio) {
        return;
    }

    sm = ctx->storage_metrics_ctx;
    if (ctx->storage_metrics == FLB_TRUE && sm != NULL) {
        cmt_destroy(sm->cmt);
        flb_free(sm);
        ctx->storage_metrics_ctx = NULL;
    }

    cio_destroy(cio);
    ctx->cio = NULL;
}
