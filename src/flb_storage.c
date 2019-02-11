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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_storage.h>

static void print_storage_info(struct flb_config *ctx, struct cio_ctx *cio)
{
    char *sync;
    char *checksum;
    struct flb_input_instance *in;

    flb_info("[storage] initializing...");

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

    flb_info("[storage] %s synchronization mode, checksum %s",
             sync, checksum);

    /* Storage input plugin */
    if (ctx->storage_input_plugin) {
        in = (struct flb_input_instance *) ctx->storage_input_plugin;
        flb_info("[storage] backlog input plugin: %s", in->name);
    }
}

static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    if (level == CIO_ERROR) {
        flb_error("[storage] %s", str);
    }
    else if (level == CIO_WARN) {
        flb_warn("[storage] %s", str);
    }
    else if (level == CIO_INFO) {
        flb_info("[storage] %s", str);
    }
    else if (level == CIO_DEBUG) {
        flb_debug("[storage] %s", str);
    }

    return 0;
}

static int storage_input_create(struct cio_ctx *cio,
                                struct flb_input_instance *in)
{
    int type;
    char *tmp;
    char *name;
    struct flb_storage_input *si;
    struct cio_stream *stream;

    /* storage config: get stream type */
    tmp = flb_input_get_property("storage.type", in);
    if (tmp) {
        if (strcasecmp(tmp, "filesystem") == 0) {
            type = CIO_STORE_FS;
        }
        else if (strcasecmp(tmp, "memory") == 0) {
            type = CIO_STORE_MEM;
        }
        else {
            flb_error("[storage] invalid type '%s' on instance %s",
                      tmp, flb_input_name(in));;
            return -1;
        }
    }
    else {
        type = CIO_STORE_MEM;
    }

    if (type == CIO_STORE_FS && cio->root_path == NULL) {
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
    stream = cio_stream_create(cio, name, type);
    if (!stream) {
        flb_error("[storage] cannot create stream for instance %s",
                  name);
        flb_free(si);
        return -1;
    }

    si->stream = stream;
    si->cio = cio;

    in->storage = si;

    return 0;
}

void flb_storage_input_destroy(struct flb_input_instance *in)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_input_chunk *ic;

    /* Save current temporal data and destroy chunk references */
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
        ret = storage_input_create(config->cio, in);
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
    cio = cio_create(ctx->storage_path, log_cb, CIO_DEBUG, flags);
    if (!cio) {
        flb_error("[storage] error initializing storage engine");
        return -1;
    }
    ctx->cio = cio;

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
    cio_destroy(cio);

    if (ctx->storage_bl_mem_limit) {
        flb_free(ctx->storage_bl_mem_limit);
    }

    /* Delete references from input instances */
    storage_contexts_destroy(ctx);
    ctx->cio = NULL;
}
