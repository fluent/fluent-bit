/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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
#include <stdlib.h>
#include <string.h>

#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_os.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_scan.h>

#include <monkey/mk_core/mk_list.h>

/*
 * Validate if root_path exists, if don't, create it, otherwise
 * check if we have write access to it.
 */
static int check_root_path(struct cio_ctx *ctx, const char *root_path)
{
    int ret;

    ret = cio_os_isdir(root_path);
    if (ret == -1) {
        /* Try to create the path */
        ret = cio_os_mkpath(root_path, 0755);
        if (ret == -1) {
            return -1;
        }
        cio_log_info(ctx, "created root path %s", root_path);
        return 0;
    }

    /* Directory already exists, check write access */
    return access(root_path, W_OK);
}

struct cio_ctx *cio_create(const char *root_path,
                           void (*log_cb), int log_level, int flags)
{
    int ret;
    struct cio_ctx *ctx;

    if (log_level < CIO_ERROR || log_level > CIO_DEBUG) {
        fprintf(stderr, "[cio] invalid log level, aborting");
        return NULL;
    }
#ifndef CIO_HAVE_BACKEND_FILESYSTEM
    if (root_path) {
        fprintf(stderr, "[cio] file system backend not supported\n");
        return NULL;
    }
#endif

    cio_page_size = getpagesize();

    /* Create context */
    ctx = calloc(1, sizeof(struct cio_ctx));
    if (!ctx) {
        perror("calloc");
        return NULL;
    }
    cio_set_log_callback(ctx, log_cb);
    cio_set_log_level(ctx, log_level);
    mk_list_init(&ctx->streams);

    ctx->flags = flags;

    /* Check or initialize file system root path */
    if (root_path) {
        ret = check_root_path(ctx, root_path);
        if (ret == -1) {
            cio_log_error(ctx,
                          "[chunkio] cannot initialize root path %s\n",
                          root_path);
            free(ctx);
            return NULL;
        }

        ctx->root_path = strdup(root_path);
    }
    else {
        ctx->root_path = NULL;
    }

    if (ctx->root_path) {
        cio_scan_streams(ctx);
    }

    return ctx;
}

void cio_destroy(struct cio_ctx *ctx)
{
    cio_stream_destroy_all(ctx);
    free(ctx->root_path);
    free(ctx);
}

void cio_set_log_callback(struct cio_ctx *ctx, void (*log_cb))
{
    ctx->log_cb = log_cb;
}

int cio_set_log_level(struct cio_ctx *ctx, int level)
{
    if (level < CIO_ERROR || level > CIO_DEBUG) {
        return -1;
    }

    ctx->log_level = level;
    return 0;
}
