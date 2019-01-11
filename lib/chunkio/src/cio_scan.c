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
#include <sys/types.h>

#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_memfs.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_log.h>

#ifdef CIO_HAVE_BACKEND_FILESYSTEM
static int cio_scan_stream_files(struct cio_ctx *ctx, struct cio_stream *st)
{
    int len;
    int ret;
    char *path;
    DIR *dir;
    struct dirent *ent;

    len = strlen(ctx->root_path) + strlen(st->name) + 2;
    path = malloc(len);
    if (!path) {
        cio_errno();
        return -1;
    }

    ret = snprintf(path, len, "%s/%s", ctx->root_path, st->name);
    if (ret == -1) {
        cio_errno();
        free(path);
        return -1;
    }

    dir = opendir(path);
    if (!dir) {
        cio_errno();
        free(path);
        return -1;
    }

    cio_log_debug(ctx, "[cio scan] opening stream %s", st->name);

    /* Iterate the root_path */
    while ((ent = readdir(dir)) != NULL) {
        if ((ent->d_name[0] == '.') || (strcmp(ent->d_name, "..") == 0)) {
            continue;
        }

        /* Look just for directories */
        if (ent->d_type != DT_REG) {
            continue;
        }

        /* register every directory as a stream */
        cio_chunk_open(ctx, st, ent->d_name, CIO_OPEN_RD, 0);
    }

    closedir(dir);
    free(path);

    return 0;
}

/* Given a cio context, scan it root_path and populate stream/files */
int cio_scan_streams(struct cio_ctx *ctx)
{
    DIR *dir;
    struct dirent *ent;
    struct cio_stream *st;

    dir = opendir(ctx->root_path);
    if (!dir) {
        cio_errno();
        return -1;
    }

    cio_log_debug(ctx, "[cio scan] opening path %s", ctx->root_path);

    /* Iterate the root_path */
    while ((ent = readdir(dir)) != NULL) {
        if ((ent->d_name[0] == '.') || (strcmp(ent->d_name, "..") == 0)) {
            continue;
        }

        /* Look just for directories */
        if (ent->d_type != DT_DIR) {
            continue;
        }

        /* register every directory as a stream */
        st = cio_stream_create(ctx, ent->d_name, CIO_STORE_FS);
        if (st) {
            cio_scan_stream_files(ctx, st);
        }
    }

    closedir(dir);
    return 0;
}
#else
int cio_scan_streams(struct cio_ctx *ctx)
{
    cio_log_error(ctx, "[cio scan] file system backend not supported");
    return -1;
}
#endif

void cio_scan_dump(struct cio_ctx *ctx)
{
    struct mk_list *head;
    struct cio_stream *st;

    cio_log_info(ctx, "scan dump of %s", ctx->root_path);

    /* Iterate streams */
    mk_list_foreach(head, &ctx->streams) {
        st = mk_list_entry(head, struct cio_stream, _head);
        printf(" stream:%-60s%i chunks\n",
               st->name, mk_list_size(&st->files));

        if (st->type == CIO_STORE_MEM) {
            cio_memfs_scan_dump(ctx, st);
        }
        else if (st->type == CIO_STORE_FS) {
            cio_file_scan_dump(ctx, st);
        }
    }
}
