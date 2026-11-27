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
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_file_native.h>
#include <chunkio/cio_memfs.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_error.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_scan.h>

#ifdef _WIN32
#include "win32/dirent.h"
#endif

#ifdef CIO_HAVE_BACKEND_FILESYSTEM
/*
 * Return the file last-write time with sub-second precision when the
 * platform provides it. Pooled chunk files are named after their slot, so
 * this timestamp is the only ordering information that survives a restart.
 */
static int scan_file_mtime(const char *path,
                           uint64_t *sec, uint64_t *nsec)
{
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULARGE_INTEGER t;
    uint64_t ns100;

    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) {
        return -1;
    }

    t.LowPart = fad.ftLastWriteTime.dwLowDateTime;
    t.HighPart = fad.ftLastWriteTime.dwHighDateTime;

    /* 100ns intervals since 1601-01-01 -> Unix epoch */
    ns100 = t.QuadPart - 116444736000000000ULL;
    *sec = ns100 / 10000000ULL;
    *nsec = (ns100 % 10000000ULL) * 100ULL;
#else
    struct stat sb;

    if (stat(path, &sb) != 0) {
        return -1;
    }
#if defined(__APPLE__)
    *sec = (uint64_t) sb.st_mtimespec.tv_sec;
    *nsec = (uint64_t) sb.st_mtimespec.tv_nsec;
#else
    *sec = (uint64_t) sb.st_mtim.tv_sec;
    *nsec = (uint64_t) sb.st_mtim.tv_nsec;
#endif
#endif

    return 0;
}

static int cio_scan_stream_files(struct cio_ctx *ctx, struct cio_stream *st,
                                 char *chunk_extension)
{
    int len;
    int ret;
    int err;
    int ext_off;
    int ext_len = 0;
    int slot;
    int have_time;
    int have_size;
    size_t file_size;
    uint64_t mtime_sec = 0;
    uint64_t mtime_nsec = 0;
    char *path;
    DIR *dir;
    struct dirent *ent;
    struct cio_chunk *chunk;

    len = strlen(ctx->options.root_path) + strlen(st->name) + 2;
    path = malloc(len);
    if (!path) {
        cio_errno();
        return -1;
    }

    ret = snprintf(path, len, "%s/%s", ctx->options.root_path, st->name);
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

    if (chunk_extension) {
        ext_len = strlen(chunk_extension);
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

        /*
         * File-slot pool: an empty slot file is a free slot, not a chunk.
         * Leave it in place so new chunks reuse it; if the slot number is
         * outside the current pool size (left over from a larger pool) it is
         * not reusable, so unlink it instead of leaving an orphan behind.
         */
        slot = cio_stream_pool_slot_from_name(ent->d_name);

        /*
         * Check the file matches the desired extension (if set). Canonical
         * slot artifacts always use the ".flb" physical name, but they are
         * still chunks of this stream: a client loading another logical
         * extension (e.g. ".out") must not lose its backlog. This also
         * applies when the pool is disabled or the slot is outside a reduced
         * pool size, otherwise an opt-out/shrink restart would hide the
         * backlog.
         */
        if (chunk_extension && slot < 0) {
            len = strlen(ent->d_name);
            if (len <= ext_len) {
                continue;
            }

            ext_off = len - ext_len;
            if (strncmp(ent->d_name + ext_off, chunk_extension, ext_len) != 0) {
                continue;
            }
        }

        ctx->last_chunk_error = 0;

        have_time = CIO_FALSE;
        have_size = CIO_FALSE;
        file_size = 0;
        if (slot >= 0) {
            struct stat sb;
            char *spath;

            spath = cio_file_native_compose_path(ctx->options.root_path,
                                                 st->name, ent->d_name);
            if (spath) {
                if (stat(spath, &sb) == 0) {
                    have_size = CIO_TRUE;
                    file_size = (size_t) sb.st_size;

                    if (scan_file_mtime(spath, &mtime_sec, &mtime_nsec) == 0) {
                        have_time = CIO_TRUE;
                    }
                }

                if (have_size == CIO_TRUE && file_size == 0) {
                    if (cio_stream_pool_slot_valid(st, slot) == CIO_FALSE) {
                        cio_file_native_delete_by_path(spath);
                    }
                    free(spath);
                    continue;
                }
                free(spath);
            }
        }

        /*
         * Mark the stream as scanning while the existing file is opened: the
         * filesystem backend must recover non-slot (legacy or fallback) names
         * in place instead of redirecting them to a fresh slot.
         */
        st->scanning = CIO_TRUE;
        chunk = cio_chunk_open(ctx, st, ent->d_name, ctx->options.flags, 0,
                               &err);
        st->scanning = CIO_FALSE;

        /*
         * A pooled chunk file only carries its slot name, so the original
         * creation stamp is gone after a restart and backlog order (Fluent
         * Bit sorts recovered chunks by name) would follow slot numbers.
         * Keep the physical name, but give the in-memory chunk a logical
         * name that embeds the file last-write time: it sorts like a stock
         * generated chunk name and stays stable for the chunk lifetime.
         */
        if (chunk != NULL && slot >= 0 && have_time == CIO_TRUE) {
            char order_name[128];
            char *copy;

            snprintf(order_name, sizeof(order_name),
                     "slot-%06d-%" PRIu64 ".%09" PRIu64 ".flb",
                     slot, mtime_sec, mtime_nsec);
            copy = strdup(order_name);
            if (copy != NULL) {
                free(chunk->name);
                chunk->name = copy;
            }
        }

        if (ctx->options.flags & CIO_DELETE_IRRECOVERABLE) {
            if (err == CIO_CORRUPTED) {
                if (ctx->last_chunk_error == CIO_ERR_BAD_CHECKSUM ||
                    ctx->last_chunk_error == CIO_ERR_BAD_FILE_SIZE ||
                    ctx->last_chunk_error == CIO_ERR_BAD_LAYOUT)
                {
                    cio_log_error(ctx, "[cio scan] discarding irrecoverable chunk");

                    cio_chunk_delete(ctx, st, ent->d_name);
                }
            }
        }
    }

    closedir(dir);
    free(path);

    return 0;
}

/* Given a cio context, scan it root_path and populate stream/files */
int cio_scan_streams(struct cio_ctx *ctx, char *chunk_extension)
{
    DIR *dir;
    struct dirent *ent;
    struct cio_stream *st;

    dir = opendir(ctx->options.root_path);
    if (!dir) {
        cio_errno();
        return -1;
    }

    cio_log_debug(ctx, "[cio scan] opening path %s", ctx->options.root_path);

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
            cio_scan_stream_files(ctx, st, chunk_extension);
        }
    }

    closedir(dir);
    return 0;
}
#else
int cio_scan_streams(struct cio_ctx *ctx, char *chunk_extension)
{
    (void) chunk_extension;
    cio_log_error(ctx, "[cio scan] file system backend not supported");
    return -1;
}
#endif

void cio_scan_dump(struct cio_ctx *ctx)
{
    struct mk_list *head;
    struct cio_stream *st;

    cio_log_info(ctx, "scan dump of %s", ctx->options.root_path);

    /* Iterate streams */
    mk_list_foreach(head, &ctx->streams) {
        st = mk_list_entry(head, struct cio_stream, _head);
        printf(" stream:%-60s%i chunks\n",
               st->name, mk_list_size(&st->chunks));

        if (st->type == CIO_STORE_MEM) {
            cio_memfs_scan_dump(ctx, st);
        }
        else if (st->type == CIO_STORE_FS) {
            cio_file_scan_dump(ctx, st);
        }
    }
}
