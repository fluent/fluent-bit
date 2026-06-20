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

#ifndef CHUNKIO_H
#define CHUNKIO_H

#include <chunkio/cio_info.h>
#include <monkey/mk_core/mk_list.h>

#define CIO_FALSE   0
#define CIO_TRUE   !0

/* debug levels */
#define CIO_LOG_ERROR  1
#define CIO_LOG_WARN   2
#define CIO_LOG_INFO   3
#define CIO_LOG_DEBUG  4
#define CIO_LOG_TRACE  5

/* Storage backend */
#define CIO_STORE_FS        0
#define CIO_STORE_MEM       1

/* flags */
#define CIO_OPEN                 1         /* open/create file reference */
#define CIO_OPEN_RW              CIO_OPEN  /* new name for read/write mode */
#define CIO_OPEN_RD              2         /* open and read/mmap content if exists */
#define CIO_CHECKSUM             4         /* enable checksum verification (crc32) */
#define CIO_FULL_SYNC            8         /* force sync to fs through MAP_SYNC */
#define CIO_DELETE_IRRECOVERABLE 16        /* delete irrecoverable chunks from disk */
#define CIO_TRIM_FILES           32        /* trim files to their required size */

/* Return status */
#define CIO_CORRUPTED      -3         /* Indicate that a chunk is corrupted */
#define CIO_RETRY          -2         /* The operations needs to be retried */
#define CIO_ERROR          -1         /* Generic error */
#define CIO_OK              0         /* OK */

/* Configuration limits */
/* The file minimum growth factor is 8 memory pages and
 * the file maximum growth factor is 8 megabytes
 */
#define CIO_REALLOC_HINT_MIN            (cio_getpagesize() * 8)
#define CIO_REALLOC_HINT_MAX            (8 * 1000 * 1000)

/* defaults */
#define CIO_MAX_CHUNKS_UP               64  /* default limit for cio_ctx->max_chunks_up */
#define CIO_DISABLE_REALLOC_HINT        -1  /* default value of size of realloc hint */
#define CIO_DEFAULT_REALLOC_HINT        CIO_REALLOC_HINT_MIN
#define CIO_INITIALIZED                 1337

struct cio_ctx;

struct cio_options {
    /* this bool flag sets if the options has been initialized, that's a mandatory step */
    int initialized;

    int flags;
    char *root_path;

    /* logging */
    int log_level;
    int (*log_cb)(struct cio_ctx *, int, const char *, int, char *);

    char *user;
    char *group;
    char *chmod;

    /* chunk handlings */
    int realloc_size_hint;
};

struct cio_ctx {
    int page_size;
    int realloc_size_hint;
    struct cio_options options;

    void *processed_user;
    void *processed_group;

    /*
     * Internal counters
     */
    size_t total_chunks;      /* Total number of registered chunks */
    size_t total_chunks_up;   /* Total number of chunks 'up' in memory */

    /*
     * maximum open 'file' chunks: this limit helps where there are many
     * chunks in the filesystem and you don't need all of them up in
     * memory. For short, it restrict the open number of files and
     * the amount of memory mapped.
     */
    size_t max_chunks_up;

    /* streams */
    struct mk_list streams;

    /* errors */
    int last_chunk_error; /* this field is necessary to discard irrecoverable
                           * chunks in cio_scan_stream_files, it's not the
                           * best approach but the only at the moment.
                           */
};

#include <chunkio/cio_stream.h>
#include <chunkio/cio_chunk.h>

void cio_options_init(struct cio_options *options);
struct cio_ctx *cio_create(struct cio_options *options);
void cio_destroy(struct cio_ctx *ctx);
int cio_load(struct cio_ctx *ctx, char *chunk_extension);
int cio_qsort(struct cio_ctx *ctx, int (*compar)(const void *, const void *));

void cio_set_log_callback(struct cio_ctx *ctx, void (*log_cb));
int cio_set_log_level(struct cio_ctx *ctx, int level);
int cio_set_max_chunks_up(struct cio_ctx *ctx, int n);
int cio_set_realloc_size_hint(struct cio_ctx *ctx, size_t realloc_size_hint);

void cio_enable_file_trimming(struct cio_ctx *ctx);
void cio_disable_file_trimming(struct cio_ctx *ctx);

int cio_meta_write(struct cio_chunk *ch, char *buf, size_t size);
int cio_meta_cmp(struct cio_chunk *ch, char *meta_buf, int meta_len);
int cio_meta_read(struct cio_chunk *ch, char **meta_buf, int *meta_len);
int cio_meta_size(struct cio_chunk *ch);

#endif
