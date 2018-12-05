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

#include <monkey/mk_core/mk_list.h>

#define CIO_FALSE   0
#define CIO_TRUE   !0

/* debug levels */
#define CIO_ERROR  1
#define CIO_WARN   2
#define CIO_INFO   3
#define CIO_DEBUG  4

/* Storage backend */
#define CIO_STORE_FS    0
#define CIO_STORE_MEM   1

/* flags */
#define CIO_OPEN        1   /* open/create file reference */
#define CIO_OPEN_RD     2   /* open and read/mmap content if exists */
#define CIO_CHECKSUM    4   /* enable checksum verification (crc32) */
#define CIO_FULL_SYNC   8   /* force sync to fs through MAP_SYNC */

int cio_page_size;

struct cio_ctx {
    int flags;
    char *root_path;

    /* logging */
    int log_level;
    void (*log_cb)(void *, int, const char *, int, const char *);

    /* streams */
    struct mk_list streams;
};

#include <chunkio/cio_stream.h>
#include <chunkio/cio_chunk.h>

struct cio_ctx *cio_create(const char *root_path,
                           void (*log_cb), int log_level, int flags);
void cio_destroy(struct cio_ctx *ctx);

void cio_set_log_callback(struct cio_ctx *ctx, void (*log_cb));
int cio_set_log_level(struct cio_ctx *ctx, int level);


int cio_meta_write(struct cio_chunk *ch, char *buf, size_t size);
int cio_meta_cmp(struct cio_chunk *ch, char *meta_buf, int meta_len);

#endif
