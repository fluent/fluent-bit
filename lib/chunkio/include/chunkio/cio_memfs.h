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

#ifndef CIO_MEMFS_H
#define CIO_MEMFS_H

#include <chunkio/chunkio.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_crc32.h>

struct cio_memfs {
    char *name;               /* file name */
    crc_t crc_cur;            /* un-finalized checksum */

    /* metadata */
    char *meta_data;
    int  meta_len;

    /* content-data */
    char *buf_data;           /* buffer with content data */
    size_t buf_len;           /* buffer content length */
    size_t buf_size;          /* buffer allocated size */
    size_t realloc_size;      /* chunk size to increase buf_data */
};


struct cio_memfs *cio_memfs_open(struct cio_ctx *ctx, struct cio_stream *st,
                                 struct cio_chunk *ch, int flags,
                                 size_t size);
void cio_memfs_close(struct cio_chunk *ch);
int cio_memfs_write(struct cio_chunk *ch, const void *buf, size_t count);
int cio_memfs_close_stream(struct cio_stream *st);
void cio_memfs_scan_dump(struct cio_ctx *ctx, struct cio_stream *st);
int cio_memfs_content_copy(struct cio_chunk *ch,
                           void **out_buf, size_t *out_size);

#endif
