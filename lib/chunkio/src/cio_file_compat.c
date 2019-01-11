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

#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_file_st.h>
#include <chunkio/cio_crc32.h>

struct cio_file *cio_file_open(struct cio_ctx *ctx,
                               struct cio_stream *st,
                               struct cio_chunk *ch,
                               int flags,
                               size_t size)
{
    return NULL;
}

void cio_file_close(struct cio_chunk *ch, int delete)
{
    return;
}

int cio_file_write(struct cio_chunk *ch, const void *buf, size_t count)
{
    return -1;
}

int cio_file_write_metadata(struct cio_chunk *ch, char *buf, size_t size)
{
    return -1;
}

int cio_file_sync(struct cio_chunk *ch)
{
    return -1;
}

int cio_file_fs_size_change(struct cio_file *cf, size_t new_size)
{
    return -1;
}

int cio_file_close_stream(struct cio_stream *st)
{
    return -1;
}

char *cio_file_hash(struct cio_file *cf)
{
    return NULL;
}

void cio_file_hash_print(struct cio_file *cf)
{
    return;
}

void cio_file_calculate_checksum(struct cio_file *cf, crc_t *out)
{
    return;
}

void cio_file_scan_dump(struct cio_ctx *ctx, struct cio_stream *st)
{
    return;
}

int cio_file_read_prepare(struct cio_ctx *ctx, struct cio_chunk *ch)
{
    return -1;
}
