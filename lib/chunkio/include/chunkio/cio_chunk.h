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

#ifndef CIO_CHUNK_H
#define CIO_CHUNK_H

#include <sys/types.h>
#include <inttypes.h>

#include <chunkio/chunkio_compat.h>

struct cio_chunk {
    int lock;                 /* locked for write operations ? */
    char *name;               /* chunk name */
    void *backend;            /* backend context (cio_file, cio_memfs) */

    /* Transaction helpers */
    int tx_active;            /* active transaction ?         */
    uint32_t tx_crc;          /* CRC32 upon transaction begin */
    off_t tx_content_length;  /* content length               */

    struct cio_ctx *ctx;      /* library context      */
    struct cio_stream *st;    /* stream context       */

    /* error handling */
    int error_n;

    /*
     * The state head links to the stream->chunks_up or stream->chunks_down
     * linked list.
     */
    struct mk_list _state_head;

    struct mk_list _head;     /* head link to stream->files */
};

struct cio_chunk *cio_chunk_open(struct cio_ctx *ctx, struct cio_stream *st,
                                 const char *name, int flags, size_t size,
                                 int *err);
void cio_chunk_close(struct cio_chunk *ch, int delete);
int cio_chunk_delete(struct cio_ctx *ctx, struct cio_stream *st, const char *name);
int cio_chunk_write(struct cio_chunk *ch, const void *buf, size_t count);
int cio_chunk_write_at(struct cio_chunk *ch, off_t offset,
                       const void *buf, size_t count);
int cio_chunk_sync(struct cio_chunk *ch);
int cio_chunk_get_content(struct cio_chunk *ch, char **buf, size_t *size);
int cio_chunk_get_content_copy(struct cio_chunk *ch,
                               void **out_buf, size_t *out_size);

ssize_t cio_chunk_get_content_size(struct cio_chunk *ch);
ssize_t cio_chunk_get_real_size(struct cio_chunk *ch);
size_t cio_chunk_get_content_end_pos(struct cio_chunk *ch);
void cio_chunk_close_stream(struct cio_stream *st);
char *cio_chunk_hash(struct cio_chunk *ch);
int cio_chunk_lock(struct cio_chunk *ch);
int cio_chunk_unlock(struct cio_chunk *ch);
int cio_chunk_is_locked(struct cio_chunk *ch);

/* transaction handling */
int cio_chunk_tx_begin(struct cio_chunk *ch);
int cio_chunk_tx_commit(struct cio_chunk *ch);
int cio_chunk_tx_rollback(struct cio_chunk *ch);

/* Chunk content up/down */
int cio_chunk_is_up(struct cio_chunk *ch);
int cio_chunk_is_file(struct cio_chunk *ch);
int cio_chunk_up(struct cio_chunk *ch);
int cio_chunk_up_force(struct cio_chunk *ch);
int cio_chunk_down(struct cio_chunk *ch);
char *cio_version();

/* Counters */
size_t cio_chunk_counter_total_add(struct cio_ctx *ctx);
size_t cio_chunk_counter_total_sub(struct cio_ctx *ctx);
size_t cio_chunk_counter_total_up_add(struct cio_ctx *ctx);
size_t cio_chunk_counter_total_up_sub(struct cio_ctx *ctx);

#endif
