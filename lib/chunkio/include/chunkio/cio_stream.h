/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2019 Eduardo Silva <eduardo@monkey.io>
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

#ifndef CIO_STREAM_H
#define CIO_STREAM_H

#include <monkey/mk_core/mk_list.h>

struct cio_stream {
    int type;                   /* type: CIO_STORE_FS or CIO_STORE_MEM */
    char *name;                 /* stream name */
    struct mk_list _head;       /* head link to ctx->streams list */
    struct mk_list chunks;      /* list of all chunks in the stream */
    struct mk_list chunks_up;   /* list of chunks who are 'up'   */
    struct mk_list chunks_down; /* list of chunks who are 'down' */
    void *parent;               /* ref to parent ctx */
};

struct cio_stream *cio_stream_create(struct cio_ctx *ctx, const char *name,
                                     int type);
struct cio_stream *cio_stream_get(struct cio_ctx *ctx, const char *name);
int cio_stream_delete(struct cio_stream *st);
void cio_stream_destroy(struct cio_stream *st);
void cio_stream_destroy_all(struct cio_ctx *ctx);
size_t cio_stream_size_chunks_up(struct cio_stream *st);

#endif
