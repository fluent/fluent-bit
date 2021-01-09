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

#ifndef CIO_STATS_H
#define CIO_STATS_H

#include <chunkio/chunkio.h>

struct cio_stats {
    /* Streams */
    int streams_total;       /* total number of registered streams */

    /* Chunks */
    int chunks_total;        /* total number of registered chunks */
    int chunks_mem;          /* number of chunks of memory type */
    int chunks_fs;           /* number of chunks in file type */
    int chunks_fs_up;        /* number of chunks in file type 'Up' in memory */
    int chunks_fs_down;      /* number of chunks in file type 'down' */
};

void cio_stats_get(struct cio_ctx *ctx, struct cio_stats *stats);
void cio_stats_print_summary(struct cio_ctx *ctx);

#endif
