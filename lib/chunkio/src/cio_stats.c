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

#include <stdio.h>
#include <string.h>

#include <chunkio/chunkio_compat.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_stats.h>

void cio_stats_get(struct cio_ctx *ctx, struct cio_stats *stats)
{
    struct mk_list *head;
    struct mk_list *f_head;
    struct cio_chunk *ch;
    struct cio_stream *stream;

    memset(stats, 0, sizeof(struct cio_stats));

    /* Iterate each stream */
    mk_list_foreach(head, &ctx->streams) {
        stream = mk_list_entry(head, struct cio_stream, _head);
        stats->streams_total++;

        /* Iterate chunks */
        mk_list_foreach(f_head, &stream->chunks) {
            stats->chunks_total++;

            if (stream->type == CIO_STORE_MEM) {
                stats->chunks_mem++;
                continue;
            }

            /* Only applicable for 'file' type chunks */
            ch = mk_list_entry(f_head, struct cio_chunk, _head);
            stats->chunks_fs++;

            if (cio_chunk_is_up(ch) == CIO_TRUE) {
                stats->chunks_fs_up++;
            }
            else {
                stats->chunks_fs_down++;
            }
        }
    }
}

void cio_stats_print_summary(struct cio_ctx *ctx)
{
    struct cio_stats st;

    /* retrieve stats */
    cio_stats_get(ctx, &st);

    printf("======== Chunk I/O Stats ========\n");
    printf("- streams total     : %i\n", st.streams_total);
    printf("- chunks total      : %i\n", st.chunks_total);
    printf("- chunks memfs total: %i\n", st.chunks_mem);
    printf("- chunks file total : %i\n", st.chunks_fs);
    printf("  - files up        : %i\n", st.chunks_fs_up);
    printf("  - files down      : %i\n", st.chunks_fs_down);
}
