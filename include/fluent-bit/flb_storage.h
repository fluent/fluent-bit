/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_STORAGE_H
#define FLB_STORAGE_H

#include <fluent-bit/flb_info.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_stats.h>

/* Storage type */
#define FLB_STORAGE_FS      CIO_STORE_FS    /* 0 */
#define FLB_STORAGE_MEM     CIO_STORE_MEM   /* 1 */
#define FLB_STORAGE_MEMRB   10

/* Storage defaults */
#define FLB_STORAGE_BL_MEM_LIMIT   "100M"
#define FLB_STORAGE_MAX_CHUNKS_UP  128

struct flb_storage_metrics {
    int fd;

    struct cmt *cmt;

    /* cmetrics */
    struct cmt_gauge *cmt_chunks;           /* total number of chunks */
    struct cmt_gauge *cmt_mem_chunks;       /* number of chunks up in memory */
    struct cmt_gauge *cmt_fs_chunks;        /* total number of filesystem chunks */
    struct cmt_gauge *cmt_fs_chunks_up;     /* number of filesystem chunks up in memory */
    struct cmt_gauge *cmt_fs_chunks_down;   /* number of filesystem chunks down */
};

/*
 * The storage structure helps to associate the contexts between
 * input instances and the chunkio context and further streams.
 *
 * Each input instance have a stream associated.
 */
struct flb_storage_input {
    int type;                   /* CIO_STORE_FS | CIO_STORE_MEM */
    struct cio_stream *stream;
    struct cio_ctx *cio;
};

static inline char *flb_storage_get_type(int type)
{
    switch(type) {
        case FLB_STORAGE_FS:
            return "'filesystem' (memory + filesystem)";
        case FLB_STORAGE_MEM:
            return "'memory' (memory only)";
        case FLB_STORAGE_MEMRB:
            return "'memrb' (memory ring buffer)";
    };

    return NULL;
}

int flb_storage_create(struct flb_config *ctx);
int flb_storage_input_create(struct cio_ctx *cio,
                             struct flb_input_instance *in);
void flb_storage_destroy(struct flb_config *ctx);
void flb_storage_input_destroy(struct flb_input_instance *in);

struct flb_storage_metrics *flb_storage_metrics_create(struct flb_config *ctx);

/* cmetrics */
int flb_storage_metrics_update(struct flb_config *config, struct flb_storage_metrics *sm);

void flb_storage_chunk_count(struct flb_config *ctx, int *mem_chunks, int *fs_chunks);

#endif
