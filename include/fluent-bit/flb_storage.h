/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#define FLB_STORAGE_BL_MEM_LIMIT   "5M"
#define FLB_STORAGE_MAX_CHUNKS_UP  128

struct flb_storage_metrics {
    int fd;
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

int flb_storage_create(struct flb_config *ctx);
int flb_storage_input_create(struct cio_ctx *cio,
                             struct flb_input_instance *in);
void flb_storage_destroy(struct flb_config *ctx);
void flb_storage_input_destroy(struct flb_input_instance *in);

struct flb_storage_metrics *flb_storage_metrics_create(struct flb_config *ctx);

#endif
