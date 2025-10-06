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

#ifndef FLB_VIVO_STREAM_H
#define FLB_VIVO_STREAM_H

#include <fluent-bit/flb_info.h>

#include "vivo.h"

struct vivo_stream_entry {
    int64_t id;
    flb_sds_t data;
    struct mk_list _head;
};

struct vivo_stream {
    size_t entries_added;

    size_t current_bytes_size;

    struct mk_list entries;
    struct mk_list purge;

    /* mutex to protect the context */
    pthread_mutex_t stream_mutex;

    /* back reference to struct vivo_exporter context */
    void *parent;
};


struct vivo_stream *vivo_stream_create(struct vivo_exporter *ctx);
void vivo_stream_destroy(struct vivo_stream *vs);
struct vivo_stream_entry *vivo_stream_entry_create(struct vivo_stream *vs,
                                                   void *data, size_t size);
struct vivo_stream_entry *vivo_stream_append(struct vivo_stream *vs, void *data,
                                             size_t size);
flb_sds_t vivo_stream_get_content(struct vivo_stream *vs, int64_t from, int64_t to,
                                  int64_t limit,
                                  int64_t *stream_start_id, int64_t *stream_end_id,
                                  int64_t *stream_next_id);

#endif
