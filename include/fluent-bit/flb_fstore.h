/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#ifndef FLB_FSTORE_H
#define FLB_FSTORE_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_stats.h>

#define FLB_FSTORE_LOCK        222
#define FLB_FSTORE_UNLOCK      333

struct flb_fstore_file {
    flb_sds_t name;                 /* file name */

    void *meta_buf;                 /* copy of metadata content */
    size_t meta_size;               /* metadata size */
    void *data;                     /* opaque data type for user/caller context */
    struct cio_chunk *chunk;        /* chunk context */
    struct mk_list _head;           /* link to parent flb_fstore->files */
};

struct flb_fstore {
    struct cio_ctx *cio;            /* Chunk I/O context */
    struct cio_stream *stream;      /* Chunk I/O stream context */

    /* Linked list of known files on the current 'active' stream */
    struct mk_list files;
};

struct flb_fstore *flb_fstore_create(char *path, char *stream_name);
int flb_fstore_destroy(struct flb_fstore *fs);

int flb_fstore_file_meta_set(struct flb_fstore *fs,
                             struct flb_fstore_file *fsf,
                             void *meta, size_t size);

struct flb_fstore_file *flb_fstore_file_create(struct flb_fstore *fs,
                                               char *name,
                                               size_t size);
int flb_fstore_file_content_copy(struct flb_fstore *fs,
                                 struct flb_fstore_file *fsf,
                                 void **out_buf, size_t *out_size);

int flb_fstore_file_append(struct flb_fstore_file *fsf, void *data, size_t size);
int flb_fstore_file_inactive(struct flb_fstore *fs,
                             struct flb_fstore_file *fsf);
int flb_fstore_file_delete(struct flb_fstore *fs,
                           struct flb_fstore_file *fsf);

#endif
