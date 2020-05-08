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

#ifndef FLB_INPUT_CHUNK_H
#define FLB_INPUT_CHUNK_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_core.h>
#include <msgpack.h>

/*
 * This variable defines a 'hint' size for new Chunks created, this
 * value is passed to Chunk I/O.
 */
#define FLB_INPUT_CHUNK_SIZE           262144  /* 256KB (hint) */

/*
 * Defines a maximum size for a Chunk in the file system: note that despite
 * this is considered a limit, a Chunk size might get greater than this.
 */
#define FLB_INPUT_CHUNK_FS_MAX_SIZE   2048000  /* 2MB */

struct flb_input_chunk {
    int busy;                       /* buffer is being flushed  */
    int fs_backlog;                 /* chunk originated from fs backlog */
    int sp_done;                    /* sp already processed this chunk */
#ifdef FLB_HAVE_METRICS
    int total_records;              /* total records in the chunk */
    int added_records;              /* recently added records */
#endif
    void *chunk;                    /* context of struct cio_chunk */
    off_t stream_off;               /* stream offset */
    msgpack_packer mp_pck;          /* msgpack packer */
    struct flb_input_instance *in;  /* reference to parent input instance */
    struct mk_list _head;
};

struct flb_input_chunk *flb_input_chunk_create(struct flb_input_instance *in,
                                               const char *tag, int tag_len);
int flb_input_chunk_destroy(struct flb_input_chunk *ic, int del);
void flb_input_chunk_destroy_all(struct flb_input_instance *in);
int flb_input_chunk_write(void *data, const char *buf, size_t len);
int flb_input_chunk_write_at(void *data, off_t offset,
                             const char *buf, size_t len);
int flb_input_chunk_append_obj(struct flb_input_instance *in,
                               const char *tag, int tag_len,
                               msgpack_object data);
int flb_input_chunk_append_raw(struct flb_input_instance *in,
                               const char *tag, size_t tag_len,
                               const void *buf, size_t buf_size);
const void *flb_input_chunk_flush(struct flb_input_chunk *ic, size_t *size);
int flb_input_chunk_release_lock(struct flb_input_chunk *ic);
flb_sds_t flb_input_chunk_get_name(struct flb_input_chunk *ic);
int flb_input_chunk_get_tag(struct flb_input_chunk *ic,
                            const char **tag_buf, int *tag_len);
ssize_t flb_input_chunk_get_size(struct flb_input_chunk *ic);
size_t flb_input_chunk_set_limits(struct flb_input_instance *in);
size_t flb_input_chunk_total_size(struct flb_input_instance *in);
struct flb_input_chunk *flb_input_chunk_map(struct flb_input_instance *in,
                                            void *chunk);
int flb_input_chunk_set_up_down(struct flb_input_chunk *ic);
int flb_input_chunk_set_up(struct flb_input_chunk *ic);
int flb_input_chunk_down(struct flb_input_chunk *ic);
int flb_input_chunk_is_up(struct flb_input_chunk *ic);

#endif
