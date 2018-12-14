/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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
#include <monkey/mk_core.h>
#include <msgpack.h>

#define FLB_INPUT_CHUNK_SIZE 262144  /* 256KB (hint) */

struct flb_input_chunk {
    int busy;                       /* buffer is being flushed  */
    void *chunk;                    /* context of struct cio_chunk */
    msgpack_packer mp_pck;          /* msgpack packer */
    struct flb_input_instance *in;  /* reference to parent input instance */
    struct mk_list _head;
};

struct flb_input_chunk *flb_input_chunk_create(struct flb_input_instance *in,
                                               char *tag, int tag_len);
int flb_input_chunk_destroy(struct flb_input_chunk *ic, int del);
void flb_input_chunk_destroy_all(struct flb_input_instance *in);
int flb_input_chunk_write(void *data, const char *buf, size_t len);
int flb_input_chunk_write_at(void *data, off_t offset,
                             const char *buf, size_t len);
int flb_input_chunk_append_obj(struct flb_input_instance *in,
                               char *tag, int tag_len,
                               msgpack_object data);
int flb_input_chunk_append_raw(struct flb_input_instance *in,
                               char *tag, size_t tag_len,
                               void *buf, size_t buf_size);
void *flb_input_chunk_flush(struct flb_input_chunk *ic, size_t *size);
int flb_input_chunk_release_lock(struct flb_input_chunk *ic);
int flb_input_chunk_get_tag(struct flb_input_chunk *ic,
                            char **tag_buf, int *tag_len);
ssize_t flb_input_chunk_get_size(struct flb_input_chunk *ic);
int flb_input_chunk_set_limits(struct flb_input_instance *in);
size_t flb_input_chunk_total_size(struct flb_input_instance *in);
struct flb_input_chunk *flb_input_chunk_map(struct flb_input_instance *in,
                                            void *chunk);

#endif
