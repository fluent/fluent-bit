/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_routes_mask.h>
#include <stdint.h>

struct cio_chunk;

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

/* Number of bytes reserved for Metadata Header on Chunks */
#define FLB_INPUT_CHUNK_META_HEADER   4

/* Chunk metadata flags */
#define FLB_CHUNK_FLAG_DIRECT_ROUTES        (1 << 0)
#define FLB_CHUNK_FLAG_DIRECT_ROUTE_LABELS  (1 << 1)
#define FLB_CHUNK_FLAG_DIRECT_ROUTE_WIDE_IDS (1 << 2)
#define FLB_CHUNK_FLAG_DIRECT_ROUTE_PLUGIN_IDS (1 << 3)

#define FLB_CHUNK_DIRECT_ROUTE_LABEL_ALIAS_FLAG 0x8000
#define FLB_CHUNK_DIRECT_ROUTE_LABEL_LENGTH_MASK 0x7FFF

struct flb_output_instance;

struct flb_chunk_direct_route {
    uint32_t id;
    uint16_t label_length;
    const char *label;
    uint8_t label_is_alias;
    uint16_t plugin_name_length;
    const char *plugin_name;
};

/* Chunks magic bytes (starting from Fluent Bit v1.8.10) */
#define FLB_INPUT_CHUNK_MAGIC_BYTE_0  (unsigned char) 0xF1
#define FLB_INPUT_CHUNK_MAGIC_BYTE_1  (unsigned char) 0x77

/* Chunk types: Log, Metrics, Traces, Profiles and Blobs are supported */
#define FLB_INPUT_CHUNK_TYPE_LOGS      0
#define FLB_INPUT_CHUNK_TYPE_METRICS   1
#define FLB_INPUT_CHUNK_TYPE_TRACES    2
#define FLB_INPUT_CHUNK_TYPE_BLOBS     3
#define FLB_INPUT_CHUNK_TYPE_PROFILES  4

#ifdef FLB_HAVE_CHUNK_TRACE
#define FLB_INPUT_CHUNK_HAS_TRACE     1 << 31
#endif /* FLB_HAVE_CHUNK_TRACE */

/* Max length for Tag */
#define FLB_INPUT_CHUNK_TAG_MAX        (65535 - FLB_INPUT_CHUNK_META_HEADER)

struct flb_input_chunk {
    int  event_type;                 /* chunk type: logs, metrics or traces */
    bool fs_counted;
    int  busy;                       /* buffer is being flushed  */
    int  fs_backlog;                 /* chunk originated from fs backlog */
    int  sp_done;                    /* sp already processed this chunk */
#ifdef FLB_HAVE_METRICS
    int  total_records;              /* total records in the chunk */
    int  added_records;              /* recently added records */
#endif
    void *chunk;                    /* context of struct cio_chunk */
    off_t stream_off;               /* stream offset */
    msgpack_packer mp_pck;          /* msgpack packer */
    struct flb_input_instance *in;  /* reference to parent input instance */
    struct flb_task *task;          /* reference to the outgoing task */
#ifdef FLB_HAVE_CHUNK_TRACE
    struct flb_chunk_trace *trace;
#endif /* FLB_HAVE_CHUNK_TRACE */
    double create_time;           /* chunk creation time in seconds with fractional precision) */
    flb_route_mask_element *routes_mask; /* track the output plugins the chunk routes to */
    struct mk_list _head;
};

struct flb_input_chunk *flb_input_chunk_create(struct flb_input_instance *in, int event_type,
                                               const char *tag, int tag_len);
int flb_input_chunk_destroy(struct flb_input_chunk *ic, int del);
void flb_input_chunk_destroy_all(struct flb_input_instance *in);
int flb_input_chunk_destroy_corrupted(struct flb_input_chunk *ic,
                                      const char *tag_buf, int tag_len,
                                      int del);
int flb_input_chunk_write(void *data, const char *buf, size_t len);
int flb_input_chunk_write_at(void *data, off_t offset,
                             const char *buf, size_t len);
int flb_input_chunk_append_obj(struct flb_input_instance *in,
                               const char *tag, int tag_len,
                               msgpack_object data);
int flb_input_chunk_append_raw(struct flb_input_instance *in,
                               int event_type,
                               size_t records,
                               const char *tag, size_t tag_len,
                               const void *buf, size_t buf_size);

const void *flb_input_chunk_flush(struct flb_input_chunk *ic, size_t *size);
int flb_input_chunk_release_lock(struct flb_input_chunk *ic);
flb_sds_t flb_input_chunk_get_name(struct flb_input_chunk *ic);
int flb_input_chunk_get_event_type(struct flb_input_chunk *ic);

int flb_input_chunk_get_tag(struct flb_input_chunk *ic,
                            const char **tag_buf, int *tag_len);

int flb_input_chunk_write_header_v2(struct cio_chunk *chunk,
                                    int event_type,
                                    char *tag, int tag_len,
                                    const struct flb_chunk_direct_route *routes,
                                    int route_count);
int flb_chunk_route_plugin_matches(struct flb_output_instance *o_ins,
                                   const struct flb_chunk_direct_route *route);
int flb_input_chunk_has_direct_routes(struct flb_input_chunk *ic);
int flb_input_chunk_get_direct_routes(struct flb_input_chunk *ic,
                                      struct flb_chunk_direct_route **routes,
                                      int *route_count);
void flb_input_chunk_destroy_direct_routes(struct flb_chunk_direct_route *routes,
                                           int route_count);

void flb_input_chunk_ring_buffer_cleanup(struct flb_input_instance *ins);
void flb_input_chunk_ring_buffer_collector(struct flb_config *ctx, void *data);
ssize_t flb_input_chunk_get_size(struct flb_input_chunk *ic);
ssize_t flb_input_chunk_get_real_size(struct flb_input_chunk *ic);
size_t flb_input_chunk_set_limits(struct flb_input_instance *in);
size_t flb_input_chunk_total_size(struct flb_input_instance *in);
struct flb_input_chunk *flb_input_chunk_map(struct flb_input_instance *in,
                                            int event_type,
                                            void *chunk);
int flb_input_chunk_set_up_down(struct flb_input_chunk *ic);
int flb_input_chunk_set_up(struct flb_input_chunk *ic);
int flb_input_chunk_down(struct flb_input_chunk *ic);
int flb_input_chunk_is_up(struct flb_input_chunk *ic);
void flb_input_chunk_update_output_instances(struct flb_input_chunk *ic,
                                             size_t chunk_size);
size_t flb_input_chunk_get_total_ring_buffer_size(const struct flb_config *config);

#endif
