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

#ifndef FLB_FILTER_MULTILINE_H
#define FLB_FILTER_MULTILINE_H

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_emitter.h>
#include "ml_concat.h"

#define FLB_MULTILINE_MEM_BUF_LIMIT_DEFAULT  "10M"
#define FLB_MULTILINE_METRIC_EMITTED         200
#define FLB_MULTILINE_METRIC_TRUNCATED       201
#define FLB_MULTILINE_MODE_PARTIAL_MESSAGE   "partial_message"
#define FLB_MULTILINE_MODE_PARSER            "parser"
#define FLB_MULTILINE_STREAM_EVICT_MAX       256

/*
 * input instance + tag is the unique identifier for a multiline stream.
 *
 * Streams are created on demand and evicted after they have not received
 * records for 'stream_idle_timeout' (default 5 minutes, see
 * evict_idle_streams() in ml.c). Without eviction every distinct tag ever
 * seen keeps its parser buffers allocated until shutdown.
 */
struct ml_stream {
    flb_sds_t tag;
    flb_sds_t input_name;
    uint64_t stream_id;
    uint64_t last_used;       /* cfl_time_now() of the last record appended */

    struct mk_list _head;
};

struct ml_ctx {
    int debug_flush;
    int use_buffer;
    flb_sds_t key_content;
    flb_sds_t mode;

    /* packaging buffers */
    msgpack_sbuffer mp_sbuf;  /* temporary msgpack buffer */
    msgpack_packer mp_pck;    /* temporary msgpack packer */

    /* Multiline core engine */
    uint64_t stream_id;
    struct flb_ml *m;
    struct mk_list *multiline_parsers;
    int flush_ms;

    /* idle stream eviction (buffered 'parser' mode only) */
    int stream_idle_timeout;          /* seconds, 0 disables eviction */
    uint64_t last_evict_check;        /* cfl_time_now() of the last sweep */

    int timer_created;

    int partial_mode;

    struct mk_list ml_streams;

    struct mk_list split_message_packers;

    struct flb_filter_instance *ins;

    struct flb_emitter_callbacks emitter_callbacks;

    /* Shutdown-only gate for concurrent buffered parser callbacks. */
    uint64_t active_callbacks;
    uint64_t shutdown_flush_requested;

    /* emitter */
    flb_sds_t emitter_name;                 /* emitter input plugin name */
    flb_sds_t emitter_storage_type;         /* emitter storage type */
    size_t emitter_mem_buf_limit;           /* Emitter buffer limit */
    struct flb_input_instance *ins_emitter; /* emitter input plugin instance */
    struct flb_config *config;              /* Fluent Bit context */
    struct flb_input_instance *i_ins;       /* Fluent Bit input instance (last used)*/

#ifdef FLB_HAVE_METRICS
    struct cmt_counter *cmt_emitted;
    struct cmt_counter *cmt_truncated;
    struct cmt_counter *cmt_streams_evicted;
    struct cmt_gauge *cmt_streams_active;
#endif
};

/* Register external function to emit records, check 'plugins/in_emitter' */
int in_emitter_add_record(const char *tag, int tag_len,
                          const char *buf_data, size_t buf_size,
                          struct flb_input_instance *in,
                          struct flb_input_instance *i_ins);

#endif
