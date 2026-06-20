/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022-2026 The Fluent Bit Authors
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

#ifndef FLB_CHUNK_TRACE_H
#define FLB_CHUNK_TRACE_H

#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_lib.h>

#include <chunkio/cio_chunk.h>

/* A record has been received from input */
#define FLB_CHUNK_TRACE_TYPE_INPUT      1
/* A record has been filtered */
#define FLB_CHUNK_TRACE_TYPE_FILTER     2
/* A trace with the final record before output */
#define FLB_CHUNK_TRACE_TYPE_PRE_OUTPUT 3
/* A record has been output */
#define FLB_CHUNK_TRACE_TYPE_OUTPUT     4

#define FLB_CHUNK_TRACE_LIMIT_TIME    1
#define FLB_CHUNK_TRACE_LIMIT_COUNT   2

struct flb_chunk_trace_input_record {
    struct flb_time t;
    void *input;
    char *buf;
    size_t buf_size;
};

struct flb_chunk_trace_filter_record {
    struct flb_time t;
    int trace_version;
    void *filter;
    char *buf;
    size_t buf_size;
};

struct flb_chunk_trace_limit {
    /* set to one of: */
    /*   FLB_CHUNK_TRACE_LIMIT_TIME */
    /*   FLB_CHUNK_TRACE_LIMIT_COUNT */
    int type;

    /* limit is in seconds */
    int seconds;
    /* unix timestamp when time limit started */
    int seconds_started;

    /* limit is a count */
    int count;
};

struct flb_chunk_pipeline_context {
    flb_ctx_t *flb;
    flb_sds_t output_name;
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    struct mk_list *props;
    void *data;
    void *input;
    void *output;
};

struct flb_chunk_trace_context {
    void *input;
    int trace_count;
    struct flb_chunk_trace_limit limit;
    flb_sds_t trace_prefix;
    int to_destroy;
    int chunks;

    struct flb_chunk_pipeline_context pipeline;
};

struct flb_chunk_trace {
    struct flb_input_chunk *ic;
    struct flb_chunk_trace_context *ctxt;
    flb_sds_t trace_id;
    int tracer_versions;
};

struct flb_chunk_trace_context *flb_chunk_trace_context_new(void *input, const char *output_name, const char *trace_prefix, void *data, struct mk_list *props);
void flb_chunk_trace_context_destroy(void *input);
struct flb_chunk_trace *flb_chunk_trace_new(struct flb_input_chunk *chunk);
void flb_chunk_trace_destroy(struct flb_chunk_trace *);
int flb_chunk_trace_input(struct flb_chunk_trace *trace);
void flb_chunk_trace_do_input(struct flb_input_chunk *trace);
int flb_chunk_trace_pre_output(struct flb_chunk_trace *trace);
int flb_chunk_trace_filter(struct flb_chunk_trace *trace, void *pfilter, struct flb_time *, struct flb_time *, char *buf, size_t buf_size);
int flb_chunk_trace_output(struct flb_chunk_trace *trace, struct flb_output_instance *output, int ret);
void flb_chunk_trace_free(struct flb_chunk_trace *trace);
int flb_chunk_trace_context_set_limit(void *input, int, int);
int flb_chunk_trace_context_hit_limit(void *input);

#endif // FLB_CHUNK_TRACE_H
