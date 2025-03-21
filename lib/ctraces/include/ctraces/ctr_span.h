/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#ifndef CTR_SPAN_H
#define CTR_SPAN_H

#include <ctraces/ctraces.h>
#include <ctraces/ctr_scope.h>

/*
 * OpenTelemetry Trace Protobuf defition
 * -------------------------------------
 * https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/trace/v1/trace.proto
 */

/* Span kind */
#define CTRACE_SPAN_UNSPECIFIED   0
#define CTRACE_SPAN_INTERNAL      1
#define CTRACE_SPAN_SERVER        2
#define CTRACE_SPAN_CLIENT        3
#define CTRACE_SPAN_PRODUCER      4
#define CTRACE_SPAN_CONSUMER      5

/* Status code */
#define CTRACE_SPAN_STATUS_CODE_UNSET  0
#define CTRACE_SPAN_STATUS_CODE_OK     1
#define CTRACE_SPAN_STATUS_CODE_ERROR  2

struct ctrace_span_status {
    int code;
    cfl_sds_t message;
};

struct ctrace_span_event {
    uint64_t time_unix_nano;

    cfl_sds_t name;

    /* event attributes */
    struct ctrace_attributes *attr;

    /* number of attributes that were discarded */
    uint32_t dropped_attr_count;

    /* ---- INTERNAL --- */
    struct cfl_list _head;
};

/* Span */
struct ctrace_span {
    struct ctrace_id *trace_id;       /* the unique span ID    */
    struct ctrace_id *span_id;        /* the unique span ID    */
    struct ctrace_id *parent_span_id; /* any parent ? a NULL means a root span */
    cfl_sds_t trace_state;            /* trace state */
    int32_t flags;                    /* flags */

    cfl_sds_t name;                   /* user-name assigned */

    int kind;                         /* span kind */
    uint64_t start_time_unix_nano;    /* start time */
    uint64_t end_time_unix_nano;      /* end time */

    struct ctrace_attributes *attr;   /* attributes */
    uint32_t dropped_attr_count;      /* number of attributes that were discarded */

    struct cfl_list events;           /* events     */
    uint32_t dropped_events_count;    /* number of events that were discarded */

    struct cfl_list links;            /* links */
    uint32_t dropped_links_count;     /* number of links that were discarded */

    cfl_sds_t schema_url;             /* schema URL */

    struct ctrace_span_status status; /* status code */

    /* --- INTERNAL --- */

    /* link to 'struct scope_span->spans' list */
    struct cfl_list _head;

    /* link to global list on 'struct ctrace->span_list' */
    struct cfl_list _head_global;


    /* references from parent contexts */
    struct ctrace_scope_span *scope_span;
    struct ctrace *ctx;            /* parent ctrace context */
};

struct ctrace_span *ctr_span_create(struct ctrace *ctx, struct ctrace_scope_span *scope_span, cfl_sds_t name,
                                    struct ctrace_span *parent);

void ctr_span_destroy(struct ctrace_span *span);

/* Span fields */
int ctr_span_set_status(struct ctrace_span *span, int code, char *message);
void ctr_span_set_dropped_events_count(struct ctrace_span *span, uint32_t count);
void ctr_span_set_dropped_links_count(struct ctrace_span *span, uint32_t count);
int ctr_span_set_trace_state(struct ctrace_span *span, char *state, int len);
int ctr_span_set_flags(struct ctrace_span *span, uint32_t flags);
void ctr_span_set_schema_url(struct ctrace_span *span, char *url);

/* span IDs */
int ctr_span_set_trace_id(struct ctrace_span *span, void *buf, size_t len);
int ctr_span_set_trace_id_with_cid(struct ctrace_span *span, struct ctrace_id *cid);
int ctr_span_set_span_id(struct ctrace_span *span, void *buf, size_t len);
int ctr_span_set_span_id_with_cid(struct ctrace_span *span, struct ctrace_id *cid);
int ctr_span_set_parent_span_id(struct ctrace_span *span, void *buf, size_t len);
int ctr_span_set_parent_span_id_with_cid(struct ctrace_span *span, struct ctrace_id *cid);

/* attributes */
int ctr_span_set_attributes(struct ctrace_span *span, struct ctrace_attributes *attr);
int ctr_span_set_attribute_string(struct ctrace_span *span, char *key, char *value);
int ctr_span_set_attribute_bool(struct ctrace_span *span, char *key, int b);
int ctr_span_set_attribute_int64(struct ctrace_span *span, char *key, int64_t value);
int ctr_span_set_attribute_double(struct ctrace_span *span, char *key, double value);
int ctr_span_set_attribute_array(struct ctrace_span *span, char *key,
                                 struct cfl_array *value);
int ctr_span_set_attribute_kvlist(struct ctrace_span *span, char *key,
                                  struct cfl_kvlist *value);
void ctr_span_set_dropped_attributes_count(struct ctrace_span *span, uint32_t count);


/* time */
void ctr_span_start(struct ctrace *ctx, struct ctrace_span *span);
void ctr_span_start_ts(struct ctrace *ctx, struct ctrace_span *span, uint64_t ts);

void ctr_span_end(struct ctrace *ctx, struct ctrace_span *span);
void ctr_span_end_ts(struct ctrace *ctx, struct ctrace_span *span, uint64_t ts);

/* kind */
int ctr_span_kind_set(struct ctrace_span *span, int kind);
char *ctr_span_kind_string(struct ctrace_span *span);

/* events */
struct ctrace_span_event *ctr_span_event_add(struct ctrace_span *span, char *name);
struct ctrace_span_event *ctr_span_event_add_ts(struct ctrace_span *span, char *name, uint64_t ts);
int ctr_span_event_set_attributes(struct ctrace_span_event *event, struct ctrace_attributes *attr);
void ctr_span_event_set_dropped_attributes_count(struct ctrace_span_event *event, uint32_t count);
void ctr_span_event_delete(struct ctrace_span_event *event);

int ctr_span_event_set_attribute_string(struct ctrace_span_event *event, char *key, char *value);
int ctr_span_event_set_attribute_bool(struct ctrace_span_event *event, char *key, int b);
int ctr_span_event_set_attribute_int(struct ctrace_span_event *event, char *key, int value);
int ctr_span_event_set_attribute_double(struct ctrace_span_event *event, char *key, double value);
int ctr_span_event_set_attribute_array(struct ctrace_span_event *event, char *key,
                                       struct cfl_array *value);
int ctr_span_event_set_attribute_kvlist(struct ctrace_span_event *event, char *key,
                                        struct cfl_kvlist *value);

#endif
