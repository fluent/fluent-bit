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

#include <ctraces/ctraces.h>

#include <cfl/cfl.h>
#include <cfl/cfl_time.h>
#include <cfl/cfl_kvlist.h>

struct ctrace_span *ctr_span_create(struct ctrace *ctx, struct ctrace_scope_span *scope_span, cfl_sds_t name,
                                    struct ctrace_span *parent)
{
    struct ctrace_span *span;

    if (!ctx || !scope_span || !name) {
        return NULL;
    }

    /* allocate a spanc context */
    span = calloc(1, sizeof(struct ctrace_span));

    if (span == NULL) {
        ctr_errno();
        return NULL;
    }

    /* references */
    span->scope_span = scope_span;
    span->ctx = ctx;

    /* name */
    span->name = cfl_sds_create(name);
    if (span->name == NULL) {
        free(span);

        return NULL;
    }

    /* attributes */
    span->attr = ctr_attributes_create();
    if (span->attr == NULL) {
        cfl_sds_destroy(span->name);
        free(span);

        return NULL;
    }

    cfl_list_init(&span->events);
    cfl_list_init(&span->links);

    /* dropped attributes count */
    span->dropped_attr_count = 0;

    /* if a parent context was given, populate the span parent id */
    if (parent != NULL && parent->span_id != NULL) {
        ctr_span_set_parent_span_id_with_cid(span, parent->span_id);
    }

    /* link span to struct scope_span->spans */
    cfl_list_add(&span->_head, &scope_span->spans);

    /* link span to the struct ctrace->span_list */
    cfl_list_add(&span->_head_global, &ctx->span_list);

    /* set default kind */
    ctr_span_kind_set(span, CTRACE_SPAN_INTERNAL);

    /* always start a span by default, the start can be overriden later if needed */
    ctr_span_start(ctx, span);

    return span;
}

/* Set the Span ID with a given buffer and length */
int ctr_span_set_trace_id(struct ctrace_span *span, void *buf, size_t len)
{
    if (!buf || len <= 0) {
        return -1;
    }

    /* If trace_id is already set, free it first */
    if (span->trace_id != NULL) {
        ctr_id_destroy(span->trace_id);
        span->trace_id = NULL;
    }

    span->trace_id = ctr_id_create(buf, len);
    if (!span->trace_id) {
        return -1;
    }

    return 0;
}

/* Set the Span ID by using a ctrace_id context */
int ctr_span_set_trace_id_with_cid(struct ctrace_span *span, struct ctrace_id *cid)
{
    return ctr_span_set_trace_id(span,
                                 ctr_id_get_buf(cid),
                                 ctr_id_get_len(cid));
}

/* Set the Span ID with a given buffer and length */
int ctr_span_set_span_id(struct ctrace_span *span, void *buf, size_t len)
{
    if (!buf || len <= 0) {
        return -1;
    }
    if (span->span_id != NULL) {
        ctr_id_destroy(span->span_id);
    }
    span->span_id = ctr_id_create(buf, len);
    if (!span->span_id) {
        return -1;
    }

    return 0;
}

/* Set the Span ID by using a ctrace_id context */
int ctr_span_set_span_id_with_cid(struct ctrace_span *span, struct ctrace_id *cid)
{
    return ctr_span_set_span_id(span,
                                ctr_id_get_buf(cid),
                                ctr_id_get_len(cid));
}

/* Set the Span Parent ID with a given buffer and length */
int ctr_span_set_parent_span_id(struct ctrace_span *span, void *buf, size_t len)
{
    if (!buf || len <= 0) {
        return -1;
    }

    if (span->parent_span_id) {
        ctr_id_destroy(span->parent_span_id);
    }

    span->parent_span_id = ctr_id_create(buf, len);
    if (!span->parent_span_id) {
        return -1;
    }

    return 0;
}

/* Set the Span ID by using a ctrace_id context */
int ctr_span_set_parent_span_id_with_cid(struct ctrace_span *span, struct ctrace_id *cid)
{
    return ctr_span_set_parent_span_id(span,
                                       ctr_id_get_buf(cid),
                                       ctr_id_get_len(cid));
}

int ctr_span_kind_set(struct ctrace_span *span, int kind)
{
    if (kind < CTRACE_SPAN_UNSPECIFIED || kind > CTRACE_SPAN_CONSUMER) {
        return -1;
    }

    span->kind = kind;
    return 0;
}

/* returns a read-only version of the Span kind */
char *ctr_span_kind_string(struct ctrace_span *span)
{
    switch (span->kind) {
        case CTRACE_SPAN_INTERNAL:
            return "internal";
        case CTRACE_SPAN_SERVER:
            return "server";
        case CTRACE_SPAN_CLIENT:
            return "client";
        case CTRACE_SPAN_PRODUCER:
            return "producer";
        case CTRACE_SPAN_CONSUMER:
            return "consumer";
        default:
            return "unspecified";
    };
}

/*
 * Span attributes
 * ---------------
 */
int ctr_span_set_attributes(struct ctrace_span *span, struct ctrace_attributes *attr)
{
    if (!attr) {
        return -1;
    }

    if (span->attr) {
        ctr_attributes_destroy(span->attr);
    }

    span->attr = attr;
    return 0;
}

int ctr_span_set_attribute_string(struct ctrace_span *span, char *key, char *value)
{
    return ctr_attributes_set_string(span->attr, key, value);
}

int ctr_span_set_attribute_bool(struct ctrace_span *span, char *key, int b)
{
    return ctr_attributes_set_bool(span->attr, key, b);
}

int ctr_span_set_attribute_int64(struct ctrace_span *span, char *key, int64_t value)
{
    return ctr_attributes_set_int64(span->attr, key, value);
}

int ctr_span_set_attribute_double(struct ctrace_span *span, char *key, double value)
{
    return ctr_attributes_set_double(span->attr, key, value);
}

int ctr_span_set_attribute_array(struct ctrace_span *span, char *key,
                                 struct cfl_array *value)
{
    return ctr_attributes_set_array(span->attr, key, value);
}

int ctr_span_set_attribute_kvlist(struct ctrace_span *span, char *key,
                                  struct cfl_kvlist *value)
{

    return ctr_attributes_set_kvlist(span->attr, key, value);
}

void ctr_span_start(struct ctrace *ctx, struct ctrace_span *span)
{
    uint64_t ts;

    ts = cfl_time_now();
    ctr_span_start_ts(ctx, span, ts);
}

void ctr_span_start_ts(struct ctrace *ctx, struct ctrace_span *span, uint64_t ts)
{
    /* set the initial timestamp */
    span->start_time_unix_nano = ts;

    /* always set the span end time as the start time, so duration can be zero */
    ctr_span_end_ts(ctx, span, ts);
}

void ctr_span_end(struct ctrace *ctx, struct ctrace_span *span)
{
    uint64_t ts;

    ts = cfl_time_now();
    ctr_span_end_ts(ctx, span, ts);
}

void ctr_span_end_ts(struct ctrace *ctx, struct ctrace_span *span, uint64_t ts)
{
    span->end_time_unix_nano = ts;
}

int ctr_span_set_status(struct ctrace_span *span, int code, char *message)
{
    struct ctrace_span_status *status;

    status = &span->status;
    if (status->message) {
        cfl_sds_destroy(status->message);
    }

    if (message) {
        status->message = cfl_sds_create(message);
        if (!status->message) {
            return -1;
        }
    }

    status->code = code;
    return 0;
}

int ctr_span_set_trace_state(struct ctrace_span *span, char *state, int len)
{
    if (span->trace_state) {
        cfl_sds_destroy(span->trace_state);
    }

    span->trace_state = cfl_sds_create_len(state, len);
    if (!span->trace_state) {
        return -1;
    }

    return 0;
}

int ctr_span_set_flags(struct ctrace_span *span, uint32_t flags)
{
    span->flags = flags;
    return 0;
}

void ctr_span_set_schema_url(struct ctrace_span *span, char *url)
{
    if (span->schema_url) {
        cfl_sds_destroy(span->schema_url);
    }

    span->schema_url = cfl_sds_create(url);
}

void ctr_span_set_dropped_link_count(struct ctrace_span *span, uint32_t count)
{
    span->dropped_links_count = count;
}

void ctr_span_set_dropped_events_count(struct ctrace_span *span, uint32_t count)
{
    span->dropped_events_count = count;
}

void ctr_span_set_dropped_links_count(struct ctrace_span *span, uint32_t count)
{
    span->dropped_links_count = count;
}

void ctr_span_set_dropped_attributes_count(struct ctrace_span *span, uint32_t count)
{
    span->dropped_attr_count = count;
}

void ctr_span_destroy(struct ctrace_span *span)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct ctrace_span_event *event;
    struct ctrace_span_status *status;
    struct ctrace_link *link;

    if (span->name != NULL) {
        cfl_sds_destroy(span->name);
    }

    if (span->trace_id != NULL) {
        ctr_id_destroy(span->trace_id);
    }

    if (span->span_id != NULL) {
        ctr_id_destroy(span->span_id);
    }

    if (span->parent_span_id != NULL) {
        ctr_id_destroy(span->parent_span_id);
    }

    /* attributes */
    if (span->attr != NULL) {
        ctr_attributes_destroy(span->attr);
    }
    if (span->trace_state != NULL) {
        cfl_sds_destroy(span->trace_state);
    }

    if (span->schema_url != NULL) {
        cfl_sds_destroy(span->schema_url);
    }

    /* events */
    cfl_list_foreach_safe(head, tmp, &span->events) {
        event = cfl_list_entry(head, struct ctrace_span_event, _head);
        ctr_span_event_delete(event);
    }

    /* links */
    cfl_list_foreach_safe(head, tmp, &span->links) {
        link = cfl_list_entry(head, struct ctrace_link, _head);
        ctr_link_destroy(link);
    }

    /* status */
    status = &span->status;
    if (status->message != NULL) {
        cfl_sds_destroy(status->message);
    }

    cfl_list_del(&span->_head);
    cfl_list_del(&span->_head_global);
    free(span);
}

/*
 * Span Events
 * -----------
 */
struct ctrace_span_event *ctr_span_event_add_ts(struct ctrace_span *span, char *name, uint64_t ts)
{
    struct ctrace_span_event *ev;

    if (name == NULL) {
        return NULL;
    }

    ev = calloc(1, sizeof(struct ctrace_span_event));
    if (ev == NULL) {
        ctr_errno();
        return NULL;
    }
    ev->name = cfl_sds_create(name);
    if (ev->name == NULL) {
        free(ev);
        return NULL;
    }
    ev->attr = ctr_attributes_create();
    ev->dropped_attr_count = 0;

    /* if no timestamp is given, use the current time */
    if (ts == 0) {
        ev->time_unix_nano = cfl_time_now();
    }
    else {
        ev->time_unix_nano = ts;
    }

    cfl_list_add(&ev->_head, &span->events);
    return ev;
}

struct ctrace_span_event *ctr_span_event_add(struct ctrace_span *span, char *name)
{
    return ctr_span_event_add_ts(span, name, 0);
}

int ctr_span_event_set_attribute_string(struct ctrace_span_event *event, char *key, char *value)
{
    return ctr_attributes_set_string(event->attr, key, value);
}

int ctr_span_event_set_attribute_bool(struct ctrace_span_event *event, char *key, int b)
{
    return ctr_attributes_set_bool(event->attr, key, b);
}

int ctr_span_event_set_attribute_int64(struct ctrace_span_event *event, char *key, int64_t value)
{
    return ctr_attributes_set_int64(event->attr, key, value);
}

int ctr_span_event_set_attribute_double(struct ctrace_span_event *event, char *key, double value)
{
    return ctr_attributes_set_double(event->attr, key, value);
}

int ctr_span_event_set_attribute_array(struct ctrace_span_event *event, char *key,
                                       struct cfl_array *value)
{
    return ctr_attributes_set_array(event->attr, key, value);
}

int ctr_span_event_set_attribute_kvlist(struct ctrace_span_event *event, char *key,
                                        struct cfl_kvlist *value)
{

    return ctr_attributes_set_kvlist(event->attr, key, value);
}

int ctr_span_event_set_attributes(struct ctrace_span_event *event, struct ctrace_attributes *attr)
{
    if (!attr) {
        return -1;
    }

    if (event->attr) {
        ctr_attributes_destroy(event->attr);
    }

    event->attr = attr;
    return 0;
}

void ctr_span_event_set_dropped_attributes_count(struct ctrace_span_event *event, uint32_t count)
{
    event->dropped_attr_count = count;
}

void ctr_span_event_delete(struct ctrace_span_event *event)
{
    if (event->name) {
        cfl_sds_destroy(event->name);
    }

    if (event->attr) {
        ctr_attributes_destroy(event->attr);
    }

    cfl_list_del(&event->_head);
    free(event);
}

