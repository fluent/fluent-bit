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

/*
 * Summaries
 * =========
 * Once per window every pattern that lost records gets one summary record:
 * the template as the message plus how many records were seen, kept and
 * dropped. Kept records and summaries together account for the whole stream,
 * also for a pattern that went quiet right after its last drop.
 *
 * Attached to an input, summaries are produced by the timer and enter the
 * pipeline after this processor, so they are sent even when the input is
 * idle. Attached to an output, they are added to the next chunk that goes
 * through, because nothing can be injected into a single route.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "adaptive.h"

#define SUMMARY_EVICTED   "<evicted>"

struct summary_values {
    uint64_t id;
    const char *template_str;
    size_t template_len;
    uint64_t count;
    uint64_t kept;
    uint64_t dropped;
    uint64_t bytes_dropped;
};

typedef int (*summary_sink) (struct adaptive_ctx *ctx, struct cfl_kvlist *body,
                             uint64_t now, void *data);

int adaptive_summary_due(struct adaptive_ctx *ctx, uint64_t now)
{
    return ctx->summary && ctx->enforce &&
           now / ctx->policy->window_ns != ctx->summary_window;
}

int adaptive_summary_is_record(struct adaptive_ctx *ctx, struct cfl_kvlist *body)
{
    struct cfl_variant *variant;

    variant = cfl_kvlist_fetch_s(body, ctx->annotate_key, cfl_sds_len(ctx->annotate_key));
    if (!variant || variant->type != CFL_VARIANT_KVLIST) {
        return FLB_FALSE;
    }

    return cfl_kvlist_fetch_s(variant->data.as_kvlist, "summary", 7) != NULL;
}

static void summary_count(struct adaptive_ctx *ctx, const char *status, uint64_t records)
{
    char *labels[6];

    if (!ctx->cmt_summaries || records == 0) {
        return;
    }

    adaptive_labels(ctx, labels);
    labels[5] = (char *) status;
    cmt_counter_add(ctx->cmt_summaries, cfl_time_now(), (double) records, 6, labels);
}

static struct cfl_kvlist *summary_body(struct adaptive_ctx *ctx, struct adaptive_group *group,
                                       struct summary_values *values)
{
    int ret;
    char id[17];
    struct cfl_kvlist *body;
    struct cfl_kvlist *info;
    struct flb_slist_entry *key;

    body = cfl_kvlist_create();
    info = cfl_kvlist_create();
    if (!body || !info) {
        if (body) {
            cfl_kvlist_destroy(body);
        }
        if (info) {
            cfl_kvlist_destroy(info);
        }
        return NULL;
    }

    snprintf(id, sizeof(id), "%016" PRIx64, values->id);

    ret = cfl_kvlist_insert_bool(info, "summary", CFL_TRUE);
    if (ret == 0) {
        ret = cfl_kvlist_insert_string_s(info, "pattern_id", 10, id, 16, CFL_FALSE);
    }
    if (ret == 0 && !cfl_list_is_empty(&ctx->selectors)) {
        ret = cfl_kvlist_insert_string_s(info, "group", 5, group->key,
                                         cfl_sds_len(group->key), CFL_FALSE);
    }
    if (ret == 0) {
        ret = cfl_kvlist_insert_int64(info, "window", ctx->window);
    }
    if (ret == 0) {
        ret = cfl_kvlist_insert_int64(info, "count", (int64_t) values->count);
    }
    if (ret == 0) {
        ret = cfl_kvlist_insert_int64(info, "kept", (int64_t) values->kept);
    }
    if (ret == 0) {
        ret = cfl_kvlist_insert_int64(info, "dropped", (int64_t) values->dropped);
    }
    if (ret == 0) {
        ret = cfl_kvlist_insert_int64(info, "bytes_dropped", (int64_t) values->bytes_dropped);
    }
    if (ret != 0) {
        cfl_kvlist_destroy(body);
        cfl_kvlist_destroy(info);
        return NULL;
    }

    /* the template stands where the message of the dropped records was */
    key = mk_list_entry_first(ctx->keys, struct flb_slist_entry, _head);
    ret = cfl_kvlist_insert_string_s(body, key->str, flb_sds_len(key->str),
                                     (char *) values->template_str, values->template_len,
                                     CFL_FALSE);
    if (ret != 0) {
        cfl_kvlist_destroy(body);
        cfl_kvlist_destroy(info);
        return NULL;
    }

    ret = cfl_kvlist_insert_kvlist_s(body, ctx->annotate_key,
                                     cfl_sds_len(ctx->annotate_key), info);
    if (ret != 0) {
        cfl_kvlist_destroy(body);
        cfl_kvlist_destroy(info);
        return NULL;
    }

    return body;
}

/* Hand one summary per pattern with drops to the sink. Returns the number */
static int group_emit(struct adaptive_ctx *ctx, struct adaptive_group *group, uint64_t now,
                      summary_sink sink, void *data)
{
    int count = 0;
    struct cfl_list *head;
    struct cfl_kvlist *body;
    struct adaptive_pattern *pattern;
    struct summary_values values;

    cfl_list_foreach(head, &group->miner->lru) {
        pattern = cfl_list_entry(head, struct adaptive_pattern, _lru);
        if (pattern->dropped == pattern->sum_dropped) {
            continue;
        }

        values.id = pattern->id;
        values.template_str = pattern->template_str;
        values.template_len = cfl_sds_len(pattern->template_str);
        values.count = pattern->count - pattern->sum_count;
        values.kept = pattern->kept - pattern->sum_kept;
        values.dropped = pattern->dropped - pattern->sum_dropped;
        values.bytes_dropped = pattern->bytes_dropped - pattern->sum_bytes_dropped;

        body = summary_body(ctx, group, &values);
        if (!body || sink(ctx, body, now, data) != 0) {
            return -1;
        }
        count++;
    }

    if (group->lost_dropped > 0) {
        values.id = 0;
        values.template_str = SUMMARY_EVICTED;
        values.template_len = sizeof(SUMMARY_EVICTED) - 1;
        values.count = group->lost_count;
        values.kept = group->lost_kept;
        values.dropped = group->lost_dropped;
        values.bytes_dropped = group->lost_bytes_dropped;

        body = summary_body(ctx, group, &values);
        if (!body || sink(ctx, body, now, data) != 0) {
            return -1;
        }
        count++;
    }

    return count;
}

/* The summaries of this group were delivered: start counting again */
static void group_mark(struct adaptive_group *group)
{
    struct cfl_list *head;
    struct adaptive_pattern *pattern;

    cfl_list_foreach(head, &group->miner->lru) {
        pattern = cfl_list_entry(head, struct adaptive_pattern, _lru);
        pattern->sum_count = pattern->count;
        pattern->sum_kept = pattern->kept;
        pattern->sum_dropped = pattern->dropped;
        pattern->sum_bytes_dropped = pattern->bytes_dropped;
    }

    group->lost_count = 0;
    group->lost_kept = 0;
    group->lost_dropped = 0;
    group->lost_bytes_dropped = 0;
}

static int sink_chunk(struct adaptive_ctx *ctx, struct cfl_kvlist *body,
                      uint64_t now, void *data)
{
    struct cfl_kvlist *metadata = NULL;
    struct cfl_object *cobj_body = NULL;
    struct cfl_object *cobj_metadata = NULL;
    struct flb_mp_chunk_record *record;
    struct flb_mp_chunk_cobj *chunk_cobj = data;

    (void) ctx;

    metadata = cfl_kvlist_create();
    cobj_body = cfl_object_create();
    cobj_metadata = cfl_object_create();
    if (!metadata || !cobj_body || !cobj_metadata) {
        goto error;
    }

    record = flb_mp_chunk_record_create(chunk_cobj);
    if (!record) {
        goto error;
    }

    cfl_object_set(cobj_body, CFL_OBJECT_KVLIST, body);
    cfl_object_set(cobj_metadata, CFL_OBJECT_KVLIST, metadata);

    flb_time_from_uint64(&record->event.timestamp, now);
    record->cobj_record = cobj_body;
    record->cobj_metadata = cobj_metadata;
    record->modified = FLB_TRUE;
    cfl_list_add(&record->_head, &chunk_cobj->records);

    return 0;

error:
    cfl_kvlist_destroy(body);
    if (metadata) {
        cfl_kvlist_destroy(metadata);
    }
    if (cobj_body) {
        cfl_object_destroy(cobj_body);
    }
    if (cobj_metadata) {
        cfl_object_destroy(cobj_metadata);
    }

    return -1;
}

/* Add the pending summaries to the chunk being processed */
int adaptive_summary_append(struct adaptive_ctx *ctx,
                            struct flb_mp_chunk_cobj *chunk_cobj, uint64_t now)
{
    int ret;
    int total = 0;
    struct cfl_list *head;
    struct adaptive_group *group;

    cfl_list_foreach(head, &ctx->groups) {
        group = cfl_list_entry(head, struct adaptive_group, _head);
        ret = group_emit(ctx, group, now, sink_chunk, chunk_cobj);
        if (ret < 0) {
            /* what was added stays, the rest is counted again next time */
            ctx->summary_failures++;
            summary_count(ctx, "failed", 1);
            break;
        }
        group_mark(group);
        total += ret;
    }

    ctx->summary_window = now / ctx->policy->window_ns;
    ctx->summary_records += total;
    summary_count(ctx, "emitted", total);

    return total;
}

static int sink_encoder(struct adaptive_ctx *ctx, struct cfl_kvlist *body,
                        uint64_t now, void *data)
{
    int ret;
    char *buf = NULL;
    size_t size = 0;
    struct flb_time tm;
    struct cfl_object *cobj;
    struct flb_log_event_encoder *encoder = data;

    (void) ctx;

    cobj = cfl_object_create();
    if (!cobj) {
        cfl_kvlist_destroy(body);
        return -1;
    }
    cfl_object_set(cobj, CFL_OBJECT_KVLIST, body);

    ret = flb_mp_cfl_to_msgpack(cobj, &buf, &size);
    cfl_object_destroy(cobj);
    if (ret != 0) {
        return -1;
    }

    flb_time_from_uint64(&tm, now);

    ret = flb_log_event_encoder_begin_record(encoder);
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_timestamp(encoder, &tm);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_body_from_raw_msgpack(encoder, buf, size);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(encoder);
    }
    else {
        flb_log_event_encoder_rollback_record(encoder);
    }
    flb_free(buf);

    return ret == FLB_EVENT_ENCODER_SUCCESS ? 0 : -1;
}

/*
 * Encode the pending summaries of every group as log records. Returns how
 * many were written, the caller owns what the encoder holds.
 */
int adaptive_summary_encode(struct adaptive_ctx *ctx, struct flb_log_event_encoder *encoder,
                            uint64_t now)
{
    int ret;
    int total = 0;
    struct cfl_list *head;
    struct adaptive_group *group;

    cfl_list_foreach(head, &ctx->groups) {
        group = cfl_list_entry(head, struct adaptive_group, _head);
        ret = group_emit(ctx, group, now, sink_encoder, encoder);
        if (ret < 0) {
            /* what was encoded stays, the rest is counted again next time */
            ctx->summary_failures++;
            summary_count(ctx, "failed", 1);
            break;
        }
        group_mark(group);
        total += ret;
    }

    ctx->summary_window = now / ctx->policy->window_ns;
    ctx->summary_records += total;
    summary_count(ctx, "emitted", total);

    return total;
}

/* Send the pending summaries into the input, after this processor */
int adaptive_summary_ingress(struct adaptive_ctx *ctx, uint64_t now)
{
    int ret;
    int total = 0;
    void *buf;
    size_t size;
    struct cfl_list *head;
    struct adaptive_group *group;
    struct flb_log_event_encoder *encoder;

    cfl_list_foreach(head, &ctx->groups) {
        group = cfl_list_entry(head, struct adaptive_group, _head);
        if (!group->tag) {
            continue;
        }

        encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
        if (!encoder) {
            return -1;
        }

        ret = group_emit(ctx, group, now, sink_encoder, encoder);
        if (ret > 0) {
            buf = encoder->output_buffer;
            size = encoder->output_length;
            flb_log_event_encoder_claim_internal_buffer_ownership(encoder);

            if (flb_input_ingress_try_resume_log(ctx->input, ctx->ins->pu->stage + 1,
                                                 group->tag, cfl_sds_len(group->tag),
                                                 &buf, size, ret) == 0) {
                group_mark(group);
                total += ret;
            }
            else {
                /* the queue is full: the counts stay and go out next time */
                ret = -1;
            }
            if (buf) {
                flb_free(buf);
            }
        }
        flb_log_event_encoder_destroy(encoder);

        if (ret < 0) {
            ctx->summary_failures++;
            summary_count(ctx, "failed", 1);
        }
    }

    ctx->summary_window = now / ctx->policy->window_ns;
    ctx->summary_records += total;
    summary_count(ctx, "emitted", total);

    return total;
}
