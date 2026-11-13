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
 * Fast path
 * =========
 * The usual way through a processor turns every record of a chunk into an
 * object tree and encodes the survivors again. Most records this processor
 * sees are either dropped or kept exactly as they came, so here the chunk is
 * walked as MessagePack instead:
 *
 *  - a record that is kept untouched is copied as bytes;
 *  - a record that is dropped is skipped;
 *  - only a record that gets an annotation is packed again.
 *
 * Nothing is written while the output would be equal to the input: a chunk
 * where every record is kept as it came is returned as untouched.
 *
 * The decisions are the same as in cb_process_logs(). Records whose message
 * is not a plain string (a map under the key, or no message at all) are
 * converted one by one and go through adaptive_source_resolve().
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <msgpack.h>

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "adaptive.h"

/* The output of one chunk, started only when it differs from the input */
struct raw_out {
    int started;
    int failed;
    const char *data;           /* the input                              */
    const char *group_start;    /* group opener not written yet           */
    size_t group_start_len;
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
};

static msgpack_object *map_get(msgpack_object *map, const char *key, size_t len)
{
    uint32_t i;
    msgpack_object_kv *kv;

    if (!map || map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    for (i = 0; i < map->via.map.size; i++) {
        kv = &map->via.map.ptr[i];
        if (kv->key.type == MSGPACK_OBJECT_STR && kv->key.via.str.size == len &&
            memcmp(kv->key.via.str.ptr, key, len) == 0) {
            return &kv->val;
        }
    }

    return NULL;
}

static void out_write(struct raw_out *out, const char *buf, size_t len)
{
    if (len > 0 && msgpack_sbuffer_write(&out->sbuf, buf, len) != 0) {
        out->failed = FLB_TRUE;
    }
}

/*
 * From here on the output is written: everything before 'upto' was kept as
 * it came. A group opener with no record kept after it stays pending.
 */
static void out_start(struct raw_out *out, const char *upto)
{
    if (out->started) {
        return;
    }
    out->started = FLB_TRUE;

    if (out->group_start) {
        upto = out->group_start;
    }
    out_write(out, out->data, upto - out->data);
}

/* A record is about to be written: its group has to be open before it */
static void out_group_open(struct raw_out *out)
{
    if (out->group_start) {
        if (out->started) {
            out_write(out, out->group_start, out->group_start_len);
        }
        out->group_start = NULL;
    }
}

static int raw_summary_is_record(struct adaptive_ctx *ctx, msgpack_object *body)
{
    msgpack_object *info;

    info = map_get(body, ctx->annotate_key, cfl_sds_len(ctx->annotate_key));

    return info && info->type == MSGPACK_OBJECT_MAP && map_get(info, "summary", 7) != NULL;
}

/*
 * Find what the record is mined by. Returns FLB_FALSE when the record needs
 * the object based resolver: its message is a map, or it has no message.
 */
static int raw_source(struct adaptive_ctx *ctx, msgpack_object *body,
                      struct adaptive_source *source)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;
    msgpack_object *value;

    source->type = ADAPTIVE_SOURCE_NONE;
    source->str = NULL;
    source->len = 0;
    source->level = NULL;
    source->level_len = 0;

    mk_list_foreach(head, ctx->keys) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        value = map_get(body, entry->str, flb_sds_len(entry->str));
        if (!value) {
            continue;
        }

        if (value->type == MSGPACK_OBJECT_STR) {
            adaptive_source_from_text(ctx, value->via.str.ptr, value->via.str.size, source);
            return FLB_TRUE;
        }

        if (value->type == MSGPACK_OBJECT_MAP && ctx->structured) {
            return FLB_FALSE;
        }
    }

    if (ctx->structured && body->via.map.size > 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static size_t key_append_object(char *buf, size_t used, msgpack_object *value)
{
    int len;
    char tmp[32];

    if (!value) {
        return adaptive_group_key_append(buf, used, "-", 1);
    }

    if (value->type == MSGPACK_OBJECT_STR) {
        return adaptive_group_key_append(buf, used, value->via.str.ptr, value->via.str.size);
    }
    else if (value->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        len = snprintf(tmp, sizeof(tmp), "%" PRIu64, value->via.u64);
    }
    else if (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        len = snprintf(tmp, sizeof(tmp), "%" PRId64, value->via.i64);
    }
    else if (value->type == MSGPACK_OBJECT_BOOLEAN) {
        len = snprintf(tmp, sizeof(tmp), "%s", value->via.boolean ? "true" : "false");
    }
    else {
        return adaptive_group_key_append(buf, used, "-", 1);
    }

    return adaptive_group_key_append(buf, used, tmp, len);
}

static struct adaptive_group *raw_group(struct adaptive_ctx *ctx, struct flb_log_event *event,
                                        const char *tag, int tag_len, uint64_t now)
{
    int i;
    size_t used = 0;
    char *buf = ctx->group_buf;
    struct cfl_list *head;
    struct adaptive_selector *selector;
    msgpack_object *value;

    cfl_list_foreach(head, &ctx->selectors) {
        selector = cfl_list_entry(head, struct adaptive_selector, _head);

        if (used > 0) {
            used = adaptive_group_key_append(buf, used, "/", 1);
        }

        if (selector->type == ADAPTIVE_SELECT_TAG) {
            used = adaptive_group_key_append(buf, used, tag ? tag : "-",
                                             tag ? (size_t) tag_len : 1);
            continue;
        }

        if (selector->type == ADAPTIVE_SELECT_RESOURCE) {
            /* OTLP groups carry {"resource": {"attributes": {...}}, "scope": {...}} */
            value = map_get(event->group_attributes, "resource", 8);
            value = map_get(value, "attributes", 10);
            value = map_get(value, selector->parts[0], cfl_sds_len(selector->parts[0]));
        }
        else {
            value = event->body;
            for (i = 0; i < selector->part_count && value; i++) {
                value = map_get(value, selector->parts[i], cfl_sds_len(selector->parts[i]));
            }
        }
        used = key_append_object(buf, used, value);
    }

    return adaptive_group_by_key(ctx, used, tag, tag_len, now);
}

static int raw_is_protected(struct adaptive_ctx *ctx, struct flb_log_event *event,
                            struct adaptive_source *source)
{
    const char *name;
    msgpack_object *otlp;
    msgpack_object *value;

    if (ctx->protect_levels) {
        /* the severity found next to a nested or JSON message comes first */
        if (source->level &&
            adaptive_level_is_protected(ctx, source->level, source->level_len)) {
            return FLB_TRUE;
        }

        if (ctx->level_key) {
            value = map_get(event->body, ctx->level_key, cfl_sds_len(ctx->level_key));
            if (value && value->type == MSGPACK_OBJECT_STR &&
                adaptive_level_is_protected(ctx, value->via.str.ptr, value->via.str.size)) {
                return FLB_TRUE;
            }
        }

        /* OTLP logs carry their severity in the record metadata */
        otlp = map_get(event->metadata, "otlp", 4);
        value = map_get(otlp, "severity_text", 13);
        if (value && value->type == MSGPACK_OBJECT_STR &&
            adaptive_level_is_protected(ctx, value->via.str.ptr, value->via.str.size)) {
            return FLB_TRUE;
        }

        value = map_get(otlp, "severity_number", 15);
        if (value && (value->type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
                      value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER)) {
            name = adaptive_otlp_severity_name(value->via.i64);
            if (name && adaptive_level_is_protected(ctx, name, strlen(name))) {
                return FLB_TRUE;
            }
        }
    }

    if (ctx->protect_regex &&
        flb_regex_match(ctx->protect_regex, (unsigned char *) source->str, source->len) > 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static void pack_str(msgpack_packer *pck, const char *str, size_t len)
{
    msgpack_pack_str(pck, len);
    msgpack_pack_str_body(pck, str, len);
}

/* The record again, with the annotation map as its last key */
static void pack_annotated(struct adaptive_ctx *ctx, msgpack_packer *pck,
                           struct flb_log_event *event, struct adaptive_pattern *pattern,
                           struct adaptive_decision *decision)
{
    int fields = 0;
    char id[17];
    uint32_t i;
    uint32_t keys = 0;
    size_t key_len = cfl_sds_len(ctx->annotate_key);
    msgpack_object_kv *kv;
    msgpack_object *body = event->body;

    /* an annotation left by an earlier instance is replaced */
    for (i = 0; i < body->via.map.size; i++) {
        kv = &body->via.map.ptr[i];
        if (kv->key.type == MSGPACK_OBJECT_STR && kv->key.via.str.size == key_len &&
            memcmp(kv->key.via.str.ptr, ctx->annotate_key, key_len) == 0) {
            continue;
        }
        keys++;
    }

    msgpack_pack_array(pck, 2);
    msgpack_pack_object(pck, event->root->via.array.ptr[0]);

    msgpack_pack_map(pck, keys + 1);
    for (i = 0; i < body->via.map.size; i++) {
        kv = &body->via.map.ptr[i];
        if (kv->key.type == MSGPACK_OBJECT_STR && kv->key.via.str.size == key_len &&
            memcmp(kv->key.via.str.ptr, ctx->annotate_key, key_len) == 0) {
            continue;
        }
        msgpack_pack_object(pck, kv->key);
        msgpack_pack_object(pck, kv->val);
    }

    fields += ctx->annotate_pattern_id ? 1 : 0;
    fields += decision->action == ADAPTIVE_DROP ? 1 : 0;
    fields += decision->suppressed > 0 ? 1 : 0;
    fields += decision->sample_rate > 1 ? 1 : 0;
    fields += ctx->annotate_template ? 1 : 0;

    pack_str(pck, ctx->annotate_key, key_len);
    msgpack_pack_map(pck, fields);

    if (ctx->annotate_pattern_id) {
        snprintf(id, sizeof(id), "%016" PRIx64, pattern->id);
        pack_str(pck, "pattern_id", 10);
        pack_str(pck, id, 16);
    }
    if (decision->action == ADAPTIVE_DROP) {
        pack_str(pck, "decision", 8);
        pack_str(pck, "drop", 4);
    }
    if (decision->suppressed > 0) {
        pack_str(pck, "suppressed", 10);
        msgpack_pack_int64(pck, (int64_t) decision->suppressed);
    }
    if (decision->sample_rate > 1) {
        pack_str(pck, "sample_rate", 11);
        msgpack_pack_int64(pck, (int64_t) decision->sample_rate);
    }
    if (ctx->annotate_template) {
        pack_str(pck, "template", 8);
        pack_str(pck, pattern->template_str, cfl_sds_len(pattern->template_str));
    }
}

/* On an output the summaries of a closed window ride on the chunk at hand */
static void raw_summaries(struct adaptive_ctx *ctx, struct raw_out *out,
                          const char *end, uint64_t now)
{
    struct flb_log_event_encoder *encoder;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!encoder) {
        return;
    }

    if (adaptive_summary_encode(ctx, encoder, now) > 0 && encoder->output_length > 0) {
        out_start(out, end);
        out_write(out, encoder->output_buffer, encoder->output_length);
    }

    flb_log_event_encoder_destroy(encoder);
}

int adaptive_raw_process(struct adaptive_ctx *ctx, const void *data, size_t bytes,
                         void **out_buf, size_t *out_size, const char *tag, int tag_len,
                         uint64_t now, struct adaptive_totals *delta)
{
    int ret;
    int is_new;
    int changed;
    int is_protected;
    int32_t record_type;
    size_t length;
    const char *base;
    struct raw_out out;
    struct cfl_object *cobj;
    struct adaptive_source source;
    struct adaptive_decision decision;
    struct adaptive_group *group;
    struct adaptive_pattern *pattern;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;

    *out_buf = NULL;
    *out_size = 0;

    ret = flb_log_event_decoder_init(&decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        return FLB_PROCESSOR_RAW_UNSUPPORTED;
    }
    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);

    memset(&out, 0, sizeof(out));
    out.data = data;
    msgpack_sbuffer_init(&out.sbuf);
    msgpack_packer_init(&out.pck, &out.sbuf, msgpack_sbuffer_write);

    while (flb_log_event_decoder_next(&decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {
        base = decoder.record_base;
        length = decoder.record_length;

        if (flb_log_event_decoder_get_record_type(&event, &record_type) != 0) {
            record_type = FLB_LOG_EVENT_NORMAL;
        }

        /* group envelopes are written only around records that are kept */
        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            out.group_start = base;
            out.group_start_len = length;
            continue;
        }
        else if (record_type == FLB_LOG_EVENT_GROUP_END) {
            if (out.started && !out.group_start) {
                out_write(&out, base, length);
            }
            out.group_start = NULL;
            continue;
        }

        delta->records++;
        cobj = NULL;
        pattern = NULL;
        group = NULL;

        if (event.body && event.body->type == MSGPACK_OBJECT_MAP &&
            event.root && event.root->type == MSGPACK_OBJECT_ARRAY &&
            event.root->via.array.size == 2 && !raw_summary_is_record(ctx, event.body)) {
            if (!raw_source(ctx, event.body, &source)) {
                /* uncommon shape: let the object based resolver read it */
                source.type = ADAPTIVE_SOURCE_NONE;
                cobj = flb_mp_object_to_cfl(event.body);
                if (cobj && cobj->variant && cobj->variant->type == CFL_VARIANT_KVLIST) {
                    adaptive_source_resolve(ctx, cobj->variant->data.as_kvlist, &source);
                }
            }

            if (source.type != ADAPTIVE_SOURCE_NONE) {
                group = raw_group(ctx, &event, tag, tag_len, now);
            }
            if (group) {
                pattern = adaptive_miner_process(group->miner, source.str, source.len, now,
                                                 &is_new, &changed);
            }
        }

        if (!pattern) {
            /* not a log line this processor can read: it passes as it came */
            delta->unmatched++;
            delta->by_reason[ADAPTIVE_KEEP][ADAPTIVE_REASON_UNMATCHED]++;
            out_group_open(&out);
            if (out.started) {
                out_write(&out, base, length);
            }
            if (cobj) {
                cfl_object_destroy(cobj);
            }
            continue;
        }

        if (is_new && ctx->report_exemplars) {
            pattern->exemplar = cfl_sds_create_len(source.str,
                                                   source.len > ADAPTIVE_EXEMPLAR_MAX ?
                                                   ADAPTIVE_EXEMPLAR_MAX : source.len);
        }

        is_protected = raw_is_protected(ctx, &event, &source);
        adaptive_policy_decide(ctx->policy, pattern, source.len, now, is_protected, &decision);

        delta->bytes += source.len;
        delta->by_reason[decision.action][decision.reason]++;

        if (cobj) {
            cfl_object_destroy(cobj);
        }

        if (decision.action == ADAPTIVE_DROP) {
            delta->dropped++;
            delta->bytes_dropped += source.len;
            if (ctx->enforce) {
                out_start(&out, base);
                continue;
            }
        }
        else {
            delta->kept++;
        }

        if (ctx->annotate && adaptive_annotation_needed(ctx, &decision)) {
            out_start(&out, base);
            out_group_open(&out);
            pack_annotated(ctx, &out.pck, &event, pattern, &decision);
            continue;
        }

        out_group_open(&out);
        if (out.started) {
            out_write(&out, base, length);
        }
    }

    /* bytes the decoder could not read are passed on, never lost */
    if (out.started && decoder.offset < bytes) {
        out_write(&out, (const char *) data + decoder.offset, bytes - decoder.offset);
    }
    flb_log_event_decoder_destroy(&decoder);

    if (!ctx->ingress && adaptive_summary_due(ctx, now)) {
        out.group_start = NULL;
        raw_summaries(ctx, &out, (const char *) data + bytes, now);
    }

    if (out.failed) {
        msgpack_sbuffer_destroy(&out.sbuf);
        return FLB_PROCESSOR_FAILURE;
    }

    if (!out.started) {
        msgpack_sbuffer_destroy(&out.sbuf);
        return FLB_PROCESSOR_RAW_NOTOUCH;
    }

    if (out.sbuf.size == 0) {
        /* every record was removed: the caller still expects an allocation */
        msgpack_sbuffer_destroy(&out.sbuf);
        *out_buf = flb_malloc(1);
        if (!*out_buf) {
            flb_errno();
            return FLB_PROCESSOR_FAILURE;
        }
        return FLB_PROCESSOR_RAW_MODIFIED;
    }

    *out_buf = out.sbuf.data;
    *out_size = out.sbuf.size;

    return FLB_PROCESSOR_RAW_MODIFIED;
}
