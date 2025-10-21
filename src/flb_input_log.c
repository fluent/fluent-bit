/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_conditionals.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>

#include <stdint.h>
#include <string.h>

struct flb_route_payload {
    struct flb_route *route;
    int is_default;
    flb_sds_t tag;
    char *data;
    size_t size;
    size_t total_records;
    struct mk_list _head;
};

static void route_payload_destroy(struct flb_route_payload *payload)
{
    if (!payload) {
        return;
    }

    if (!mk_list_entry_is_orphan(&payload->_head)) {
        mk_list_del(&payload->_head);
    }

    if (payload->tag) {
        flb_sds_destroy(payload->tag);
    }

    if (payload->data) {
        flb_free(payload->data);
    }

    flb_free(payload);
}

static struct flb_route_payload *route_payload_find(struct mk_list *payloads,
                                                    struct flb_route *route)
{
    struct mk_list *head;
    struct flb_route_payload *payload;

    if (!payloads || !route) {
        return NULL;
    }

    mk_list_foreach(head, payloads) {
        payload = mk_list_entry(head, struct flb_route_payload, _head);

        if (payload->route == route) {
            return payload;
        }
    }

    return NULL;
}

static int append_output_to_payload_tag(struct flb_route_payload *payload,
                                        struct flb_output_instance *out)
{
    const char *identifier;

    if (!payload || !out) {
        return -1;
    }

    if (out->alias) {
        identifier = out->alias;
    }
    else {
        identifier = flb_output_name(out);
    }

    if (!identifier) {
        return -1;
    }

    if (!payload->tag) {
        payload->tag = flb_sds_create(identifier);
        if (!payload->tag) {
            return -1;
        }
    }
    else {
        payload->tag = flb_sds_cat(payload->tag, ",", 1);
        if (!payload->tag) {
            return -1;
        }

        payload->tag = flb_sds_cat(payload->tag, identifier, strlen(identifier));
        if (!payload->tag) {
            return -1;
        }
    }

    return 0;
}

static int encode_empty_map(char **out_buf, size_t *out_size)
{
    char *buf;

    if (!out_buf || !out_size) {
        return -1;
    }

    buf = flb_malloc(1);
    if (!buf) {
        flb_errno();
        return -1;
    }

    buf[0] = 0x80;

    *out_buf = buf;
    *out_size = 1;

    return 0;
}

static int encode_cfl_object_or_empty(struct cfl_object *obj,
                                      char **out_buf,
                                      size_t *out_size)
{
    if (!out_buf || !out_size) {
        return -1;
    }

    if (obj) {
        return flb_mp_cfl_to_msgpack(obj, out_buf, out_size);
    }

    return encode_empty_map(out_buf, out_size);
}

static int encode_chunk_record(struct flb_log_event_encoder *encoder,
                               struct flb_mp_chunk_record *record)
{
    int ret;
    int record_type;
    char *mp_buf = NULL;
    size_t mp_size = 0;

    if (!encoder || !record) {
        return -1;
    }

    ret = flb_log_event_encoder_begin_record(encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_set_timestamp(encoder, &record->event.timestamp);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    if (record->event.timestamp.tm.tv_sec >= 0) {
        record_type = FLB_LOG_EVENT_NORMAL;
    }
    else if (record->event.timestamp.tm.tv_sec == FLB_LOG_EVENT_GROUP_START) {
        record_type = FLB_LOG_EVENT_GROUP_START;
    }
    else if (record->event.timestamp.tm.tv_sec == FLB_LOG_EVENT_GROUP_END) {
        record_type = FLB_LOG_EVENT_GROUP_END;
    }
    else {
        record_type = FLB_LOG_EVENT_NORMAL;
    }

    ret = encode_cfl_object_or_empty(record->cobj_metadata, &mp_buf, &mp_size);
    if (ret != 0) {
        return -1;
    }

    ret = flb_log_event_encoder_set_metadata_from_raw_msgpack(encoder,
                                                               mp_buf,
                                                               mp_size);
    flb_free(mp_buf);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    mp_buf = NULL;
    mp_size = 0;

    if (record_type == FLB_LOG_EVENT_GROUP_START &&
        record->cobj_group_attributes) {
        ret = flb_mp_cfl_to_msgpack(record->cobj_group_attributes,
                                    &mp_buf,
                                    &mp_size);
    }
    else if (record->cobj_record) {
        ret = flb_mp_cfl_to_msgpack(record->cobj_record, &mp_buf, &mp_size);
    }
    else {
        ret = encode_empty_map(&mp_buf, &mp_size);
    }

    if (ret != 0) {
        return -1;
    }

    ret = flb_log_event_encoder_set_body_from_raw_msgpack(encoder,
                                                           mp_buf,
                                                           mp_size);
    flb_free(mp_buf);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_commit_record(encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    return 0;
}

static int build_payload_for_route(struct flb_route_payload *payload,
                                   struct flb_mp_chunk_record **records,
                                   size_t record_count,
                                   uint8_t *matched_non_default)
{
    size_t i;
    int matched;
    int ret;
    struct flb_condition *compiled;
    struct flb_log_event_encoder *encoder;

    if (!payload || !records || record_count == 0 || !matched_non_default) {
        return -1;
    }

    compiled = flb_router_route_get_condition(payload->route);
    if (!compiled) {
        return 0;
    }

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!encoder) {
        return -1;
    }

    matched = 0;

    for (i = 0; i < record_count; i++) {
        if (flb_condition_evaluate(compiled, records[i]) != FLB_TRUE) {
            continue;
        }

        ret = encode_chunk_record(encoder, records[i]);
        if (ret != 0) {
            flb_log_event_encoder_destroy(encoder);
            return -1;
        }

        matched_non_default[i] = 1;
        matched++;
    }

    if (matched == 0) {
        flb_log_event_encoder_destroy(encoder);
        return 0;
    }

    payload->data = flb_malloc(encoder->output_length);
    if (!payload->data) {
        flb_log_event_encoder_destroy(encoder);
        flb_errno();
        return -1;
    }

    memcpy(payload->data, encoder->output_buffer, encoder->output_length);
    payload->size = encoder->output_length;
    payload->total_records = matched;

    flb_log_event_encoder_destroy(encoder);

    return 0;
}

static int build_payload_for_default_route(struct flb_route_payload *payload,
                                           struct flb_mp_chunk_record **records,
                                           size_t record_count,
                                           uint8_t *matched_non_default)
{
    size_t i;
    int matched;
    int ret;
    struct flb_condition *compiled;
    struct flb_log_event_encoder *encoder;

    if (!payload || !records || !matched_non_default) {
        return -1;
    }

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!encoder) {
        return -1;
    }

    compiled = flb_router_route_get_condition(payload->route);
    matched = 0;

    for (i = 0; i < record_count; i++) {
        if (matched_non_default[i]) {
            continue;
        }

        if (compiled &&
            flb_condition_evaluate(compiled, records[i]) != FLB_TRUE) {
            continue;
        }

        ret = encode_chunk_record(encoder, records[i]);
        if (ret != 0) {
            flb_log_event_encoder_destroy(encoder);
            return -1;
        }

        matched++;
    }

    if (matched == 0) {
        flb_log_event_encoder_destroy(encoder);
        return 0;
    }

    payload->data = flb_malloc(encoder->output_length);
    if (!payload->data) {
        flb_log_event_encoder_destroy(encoder);
        flb_errno();
        return -1;
    }

    memcpy(payload->data, encoder->output_buffer, encoder->output_length);
    payload->size = encoder->output_length;
    payload->total_records = matched;

    flb_log_event_encoder_destroy(encoder);

    return 0;
}

static void route_payload_list_destroy(struct mk_list *payloads)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_route_payload *payload;

    if (!payloads) {
        return;
    }

    mk_list_foreach_safe(head, tmp, payloads) {
        payload = mk_list_entry(head, struct flb_route_payload, _head);
        route_payload_destroy(payload);
    }
}

static int input_has_conditional_routes(struct flb_input_instance *ins)
{
    struct mk_list *head;
    struct flb_router_path *route_path;

    if (!ins) {
        return FLB_FALSE;
    }

    mk_list_foreach(head, &ins->routes_direct) {
        route_path = mk_list_entry(head, struct flb_router_path, _head);

        if (route_path->route && route_path->route->condition) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int split_and_append_route_payloads(struct flb_input_instance *ins,
                                           size_t records,
                                           const char *tag,
                                           size_t tag_len,
                                           const void *buf,
                                           size_t buf_size)
{
    int ret;
    int appended;
    int handled;
    int context_initialized = FLB_FALSE;
    struct mk_list payloads;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_router_path *route_path;
    struct flb_route_payload *payload;
    struct flb_router_chunk_context context;
    struct flb_event_chunk *chunk;
    struct flb_mp_chunk_record **records_array = NULL;
    uint8_t *matched_non_default = NULL;
    size_t record_count;
    size_t index;
    const char *base_tag = tag;
    size_t base_tag_len = tag_len;

    handled = FLB_FALSE;

    if (!ins || !buf || buf_size == 0) {
        return 0;
    }

    if (mk_list_is_empty(&ins->routes_direct) ||
        input_has_conditional_routes(ins) == FLB_FALSE) {
        return 0;
    }

    mk_list_init(&payloads);

    mk_list_foreach(head, &ins->routes_direct) {
        route_path = mk_list_entry(head, struct flb_router_path, _head);

        if (!route_path->route || !route_path->route->condition) {
            continue;
        }

        payload = route_payload_find(&payloads, route_path->route);
        if (!payload) {
            payload = flb_calloc(1, sizeof(struct flb_route_payload));
            if (!payload) {
                flb_errno();
                route_payload_list_destroy(&payloads);
                return -1;
            }

            payload->route = route_path->route;
            payload->is_default = route_path->route->condition->is_default;
            mk_list_add(&payload->_head, &payloads);
        }

        if (append_output_to_payload_tag(payload, route_path->ins) != 0) {
            route_payload_list_destroy(&payloads);
            return -1;
        }
    }

    if (mk_list_is_empty(&payloads)) {
        return 0;
    }

    handled = FLB_TRUE;

    if (!base_tag) {
        if (ins->tag && ins->tag_len > 0) {
            base_tag = ins->tag;
            base_tag_len = ins->tag_len;
        }
        else {
            base_tag = ins->name;
            base_tag_len = strlen(ins->name);
        }
    }

    chunk = flb_event_chunk_create(FLB_EVENT_TYPE_LOGS,
                                   records,
                                   (char *) base_tag,
                                   base_tag_len,
                                   (char *) buf,
                                   buf_size);
    if (!chunk) {
        route_payload_list_destroy(&payloads);
        return -1;
    }

    if (flb_router_chunk_context_init(&context) != 0) {
        route_payload_list_destroy(&payloads);
        flb_event_chunk_destroy(chunk);
        return -1;
    }
    context_initialized = FLB_TRUE;

    ret = flb_router_chunk_context_prepare_logs(&context, chunk);
    if (ret != 0 || !context.chunk_cobj) {
        if (context_initialized) {
            flb_router_chunk_context_destroy(&context);
        }
        route_payload_list_destroy(&payloads);
        flb_event_chunk_destroy(chunk);
        return -1;
    }

    record_count = cfl_list_size(&context.chunk_cobj->records);
    if (record_count == 0) {
        flb_router_chunk_context_destroy(&context);
        route_payload_list_destroy(&payloads);
        flb_event_chunk_destroy(chunk);
        return handled ? 1 : 0;
    }

    records_array = flb_calloc(record_count,
                               sizeof(struct flb_mp_chunk_record *));
    matched_non_default = flb_calloc(record_count, sizeof(uint8_t));
    if (!records_array || !matched_non_default) {
        flb_errno();
        if (records_array) {
            flb_free(records_array);
        }
        if (matched_non_default) {
            flb_free(matched_non_default);
        }
        flb_router_chunk_context_destroy(&context);
        route_payload_list_destroy(&payloads);
        flb_event_chunk_destroy(chunk);
        return -1;
    }

    index = 0;
    cfl_list_foreach(head, &context.chunk_cobj->records) {
        records_array[index++] =
            cfl_list_entry(head, struct flb_mp_chunk_record, _head);
    }

    mk_list_foreach(head, &payloads) {
        payload = mk_list_entry(head, struct flb_route_payload, _head);

        if (payload->is_default) {
            continue;
        }

        ret = build_payload_for_route(payload,
                                       records_array,
                                       record_count,
                                       matched_non_default);
        if (ret != 0) {
            flb_free(records_array);
            flb_free(matched_non_default);
            flb_router_chunk_context_destroy(&context);
            route_payload_list_destroy(&payloads);
            flb_event_chunk_destroy(chunk);
            return -1;
        }
    }

    mk_list_foreach(head, &payloads) {
        payload = mk_list_entry(head, struct flb_route_payload, _head);

        if (!payload->is_default) {
            continue;
        }

        ret = build_payload_for_default_route(payload,
                                              records_array,
                                              record_count,
                                              matched_non_default);
        if (ret != 0) {
            flb_free(records_array);
            flb_free(matched_non_default);
            flb_router_chunk_context_destroy(&context);
            route_payload_list_destroy(&payloads);
            flb_event_chunk_destroy(chunk);
            return -1;
        }
    }

    flb_free(records_array);
    flb_free(matched_non_default);

    mk_list_foreach_safe(head, tmp, &payloads) {
        payload = mk_list_entry(head, struct flb_route_payload, _head);

        if (payload->total_records <= 0 || !payload->data) {
            route_payload_destroy(payload);
        }
    }

    appended = 0;
    mk_list_foreach(head, &payloads) {
        payload = mk_list_entry(head, struct flb_route_payload, _head);

        ret = flb_input_chunk_append_raw(ins,
                                         FLB_INPUT_LOGS,
                                         payload->total_records,
                                         payload->tag,
                                         flb_sds_len(payload->tag),
                                         payload->data,
                                         payload->size);
        if (ret != 0) {
            flb_router_chunk_context_destroy(&context);
            route_payload_list_destroy(&payloads);
            flb_event_chunk_destroy(chunk);
            return -1;
        }

        appended++;
    }

    if (context_initialized) {
        flb_router_chunk_context_destroy(&context);
    }
    route_payload_list_destroy(&payloads);
    flb_event_chunk_destroy(chunk);

    return handled ? (appended > 0 ? appended : 1) : 0;
}

static int input_log_append(struct flb_input_instance *ins,
                            size_t processor_starting_stage,
                            size_t records,
                            const char *tag, size_t tag_len,
                            const void *buf, size_t buf_size)
{
    int ret;
    int processor_is_active;
    void *out_buf = (void *) buf;
    size_t out_size = buf_size;

    processor_is_active = flb_processor_is_active(ins->processor);
    if (processor_is_active) {
        if (!tag) {
            if (ins->tag && ins->tag_len > 0) {
                tag = ins->tag;
                tag_len = ins->tag_len;
            }
            else {
                tag = ins->name;
                tag_len = strlen(ins->name);
            }
        }

        ret = flb_processor_run(ins->processor,
                                processor_starting_stage,
                                FLB_PROCESSOR_LOGS,
                                tag, tag_len,
                                (char *) buf, buf_size,
                                &out_buf, &out_size);
        if (ret == -1) {
            return -1;
        }

        if (out_size == 0) {
            return 0;
        }

        if (buf != out_buf) {
            /* a new buffer was created, re-count the number of records */
            records = flb_mp_count(out_buf, out_size);
        }
    }

    ret = split_and_append_route_payloads(ins, records, tag, tag_len,
                                          out_buf, out_size);
    if (ret < 0) {
        if (processor_is_active && buf != out_buf) {
            flb_free(out_buf);
        }
        return -1;
    }

    if (ret > 0) {
        if (processor_is_active && buf != out_buf) {
            flb_free(out_buf);
        }
        return 0;
    }

    ret = flb_input_chunk_append_raw(ins, FLB_INPUT_LOGS, records,
                                     tag, tag_len, out_buf, out_size);

    if (processor_is_active && buf != out_buf) {
        flb_free(out_buf);
    }
    return ret;
}

/* Take a msgpack serialized record and enqueue it as a chunk */
int flb_input_log_append(struct flb_input_instance *ins,
                         const char *tag, size_t tag_len,
                         const void *buf, size_t buf_size)
{
    int ret;
    size_t records;

    records = flb_mp_count(buf, buf_size);
    ret = input_log_append(ins, 0, records, tag, tag_len, buf, buf_size);
    return ret;
}

/* Take a msgpack serialized record and enqueue it as a chunk */
int flb_input_log_append_skip_processor_stages(struct flb_input_instance *ins,
                                               size_t processor_starting_stage,
                                               const char *tag,
                                               size_t tag_len,
                                               const void *buf,
                                               size_t buf_size)
{
    return input_log_append(ins,
                            processor_starting_stage,
                            flb_mp_count(buf, buf_size),
                            tag,
                            tag_len,
                            buf,
                            buf_size);
}

/* Take a msgpack serialized record and enqueue it as a chunk */
int flb_input_log_append_records(struct flb_input_instance *ins,
                                 size_t records,
                                 const char *tag, size_t tag_len,
                                 const void *buf, size_t buf_size)
{
    int ret;

    ret = input_log_append(ins, 0, records, tag, tag_len, buf, buf_size);
    return ret;
}


