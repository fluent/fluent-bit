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

#include "fluent-bit/flb_pack.h"
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_routes_mask.h>
#include <fluent-bit/flb_conditionals.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>

#include <chunkio/chunkio.h>

#include <stdint.h>
#include <string.h>

struct flb_route_payload {
    struct flb_route *route;
    int is_default;
    flb_sds_t tag;
    char *data;
    size_t size;
    size_t total_records;
    struct cfl_list _head;
};

static void route_payload_destroy(struct flb_route_payload *payload)
{
    if (!payload) {
        return;
    }

    if (!cfl_list_entry_is_orphan(&payload->_head)) {
        cfl_list_del(&payload->_head);
    }

    if (payload->tag) {
        flb_sds_destroy(payload->tag);
    }

    if (payload->data) {
        flb_free(payload->data);
    }

    flb_free(payload);
}

static struct flb_route_payload *route_payload_find(struct cfl_list *payloads,
                                                    struct flb_route *route)
{
    struct cfl_list *head;
    struct flb_route_payload *payload;

    if (!payloads || !route) {
        return NULL;
    }

    cfl_list_foreach(head, payloads) {
        payload = cfl_list_entry(head, struct flb_route_payload, _head);

        if (payload->route == route) {
            return payload;
        }
    }

    return NULL;
}

static int route_payload_apply_outputs(struct flb_input_instance *ins,
                                       struct flb_route_payload *payload)
{
    int ret;
    size_t out_size = 0;
    size_t chunk_size_sz = 0;
    ssize_t chunk_size;
    struct cfl_list *head;
    struct flb_input_chunk *chunk = NULL;
    struct flb_router_path *route_path;

    if (!ins || !payload || !payload->tag || !payload->route) {
        return -1;
    }

    if (!ins->ht_log_chunks || !ins->config) {
        return -1;
    }

    ret = flb_hash_table_get(ins->ht_log_chunks,
                             payload->tag,
                             flb_sds_len(payload->tag),
                             (void **) &chunk,
                             &out_size);
    if (ret == -1 || !chunk || !chunk->routes_mask) {
        return -1;
    }

    if (chunk->fs_counted == FLB_TRUE) {
        chunk_size = flb_input_chunk_get_real_size(chunk);
        if (chunk_size > 0) {
            chunk_size_sz = (size_t) chunk_size;
        }
        else {
            chunk_size = 0;
        }
    }
    else {
        chunk_size = 0;
    }

    if (chunk_size_sz > 0) {
        cfl_list_foreach(head, &ins->routes_direct) {
            route_path = cfl_list_entry(head, struct flb_router_path, _head);

            if (!route_path->ins) {
                continue;
            }

            if (flb_routes_mask_get_bit(chunk->routes_mask,
                                        route_path->ins->id,
                                        ins->config) == 0) {
                continue;
            }

            if (route_path->route == payload->route) {
                continue;
            }

            if (route_path->ins->total_limit_size != -1) {
                if (route_path->ins->fs_chunks_size > chunk_size_sz) {
                    route_path->ins->fs_chunks_size -= chunk_size_sz;
                }
                else {
                    route_path->ins->fs_chunks_size = 0;
                }
            }

            flb_routes_mask_clear_bit(chunk->routes_mask,
                                      route_path->ins->id,
                                      ins->config);
        }
    }

    memset(chunk->routes_mask, 0, sizeof(flb_route_mask_element) * ins->config->route_mask_size);

    cfl_list_foreach(head, &ins->routes_direct) {
        route_path = cfl_list_entry(head, struct flb_router_path, _head);
        if (!route_path->route || !route_path->ins) {
            continue;
        }

        if (route_path->route != payload->route) {
            continue;
        }

        flb_routes_mask_set_bit(chunk->routes_mask,
                                route_path->ins->id,
                                ins->config);
    }

    if (flb_routes_mask_is_empty(chunk->routes_mask, ins->config) == FLB_TRUE) {
        return -1;
    }

    if (chunk->fs_counted == FLB_FALSE) {
        chunk_size = flb_input_chunk_get_real_size(chunk);
        if (chunk_size > 0) {
            flb_input_chunk_update_output_instances(chunk,
                                                    (size_t) chunk_size);
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

static int build_payload_for_route(struct flb_input_instance *ins,
                                   struct flb_route_payload *payload,
                                   struct flb_mp_chunk_record **records,
                                   size_t record_count,
                                   uint8_t *matched_non_default)
{
    size_t i;
    int ret;
    int condition_result;
    int matched;
    int32_t record_type;
    struct flb_log_event_encoder *encoder;
    struct flb_mp_chunk_record *group_end = NULL;
    struct flb_mp_chunk_record *group_start_record = NULL;
    uint8_t *matched_by_route = NULL;

    if (!payload || !records || record_count == 0 || !matched_non_default) {
        return -1;
    }

    /* Check if route has a condition (flb_router_condition_evaluate_record handles NULL conditions) */
    if (!payload->route->condition) {
        return 0;
    }

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!encoder) {
        return -1;
    }

    /* Track which records match THIS specific route */
    matched_by_route = flb_calloc(record_count, sizeof(uint8_t));
    if (!matched_by_route) {
        flb_errno();
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    matched = 0;

    /* First pass: evaluate conditions and mark matching records */
    for (i = 0; i < record_count; i++) {
        if (flb_log_event_decoder_get_record_type(&records[i]->event, &record_type) == 0) {
            if (record_type == FLB_LOG_EVENT_GROUP_START) {
                continue;
            }
            else if (record_type == FLB_LOG_EVENT_GROUP_END) {
                group_end = records[i];
                continue;
            }
        }

        condition_result = flb_router_condition_evaluate_record(payload->route, records[i]);
        if (condition_result != FLB_TRUE) {
            continue;
        }

        matched_by_route[i] = 1;
        matched_non_default[i] = 1;
        matched++;
    }

    /* If no matches, return early */
    if (matched == 0) {
        flb_free(matched_by_route);
        flb_log_event_encoder_destroy(encoder);
        return 0;
    }

    /* Second pass: find GROUP_START record */
    for (i = 0; i < record_count; i++) {
        if (flb_log_event_decoder_get_record_type(&records[i]->event, &record_type) == 0 &&
            record_type == FLB_LOG_EVENT_GROUP_START) {
            group_start_record = records[i];
            break;
        }
    }

    if (group_start_record != NULL) {
        ret = encode_chunk_record(encoder, group_start_record);
        if (ret != 0) {
            flb_free(matched_by_route);
            flb_log_event_encoder_destroy(encoder);
            return -1;
        }
    }

    /* Encode matching records */
    for (i = 0; i < record_count; i++) {
        if (flb_log_event_decoder_get_record_type(&records[i]->event, &record_type) == 0 &&
            record_type == FLB_LOG_EVENT_NORMAL) {
            if (matched_by_route[i]) {
                ret = encode_chunk_record(encoder, records[i]);
                if (ret != 0) {
                    flb_free(matched_by_route);
                    flb_log_event_encoder_destroy(encoder);
                    return -1;
                }
            }
        }
    }

    if (group_end != NULL && group_start_record != NULL) {
        ret = encode_chunk_record(encoder, group_end);
        if (ret != 0) {
            flb_free(matched_by_route);
            flb_log_event_encoder_destroy(encoder);
            return -1;
        }
    }

    flb_free(matched_by_route);

    /* Ensure output_buffer and output_length are up to date */
    if (encoder->buffer.size == 0) {
        flb_log_event_encoder_destroy(encoder);
        return 0;
    }

    payload->size = encoder->buffer.size;
    payload->data = flb_malloc(payload->size);
    if (!payload->data) {
        flb_log_event_encoder_destroy(encoder);
        flb_errno();
        return -1;
    }

    /* Copy the buffer data - msgpack_sbuffer uses flat memory, no zones */
    memcpy(payload->data, encoder->buffer.data, payload->size);
    payload->total_records = matched;

    flb_log_event_encoder_destroy(encoder);

    return 0;
}

static int build_payload_for_default_route(struct flb_input_instance *ins,
                                           struct flb_route_payload *payload,
                                           struct flb_mp_chunk_record **records,
                                           size_t record_count,
                                           uint8_t *matched_non_default)
{
    size_t i;
    int matched;
    int ret;
    int condition_result;
    int32_t record_type;
    struct flb_log_event_encoder *encoder;
    struct flb_mp_chunk_record *group_end = NULL;
    struct flb_mp_chunk_record *group_start_record = NULL;
    int *matched_by_default = NULL;

    if (!payload || !records || !matched_non_default) {
        return -1;
    }

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!encoder) {
        return -1;
    }

    matched = 0;

    /* First pass: evaluate conditions */
    for (i = 0; i < record_count; i++) {
        if (flb_log_event_decoder_get_record_type(&records[i]->event, &record_type) == 0) {
            if (record_type == FLB_LOG_EVENT_GROUP_START) {
                continue;
            }
            else if (record_type == FLB_LOG_EVENT_GROUP_END) {
                group_end = records[i];
                continue;
            }
        }

        if (matched_non_default[i]) {
            continue;
        }

        condition_result = flb_router_condition_evaluate_record(payload->route, records[i]);
        if (condition_result != FLB_TRUE) {
            continue;
        }

        matched++;
    }

    /* If no matches, return early - no need to create payload */
    if (matched == 0) {
        flb_log_event_encoder_destroy(encoder);
        return 0;
    }

    /* Second pass: find GROUP_START record */
    for (i = 0; i < record_count; i++) {
        if (flb_log_event_decoder_get_record_type(&records[i]->event, &record_type) == 0 &&
            record_type == FLB_LOG_EVENT_GROUP_START) {
            group_start_record = records[i];
            break;
        }
    }

    matched_by_default = flb_calloc(record_count, sizeof(int));
    if (!matched_by_default) {
        flb_errno();
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    /* Mark matching records */
    for (i = 0; i < record_count; i++) {
        if (flb_log_event_decoder_get_record_type(&records[i]->event, &record_type) == 0 &&
            record_type == FLB_LOG_EVENT_NORMAL) {
            if (!matched_non_default[i]) {
                if (payload->route->condition) {
                    condition_result = flb_router_condition_evaluate_record(payload->route, records[i]);
                    if (condition_result == FLB_TRUE) {
                        matched_by_default[i] = 1;
                    }
                }
                else {
                    matched_by_default[i] = 1;
                }
            }
        }
    }

    if (group_start_record != NULL) {
        ret = encode_chunk_record(encoder, group_start_record);
        if (ret != 0) {
            flb_free(matched_by_default);
            flb_log_event_encoder_destroy(encoder);
            return -1;
        }
    }

    /* Encode matching records */
    for (i = 0; i < record_count; i++) {
        if (flb_log_event_decoder_get_record_type(&records[i]->event, &record_type) == 0 &&
            record_type == FLB_LOG_EVENT_NORMAL) {
            if (matched_by_default[i]) {
                ret = encode_chunk_record(encoder, records[i]);
                if (ret != 0) {
                    flb_free(matched_by_default);
                    flb_log_event_encoder_destroy(encoder);
                    return -1;
                }
            }
        }
    }

    if (group_end != NULL && group_start_record != NULL) {
        ret = encode_chunk_record(encoder, group_end);
        if (ret != 0) {
            flb_free(matched_by_default);
            flb_log_event_encoder_destroy(encoder);
            return -1;
        }
    }

    flb_free(matched_by_default);

    /* Ensure output_buffer and output_length are up to date */
    if (encoder->buffer.size == 0) {
        flb_log_event_encoder_destroy(encoder);
        return 0;
    }

    payload->size = encoder->buffer.size;
    payload->data = flb_malloc(payload->size);
    if (!payload->data) {
        flb_log_event_encoder_destroy(encoder);
        flb_errno();
        return -1;
    }

    /* Copy the buffer data - msgpack_sbuffer uses flat memory, no zones */
    memcpy(payload->data, encoder->buffer.data, payload->size);
    payload->total_records = matched;

    flb_log_event_encoder_destroy(encoder);

    return 0;
}

static void route_payload_list_destroy(struct cfl_list *payloads)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct flb_route_payload *payload;

    if (!payloads) {
        return;
    }

    cfl_list_foreach_safe(head, tmp, payloads) {
        payload = cfl_list_entry(head, struct flb_route_payload, _head);
        route_payload_destroy(payload);
    }
}

static void input_chunk_remove_conditional_routes(struct flb_input_instance *ins,
                                                  struct flb_input_chunk *chunk)
{
    ssize_t chunk_size;
    size_t chunk_size_sz;
    struct cfl_list *head;
    struct flb_router_path *route_path;

    if (!ins || !chunk || !chunk->routes_mask || !ins->config) {
        return;
    }

    chunk_size = -1;
    cfl_list_foreach(head, &ins->routes_direct) {
        route_path = cfl_list_entry(head, struct flb_router_path, _head);

        if (!route_path->route || !route_path->ins) {
            continue;
        }

        if (!route_path->route->condition &&
            !route_path->route->per_record_routing) {
            continue;
        }

        if (flb_routes_mask_get_bit(chunk->routes_mask,
                                    route_path->ins->id,
                                    ins->config) == 0) {
            continue;
        }

        flb_routes_mask_clear_bit(chunk->routes_mask,
                                  route_path->ins->id,
                                  ins->config);

        if (route_path->ins->total_limit_size == -1 ||
            chunk->fs_counted == FLB_FALSE) {
            continue;
        }

        if (chunk_size == -1) {
            chunk_size = flb_input_chunk_get_real_size(chunk);
            if (chunk_size <= 0) {
                chunk_size = 0;
            }
        }

        if (chunk_size > 0) {
            chunk_size_sz = (size_t) chunk_size;
            if (route_path->ins->fs_chunks_size > chunk_size_sz) {
                route_path->ins->fs_chunks_size -= chunk_size_sz;
            }
            else {
                route_path->ins->fs_chunks_size = 0;
            }
        }
    }
}

static int input_has_conditional_routes(struct flb_input_instance *ins)
{
    struct cfl_list *head;
    struct flb_router_path *route_path;

    if (!ins) {
        return FLB_FALSE;
    }

    cfl_list_foreach(head, &ins->routes_direct) {
        route_path = cfl_list_entry(head, struct flb_router_path, _head);
        if (route_path->route && (route_path->route->condition || route_path->route->per_record_routing)) {
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
    size_t out_size = 0;
    uint8_t *matched_non_default = NULL;
    struct cfl_list payloads;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct flb_router_path *route_path;
    struct flb_route_payload *payload;
    struct flb_router_chunk_context context;
    struct flb_event_chunk *chunk;
    struct flb_mp_chunk_record **records_array = NULL;
    struct flb_input_chunk *orphaned_chunk = NULL;

    size_t record_count;
    size_t index;
    size_t base_tag_len = tag_len;
    const char *base_tag = tag;

    handled = FLB_FALSE;

    if (!ins || !buf || buf_size == 0) {
        return 0;
    }

    if (cfl_list_size(&ins->routes_direct) == 0) {
        return 0;
    }

    if (input_has_conditional_routes(ins) == FLB_FALSE) {
        return 0;
    }

    /* Conditional routing not supported for threaded inputs */
    if (flb_input_is_threaded(ins)) {
        flb_plg_warn(ins, "conditional routing not supported for threaded inputs, "
                          "falling back to normal routing");
        return 0;
    }

    cfl_list_init(&payloads);
    cfl_list_foreach(head, &ins->routes_direct) {
        route_path = cfl_list_entry(head, struct flb_router_path, _head);
        if (!route_path->route ||
            (!route_path->route->condition && !route_path->route->per_record_routing)) {
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
            payload->is_default = route_path->route->condition ? route_path->route->condition->is_default : 0;

            /* Use the route name as the tag */
            payload->tag = flb_sds_create(route_path->route->name);
            if (!payload->tag) {
                flb_free(payload);
                route_payload_list_destroy(&payloads);
                return -1;
            }
            cfl_list_add(&payload->_head, &payloads);
        }
    }

    if (cfl_list_size(&payloads) == 0) {
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
    else if (base_tag_len == 0) {
        base_tag_len = strlen(base_tag);
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
        if (handled) {
            return 1;
        }
        else {
            return 0;
        }
    }

    records_array = flb_calloc(record_count, sizeof(struct flb_mp_chunk_record *));
    if (!records_array) {
        flb_errno();
        flb_router_chunk_context_destroy(&context);
        route_payload_list_destroy(&payloads);
        flb_event_chunk_destroy(chunk);
        return -1;
    }

    matched_non_default = flb_calloc(record_count, sizeof(uint8_t));
    if (!matched_non_default) {
        flb_errno();
        flb_free(records_array);
        flb_router_chunk_context_destroy(&context);
        route_payload_list_destroy(&payloads);
        flb_event_chunk_destroy(chunk);
        return -1;
    }

    index = 0;
    cfl_list_foreach(head, &context.chunk_cobj->records) {
        records_array[index++] = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
    }

    cfl_list_foreach(head, &payloads) {
        payload = cfl_list_entry(head, struct flb_route_payload, _head);
        if (payload->is_default) {
            continue;
        }

        ret = build_payload_for_route(ins,
                                       payload,
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

    cfl_list_foreach(head, &payloads) {
        payload = cfl_list_entry(head, struct flb_route_payload, _head);
        if (!payload->is_default) {
            continue;
        }

        ret = build_payload_for_default_route(ins,
                                              payload,
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

    cfl_list_foreach_safe(head, tmp, &payloads) {
        payload = cfl_list_entry(head, struct flb_route_payload, _head);
        if (payload->total_records <= 0 || !payload->data) {
            route_payload_destroy(payload);
        }
    }

    appended = 0;
    cfl_list_foreach(head, &payloads) {
        payload = cfl_list_entry(head, struct flb_route_payload, _head);

        /* Skip payloads with no data or no records */
        if (payload->total_records <= 0 || !payload->data || payload->size == 0) {
            continue;
        }

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

        if (route_payload_apply_outputs(ins, payload) != 0) {
            /* Clean up the orphaned chunk from ht_log_chunks */
            orphaned_chunk = NULL;
            out_size = 0;
            ret = flb_hash_table_get(ins->ht_log_chunks,
                                     payload->tag,
                                     flb_sds_len(payload->tag),
                                     (void **) &orphaned_chunk,
                                     &out_size);
            if (ret >= 0 && orphaned_chunk) {
                flb_hash_table_del_ptr(ins->ht_log_chunks,
                                       payload->tag,
                                       flb_sds_len(payload->tag),
                                       (void *) orphaned_chunk);
                /* Destroy the orphaned chunk completely */
                flb_input_chunk_destroy(orphaned_chunk, FLB_TRUE);
            }
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

    if (handled) {
        if (appended > 0) {
            return appended;
        }
        return 1;
    }

    return 0;
}

static int input_log_append(struct flb_input_instance *ins,
                            size_t processor_starting_stage,
                            size_t records,
                            const char *tag, size_t tag_len,
                            const void *buf, size_t buf_size)
{
    int ret;
    int conditional_result;
    int conditional_handled = FLB_FALSE;
    int processor_is_active;
    void *out_buf = (void *) buf;
    size_t dummy = 0;
    size_t out_size = buf_size;
    const char *base_tag = tag;
    size_t base_tag_len = tag_len;
    struct flb_input_chunk *chunk = NULL;

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
    else if (base_tag_len == 0) {
        base_tag_len = strlen(base_tag);
    }

    conditional_result = split_and_append_route_payloads(ins, records, tag, tag_len,
                                                         out_buf, out_size);
    if (conditional_result < 0) {
        if (processor_is_active && buf != out_buf) {
            flb_free(out_buf);
        }
        return -1;
    }

    if (conditional_result > 0) {
        conditional_handled = FLB_TRUE;
    }

    /*
     * Always call flb_input_chunk_append_raw to ensure non-conditional routes
     * receive data even when conditional routes exist. The conditional routing
     * should be additive, not exclusive.
     */
    ret = flb_input_chunk_append_raw(ins, FLB_INPUT_LOGS, records,
                                     tag, tag_len, out_buf, out_size);

    if (ret == 0 && conditional_handled == FLB_TRUE && base_tag) {
        chunk = NULL;
        dummy = 0;

        if (flb_hash_table_get(ins->ht_log_chunks,
                               base_tag,
                               base_tag_len,
                               (void **) &chunk,
                               &dummy) >= 0 && chunk) {
            input_chunk_remove_conditional_routes(ins, chunk);
        }
    }

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


