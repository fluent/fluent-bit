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


#include "cm.h"
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mem.h>
#include <string.h>
#include <stdint.h>

/* Fall back for shapes that the existing CFL conversion cannot represent. */
static int object_supported(msgpack_object *object, size_t depth)
{
    size_t index;

    if (depth > 32 || object->type == MSGPACK_OBJECT_EXT) {
        return FLB_FALSE;
    }
    if (object->type == MSGPACK_OBJECT_MAP) {
        for (index = 0; index < object->via.map.size; index++) {
            if (object->via.map.ptr[index].key.type != MSGPACK_OBJECT_STR ||
                !object_supported(&object->via.map.ptr[index].val, depth + 1)) {
                return FLB_FALSE;
            }
        }
    }
    else if (object->type == MSGPACK_OBJECT_ARRAY) {
        for (index = 0; index < object->via.array.size; index++) {
            if (!object_supported(&object->via.array.ptr[index], depth + 1)) {
                return FLB_FALSE;
            }
        }
    }
    return FLB_TRUE;
}

static void string_object(msgpack_object *object, cfl_sds_t value)
{
    object->type = MSGPACK_OBJECT_STR;
    object->via.str.ptr = value;
    object->via.str.size = cfl_sds_len(value);
}

int cm_logs_raw_supported(struct flb_processor_instance *ins)
{
    struct content_modifier_ctx *ctx;

    ctx = ins->context;
    return ctx != NULL && ctx->context_type == CM_CONTEXT_LOG_BODY &&
           (ctx->action_type == CM_ACTION_INSERT || ctx->action_type == CM_ACTION_UPSERT ||
            ctx->action_type == CM_ACTION_DELETE || ctx->action_type == CM_ACTION_RENAME);
}

int cm_logs_process_raw(struct flb_processor_instance **instances, size_t instance_count,
                        const void *data, size_t bytes,
                        void **out_buf, size_t *out_size,
                        const char *tag, int tag_len)
{
    int ret;
    int result;
    int changed;
    int record_changed;
    int record_type;
    size_t index;
    size_t consumed;
    size_t action_index;
    size_t match;
    size_t capacity;
    size_t required;
    size_t count;
    size_t key_length;
    struct content_modifier_ctx *ctx;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    msgpack_sbuffer output;
    msgpack_packer packer;
    msgpack_object root;
    msgpack_object elements[2];
    msgpack_object_kv *pairs;
    msgpack_object_kv *resized;

    (void) tag;
    (void) tag_len;
    if (instance_count == 0 || instance_count > UINT32_MAX) {
        return FLB_PROCESSOR_RAW_UNSUPPORTED;
    }
    for (action_index = 0; action_index < instance_count; action_index++) {
        if (!cm_logs_raw_supported(instances[action_index])) {
            return FLB_PROCESSOR_RAW_UNSUPPORTED;
        }
    }

    ret = flb_log_event_decoder_init(&decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        return FLB_PROCESSOR_RAW_UNSUPPORTED;
    }
    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);
    msgpack_sbuffer_init(&output);
    msgpack_packer_init(&packer, &output, msgpack_sbuffer_write);
    pairs = NULL;
    capacity = 0;
    changed = FLB_FALSE;
    consumed = 0;
    result = FLB_PROCESSOR_RAW_UNSUPPORTED;

    while ((ret = flb_log_event_decoder_next(&decoder, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        /* The decoder can skip invalid markers. Let the existing path handle them. */
        if (decoder.record_base != (const char *) data + consumed) {
            goto cleanup;
        }
        consumed += decoder.record_length;
        ret = flb_log_event_decoder_get_record_type(&event, &record_type);
        if (ret != FLB_EVENT_DECODER_SUCCESS || record_type != FLB_LOG_EVENT_NORMAL ||
            event.format != FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2 ||
            event.body->type != MSGPACK_OBJECT_MAP ||
            !object_supported(event.body, 0) || !object_supported(event.metadata, 0)) {
            goto cleanup;
        }

        /* An action can add at most one field. Reuse the largest scratch map. */
        if (instance_count > UINT32_MAX - event.body->via.map.size) {
            result = FLB_PROCESSOR_FAILURE;
            goto cleanup;
        }
        required = (size_t) event.body->via.map.size + instance_count;
        if (required > SIZE_MAX / sizeof(msgpack_object_kv)) {
            result = FLB_PROCESSOR_FAILURE;
            goto cleanup;
        }
        if (required > capacity) {
            resized = flb_realloc(pairs, required * sizeof(msgpack_object_kv));
            if (resized == NULL) {
                flb_errno();
                result = FLB_PROCESSOR_FAILURE;
                goto cleanup;
            }
            pairs = resized;
            capacity = required;
        }
        count = event.body->via.map.size;
        if (count > 0) {
            memcpy(pairs, event.body->via.map.ptr, count * sizeof(msgpack_object_kv));
        }
        record_changed = FLB_FALSE;
        for (action_index = 0; action_index < instance_count; action_index++) {
            ctx = instances[action_index]->context;
            key_length = cfl_sds_len(ctx->key);
            match = SIZE_MAX;
            for (index = 0; index < count; index++) {
                if (pairs[index].key.via.str.size == key_length &&
                    strncmp(pairs[index].key.via.str.ptr, ctx->key, key_length) == 0) {
                    match = index;
                    break;
                }
            }
            if ((ctx->action_type == CM_ACTION_INSERT && match != SIZE_MAX) ||
                ((ctx->action_type == CM_ACTION_DELETE || ctx->action_type == CM_ACTION_RENAME) &&
                 match == SIZE_MAX)) {
                continue;
            }
            if (ctx->action_type == CM_ACTION_RENAME) {
                string_object(&pairs[match].key, ctx->value);
            }
            else {
                if (match != SIZE_MAX) {
                    memmove(&pairs[match], &pairs[match + 1],
                            (count - match - 1) * sizeof(msgpack_object_kv));
                    count--;
                }
                if (ctx->action_type == CM_ACTION_INSERT || ctx->action_type == CM_ACTION_UPSERT) {
                    string_object(&pairs[count].key, ctx->key);
                    string_object(&pairs[count].val, ctx->value);
                    count++;
                }
            }
            record_changed = FLB_TRUE;
        }
        if (!record_changed) {
            if (msgpack_sbuffer_write(&output, decoder.record_base, decoder.record_length) != 0) {
                result = FLB_PROCESSOR_FAILURE;
                goto cleanup;
            }
            continue;
        }

        root = *event.root;
        memcpy(elements, root.via.array.ptr, sizeof(elements));
        elements[1] = *event.body;
        elements[1].via.map.ptr = pairs;
        elements[1].via.map.size = count;
        root.via.array.ptr = elements;
        if (msgpack_pack_object(&packer, root) != 0) {
            result = FLB_PROCESSOR_FAILURE;
            goto cleanup;
        }
        changed = FLB_TRUE;
    }

    if (consumed != bytes ||
        flb_log_event_decoder_get_last_result(&decoder) != FLB_EVENT_DECODER_SUCCESS) {
        goto cleanup;
    }
    result = FLB_PROCESSOR_RAW_NOTOUCH;
    if (changed) {
        *out_buf = output.data;
        *out_size = output.size;
        output.data = NULL;
        result = FLB_PROCESSOR_RAW_MODIFIED;
    }

cleanup:
    msgpack_sbuffer_destroy(&output);
    flb_free(pairs);
    flb_log_event_decoder_destroy(&decoder);
    return result;
}
