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
 */

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_search_bulk.h>

#include <msgpack.h>
#include <limits.h>
#include <string.h>

#define FLB_SEARCH_BULK_ITEM_INVALID        -1
#define FLB_SEARCH_BULK_ITEM_ACKNOWLEDGED    0
#define FLB_SEARCH_BULK_ITEM_RETRYABLE       1
#define FLB_SEARCH_BULK_ITEM_UNRECOVERABLE   2

static int object_key_equals(msgpack_object key, const char *value, size_t length)
{
    if (key.type != MSGPACK_OBJECT_STR || key.via.str.size != length) {
        return FLB_FALSE;
    }

    return strncmp(key.via.str.ptr, value, length) == 0;
}

static void json_skip_whitespace(const char *json, size_t size, size_t *offset)
{
    while (*offset < size) {
        if (json[*offset] != ' ' && json[*offset] != '\t' &&
            json[*offset] != '\r' && json[*offset] != '\n') {
            break;
        }
        (*offset)++;
    }
}

static int json_is_hexadecimal(char value)
{
    if ((value >= '0' && value <= '9') ||
        (value >= 'a' && value <= 'f') ||
        (value >= 'A' && value <= 'F')) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int json_scan_string(const char *json, size_t size, size_t *offset,
                            size_t *content_start, size_t *content_size)
{
    char value;
    size_t index;
    size_t start;

    if (*offset >= size || json[*offset] != '"') {
        return -1;
    }

    start = *offset + 1;
    index = start;
    while (index < size) {
        value = json[index];
        if (value == '"') {
            if (content_start != NULL) {
                *content_start = start;
            }
            if (content_size != NULL) {
                *content_size = index - start;
            }
            *offset = index + 1;
            return 0;
        }
        if ((unsigned char) value < 0x20) {
            return -1;
        }
        if (value == '\\') {
            index++;
            if (index >= size || strchr("\"\\/bfnrtu", json[index]) == NULL) {
                return -1;
            }
            if (json[index] == 'u') {
                if (index + 4 >= size) {
                    return -1;
                }
                if (json_is_hexadecimal(json[index + 1]) == FLB_FALSE ||
                    json_is_hexadecimal(json[index + 2]) == FLB_FALSE ||
                    json_is_hexadecimal(json[index + 3]) == FLB_FALSE ||
                    json_is_hexadecimal(json[index + 4]) == FLB_FALSE) {
                    return -1;
                }
                index += 4;
            }
        }
        index++;
    }

    return -1;
}

static int json_skip_value(const char *json, size_t size,
                           size_t *offset, int depth);

static int json_skip_object(const char *json, size_t size,
                            size_t *offset, int depth)
{
    if (depth > 64 || *offset >= size || json[*offset] != '{') {
        return -1;
    }

    (*offset)++;
    json_skip_whitespace(json, size, offset);
    if (*offset < size && json[*offset] == '}') {
        (*offset)++;
        return 0;
    }

    while (*offset < size) {
        if (json_scan_string(json, size, offset, NULL, NULL) != 0) {
            return -1;
        }
        json_skip_whitespace(json, size, offset);
        if (*offset >= size || json[*offset] != ':') {
            return -1;
        }
        (*offset)++;
        if (json_skip_value(json, size, offset, depth + 1) != 0) {
            return -1;
        }
        json_skip_whitespace(json, size, offset);
        if (*offset >= size) {
            return -1;
        }
        if (json[*offset] == '}') {
            (*offset)++;
            return 0;
        }
        if (json[*offset] != ',') {
            return -1;
        }
        (*offset)++;
        json_skip_whitespace(json, size, offset);
    }

    return -1;
}

static int json_skip_array(const char *json, size_t size,
                           size_t *offset, int depth)
{
    if (depth > 64 || *offset >= size || json[*offset] != '[') {
        return -1;
    }

    (*offset)++;
    json_skip_whitespace(json, size, offset);
    if (*offset < size && json[*offset] == ']') {
        (*offset)++;
        return 0;
    }

    while (*offset < size) {
        if (json_skip_value(json, size, offset, depth + 1) != 0) {
            return -1;
        }
        json_skip_whitespace(json, size, offset);
        if (*offset >= size) {
            return -1;
        }
        if (json[*offset] == ']') {
            (*offset)++;
            return 0;
        }
        if (json[*offset] != ',') {
            return -1;
        }
        (*offset)++;
        json_skip_whitespace(json, size, offset);
    }

    return -1;
}

static int json_skip_number(const char *json, size_t size, size_t *offset)
{
    size_t index;

    index = *offset;
    if (index < size && json[index] == '-') {
        index++;
    }
    if (index >= size) {
        return -1;
    }
    if (json[index] == '0') {
        index++;
    }
    else {
        if (json[index] < '1' || json[index] > '9') {
            return -1;
        }
        while (index < size && json[index] >= '0' && json[index] <= '9') {
            index++;
        }
    }
    if (index < size && json[index] == '.') {
        index++;
        if (index >= size || json[index] < '0' || json[index] > '9') {
            return -1;
        }
        while (index < size && json[index] >= '0' && json[index] <= '9') {
            index++;
        }
    }
    if (index < size && (json[index] == 'e' || json[index] == 'E')) {
        index++;
        if (index < size && (json[index] == '+' || json[index] == '-')) {
            index++;
        }
        if (index >= size || json[index] < '0' || json[index] > '9') {
            return -1;
        }
        while (index < size && json[index] >= '0' && json[index] <= '9') {
            index++;
        }
    }

    *offset = index;
    return 0;
}

static int json_skip_value(const char *json, size_t size,
                           size_t *offset, int depth)
{
    json_skip_whitespace(json, size, offset);
    if (*offset >= size) {
        return -1;
    }

    if (json[*offset] == '"') {
        return json_scan_string(json, size, offset, NULL, NULL);
    }
    if (json[*offset] == '{') {
        return json_skip_object(json, size, offset, depth);
    }
    if (json[*offset] == '[') {
        return json_skip_array(json, size, offset, depth);
    }
    if (size - *offset >= 4 &&
        (memcmp(json + *offset, "true", 4) == 0 ||
         memcmp(json + *offset, "null", 4) == 0)) {
        *offset += 4;
        return 0;
    }
    if (size - *offset >= 5 && memcmp(json + *offset, "false", 5) == 0) {
        *offset += 5;
        return 0;
    }

    return json_skip_number(json, size, offset);
}

static int top_level_errors_is_false(const char *json, size_t size)
{
    size_t offset;
    size_t key_start;
    size_t key_size;
    size_t value_end;

    offset = 0;
    json_skip_whitespace(json, size, &offset);
    if (offset >= size || json[offset] != '{') {
        return FLB_FALSE;
    }

    offset++;
    json_skip_whitespace(json, size, &offset);
    while (offset < size && json[offset] != '}') {
        if (json_scan_string(json, size, &offset,
                             &key_start, &key_size) != 0) {
            return FLB_FALSE;
        }
        json_skip_whitespace(json, size, &offset);
        if (offset >= size || json[offset] != ':') {
            return FLB_FALSE;
        }
        offset++;
        json_skip_whitespace(json, size, &offset);

        if (key_size == 6 && memcmp(json + key_start, "errors", 6) == 0) {
            if (size - offset < 5 || memcmp(json + offset, "false", 5) != 0) {
                return FLB_FALSE;
            }

            value_end = offset + 5;
            json_skip_whitespace(json, size, &value_end);
            if (value_end == size || json[value_end] == ',' ||
                json[value_end] == '}') {
                return FLB_TRUE;
            }
            return FLB_FALSE;
        }

        if (json_skip_value(json, size, &offset, 0) != 0) {
            return FLB_FALSE;
        }
        json_skip_whitespace(json, size, &offset);
        if (offset >= size || json[offset] != ',') {
            return FLB_FALSE;
        }
        offset++;
        json_skip_whitespace(json, size, &offset);
    }

    return FLB_FALSE;
}

static void copy_error_text(char *destination, size_t destination_size,
                            msgpack_object value)
{
    unsigned char character;
    size_t index;
    size_t copy_size;

    if (destination_size == 0 || value.type != MSGPACK_OBJECT_STR) {
        return;
    }

    copy_size = value.via.str.size;
    if (copy_size >= destination_size) {
        copy_size = destination_size - 1;
    }

    for (index = 0; index < copy_size; index++) {
        character = value.via.str.ptr[index];
        if (character < 0x20 || character == 0x7f) {
            destination[index] = ' ';
        }
        else {
            destination[index] = character;
        }
    }
    destination[copy_size] = '\0';
}

static void capture_first_error(struct flb_search_bulk_stats *stats,
                                int status, msgpack_object operation)
{
    int index;
    int error_index;
    msgpack_object error;
    msgpack_object value;

    if (stats == NULL || stats->failed_items != 0) {
        return;
    }

    stats->first_error_status = status;
    for (index = 0; index < operation.via.map.size; index++) {
        if (object_key_equals(operation.via.map.ptr[index].key,
                              "error", 5) == FLB_FALSE) {
            continue;
        }

        error = operation.via.map.ptr[index].val;
        if (error.type != MSGPACK_OBJECT_MAP) {
            return;
        }

        for (error_index = 0; error_index < error.via.map.size; error_index++) {
            value = error.via.map.ptr[error_index].val;
            if (object_key_equals(error.via.map.ptr[error_index].key,
                                  "type", 4) == FLB_TRUE) {
                copy_error_text(stats->first_error_type,
                                sizeof(stats->first_error_type), value);
            }
            else if (object_key_equals(error.via.map.ptr[error_index].key,
                                       "reason", 6) == FLB_TRUE) {
                copy_error_text(stats->first_error_reason,
                                sizeof(stats->first_error_reason), value);
            }
        }
        return;
    }
}

static int classify_item(msgpack_object item,
                         int acknowledge_all_conflicts,
                         int *out_status,
                         msgpack_object *out_operation)
{
    int index;
    int status;
    msgpack_object operation;
    msgpack_object key;
    msgpack_object value;

    if (item.type != MSGPACK_OBJECT_MAP || item.via.map.size != 1) {
        return FLB_SEARCH_BULK_ITEM_INVALID;
    }

    key = item.via.map.ptr[0].key;
    operation = item.via.map.ptr[0].val;
    if (key.type != MSGPACK_OBJECT_STR || operation.type != MSGPACK_OBJECT_MAP) {
        return FLB_SEARCH_BULK_ITEM_INVALID;
    }

    status = -1;
    for (index = 0; index < operation.via.map.size; index++) {
        value = operation.via.map.ptr[index].val;
        if (object_key_equals(operation.via.map.ptr[index].key,
                              "status", 6) == FLB_TRUE) {
            if (value.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
                return FLB_SEARCH_BULK_ITEM_INVALID;
            }
            if (value.via.u64 > INT_MAX) {
                return FLB_SEARCH_BULK_ITEM_INVALID;
            }
            status = (int) value.via.u64;
            break;
        }
    }

    if (status < 0) {
        return FLB_SEARCH_BULK_ITEM_INVALID;
    }

    *out_status = status;
    *out_operation = operation;

    if (status >= 200 && status < 300) {
        return FLB_SEARCH_BULK_ITEM_ACKNOWLEDGED;
    }
    if (status == 409) {
        if (acknowledge_all_conflicts == FLB_TRUE ||
            object_key_equals(key, "create", 6) == FLB_TRUE) {
            return FLB_SEARCH_BULK_ITEM_ACKNOWLEDGED;
        }

        return FLB_SEARCH_BULK_ITEM_RETRYABLE;
    }
    if (status >= 400 && status < 500 && status != 408 && status != 429) {
        return FLB_SEARCH_BULK_ITEM_UNRECOVERABLE;
    }

    return FLB_SEARCH_BULK_ITEM_RETRYABLE;
}

static int next_entry(const char *payload, size_t payload_size,
                      size_t *offset, size_t *entry_start, size_t *entry_size)
{
    const char *line_end;
    const char *record_end;
    size_t remaining;

    if (*offset >= payload_size) {
        return -1;
    }

    *entry_start = *offset;
    remaining = payload_size - *offset;
    line_end = memchr(payload + *offset, '\n', remaining);
    if (line_end == NULL) {
        return -1;
    }

    *offset = (line_end - payload) + 1;
    remaining = payload_size - *offset;
    record_end = memchr(payload + *offset, '\n', remaining);
    if (record_end == NULL) {
        return -1;
    }

    *offset = (record_end - payload) + 1;
    *entry_size = *offset - *entry_start;
    return 0;
}

void flb_search_bulk_retry_destroy(void *data)
{
    struct flb_search_bulk_retry *retry;

    retry = data;
    if (retry == NULL) {
        return;
    }

    flb_free(retry->payload);
    flb_free(retry);
}

int flb_search_bulk_process_response(const char *response,
                                     size_t response_size,
                                     const char *payload,
                                     size_t payload_size,
                                     int acknowledge_all_conflicts,
                                     int drop_unrecoverable_records,
                                     struct flb_search_bulk_stats *stats,
                                     struct flb_search_bulk_retry **out_retry)
{
    int index;
    int result;
    int root_type;
    int errors_found;
    int has_errors;
    int item_result;
    int status;
    char *packed_response;
    size_t packed_size;
    size_t unpack_offset;
    size_t payload_offset;
    size_t entry_start;
    size_t entry_size;
    msgpack_unpacked unpacked;
    msgpack_object root;
    msgpack_object items;
    msgpack_object key;
    msgpack_object value;
    msgpack_object operation;
    struct flb_search_bulk_retry *retry;

    *out_retry = NULL;
    if (stats != NULL) {
        memset(stats, 0, sizeof(struct flb_search_bulk_stats));
    }
    packed_response = NULL;
    retry = NULL;
    items.type = MSGPACK_OBJECT_NIL;
    errors_found = FLB_FALSE;
    has_errors = FLB_FALSE;

    result = flb_pack_json(response, response_size,
                           &packed_response, &packed_size,
                           &root_type, NULL);
    if (result != 0) {
        /*
         * A successful bulk response can exceed the configured HTTP response
         * buffer. Preserve the success marker available at the start of the
         * bounded response instead of retrying an already accepted batch.
        */
        if (top_level_errors_is_false(response, response_size) == FLB_TRUE) {
            return FLB_SEARCH_BULK_COMPLETE;
        }
        return FLB_SEARCH_BULK_INVALID;
    }

    msgpack_unpacked_init(&unpacked);
    unpack_offset = 0;
    result = msgpack_unpack_next(&unpacked, packed_response,
                                 packed_size, &unpack_offset);
    if (result != MSGPACK_UNPACK_SUCCESS) {
        result = FLB_SEARCH_BULK_INVALID;
        goto done;
    }

    root = unpacked.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        result = FLB_SEARCH_BULK_INVALID;
        goto done;
    }

    for (index = 0; index < root.via.map.size; index++) {
        key = root.via.map.ptr[index].key;
        value = root.via.map.ptr[index].val;

        if (object_key_equals(key, "errors", 6) == FLB_TRUE) {
            if (value.type != MSGPACK_OBJECT_BOOLEAN) {
                result = FLB_SEARCH_BULK_INVALID;
                goto done;
            }
            errors_found = FLB_TRUE;
            has_errors = value.via.boolean;
        }
        else if (object_key_equals(key, "items", 5) == FLB_TRUE) {
            if (value.type != MSGPACK_OBJECT_ARRAY) {
                result = FLB_SEARCH_BULK_INVALID;
                goto done;
            }
            items = value;
        }
    }

    if (errors_found == FLB_FALSE) {
        result = FLB_SEARCH_BULK_INVALID;
        goto done;
    }
    if (has_errors == FLB_FALSE) {
        result = FLB_SEARCH_BULK_COMPLETE;
        goto done;
    }
    if (items.type != MSGPACK_OBJECT_ARRAY) {
        result = FLB_SEARCH_BULK_INVALID;
        goto done;
    }

    retry = flb_calloc(1, sizeof(struct flb_search_bulk_retry));
    if (retry == NULL) {
        result = FLB_SEARCH_BULK_INVALID;
        goto done;
    }
    retry->payload = flb_malloc(payload_size);
    if (retry->payload == NULL) {
        result = FLB_SEARCH_BULK_INVALID;
        goto done;
    }

    payload_offset = 0;
    for (index = 0; index < items.via.array.size; index++) {
        if (next_entry(payload, payload_size, &payload_offset,
                       &entry_start, &entry_size) != 0) {
            result = FLB_SEARCH_BULK_INVALID;
            goto done;
        }

        item_result = classify_item(items.via.array.ptr[index],
                                    acknowledge_all_conflicts,
                                    &status, &operation);
        if (item_result == FLB_SEARCH_BULK_ITEM_INVALID) {
            result = FLB_SEARCH_BULK_INVALID;
            goto done;
        }

        if (stats != NULL) {
            stats->total_items++;
            if (item_result == FLB_SEARCH_BULK_ITEM_ACKNOWLEDGED) {
                stats->successful_items++;
                stats->successful_bytes += entry_size;
            }
        }
        if (item_result != FLB_SEARCH_BULK_ITEM_ACKNOWLEDGED) {
            capture_first_error(stats, status, operation);
            if (stats != NULL) {
                stats->failed_items++;
                if (item_result == FLB_SEARCH_BULK_ITEM_UNRECOVERABLE) {
                    stats->unrecoverable_items++;
                    stats->unrecoverable_bytes += entry_size;
                }
                else {
                    stats->retryable_items++;
                }
            }
        }

        if (item_result == FLB_SEARCH_BULK_ITEM_RETRYABLE ||
            (item_result == FLB_SEARCH_BULK_ITEM_UNRECOVERABLE &&
             drop_unrecoverable_records == FLB_FALSE)) {
            memcpy(retry->payload + retry->size,
                   payload + entry_start, entry_size);
            retry->size += entry_size;
            retry->records++;
        }
    }

    if (payload_offset != payload_size) {
        result = FLB_SEARCH_BULK_INVALID;
        goto done;
    }
    if (retry->records == 0) {
        result = FLB_SEARCH_BULK_COMPLETE;
        goto done;
    }

    *out_retry = retry;
    retry = NULL;
    result = FLB_SEARCH_BULK_RETRY;

 done:
    flb_search_bulk_retry_destroy(retry);
    msgpack_unpacked_destroy(&unpacked);
    flb_free(packed_response);
    return result;
}
