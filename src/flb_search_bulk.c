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
#include <string.h>

static int object_key_equals(msgpack_object key, const char *value, size_t length)
{
    if (key.type != MSGPACK_OBJECT_STR || key.via.str.size != length) {
        return FLB_FALSE;
    }

    return strncmp(key.via.str.ptr, value, length) == 0;
}

static int response_contains(const char *response, size_t response_size,
                             const char *value, size_t value_size)
{
    size_t index;

    if (value_size > response_size) {
        return FLB_FALSE;
    }

    for (index = 0; index <= response_size - value_size; index++) {
        if (memcmp(response + index, value, value_size) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int item_is_acknowledged(msgpack_object item,
                                int acknowledge_all_conflicts)
{
    int index;
    int status;
    msgpack_object operation;
    msgpack_object key;
    msgpack_object value;

    if (item.type != MSGPACK_OBJECT_MAP || item.via.map.size != 1) {
        return -1;
    }

    key = item.via.map.ptr[0].key;
    operation = item.via.map.ptr[0].val;
    if (key.type != MSGPACK_OBJECT_STR || operation.type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    status = -1;
    for (index = 0; index < operation.via.map.size; index++) {
        value = operation.via.map.ptr[index].val;
        if (object_key_equals(operation.via.map.ptr[index].key,
                              "status", 6) == FLB_TRUE) {
            if (value.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
                return -1;
            }
            status = value.via.u64;
            break;
        }
    }

    if (status < 0) {
        return -1;
    }
    if (status >= 200 && status < 300) {
        return FLB_TRUE;
    }
    if (status == 409) {
        if (acknowledge_all_conflicts == FLB_TRUE ||
            object_key_equals(key, "create", 6) == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
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
                                     struct flb_search_bulk_retry **out_retry)
{
    int index;
    int result;
    int root_type;
    int errors_found;
    int has_errors;
    int acknowledged;
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
    struct flb_search_bulk_retry *retry;

    *out_retry = NULL;
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
        if (response_contains(response, response_size,
                              "\"errors\":false,\"items\":[",
                              sizeof("\"errors\":false,\"items\":[") - 1) == FLB_TRUE) {
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

        acknowledged = item_is_acknowledged(items.via.array.ptr[index],
                                            acknowledge_all_conflicts);
        if (acknowledged < 0) {
            result = FLB_SEARCH_BULK_INVALID;
            goto done;
        }
        if (acknowledged == FLB_FALSE) {
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
