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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_upstream.h>

#include <msgpack.h>

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FLB_SYSTEM_WINDOWS
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "manticore.h"

#define MANTICORE_STREAM_OK             0
#define MANTICORE_STREAM_RETRY          1
#define MANTICORE_STREAM_RECORD_ERROR   2
struct manticore_id_list {
    uint64_t *values;
    size_t count;
    size_t capacity;
};

static int append(flb_sds_t *buf, const char *data, size_t len)
{
    return flb_sds_cat_safe(buf, data, len);
}

static int is_query_component_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.' || c == '~';
}

static flb_sds_t build_bulk_uri(const char *table)
{
    int ret;
    size_t i;
    char encoded[4];
    flb_sds_t uri;

    uri = flb_sds_create(FLB_MANTICORE_BULK_URI);
    if (uri == NULL) {
        return NULL;
    }

    for (i = 0; table[i] != '\0'; i++) {
        if (is_query_component_char((unsigned char) table[i])) {
            ret = append(&uri, &table[i], 1);
        }
        else {
            snprintf(encoded, sizeof(encoded), "%%%02X",
                     (unsigned char) table[i]);
            ret = append(&uri, encoded, 3);
        }

        if (ret != 0) {
            flb_sds_destroy(uri);
            return NULL;
        }
    }

    return uri;
}

static char *object_to_json(const msgpack_object *obj, int escape_unicode)
{
    return flb_msgpack_to_json_str(256, obj, escape_unicode);
}

static int key_equals(const msgpack_object *key, const char *name)
{
    size_t len;

    if (key->type != MSGPACK_OBJECT_STR || name == NULL) {
        return FLB_FALSE;
    }

    len = strlen(name);
    if (key->via.str.size != len) {
        return FLB_FALSE;
    }

    return memcmp(key->via.str.ptr, name, len) == 0;
}

static int parse_id(const msgpack_object *value, uint64_t *id)
{
    size_t i;
    uint64_t current;
    unsigned int digit;

    if (value->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        if (value->via.u64 == 0) {
            return -1;
        }
        *id = value->via.u64;
        return 0;
    }

    if (value->type != MSGPACK_OBJECT_STR || value->via.str.size == 0) {
        return -1;
    }

    current = 0;
    for (i = 0; i < value->via.str.size; i++) {
        if (value->via.str.ptr[i] < '0' || value->via.str.ptr[i] > '9') {
            return -1;
        }
        digit = value->via.str.ptr[i] - '0';
        if (current > (UINT64_MAX - digit) / 10) {
            return -1;
        }
        current = current * 10 + digit;
    }

    if (current == 0) {
        return -1;
    }
    *id = current;
    return 0;
}

static int append_id(struct manticore_id_list *ids, uint64_t id)
{
    size_t capacity;
    uint64_t *values;

    if (ids->count == ids->capacity) {
        capacity = ids->capacity == 0 ? 64 : ids->capacity * 2;
        if (capacity < ids->capacity ||
            capacity > SIZE_MAX / sizeof(uint64_t)) {
            return -1;
        }
        values = flb_realloc(ids->values, capacity * sizeof(uint64_t));
        if (values == NULL) {
            return -1;
        }
        ids->values = values;
        ids->capacity = capacity;
    }

    ids->values[ids->count++] = id;
    return 0;
}

static int compare_ids(const void *left, const void *right)
{
    uint64_t a;
    uint64_t b;

    a = *(const uint64_t *) left;
    b = *(const uint64_t *) right;
    return (a > b) - (a < b);
}

static int validate_record(struct flb_out_manticore *ctx,
                           const msgpack_object *body, uint64_t *id)
{
    int i;
    int id_found;
    const msgpack_object_kv *entry;

    if (body == NULL || body->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "log record body must be a map");
        return -1;
    }

    entry = body->via.map.ptr;
    id_found = FLB_FALSE;
    for (i = 0; i < body->via.map.size; i++) {
        if (entry[i].key.type != MSGPACK_OBJECT_STR) {
            flb_plg_error(ctx->ins, "record keys must be strings");
            return -1;
        }

        if (!key_equals(&entry[i].key, ctx->id_key)) {
            continue;
        }

        if (id_found || parse_id(&entry[i].val, id) != 0) {
            flb_plg_error(ctx->ins,
                          "record key '%s' must be a unique, non-zero numeric ID",
                          ctx->id_key);
            return -1;
        }
        id_found = FLB_TRUE;
    }

    if (!id_found) {
        flb_plg_error(ctx->ins,
                      "record key '%s' must contain a non-zero numeric ID",
                      ctx->id_key);
        return -1;
    }

    return 0;
}

static int validate_events(struct flb_out_manticore *ctx,
                           const void *data, size_t bytes,
                           struct manticore_id_list *collected_ids)
{
    int ret;
    size_t i;
    uint64_t id;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;
    struct manticore_id_list ids = {0};

    ret = flb_log_event_decoder_init(&decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "could not initialize log event decoder: %s",
                      flb_log_event_decoder_get_error_description(ret));
        return MANTICORE_STREAM_RETRY;
    }

    while (flb_log_event_decoder_next(&decoder, &event) ==
           FLB_EVENT_DECODER_SUCCESS) {
        if (validate_record(ctx, event.body, &id) != 0) {
            flb_free(ids.values);
            flb_log_event_decoder_destroy(&decoder);
            return MANTICORE_STREAM_RECORD_ERROR;
        }
        if (append_id(&ids, id) != 0) {
            flb_plg_error(ctx->ins, "could not allocate document ID preflight");
            flb_free(ids.values);
            flb_log_event_decoder_destroy(&decoder);
            return MANTICORE_STREAM_RETRY;
        }
    }

    ret = flb_log_event_decoder_get_last_result(&decoder);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "could not decode log event: %s",
                      flb_log_event_decoder_get_error_description(ret));
    }
    else if (ids.count == 0) {
        flb_plg_error(ctx->ins, "bulk_import requires at least one record");
        ret = MANTICORE_STREAM_RECORD_ERROR;
    }
    else if (ids.count > 1) {
        qsort(ids.values, ids.count, sizeof(uint64_t), compare_ids);
        for (i = 1; i < ids.count; i++) {
            if (ids.values[i - 1] == ids.values[i]) {
                flb_plg_error(ctx->ins,
                              "record key '%s' must be unique within a chunk",
                              ctx->id_key);
                ret = MANTICORE_STREAM_RECORD_ERROR;
                break;
            }
        }
    }

    flb_log_event_decoder_destroy(&decoder);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_free(ids.values);
        return MANTICORE_STREAM_RECORD_ERROR;
    }

    if (collected_ids != NULL) {
        *collected_ids = ids;
    }
    else {
        flb_free(ids.values);
    }
    return MANTICORE_STREAM_OK;
}

static flb_sds_t format_record(struct flb_out_manticore *ctx,
                               const msgpack_object *body)
{
    int ret;
    int i;
    int id_len;
    int fields;
    uint64_t numeric_id;
    char id_json[32];
    char *key_json;
    char *value_json;
    flb_sds_t out;
    const msgpack_object *id;
    const msgpack_object_kv *entry;

    if (body == NULL || body->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    id = NULL;
    fields = 0;
    entry = body->via.map.ptr;

    for (i = 0; i < body->via.map.size; i++) {
        if (key_equals(&entry[i].key, ctx->id_key)) {
            id = &entry[i].val;
        }
        else {
            fields++;
        }
    }

    if (id == NULL || parse_id(id, &numeric_id) != 0) {
        return NULL;
    }
    id_len = snprintf(id_json, sizeof(id_json), "%" PRIu64, numeric_id);
    if (id_len <= 0 || id_len >= sizeof(id_json)) {
        return NULL;
    }

    out = flb_sds_create_size(512);
    if (out == NULL) {
        return NULL;
    }

    ret = append(&out, "{\"", sizeof("{\"") - 1);
    ret |= append(&out, ctx->bulk_action, strlen(ctx->bulk_action));
    ret |= append(&out, "\":{\"table\":", sizeof("\":{\"table\":") - 1);
    ret |= append(&out, ctx->table_json, flb_sds_len(ctx->table_json));
    ret |= append(&out, ",\"id\":", sizeof(",\"id\":") - 1);
    ret |= append(&out, id_json, id_len);
    ret |= append(&out, ",\"doc\":{", sizeof(",\"doc\":{") - 1);

    fields = 0;
    for (i = 0; i < body->via.map.size; i++) {
        if (key_equals(&entry[i].key, ctx->id_key)) {
            continue;
        }

        key_json = object_to_json(&entry[i].key,
                                  ctx->config->json_escape_unicode);
        value_json = object_to_json(&entry[i].val,
                                    ctx->config->json_escape_unicode);
        if (key_json == NULL || value_json == NULL) {
            flb_free(key_json);
            flb_free(value_json);
            flb_sds_destroy(out);
            return NULL;
        }

        if (fields++ > 0) {
            ret |= append(&out, ",", sizeof(",") - 1);
        }
        ret |= append(&out, key_json, strlen(key_json));
        ret |= append(&out, ":", sizeof(":") - 1);
        ret |= append(&out, value_json, strlen(value_json));
        flb_free(key_json);
        flb_free(value_json);

        if (ret != 0) {
            flb_sds_destroy(out);
            return NULL;
        }
    }

    ret |= append(&out, "}}}\n", sizeof("}}}\n") - 1);
    if (ret != 0) {
        flb_sds_destroy(out);
        return NULL;
    }

    return out;
}

static int write_all(struct flb_connection *connection,
                     const void *data, size_t length)
{
    int ret;
    size_t written;

    written = 0;
    ret = flb_io_net_write(connection, data, length, &written);
    if (ret == -1 || written != length) {
        return -1;
    }

    return 0;
}

static int write_chunk(struct flb_connection *connection,
                       const void *data, size_t length)
{
    int len;
    char header[32];

    len = snprintf(header, sizeof(header), "%zx\r\n", length);
    if (len <= 0 || len >= sizeof(header)) {
        return -1;
    }

    if (write_all(connection, header, len) != 0 ||
        write_all(connection, data, length) != 0 ||
        write_all(connection, "\r\n", 2) != 0) {
        return -1;
    }

    return 0;
}

static void inspect_item_status(const msgpack_object *item,
                                int *has_status, int *retryable)
{
    int i;
    msgpack_object action;
    msgpack_object key;
    msgpack_object value;

    if (item->type != MSGPACK_OBJECT_MAP || item->via.map.size != 1) {
        return;
    }

    action = item->via.map.ptr[0].val;
    if (action.type != MSGPACK_OBJECT_MAP) {
        return;
    }

    for (i = 0; i < action.via.map.size; i++) {
        key = action.via.map.ptr[i].key;
        value = action.via.map.ptr[i].val;
        if (key.type != MSGPACK_OBJECT_STR || key.via.str.size != 6 ||
            memcmp(key.via.str.ptr, "status", 6) != 0) {
            continue;
        }

        if (value.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            *has_status = FLB_TRUE;
            if (value.via.u64 == 408 || value.via.u64 == 429 ||
                value.via.u64 >= 500) {
                *retryable = FLB_TRUE;
            }
            return;
        }
    }
}

static void inspect_response_items(const msgpack_object *items,
                                   int *has_status, int *retryable)
{
    int i;

    if (items->type != MSGPACK_OBJECT_ARRAY) {
        return;
    }

    for (i = 0; i < items->via.array.size; i++) {
        inspect_item_status(&items->via.array.ptr[i], has_status, retryable);
    }
}

static int response_ok(struct flb_out_manticore *ctx,
                       struct flb_http_client *client)
{
    int i;
    int ret;
    int root_type;
    int errors;
    int has_status;
    int retryable;
    char *packed;
    size_t packed_size;
    size_t offset;
    msgpack_object root;
    msgpack_object key;
    msgpack_object value;
    msgpack_unpacked result;

    packed = NULL;
    packed_size = 0;
    errors = -1;
    has_status = FLB_FALSE;
    retryable = FLB_FALSE;
    if (client->resp.payload_size > 0) {
        ret = flb_pack_json(client->resp.payload, client->resp.payload_size,
                            &packed, &packed_size, &root_type, NULL);
        if (ret == 0) {
            msgpack_unpacked_init(&result);
            offset = 0;
            ret = msgpack_unpack_next(&result, packed, packed_size, &offset);
            if (ret == MSGPACK_UNPACK_SUCCESS) {
                root = result.data;
                if (root.type == MSGPACK_OBJECT_MAP) {
                    for (i = 0; i < root.via.map.size; i++) {
                        key = root.via.map.ptr[i].key;
                        value = root.via.map.ptr[i].val;
                        if (key.type == MSGPACK_OBJECT_STR &&
                            key.via.str.size == 6 &&
                            memcmp(key.via.str.ptr, "errors", 6) == 0 &&
                            value.type == MSGPACK_OBJECT_BOOLEAN) {
                            errors = value.via.boolean;
                        }
                        else if (key.type == MSGPACK_OBJECT_STR &&
                                 key.via.str.size == 5 &&
                                 memcmp(key.via.str.ptr, "items", 5) == 0) {
                            inspect_response_items(&value, &has_status, &retryable);
                        }
                    }
                }
            }
            msgpack_unpacked_destroy(&result);
        }
        flb_free(packed);
    }

    if (client->resp.status >= 200 && client->resp.status < 300) {
        if (errors == FLB_FALSE) {
            return FLB_OK;
        }

        if (errors == FLB_TRUE && retryable == FLB_TRUE) {
            flb_plg_warn(ctx->ins,
                         "Manticore /bulk returned a retryable item error");
            return FLB_RETRY;
        }

        flb_plg_error(ctx->ins, "invalid or failed Manticore /bulk response: %.*s",
                      (int) client->resp.payload_size,
                      client->resp.payload);
        return FLB_ERROR;
    }

    if (client->resp.payload_size > 0) {
        flb_plg_error(ctx->ins, "Manticore /bulk returned HTTP %d: %.*s",
                      client->resp.status,
                      (int) client->resp.payload_size,
                      client->resp.payload);
    }
    else {
        flb_plg_error(ctx->ins, "Manticore /bulk returned HTTP %d",
                      client->resp.status);
    }

    if (retryable == FLB_TRUE || client->resp.status == 408 ||
        client->resp.status == 429) {
        return FLB_RETRY;
    }

    if (client->resp.status >= 500 && has_status == FLB_FALSE) {
        return FLB_RETRY;
    }

    return FLB_ERROR;
}

static int stream_events(struct flb_out_manticore *ctx,
                         struct flb_connection *connection,
                         const void *data, size_t bytes)
{
    int ret;
    flb_sds_t line;
    flb_sds_t chunk;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;

    ret = flb_log_event_decoder_init(&decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        return MANTICORE_STREAM_RETRY;
    }

    chunk = flb_sds_create_size(ctx->stream_chunk_size);
    if (chunk == NULL) {
        flb_log_event_decoder_destroy(&decoder);
        return MANTICORE_STREAM_RETRY;
    }

    while ((ret = flb_log_event_decoder_next(&decoder, &event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        line = format_record(ctx, event.body);
        if (line == NULL) {
            ret = MANTICORE_STREAM_RETRY;
            break;
        }

        if (flb_sds_len(chunk) > 0 &&
            flb_sds_len(chunk) + flb_sds_len(line) > ctx->stream_chunk_size) {
            if (write_chunk(connection, chunk, flb_sds_len(chunk)) != 0) {
                flb_sds_destroy(line);
                ret = MANTICORE_STREAM_RETRY;
                break;
            }
            flb_sds_len_set(chunk, 0);
            chunk[0] = '\0';
        }

        if (flb_sds_len(line) > ctx->stream_chunk_size) {
            ret = write_chunk(connection, line, flb_sds_len(line));
        }
        else {
            ret = append(&chunk, line, flb_sds_len(line));
        }
        flb_sds_destroy(line);

        if (ret != 0) {
            ret = MANTICORE_STREAM_RETRY;
            break;
        }
    }

    if (ret != MANTICORE_STREAM_RETRY &&
        ret != MANTICORE_STREAM_RECORD_ERROR) {
        ret = flb_log_event_decoder_get_last_result(&decoder);
        if (ret == FLB_EVENT_DECODER_SUCCESS) {
            ret = MANTICORE_STREAM_OK;
        }
        else {
            flb_plg_error(ctx->ins, "could not decode log event: %s",
                          flb_log_event_decoder_get_error_description(ret));
            ret = MANTICORE_STREAM_RECORD_ERROR;
        }
    }

    if (ret == MANTICORE_STREAM_OK && flb_sds_len(chunk) > 0) {
        if (write_chunk(connection, chunk, flb_sds_len(chunk)) != 0) {
            ret = MANTICORE_STREAM_RETRY;
        }
    }

    flb_sds_destroy(chunk);
    flb_log_event_decoder_destroy(&decoder);
    return ret;
}

#ifndef FLB_SYSTEM_WINDOWS
static size_t session_id_slot(uint64_t id, size_t capacity)
{
    id ^= id >> 33;
    id *= UINT64_C(0xff51afd7ed558ccd);
    id ^= id >> 33;
    id *= UINT64_C(0xc4ceb9fe1a85ec53);
    id ^= id >> 33;
    return (size_t) id & (capacity - 1);
}

static int session_id_contains(struct flb_out_manticore *ctx, uint64_t id)
{
    size_t slot;

    if (ctx->session_id_capacity == 0) {
        return FLB_FALSE;
    }
    slot = session_id_slot(id, ctx->session_id_capacity);
    while (ctx->session_ids[slot] != 0) {
        if (ctx->session_ids[slot] == id) {
            return FLB_TRUE;
        }
        slot = (slot + 1) & (ctx->session_id_capacity - 1);
    }
    return FLB_FALSE;
}

static void session_id_insert(struct flb_out_manticore *ctx, uint64_t id)
{
    size_t slot;

    slot = session_id_slot(id, ctx->session_id_capacity);
    while (ctx->session_ids[slot] != 0) {
        slot = (slot + 1) & (ctx->session_id_capacity - 1);
    }
    ctx->session_ids[slot] = id;
    ctx->session_id_count++;
}

static int prepare_session_ids(struct flb_out_manticore *ctx,
                               struct manticore_id_list *incoming)
{
    size_t i;
    size_t required;
    size_t capacity;
    uint64_t *old_ids;
    uint64_t *new_ids;
    size_t old_capacity;

    if (incoming->count > SIZE_MAX - ctx->session_id_count) {
        return -1;
    }
    required = incoming->count + ctx->session_id_count;
    if (required > ctx->max_session_ids) {
        flb_plg_error(ctx->ins,
                      "single-chunk session exceeds max_session_ids (%zu)",
                      ctx->max_session_ids);
        return MANTICORE_STREAM_RECORD_ERROR;
    }
    capacity = ctx->session_id_capacity == 0 ? 128 : ctx->session_id_capacity;
    while (required > capacity / 2) {
        if (capacity > SIZE_MAX / 2) {
            return -1;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(uint64_t)) {
        return -1;
    }

    for (i = 0; i < incoming->count; i++) {
        if (session_id_contains(ctx, incoming->values[i])) {
            flb_plg_error(ctx->ins,
                          "record key '%s' must be unique within a session",
                          ctx->id_key);
            return MANTICORE_STREAM_RECORD_ERROR;
        }
    }

    if (capacity != ctx->session_id_capacity) {
        new_ids = flb_calloc(capacity, sizeof(uint64_t));
        if (new_ids == NULL) {
            return -1;
        }
        old_ids = ctx->session_ids;
        old_capacity = ctx->session_id_capacity;
        ctx->session_ids = new_ids;
        ctx->session_id_capacity = capacity;
        ctx->session_id_count = 0;
        for (i = 0; i < old_capacity; i++) {
            if (old_ids[i] != 0) {
                session_id_insert(ctx, old_ids[i]);
            }
        }
        flb_free(old_ids);
    }
    return MANTICORE_STREAM_OK;
}

static int rollback_spool(struct flb_out_manticore *ctx, off_t offset)
{
    int failed;

    failed = FLB_FALSE;
    clearerr(ctx->spool);
    if (fflush(ctx->spool) != 0) {
        failed = FLB_TRUE;
    }
    if (ftruncate(ctx->spool_fd, offset) != 0) {
        failed = FLB_TRUE;
    }
    if (fseeko(ctx->spool, offset, SEEK_SET) != 0) {
        failed = FLB_TRUE;
    }
    if (failed == FLB_TRUE) {
        flb_plg_error(ctx->ins, "could not roll back spool '%s'",
                      ctx->spool_path);
        return -1;
    }
    return 0;
}

static int rollback_commit(struct flb_out_manticore *ctx, off_t offset)
{
    int failed;

    failed = FLB_FALSE;
    clearerr(ctx->commit);
    if (fflush(ctx->commit) != 0) {
        failed = FLB_TRUE;
    }
    if (ftruncate(ctx->commit_fd, offset) != 0) {
        failed = FLB_TRUE;
    }
    if (fseeko(ctx->commit, offset, SEEK_SET) != 0) {
        failed = FLB_TRUE;
    }
    if (failed == FLB_TRUE) {
        flb_plg_error(ctx->ins, "could not roll back commit journal '%s'",
                      ctx->commit_path);
        return -1;
    }
    return 0;
}

static uint64_t hash_bytes(uint64_t hash, const void *data, size_t length)
{
    size_t i;
    const unsigned char *bytes;

    bytes = data;
    for (i = 0; i < length; i++) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static int hash_file_range(int fd, off_t start, off_t end, uint64_t *result)
{
    ssize_t length;
    off_t offset;
    uint64_t hash;
    char *buffer;
    size_t requested;

    buffer = flb_malloc(65536);
    if (buffer == NULL) {
        return -1;
    }
    hash = UINT64_C(1469598103934665603);
    offset = start;
    while (offset < end) {
        requested = (size_t) (end - offset);
        if (requested > 65536) {
            requested = 65536;
        }
        length = pread(fd, buffer, requested, offset);
        if (length <= 0) {
            flb_free(buffer);
            return -1;
        }
        hash = hash_bytes(hash, buffer, (size_t) length);
        offset += length;
    }
    flb_free(buffer);
    *result = hash;
    return 0;
}

static int commit_spool_offset(struct flb_out_manticore *ctx, off_t start,
                               off_t offset,
                               off_t *journal_offset)
{
    uint64_t checksum;
    uint64_t value;

    if (offset < 0) {
        return -1;
    }
    *journal_offset = ftello(ctx->commit);
    if (*journal_offset < 0) {
        return -1;
    }
    value = (uint64_t) offset;
    if (hash_file_range(ctx->spool_fd, start, offset, &checksum) != 0 ||
        fprintf(ctx->commit,
                "%016" PRIx64 " %016" PRIx64 " %016" PRIx64 "\n",
                value, ~value, checksum) != 51 ||
        fflush(ctx->commit) != 0 || fsync(ctx->commit_fd) != 0) {
        if (rollback_commit(ctx, *journal_offset) != 0) {
            return -2;
        }
        return -1;
    }
    return 0;
}

static int spool_events(struct flb_out_manticore *ctx,
                        const void *data, size_t bytes)
{
    int ret;
    off_t offset;
    off_t journal_offset;
    off_t committed_offset;
    int commit_result;
    size_t i;

    flb_sds_t line;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;
    struct manticore_id_list ids = {0};

    ret = validate_events(ctx, data, bytes, &ids);
    if (ret != MANTICORE_STREAM_OK) {
        return ret == MANTICORE_STREAM_RETRY ? FLB_RETRY : FLB_ERROR;
    }

    ret = prepare_session_ids(ctx, &ids);
    if (ret != MANTICORE_STREAM_OK) {
        flb_free(ids.values);
        return ret == MANTICORE_STREAM_RECORD_ERROR ? FLB_ERROR : FLB_RETRY;
    }

    offset = ftello(ctx->spool);
    if (offset < 0 ||
        flb_log_event_decoder_init(&decoder, (char *) data, bytes) !=
        FLB_EVENT_DECODER_SUCCESS) {
        flb_free(ids.values);
        return FLB_RETRY;
    }

    ret = FLB_OK;
    while (flb_log_event_decoder_next(&decoder, &event) ==
           FLB_EVENT_DECODER_SUCCESS) {
        line = format_record(ctx, event.body);
        if (line == NULL) {
            ret = FLB_RETRY;
            break;
        }
        if (fwrite(line, 1, flb_sds_len(line), ctx->spool) !=
            flb_sds_len(line)) {
            flb_sds_destroy(line);
            ret = FLB_RETRY;
            break;
        }
        flb_sds_destroy(line);
    }
    flb_log_event_decoder_destroy(&decoder);

    if (ret == FLB_OK) {
        committed_offset = ftello(ctx->spool);
        commit_result = 0;
        if (committed_offset < 0 || fflush(ctx->spool) != 0 ||
            fsync(ctx->spool_fd) != 0) {
            ret = FLB_RETRY;
        }
        else {
            commit_result = commit_spool_offset(ctx, offset, committed_offset,
                                                &journal_offset);
            if (commit_result != 0) {
                ret = commit_result == -2 ? FLB_ERROR : FLB_RETRY;
            }
        }
    }
    if (ret != FLB_OK) {
        if (rollback_spool(ctx, offset) != 0) {
            ret = FLB_ERROR;
        }
    }
    else {
        for (i = 0; i < ids.count; i++) {
            session_id_insert(ctx, ids.values[i]);
        }
    }
    flb_free(ids.values);
    return ret;
}

static int stream_spool(struct flb_out_manticore *ctx,
                        struct flb_connection *connection)
{
    size_t length;
    char *buffer;

    buffer = flb_malloc(ctx->stream_chunk_size);
    if (buffer == NULL) {
        return -1;
    }
    if (fflush(ctx->spool) != 0 || fseeko(ctx->spool, 0, SEEK_SET) != 0) {
        flb_free(buffer);
        return -1;
    }

    while ((length = fread(buffer, 1, ctx->stream_chunk_size,
                           ctx->spool)) > 0) {
        if (write_chunk(connection, buffer, length) != 0) {
            flb_free(buffer);
            return -1;
        }
    }
    if (ferror(ctx->spool)) {
        clearerr(ctx->spool);
        flb_free(buffer);
        return -1;
    }
    flb_free(buffer);
    return 0;
}
#endif

static int send_stream(struct flb_out_manticore *ctx,
                       const void *data, size_t bytes)
{
    int ret;
    int result;
    size_t sent;
    struct flb_connection *connection;
    struct flb_http_client *client;

    /* A permanent record error must not follow already transmitted records. */
    ret = validate_events(ctx, data, bytes, NULL);
    if (ret != MANTICORE_STREAM_OK) {
        return ret == MANTICORE_STREAM_RETRY ? FLB_RETRY : FLB_ERROR;
    }

    connection = flb_upstream_conn_get(ctx->u);
    if (connection == NULL) {
        return FLB_RETRY;
    }

    client = flb_http_client(connection, FLB_HTTP_POST,
                             ctx->bulk_uri,
                             NULL, 0, NULL, 0, NULL, 0);
    if (client == NULL) {
        flb_upstream_conn_release(connection);
        return FLB_RETRY;
    }

    flb_http_remove_header(client, "Content-Length", 14);
    flb_http_remove_header(client, "Connection", 10);
    client->body_len = -1;
    flb_http_add_header(client, "Content-Type", 12,
                        "application/x-ndjson", 20);
    flb_http_add_header(client, "Transfer-Encoding", 17, "chunked", 7);
    flb_http_add_header(client, "Connection", 10, "close", 5);
    flb_http_add_header(client, "User-Agent", 10,
                        "Fluent-Bit-Manticore", 20);
    flb_http_buffer_size(client, ctx->buffer_size);

    if (ctx->http_user != NULL) {
        flb_http_basic_auth(client, ctx->http_user, ctx->http_passwd);
    }

    sent = 0;
    ret = flb_http_do_request(client, &sent);
    if (ret != FLB_HTTP_MORE) {
        result = FLB_RETRY;
        goto done;
    }

    ret = stream_events(ctx, connection, data, bytes);
    if (ret != MANTICORE_STREAM_OK) {
        result = ret == MANTICORE_STREAM_RECORD_ERROR ? FLB_ERROR : FLB_RETRY;
        goto done;
    }

    if (write_all(connection, "0\r\n\r\n", 5) != 0) {
        result = FLB_RETRY;
        goto done;
    }

    do {
        ret = flb_http_get_response_data(client, 0);
    } while (ret == FLB_HTTP_MORE || ret == FLB_HTTP_CHUNK_AVAILABLE);

    if (ret != FLB_HTTP_OK) {
        result = FLB_RETRY;
        goto done;
    }

    result = response_ok(ctx, client);

done:
    /* Closing the session releases Manticore's bulk_import reservation. */
    flb_upstream_conn_recycle(connection, FLB_FALSE);
    flb_http_client_destroy(client);
    flb_upstream_conn_release(connection);
    return result;
}

#ifndef FLB_SYSTEM_WINDOWS
static int send_spool(struct flb_out_manticore *ctx)
{
    int ret;
    int result;
    size_t sent;
    struct flb_connection *connection;
    struct flb_http_client *client;

    connection = flb_upstream_conn_get(ctx->u);
    if (connection == NULL) {
        return FLB_RETRY;
    }

    client = flb_http_client(connection, FLB_HTTP_POST, ctx->bulk_uri,
                             NULL, 0, NULL, 0, NULL, 0);
    if (client == NULL) {
        flb_upstream_conn_release(connection);
        return FLB_RETRY;
    }

    flb_http_remove_header(client, "Content-Length", 14);
    flb_http_remove_header(client, "Connection", 10);
    client->body_len = -1;
    flb_http_add_header(client, "Content-Type", 12,
                        "application/x-ndjson", 20);
    flb_http_add_header(client, "Transfer-Encoding", 17, "chunked", 7);
    flb_http_add_header(client, "Connection", 10, "close", 5);
    flb_http_add_header(client, "User-Agent", 10,
                        "Fluent-Bit-Manticore", 20);
    flb_http_buffer_size(client, ctx->buffer_size);
    if (ctx->http_user != NULL) {
        flb_http_basic_auth(client, ctx->http_user, ctx->http_passwd);
    }

    sent = 0;
    ret = flb_http_do_request(client, &sent);
    if (ret != FLB_HTTP_MORE || stream_spool(ctx, connection) != 0 ||
        write_all(connection, "0\r\n\r\n", 5) != 0) {
        result = FLB_RETRY;
        goto done;
    }

    do {
        ret = flb_http_get_response_data(client, 0);
    } while (ret == FLB_HTTP_MORE || ret == FLB_HTTP_CHUNK_AVAILABLE);
    result = ret == FLB_HTTP_OK ? response_ok(ctx, client) : FLB_RETRY;

done:
    flb_upstream_conn_recycle(connection, FLB_FALSE);
    flb_http_client_destroy(client);
    flb_upstream_conn_release(connection);
    return result;
}

static int recover_spool(struct flb_out_manticore *ctx)
{
    int consumed;
    off_t data_size;
    off_t good_end;
    off_t current;
    uint64_t checksum;
    uint64_t expected_checksum;
    uint64_t value;
    uint64_t inverse;
    char boundary;
    char line[128];
    struct stat status;

    if (fstat(ctx->spool_fd, &status) != 0 || status.st_size < 0) {
        return -1;
    }
    data_size = status.st_size;
    current = 0;
    good_end = 0;
    clearerr(ctx->commit);
    if (fseeko(ctx->commit, 0, SEEK_SET) != 0) {
        return -1;
    }

    if (fgets(line, sizeof(line), ctx->commit) == NULL) {
        if (ferror(ctx->commit) || data_size != 0) {
            return -1;
        }
        return 0;
    }

    if (fseeko(ctx->commit, 0, SEEK_SET) != 0) {
        return -1;
    }

    /* A successful upload can crash after the spool was truncated but before
     * its journal was cleared. The upload is already acknowledged by the
     * server, so validate complete journal records and reset the empty pair.
     */
    if (data_size == 0) {
        while (fgets(line, sizeof(line), ctx->commit) != NULL) {
            if (strchr(line, '\n') == NULL) {
                if (!feof(ctx->commit)) {
                    flb_plg_error(ctx->ins, "commit journal '%s' is corrupt",
                                  ctx->commit_path);
                    return -1;
                }
                break;
            }
            consumed = 0;
            if (sscanf(line,
                       "%16" SCNx64 " %16" SCNx64 " %16" SCNx64 "%n",
                       &value, &inverse, &expected_checksum, &consumed) != 3 ||
                consumed != 50 || line[consumed] != '\n' ||
                line[consumed + 1] != '\0' || inverse != ~value ||
                value == 0) {
                flb_plg_error(ctx->ins, "commit journal '%s' is corrupt",
                              ctx->commit_path);
                return -1;
            }
            good_end = ftello(ctx->commit);
            if (good_end < 0) {
                return -1;
            }
        }
        if (ferror(ctx->commit)) {
            return -1;
        }
        clearerr(ctx->commit);
        if (ftruncate(ctx->commit_fd, 0) != 0 ||
            fsync(ctx->commit_fd) != 0 ||
            fseeko(ctx->commit, 0, SEEK_END) != 0) {
            return -1;
        }
        return 0;
    }

    while (fgets(line, sizeof(line), ctx->commit) != NULL) {
        if (strchr(line, '\n') == NULL) {
            if (!feof(ctx->commit)) {
                flb_plg_error(ctx->ins, "commit journal '%s' is corrupt",
                              ctx->commit_path);
                return -1;
            }
            break;
        }
        consumed = 0;
        if (sscanf(line,
                   "%16" SCNx64 " %16" SCNx64 " %16" SCNx64 "%n",
                   &value, &inverse, &expected_checksum, &consumed) != 3 ||
            consumed != 50 || line[consumed] != '\n' ||
            line[consumed + 1] != '\0' || inverse != ~value ||
            value <= (uint64_t) current || value > (uint64_t) data_size ||
            hash_file_range(ctx->spool_fd, current, (off_t) value,
                            &checksum) != 0 || checksum != expected_checksum ||
            pread(ctx->spool_fd, &boundary, 1, (off_t) value - 1) != 1 ||
            boundary != '\n') {
            flb_plg_error(ctx->ins, "commit journal or spool '%s' is corrupt",
                          ctx->spool_path);
            return -1;
        }
        current = (off_t) value;
        good_end = ftello(ctx->commit);
        if (good_end < 0) {
            return -1;
        }
    }
    if (ferror(ctx->commit)) {
        return -1;
    }

    clearerr(ctx->commit);
    if (ftruncate(ctx->commit_fd, good_end) != 0 ||
        fsync(ctx->commit_fd) != 0 ||
        fseeko(ctx->commit, 0, SEEK_END) != 0) {
        return -1;
    }
    if (ftruncate(ctx->spool_fd, current) != 0 ||
        fsync(ctx->spool_fd) != 0 ||
        fseeko(ctx->spool, current, SEEK_SET) != 0) {
        return -1;
    }
    return 0;
}

static int sync_parent_directory(const char *path)
{
    int fd;
    int ret;
    char *copy;
    char *separator;

    copy = flb_strdup(path);
    if (copy == NULL) {
        return -1;
    }
    separator = strrchr(copy, '/');
    if (separator == NULL) {
        flb_free(copy);
        copy = flb_strdup(".");
        if (copy == NULL) {
            return -1;
        }
    }
    else if (separator == copy) {
        separator[1] = '\0';
    }
    else {
        *separator = '\0';
    }
#ifdef O_DIRECTORY
    fd = open(copy, O_RDONLY | O_DIRECTORY);
#else
    fd = open(copy, O_RDONLY);
#endif
    flb_free(copy);
    if (fd < 0) {
        return -1;
    }
    ret = fsync(fd);
    close(fd);
    return ret;
}

static int open_spool(struct flb_out_manticore *ctx)
{
    int flags;
    struct stat status;

    flags = O_CREAT | O_RDWR | O_APPEND;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    ctx->spool_fd = open(ctx->spool_path, flags, S_IRUSR | S_IWUSR);
    if (ctx->spool_fd < 0 || flock(ctx->spool_fd, LOCK_EX | LOCK_NB) != 0) {
        flb_plg_error(ctx->ins, "could not exclusively open spool '%s'",
                      ctx->spool_path);
        if (ctx->spool_fd >= 0) {
            close(ctx->spool_fd);
            ctx->spool_fd = -1;
        }
        return -1;
    }
    if (fstat(ctx->spool_fd, &status) != 0 || !S_ISREG(status.st_mode)) {
        flb_plg_error(ctx->ins, "spool '%s' must be a regular file",
                      ctx->spool_path);
        close(ctx->spool_fd);
        ctx->spool_fd = -1;
        return -1;
    }
    ctx->spool = fdopen(ctx->spool_fd, "a+");
    if (ctx->spool == NULL) {
        close(ctx->spool_fd);
        ctx->spool_fd = -1;
        return -1;
    }

    if (strlen(ctx->spool_path) > SIZE_MAX - 8) {
        fclose(ctx->spool);
        ctx->spool = NULL;
        ctx->spool_fd = -1;
        return -1;
    }
    ctx->commit_path = flb_sds_create_size(strlen(ctx->spool_path) + 8);
    if (ctx->commit_path == NULL ||
        flb_sds_printf(&ctx->commit_path, "%s.commit", ctx->spool_path) == NULL) {
        flb_sds_destroy(ctx->commit_path);
        ctx->commit_path = NULL;
        fclose(ctx->spool);
        ctx->spool = NULL;
        ctx->spool_fd = -1;
        return -1;
    }
    ctx->commit_fd = open(ctx->commit_path, flags, S_IRUSR | S_IWUSR);
    if (ctx->commit_fd < 0 || fstat(ctx->commit_fd, &status) != 0 ||
        !S_ISREG(status.st_mode)) {
        flb_plg_error(ctx->ins, "could not open commit journal '%s'",
                      ctx->commit_path);
        if (ctx->commit_fd >= 0) {
            close(ctx->commit_fd);
        }
        ctx->commit_fd = -1;
        fclose(ctx->spool);
        ctx->spool = NULL;
        ctx->spool_fd = -1;
        return -1;
    }
    ctx->commit = fdopen(ctx->commit_fd, "a+");
    if (ctx->commit == NULL) {
        close(ctx->commit_fd);
        ctx->commit_fd = -1;
        fclose(ctx->spool);
        ctx->spool = NULL;
        ctx->spool_fd = -1;
        return -1;
    }
    if (recover_spool(ctx) != 0 ||
        sync_parent_directory(ctx->spool_path) != 0) {
        flb_plg_error(ctx->ins, "could not recover durable spool '%s'",
                      ctx->spool_path);
        fclose(ctx->commit);
        ctx->commit = NULL;
        ctx->commit_fd = -1;
        fclose(ctx->spool);
        ctx->spool = NULL;
        ctx->spool_fd = -1;
        return -1;
    }
    return 0;
}

static int clear_spool(struct flb_out_manticore *ctx)
{
    clearerr(ctx->spool);
    if (fflush(ctx->spool) != 0 ||
        ftruncate(ctx->spool_fd, 0) != 0 ||
        fsync(ctx->spool_fd) != 0 ||
        fseeko(ctx->spool, 0, SEEK_SET) != 0) {
        flb_plg_error(ctx->ins, "could not clear spool '%s'",
                      ctx->spool_path);
        return -1;
    }

    /* Retire commit records only after the empty spool is durable. */
    clearerr(ctx->commit);
    if (fflush(ctx->commit) != 0 ||
        ftruncate(ctx->commit_fd, 0) != 0 ||
        fsync(ctx->commit_fd) != 0 ||
        fseeko(ctx->commit, 0, SEEK_END) != 0) {
        flb_plg_error(ctx->ins, "could not clear commit journal '%s'",
                      ctx->commit_path);
        return -1;
    }
    return 0;
}

static void close_spool(struct flb_out_manticore *ctx)
{
    if (ctx->commit != NULL) {
        fclose(ctx->commit);
        ctx->commit = NULL;
        ctx->commit_fd = -1;
    }
    if (ctx->spool != NULL) {
        fclose(ctx->spool);
        ctx->spool = NULL;
        ctx->spool_fd = -1;
    }
}

static int remove_owned_path(struct flb_out_manticore *ctx,
                             const char *path, int fd, const char *kind)
{
    struct stat open_status;
    struct stat path_status;

    if (fstat(fd, &open_status) != 0 || lstat(path, &path_status) != 0 ||
        open_status.st_dev != path_status.st_dev ||
        open_status.st_ino != path_status.st_ino) {
        flb_plg_warn(ctx->ins, "refusing to remove replaced %s '%s'", kind, path);
        return -1;
    }
    if (unlink(path) != 0) {
        flb_plg_warn(ctx->ins, "could not remove %s '%s'", kind, path);
        return -1;
    }
    return 0;
}

static void remove_spool(struct flb_out_manticore *ctx, const char *reason)
{
    int failed;

    failed = FLB_FALSE;
    if (remove_owned_path(ctx, ctx->spool_path, ctx->spool_fd,
                          reason) != 0) {
        failed = FLB_TRUE;
    }
    if (ctx->commit_path != NULL &&
        remove_owned_path(ctx, ctx->commit_path, ctx->commit_fd,
                          "commit journal") != 0) {
        failed = FLB_TRUE;
    }
    if (failed == FLB_FALSE && sync_parent_directory(ctx->spool_path) != 0) {
        flb_plg_warn(ctx->ins, "could not sync spool directory for '%s'",
                     ctx->spool_path);
    }
}
#endif

static int cb_manticore_init(struct flb_output_instance *ins,
                             struct flb_config *config, void *data)
{
    int io_flags;
    int ret;
    char *table_json;
    msgpack_object table;
    struct flb_out_manticore *ctx;
#ifndef FLB_SYSTEM_WINDOWS
    off_t spool_size;
#endif

    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_out_manticore));
    if (ctx == NULL) {
        return -1;
    }

    ctx->ins = ins;
    ctx->config = config;
    ctx->spool_fd = -1;
    ctx->commit_fd = -1;
    flb_output_net_default("127.0.0.1", FLB_MANTICORE_DEFAULT_PORT, ins);

    ret = flb_output_config_map_set(ins, ctx);
    if (ret == -1 || ctx->table == NULL || ctx->table[0] == '\0') {
        flb_plg_error(ins, "table is required");
        flb_free(ctx);
        return -1;
    }

    if (strcasecmp(ctx->action, "insert") != 0 &&
        strcasecmp(ctx->action, "create") != 0) {
        flb_plg_error(ins, "action must be 'insert' or 'create'");
        flb_free(ctx);
        return -1;
    }

    ctx->bulk_action = strcasecmp(ctx->action, "create") == 0 ?
                       "create" : "insert";

    if (ctx->single_chunk == FLB_TRUE) {
#ifdef FLB_SYSTEM_WINDOWS
        flb_plg_error(ins, "single_chunk is not supported on Windows");
        flb_free(ctx);
        return -1;
#else
        if (ins->tp_workers != 1) {
            flb_plg_error(ins, "single_chunk requires exactly one output worker");
            flb_free(ctx);
            return -1;
        }
        if (ctx->spool_path == NULL || ctx->spool_path[0] == '\0') {
            flb_plg_error(ins, "spool_path is required when single_chunk is enabled");
            flb_free(ctx);
            return -1;
        }
        if (strcasecmp(ctx->action, "insert") != 0) {
            flb_plg_error(ins, "single_chunk requires action 'insert' for replay safety");
            flb_free(ctx);
            return -1;
        }
#endif
    }

    if (ctx->stream_chunk_size == 0 || ctx->max_session_ids == 0) {
        flb_plg_error(ins,
                      "stream_chunk_size and max_session_ids must be greater than zero");
        flb_free(ctx);
        return -1;
    }

    table.type = MSGPACK_OBJECT_STR;
    table.via.str.ptr = ctx->table;
    table.via.str.size = strlen(ctx->table);
    table_json = object_to_json(&table, config->json_escape_unicode);
    if (table_json == NULL) {
        flb_free(ctx);
        return -1;
    }
    ctx->table_json = flb_sds_create(table_json);
    flb_free(table_json);
    if (ctx->table_json == NULL) {
        flb_free(ctx);
        return -1;
    }

    ctx->bulk_uri = build_bulk_uri(ctx->table);
    if (ctx->bulk_uri == NULL) {
        flb_sds_destroy(ctx->table_json);
        flb_free(ctx);
        return -1;
    }

    /* A persistent session would keep the bulk_import reservation active. */
    ins->net_setup.keepalive = FLB_FALSE;

    io_flags = ins->use_tls == FLB_TRUE ? FLB_IO_TLS : FLB_IO_TCP;
    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    ctx->u = flb_upstream_create(config, ins->host.name, ins->host.port,
                                 io_flags, ins->tls);
    if (ctx->u == NULL) {
        flb_sds_destroy(ctx->bulk_uri);
        flb_sds_destroy(ctx->table_json);
        flb_free(ctx);
        return -1;
    }
    flb_output_upstream_set(ctx->u, ins);

#ifndef FLB_SYSTEM_WINDOWS
    if (ctx->single_chunk == FLB_TRUE) {
        if (open_spool(ctx) != 0) {
            flb_upstream_destroy(ctx->u);
            flb_sds_destroy(ctx->bulk_uri);
            flb_sds_destroy(ctx->table_json);
            flb_sds_destroy(ctx->commit_path);
            flb_free(ctx);
            return -1;
        }
        spool_size = ftello(ctx->spool);
        if (spool_size < 0) {
            close_spool(ctx);
            flb_upstream_destroy(ctx->u);
            flb_sds_destroy(ctx->bulk_uri);
            flb_sds_destroy(ctx->table_json);
            flb_sds_destroy(ctx->commit_path);
            flb_free(ctx);
            return -1;
        }
        if (spool_size > 0) {
            flb_plg_info(ins, "replaying pending single-chunk spool '%s'",
                         ctx->spool_path);
            if (send_spool(ctx) != FLB_OK || clear_spool(ctx) != 0) {
                flb_plg_error(ins, "could not replay pending spool '%s'",
                              ctx->spool_path);
                close_spool(ctx);
                flb_upstream_destroy(ctx->u);
                flb_sds_destroy(ctx->bulk_uri);
                flb_sds_destroy(ctx->table_json);
                flb_sds_destroy(ctx->commit_path);
                flb_free(ctx);
                return -1;
            }
        }
    }
#endif
    flb_output_set_context(ins, ctx);
    flb_output_set_http_debug_callbacks(ins);
    return 0;
}

static void cb_manticore_flush(struct flb_event_chunk *event_chunk,
                               struct flb_output_flush *out_flush,
                               struct flb_input_instance *ins,
                               void *out_context,
                               struct flb_config *config)
{
    int ret;
    struct flb_out_manticore *ctx;

    (void) ins;
    (void) config;

    ctx = out_context;
    if (ctx->single_chunk == FLB_TRUE) {
#ifndef FLB_SYSTEM_WINDOWS
        if (ctx->session_failed == FLB_TRUE) {
            ret = FLB_ERROR;
        }
        else {
            ret = spool_events(ctx, event_chunk->data, event_chunk->size);
            if (ret == FLB_ERROR) {
                ctx->session_failed = FLB_TRUE;
                if (clear_spool(ctx) != 0) {
                    flb_plg_error(ctx->ins,
                                  "could not durably abort single-chunk session");
                }
            }
        }
#else
        ret = FLB_ERROR;
#endif
    }
    else {
        ret = send_stream(ctx, event_chunk->data, event_chunk->size);
    }
    FLB_OUTPUT_RETURN(ret);
}

static int cb_manticore_exit(void *data, struct flb_config *config)
{
    int fs_chunks;
    int mem_chunks;
    int tasks;
    int ret;
    struct flb_out_manticore *ctx;
#ifndef FLB_SYSTEM_WINDOWS
    off_t spool_size;
#endif

    ctx = data;
    if (ctx == NULL) {
        return 0;
    }

#ifndef FLB_SYSTEM_WINDOWS
    if (ctx->single_chunk == FLB_TRUE && ctx->spool != NULL) {
        if (ctx->session_failed == FLB_TRUE) {
            flb_plg_error(ctx->ins,
                          "single-chunk session aborted after a permanent record error");
            config->exit_status_code = 1;
            ret = FLB_ERROR;
        }
        else if ((tasks = flb_task_running_count(config)) > 0) {
            flb_plg_error(ctx->ins,
                          "single-chunk session is incomplete (%d running tasks)",
                          tasks);
            ret = FLB_RETRY;
        }
        else {
            flb_storage_chunk_count(config, &mem_chunks, &fs_chunks);
            if (mem_chunks + fs_chunks > 0) {
                flb_plg_error(ctx->ins,
                              "single-chunk session is incomplete (%d pending chunks)",
                              mem_chunks + fs_chunks);
                ret = FLB_RETRY;
            }
            else if (fseeko(ctx->spool, 0, SEEK_END) != 0 ||
                     (spool_size = ftello(ctx->spool)) < 0) {
                ret = FLB_RETRY;
            }
            else if (spool_size > 0) {
                ret = send_spool(ctx);
            }
            else {
                ret = FLB_OK;
            }
        }

        if (ret == FLB_OK && clear_spool(ctx) != 0) {
            ret = FLB_RETRY;
        }
        if (ctx->session_failed == FLB_TRUE) {
            if (clear_spool(ctx) != 0) {
                config->exit_status_code = 1;
            }
            remove_spool(ctx, "aborted");
            close_spool(ctx);
        }
        else if (ret == FLB_OK) {
            remove_spool(ctx, "empty");
            close_spool(ctx);
        }
        else {
            if (ret == FLB_ERROR) {
                flb_plg_error(ctx->ins,
                              "single-chunk upload was rejected permanently");
            }
            flb_plg_error(ctx->ins,
                          "single-chunk upload failed; preserving spool '%s'",
                          ctx->spool_path);
            /*
             * A remote final-publication failure during cb_exit is best
             * effort. Preserve the durable spool for the next startup;
             * Fluent Bit's shutdown status is not a Manticore publication
             * certificate.
             */
            close_spool(ctx);
        }
    }
#endif

    if (ctx->u != NULL) {
        flb_upstream_destroy(ctx->u);
    }
    if (ctx->table_json != NULL) {
        flb_sds_destroy(ctx->table_json);
    }
    if (ctx->bulk_uri != NULL) {
        flb_sds_destroy(ctx->bulk_uri);
    }
    if (ctx->commit_path != NULL) {
        flb_sds_destroy(ctx->commit_path);
    }
    flb_free(ctx->session_ids);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "table", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_manticore, table),
     "Target Manticore table (must already exist)"
    },
    {
     FLB_CONFIG_MAP_STR, "action", "insert",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, action),
     "Manticore bulk import action: insert or create"
    },
    {
     FLB_CONFIG_MAP_STR, "id_key", "id",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, id_key),
     "Required top-level non-zero numeric document ID, removed from doc"
    },
    {
     FLB_CONFIG_MAP_BOOL, "single_chunk", "false",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, single_chunk),
     "Stage all flushes locally and publish one bulk_import request on shutdown"
    },
    {
     FLB_CONFIG_MAP_STR, "spool_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_manticore, spool_path),
     "Durable spool file required by single_chunk"
    },
    {
     FLB_CONFIG_MAP_SIZE, "max_session_ids", "1M",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, max_session_ids),
     "Maximum IDs tracked for session-wide duplicate detection"
    },
    {
     FLB_CONFIG_MAP_SIZE, "stream_chunk_size", "64K",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, stream_chunk_size),
     "Maximum uncompressed NDJSON bytes buffered per HTTP chunk"
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_size", "64K",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, buffer_size),
     "Maximum response buffer size"
    },
    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_manticore, http_user),
     "HTTP Basic authentication user"
    },
    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct flb_out_manticore, http_passwd),
     "HTTP Basic authentication password"
    },
    {0}
};

struct flb_output_plugin out_manticore_plugin = {
    .name        = "manticore",
    .description = "Manticore Search native streaming output",
    .cb_init     = cb_manticore_init,
    .cb_pre_run  = NULL,
    .cb_flush    = cb_manticore_flush,
    .cb_exit     = cb_manticore_exit,
    .workers     = 2,
    .config_map  = config_map,
    .event_type  = FLB_OUTPUT_LOGS,
    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS
};
