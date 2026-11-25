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

#include <fluent-bit/flb_opentelemetry.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_log_event.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_time.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_cat.h>
#include <cmetrics/cmt_encode_opentelemetry.h>

#include <ctraces/ctraces.h>
#include <ctraces/ctr_encode_opentelemetry.h>

#include <cfl/cfl_arena.h>
#include <cfl/cfl_hash.h>

#include <fluent-otel-proto/fluent-otel.h>

#include <msgpack.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#define FLB_OTEL_LOGS_SCHEMA_KEY "schema"
#define FLB_OTEL_LOGS_SCHEMA_OTLP "otlp"
#define FLB_OTEL_LOGS_METADATA_KEY "otlp"
#define FLB_OTEL_PROTO_ARENA_INITIAL_CHUNK_SIZE 4096
#define FLB_OTEL_PROTO_ARENA_MAX_CHUNK_SIZE 65536

struct otlp_proto_arena {
    struct cfl_arena *backend;
};

/*
 * Protobuf objects live until the request has been packed. Pointer arrays that
 * grow with realloc remain heap-backed and are released separately.
 */

struct otlp_proto_logs_scope_state {
    int64_t scope_id;
    uint64_t scope_hash;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log;
};

struct otlp_proto_logs_resource_state {
    int64_t resource_id;
    uint64_t resource_hash;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log;
    struct otlp_proto_logs_scope_state *scopes;
    size_t scope_count;
};

static msgpack_object *msgpack_map_get_object(msgpack_object_map *map,
                                              const char *key);

static void *otlp_proto_arena_malloc(void *context, size_t size)
{
    (void) context;

    return flb_malloc(size);
}

static void otlp_proto_arena_free(void *context, void *pointer)
{
    (void) context;

    flb_free(pointer);
}

static int otlp_proto_arena_init(struct otlp_proto_arena *arena)
{
    struct cfl_arena_options options;

    cfl_arena_options_init(&options);
    options.chunk_size = FLB_OTEL_PROTO_ARENA_INITIAL_CHUNK_SIZE;
    options.maximum_chunk_size = FLB_OTEL_PROTO_ARENA_MAX_CHUNK_SIZE;
    options.malloc_fn = otlp_proto_arena_malloc;
    options.free_fn = otlp_proto_arena_free;

    arena->backend = cfl_arena_create_with_options(&options);
    if (arena->backend == NULL) {
        return -1;
    }

    return 0;
}

static void otlp_proto_arena_destroy(struct otlp_proto_arena *arena)
{
    cfl_arena_destroy(arena->backend);
    arena->backend = NULL;
}

static void *otlp_proto_arena_alloc(struct otlp_proto_arena *arena, size_t size)
{
    return cfl_arena_malloc(arena->backend, size);
}

static void *otlp_proto_arena_calloc(struct otlp_proto_arena *arena,
                                     size_t count,
                                     size_t size)
{
    return cfl_arena_calloc(arena->backend, count, size);
}

static char *otlp_proto_arena_strndup(struct otlp_proto_arena *arena,
                                      const char *input,
                                      size_t length)
{
    return cfl_arena_strndup(arena->backend, input, length);
}

static void set_result(int *result, int value)
{
    if (result != NULL) {
        *result = value;
    }
}

static void set_error(int *result, int value, int err)
{
    set_result(result, value);
    errno = err;
}

static uint64_t msgpack_object_hash(msgpack_object *object)
{
    uint64_t        hash;
    msgpack_sbuffer buffer;
    msgpack_packer  packer;

    if (object == NULL) {
        return cfl_hash_64bits("null", 4);
    }

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    if (msgpack_pack_object(&packer, *object) != 0) {
        msgpack_sbuffer_destroy(&buffer);
        return 0;
    }

    hash = cfl_hash_64bits(buffer.data, buffer.size);
    msgpack_sbuffer_destroy(&buffer);

    return hash;
}

static uint64_t msgpack_object_pair_hash(msgpack_object *left,
                                         msgpack_object *right)
{
    uint64_t        hash;
    msgpack_sbuffer buffer;
    msgpack_packer  packer;

    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    if (msgpack_pack_array(&packer, 2) != 0) {
        msgpack_sbuffer_destroy(&buffer);
        return 0;
    }

    if (left == NULL) {
        msgpack_pack_nil(&packer);
    }
    else if (msgpack_pack_object(&packer, *left) != 0) {
        msgpack_sbuffer_destroy(&buffer);
        return 0;
    }

    if (right == NULL) {
        msgpack_pack_nil(&packer);
    }
    else if (msgpack_pack_object(&packer, *right) != 0) {
        msgpack_sbuffer_destroy(&buffer);
        return 0;
    }

    hash = cfl_hash_64bits(buffer.data, buffer.size);
    msgpack_sbuffer_destroy(&buffer);

    return hash;
}

static msgpack_object *resource_schema_url_object(msgpack_object *resource_object,
                                                  msgpack_object *resource_body)
{
    msgpack_object *schema_url;

    if (resource_body != NULL && resource_body->type == MSGPACK_OBJECT_MAP) {
        schema_url = msgpack_map_get_object(&resource_body->via.map, "schema_url");
        if (schema_url != NULL) {
            return schema_url;
        }
    }

    if (resource_object != NULL && resource_object->type == MSGPACK_OBJECT_MAP) {
        schema_url = msgpack_map_get_object(&resource_object->via.map, "schema_url");
        if (schema_url != NULL) {
            return schema_url;
        }
    }

    return NULL;
}

static uint64_t resource_identity_hash(msgpack_object *resource_object,
                                       msgpack_object *resource_body)
{
    msgpack_object *schema_url;

    schema_url = resource_schema_url_object(resource_object, resource_body);

    return msgpack_object_pair_hash(resource_object, schema_url);
}

static msgpack_object *msgpack_map_get_object(msgpack_object_map *map,
                                              const char *key)
{
    size_t index;
    size_t key_length;
    msgpack_object_kv *entry;

    if (map == NULL || key == NULL) {
        return NULL;
    }

    key_length = strlen(key);

    for (index = 0; index < map->size; index++) {
        entry = &map->ptr[index];

        if (entry->key.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (entry->key.via.str.size != key_length) {
            continue;
        }

        if (strncmp(entry->key.via.str.ptr, key, key_length) == 0) {
            return &entry->val;
        }
    }

    return NULL;
}

static int msgpack_map_entry_is_string(msgpack_object_map *map,
                                       const char *key,
                                       const char *expected)
{
    msgpack_object *value;

    value = msgpack_map_get_object(map, key);
    if (value == NULL || value->type != MSGPACK_OBJECT_STR) {
        return FLB_FALSE;
    }

    if (value->via.str.size != strlen(expected)) {
        return FLB_FALSE;
    }

    if (strncmp(value->via.str.ptr, expected, value->via.str.size) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int msgpack_map_get_int64(msgpack_object_map *map,
                                 const char *key,
                                 int64_t *result)
{
    msgpack_object *value;

    value = msgpack_map_get_object(map, key);
    if (value == NULL) {
        return -1;
    }

    if (value->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        if (value->via.u64 > INT64_MAX) {
            return -1;
        }

        *result = (int64_t) value->via.u64;
        return 0;
    }

    if (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        *result = value->via.i64;
        return 0;
    }

    return -1;
}

static Opentelemetry__Proto__Common__V1__ArrayValue *otlp_array_value_initialize(
    struct otlp_proto_arena *arena, size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__ArrayValue *value;

    value = otlp_proto_arena_calloc(arena, 1,
                                    sizeof(Opentelemetry__Proto__Common__V1__ArrayValue));
    if (value == NULL) {
        return NULL;
    }

    opentelemetry__proto__common__v1__array_value__init(value);

    if (entry_count > 0) {
        value->values = otlp_proto_arena_calloc(arena, entry_count,
                                                sizeof(Opentelemetry__Proto__Common__V1__AnyValue *));
        if (value->values == NULL) {
            return NULL;
        }

        value->n_values = entry_count;
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__KeyValue *otlp_kvpair_value_initialize(
    struct otlp_proto_arena *arena)
{
    Opentelemetry__Proto__Common__V1__KeyValue *value;

    value = otlp_proto_arena_calloc(arena, 1,
                                    sizeof(Opentelemetry__Proto__Common__V1__KeyValue));
    if (value != NULL) {
        opentelemetry__proto__common__v1__key_value__init(value);
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__KeyValueList *otlp_kvlist_value_initialize(
    struct otlp_proto_arena *arena, size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__KeyValueList *value;

    value = otlp_proto_arena_calloc(arena, 1,
                                    sizeof(Opentelemetry__Proto__Common__V1__KeyValueList));
    if (value == NULL) {
        return NULL;
    }

    opentelemetry__proto__common__v1__key_value_list__init(value);

    if (entry_count > 0) {
        value->values = otlp_proto_arena_calloc(arena, entry_count,
                                                sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));
        if (value->values == NULL) {
            return NULL;
        }

        value->n_values = entry_count;
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__AnyValue *otlp_any_value_initialize(
    struct otlp_proto_arena *arena, int data_type, size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__AnyValue *value;

    value = otlp_proto_arena_calloc(arena, 1,
                                    sizeof(Opentelemetry__Proto__Common__V1__AnyValue));
    if (value == NULL) {
        return NULL;
    }

    opentelemetry__proto__common__v1__any_value__init(value);

    if (data_type == MSGPACK_OBJECT_STR) {
        value->value_case =
            OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_NIL) {
        value->value_case =
            OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE__NOT_SET;
    }
    else if (data_type == MSGPACK_OBJECT_BOOLEAN) {
        value->value_case =
            OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
             data_type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        value->value_case =
            OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_FLOAT32 ||
             data_type == MSGPACK_OBJECT_FLOAT64) {
        value->value_case =
            OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_ARRAY) {
        value->value_case =
            OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE;
        value->array_value = otlp_array_value_initialize(arena, entry_count);

        if (value->array_value == NULL) {
            return NULL;
        }
    }
    else if (data_type == MSGPACK_OBJECT_MAP) {
        value->value_case =
            OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE;
        value->kvlist_value = otlp_kvlist_value_initialize(arena, entry_count);

        if (value->kvlist_value == NULL) {
            return NULL;
        }
    }
    else if (data_type == MSGPACK_OBJECT_BIN) {
        value->value_case =
            OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE;
    }
    else {
        return NULL;
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__AnyValue *msgpack_object_to_otlp_any_value(
    struct otlp_proto_arena *arena, msgpack_object *object);

static Opentelemetry__Proto__Common__V1__AnyValue *msgpack_array_to_otlp_any_value(
    struct otlp_proto_arena *arena, msgpack_object *object)
{
    size_t index;
    Opentelemetry__Proto__Common__V1__AnyValue *entry;
    Opentelemetry__Proto__Common__V1__AnyValue *value;

    value = otlp_any_value_initialize(arena, MSGPACK_OBJECT_ARRAY,
                                      object->via.array.size);
    if (value == NULL) {
        return NULL;
    }

    for (index = 0; index < object->via.array.size; index++) {
        entry = msgpack_object_to_otlp_any_value(arena,
                                                 &object->via.array.ptr[index]);
        if (entry == NULL) {
            return NULL;
        }

        value->array_value->values[index] = entry;
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__KeyValue *msgpack_kv_to_otlp_any_value(
    struct otlp_proto_arena *arena, struct msgpack_object_kv *input_pair)
{
    Opentelemetry__Proto__Common__V1__KeyValue *kv;

    kv = otlp_kvpair_value_initialize(arena);
    if (kv == NULL) {
        return NULL;
    }

    if (input_pair->key.type != MSGPACK_OBJECT_STR) {
        return NULL;
    }

    kv->key = otlp_proto_arena_strndup(arena,
                                       input_pair->key.via.str.ptr,
                                       input_pair->key.via.str.size);
    if (kv->key == NULL) {
        return NULL;
    }

    kv->value = msgpack_object_to_otlp_any_value(arena, &input_pair->val);
    if (kv->value == NULL) {
        return NULL;
    }

    return kv;
}

static Opentelemetry__Proto__Common__V1__KeyValue **msgpack_map_to_otlp_kvarray(
    struct otlp_proto_arena *arena, msgpack_object *object, size_t *entry_count)
{
    size_t index;
    Opentelemetry__Proto__Common__V1__KeyValue **result;

    *entry_count = object->via.map.size;

    if (*entry_count == 0) {
        return NULL;
    }

    result = otlp_proto_arena_calloc(arena, *entry_count,
                                     sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));
    if (result == NULL) {
        *entry_count = 0;
        return NULL;
    }

    for (index = 0; index < *entry_count; index++) {
        result[index] = msgpack_kv_to_otlp_any_value(arena,
                                                     &object->via.map.ptr[index]);
        if (result[index] == NULL) {
            *entry_count = 0;
            return NULL;
        }
    }

    return result;
}

static Opentelemetry__Proto__Common__V1__AnyValue *msgpack_map_to_otlp_any_value(
    struct otlp_proto_arena *arena, msgpack_object *object)
{
    size_t index;
    Opentelemetry__Proto__Common__V1__KeyValue *entry;
    Opentelemetry__Proto__Common__V1__AnyValue *value;

    value = otlp_any_value_initialize(arena, MSGPACK_OBJECT_MAP,
                                      object->via.map.size);
    if (value == NULL) {
        return NULL;
    }

    for (index = 0; index < object->via.map.size; index++) {
        entry = msgpack_kv_to_otlp_any_value(arena, &object->via.map.ptr[index]);
        if (entry == NULL) {
            return NULL;
        }

        value->kvlist_value->values[index] = entry;
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__AnyValue *msgpack_object_to_otlp_any_value(
    struct otlp_proto_arena *arena, msgpack_object *object)
{
    Opentelemetry__Proto__Common__V1__AnyValue *value;

    if (object == NULL) {
        return NULL;
    }

    value = NULL;

    switch (object->type) {
    case MSGPACK_OBJECT_NIL:
        value = otlp_any_value_initialize(arena, MSGPACK_OBJECT_NIL, 0);
        break;
    case MSGPACK_OBJECT_BOOLEAN:
        value = otlp_any_value_initialize(arena, MSGPACK_OBJECT_BOOLEAN, 0);
        if (value != NULL) {
            value->bool_value = object->via.boolean;
        }
        break;
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        value = otlp_any_value_initialize(arena, object->type, 0);
        if (value != NULL) {
            if (object->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                if (object->via.u64 > INT64_MAX) {
                    value = NULL;
                    break;
                }

                value->int_value = (int64_t) object->via.u64;
            }
            else {
                value->int_value = object->via.i64;
            }
        }
        break;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        value = otlp_any_value_initialize(arena, object->type, 0);
        if (value != NULL) {
            value->double_value = object->via.f64;
        }
        break;
    case MSGPACK_OBJECT_STR:
        value = otlp_any_value_initialize(arena, MSGPACK_OBJECT_STR, 0);
        if (value != NULL) {
            value->string_value = otlp_proto_arena_strndup(arena,
                                                           object->via.str.ptr,
                                                           object->via.str.size);
            if (value->string_value == NULL) {
                value = NULL;
            }
        }
        break;
    case MSGPACK_OBJECT_BIN:
        value = otlp_any_value_initialize(arena, MSGPACK_OBJECT_BIN, 0);
        if (value != NULL) {
            value->bytes_value.len = object->via.bin.size;
            if (object->via.bin.size == 0) {
                value->bytes_value.data = cfl_arena_malloc(arena->backend, 1);
            }
            else {
                value->bytes_value.data = cfl_arena_memdup(arena->backend,
                                                           object->via.bin.ptr,
                                                           object->via.bin.size);
            }
            if (value->bytes_value.data == NULL) {
                value = NULL;
            }
        }
        break;
    case MSGPACK_OBJECT_ARRAY:
        value = msgpack_array_to_otlp_any_value(arena, object);
        break;
    case MSGPACK_OBJECT_MAP:
        value = msgpack_map_to_otlp_any_value(arena, object);
        break;
    default:
        break;
    }

    return value;
}

static struct otlp_proto_logs_resource_state *find_logs_resource_state(
    struct otlp_proto_logs_resource_state *states,
    size_t state_count,
    int64_t resource_id,
    uint64_t resource_hash)
{
    size_t index;

    for (index = 0; index < state_count; index++) {
        if (states[index].resource_id == resource_id &&
            states[index].resource_hash == resource_hash) {
            return &states[index];
        }
    }

    return NULL;
}

static struct otlp_proto_logs_scope_state *find_logs_scope_state(
    struct otlp_proto_logs_resource_state *resource,
    int64_t scope_id,
    uint64_t scope_hash)
{
    size_t index;

    for (index = 0; index < resource->scope_count; index++) {
        if (resource->scopes[index].scope_id == scope_id &&
            resource->scopes[index].scope_hash == scope_hash) {
            return &resource->scopes[index];
        }
    }

    return NULL;
}

static void destroy_logs_resource_states(
    struct otlp_proto_logs_resource_state *states,
    size_t state_count)
{
    size_t index;

    if (states == NULL) {
        return;
    }

    for (index = 0; index < state_count; index++) {
        flb_free(states[index].scopes);
    }

    flb_free(states);
}

static msgpack_object *find_log_body_candidate(msgpack_object *body,
                                               const char **logs_body_keys,
                                               size_t logs_body_key_count,
                                               const char **matched_key,
                                               size_t *matched_key_length)
{
    size_t index;
    msgpack_object *candidate;

    if (body == NULL || body->type == MSGPACK_OBJECT_NIL) {
        return NULL;
    }

    if (body->type != MSGPACK_OBJECT_MAP) {
        return body;
    }

    for (index = 0; index < logs_body_key_count; index++) {
        if (logs_body_keys[index] == NULL) {
            continue;
        }

        candidate = msgpack_map_get_object(&body->via.map, logs_body_keys[index]);
        if (candidate != NULL) {
            if (matched_key != NULL) {
                *matched_key = logs_body_keys[index];
            }
            if (matched_key_length != NULL) {
                *matched_key_length = strlen(logs_body_keys[index]);
            }
            return candidate;
        }
    }

    return body;
}

static int append_kvarrays(struct otlp_proto_arena *arena,
                           Opentelemetry__Proto__Common__V1__KeyValue ***base,
                           size_t *base_count,
                           Opentelemetry__Proto__Common__V1__KeyValue **extra,
                           size_t extra_count)
{
    size_t total_count;
    Opentelemetry__Proto__Common__V1__KeyValue **tmp;

    if (extra == NULL || extra_count == 0) {
        return 0;
    }

    if (*base == NULL) {
        *base = extra;
        *base_count = extra_count;
        return 0;
    }

    if (*base_count > SIZE_MAX - extra_count) {
        return -1;
    }

    total_count = *base_count + extra_count;
    if (total_count >
        SIZE_MAX / sizeof(Opentelemetry__Proto__Common__V1__KeyValue *)) {
        return -1;
    }

    tmp = otlp_proto_arena_alloc(arena,
                                 sizeof(Opentelemetry__Proto__Common__V1__KeyValue *) * total_count);
    if (tmp == NULL) {
        return -1;
    }

    memcpy(tmp, *base,
           sizeof(Opentelemetry__Proto__Common__V1__KeyValue *) * *base_count);
    memcpy(tmp + *base_count, extra,
           sizeof(Opentelemetry__Proto__Common__V1__KeyValue *) * extra_count);
    *base = tmp;
    *base_count += extra_count;

    return 0;
}

static int msgpack_map_to_otlp_kvarray_filtered(
    struct otlp_proto_arena *arena,
    msgpack_object_map *map,
    const char *ignored_key,
    size_t ignored_key_length,
    Opentelemetry__Proto__Common__V1__KeyValue ***out_values,
    size_t *out_count)
{
    size_t index;
    size_t count;
    Opentelemetry__Proto__Common__V1__KeyValue **values;

    count = 0;

    for (index = 0; index < map->size; index++) {
        if (ignored_key != NULL &&
            map->ptr[index].key.type == MSGPACK_OBJECT_STR &&
            map->ptr[index].key.via.str.size == ignored_key_length &&
            strncmp(map->ptr[index].key.via.str.ptr,
                    ignored_key,
                    ignored_key_length) == 0) {
            continue;
        }

        count++;
    }

    if (count == 0) {
        *out_values = NULL;
        *out_count = 0;
        return 0;
    }

    values = otlp_proto_arena_calloc(arena, count,
                                     sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));
    if (values == NULL) {
        *out_values = NULL;
        *out_count = 0;
        return -1;
    }

    count = 0;
    for (index = 0; index < map->size; index++) {
        if (ignored_key != NULL &&
            map->ptr[index].key.type == MSGPACK_OBJECT_STR &&
            map->ptr[index].key.via.str.size == ignored_key_length &&
            strncmp(map->ptr[index].key.via.str.ptr,
                    ignored_key,
                    ignored_key_length) == 0) {
            continue;
        }

        values[count] = msgpack_kv_to_otlp_any_value(arena, &map->ptr[index]);
        if (values[count] == NULL) {
            *out_values = NULL;
            *out_count = 0;
            return -1;
        }

        count++;
    }

    *out_values = values;
    *out_count = count;

    return 0;
}

static int log_record_set_body_and_attributes(
    struct otlp_proto_arena *arena,
    Opentelemetry__Proto__Logs__V1__LogRecord *record,
    struct flb_log_event *event,
    const char **logs_body_keys,
    size_t logs_body_key_count,
    int logs_body_key_attributes)
{
    const char *matched_key;
    size_t matched_key_length;
    msgpack_object *candidate;
    Opentelemetry__Proto__Common__V1__KeyValue **attributes;
    size_t attribute_count;

    matched_key = NULL;
    matched_key_length = 0;
    candidate = find_log_body_candidate(event->body,
                                        logs_body_keys,
                                        logs_body_key_count,
                                        &matched_key,
                                        &matched_key_length);

    record->body = msgpack_object_to_otlp_any_value(arena, candidate);
    if (candidate != NULL && record->body == NULL) {
        return -1;
    }

    if (logs_body_key_attributes == FLB_TRUE &&
        matched_key != NULL &&
        event->body != NULL &&
        event->body->type == MSGPACK_OBJECT_MAP) {
        if (msgpack_map_to_otlp_kvarray_filtered(arena,
                                                 &event->body->via.map,
                                                 matched_key,
                                                 matched_key_length,
                                                 &attributes,
                                                 &attribute_count) != 0) {
            return -1;
        }

        if (append_kvarrays(arena,
                            &record->attributes,
                            &record->n_attributes,
                            attributes,
                            attribute_count) != 0) {
            return -1;
        }
    }

    return 0;
}

static int add_msgpack_attributes_to_resource(
    struct otlp_proto_arena *arena,
    Opentelemetry__Proto__Resource__V1__Resource *resource,
    msgpack_object *resource_object)
{
    msgpack_object *field;

    if (resource_object == NULL || resource_object->type != MSGPACK_OBJECT_MAP) {
        return 0;
    }

    field = msgpack_map_get_object(&resource_object->via.map, "attributes");
    if (field != NULL && field->type == MSGPACK_OBJECT_MAP) {
        resource->attributes = msgpack_map_to_otlp_kvarray(arena, field,
                                                           &resource->n_attributes);
        if (field->via.map.size > 0 && resource->attributes == NULL) {
            return -1;
        }
    }

    field = msgpack_map_get_object(&resource_object->via.map,
                                   "dropped_attributes_count");
    if (field != NULL) {
        if (field->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            resource->dropped_attributes_count = field->via.u64;
        }
        else if (field->type == MSGPACK_OBJECT_NEGATIVE_INTEGER &&
                 field->via.i64 >= 0) {
            resource->dropped_attributes_count = (uint32_t) field->via.i64;
        }
    }

    return 0;
}

static int add_msgpack_scope_fields(
    struct otlp_proto_arena *arena,
    Opentelemetry__Proto__Common__V1__InstrumentationScope *scope,
    msgpack_object *scope_object)
{
    msgpack_object *field;

    if (scope_object == NULL || scope_object->type != MSGPACK_OBJECT_MAP) {
        return 0;
    }

    field = msgpack_map_get_object(&scope_object->via.map, "name");
    if (field != NULL && field->type == MSGPACK_OBJECT_STR) {
        scope->name = otlp_proto_arena_strndup(arena,
                                               field->via.str.ptr,
                                               field->via.str.size);
        if (scope->name == NULL) {
            return -1;
        }
    }

    field = msgpack_map_get_object(&scope_object->via.map, "version");
    if (field != NULL && field->type == MSGPACK_OBJECT_STR) {
        scope->version = otlp_proto_arena_strndup(arena,
                                                  field->via.str.ptr,
                                                  field->via.str.size);
        if (scope->version == NULL) {
            return -1;
        }
    }

    field = msgpack_map_get_object(&scope_object->via.map, "attributes");
    if (field != NULL && field->type == MSGPACK_OBJECT_MAP) {
        scope->attributes = msgpack_map_to_otlp_kvarray(arena, field,
                                                        &scope->n_attributes);
        if (field->via.map.size > 0 && scope->attributes == NULL) {
            return -1;
        }
    }

    field = msgpack_map_get_object(&scope_object->via.map,
                                   "dropped_attributes_count");
    if (field != NULL && field->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        scope->dropped_attributes_count = field->via.u64;
    }

    return 0;
}

static struct otlp_proto_logs_resource_state *append_logs_resource_state(
    struct otlp_proto_arena *arena,
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *export_logs,
    struct otlp_proto_logs_resource_state **states,
    size_t *state_count,
    int64_t resource_id,
    uint64_t resource_hash,
    msgpack_object *resource_object,
    msgpack_object *resource_body)
{
    struct otlp_proto_logs_resource_state *new_states;
    struct otlp_proto_logs_resource_state *state;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log;
    Opentelemetry__Proto__Resource__V1__Resource *resource;
    Opentelemetry__Proto__Logs__V1__ResourceLogs **tmp;
    msgpack_object *schema_url;

    resource_log = otlp_proto_arena_calloc(arena, 1,
                                            sizeof(Opentelemetry__Proto__Logs__V1__ResourceLogs));
    resource = otlp_proto_arena_calloc(arena, 1,
                                       sizeof(Opentelemetry__Proto__Resource__V1__Resource));
    if (resource_log == NULL || resource == NULL) {
        return NULL;
    }

    opentelemetry__proto__logs__v1__resource_logs__init(resource_log);
    opentelemetry__proto__resource__v1__resource__init(resource);
    resource_log->resource = resource;

    if (add_msgpack_attributes_to_resource(arena, resource, resource_object) != 0) {
        return NULL;
    }

    schema_url = resource_schema_url_object(resource_object, resource_body);
    if (schema_url != NULL && schema_url->type == MSGPACK_OBJECT_STR) {
        resource_log->schema_url = otlp_proto_arena_strndup(arena,
                                                            schema_url->via.str.ptr,
                                                            schema_url->via.str.size);
        if (resource_log->schema_url == NULL) {
            return NULL;
        }
    }

    tmp = flb_realloc(export_logs->resource_logs,
                      sizeof(Opentelemetry__Proto__Logs__V1__ResourceLogs *) *
                      (export_logs->n_resource_logs + 1));
    if (tmp == NULL) {
        return NULL;
    }

    export_logs->resource_logs = tmp;
    export_logs->resource_logs[export_logs->n_resource_logs++] = resource_log;

    new_states = flb_realloc(*states,
                             sizeof(struct otlp_proto_logs_resource_state) *
                             (*state_count + 1));
    if (new_states == NULL) {
        return NULL;
    }

    *states = new_states;
    state = &new_states[*state_count];
    memset(state, 0, sizeof(struct otlp_proto_logs_resource_state));

    state->resource_id = resource_id;
    state->resource_hash = resource_hash;
    state->resource_log = resource_log;
    (*state_count)++;

    return state;
}

static struct otlp_proto_logs_scope_state *append_logs_scope_state(
    struct otlp_proto_arena *arena,
    struct otlp_proto_logs_resource_state *resource_state,
    int64_t scope_id,
    uint64_t scope_hash,
    msgpack_object *scope_object)
{
    struct otlp_proto_logs_scope_state *new_scopes;
    struct otlp_proto_logs_scope_state *state;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log;
    Opentelemetry__Proto__Common__V1__InstrumentationScope *scope;
    Opentelemetry__Proto__Logs__V1__ScopeLogs **tmp;
    msgpack_object *schema_url;

    scope_log = otlp_proto_arena_calloc(arena, 1,
                                        sizeof(Opentelemetry__Proto__Logs__V1__ScopeLogs));
    scope = otlp_proto_arena_calloc(arena, 1,
                                    sizeof(Opentelemetry__Proto__Common__V1__InstrumentationScope));
    if (scope_log == NULL || scope == NULL) {
        return NULL;
    }

    opentelemetry__proto__logs__v1__scope_logs__init(scope_log);
    opentelemetry__proto__common__v1__instrumentation_scope__init(scope);
    scope_log->scope = scope;

    if (add_msgpack_scope_fields(arena, scope, scope_object) != 0) {
        return NULL;
    }

    if (scope_object != NULL && scope_object->type == MSGPACK_OBJECT_MAP) {
        schema_url = msgpack_map_get_object(&scope_object->via.map, "schema_url");
        if (schema_url != NULL && schema_url->type == MSGPACK_OBJECT_STR) {
            scope_log->schema_url = otlp_proto_arena_strndup(arena,
                                                             schema_url->via.str.ptr,
                                                             schema_url->via.str.size);
            if (scope_log->schema_url == NULL) {
                return NULL;
            }
        }
    }

    tmp = flb_realloc(resource_state->resource_log->scope_logs,
                      sizeof(Opentelemetry__Proto__Logs__V1__ScopeLogs *) *
                      (resource_state->resource_log->n_scope_logs + 1));
    if (tmp == NULL) {
        return NULL;
    }

    resource_state->resource_log->scope_logs = tmp;
    resource_state->resource_log->scope_logs[
        resource_state->resource_log->n_scope_logs++] = scope_log;

    new_scopes = flb_realloc(resource_state->scopes,
                             sizeof(struct otlp_proto_logs_scope_state) *
                             (resource_state->scope_count + 1));
    if (new_scopes == NULL) {
        return NULL;
    }

    resource_state->scopes = new_scopes;
    state = &new_scopes[resource_state->scope_count];
    memset(state, 0, sizeof(struct otlp_proto_logs_scope_state));

    state->scope_id = scope_id;
    state->scope_hash = scope_hash;
    state->scope_log = scope_log;
    resource_state->scope_count++;

    return state;
}

static int ensure_default_logs_scope_state(
    struct otlp_proto_arena *arena,
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *export_logs,
    struct otlp_proto_logs_resource_state **resource_states,
    size_t *resource_state_count,
    struct otlp_proto_logs_resource_state **current_resource,
    struct otlp_proto_logs_scope_state **current_scope)
{
    uint64_t resource_hash;
    uint64_t scope_hash;

    resource_hash = resource_identity_hash(NULL, NULL);
    scope_hash = msgpack_object_hash(NULL);

    *current_resource = find_logs_resource_state(*resource_states,
                                                 *resource_state_count,
                                                 0,
                                                 resource_hash);
    if (*current_resource == NULL) {
        *current_resource = append_logs_resource_state(arena,
                                                       export_logs,
                                                       resource_states,
                                                       resource_state_count,
                                                       0,
                                                       resource_hash,
                                                       NULL,
                                                       NULL);
        if (*current_resource == NULL) {
            return -1;
        }
    }

    *current_scope = find_logs_scope_state(*current_resource, 0, scope_hash);
    if (*current_scope == NULL) {
        *current_scope = append_logs_scope_state(arena,
                                                 *current_resource,
                                                 0,
                                                 scope_hash,
                                                 NULL);
        if (*current_scope == NULL) {
            return -1;
        }
    }

    return 0;
}

static int append_binary_id_field(struct otlp_proto_arena *arena,
                                  ProtobufCBinaryData *field,
                                  msgpack_object *value,
                                  size_t expected_size)
{
    size_t i;

    if (value == NULL) {
        return 0;
    }

    if (value->type == MSGPACK_OBJECT_BIN) {
        if (value->via.bin.size != expected_size) {
            return 0;
        }

        field->data = otlp_proto_arena_alloc(arena, value->via.bin.size);
        if (field->data == NULL) {
            return -1;
        }

        memcpy(field->data, value->via.bin.ptr, value->via.bin.size);
        field->len = value->via.bin.size;
        return 0;
    }

    if (value->type != MSGPACK_OBJECT_STR) {
        return 0;
    }

    if (value->via.str.size != expected_size * 2) {
        return 0;
    }

    field->data = otlp_proto_arena_calloc(arena, 1, expected_size);
    if (field->data == NULL) {
        return -1;
    }

    for (i = 0; i < expected_size; i++) {
        int high;
        int low;
        char *str = (char *) value->via.str.ptr;

        if (!isxdigit(str[i * 2]) || !isxdigit(str[i * 2 + 1])) {
            field->data = NULL;
            return -1;
        }

        high = (str[i * 2] >= 'a') ? str[i * 2] - 'a' + 10 :
               (str[i * 2] >= 'A') ? str[i * 2] - 'A' + 10 :
               str[i * 2] - '0';
        low = (str[i * 2 + 1] >= 'a') ? str[i * 2 + 1] - 'a' + 10 :
              (str[i * 2 + 1] >= 'A') ? str[i * 2 + 1] - 'A' + 10 :
              str[i * 2 + 1] - '0';

        ((unsigned char *) field->data)[i] = (high << 4) | low;
    }

    field->len = expected_size;
    return 0;
}

static int log_record_to_proto(struct otlp_proto_arena *arena,
                               Opentelemetry__Proto__Logs__V1__LogRecord *record,
                               struct flb_log_event *event,
                               const char **logs_body_keys,
                               size_t logs_body_key_count,
                               int logs_body_key_attributes)
{
    msgpack_object *metadata;
    msgpack_object *otlp_metadata;
    msgpack_object *field;
    uint64_t timestamp;
    size_t count;
    Opentelemetry__Proto__Common__V1__KeyValue **attrs;

    metadata = event->metadata;
    otlp_metadata = NULL;

    if (metadata != NULL && metadata->type == MSGPACK_OBJECT_MAP) {
        otlp_metadata = msgpack_map_get_object(&metadata->via.map,
                                               FLB_OTEL_LOGS_METADATA_KEY);
    }

    if (otlp_metadata != NULL && otlp_metadata->type == MSGPACK_OBJECT_MAP) {
        field = msgpack_map_get_object(&otlp_metadata->via.map, "timestamp");
        if (field != NULL && field->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            timestamp = field->via.u64;
        }
        else if (event->raw_timestamp != NULL &&
                 event->raw_timestamp->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            timestamp = event->raw_timestamp->via.u64;
        }
        else {
            timestamp = flb_time_to_nanosec(&event->timestamp);
        }
    }
    else if (event->raw_timestamp != NULL &&
             event->raw_timestamp->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        timestamp = event->raw_timestamp->via.u64;
    }
    else {
        timestamp = flb_time_to_nanosec(&event->timestamp);
    }

    record->time_unix_nano = timestamp;

    if (otlp_metadata != NULL && otlp_metadata->type == MSGPACK_OBJECT_MAP) {
        field = msgpack_map_get_object(&otlp_metadata->via.map,
                                       "observed_timestamp");
        if (field != NULL && field->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            record->observed_time_unix_nano = field->via.u64;
        }

        field = msgpack_map_get_object(&otlp_metadata->via.map,
                                       "severity_number");
        if (field != NULL && field->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            record->severity_number = field->via.u64;
        }

        field = msgpack_map_get_object(&otlp_metadata->via.map,
                                       "severity_text");
        if (field != NULL && field->type == MSGPACK_OBJECT_STR) {
            record->severity_text = otlp_proto_arena_strndup(arena,
                                                             field->via.str.ptr,
                                                             field->via.str.size);
            if (record->severity_text == NULL) {
                return -1;
            }
        }

        field = msgpack_map_get_object(&otlp_metadata->via.map, "attributes");
        if (field != NULL && field->type == MSGPACK_OBJECT_MAP) {
            attrs = msgpack_map_to_otlp_kvarray(arena, field, &count);
            if (field->via.map.size > 0 && attrs == NULL) {
                return -1;
            }

            if (append_kvarrays(arena,
                                &record->attributes,
                                &record->n_attributes,
                                attrs,
                                count) != 0) {
                return -1;
            }
        }

        if (append_binary_id_field(arena,
                                   &record->trace_id,
                                   msgpack_map_get_object(&otlp_metadata->via.map,
                                                          "trace_id"),
                                   16) != 0) {
            return -1;
        }

        if (append_binary_id_field(arena,
                                   &record->span_id,
                                   msgpack_map_get_object(&otlp_metadata->via.map,
                                                          "span_id"),
                                   8) != 0) {
            return -1;
        }
    }

    if (log_record_set_body_and_attributes(arena,
                                           record,
                                           event,
                                           logs_body_keys,
                                           logs_body_key_count,
                                           logs_body_key_attributes) != 0) {
        return -1;
    }

    return 0;
}

static void destroy_export_logs_arrays(
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *export_logs)
{
    size_t index;
    size_t inner;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log;

    if (export_logs == NULL) {
        return;
    }

    for (index = 0; index < export_logs->n_resource_logs; index++) {
        resource_log = export_logs->resource_logs[index];
        if (resource_log == NULL) {
            continue;
        }

        for (inner = 0; inner < resource_log->n_scope_logs; inner++) {
            scope_log = resource_log->scope_logs[inner];
            if (scope_log == NULL) {
                continue;
            }

            flb_free(scope_log->log_records);
        }

        flb_free(resource_log->scope_logs);
    }

    flb_free(export_logs->resource_logs);
}

void flb_opentelemetry_traces_proto_destroy(flb_sds_t payload)
{
    if (payload != NULL) {
        ctr_encode_opentelemetry_destroy((cfl_sds_t) payload);
    }
}

void flb_opentelemetry_metrics_proto_destroy(flb_sds_t payload)
{
    if (payload != NULL) {
        cmt_encode_opentelemetry_destroy((cfl_sds_t) payload);
    }
}

void flb_opentelemetry_logs_proto_destroy(flb_sds_t payload)
{
    if (payload != NULL) {
        flb_sds_destroy(payload);
    }
}

flb_sds_t flb_opentelemetry_metrics_to_otlp_proto(struct cmt *context,
                                                  int *result)
{
    cfl_sds_t encoded;

    if (context == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    encoded = cmt_encode_opentelemetry_create(context);
    if (encoded == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    set_result(result, FLB_OPENTELEMETRY_OTLP_PROTO_SUCCESS);
    return (flb_sds_t) encoded;
}

flb_sds_t flb_opentelemetry_metrics_msgpack_to_otlp_proto(const void *data,
                                                          size_t size,
                                                          int *result)
{
    int ret;
    int decoded_count;
    size_t offset;
    cfl_sds_t encoded;
    cfl_sds_t output;
    struct cmt *context;
    struct cmt *merged_context;

    if (data == NULL || size == 0) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    merged_context = cmt_create();
    if (merged_context == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    output = NULL;
    offset = 0;
    decoded_count = 0;

    while ((ret = cmt_decode_msgpack_create(&context,
                                            (char *) data,
                                            size,
                                            &offset)) == CMT_DECODE_MSGPACK_SUCCESS) {
        ret = cmt_cat(merged_context, context);
        cmt_destroy(context);

        if (ret != 0) {
            cmt_destroy(merged_context);
            set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }

        decoded_count++;
    }

    if (!((ret == CMT_DECODE_MSGPACK_INSUFFICIENT_DATA &&
           offset == size &&
           decoded_count > 0) ||
          (ret == CMT_DECODE_MSGPACK_SUCCESS && offset == size))) {
        cmt_destroy(merged_context);
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    if (decoded_count == 0) {
        cmt_destroy(merged_context);
        output = cfl_sds_create_size(0);
        if (output == NULL) {
            set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }

        set_result(result, FLB_OPENTELEMETRY_OTLP_PROTO_SUCCESS);
        return (flb_sds_t) output;
    }

    encoded = cmt_encode_opentelemetry_create(merged_context);
    cmt_destroy(merged_context);

    if (encoded == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    set_result(result, FLB_OPENTELEMETRY_OTLP_PROTO_SUCCESS);
    return (flb_sds_t) encoded;
}

flb_sds_t flb_opentelemetry_traces_to_otlp_proto(struct ctrace *context,
                                                 int *result)
{
    cfl_sds_t encoded;

    if (context == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    encoded = ctr_encode_opentelemetry_create(context);
    if (encoded == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    set_result(result, FLB_OPENTELEMETRY_OTLP_PROTO_SUCCESS);
    return (flb_sds_t) encoded;
}

flb_sds_t flb_opentelemetry_logs_to_otlp_proto(const void *event_chunk_data,
                                               size_t event_chunk_size,
                                               struct flb_opentelemetry_otlp_logs_options *options,
                                               int *result)
{
    int ret;
    int require_otel_metadata;
    int logs_body_key_attributes;
    int record_type;
    int64_t resource_id;
    int64_t scope_id;
    Opentelemetry__Proto__Logs__V1__LogRecord *record;
    size_t logs_body_key_count;
    flb_sds_t output;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;
    struct otlp_proto_arena arena;
    msgpack_object *group_metadata;
    msgpack_object *group_body;
    msgpack_object *resource_object;
    msgpack_object *scope_object;
    uint64_t resource_hash;
    uint64_t scope_hash;
    Opentelemetry__Proto__Logs__V1__LogRecord **tmp;
    struct otlp_proto_logs_scope_state *current_scope;
    struct otlp_proto_logs_resource_state *current_resource;
    struct otlp_proto_logs_resource_state *resource_states;
    size_t resource_state_count;
    const char **logs_body_keys;
    const char *logs_body_key;
    static const char *default_logs_body_keys[] = {"log", "message"};
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest export_logs;

    require_otel_metadata = FLB_FALSE;
    logs_body_key = "log";
    logs_body_keys = default_logs_body_keys;
    logs_body_key_count = 2;
    logs_body_key_attributes = FLB_FALSE;

    if (options != NULL) {
        require_otel_metadata = options->logs_require_otel_metadata;
        logs_body_key_attributes = options->logs_body_key_attributes;

        if (options->logs_body_keys != NULL &&
            options->logs_body_key_count > 0) {
            logs_body_keys = options->logs_body_keys;
            logs_body_key_count = options->logs_body_key_count;
        }
        else if (options->logs_body_key != NULL) {
            logs_body_key = options->logs_body_key;
            logs_body_keys = &logs_body_key;
            logs_body_key_count = 1;
        }
    }

    opentelemetry__proto__collector__logs__v1__export_logs_service_request__init(
        &export_logs);
    if (otlp_proto_arena_init(&arena) != 0) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    current_scope = NULL;
    current_resource = NULL;
    resource_states = NULL;
    resource_state_count = 0;

    ret = flb_log_event_decoder_init(&decoder,
                                     (char *) event_chunk_data,
                                     event_chunk_size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        otlp_proto_arena_destroy(&arena);
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);

    while ((ret = flb_log_event_decoder_next(&decoder, &event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_decoder_get_record_type(&event, &record_type);
        if (ret != 0) {
            flb_log_event_decoder_destroy(&decoder);
            destroy_export_logs_arrays(&export_logs);
            otlp_proto_arena_destroy(&arena);
            destroy_logs_resource_states(resource_states, resource_state_count);
            set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_INVALID_LOG_EVENT, EINVAL);
            return NULL;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            group_metadata = event.group_metadata != NULL ? event.group_metadata : event.metadata;
            group_body = event.body;

            if (group_metadata == NULL ||
                group_metadata->type != MSGPACK_OBJECT_MAP ||
                msgpack_map_entry_is_string(&group_metadata->via.map,
                                            FLB_OTEL_LOGS_SCHEMA_KEY,
                                            FLB_OTEL_LOGS_SCHEMA_OTLP) != FLB_TRUE ||
                msgpack_map_get_int64(&group_metadata->via.map, "resource_id", &resource_id) != 0 ||
                msgpack_map_get_int64(&group_metadata->via.map, "scope_id", &scope_id) != 0) {
                if (require_otel_metadata == FLB_TRUE) {
                    flb_log_event_decoder_destroy(&decoder);
                    destroy_export_logs_arrays(&export_logs);
                    otlp_proto_arena_destroy(&arena);
                    destroy_logs_resource_states(resource_states, resource_state_count);
                    set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_INVALID_LOG_EVENT, EINVAL);
                    return NULL;
                }

                current_resource = NULL;
                current_scope = NULL;
                continue;
            }

            resource_object = NULL;
            scope_object = NULL;

            if (group_body != NULL && group_body->type == MSGPACK_OBJECT_MAP) {
                resource_object = msgpack_map_get_object(&group_body->via.map, "resource");
                scope_object = msgpack_map_get_object(&group_body->via.map, "scope");
            }

            resource_hash = resource_identity_hash(resource_object, group_body);
            scope_hash = msgpack_object_hash(scope_object);

            current_resource = find_logs_resource_state(resource_states,
                                                        resource_state_count,
                                                        resource_id,
                                                        resource_hash);
            if (current_resource == NULL) {
                current_resource = append_logs_resource_state(&arena,
                                                              &export_logs,
                                                              &resource_states,
                                                              &resource_state_count,
                                                              resource_id,
                                                              resource_hash,
                                                              resource_object,
                                                              group_body);
                if (current_resource == NULL) {
                    flb_log_event_decoder_destroy(&decoder);
                    destroy_export_logs_arrays(&export_logs);
                    otlp_proto_arena_destroy(&arena);
                    destroy_logs_resource_states(resource_states, resource_state_count);
                    set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
                    return NULL;
                }
            }

            current_scope = find_logs_scope_state(current_resource,
                                                  scope_id,
                                                  scope_hash);
            if (current_scope == NULL) {
                current_scope = append_logs_scope_state(&arena,
                                                        current_resource,
                                                        scope_id,
                                                        scope_hash,
                                                        scope_object);
                if (current_scope == NULL) {
                    flb_log_event_decoder_destroy(&decoder);
                    destroy_export_logs_arrays(&export_logs);
                    otlp_proto_arena_destroy(&arena);
                    destroy_logs_resource_states(resource_states, resource_state_count);
                    set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
                    return NULL;
                }
            }

            continue;
        }
        else if (record_type == FLB_LOG_EVENT_GROUP_END) {
            current_resource = NULL;
            current_scope = NULL;
            continue;
        }

        if (current_scope == NULL) {
            if (require_otel_metadata == FLB_TRUE) {
                flb_log_event_decoder_destroy(&decoder);
                destroy_export_logs_arrays(&export_logs);
                otlp_proto_arena_destroy(&arena);
                destroy_logs_resource_states(resource_states, resource_state_count);
                set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_INVALID_LOG_EVENT, EINVAL);
                return NULL;
            }

            if (ensure_default_logs_scope_state(&arena,
                                                &export_logs,
                                                &resource_states,
                                                &resource_state_count,
                                                &current_resource,
                                                &current_scope) != 0) {
                flb_log_event_decoder_destroy(&decoder);
                destroy_export_logs_arrays(&export_logs);
                otlp_proto_arena_destroy(&arena);
                destroy_logs_resource_states(resource_states, resource_state_count);
                set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
                return NULL;
            }
        }

        tmp = flb_realloc(current_scope->scope_log->log_records,
                          sizeof(Opentelemetry__Proto__Logs__V1__LogRecord *) *
                          (current_scope->scope_log->n_log_records + 1));
        if (tmp == NULL) {
            flb_log_event_decoder_destroy(&decoder);
            destroy_export_logs_arrays(&export_logs);
            otlp_proto_arena_destroy(&arena);
            destroy_logs_resource_states(resource_states, resource_state_count);
            set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }

        current_scope->scope_log->log_records = tmp;

        record = otlp_proto_arena_calloc(&arena, 1,
                                         sizeof(Opentelemetry__Proto__Logs__V1__LogRecord));
        current_scope->scope_log->log_records[
            current_scope->scope_log->n_log_records] = record;
        if (record == NULL) {
            flb_log_event_decoder_destroy(&decoder);
            destroy_export_logs_arrays(&export_logs);
            otlp_proto_arena_destroy(&arena);
            destroy_logs_resource_states(resource_states, resource_state_count);
            set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }

        opentelemetry__proto__logs__v1__log_record__init(record);

        if (log_record_to_proto(
                &arena,
                record,
                &event,
                logs_body_keys,
                logs_body_key_count,
                logs_body_key_attributes) != 0) {
            current_scope->scope_log->log_records[
                current_scope->scope_log->n_log_records] = NULL;
            flb_log_event_decoder_destroy(&decoder);
            destroy_export_logs_arrays(&export_logs);
            otlp_proto_arena_destroy(&arena);
            destroy_logs_resource_states(resource_states, resource_state_count);
            set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }

        current_scope->scope_log->n_log_records++;
    }

    flb_log_event_decoder_destroy(&decoder);
    destroy_logs_resource_states(resource_states, resource_state_count);

    if (ret != FLB_EVENT_DECODER_SUCCESS &&
        ret != FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA) {
        destroy_export_logs_arrays(&export_logs);
        otlp_proto_arena_destroy(&arena);
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_INVALID_LOG_EVENT, EINVAL);
        return NULL;
    }

    output = flb_sds_create_size(
        opentelemetry__proto__collector__logs__v1__export_logs_service_request__get_packed_size(
            &export_logs));
    if (output == NULL) {
        destroy_export_logs_arrays(&export_logs);
        otlp_proto_arena_destroy(&arena);
        set_error(result, FLB_OPENTELEMETRY_OTLP_PROTO_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    cfl_sds_set_len((cfl_sds_t) output,
        opentelemetry__proto__collector__logs__v1__export_logs_service_request__pack(
            &export_logs, (uint8_t *) output));

    destroy_export_logs_arrays(&export_logs);
    otlp_proto_arena_destroy(&arena);
    set_result(result, FLB_OPENTELEMETRY_OTLP_PROTO_SUCCESS);

    return output;
}
