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

#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_json_tree.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_opentelemetry.h>
#include <fluent-bit/flb_time.h>

#include <cfl/cfl_arena.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>

#define OTEL_JSON_CFL_ARENA_CHUNK_SIZE 16384
/*
 * The established path builds maps and arrays with 32-bit headers that are
 * patched once the entries are known, the logs_max_size accounting counts
 * them the same way. Values it copies unchanged keep compact headers.
 */
#define OTEL_JSON_CFL_MAP_HEADER_SIZE  5
#define OTEL_JSON_CFL_ARRAY_HEADER_SIZE 5
#define OTEL_JSON_CFL_RECORD_SIZE      12
#define OTEL_JSON_CFL_MAX_DEPTH        32

struct json_cfl_builder {
    const struct flb_opentelemetry_logs_decode_options *options;
    struct flb_mp_chunk_cobj *chunk;
    struct cfl_arena *arena;
    size_t size;
    size_t limit;
    int error_status;
    int unsupported;
};

struct flb_opentelemetry_logs_json_cfl {
    struct flb_mp_chunk_cobj *chunk;
    struct cfl_arena *arena;
    struct flb_json_tree *document;
    size_t encoded_size;
    size_t record_count;
};


static void *json_arena_malloc(void *context, size_t size)
{
    (void) context;
    return flb_malloc(size);
}

static void json_arena_free(void *context, void *pointer)
{
    (void) context;
    flb_free(pointer);
}

static struct cfl_arena *json_arena_create(void)
{
    struct cfl_arena_options options;

    cfl_arena_options_init(&options);
    options.chunk_size = OTEL_JSON_CFL_ARENA_CHUNK_SIZE;
    options.maximum_chunk_size = 65536;
    options.malloc_fn = json_arena_malloc;
    options.free_fn = json_arena_free;

    return cfl_arena_create_with_options(&options);
}

static int json_cfl_account(struct json_cfl_builder *builder, size_t bytes)
{
    if (bytes > builder->limit || builder->size > builder->limit - bytes) {
        return -1;
    }
    builder->size += bytes;
    return 0;
}

static size_t json_cfl_uint_size(uint64_t value)
{
    if (value <= 0x7f) {
        return 1;
    }
    if (value <= UINT8_MAX) {
        return 2;
    }
    if (value <= UINT16_MAX) {
        return 3;
    }
    if (value <= UINT32_MAX) {
        return 5;
    }
    return 9;
}

static size_t json_cfl_int_size(int64_t value)
{
    if (value >= -32) {
        return 1;
    }
    if (value >= INT8_MIN) {
        return 2;
    }
    if (value >= INT16_MIN) {
        return 3;
    }
    if (value >= INT32_MIN) {
        return 5;
    }
    return 9;
}

static size_t json_cfl_string_header_size(size_t length)
{
    if (length <= 31) {
        return 1;
    }
    if (length <= UINT8_MAX) {
        return 2;
    }
    if (length <= UINT16_MAX) {
        return 3;
    }
    return 5;
}

static size_t json_cfl_binary_header_size(size_t length)
{
    if (length <= UINT8_MAX) {
        return 2;
    }
    if (length <= UINT16_MAX) {
        return 3;
    }
    return 5;
}

static size_t json_cfl_array_header_size(size_t entries)
{
    if (entries <= 15) {
        return 1;
    }
    if (entries <= UINT16_MAX) {
        return 3;
    }
    return 5;
}

static int json_cfl_account_sized(struct json_cfl_builder *builder,
                                  size_t header, size_t value)
{
    if (json_cfl_account(builder, header) != 0) {
        return -1;
    }
    return json_cfl_account(builder, value);
}

static struct cfl_variant *json_cfl_string(struct json_cfl_builder *builder,
                                           const char *value, size_t length)
{
    if (json_cfl_account_sized(builder, json_cfl_string_header_size(length), length) != 0) {
        return NULL;
    }
    return cfl_variant_create_from_string_s_in(builder->arena,
                                                (char *) value, length, CFL_TRUE);
}

static struct cfl_variant *json_cfl_uint(struct json_cfl_builder *builder,
                                         uint64_t value)
{
    if (json_cfl_account(builder, json_cfl_uint_size(value)) != 0) {
        return NULL;
    }
    return cfl_variant_create_from_uint64_in(builder->arena, value);
}

static struct cfl_variant *json_cfl_int(struct json_cfl_builder *builder,
                                        int64_t value)
{
    if (value >= 0) {
        return json_cfl_uint(builder, (uint64_t) value);
    }
    if (json_cfl_account(builder, json_cfl_int_size(value)) != 0) {
        return NULL;
    }
    return cfl_variant_create_from_int64_in(builder->arena, value);
}

static struct cfl_variant *json_cfl_double(struct json_cfl_builder *builder,
                                           double value)
{
    if (json_cfl_account(builder, 9) != 0) {
        return NULL;
    }
    return cfl_variant_create_from_double_in(builder->arena, value);
}

static struct cfl_variant *json_cfl_bool(struct json_cfl_builder *builder, int value)
{
    if (json_cfl_account(builder, 1) != 0) {
        return NULL;
    }
    return cfl_variant_create_from_bool_in(builder->arena, value);
}

static struct cfl_variant *json_cfl_null(struct json_cfl_builder *builder)
{
    if (json_cfl_account(builder, 1) != 0) {
        return NULL;
    }
    return cfl_variant_create_from_null_in(builder->arena);
}

static struct cfl_kvlist *json_cfl_kvlist_create(struct json_cfl_builder *builder)
{
    if (json_cfl_account(builder, OTEL_JSON_CFL_MAP_HEADER_SIZE) != 0) {
        return NULL;
    }
    return cfl_kvlist_create_in(builder->arena);
}

static int json_cfl_insert(struct json_cfl_builder *builder,
                           struct cfl_kvlist *kvlist,
                           const char *key, size_t key_length,
                           struct cfl_variant *value)
{
    if (value == NULL) {
        return -1;
    }
    if (json_cfl_account_sized(builder, json_cfl_string_header_size(key_length),
                               key_length) != 0 ||
        cfl_kvlist_insert_s(kvlist, (char *) key, key_length, value) != 0) {
        cfl_variant_destroy(value);
        return -1;
    }
    return 0;
}

static int json_cfl_insert_kvlist(struct json_cfl_builder *builder,
                                  struct cfl_kvlist *target,
                                  const char *key, size_t key_length,
                                  struct cfl_kvlist *value)
{
    struct cfl_variant *variant;

    if (value == NULL) {
        return -1;
    }
    variant = cfl_variant_create_from_kvlist_in(builder->arena, value);
    if (variant == NULL) {
        cfl_kvlist_destroy(value);
        return -1;
    }
    return json_cfl_insert(builder, target, key, key_length, variant);
}

static struct cfl_object *json_cfl_object(struct json_cfl_builder *builder,
                                          struct cfl_kvlist *kvlist)
{
    struct cfl_object *object;

    if (kvlist == NULL) {
        return NULL;
    }
    object = cfl_object_create();
    if (object == NULL) {
        cfl_kvlist_destroy(kvlist);
        return NULL;
    }
    object->variant = cfl_variant_create_from_kvlist_in(builder->arena, kvlist);
    if (object->variant == NULL) {
        cfl_kvlist_destroy(kvlist);
        cfl_object_destroy(object);
        return NULL;
    }
    object->type = CFL_OBJECT_KVLIST;
    return object;
}

static struct flb_mp_chunk_record *json_cfl_record_add(struct json_cfl_builder *builder,
                                                        struct flb_time *timestamp)
{
    struct flb_mp_chunk_record *record;

    if (json_cfl_account(builder, OTEL_JSON_CFL_RECORD_SIZE) != 0) {
        return NULL;
    }
    record = flb_mp_chunk_record_create(builder->chunk);
    if (record == NULL) {
        return NULL;
    }
    memset(&record->event, 0, sizeof(record->event));
    flb_time_copy(&record->event.timestamp, timestamp);
    cfl_list_add(&record->_head, &builder->chunk->records);
    return record;
}

/*
 * Keys are compared case-insensitively. The expected length is known at
 * compile time, so most keys are rejected by their length alone; callers
 * pass string literals through the json_obj_get() macro.
 */
#define json_obj_get(object, literal) \
    flb_json_node_obj_get_case(object, "" literal, sizeof(literal) - 1)

static int json_base64_decode(const char *source, size_t source_size,
                              unsigned char **output, size_t *output_size)
{
    int result;
    char value;
    char *normalized;
    size_t index;
    size_t padded_size;
    unsigned char *decoded;

    *output = NULL;
    *output_size = 0;
    if (source_size % 4 == 1) {
        return -1;
    }
    padded_size = source_size + ((4 - source_size % 4) % 4);
    normalized = flb_malloc(padded_size + 1);
    decoded = flb_malloc((padded_size / 4) * 3 + 1);
    if (normalized == NULL || decoded == NULL) {
        flb_free(normalized);
        flb_free(decoded);
        return -1;
    }
    for (index = 0; index < source_size; index++) {
        value = source[index];
        normalized[index] = value == '-' ? '+' : (value == '_' ? '/' : value);
    }
    for (; index < padded_size; index++) {
        normalized[index] = '=';
    }
    normalized[padded_size] = '\0';
    result = flb_base64_decode(decoded, (padded_size / 4) * 3 + 1, output_size,
                               (unsigned char *) normalized, padded_size);
    flb_free(normalized);
    if (result != 0) {
        flb_free(decoded);
        return -1;
    }
    *output = decoded;
    return 0;
}

static struct cfl_variant *json_plain_value(struct json_cfl_builder *builder,
                                            struct flb_json_node *value);
static struct cfl_variant *json_converted_value(struct json_cfl_builder *builder,
                                                struct flb_json_node *value, size_t depth);

/*
 * The conversion of OTLP JSON values below mirrors the established msgpack
 * path in flb_opentelemetry_utils.c function by function, including its
 * leniency, so both paths produce the same records:
 *
 *   json_wrapped()          flb_otel_utils_json_payload_get_wrapped_value()
 *   json_unwrapped_value()  flb_otel_utils_json_payload_append_unwrapped_value()
 *   json_converted_*()      flb_otel_utils_json_payload_append_converted_*()
 *
 * A result CFL cannot hold, a map key that is not a string, marks the
 * payload unsupported so the caller can use the msgpack path instead.
 */
#define JSON_WRAPPED_STRING 1
#define JSON_WRAPPED_BOOL   2
#define JSON_WRAPPED_INT    3
#define JSON_WRAPPED_DOUBLE 4
#define JSON_WRAPPED_BYTES  5
#define JSON_WRAPPED_ARRAY  6
#define JSON_WRAPPED_KVLIST 7

/* like the established path, a wrapper key matches any prefix of the name */
static int json_wrapper_key(const char *key, size_t key_length, const char *name)
{
    return strncasecmp(key, name, key_length) == 0;
}

static int json_wrapped(struct flb_json_node *object, struct flb_json_node **out_value,
                        int *out_type)
{
    int type;
    int value_type;
    size_t key_length;
    const char *key_name;
    struct flb_json_node *key;
    struct flb_json_node *value;

    if (flb_json_node_type(object) != FLB_JSON_NODE_OBJ) {
        return -1;
    }
    type = -1;
    value = NULL;
    value_type = FLB_JSON_NODE_NONE;
    if (flb_json_node_obj_size(object) == 1) {
        key = flb_json_node_first(object);
        value = flb_json_node_key_value(key);
        key_name = flb_json_node_get_strn(key, &key_length);
        value_type = flb_json_node_type(value);

        if (json_wrapper_key(key_name, key_length, "stringValue")) {
            if (value_type != FLB_JSON_NODE_NULL && value_type != FLB_JSON_NODE_STR) {
                return -2;
            }
            type = JSON_WRAPPED_STRING;
        }
        else if (json_wrapper_key(key_name, key_length, "boolValue")) {
            if (value_type != FLB_JSON_NODE_BOOL) {
                return -2;
            }
            type = JSON_WRAPPED_BOOL;
        }
        else if (json_wrapper_key(key_name, key_length, "intValue")) {
            if (value_type != FLB_JSON_NODE_UINT && value_type != FLB_JSON_NODE_SINT &&
                value_type != FLB_JSON_NODE_STR) {
                return -2;
            }
            type = JSON_WRAPPED_INT;
        }
        else if (json_wrapper_key(key_name, key_length, "doubleValue")) {
            if (value_type != FLB_JSON_NODE_REAL && value_type != FLB_JSON_NODE_STR) {
                return -2;
            }
            type = JSON_WRAPPED_DOUBLE;
        }
        else if (json_wrapper_key(key_name, key_length, "bytesValue")) {
            if (value_type != FLB_JSON_NODE_STR) {
                return -2;
            }
            type = JSON_WRAPPED_BYTES;
        }
        else if (json_wrapper_key(key_name, key_length, "arrayValue")) {
            if (value_type != FLB_JSON_NODE_ARR && value_type != FLB_JSON_NODE_OBJ) {
                return -2;
            }
            type = JSON_WRAPPED_ARRAY;
        }
        else if (json_wrapper_key(key_name, key_length, "kvlistValue")) {
            if (value_type != FLB_JSON_NODE_OBJ) {
                return -2;
            }
            type = JSON_WRAPPED_KVLIST;
        }
    }
    if (type == -1) {
        return -1;
    }
    if (out_type != NULL) {
        *out_type = type;
    }
    if (value_type == FLB_JSON_NODE_OBJ && flb_json_node_obj_size(value) == 1) {
        key = flb_json_node_first(value);
        if (flb_json_node_get_len(key) != 6 ||
            strncasecmp(flb_json_node_get_str(key), "values", 6) != 0) {
            return -3;
        }
        value = flb_json_node_key_value(key);
    }
    if (type == JSON_WRAPPED_ARRAY && !flb_json_node_is_arr(value) &&
        (!flb_json_node_is_obj(value) || flb_json_node_obj_size(value) != 0)) {
        return -2;
    }
    else if (type == JSON_WRAPPED_KVLIST && !flb_json_node_is_arr(value) &&
             !flb_json_node_is_obj(value)) {
        return -2;
    }
    if (out_value != NULL) {
        *out_value = value;
    }
    return 0;
}

static struct cfl_variant *json_converted_array(struct json_cfl_builder *builder,
                                                struct flb_json_node *array, size_t depth)
{
    size_t index;
    size_t maximum;
    struct flb_json_node *entry;
    struct cfl_array *result;
    struct cfl_variant *variant;

    if (depth > OTEL_JSON_CFL_MAX_DEPTH) {
        builder->unsupported = FLB_TRUE;
        return NULL;
    }
    if (json_cfl_account(builder, OTEL_JSON_CFL_ARRAY_HEADER_SIZE) != 0) {
        return NULL;
    }
    result = cfl_array_create_in(builder->arena, flb_json_node_arr_size(array));
    if (result == NULL) {
        return NULL;
    }
    flb_json_node_arr_foreach(array, index, maximum, entry) {
        variant = json_converted_value(builder, entry, depth + 1);
        if (variant == NULL || cfl_array_append(result, variant) != 0) {
            if (variant != NULL) {
                cfl_variant_destroy(variant);
            }
            cfl_array_destroy(result);
            return NULL;
        }
    }
    variant = cfl_variant_create_from_array_in(builder->arena, result);
    if (variant == NULL) {
        cfl_array_destroy(result);
    }
    return variant;
}

static struct cfl_variant *json_kvlist_variant(struct json_cfl_builder *builder,
                                               struct cfl_kvlist *kvlist)
{
    struct cfl_variant *variant;

    if (kvlist == NULL) {
        return NULL;
    }
    variant = cfl_variant_create_from_kvlist_in(builder->arena, kvlist);
    if (variant == NULL) {
        cfl_kvlist_destroy(kvlist);
    }
    return variant;
}

/* Insert a converted key, CFL only holds string keys */
static int json_converted_insert(struct json_cfl_builder *builder, struct cfl_kvlist *kvlist,
                                 struct flb_json_node *key, struct cfl_variant *value, size_t depth)
{
    int result;
    size_t size;
    struct cfl_variant *key_variant;

    if (value == NULL) {
        return -1;
    }
    if (flb_json_node_is_str(key)) {
        return json_cfl_insert(builder, kvlist, flb_json_node_get_str(key),
                               flb_json_node_get_len(key), value);
    }

    /* the key is accounted once, by the insertion */
    size = builder->size;
    key_variant = json_converted_value(builder, key, depth + 1);
    builder->size = size;
    if (key_variant == NULL || key_variant->type != CFL_VARIANT_STRING) {
        if (key_variant != NULL) {
            builder->unsupported = FLB_TRUE;
            cfl_variant_destroy(key_variant);
        }
        cfl_variant_destroy(value);
        return -1;
    }
    result = json_cfl_insert(builder, kvlist, key_variant->data.as_string,
                             cfl_variant_size_get(key_variant), value);
    cfl_variant_destroy(key_variant);
    return result;
}

static struct cfl_kvlist *json_converted_kvlist(struct json_cfl_builder *builder,
                                                struct flb_json_node *array, size_t depth)
{
    size_t index;
    size_t maximum;
    struct flb_json_node *entry;
    struct flb_json_node *key;
    struct flb_json_node *value;
    struct cfl_kvlist *result;
    struct cfl_variant *variant;

    if (!flb_json_node_is_arr(array)) {
        return NULL;
    }
    if (depth > OTEL_JSON_CFL_MAX_DEPTH) {
        builder->unsupported = FLB_TRUE;
        return NULL;
    }
    result = json_cfl_kvlist_create(builder);
    if (result == NULL) {
        return NULL;
    }
    flb_json_node_arr_foreach(array, index, maximum, entry) {
        key = json_obj_get(entry, "key");
        if (!flb_json_node_is_obj(entry) || key == NULL) {
            cfl_kvlist_destroy(result);
            return NULL;
        }
        value = json_obj_get(entry, "value");
        if (value == NULL) {
            /* an unset value is an empty string */
            variant = json_cfl_string(builder, "", 0);
        }
        else if (flb_json_node_is_obj(value) && flb_json_node_obj_size(value) == 0) {
            variant = json_cfl_null(builder);
        }
        else if (!flb_json_node_is_obj(value)) {
            cfl_kvlist_destroy(result);
            return NULL;
        }
        else {
            variant = json_converted_value(builder, value, depth + 1);
        }
        if (json_converted_insert(builder, result, key, variant, depth) != 0) {
            cfl_kvlist_destroy(result);
            return NULL;
        }
    }
    return result;
}

static struct cfl_variant *json_converted_map(struct json_cfl_builder *builder,
                                              struct flb_json_node *object, size_t depth);

/*
 * Returns 0 with the converted value, NULL on failure, or the json_wrapped()
 * status when the object is not a valid wrapper.
 */
static int json_unwrapped_value(struct json_cfl_builder *builder, struct flb_json_node *object,
                                size_t depth, struct cfl_variant **out_variant)
{
    int ret;
    int type;
    size_t length;
    size_t bytes_size;
    unsigned char *bytes;
    char buffer[33];
    struct flb_json_node *value;
    struct cfl_array *array;

    ret = json_wrapped(object, &value, &type);
    if (ret != 0) {
        return ret;
    }
    *out_variant = NULL;

    switch (type) {
    case JSON_WRAPPED_INT:
        if (flb_json_node_is_str(value)) {
            length = flb_json_node_get_len(value);
            if (length > sizeof(buffer) - 1) {
                length = sizeof(buffer) - 1;
            }
            memcpy(buffer, flb_json_node_get_str(value), length);
            buffer[length] = '\0';
            *out_variant = json_cfl_int(builder, strtoll(buffer, NULL, 10));
            return 0;
        }
        break;
    case JSON_WRAPPED_BYTES:
        if (json_base64_decode(flb_json_node_get_str(value), flb_json_node_get_len(value),
                               &bytes, &bytes_size) != 0) {
            return -2;
        }
        if (json_cfl_account_sized(builder, json_cfl_binary_header_size(bytes_size),
                                   bytes_size) == 0) {
            *out_variant = cfl_variant_create_from_bytes_in(builder->arena, (char *) bytes,
                                                            bytes_size, CFL_FALSE);
        }
        flb_free(bytes);
        return 0;
    case JSON_WRAPPED_ARRAY:
        if (flb_json_node_is_arr(value)) {
            *out_variant = json_converted_array(builder, value, depth + 1);
            return 0;
        }
        if (json_cfl_account(builder, OTEL_JSON_CFL_ARRAY_HEADER_SIZE) != 0) {
            return 0;
        }
        array = cfl_array_create_in(builder->arena, 0);
        if (array != NULL) {
            *out_variant = cfl_variant_create_from_array_in(builder->arena, array);
            if (*out_variant == NULL) {
                cfl_array_destroy(array);
            }
        }
        return 0;
    case JSON_WRAPPED_KVLIST:
        if (flb_json_node_is_arr(value)) {
            *out_variant = json_kvlist_variant(builder,
                                               json_converted_kvlist(builder, value,
                                                                     depth + 1));
        }
        else {
            *out_variant = json_converted_map(builder, value, depth + 1);
        }
        return 0;
    default:
        break;
    }

    /* strings, booleans, numbers and doubles keep their JSON value */
    *out_variant = json_converted_value(builder, value, depth + 1);
    return 0;
}

static struct cfl_variant *json_converted_map(struct json_cfl_builder *builder,
                                              struct flb_json_node *object, size_t depth)
{
    int ret;
    size_t index;
    size_t maximum;
    struct flb_json_node *key;
    struct flb_json_node *value;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *variant;

    if (depth > OTEL_JSON_CFL_MAX_DEPTH) {
        builder->unsupported = FLB_TRUE;
        return NULL;
    }
    variant = NULL;
    ret = json_unwrapped_value(builder, object, depth, &variant);
    if (ret == 0) {
        return variant;
    }
    else if (ret != -1) {
        return NULL;
    }

    kvlist = json_cfl_kvlist_create(builder);
    if (kvlist == NULL) {
        return NULL;
    }
    flb_json_node_obj_foreach(object, index, maximum, key, value) {
        if (json_converted_insert(builder, kvlist, key,
                                  json_converted_value(builder, value, depth + 1),
                                  depth) != 0) {
            cfl_kvlist_destroy(kvlist);
            return NULL;
        }
    }
    return json_kvlist_variant(builder, kvlist);
}

static struct cfl_variant *json_converted_value(struct json_cfl_builder *builder,
                                                struct flb_json_node *value, size_t depth)
{
    switch (flb_json_node_type(value)) {
    case FLB_JSON_NODE_OBJ:
        return json_converted_map(builder, value, depth + 1);
    case FLB_JSON_NODE_ARR:
        return json_converted_array(builder, value, depth + 1);
    case FLB_JSON_NODE_NULL:
        /* the established path encodes JSON null as an empty string */
        return json_cfl_string(builder, "", 0);
    default:
        return json_plain_value(builder, value);
    }
}

/* Copy a JSON value as is, the way the established path copies msgpack objects */
static struct cfl_variant *json_raw_value(struct json_cfl_builder *builder,
                                          struct flb_json_node *value, size_t depth)
{
    int type;
    size_t index;
    size_t maximum;
    struct flb_json_node *key;
    struct flb_json_node *entry;
    struct cfl_array *array;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *variant;

    if (depth > OTEL_JSON_CFL_MAX_DEPTH) {
        return NULL;
    }
    type = flb_json_node_type(value);
    if (type == FLB_JSON_NODE_OBJ) {
        if (json_cfl_account(builder,
                             json_cfl_array_header_size(flb_json_node_obj_size(value))) != 0) {
            return NULL;
        }
        kvlist = cfl_kvlist_create_in(builder->arena);
        if (kvlist == NULL) {
            return NULL;
        }
        flb_json_node_obj_foreach(value, index, maximum, key, entry) {
            if (json_cfl_insert(builder, kvlist, flb_json_node_get_str(key),
                                flb_json_node_get_len(key),
                                json_raw_value(builder, entry, depth + 1)) != 0) {
                cfl_kvlist_destroy(kvlist);
                return NULL;
            }
        }
        variant = cfl_variant_create_from_kvlist_in(builder->arena, kvlist);
        if (variant == NULL) {
            cfl_kvlist_destroy(kvlist);
        }
        return variant;
    }
    if (type == FLB_JSON_NODE_ARR) {
        if (json_cfl_account(builder,
                             json_cfl_array_header_size(flb_json_node_arr_size(value))) != 0) {
            return NULL;
        }
        array = cfl_array_create_in(builder->arena, flb_json_node_arr_size(value));
        if (array == NULL) {
            return NULL;
        }
        flb_json_node_arr_foreach(value, index, maximum, entry) {
            variant = json_raw_value(builder, entry, depth + 1);
            if (variant == NULL || cfl_array_append(array, variant) != 0) {
                if (variant != NULL) {
                    cfl_variant_destroy(variant);
                }
                cfl_array_destroy(array);
                return NULL;
            }
        }
        variant = cfl_variant_create_from_array_in(builder->arena, array);
        if (variant == NULL) {
            cfl_array_destroy(array);
        }
        return variant;
    }
    return json_plain_value(builder, value);
}

/*
 * Parse a decimal string the way the established path does: at most 31
 * characters are considered, and they must all be digits. Values beyond
 * 64 bits saturate. Returns the number of digits, or -1.
 */
static int json_parse_digits(struct flb_json_node *value, uint64_t *result)
{
    size_t index;
    size_t length;
    const char *string;
    char buffer[32];

    if (!flb_json_node_is_str(value)) {
        return -1;
    }
    string = flb_json_node_get_str(value);
    length = flb_json_node_get_len(value);
    if (length > sizeof(buffer) - 1) {
        length = sizeof(buffer) - 1;
    }
    for (index = 0; index < length && string[index] != '\0'; index++) {
        if (!isdigit((unsigned char) string[index])) {
            return -1;
        }
        buffer[index] = string[index];
    }
    buffer[index] = '\0';
    *result = index > 0 ? strtoull(buffer, NULL, 10) : 0;
    return index;
}

/* The timestamp of a log record, it must be an unsigned integer or digits */
static int json_record_timestamp(struct flb_json_node *value, struct flb_time *tm)
{
    uint64_t number;

    if (flb_json_node_is_uint(value)) {
        number = flb_json_node_get_uint(value);
    }
    else if (json_parse_digits(value, &number) < 0) {
        return -1;
    }
    return flb_time_from_uint64(tm, number);
}

/* A non-empty identifier must have the exact hexadecimal length */
static int json_identifier_valid(struct flb_json_node *value, size_t length)
{
    size_t index;
    const char *string;

    if (!flb_json_node_is_str(value)) {
        return FLB_FALSE;
    }
    if (flb_json_node_get_len(value) == 0) {
        return FLB_TRUE;
    }
    if (flb_json_node_get_len(value) != length) {
        return FLB_FALSE;
    }
    string = flb_json_node_get_str(value);
    for (index = 0; index < length; index++) {
        if (!isxdigit((unsigned char) string[index])) {
            return FLB_FALSE;
        }
    }
    return FLB_TRUE;
}

/*
 * Reject a log record the established path rejects, with the same status and
 * in the same order, before any of it is built.
 */
static int json_record_validate(struct json_cfl_builder *builder, struct flb_json_node *log_record,
                                struct flb_time *tm)
{
    struct flb_json_node *value;

    if (!flb_json_node_is_obj(log_record)) {
        return FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_ENTRY_TYPE;
    }
    value = json_obj_get(log_record, "timeUnixNano");
    if (value == NULL) {
        value = json_obj_get(log_record, "observedTimeUnixNano");
    }
    if (value == NULL) {
        flb_time_get(tm);
    }
    else if (json_record_timestamp(value, tm) != 0) {
        return FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE;
    }
    else if (flb_time_is_valid_eventtime(tm) != FLB_TRUE) {
        /* the msgpack path keeps such a record with an unrelated timestamp */
        builder->unsupported = FLB_TRUE;
        return FLB_OTEL_LOGS_ERR_UNEXPECTED_TIMESTAMP_TYPE;
    }
    value = json_obj_get(log_record, "attributes");
    if (value != NULL && !flb_json_node_is_arr(value)) {
        return FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE;
    }
    value = json_obj_get(log_record, "traceId");
    if (value != NULL && json_identifier_valid(value, 32) == FLB_FALSE) {
        return FLB_OTEL_LOGS_ERR_INVALID_TRACE_ID;
    }
    value = json_obj_get(log_record, "spanId");
    if (value != NULL && json_identifier_valid(value, 16) == FLB_FALSE) {
        return FLB_OTEL_LOGS_ERR_INVALID_SPAN_ID;
    }
    value = json_obj_get(log_record, "body");
    if (value != NULL && !flb_json_node_is_obj(value)) {
        return FLB_OTEL_LOGS_ERR_UNEXPECTED_BODY_TYPE;
    }
    return 0;
}

static struct cfl_variant *json_plain_value(struct json_cfl_builder *builder,
                                            struct flb_json_node *value)
{
    size_t length;
    const char *string;

    switch (flb_json_node_type(value)) {
    case FLB_JSON_NODE_STR:
        string = flb_json_node_get_strn(value, &length);
        return json_cfl_string(builder, string, length);
    case FLB_JSON_NODE_UINT:
        return json_cfl_uint(builder, flb_json_node_get_uint(value));
    case FLB_JSON_NODE_SINT:
        return json_cfl_int(builder, flb_json_node_get_sint(value));
    case FLB_JSON_NODE_REAL:
        return json_cfl_double(builder, flb_json_node_get_real(value));
    case FLB_JSON_NODE_BOOL:
        return json_cfl_bool(builder, flb_json_node_get_bool(value));
    case FLB_JSON_NODE_NULL:
        return json_cfl_null(builder);
    default:
        return NULL;
    }
}

static struct cfl_kvlist *json_record_metadata(struct json_cfl_builder *builder,
                                               struct flb_json_node *log_record)
{
    int result;
    uint64_t number;
    unsigned char identifier[16];
    struct flb_json_node *value;
    struct cfl_kvlist *metadata;
    struct cfl_kvlist *otlp;

    result = 0;
    metadata = json_cfl_kvlist_create(builder);
    otlp = json_cfl_kvlist_create(builder);
    if (metadata == NULL || otlp == NULL) {
        goto error;
    }
    value = json_obj_get(log_record, "observedTimeUnixNano");
    if (json_parse_digits(value, &number) > 0) {
        /* the established path stores it as a signed integer */
        result = json_cfl_insert(builder, otlp, "observed_timestamp", 18,
                                 json_cfl_int(builder, (int64_t) number));
    }
    value = json_obj_get(log_record, "severityNumber");
    if (result == 0 && value != NULL) {
        result = json_cfl_insert(builder, otlp, "severity_number", 15,
                                 json_raw_value(builder, value, 0));
    }
    value = json_obj_get(log_record, "severityText");
    if (result == 0 && flb_json_node_is_str(value)) {
        result = json_cfl_insert(builder, otlp, "severity_text", 13,
                                 json_cfl_string(builder, flb_json_node_get_str(value),
                                                 flb_json_node_get_len(value)));
    }
    value = json_obj_get(log_record, "attributes");
    if (result == 0 && value != NULL) {
        result = json_cfl_insert_kvlist(builder, otlp, "attributes", 10,
                                        json_converted_kvlist(builder, value, 0));
        if (result != 0) {
            builder->error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE;
        }
    }
    value = json_obj_get(log_record, "droppedAttributesCount");
    if (result == 0 && value != NULL &&
        (flb_json_node_is_int(value) || flb_json_node_is_uint(value))) {
        result = json_cfl_insert(builder, otlp, "dropped_attributes_count", 24,
                                 json_plain_value(builder, value));
    }
    value = json_obj_get(log_record, "traceId");
    if (result == 0 && flb_json_node_is_str(value) && flb_json_node_get_len(value) > 0) {
        if (flb_json_node_get_len(value) != 32 ||
            flb_otel_utils_hex_to_id(flb_json_node_get_str(value), 32, identifier, 16) != 0 ||
            json_cfl_account_sized(builder, json_cfl_binary_header_size(16), 16) != 0) {
            goto error;
        }
        result = json_cfl_insert(builder, otlp, "trace_id", 8,
                    cfl_variant_create_from_bytes_in(builder->arena,
                                                     (char *) identifier, 16, CFL_FALSE));
    }
    value = json_obj_get(log_record, "spanId");
    if (result == 0 && flb_json_node_is_str(value) && flb_json_node_get_len(value) > 0) {
        if (flb_json_node_get_len(value) != 16 ||
            flb_otel_utils_hex_to_id(flb_json_node_get_str(value), 16, identifier, 8) != 0 ||
            json_cfl_account_sized(builder, json_cfl_binary_header_size(8), 8) != 0) {
            goto error;
        }
        result = json_cfl_insert(builder, otlp, "span_id", 7,
                    cfl_variant_create_from_bytes_in(builder->arena,
                                                     (char *) identifier, 8, CFL_FALSE));
    }
    value = json_obj_get(log_record, "flags");
    if (value == NULL) {
        value = json_obj_get(log_record, "traceFlags");
    }
    if (result == 0 && (flb_json_node_is_uint(value) || json_parse_digits(value, &number) > 0)) {
        if (flb_json_node_is_uint(value)) {
            number = flb_json_node_get_uint(value);
        }
        result = json_cfl_insert(builder, otlp, "trace_flags", 11,
                                 json_cfl_uint(builder, number & 0xff));
    }
    value = json_obj_get(log_record, "eventName");
    if (result == 0 && flb_json_node_is_str(value)) {
        result = json_cfl_insert(builder, otlp, "event_name", 10,
                                 json_cfl_string(builder, flb_json_node_get_str(value),
                                                 flb_json_node_get_len(value)));
    }
    if (result == 0) {
        result = json_cfl_insert_kvlist(builder, metadata, "otlp", 4, otlp);
        otlp = NULL;
    }
    if (result == 0) {
        return metadata;
    }

error:
    cfl_kvlist_destroy(otlp);
    cfl_kvlist_destroy(metadata);
    return NULL;
}

static struct cfl_kvlist *json_record_body(struct json_cfl_builder *builder,
                                           struct flb_json_node *log_record)
{
    int type;
    const char *key;
    struct flb_json_node *body;
    struct cfl_kvlist *result;
    struct cfl_variant *variant;

    body = json_obj_get(log_record, "body");
    if (body == NULL) {
        return json_cfl_kvlist_create(builder);
    }

    /*
     * A kvlist, or a map that is not a wrapped value, is the record itself.
     * Anything else is stored under the body key.
     */
    type = -1;
    if (json_wrapped(body, NULL, &type) != 0 ||
        (builder->options->body_key == NULL && type == JSON_WRAPPED_KVLIST)) {
        variant = json_converted_value(builder, body, 0);
        if (variant == NULL || variant->type != CFL_VARIANT_KVLIST) {
            if (variant != NULL) {
                cfl_variant_destroy(variant);
            }
            builder->error_status = FLB_OTEL_LOGS_ERR_APPEND_BODY_FAILURE;
            return NULL;
        }
        result = variant->data.as_kvlist;
        variant->data.as_kvlist = NULL;
        variant->type = CFL_VARIANT_NULL;
        cfl_variant_destroy(variant);
        return result;
    }

    result = json_cfl_kvlist_create(builder);
    if (result == NULL) {
        return NULL;
    }
    key = builder->options->body_key != NULL ? builder->options->body_key : "log";
    variant = json_converted_value(builder, body, 0);
    if (json_cfl_insert(builder, result, key, strlen(key), variant) != 0) {
        builder->error_status = FLB_OTEL_LOGS_ERR_APPEND_BODY_FAILURE;
        cfl_kvlist_destroy(result);
        return NULL;
    }
    return result;
}

static struct cfl_kvlist *json_group_metadata(struct json_cfl_builder *builder,
                                              size_t resource_index, size_t scope_index)
{
    struct cfl_kvlist *result;

    result = json_cfl_kvlist_create(builder);
    if (result == NULL ||
        json_cfl_insert(builder, result, "schema", 6,
                        json_cfl_string(builder, "otlp", 4)) != 0 ||
        json_cfl_insert(builder, result, "resource_id", 11,
                        json_cfl_uint(builder, resource_index)) != 0 ||
        json_cfl_insert(builder, result, "scope_id", 8,
                        json_cfl_uint(builder, scope_index)) != 0) {
        cfl_kvlist_destroy(result);
        return NULL;
    }
    return result;
}

static struct cfl_kvlist *json_group_body(struct json_cfl_builder *builder,
                                          struct flb_json_node *resource_log,
                                          struct flb_json_node *scope_log)
{
    int result;
    struct flb_json_node *resource;
    struct flb_json_node *scope;
    struct flb_json_node *schema_url;
    struct flb_json_node *value;
    struct cfl_kvlist *body;
    struct cfl_kvlist *resource_map;
    struct cfl_kvlist *scope_map;

    result = 0;
    scope_map = NULL;
    body = json_cfl_kvlist_create(builder);
    resource_map = json_cfl_kvlist_create(builder);
    if (body == NULL || resource_map == NULL) {
        goto error;
    }
    resource = json_obj_get(resource_log, "resource");
    if (flb_json_node_is_obj(resource)) {
        value = json_obj_get(resource, "attributes");
        if (value != NULL) {
            result = json_cfl_insert_kvlist(builder, resource_map, "attributes", 10,
                                            json_converted_kvlist(builder, value, 0));
            if (result != 0) {
                builder->error_status = FLB_OTEL_RESOURCE_INVALID_ATTRIBUTE;
            }
        }
        value = json_obj_get(resource, "droppedAttributesCount");
        if (result == 0 && value != NULL) {
            result = json_cfl_insert(builder, resource_map, "dropped_attributes_count", 24,
                                     json_raw_value(builder, value, 0));
        }
    }
    value = json_obj_get(resource_log, "schemaUrl");
    if (result == 0 && flb_json_node_is_str(value)) {
        result = json_cfl_insert(builder, resource_map, "schema_url", 10,
                                 json_cfl_string(builder, flb_json_node_get_str(value),
                                                 flb_json_node_get_len(value)));
    }
    if (result == 0) {
        result = json_cfl_insert_kvlist(builder, body, "resource", 8, resource_map);
        resource_map = NULL;
    }
    scope = json_obj_get(scope_log, "scope");
    if (!flb_json_node_is_obj(scope)) {
        scope = NULL;
    }
    schema_url = json_obj_get(scope_log, "schemaUrl");
    if (!flb_json_node_is_str(schema_url)) {
        schema_url = NULL;
    }

    /* the scope is only described when the request carries one */
    if (scope == NULL && schema_url == NULL) {
        if (result == 0) {
            return body;
        }
        goto error;
    }
    if (result == 0) {
        scope_map = json_cfl_kvlist_create(builder);
        if (scope_map == NULL) {
            goto error;
        }
    }
    if (result == 0 && scope != NULL) {
        value = json_obj_get(scope, "name");
        if (flb_json_node_is_str(value)) {
            result = json_cfl_insert(builder, scope_map, "name", 4,
                                     json_cfl_string(builder, flb_json_node_get_str(value),
                                                     flb_json_node_get_len(value)));
        }
        value = json_obj_get(scope, "version");
        if (result == 0 && flb_json_node_is_str(value)) {
            result = json_cfl_insert(builder, scope_map, "version", 7,
                                     json_cfl_string(builder, flb_json_node_get_str(value),
                                                     flb_json_node_get_len(value)));
        }
        value = json_obj_get(scope, "droppedAttributesCount");
        if (result == 0 && value != NULL) {
            result = json_cfl_insert(builder, scope_map, "dropped_attributes_count", 24,
                                     json_raw_value(builder, value, 0));
        }
        value = json_obj_get(scope, "attributes");
        if (result == 0 && value != NULL) {
            result = json_cfl_insert_kvlist(builder, scope_map, "attributes", 10,
                                            json_converted_kvlist(builder, value, 0));
            if (result != 0) {
                builder->error_status = FLB_OTEL_LOGS_ERR_SCOPE_KVLIST;
            }
        }
    }
    if (result == 0 && schema_url != NULL) {
        result = json_cfl_insert(builder, scope_map, "schema_url", 10,
                                 json_cfl_string(builder, flb_json_node_get_str(schema_url),
                                                 flb_json_node_get_len(schema_url)));
    }
    if (result == 0) {
        result = json_cfl_insert_kvlist(builder, body, "scope", 5, scope_map);
        scope_map = NULL;
    }
    if (result == 0) {
        return body;
    }

error:
    cfl_kvlist_destroy(scope_map);
    cfl_kvlist_destroy(resource_map);
    cfl_kvlist_destroy(body);
    return NULL;
}

static int json_scope_logs(struct json_cfl_builder *builder,
                           struct flb_json_node *resource_log, struct flb_json_node *scope_log,
                           size_t resource_index, size_t scope_index,
                           size_t *record_count)
{
    size_t index;
    size_t maximum;
    struct flb_json_node *records;
    struct flb_json_node *log_record;
    struct flb_time tm;
    struct flb_mp_chunk_record *group;
    struct flb_mp_chunk_record *record;

    records = json_obj_get(scope_log, "logRecords");
    if (records == NULL ||
        (flb_json_node_is_arr(records) && flb_json_node_arr_size(records) == 0)) {
        return 0;
    }
    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_START, 0);
    group = json_cfl_record_add(builder, &tm);
    if (group == NULL) {
        return -1;
    }
    group->cobj_metadata = json_cfl_object(builder,
                              json_group_metadata(builder, resource_index, scope_index));
    group->cobj_record = json_cfl_object(builder,
                                         json_group_body(builder, resource_log, scope_log));
    if (group->cobj_metadata == NULL || group->cobj_record == NULL) {
        return -1;
    }
    if (!flb_json_node_is_arr(records)) {
        builder->error_status = FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_TYPE;
        return -1;
    }
    group->cobj_group_metadata = group->cobj_metadata;
    group->cobj_group_attributes = group->cobj_record;
    group->owns_group_metadata = FLB_TRUE;
    group->owns_group_attributes = FLB_TRUE;

    flb_json_node_arr_foreach(records, index, maximum, log_record) {
        builder->error_status = json_record_validate(builder, log_record, &tm);
        if (builder->error_status != 0) {
            return -1;
        }
        record = json_cfl_record_add(builder, &tm);
        if (record == NULL) {
            return -1;
        }
        /* the metadata is checked first, it decides the status of a bad record */
        record->cobj_metadata = json_cfl_object(builder,
                                                json_record_metadata(builder, log_record));
        if (record->cobj_metadata == NULL) {
            return -1;
        }
        record->cobj_record = json_cfl_object(builder, json_record_body(builder, log_record));
        if (record->cobj_record == NULL) {
            return -1;
        }
        record->cobj_group_metadata = group->cobj_group_metadata;
        record->cobj_group_attributes = group->cobj_group_attributes;
        (*record_count)++;
    }

    flb_time_set(&tm, FLB_LOG_EVENT_GROUP_END, 0);
    record = json_cfl_record_add(builder, &tm);
    if (record == NULL) {
        return -1;
    }
    record->cobj_metadata = json_cfl_object(builder, json_cfl_kvlist_create(builder));
    record->cobj_record = json_cfl_object(builder, json_cfl_kvlist_create(builder));
    if (record->cobj_metadata == NULL || record->cobj_record == NULL) {
        return -1;
    }
    record->cobj_group_metadata = group->cobj_group_metadata;
    record->cobj_group_attributes = group->cobj_group_attributes;
    return 0;
}

int flb_opentelemetry_logs_json_to_cfl(
        const char *body, size_t length,
        const struct flb_opentelemetry_logs_decode_options *options,
        struct flb_opentelemetry_logs_json_cfl **out_result,
        int *error_status)
{
    int result;
    int status;
    size_t resource_index;
    size_t resource_maximum;
    size_t scope_index;
    size_t scope_maximum;
    struct flb_json_node *root;
    struct flb_json_node *resource_logs;
    struct flb_json_node *resource_log;
    struct flb_json_node *scope_logs;
    struct flb_json_node *scope_log;
    struct flb_json_node *resource;
    struct json_cfl_builder builder;
    struct flb_opentelemetry_logs_json_cfl *output;

    status = 0;
    builder.error_status = 0;
    builder.unsupported = FLB_FALSE;

    if (error_status != NULL) {
        *error_status = 0;
    }
    if (body == NULL || options == NULL || options->metadata_key == NULL ||
        out_result == NULL) {
        return -1;
    }
    *out_result = NULL;
    output = flb_calloc(1, sizeof(*output));
    if (output == NULL) {
        return -1;
    }
    output->arena = json_arena_create();
    if (output->arena == NULL) {
        result = -1;
        goto error;
    }

    /*
     * The tree replaces invalid Unicode like the established conversion does.
     * Leave every payload it does not read, such as content after the request
     * object or a build without a tree backend, to the established conversion
     * so those requests are handled exactly as before.
     */
    output->document = flb_json_tree_read(body, length);
    if (output->document == NULL) {
        result = FLB_OTEL_LOGS_JSON_CFL_UNSUPPORTED;
        goto error;
    }
    root = flb_json_tree_root(output->document);
    if (!flb_json_node_is_obj(root)) {
        status = FLB_OTEL_LOGS_ERR_UNEXPECTED_ROOT_OBJECT_TYPE;
        result = -1;
        goto error;
    }
    resource_logs = json_obj_get(root, "resourceLogs");
    if (resource_logs == NULL) {
        status = FLB_OTEL_LOGS_ERR_RESOURCELOGS_MISSING;
        result = -1;
        goto error;
    }
    if (!flb_json_node_is_arr(resource_logs)) {
        status = FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_TYPE;
        result = -1;
        goto error;
    }
    builder.options = options;
    builder.arena = output->arena;
    builder.size = 0;
    builder.limit = options->output_limit;
    builder.chunk = flb_mp_chunk_cobj_create(NULL, NULL);
    if (builder.chunk == NULL) {
        result = -1;
        goto error;
    }
    builder.chunk->record_pool_enabled = FLB_TRUE;
    output->chunk = builder.chunk;

    /* the checks and their order follow flb_opentelemetry_logs_json_to_msgpack() */
    flb_json_node_arr_foreach(resource_logs, resource_index, resource_maximum, resource_log) {
        if (!flb_json_node_is_obj(resource_log)) {
            status = FLB_OTEL_LOGS_ERR_UNEXPECTED_RESOURCELOGS_ENTRY_TYPE;
            result = -1;
            goto error;
        }
        resource = json_obj_get(resource_log, "resource");
        if (flb_json_node_is_obj(resource) && json_obj_get(resource, "attributes") != NULL &&
            !flb_json_node_is_arr(json_obj_get(resource, "attributes"))) {
            status = FLB_OTEL_LOGS_ERR_UNEXPECTED_ATTRIBUTES_TYPE;
            result = -1;
            goto error;
        }
        scope_logs = json_obj_get(resource_log, "scopeLogs");
        if (scope_logs == NULL) {
            status = FLB_OTEL_LOGS_ERR_SCOPELOGS_MISSING;
            result = -1;
            goto error;
        }
        if (!flb_json_node_is_arr(scope_logs)) {
            status = FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE;
            result = -1;
            goto error;
        }
        flb_json_node_arr_foreach(scope_logs, scope_index, scope_maximum, scope_log) {
            if (!flb_json_node_is_obj(scope_log)) {
                status = FLB_OTEL_LOGS_ERR_UNEXPECTED_SCOPELOGS_TYPE;
                result = -1;
                goto error;
            }
            if (json_scope_logs(&builder, resource_log, scope_log,
                                resource_index, scope_index,
                                &output->record_count) != 0) {
                status = builder.error_status;
                result = -1;
                if (builder.unsupported == FLB_TRUE) {
                    status = 0;
                    result = FLB_OTEL_LOGS_JSON_CFL_UNSUPPORTED;
                }
                goto error;
            }
        }
    }
    output->encoded_size = builder.size;
    *out_result = output;
    return 0;

error:
    if (error_status != NULL) {
        *error_status = status;
    }
    flb_opentelemetry_logs_json_cfl_destroy(output);
    return result;
}

struct flb_mp_chunk_cobj *flb_opentelemetry_logs_json_cfl_take_chunk(
        struct flb_opentelemetry_logs_json_cfl *result)
{
    struct flb_mp_chunk_cobj *chunk;

    if (result == NULL) {
        return NULL;
    }
    chunk = result->chunk;
    result->chunk = NULL;
    return chunk;
}

size_t flb_opentelemetry_logs_json_cfl_get_encoded_size(
        struct flb_opentelemetry_logs_json_cfl *result)
{
    return result != NULL ? result->encoded_size : 0;
}

void flb_opentelemetry_logs_json_cfl_destroy(
        struct flb_opentelemetry_logs_json_cfl *result)
{
    if (result == NULL) {
        return;
    }
    flb_mp_chunk_cobj_destroy(result->chunk);
    cfl_arena_destroy(result->arena);
    flb_json_tree_destroy(result->document);
    flb_free(result);
}
