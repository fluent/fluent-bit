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

#include <errno.h>
#include <inttypes.h>
#include <limits.h>

#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_log_event.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_opentelemetry.h>
#include <fluent-bit/flb_time.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_untyped.h>

#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>

#include <msgpack.h>
#include <fluent-bit/flb_json.h>

#define FLB_OTEL_LOGS_SCHEMA_KEY "schema"
#define FLB_OTEL_LOGS_SCHEMA_OTLP "otlp"
#define FLB_OTEL_LOGS_METADATA_KEY "otlp"

struct otlp_logs_scope_state {
    int64_t         scope_id;
    struct flb_json_mut_val *scope_log;
    struct flb_json_mut_val *log_records;
};

struct otlp_logs_resource_state {
    int64_t                             resource_id;
    struct flb_json_mut_val                     *resource_log;
    struct flb_json_mut_val                     *scope_logs;
    struct otlp_logs_scope_state       *scopes;
    size_t                              scope_count;
};

struct otlp_metrics_scope_state {
    struct flb_json_mut_val *metrics;
};

static msgpack_object *msgpack_map_get_object(msgpack_object_map *map,
                                              const char *key);

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

static flb_sds_t otlp_doc_to_sds(struct flb_json_mut_doc *doc, int pretty)
{
    char      *json_buffer;
    size_t     json_size;
    flb_sds_t  json;

    if (pretty == FLB_TRUE) {
        json_buffer = flb_json_mut_write_pretty(doc, &json_size);
    }
    else {
        json_buffer = flb_json_mut_write(doc, &json_size);
    }

    if (json_buffer == NULL) {
        return NULL;
    }

    json = flb_sds_create_len(json_buffer, json_size);
    flb_free(json_buffer);

    return json;
}

static int append_rendered_root_array_content(flb_sds_t *target,
                                              int *first_entry,
                                              flb_sds_t rendered,
                                              const char *root_key)
{
    flb_sds_t  prefix;
    char      *content_start;
    char      *suffix;
    size_t     content_length;

    if (target == NULL || *target == NULL || first_entry == NULL ||
        rendered == NULL || root_key == NULL) {
        return -1;
    }

    prefix = flb_sds_create_size(strlen(root_key) + 8);
    if (prefix == NULL) {
        return -1;
    }

    prefix = flb_sds_printf(&prefix, "{\"%s\":[", root_key);
    if (prefix == NULL) {
        return -1;
    }

    if (flb_sds_len(rendered) < flb_sds_len(prefix) + 2 ||
        strncmp(rendered, prefix, flb_sds_len(prefix)) != 0 ||
        strcmp(rendered + flb_sds_len(rendered) - 2, "]}") != 0) {
        flb_sds_destroy(prefix);
        return -1;
    }

    content_start = rendered + flb_sds_len(prefix);
    suffix = rendered + flb_sds_len(rendered) - 2;
    content_length = (size_t) (suffix - content_start);

    flb_sds_destroy(prefix);

    if (content_length == 0) {
        return 0;
    }

    if (!*first_entry) {
        *target = flb_sds_cat(*target, ",", 1);
        if (*target == NULL) {
            return -1;
        }
    }

    *target = flb_sds_cat(*target, content_start, content_length);
    if (*target == NULL) {
        return -1;
    }

    *first_entry = FLB_FALSE;

    return 0;
}

static int json_add_uint64_string(struct flb_json_mut_doc *doc,
                                  struct flb_json_mut_val *obj,
                                  const char *key,
                                  uint64_t value)
{
    char buffer[32];
    int  length;

    length = snprintf(buffer, sizeof(buffer), "%" PRIu64, value);
    if (length <= 0 || (size_t) length >= sizeof(buffer)) {
        return -1;
    }

    return flb_json_mut_obj_add_strncpy(doc, obj, key, buffer, length) ? 0 : -1;
}

static int json_add_int64_string(struct flb_json_mut_doc *doc,
                                 struct flb_json_mut_val *obj,
                                 const char *key,
                                 int64_t value)
{
    char buffer[32];
    int  length;

    length = snprintf(buffer, sizeof(buffer), "%" PRId64, value);
    if (length <= 0 || (size_t) length >= sizeof(buffer)) {
        return -1;
    }

    return flb_json_mut_obj_add_strncpy(doc, obj, key, buffer, length) ? 0 : -1;
}

static int binary_to_base64_sds(const char *input, size_t length, flb_sds_t *output)
{
    int      result;
    size_t   encoded_length;
    flb_sds_t encoded;

    *output = NULL;

    result = flb_base64_encode(NULL, 0, &encoded_length,
                               (const unsigned char *) input, length);
    if (result != 0 && result != -0x002A) {
        return -1;
    }

    encoded = flb_sds_create_size(encoded_length + 1);
    if (encoded == NULL) {
        flb_errno();
        return -1;
    }

    result = flb_base64_encode((unsigned char *) encoded,
                               flb_sds_alloc(encoded),
                               &encoded_length,
                               (const unsigned char *) input,
                               length);
    if (result != 0) {
        flb_sds_destroy(encoded);
        return -1;
    }

    cfl_sds_set_len((cfl_sds_t) encoded, encoded_length);
    *output = encoded;

    return 0;
}

static int binary_to_hex(char *output, size_t output_size,
                         const char *input, size_t input_size)
{
    static const char hex[] = "0123456789abcdef";
    size_t            index;

    if (output_size < (input_size * 2) + 1) {
        return -1;
    }

    for (index = 0; index < input_size; index++) {
        output[index * 2] = hex[((unsigned char) input[index]) >> 4];
        output[(index * 2) + 1] = hex[((unsigned char) input[index]) & 0x0f];
    }

    output[input_size * 2] = '\0';

    return 0;
}

static int otlp_uint64_field_value(msgpack_object_map *map,
                                   const char *key,
                                   uint64_t *value)
{
    msgpack_object *field;

    if (map == NULL || key == NULL || value == NULL) {
        return -1;
    }

    field = msgpack_map_get_object(map, (char *) key);
    if (field == NULL) {
        return -1;
    }

    if (field->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        *value = field->via.u64;
        return 0;
    }

    if (field->type == MSGPACK_OBJECT_NEGATIVE_INTEGER &&
        field->via.i64 >= 0) {
        *value = (uint64_t) field->via.i64;
        return 0;
    }

    return -1;
}

static int valid_sds_reference(cfl_sds_t value)
{
    return ((uintptr_t) value) > 1;
}

static struct flb_json_mut_val *create_binary_value(struct flb_json_mut_doc *doc,
                                           const char *input,
                                           size_t length)
{
    flb_sds_t encoded;
    struct flb_json_mut_val *value;

    if (binary_to_base64_sds(input, length, &encoded) != 0) {
        return NULL;
    }

    value = flb_json_mut_strncpy(doc, encoded, flb_sds_len(encoded));
    flb_sds_destroy(encoded);

    return value;
}

static struct flb_json_mut_val *msgpack_object_to_otlp_any_value(struct flb_json_mut_doc *doc,
                                                        msgpack_object *object);

static struct flb_json_mut_val *msgpack_array_to_otlp_any_value(struct flb_json_mut_doc *doc,
                                                       msgpack_object_array *array)
{
    size_t          index;
    struct flb_json_mut_val *entry;
    struct flb_json_mut_val *result;
    struct flb_json_mut_val *values;

    result = flb_json_mut_obj(doc);
    values = flb_json_mut_arr(doc);

    if (result == NULL || values == NULL) {
        return NULL;
    }

    if (!flb_json_mut_obj_add_val(doc, result, "values", values)) {
        return NULL;
    }

    for (index = 0; index < array->size; index++) {
        entry = msgpack_object_to_otlp_any_value(doc, &array->ptr[index]);
        if (entry == NULL || !flb_json_mut_arr_add_val(values, entry)) {
            return NULL;
        }
    }

    return result;
}

static struct flb_json_mut_val *msgpack_map_to_otlp_kv_array(struct flb_json_mut_doc *doc,
                                                    msgpack_object_map *map)
{
    int             key_index;
    size_t          index;
    struct flb_json_mut_val *entry;
    struct flb_json_mut_val *result;
    struct flb_json_mut_val *value;

    result = flb_json_mut_arr(doc);
    if (result == NULL) {
        return NULL;
    }

    for (index = 0; index < map->size; index++) {
        if (map->ptr[index].key.type != MSGPACK_OBJECT_STR) {
            return NULL;
        }

        entry = flb_json_mut_obj(doc);
        value = msgpack_object_to_otlp_any_value(doc, &map->ptr[index].val);
        if (entry == NULL || value == NULL) {
            return NULL;
        }

        key_index = flb_json_mut_obj_add_strncpy(doc,
                                               entry,
                                               "key",
                                               map->ptr[index].key.via.str.ptr,
                                               map->ptr[index].key.via.str.size);
        if (!key_index ||
            !flb_json_mut_obj_add_val(doc, entry, "value", value) ||
            !flb_json_mut_arr_add_val(result, entry)) {
            return NULL;
        }
    }

    return result;
}

static struct flb_json_mut_val *msgpack_map_to_otlp_kv_array_filtered(
    struct flb_json_mut_doc *doc,
    msgpack_object_map *map,
    const char *skip_key,
    size_t skip_key_length)
{
    int                         key_index;
    size_t                      index;
    struct flb_json_mut_val    *entry;
    struct flb_json_mut_val    *result;
    struct flb_json_mut_val    *value;
    msgpack_object             *key;

    result = flb_json_mut_arr(doc);
    if (result == NULL) {
        return NULL;
    }

    for (index = 0; index < map->size; index++) {
        key = &map->ptr[index].key;

        if (key->type != MSGPACK_OBJECT_STR) {
            return NULL;
        }

        if (skip_key != NULL &&
            key->via.str.size == skip_key_length &&
            strncmp(key->via.str.ptr, skip_key, skip_key_length) == 0) {
            continue;
        }

        entry = flb_json_mut_obj(doc);
        value = msgpack_object_to_otlp_any_value(doc, &map->ptr[index].val);
        if (entry == NULL || value == NULL) {
            return NULL;
        }

        key_index = flb_json_mut_obj_add_strncpy(doc,
                                                 entry,
                                                 "key",
                                                 key->via.str.ptr,
                                                 key->via.str.size);
        if (!key_index ||
            !flb_json_mut_obj_add_val(doc, entry, "value", value) ||
            !flb_json_mut_arr_add_val(result, entry)) {
            return NULL;
        }
    }

    return result;
}

static struct flb_json_mut_val *msgpack_map_to_otlp_any_value(struct flb_json_mut_doc *doc,
                                                     msgpack_object_map *map)
{
    struct flb_json_mut_val *result;
    struct flb_json_mut_val *values;

    result = flb_json_mut_obj(doc);
    values = msgpack_map_to_otlp_kv_array(doc, map);

    if (result == NULL || values == NULL) {
        return NULL;
    }

    if (!flb_json_mut_obj_add_val(doc, result, "values", values)) {
        return NULL;
    }

    return result;
}

static struct flb_json_mut_val *msgpack_object_to_otlp_any_value(struct flb_json_mut_doc *doc,
                                                        msgpack_object *object)
{
    struct flb_json_mut_val *root;
    struct flb_json_mut_val *value;

    if (object == NULL || object->type == MSGPACK_OBJECT_NIL) {
        return NULL;
    }

    root = flb_json_mut_obj(doc);
    if (root == NULL) {
        return NULL;
    }

    switch (object->type) {
    case MSGPACK_OBJECT_BOOLEAN:
        return flb_json_mut_obj_add_bool(doc, root, "boolValue",
                                       object->via.boolean) ? root : NULL;
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        return json_add_uint64_string(doc, root, "intValue",
                                      object->via.u64) == 0 ? root : NULL;
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        return json_add_int64_string(doc, root, "intValue",
                                     object->via.i64) == 0 ? root : NULL;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        return flb_json_mut_obj_add_real(doc, root, "doubleValue",
                                       object->via.f64) ? root : NULL;
    case MSGPACK_OBJECT_STR:
        return flb_json_mut_obj_add_strncpy(doc, root, "stringValue",
                                          object->via.str.ptr,
                                          object->via.str.size) ? root : NULL;
    case MSGPACK_OBJECT_BIN:
        value = create_binary_value(doc, object->via.bin.ptr, object->via.bin.size);
        return (value != NULL &&
                flb_json_mut_obj_add_val(doc, root, "bytesValue", value)) ? root : NULL;
    case MSGPACK_OBJECT_ARRAY:
        value = msgpack_array_to_otlp_any_value(doc, &object->via.array);
        return (value != NULL &&
                flb_json_mut_obj_add_val(doc, root, "arrayValue", value)) ? root : NULL;
    case MSGPACK_OBJECT_MAP:
        value = msgpack_map_to_otlp_any_value(doc, &object->via.map);
        return (value != NULL &&
                flb_json_mut_obj_add_val(doc, root, "kvlistValue", value)) ? root : NULL;
    default:
        return NULL;
    }
}

static struct flb_json_mut_val *cfl_variant_to_otlp_any_value(struct flb_json_mut_doc *doc,
                                                     struct cfl_variant *variant);

static struct flb_json_mut_val *cfl_array_to_otlp_any_value(struct flb_json_mut_doc *doc,
                                                   struct cfl_array *array)
{
    size_t          index;
    struct flb_json_mut_val *entry;
    struct flb_json_mut_val *result;
    struct flb_json_mut_val *values;

    result = flb_json_mut_obj(doc);
    values = flb_json_mut_arr(doc);

    if (result == NULL || values == NULL) {
        return NULL;
    }

    if (!flb_json_mut_obj_add_val(doc, result, "values", values)) {
        return NULL;
    }

    for (index = 0; index < array->entry_count; index++) {
        entry = cfl_variant_to_otlp_any_value(doc, array->entries[index]);
        if (entry == NULL || !flb_json_mut_arr_add_val(values, entry)) {
            return NULL;
        }
    }

    return result;
}

static struct flb_json_mut_val *cfl_kvlist_to_otlp_kv_array(struct flb_json_mut_doc *doc,
                                                   struct cfl_kvlist *kvlist)
{
    struct cfl_kvpair *pair;
    struct cfl_list   *head;
    struct flb_json_mut_val    *entry;
    struct flb_json_mut_val    *result;
    struct flb_json_mut_val    *value;

    result = flb_json_mut_arr(doc);
    if (result == NULL) {
        return NULL;
    }

    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        entry = flb_json_mut_obj(doc);
        value = cfl_variant_to_otlp_any_value(doc, pair->val);
        if (entry == NULL || value == NULL) {
            return NULL;
        }

        if (!flb_json_mut_obj_add_strncpy(doc, entry, "key",
                                        pair->key, cfl_sds_len(pair->key)) ||
            !flb_json_mut_obj_add_val(doc, entry, "value", value) ||
            !flb_json_mut_arr_add_val(result, entry)) {
            return NULL;
        }
    }

    return result;
}

static struct flb_json_mut_val *cfl_kvlist_to_otlp_any_value(struct flb_json_mut_doc *doc,
                                                    struct cfl_kvlist *kvlist)
{
    struct flb_json_mut_val *result;
    struct flb_json_mut_val *values;

    result = flb_json_mut_obj(doc);
    values = cfl_kvlist_to_otlp_kv_array(doc, kvlist);

    if (result == NULL || values == NULL) {
        return NULL;
    }

    if (!flb_json_mut_obj_add_val(doc, result, "values", values)) {
        return NULL;
    }

    return result;
}

static struct flb_json_mut_val *cfl_variant_to_otlp_any_value(struct flb_json_mut_doc *doc,
                                                     struct cfl_variant *variant)
{
    struct flb_json_mut_val *root;
    struct flb_json_mut_val *value;

    if (variant == NULL) {
        return NULL;
    }

    root = flb_json_mut_obj(doc);
    if (root == NULL) {
        return NULL;
    }

    switch (variant->type) {
    case CFL_VARIANT_BOOL:
        return flb_json_mut_obj_add_bool(doc, root, "boolValue",
                                       variant->data.as_bool) ? root : NULL;
    case CFL_VARIANT_INT:
        return json_add_int64_string(doc, root, "intValue",
                                     variant->data.as_int64) == 0 ? root : NULL;
    case CFL_VARIANT_UINT:
        return json_add_uint64_string(doc, root, "intValue",
                                      variant->data.as_uint64) == 0 ? root : NULL;
    case CFL_VARIANT_DOUBLE:
        return flb_json_mut_obj_add_real(doc, root, "doubleValue",
                                       variant->data.as_double) ? root : NULL;
    case CFL_VARIANT_STRING:
        return flb_json_mut_obj_add_strncpy(doc, root, "stringValue",
                                          variant->data.as_string,
                                          cfl_sds_len(variant->data.as_string)) ? root : NULL;
    case CFL_VARIANT_BYTES:
        value = create_binary_value(doc, variant->data.as_bytes,
                                    cfl_sds_len(variant->data.as_bytes));
        return (value != NULL &&
                flb_json_mut_obj_add_val(doc, root, "bytesValue", value)) ? root : NULL;
    case CFL_VARIANT_ARRAY:
        value = cfl_array_to_otlp_any_value(doc, variant->data.as_array);
        return (value != NULL &&
                flb_json_mut_obj_add_val(doc, root, "arrayValue", value)) ? root : NULL;
    case CFL_VARIANT_KVLIST:
        value = cfl_kvlist_to_otlp_any_value(doc, variant->data.as_kvlist);
        return (value != NULL &&
                flb_json_mut_obj_add_val(doc, root, "kvlistValue", value)) ? root : NULL;
    default:
        return NULL;
    }
}

static int msgpack_map_entry_is_string(msgpack_object_map *map,
                                       const char *key,
                                       const char *value)
{
    int            index;
    msgpack_object *entry_value;
    size_t          value_length;

    if (map == NULL || key == NULL || value == NULL) {
        return FLB_FALSE;
    }

    index = flb_otel_utils_find_map_entry_by_key(map, (char *) key, 0, FLB_TRUE);
    if (index < 0) {
        return FLB_FALSE;
    }

    entry_value = &map->ptr[index].val;
    value_length = strlen(value);

    if (entry_value->type != MSGPACK_OBJECT_STR ||
        entry_value->via.str.size != value_length) {
        return FLB_FALSE;
    }

    return strncmp(entry_value->via.str.ptr, value, value_length) == 0;
}

static int msgpack_map_contains_key(msgpack_object_map *map, const char *key)
{
    if (map == NULL || key == NULL) {
        return FLB_FALSE;
    }

    return flb_otel_utils_find_map_entry_by_key(map, (char *) key, 0, FLB_TRUE) >= 0;
}

int flb_opentelemetry_log_is_otlp(struct flb_log_event *log_event)
{
    if (log_event == NULL) {
        return FLB_FALSE;
    }

    if (log_event->group_metadata != NULL &&
        log_event->group_metadata->type == MSGPACK_OBJECT_MAP &&
        msgpack_map_entry_is_string(&log_event->group_metadata->via.map,
                                    FLB_OTEL_LOGS_SCHEMA_KEY,
                                    FLB_OTEL_LOGS_SCHEMA_OTLP) == FLB_TRUE) {
        return FLB_TRUE;
    }

    if (log_event->metadata != NULL &&
        log_event->metadata->type == MSGPACK_OBJECT_MAP &&
        msgpack_map_contains_key(&log_event->metadata->via.map,
                                 FLB_OTEL_LOGS_METADATA_KEY) == FLB_TRUE) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

int flb_opentelemetry_logs_chunk_is_otlp(const void *event_chunk_data,
                                         size_t event_chunk_size)
{
    int                           ret;
    struct flb_log_event          event;
    struct flb_log_event_decoder  decoder;

    if (event_chunk_data == NULL || event_chunk_size == 0) {
        return FLB_FALSE;
    }

    ret = flb_log_event_decoder_init(&decoder,
                                     (char *) event_chunk_data,
                                     event_chunk_size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        return FLB_FALSE;
    }

    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);

    while ((ret = flb_log_event_decoder_next(&decoder, &event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        if (flb_opentelemetry_log_is_otlp(&event) == FLB_TRUE) {
            flb_log_event_decoder_destroy(&decoder);
            return FLB_TRUE;
        }
    }

    flb_log_event_decoder_destroy(&decoder);

    return FLB_FALSE;
}

static int msgpack_map_get_int64(msgpack_object_map *map,
                                 const char *key,
                                 int64_t *output)
{
    int            index;
    msgpack_object *value;

    index = flb_otel_utils_find_map_entry_by_key(map, (char *) key, 0, FLB_TRUE);
    if (index < 0) {
        return -1;
    }

    value = &map->ptr[index].val;

    if (value->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        *output = (int64_t) value->via.u64;
        return 0;
    }
    else if (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        *output = value->via.i64;
        return 0;
    }

    return -1;
}

static msgpack_object *msgpack_map_get_object(msgpack_object_map *map,
                                              const char *key)
{
    int index;

    index = flb_otel_utils_find_map_entry_by_key(map, (char *) key, 0, FLB_TRUE);
    if (index < 0) {
        return NULL;
    }

    return &map->ptr[index].val;
}

static struct otlp_logs_resource_state *find_logs_resource_state(
    struct otlp_logs_resource_state *states,
    size_t state_count,
    int64_t resource_id)
{
    size_t index;

    for (index = 0; index < state_count; index++) {
        if (states[index].resource_id == resource_id) {
            return &states[index];
        }
    }

    return NULL;
}

static struct otlp_logs_scope_state *find_logs_scope_state(
    struct otlp_logs_resource_state *resource,
    int64_t scope_id)
{
    size_t index;

    for (index = 0; index < resource->scope_count; index++) {
        if (resource->scopes[index].scope_id == scope_id) {
            return &resource->scopes[index];
        }
    }

    return NULL;
}

static int add_msgpack_attributes_array(struct flb_json_mut_doc *doc,
                                        struct flb_json_mut_val *obj,
                                        const char *key,
                                        msgpack_object *source)
{
    struct flb_json_mut_val *value;

    if (source == NULL || source->type != MSGPACK_OBJECT_MAP) {
        return 0;
    }

    value = msgpack_map_to_otlp_kv_array(doc, &source->via.map);
    if (value == NULL) {
        return -1;
    }

    return flb_json_mut_obj_add_val(doc, obj, key, value) ? 0 : -1;
}

static struct flb_json_mut_val *logs_group_resource_to_json(struct flb_json_mut_doc *doc,
                                                   msgpack_object *resource_object)
{
    msgpack_object *attributes;
    msgpack_object *metadata;
    struct flb_json_mut_val *resource;

    resource = flb_json_mut_obj(doc);
    if (resource == NULL) {
        return NULL;
    }

    if (resource_object == NULL || resource_object->type != MSGPACK_OBJECT_MAP) {
        return resource;
    }

    attributes = msgpack_map_get_object(&resource_object->via.map, "attributes");
    if (attributes != NULL &&
        add_msgpack_attributes_array(doc, resource, "attributes", attributes) != 0) {
        return NULL;
    }

    metadata = msgpack_map_get_object(&resource_object->via.map,
                                      "dropped_attributes_count");
    if (metadata != NULL) {
        if (metadata->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            if (!flb_json_mut_obj_add_uint(doc, resource, "droppedAttributesCount",
                                         metadata->via.u64)) {
                return NULL;
            }
        }
        else if (metadata->type == MSGPACK_OBJECT_NEGATIVE_INTEGER &&
                 metadata->via.i64 >= 0) {
            if (!flb_json_mut_obj_add_uint(doc, resource, "droppedAttributesCount",
                                         (uint64_t) metadata->via.i64)) {
                return NULL;
            }
        }
    }

    return resource;
}

static struct flb_json_mut_val *logs_group_scope_to_json(struct flb_json_mut_doc *doc,
                                                msgpack_object *scope_object)
{
    msgpack_object *field;
    struct flb_json_mut_val *scope;

    scope = flb_json_mut_obj(doc);
    if (scope == NULL) {
        return NULL;
    }

    if (scope_object == NULL || scope_object->type != MSGPACK_OBJECT_MAP) {
        return scope;
    }

    field = msgpack_map_get_object(&scope_object->via.map, "name");
    if (field != NULL && field->type == MSGPACK_OBJECT_STR) {
        if (!flb_json_mut_obj_add_strncpy(doc, scope, "name",
                                        field->via.str.ptr,
                                        field->via.str.size)) {
            return NULL;
        }
    }

    field = msgpack_map_get_object(&scope_object->via.map, "version");
    if (field != NULL && field->type == MSGPACK_OBJECT_STR) {
        if (!flb_json_mut_obj_add_strncpy(doc, scope, "version",
                                        field->via.str.ptr,
                                        field->via.str.size)) {
            return NULL;
        }
    }

    field = msgpack_map_get_object(&scope_object->via.map, "attributes");
    if (field != NULL &&
        add_msgpack_attributes_array(doc, scope, "attributes", field) != 0) {
        return NULL;
    }

    field = msgpack_map_get_object(&scope_object->via.map, "dropped_attributes_count");
    if (field != NULL && field->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        if (!flb_json_mut_obj_add_uint(doc, scope, "droppedAttributesCount",
                                     field->via.u64)) {
            return NULL;
        }
    }

    return scope;
}

static struct otlp_logs_resource_state *append_logs_resource_state(
    struct flb_json_mut_doc *doc,
    struct flb_json_mut_val *resource_logs,
    struct otlp_logs_resource_state **states,
    size_t *state_count,
    int64_t resource_id,
    msgpack_object *resource_object,
    msgpack_object *resource_body)
{
    struct otlp_logs_resource_state *new_states;
    struct otlp_logs_resource_state *state;
    msgpack_object                  *schema_url;
    struct flb_json_mut_val                  *resource_log;
    struct flb_json_mut_val                  *resource;
    struct flb_json_mut_val                  *scope_logs;

    resource_log = flb_json_mut_obj(doc);
    scope_logs = flb_json_mut_arr(doc);
    resource = logs_group_resource_to_json(doc, resource_object);

    if (resource_log == NULL || scope_logs == NULL || resource == NULL) {
        return NULL;
    }

    if (!flb_json_mut_obj_add_val(doc, resource_log, "resource", resource) ||
        !flb_json_mut_obj_add_val(doc, resource_log, "scopeLogs", scope_logs) ||
        !flb_json_mut_arr_add_val(resource_logs, resource_log)) {
        return NULL;
    }

    if (resource_body != NULL && resource_body->type == MSGPACK_OBJECT_MAP) {
        schema_url = msgpack_map_get_object(&resource_body->via.map, "schema_url");
        if (schema_url != NULL && schema_url->type == MSGPACK_OBJECT_STR) {
            if (!flb_json_mut_obj_add_strncpy(doc,
                                            resource_log,
                                            "schemaUrl",
                                            schema_url->via.str.ptr,
                                            schema_url->via.str.size)) {
                return NULL;
            }
        }
    }

    new_states = flb_realloc(*states,
                             sizeof(struct otlp_logs_resource_state) *
                             (*state_count + 1));
    if (new_states == NULL) {
        flb_errno();
        return NULL;
    }

    *states = new_states;
    state = &new_states[*state_count];
    memset(state, 0, sizeof(struct otlp_logs_resource_state));

    state->resource_id = resource_id;
    state->resource_log = resource_log;
    state->scope_logs = scope_logs;

    (*state_count)++;

    return state;
}

static struct otlp_logs_scope_state *append_logs_scope_state(
    struct flb_json_mut_doc *doc,
    struct otlp_logs_resource_state *resource_state,
    int64_t scope_id,
    msgpack_object *scope_object)
{
    struct otlp_logs_scope_state *new_scopes;
    struct otlp_logs_scope_state *state;
    msgpack_object               *schema_url;
    struct flb_json_mut_val               *log_records;
    struct flb_json_mut_val               *scope;
    struct flb_json_mut_val               *scope_log;

    scope_log = flb_json_mut_obj(doc);
    log_records = flb_json_mut_arr(doc);
    scope = logs_group_scope_to_json(doc, scope_object);

    if (scope_log == NULL || log_records == NULL || scope == NULL) {
        return NULL;
    }

    if (!flb_json_mut_obj_add_val(doc, scope_log, "scope", scope) ||
        !flb_json_mut_obj_add_val(doc, scope_log, "logRecords", log_records) ||
        !flb_json_mut_arr_add_val(resource_state->scope_logs, scope_log)) {
        return NULL;
    }

    if (scope_object != NULL && scope_object->type == MSGPACK_OBJECT_MAP) {
        schema_url = msgpack_map_get_object(&scope_object->via.map, "schema_url");
        if (schema_url != NULL && schema_url->type == MSGPACK_OBJECT_STR) {
            if (!flb_json_mut_obj_add_strncpy(doc,
                                            scope_log,
                                            "schemaUrl",
                                            schema_url->via.str.ptr,
                                            schema_url->via.str.size)) {
                return NULL;
            }
        }
    }

    new_scopes = flb_realloc(resource_state->scopes,
                             sizeof(struct otlp_logs_scope_state) *
                             (resource_state->scope_count + 1));
    if (new_scopes == NULL) {
        flb_errno();
        return NULL;
    }

    resource_state->scopes = new_scopes;
    state = &new_scopes[resource_state->scope_count];
    memset(state, 0, sizeof(struct otlp_logs_scope_state));

    state->scope_id = scope_id;
    state->scope_log = scope_log;
    state->log_records = log_records;

    resource_state->scope_count++;

    return state;
}

static int ensure_default_logs_scope_state(
    struct flb_json_mut_doc *doc,
    struct flb_json_mut_val *resource_logs,
    struct otlp_logs_resource_state **resource_states,
    size_t *resource_state_count,
    struct otlp_logs_resource_state **current_resource,
    struct otlp_logs_scope_state **current_scope)
{
    *current_resource = find_logs_resource_state(*resource_states,
                                                 *resource_state_count,
                                                 0);
    if (*current_resource == NULL) {
        *current_resource = append_logs_resource_state(doc,
                                                       resource_logs,
                                                       resource_states,
                                                       resource_state_count,
                                                       0,
                                                       NULL,
                                                       NULL);
        if (*current_resource == NULL) {
            return -1;
        }
    }

    *current_scope = find_logs_scope_state(*current_resource, 0);
    if (*current_scope == NULL) {
        *current_scope = append_logs_scope_state(doc,
                                                 *current_resource,
                                                 0,
                                                 NULL);
        if (*current_scope == NULL) {
            return -1;
        }
    }

    return 0;
}

static msgpack_object *find_log_body_candidate(msgpack_object *body,
                                               const char **logs_body_keys,
                                               size_t logs_body_key_count,
                                               const char **matched_key,
                                               size_t *matched_key_length)
{
    size_t          index;
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

static struct flb_json_mut_val *extract_log_body_value(struct flb_json_mut_doc *doc,
                                              msgpack_object *body,
                                              const char **logs_body_keys,
                                              size_t logs_body_key_count,
                                              const char **matched_key,
                                              size_t *matched_key_length)
{
    msgpack_object *candidate;

    candidate = find_log_body_candidate(body,
                                        logs_body_keys,
                                        logs_body_key_count,
                                        matched_key,
                                        matched_key_length);

    return msgpack_object_to_otlp_any_value(doc, candidate);
}

static int add_binary_id_field(struct flb_json_mut_doc *doc,
                               struct flb_json_mut_val *obj,
                               const char *key,
                               msgpack_object *value,
                               size_t expected_size)
{
    char      hex_buffer[33];
    flb_sds_t encoded;

    if (value == NULL || value->type != MSGPACK_OBJECT_BIN) {
        return 0;
    }

    if (value->via.bin.size == expected_size &&
        binary_to_hex(hex_buffer, sizeof(hex_buffer),
                      value->via.bin.ptr, value->via.bin.size) == 0) {
        return flb_json_mut_obj_add_strcpy(doc, obj, key, hex_buffer) ? 0 : -1;
    }

    if (binary_to_base64_sds(value->via.bin.ptr, value->via.bin.size, &encoded) != 0) {
        return -1;
    }

    if (!flb_json_mut_obj_add_strn(doc, obj, key, encoded, flb_sds_len(encoded))) {
        flb_sds_destroy(encoded);
        return -1;
    }

    flb_sds_destroy(encoded);

    return 0;
}

static struct flb_json_mut_val *log_record_to_json(struct flb_json_mut_doc *doc,
                                          struct flb_log_event *event,
                                          const char **logs_body_keys,
                                          size_t logs_body_key_count,
                                          int logs_body_key_attributes)
{
    int               attributes_added;
    const char       *matched_body_key;
    msgpack_object *metadata;
    msgpack_object *field;
    msgpack_object *otlp_metadata;
    struct flb_json_mut_val *attributes;
    struct flb_json_mut_val *body;
    struct flb_json_mut_val *record;
    size_t           matched_body_key_length;
    uint64_t        timestamp;

    record = flb_json_mut_obj(doc);
    if (record == NULL) {
        return NULL;
    }

    metadata = event->metadata;
    otlp_metadata = NULL;
    attributes = NULL;
    attributes_added = FLB_FALSE;
    matched_body_key = NULL;
    matched_body_key_length = 0;

    if (metadata != NULL && metadata->type == MSGPACK_OBJECT_MAP) {
        otlp_metadata = msgpack_map_get_object(&metadata->via.map, FLB_OTEL_LOGS_METADATA_KEY);
    }

    if (otlp_metadata != NULL && otlp_metadata->type == MSGPACK_OBJECT_MAP &&
        otlp_uint64_field_value(&otlp_metadata->via.map, "timestamp", &timestamp) == 0) {
        /* preserve the exact OTLP log timestamp when the normalized chunk carries it */
    }
    else if (event->raw_timestamp != NULL) {
        if (event->raw_timestamp->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            timestamp = event->raw_timestamp->via.u64;
        }
        else if (event->raw_timestamp->type == MSGPACK_OBJECT_NEGATIVE_INTEGER &&
                 event->raw_timestamp->via.i64 >= 0) {
            timestamp = (uint64_t) event->raw_timestamp->via.i64;
        }
        else {
            timestamp = flb_time_to_nanosec(&event->timestamp);
        }
    }
    else {
        timestamp = flb_time_to_nanosec(&event->timestamp);
    }
    if (timestamp > 0 &&
        json_add_uint64_string(doc, record, "timeUnixNano", timestamp) != 0) {
        return NULL;
    }

    if (otlp_metadata != NULL && otlp_metadata->type == MSGPACK_OBJECT_MAP) {
        field = msgpack_map_get_object(&otlp_metadata->via.map, "observed_timestamp");
        if (field != NULL) {
            if (field->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                if (json_add_uint64_string(doc, record, "observedTimeUnixNano",
                                           field->via.u64) != 0) {
                    return NULL;
                }
            }
            else if (field->type == MSGPACK_OBJECT_NEGATIVE_INTEGER &&
                     field->via.i64 >= 0) {
                if (json_add_uint64_string(doc, record, "observedTimeUnixNano",
                                           (uint64_t) field->via.i64) != 0) {
                    return NULL;
                }
            }
        }

        field = msgpack_map_get_object(&otlp_metadata->via.map, "severity_number");
        if (field != NULL) {
            if (field->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                if (!flb_json_mut_obj_add_uint(doc, record, "severityNumber",
                                             field->via.u64)) {
                    return NULL;
                }
            }
            else if (field->type == MSGPACK_OBJECT_NEGATIVE_INTEGER &&
                     field->via.i64 >= 0) {
                if (!flb_json_mut_obj_add_uint(doc, record, "severityNumber",
                                             (uint64_t) field->via.i64)) {
                    return NULL;
                }
            }
        }

        field = msgpack_map_get_object(&otlp_metadata->via.map, "severity_text");
        if (field != NULL && field->type == MSGPACK_OBJECT_STR) {
            if (!flb_json_mut_obj_add_strncpy(doc, record, "severityText",
                                            field->via.str.ptr,
                                            field->via.str.size)) {
                return NULL;
            }
        }

        field = msgpack_map_get_object(&otlp_metadata->via.map, "attributes");
        if (field != NULL && field->type == MSGPACK_OBJECT_MAP) {
            attributes = msgpack_map_to_otlp_kv_array(doc, &field->via.map);
            if (attributes == NULL) {
                return NULL;
            }

            if (flb_json_mut_arr_size(attributes) > 0 &&
                !flb_json_mut_obj_add_val(doc, record, "attributes", attributes)) {
                return NULL;
            }

            attributes_added = FLB_TRUE;
        }

        if (add_binary_id_field(doc, record, "traceId",
                                msgpack_map_get_object(&otlp_metadata->via.map, "trace_id"),
                                16) != 0 ||
            add_binary_id_field(doc, record, "spanId",
                                msgpack_map_get_object(&otlp_metadata->via.map, "span_id"),
                                8) != 0) {
            return NULL;
        }
    }

    body = extract_log_body_value(doc,
                                  event->body,
                                  logs_body_keys,
                                  logs_body_key_count,
                                  &matched_body_key,
                                  &matched_body_key_length);

    if (logs_body_key_attributes == FLB_TRUE &&
        matched_body_key != NULL &&
        event->body != NULL &&
        event->body->type == MSGPACK_OBJECT_MAP &&
        attributes == NULL) {
        attributes = msgpack_map_to_otlp_kv_array_filtered(doc,
                                                           &event->body->via.map,
                                                           matched_body_key,
                                                           matched_body_key_length);
        if (attributes == NULL) {
            return NULL;
        }
    }

    if (attributes != NULL &&
        attributes_added == FLB_FALSE &&
        flb_json_mut_arr_size(attributes) > 0 &&
        !flb_json_mut_obj_add_val(doc, record, "attributes", attributes)) {
        return NULL;
    }

    if (body != NULL && !flb_json_mut_obj_add_val(doc, record, "body", body)) {
        return NULL;
    }

    return record;
}

static void destroy_logs_resource_states(struct otlp_logs_resource_state *states,
                                         size_t count)
{
    size_t index;

    if (states == NULL) {
        return;
    }

    for (index = 0; index < count; index++) {
        if (states[index].scopes != NULL) {
            flb_free(states[index].scopes);
        }
    }

    flb_free(states);
}

static flb_sds_t flb_opentelemetry_logs_to_otlp_json_render(
    const void *event_chunk_data,
    size_t event_chunk_size,
    struct flb_opentelemetry_otlp_json_options *options,
    int pretty,
    int *result)
{
    int                              ret;
    int32_t                          record_type;
    int                              logs_body_key_attributes;
    int                              require_otel_metadata;
    int64_t                          resource_id;
    int64_t                          scope_id;
    const char                     **logs_body_keys;
    const char                      *logs_body_key;
    struct flb_json_mut_doc                  *doc;
    struct flb_json_mut_val                  *resource_logs;
    struct flb_json_mut_val                  *root;
    struct flb_json_mut_val                  *record;
    msgpack_object                  *group_body;
    msgpack_object                  *group_metadata;
    msgpack_object                  *resource_object;
    msgpack_object                  *scope_object;
    flb_sds_t                        json;
    struct flb_log_event             event;
    struct flb_log_event_decoder     decoder;
    struct otlp_logs_scope_state    *current_scope;
    struct otlp_logs_resource_state *current_resource;
    struct otlp_logs_resource_state *resource_states;
    size_t                           logs_body_key_count;
    size_t                           resource_state_count;
    static const char               *default_logs_body_keys[] = {"log", "message"};

    if (event_chunk_data == NULL || event_chunk_size == 0) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    require_otel_metadata = FLB_TRUE;
    logs_body_key = "log";
    logs_body_keys = default_logs_body_keys;
    logs_body_key_count = 2;
    logs_body_key_attributes = FLB_FALSE;

    if (options != NULL) {
        require_otel_metadata = options->logs_require_otel_metadata;
        logs_body_key_attributes = options->logs_body_key_attributes;
        if (options->logs_body_keys != NULL && options->logs_body_key_count > 0) {
            logs_body_keys = options->logs_body_keys;
            logs_body_key_count = options->logs_body_key_count;
        }
        else if (options->logs_body_key != NULL) {
            logs_body_key = options->logs_body_key;
            logs_body_keys = &logs_body_key;
            logs_body_key_count = 1;
        }
    }

    if (require_otel_metadata == FLB_TRUE &&
        flb_opentelemetry_logs_chunk_is_otlp(event_chunk_data,
                                             event_chunk_size) != FLB_TRUE) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_LOG_EVENT, EINVAL);
        return NULL;
    }

    ret = flb_log_event_decoder_init(&decoder,
                                     (char *) event_chunk_data,
                                     event_chunk_size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);

    doc = flb_json_mut_doc_create();
    root = flb_json_mut_obj(doc);
    resource_logs = flb_json_mut_arr(doc);
    resource_states = NULL;
    resource_state_count = 0;
    current_resource = NULL;
    current_scope = NULL;
    json = NULL;

    if (doc == NULL || root == NULL || resource_logs == NULL ||
        !flb_json_mut_obj_add_val(doc, root, "resourceLogs", resource_logs)) {
        flb_log_event_decoder_destroy(&decoder);
        destroy_logs_resource_states(resource_states, resource_state_count);
        if (doc != NULL) {
            flb_json_mut_doc_destroy(doc);
        }
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    flb_json_mut_doc_set_root(doc, root);

    while ((ret = flb_log_event_decoder_next(&decoder, &event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_decoder_get_record_type(&event, &record_type);
        if (ret != 0) {
            flb_log_event_decoder_destroy(&decoder);
            destroy_logs_resource_states(resource_states, resource_state_count);
            flb_json_mut_doc_destroy(doc);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_LOG_EVENT, EINVAL);
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
                    destroy_logs_resource_states(resource_states, resource_state_count);
                    flb_json_mut_doc_destroy(doc);
                    set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_LOG_EVENT, EINVAL);
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

            current_resource = find_logs_resource_state(resource_states,
                                                        resource_state_count,
                                                        resource_id);
            if (current_resource == NULL) {
                current_resource = append_logs_resource_state(doc,
                                                              resource_logs,
                                                              &resource_states,
                                                              &resource_state_count,
                                                              resource_id,
                                                              resource_object,
                                                              group_body);
                if (current_resource == NULL) {
                    flb_log_event_decoder_destroy(&decoder);
                    destroy_logs_resource_states(resource_states, resource_state_count);
                    flb_json_mut_doc_destroy(doc);
                    set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
                    return NULL;
                }
            }

            current_scope = find_logs_scope_state(current_resource, scope_id);
            if (current_scope == NULL) {
                current_scope = append_logs_scope_state(doc,
                                                        current_resource,
                                                        scope_id,
                                                        scope_object);
                if (current_scope == NULL) {
                    flb_log_event_decoder_destroy(&decoder);
                    destroy_logs_resource_states(resource_states, resource_state_count);
                    flb_json_mut_doc_destroy(doc);
                    set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
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
                destroy_logs_resource_states(resource_states, resource_state_count);
                flb_json_mut_doc_destroy(doc);
                set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_LOG_EVENT, EINVAL);
                return NULL;
            }

            if (ensure_default_logs_scope_state(doc,
                                                resource_logs,
                                                &resource_states,
                                                &resource_state_count,
                                                &current_resource,
                                                &current_scope) != 0) {
                flb_log_event_decoder_destroy(&decoder);
                destroy_logs_resource_states(resource_states, resource_state_count);
                flb_json_mut_doc_destroy(doc);
                set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
                return NULL;
            }
        }

        record = log_record_to_json(doc,
                                    &event,
                                    logs_body_keys,
                                    logs_body_key_count,
                                    logs_body_key_attributes);
        if (record == NULL ||
            !flb_json_mut_arr_add_val(current_scope->log_records, record)) {
            flb_log_event_decoder_destroy(&decoder);
            destroy_logs_resource_states(resource_states, resource_state_count);
            flb_json_mut_doc_destroy(doc);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }
    }

    flb_log_event_decoder_destroy(&decoder);
    destroy_logs_resource_states(resource_states, resource_state_count);

    if (ret != FLB_EVENT_DECODER_SUCCESS &&
        ret != FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA) {
        flb_json_mut_doc_destroy(doc);
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_LOG_EVENT, EINVAL);
        return NULL;
    }

    json = otlp_doc_to_sds(doc, pretty);
    flb_json_mut_doc_destroy(doc);

    if (json == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    set_result(result, FLB_OPENTELEMETRY_OTLP_JSON_SUCCESS);

    return json;
}

flb_sds_t flb_opentelemetry_logs_to_otlp_json(const void *event_chunk_data,
                                              size_t event_chunk_size,
                                              struct flb_opentelemetry_otlp_json_options *options,
                                              int *result)
{
    return flb_opentelemetry_logs_to_otlp_json_render(event_chunk_data,
                                                      event_chunk_size,
                                                      options,
                                                      FLB_FALSE,
                                                      result);
}

flb_sds_t flb_opentelemetry_logs_to_otlp_json_pretty(const void *event_chunk_data,
                                                     size_t event_chunk_size,
                                                     struct flb_opentelemetry_otlp_json_options *options,
                                                     int *result)
{
    return flb_opentelemetry_logs_to_otlp_json_render(event_chunk_data,
                                                      event_chunk_size,
                                                      options,
                                                      FLB_TRUE,
                                                      result);
}

static struct cfl_kvlist *fetch_metadata_kvlist_key(struct cfl_kvlist *kvlist,
                                                    const char *key)
{
    struct cfl_variant *entry;

    if (kvlist == NULL) {
        return NULL;
    }

    entry = cfl_kvlist_fetch(kvlist, (char *) key);
    if (entry == NULL || entry->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    return entry->data.as_kvlist;
}

static struct cfl_array *fetch_metadata_array_key(struct cfl_kvlist *kvlist,
                                                  const char *key)
{
    struct cfl_variant *entry;

    if (kvlist == NULL) {
        return NULL;
    }

    entry = cfl_kvlist_fetch(kvlist, (char *) key);
    if (entry == NULL || entry->type != CFL_VARIANT_ARRAY) {
        return NULL;
    }

    return entry->data.as_array;
}

static struct cfl_kvlist *fetch_array_kvlist_entry(struct cfl_array *array,
                                                   size_t index)
{
    struct cfl_variant *entry;

    if (array == NULL || index >= array->entry_count) {
        return NULL;
    }

    entry = cfl_array_fetch_by_index(array, index);
    if (entry == NULL || entry->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    return entry->data.as_kvlist;
}

static int kvlist_fetch_uint64(struct cfl_kvlist *kvlist,
                               const char *key,
                               uint64_t *output)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(kvlist, (char *) key);
    if (value == NULL) {
        return -1;
    }

    if (value->type == CFL_VARIANT_UINT) {
        *output = value->data.as_uint64;
        return 0;
    }

    if (value->type == CFL_VARIANT_INT && value->data.as_int64 >= 0) {
        *output = (uint64_t) value->data.as_int64;
        return 0;
    }

    return -1;
}

static int kvlist_fetch_int64(struct cfl_kvlist *kvlist,
                              const char *key,
                              int64_t *output)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(kvlist, (char *) key);
    if (value == NULL) {
        return -1;
    }

    if (value->type == CFL_VARIANT_INT) {
        *output = value->data.as_int64;
        return 0;
    }

    if (value->type == CFL_VARIANT_UINT && value->data.as_uint64 <= INT64_MAX) {
        *output = (int64_t) value->data.as_uint64;
        return 0;
    }

    return -1;
}

static int kvlist_fetch_double(struct cfl_kvlist *kvlist,
                               const char *key,
                               double *output)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(kvlist, (char *) key);
    if (value == NULL) {
        return -1;
    }

    if (value->type == CFL_VARIANT_DOUBLE) {
        *output = value->data.as_double;
        return 0;
    }
    if (value->type == CFL_VARIANT_UINT) {
        *output = (double) value->data.as_uint64;
        return 0;
    }
    if (value->type == CFL_VARIANT_INT) {
        *output = (double) value->data.as_int64;
        return 0;
    }

    return -1;
}

static int kvlist_fetch_bool(struct cfl_kvlist *kvlist,
                             const char *key,
                             int *output)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(kvlist, (char *) key);
    if (value == NULL) {
        return -1;
    }

    if (value->type == CFL_VARIANT_BOOL) {
        *output = value->data.as_bool ? CMT_TRUE : CMT_FALSE;
        return 0;
    }
    if (value->type == CFL_VARIANT_UINT) {
        *output = value->data.as_uint64 != 0 ? CMT_TRUE : CMT_FALSE;
        return 0;
    }
    if (value->type == CFL_VARIANT_INT) {
        *output = value->data.as_int64 != 0 ? CMT_TRUE : CMT_FALSE;
        return 0;
    }

    return -1;
}

static char *kvlist_fetch_string(struct cfl_kvlist *kvlist, const char *key)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(kvlist, (char *) key);
    if (value == NULL || value->type != CFL_VARIANT_STRING) {
        return NULL;
    }

    return value->data.as_string;
}

static char *metrics_map_type_to_key(int type)
{
    switch (type) {
    case CMT_COUNTER:
        return "counter";
    case CMT_GAUGE:
        return "gauge";
    case CMT_UNTYPED:
        return "untyped";
    case CMT_SUMMARY:
        return "summary";
    case CMT_HISTOGRAM:
        return "histogram";
    case CMT_EXP_HISTOGRAM:
        return "exp_histogram";
    default:
        return "unknown";
    }
}

static struct cfl_kvlist *get_metric_otlp_metadata_context(struct cmt *cmt,
                                                           struct cmt_map *map)
{
    struct cfl_kvlist *otlp_root;
    struct cfl_kvlist *metrics_root;
    struct cfl_kvlist *type_root;

    if (cmt == NULL || map == NULL || map->opts == NULL || map->opts->fqname == NULL) {
        return NULL;
    }

    otlp_root = fetch_metadata_kvlist_key(cmt->external_metadata, "otlp");
    metrics_root = fetch_metadata_kvlist_key(otlp_root, "metrics");
    type_root = fetch_metadata_kvlist_key(metrics_root, metrics_map_type_to_key(map->type));

    if (type_root == NULL) {
        return NULL;
    }

    return fetch_metadata_kvlist_key(type_root, map->opts->fqname);
}

static struct cfl_kvlist *get_data_point_otlp_metadata_context(struct cmt *cmt,
                                                               struct cmt_map *map,
                                                               struct cmt_metric *sample)
{
    char               key[128];
    struct cfl_kvlist *metric_context;
    struct cfl_kvlist *datapoints_context;

    metric_context = get_metric_otlp_metadata_context(cmt, map);
    datapoints_context = fetch_metadata_kvlist_key(metric_context, "datapoints");

    if (datapoints_context == NULL) {
        return NULL;
    }

    snprintf(key, sizeof(key) - 1, "%" PRIx64 ":%" PRIu64,
             sample != NULL ? sample->hash : 0,
             sample != NULL ? cmt_metric_get_timestamp(sample) : 0);

    return fetch_metadata_kvlist_key(datapoints_context, key);
}

static int compute_flat_scope_index(size_t *scope_counts,
                                    size_t resource_count,
                                    size_t resource_index,
                                    size_t scope_index)
{
    size_t index;
    size_t offset;

    offset = 0;

    for (index = 0; index < resource_index && index < resource_count; index++) {
        offset += scope_counts[index];
    }

    return (int) (offset + scope_index);
}

static size_t resolve_target_scope_index(struct cmt *cmt,
                                         struct cmt_map *map,
                                         size_t *scope_counts,
                                         size_t resource_count,
                                         size_t total_scope_count)
{
    uint64_t           flat_scope_index;
    uint64_t           resource_index;
    uint64_t           scope_index;
    struct cfl_kvlist *metadata;
    struct cfl_kvlist *metric_context;

    metric_context = get_metric_otlp_metadata_context(cmt, map);
    metadata = fetch_metadata_kvlist_key(metric_context, "metadata");

    if (metadata == NULL) {
        return 0;
    }

    if (kvlist_fetch_uint64(metadata, "scope_flat_index", &flat_scope_index) == 0 &&
        flat_scope_index < total_scope_count) {
        return (size_t) flat_scope_index;
    }

    if (kvlist_fetch_uint64(metadata, "resource_index", &resource_index) != 0 ||
        kvlist_fetch_uint64(metadata, "scope_index", &scope_index) != 0) {
        return 0;
    }

    return (size_t) compute_flat_scope_index(scope_counts,
                                             resource_count,
                                             (size_t) resource_index,
                                             (size_t) scope_index);
}

static struct flb_json_mut_val *create_otlp_attributes_from_kvlist(struct flb_json_mut_doc *doc,
                                                          struct cfl_kvlist *kvlist)
{
    if (kvlist == NULL) {
        return flb_json_mut_arr(doc);
    }

    return cfl_kvlist_to_otlp_kv_array(doc, kvlist);
}

static struct flb_json_mut_val *create_metrics_resource_json(struct flb_json_mut_doc *doc,
                                                    struct cfl_kvlist *resource_root)
{
    struct cfl_kvlist *attributes;
    struct cfl_kvlist *metadata;
    struct flb_json_mut_val    *resource;
    struct flb_json_mut_val    *attribute_array;
    int64_t            dropped;

    resource = flb_json_mut_obj(doc);
    if (resource == NULL) {
        return NULL;
    }

    if (resource_root == NULL) {
        return resource;
    }

    attributes = fetch_metadata_kvlist_key(resource_root, "attributes");
    metadata = fetch_metadata_kvlist_key(resource_root, "metadata");

    if (attributes != NULL && cfl_kvlist_count(attributes) > 0) {
        attribute_array = create_otlp_attributes_from_kvlist(doc, attributes);
        if (attribute_array == NULL ||
            !flb_json_mut_obj_add_val(doc, resource, "attributes", attribute_array)) {
            return NULL;
        }
    }

    if (metadata != NULL &&
        kvlist_fetch_int64(metadata, "dropped_attributes_count", &dropped) == 0 &&
        dropped >= 0) {
        if (!flb_json_mut_obj_add_uint(doc, resource, "droppedAttributesCount",
                                     (uint64_t) dropped)) {
            return NULL;
        }
    }

    return resource;
}

static struct flb_json_mut_val *create_metrics_scope_json(struct flb_json_mut_doc *doc,
                                                 struct cfl_kvlist *scope_root)
{
    struct cfl_kvlist *attributes;
    struct cfl_kvlist *metadata;
    struct flb_json_mut_val    *scope;
    struct flb_json_mut_val    *attribute_array;
    char              *string;
    int64_t            dropped;

    scope = flb_json_mut_obj(doc);
    if (scope == NULL) {
        return NULL;
    }

    if (scope_root == NULL) {
        return scope;
    }

    attributes = fetch_metadata_kvlist_key(scope_root, "attributes");
    metadata = fetch_metadata_kvlist_key(scope_root, "metadata");

    if (attributes != NULL && cfl_kvlist_count(attributes) > 0) {
        attribute_array = create_otlp_attributes_from_kvlist(doc, attributes);
        if (attribute_array == NULL ||
            !flb_json_mut_obj_add_val(doc, scope, "attributes", attribute_array)) {
            return NULL;
        }
    }

    if (metadata != NULL) {
        string = kvlist_fetch_string(metadata, "name");
        if (string != NULL &&
            !flb_json_mut_obj_add_strn(doc, scope, "name", string, cfl_sds_len(string))) {
            return NULL;
        }

        string = kvlist_fetch_string(metadata, "version");
        if (string != NULL &&
            !flb_json_mut_obj_add_strn(doc, scope, "version", string, cfl_sds_len(string))) {
            return NULL;
        }

        if (kvlist_fetch_int64(metadata, "dropped_attributes_count", &dropped) == 0 &&
            dropped >= 0 &&
            !flb_json_mut_obj_add_uint(doc, scope, "droppedAttributesCount",
                                     (uint64_t) dropped)) {
            return NULL;
        }
    }

    return scope;
}

static int add_metric_metadata_json(struct flb_json_mut_doc *doc,
                                    struct flb_json_mut_val *metric,
                                    struct cmt *cmt,
                                    struct cmt_map *map)
{
    struct cfl_kvlist *context;
    struct cfl_kvlist *metadata;
    struct flb_json_mut_val    *entries;

    context = get_metric_otlp_metadata_context(cmt, map);
    metadata = fetch_metadata_kvlist_key(context, "metadata");

    if (metadata == NULL || cfl_kvlist_count(metadata) == 0) {
        return 0;
    }

    entries = cfl_kvlist_to_otlp_kv_array(doc, metadata);
    if (entries == NULL) {
        return -1;
    }

    return flb_json_mut_obj_add_val(doc, metric, "metadata", entries) ? 0 : -1;
}

static struct flb_json_mut_val *create_exemplar_json(struct flb_json_mut_doc *doc,
                                            struct cfl_kvlist *kvlist)
{
    char              hex_buffer[33];
    flb_sds_t         encoded;
    struct cfl_kvlist *filtered_attributes;
    struct cfl_variant *variant;
    struct flb_json_mut_val    *attributes;
    struct flb_json_mut_val    *exemplar;
    int64_t            sint;
    uint64_t           uint_value;
    double             double_value;

    exemplar = flb_json_mut_obj(doc);
    if (exemplar == NULL) {
        return NULL;
    }

    if (kvlist_fetch_uint64(kvlist, "time_unix_nano", &uint_value) == 0 &&
        json_add_uint64_string(doc, exemplar, "timeUnixNano", uint_value) != 0) {
        return NULL;
    }

    variant = cfl_kvlist_fetch(kvlist, "span_id");
    if (variant != NULL && variant->type == CFL_VARIANT_BYTES) {
        if (cfl_sds_len(variant->data.as_bytes) == 8 &&
            binary_to_hex(hex_buffer, sizeof(hex_buffer),
                          variant->data.as_bytes,
                          cfl_sds_len(variant->data.as_bytes)) == 0) {
            if (!flb_json_mut_obj_add_strcpy(doc, exemplar, "spanId", hex_buffer)) {
                return NULL;
            }
        }
        else {
            if (binary_to_base64_sds(variant->data.as_bytes,
                                     cfl_sds_len(variant->data.as_bytes),
                                     &encoded) != 0) {
                return NULL;
            }
            if (!flb_json_mut_obj_add_strn(doc, exemplar, "spanId",
                                         encoded, flb_sds_len(encoded))) {
                flb_sds_destroy(encoded);
                return NULL;
            }
            flb_sds_destroy(encoded);
        }
    }

    variant = cfl_kvlist_fetch(kvlist, "trace_id");
    if (variant != NULL && variant->type == CFL_VARIANT_BYTES) {
        if (cfl_sds_len(variant->data.as_bytes) == 16 &&
            binary_to_hex(hex_buffer, sizeof(hex_buffer),
                          variant->data.as_bytes,
                          cfl_sds_len(variant->data.as_bytes)) == 0) {
            if (!flb_json_mut_obj_add_strcpy(doc, exemplar, "traceId", hex_buffer)) {
                return NULL;
            }
        }
        else {
            if (binary_to_base64_sds(variant->data.as_bytes,
                                     cfl_sds_len(variant->data.as_bytes),
                                     &encoded) != 0) {
                return NULL;
            }
            if (!flb_json_mut_obj_add_strn(doc, exemplar, "traceId",
                                         encoded, flb_sds_len(encoded))) {
                flb_sds_destroy(encoded);
                return NULL;
            }
            flb_sds_destroy(encoded);
        }
    }

    if (kvlist_fetch_double(kvlist, "as_double", &double_value) == 0) {
        if (!flb_json_mut_obj_add_real(doc, exemplar, "asDouble", double_value)) {
            return NULL;
        }
    }
    else if (kvlist_fetch_int64(kvlist, "as_int", &sint) == 0) {
        if (json_add_int64_string(doc, exemplar, "asInt", sint) != 0) {
            return NULL;
        }
    }
    else if (kvlist_fetch_uint64(kvlist, "as_int", &uint_value) == 0) {
        if (json_add_uint64_string(doc, exemplar, "asInt", uint_value) != 0) {
            return NULL;
        }
    }

    filtered_attributes = fetch_metadata_kvlist_key(kvlist, "filtered_attributes");
    if (filtered_attributes != NULL && cfl_kvlist_count(filtered_attributes) > 0) {
        attributes = cfl_kvlist_to_otlp_kv_array(doc, filtered_attributes);
        if (attributes == NULL ||
            !flb_json_mut_obj_add_val(doc, exemplar, "filteredAttributes", attributes)) {
            return NULL;
        }
    }

    return exemplar;
}

static int add_data_point_common_fields(struct flb_json_mut_doc *doc,
                                        struct flb_json_mut_val *point,
                                        struct cmt *cmt,
                                        struct cmt_map *map,
                                        struct cmt_metric *sample)
{
    int               label_index;
    int               bool_value;
    uint64_t          uint_value;
    struct cfl_list  *head;
    struct cmt_label *static_label;
    struct cmt_map_label *label_name;
    struct cmt_map_label *label_value;
    struct cfl_kvlist *metadata;
    struct cfl_variant *variant;
    struct cfl_array *array;
    struct flb_json_mut_val   *attributes;
    struct flb_json_mut_val   *attribute;
    struct flb_json_mut_val   *value;
    struct flb_json_mut_val   *exemplars;

    attributes = flb_json_mut_arr(doc);
    if (attributes == NULL) {
        return -1;
    }

    cfl_list_foreach(head, &cmt->static_labels->list) {
        static_label = cfl_list_entry(head, struct cmt_label, _head);
        attribute = flb_json_mut_obj(doc);
        value = flb_json_mut_obj(doc);

        if (attribute == NULL || value == NULL ||
            !flb_json_mut_obj_add_strn(doc, attribute, "key",
                                     static_label->key,
                                     cfl_sds_len(static_label->key)) ||
            !flb_json_mut_obj_add_strn(doc, value, "stringValue",
                                     static_label->val,
                                     cfl_sds_len(static_label->val)) ||
            !flb_json_mut_obj_add_val(doc, attribute, "value", value) ||
            !flb_json_mut_arr_add_val(attributes, attribute)) {
            return -1;
        }
    }

    label_index = 0;
    label_name = cfl_list_entry_first(&map->label_keys, struct cmt_map_label, _head);
    cfl_list_foreach(head, &sample->labels) {
        label_value = cfl_list_entry(head, struct cmt_map_label, _head);
        attribute = flb_json_mut_obj(doc);
        value = flb_json_mut_obj(doc);

        (void) label_index;

        if (attribute == NULL || value == NULL ||
            !flb_json_mut_obj_add_strn(doc, attribute, "key",
                                     label_name->name,
                                     cfl_sds_len(label_name->name)) ||
            !flb_json_mut_obj_add_strn(doc, value, "stringValue",
                                     label_value->name,
                                     cfl_sds_len(label_value->name)) ||
            !flb_json_mut_obj_add_val(doc, attribute, "value", value) ||
            !flb_json_mut_arr_add_val(attributes, attribute)) {
            return -1;
        }

        label_name = cfl_list_entry_next(&label_name->_head,
                                         struct cmt_map_label,
                                         _head,
                                         &map->label_keys);
    }

    if (flb_json_mut_arr_size(attributes) > 0 &&
        !flb_json_mut_obj_add_val(doc, point, "attributes", attributes)) {
        return -1;
    }

    if (cmt_metric_get_timestamp(sample) > 0 &&
        json_add_uint64_string(doc, point, "timeUnixNano",
                               cmt_metric_get_timestamp(sample)) != 0) {
        return -1;
    }

    metadata = get_data_point_otlp_metadata_context(cmt, map, sample);

    if (cmt_metric_has_start_timestamp(sample)) {
        if (json_add_uint64_string(doc, point, "startTimeUnixNano",
                                   cmt_metric_get_start_timestamp(sample)) != 0) {
            return -1;
        }
    }
    else if (metadata != NULL &&
             kvlist_fetch_uint64(metadata, "start_time_unix_nano", &uint_value) == 0 &&
             json_add_uint64_string(doc, point, "startTimeUnixNano", uint_value) != 0) {
        return -1;
    }

    if (metadata != NULL &&
        kvlist_fetch_uint64(metadata, "flags", &uint_value) == 0 &&
        !flb_json_mut_obj_add_uint(doc, point, "flags", uint_value)) {
        return -1;
    }

    variant = metadata != NULL ? cfl_kvlist_fetch(metadata, "exemplars") : NULL;
    if (variant != NULL && variant->type == CFL_VARIANT_ARRAY) {
        array = variant->data.as_array;
        exemplars = flb_json_mut_arr(doc);
        if (exemplars == NULL) {
            return -1;
        }

        for (label_index = 0; label_index < (int) array->entry_count; label_index++) {
            variant = cfl_array_fetch_by_index(array, label_index);
            if (variant == NULL || variant->type != CFL_VARIANT_KVLIST) {
                return -1;
            }

            attribute = create_exemplar_json(doc, variant->data.as_kvlist);
            if (attribute == NULL || !flb_json_mut_arr_add_val(exemplars, attribute)) {
                return -1;
            }
        }

        if (flb_json_mut_arr_size(exemplars) > 0 &&
            !flb_json_mut_obj_add_val(doc, point, "exemplars", exemplars)) {
            return -1;
        }
    }

    if (metadata != NULL &&
        kvlist_fetch_bool(metadata, "has_sum", &bool_value) == 0 &&
        bool_value == CMT_FALSE) {
        if (!flb_json_mut_obj_add_bool(doc, point, "hasSum", false)) {
            return -1;
        }
    }

    return 0;
}

static int add_min_max_fields(struct flb_json_mut_doc *doc,
                              struct flb_json_mut_val *point,
                              struct cfl_kvlist *metadata)
{
    int    bool_value;
    double double_value;

    if (metadata == NULL) {
        return 0;
    }

    if (kvlist_fetch_bool(metadata, "has_min", &bool_value) == 0 &&
        bool_value == CMT_TRUE &&
        kvlist_fetch_double(metadata, "min", &double_value) == 0 &&
        !flb_json_mut_obj_add_real(doc, point, "min", double_value)) {
        return -1;
    }

    if (kvlist_fetch_bool(metadata, "has_max", &bool_value) == 0 &&
        bool_value == CMT_TRUE &&
        kvlist_fetch_double(metadata, "max", &double_value) == 0 &&
        !flb_json_mut_obj_add_real(doc, point, "max", double_value)) {
        return -1;
    }

    return 0;
}

static struct flb_json_mut_val *create_number_data_point_json(struct flb_json_mut_doc *doc,
                                                     struct cmt *cmt,
                                                     struct cmt_map *map,
                                                     struct cmt_metric *sample)
{
    int               value_type;
    int64_t           int64_value;
    uint64_t          uint64_value;
    char             *string;
    struct cfl_kvlist *metadata;
    struct flb_json_mut_val   *point;

    point = flb_json_mut_obj(doc);
    if (point == NULL || add_data_point_common_fields(doc, point, cmt, map, sample) != 0) {
        return NULL;
    }

    metadata = get_data_point_otlp_metadata_context(cmt, map, sample);
    value_type = cmt_metric_get_value_type(sample);

    if (value_type == CMT_METRIC_VALUE_INT64) {
        int64_value = cmt_metric_get_int64_value(sample);
        if (json_add_int64_string(doc, point, "asInt", int64_value) != 0) {
            return NULL;
        }
    }
    else if (value_type == CMT_METRIC_VALUE_UINT64) {
        uint64_value = cmt_metric_get_uint64_value(sample);
        if (json_add_uint64_string(doc, point, "asInt", uint64_value) != 0) {
            return NULL;
        }
    }
    else {
        string = metadata != NULL ? kvlist_fetch_string(metadata, "number_value_case") : NULL;
        if (string != NULL && strcmp(string, "int") == 0) {
            int64_value = cmt_metric_get_int64_value(sample);
            if (json_add_int64_string(doc, point, "asInt", int64_value) != 0) {
                return NULL;
            }
        }
        else {
            if (!flb_json_mut_obj_add_real(doc, point, "asDouble",
                                         cmt_metric_get_value(sample))) {
                return NULL;
            }
        }
    }

    return point;
}

static struct flb_json_mut_val *create_summary_data_point_json(struct flb_json_mut_doc *doc,
                                                      struct cmt *cmt,
                                                      struct cmt_map *map,
                                                      struct cmt_metric *sample,
                                                      struct cmt_summary *summary)
{
    size_t          index;
    struct flb_json_mut_val *point;
    struct flb_json_mut_val *quantile_values;
    struct flb_json_mut_val *entry;

    point = flb_json_mut_obj(doc);
    if (point == NULL || add_data_point_common_fields(doc, point, cmt, map, sample) != 0) {
        return NULL;
    }

    if (json_add_uint64_string(doc, point, "count",
                               cmt_summary_get_count_value(sample)) != 0 ||
        !flb_json_mut_obj_add_real(doc, point, "sum",
                                 cmt_summary_get_sum_value(sample))) {
        return NULL;
    }

    quantile_values = flb_json_mut_arr(doc);
    if (quantile_values == NULL) {
        return NULL;
    }

    for (index = 0; index < summary->quantiles_count; index++) {
        entry = flb_json_mut_obj(doc);
        if (entry == NULL ||
            !flb_json_mut_obj_add_real(doc, entry, "quantile", summary->quantiles[index]) ||
            !flb_json_mut_obj_add_real(doc, entry, "value",
                                     cmt_summary_quantile_get_value(sample, index)) ||
            !flb_json_mut_arr_add_val(quantile_values, entry)) {
            return NULL;
        }
    }

    if (flb_json_mut_arr_size(quantile_values) > 0 &&
        !flb_json_mut_obj_add_val(doc, point, "quantileValues", quantile_values)) {
        return NULL;
    }

    return point;
}

static struct flb_json_mut_val *create_histogram_data_point_json(struct flb_json_mut_doc *doc,
                                                        struct cmt *cmt,
                                                        struct cmt_map *map,
                                                        struct cmt_metric *sample,
                                                        struct cmt_histogram *histogram)
{
    size_t            index;
    int               bool_value;
    struct cfl_kvlist *metadata;
    struct flb_json_mut_val   *bucket_counts;
    struct flb_json_mut_val   *explicit_bounds;
    struct flb_json_mut_val   *point;

    point = flb_json_mut_obj(doc);
    if (point == NULL || add_data_point_common_fields(doc, point, cmt, map, sample) != 0) {
        return NULL;
    }

    metadata = get_data_point_otlp_metadata_context(cmt, map, sample);

    if (json_add_uint64_string(doc, point, "count",
                               cmt_metric_hist_get_count_value(sample)) != 0) {
        return NULL;
    }

    if (!(metadata != NULL &&
          kvlist_fetch_bool(metadata, "has_sum", &bool_value) == 0 &&
          bool_value == CMT_FALSE)) {
        if (!flb_json_mut_obj_add_real(doc, point, "sum",
                                     cmt_metric_hist_get_sum_value(sample))) {
            return NULL;
        }
    }

    if (add_min_max_fields(doc, point, metadata) != 0) {
        return NULL;
    }

    bucket_counts = flb_json_mut_arr(doc);
    explicit_bounds = flb_json_mut_arr(doc);
    if (bucket_counts == NULL || explicit_bounds == NULL) {
        return NULL;
    }

    for (index = 0; index < histogram->buckets->count + 1; index++) {
        char buffer[32];
        int  length;

        length = snprintf(buffer, sizeof(buffer), "%" PRIu64,
                          sample->hist_buckets[index]);
        if (length <= 0 || (size_t) length >= sizeof(buffer) ||
            !flb_json_mut_arr_add_strncpy(doc, bucket_counts, buffer, length)) {
            return NULL;
        }
    }

    for (index = 0; index < histogram->buckets->count; index++) {
        if (!flb_json_mut_arr_add_real(doc, explicit_bounds,
                                     histogram->buckets->upper_bounds[index])) {
            return NULL;
        }
    }

    return (flb_json_mut_obj_add_val(doc, point, "bucketCounts", bucket_counts) &&
            flb_json_mut_obj_add_val(doc, point, "explicitBounds", explicit_bounds)) ?
           point : NULL;
}

static struct flb_json_mut_val *create_exp_histogram_data_point_json(
    struct flb_json_mut_doc *doc,
    struct cmt *cmt,
    struct cmt_map *map,
    struct cmt_metric *sample)
{
    size_t                           index;
    int                              bool_value;
    struct cfl_kvlist               *metadata;
    struct cmt_exp_histogram_snapshot snapshot;
    struct flb_json_mut_val                  *negative;
    struct flb_json_mut_val                  *point;
    struct flb_json_mut_val                  *positive;
    struct flb_json_mut_val                  *bucket_counts;

    if (cmt_metric_exp_hist_get_snapshot(sample, &snapshot) != 0) {
        return NULL;
    }

    point = flb_json_mut_obj(doc);
    if (point == NULL || add_data_point_common_fields(doc, point, cmt, map, sample) != 0) {
        cmt_metric_exp_hist_snapshot_destroy(&snapshot);
        return NULL;
    }

    metadata = get_data_point_otlp_metadata_context(cmt, map, sample);

    if (json_add_uint64_string(doc, point, "count", snapshot.count) != 0 ||
        !flb_json_mut_obj_add_int(doc, point, "scale", snapshot.scale) ||
        json_add_uint64_string(doc, point, "zeroCount", snapshot.zero_count) != 0 ||
        !flb_json_mut_obj_add_real(doc, point, "zeroThreshold", snapshot.zero_threshold)) {
        cmt_metric_exp_hist_snapshot_destroy(&snapshot);
        return NULL;
    }

    if (!(metadata != NULL &&
          kvlist_fetch_bool(metadata, "has_sum", &bool_value) == 0 &&
          bool_value == CMT_FALSE)) {
        if (snapshot.sum_set &&
            !flb_json_mut_obj_add_real(doc, point, "sum",
                                     cmt_math_uint64_to_d64(snapshot.sum))) {
            cmt_metric_exp_hist_snapshot_destroy(&snapshot);
            return NULL;
        }
    }

    if (add_min_max_fields(doc, point, metadata) != 0) {
        cmt_metric_exp_hist_snapshot_destroy(&snapshot);
        return NULL;
    }

    if (snapshot.positive_count > 0) {
        positive = flb_json_mut_obj(doc);
        bucket_counts = flb_json_mut_arr(doc);
        if (positive == NULL || bucket_counts == NULL ||
            !flb_json_mut_obj_add_int(doc, positive, "offset", snapshot.positive_offset)) {
            cmt_metric_exp_hist_snapshot_destroy(&snapshot);
            return NULL;
        }

        for (index = 0; index < snapshot.positive_count; index++) {
            char buffer[32];
            int  length;

            length = snprintf(buffer, sizeof(buffer), "%" PRIu64,
                              snapshot.positive_buckets[index]);
            if (length <= 0 || (size_t) length >= sizeof(buffer) ||
                !flb_json_mut_arr_add_strncpy(doc, bucket_counts, buffer, length)) {
                cmt_metric_exp_hist_snapshot_destroy(&snapshot);
                return NULL;
            }
        }

        if (!flb_json_mut_obj_add_val(doc, positive, "bucketCounts", bucket_counts) ||
            !flb_json_mut_obj_add_val(doc, point, "positive", positive)) {
            cmt_metric_exp_hist_snapshot_destroy(&snapshot);
            return NULL;
        }
    }

    if (snapshot.negative_count > 0) {
        negative = flb_json_mut_obj(doc);
        bucket_counts = flb_json_mut_arr(doc);
        if (negative == NULL || bucket_counts == NULL ||
            !flb_json_mut_obj_add_int(doc, negative, "offset", snapshot.negative_offset)) {
            cmt_metric_exp_hist_snapshot_destroy(&snapshot);
            return NULL;
        }

        for (index = 0; index < snapshot.negative_count; index++) {
            char buffer[32];
            int  length;

            length = snprintf(buffer, sizeof(buffer), "%" PRIu64,
                              snapshot.negative_buckets[index]);
            if (length <= 0 || (size_t) length >= sizeof(buffer) ||
                !flb_json_mut_arr_add_strncpy(doc, bucket_counts, buffer, length)) {
                cmt_metric_exp_hist_snapshot_destroy(&snapshot);
                return NULL;
            }
        }

        if (!flb_json_mut_obj_add_val(doc, negative, "bucketCounts", bucket_counts) ||
            !flb_json_mut_obj_add_val(doc, point, "negative", negative)) {
            cmt_metric_exp_hist_snapshot_destroy(&snapshot);
            return NULL;
        }
    }

    cmt_metric_exp_hist_snapshot_destroy(&snapshot);

    return point;
}

static struct flb_json_mut_val *create_metric_json(struct flb_json_mut_doc *doc,
                                          struct cmt *cmt,
                                          struct cmt_map *map)
{
    size_t            sample_count;
    int               temporality;
    int               monotonism;
    struct cfl_list  *head;
    struct cmt_metric *sample;
    struct cmt_counter *counter;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary *summary;
    struct flb_json_mut_val   *container;
    struct flb_json_mut_val   *metric;
    struct flb_json_mut_val   *points;
    struct flb_json_mut_val   *point;

    sample_count = (map->metric_static_set ? 1 : 0) + cfl_list_size(&map->metrics);
    if (sample_count == 0) {
        return NULL;
    }

    metric = flb_json_mut_obj(doc);
    if (metric == NULL ||
        !flb_json_mut_obj_add_strn(doc, metric, "name",
                                 map->opts->fqname,
                                 cfl_sds_len(map->opts->fqname))) {
        return NULL;
    }

    if (map->opts->description != NULL &&
        !flb_json_mut_obj_add_str(doc, metric, "description",
                                map->opts->description)) {
        return NULL;
    }

    if (map->unit != NULL &&
        !flb_json_mut_obj_add_strn(doc, metric, "unit",
                                 map->unit, cfl_sds_len(map->unit))) {
        return NULL;
    }

    if (add_metric_metadata_json(doc, metric, cmt, map) != 0) {
        return NULL;
    }

    points = flb_json_mut_arr(doc);
    if (points == NULL) {
        return NULL;
    }

    temporality = 0;
    monotonism = CMT_FALSE;

    if (map->type == CMT_COUNTER) {
        counter = (struct cmt_counter *) map->parent;
        if (counter != NULL) {
            temporality = counter->aggregation_type;
            monotonism = !counter->allow_reset;
        }

        container = flb_json_mut_obj(doc);
        if (container == NULL ||
            !flb_json_mut_obj_add_val(doc, container, "dataPoints", points) ||
            !flb_json_mut_obj_add_uint(doc, container, "aggregationTemporality", temporality) ||
            !flb_json_mut_obj_add_bool(doc, container, "isMonotonic", monotonism) ||
            !flb_json_mut_obj_add_val(doc, metric, "sum", container)) {
            return NULL;
        }
    }
    else if (map->type == CMT_GAUGE || map->type == CMT_UNTYPED) {
        container = flb_json_mut_obj(doc);
        if (container == NULL ||
            !flb_json_mut_obj_add_val(doc, container, "dataPoints", points) ||
            !flb_json_mut_obj_add_val(doc, metric, "gauge", container)) {
            return NULL;
        }
    }
    else if (map->type == CMT_SUMMARY) {
        container = flb_json_mut_obj(doc);
        if (container == NULL ||
            !flb_json_mut_obj_add_val(doc, container, "dataPoints", points) ||
            !flb_json_mut_obj_add_val(doc, metric, "summary", container)) {
            return NULL;
        }
    }
    else if (map->type == CMT_HISTOGRAM) {
        histogram = (struct cmt_histogram *) map->parent;
        if (histogram != NULL) {
            temporality = histogram->aggregation_type;
        }

        container = flb_json_mut_obj(doc);
        if (container == NULL ||
            !flb_json_mut_obj_add_val(doc, container, "dataPoints", points) ||
            !flb_json_mut_obj_add_uint(doc, container, "aggregationTemporality", temporality) ||
            !flb_json_mut_obj_add_val(doc, metric, "histogram", container)) {
            return NULL;
        }
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        exp_histogram = (struct cmt_exp_histogram *) map->parent;
        if (exp_histogram != NULL) {
            temporality = exp_histogram->aggregation_type;
        }

        container = flb_json_mut_obj(doc);
        if (container == NULL ||
            !flb_json_mut_obj_add_val(doc, container, "dataPoints", points) ||
            !flb_json_mut_obj_add_uint(doc, container, "aggregationTemporality", temporality) ||
            !flb_json_mut_obj_add_val(doc, metric, "exponentialHistogram", container)) {
            return NULL;
        }
    }
    else {
        return NULL;
    }

    if (map->metric_static_set) {
        if (map->type == CMT_COUNTER || map->type == CMT_GAUGE || map->type == CMT_UNTYPED) {
            point = create_number_data_point_json(doc, cmt, map, &map->metric);
        }
        else if (map->type == CMT_SUMMARY) {
            summary = (struct cmt_summary *) map->parent;
            point = create_summary_data_point_json(doc, cmt, map, &map->metric, summary);
        }
        else if (map->type == CMT_HISTOGRAM) {
            histogram = (struct cmt_histogram *) map->parent;
            point = create_histogram_data_point_json(doc, cmt, map, &map->metric, histogram);
        }
        else {
            point = create_exp_histogram_data_point_json(doc, cmt, map, &map->metric);
        }

        if (point == NULL || !flb_json_mut_arr_add_val(points, point)) {
            return NULL;
        }
    }

    cfl_list_foreach(head, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);

        if (map->type == CMT_COUNTER || map->type == CMT_GAUGE || map->type == CMT_UNTYPED) {
            point = create_number_data_point_json(doc, cmt, map, sample);
        }
        else if (map->type == CMT_SUMMARY) {
            summary = (struct cmt_summary *) map->parent;
            point = create_summary_data_point_json(doc, cmt, map, sample, summary);
        }
        else if (map->type == CMT_HISTOGRAM) {
            histogram = (struct cmt_histogram *) map->parent;
            point = create_histogram_data_point_json(doc, cmt, map, sample, histogram);
        }
        else {
            point = create_exp_histogram_data_point_json(doc, cmt, map, sample);
        }

        if (point == NULL || !flb_json_mut_arr_add_val(points, point)) {
            return NULL;
        }
    }

    return metric;
}

static flb_sds_t flb_opentelemetry_metrics_to_otlp_json_render(struct cmt *context,
                                                               int pretty,
                                                               int *result)
{
    size_t                     index;
    size_t                     resource_count;
    size_t                     resource_index;
    size_t                     scope_index;
    size_t                     total_scope_count;
    size_t                    *scope_counts;
    struct cfl_array          *resource_metrics_list;
    struct cfl_array          *scope_metrics_list;
    struct cfl_kvlist         *resource_entry;
    struct cfl_kvlist         *resource_metrics_root;
    struct cfl_kvlist         *resource_root;
    struct cfl_kvlist         *scope_entry;
    struct cfl_kvlist         *scope_metrics_root;
    struct cfl_kvlist         *scope_root;
    struct cfl_list           *head;
    struct cmt_counter        *counter;
    struct cmt_exp_histogram  *exp_histogram;
    struct cmt_gauge          *gauge;
    struct cmt_histogram      *histogram;
    struct cmt_summary        *summary;
    struct cmt_untyped        *untyped;
    struct flb_json_mut_doc            *doc;
    struct flb_json_mut_val            *root;
    struct flb_json_mut_val            *resource_metrics;
    struct flb_json_mut_val            *resource_metric;
    struct flb_json_mut_val            *scope_metrics;
    struct flb_json_mut_val            *scope_metric;
    struct flb_json_mut_val            *scope;
    struct flb_json_mut_val            *resource;
    struct flb_json_mut_val            *metric;
    struct flb_json_mut_val           **scope_metric_arrays;
    flb_sds_t                  json;
    char                      *string;

    if (context == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    resource_metrics_list = fetch_metadata_array_key(context->external_metadata,
                                                     "resource_metrics_list");

    resource_count = (resource_metrics_list != NULL &&
                      resource_metrics_list->entry_count > 0) ?
                     resource_metrics_list->entry_count : 1;

    scope_counts = flb_calloc(resource_count, sizeof(size_t));
    if (scope_counts == NULL) {
        flb_errno();
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    total_scope_count = 0;

    for (resource_index = 0; resource_index < resource_count; resource_index++) {
        resource_entry = fetch_array_kvlist_entry(resource_metrics_list, resource_index);
        if (resource_entry != NULL) {
            scope_metrics_list = fetch_metadata_array_key(resource_entry,
                                                          "scope_metrics_list");
        }
        else {
            scope_metrics_list = fetch_metadata_array_key(context->external_metadata,
                                                          "scope_metrics_list");
        }

        scope_counts[resource_index] = (scope_metrics_list != NULL &&
                                        scope_metrics_list->entry_count > 0) ?
                                       scope_metrics_list->entry_count : 1;
        total_scope_count += scope_counts[resource_index];
    }

    doc = flb_json_mut_doc_create();
    root = flb_json_mut_obj(doc);
    resource_metrics = flb_json_mut_arr(doc);
    scope_metric_arrays = flb_calloc(total_scope_count ? total_scope_count : 1,
                                     sizeof(struct flb_json_mut_val *));
    json = NULL;

    if (doc == NULL || root == NULL || resource_metrics == NULL ||
        scope_metric_arrays == NULL ||
        !flb_json_mut_obj_add_val(doc, root, "resourceMetrics", resource_metrics)) {
        if (scope_metric_arrays != NULL) {
            flb_free(scope_metric_arrays);
        }
        flb_free(scope_counts);
        if (doc != NULL) {
            flb_json_mut_doc_destroy(doc);
        }
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    flb_json_mut_doc_set_root(doc, root);

    index = 0;
    for (resource_index = 0; resource_index < resource_count; resource_index++) {
        resource_entry = fetch_array_kvlist_entry(resource_metrics_list, resource_index);
        if (resource_entry != NULL) {
            resource_metrics_root = fetch_metadata_kvlist_key(resource_entry, "resource_metrics");
            resource_root = fetch_metadata_kvlist_key(resource_entry, "resource");
            scope_metrics_list = fetch_metadata_array_key(resource_entry, "scope_metrics_list");
            scope_metrics_root = fetch_metadata_kvlist_key(resource_entry, "scope_metrics");
            scope_root = fetch_metadata_kvlist_key(resource_entry, "scope");
        }
        else {
            resource_metrics_root = fetch_metadata_kvlist_key(context->external_metadata, "resource_metrics");
            resource_root = fetch_metadata_kvlist_key(context->external_metadata, "resource");
            scope_metrics_list = fetch_metadata_array_key(context->external_metadata, "scope_metrics_list");
            scope_metrics_root = fetch_metadata_kvlist_key(context->external_metadata, "scope_metrics");
            scope_root = fetch_metadata_kvlist_key(context->external_metadata, "scope");
        }

        resource_metric = flb_json_mut_obj(doc);
        scope_metrics = flb_json_mut_arr(doc);
        resource = create_metrics_resource_json(doc, resource_root);

        if (resource_metric == NULL || scope_metrics == NULL || resource == NULL ||
            !flb_json_mut_obj_add_val(doc, resource_metric, "resource", resource) ||
            !flb_json_mut_obj_add_val(doc, resource_metric, "scopeMetrics", scope_metrics) ||
            !flb_json_mut_arr_add_val(resource_metrics, resource_metric)) {
            flb_free(scope_metric_arrays);
            flb_free(scope_counts);
            flb_json_mut_doc_destroy(doc);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }

        if (resource_metrics_root != NULL) {
            string = kvlist_fetch_string(fetch_metadata_kvlist_key(resource_metrics_root, "metadata"),
                                         "schema_url");
            if (string != NULL &&
                !flb_json_mut_obj_add_strn(doc, resource_metric, "schemaUrl",
                                         string, cfl_sds_len(string))) {
                flb_free(scope_metric_arrays);
                flb_free(scope_counts);
                flb_json_mut_doc_destroy(doc);
                set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
                return NULL;
            }
        }

        for (scope_index = 0; scope_index < scope_counts[resource_index]; scope_index++) {
            scope_entry = fetch_array_kvlist_entry(scope_metrics_list, scope_index);
            if (scope_entry != NULL) {
                scope_metrics_root = fetch_metadata_kvlist_key(scope_entry, "scope_metrics");
                scope_root = fetch_metadata_kvlist_key(scope_entry, "scope");
            }

            scope_metric = flb_json_mut_obj(doc);
            scope = create_metrics_scope_json(doc, scope_root);
            scope_metric_arrays[index++] = flb_json_mut_arr(doc);

            if (scope_metric == NULL || scope == NULL || scope_metric_arrays[index - 1] == NULL ||
                !flb_json_mut_obj_add_val(doc, scope_metric, "scope", scope) ||
                !flb_json_mut_obj_add_val(doc, scope_metric, "metrics", scope_metric_arrays[index - 1]) ||
                !flb_json_mut_arr_add_val(scope_metrics, scope_metric)) {
                flb_free(scope_metric_arrays);
                flb_free(scope_counts);
                flb_json_mut_doc_destroy(doc);
                set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
                return NULL;
            }

            if (scope_metrics_root != NULL) {
                string = kvlist_fetch_string(fetch_metadata_kvlist_key(scope_metrics_root, "metadata"),
                                             "schema_url");
                if (string != NULL &&
                    !flb_json_mut_obj_add_strn(doc, scope_metric, "schemaUrl",
                                             string, cfl_sds_len(string))) {
                    flb_free(scope_metric_arrays);
                    flb_free(scope_counts);
                    flb_json_mut_doc_destroy(doc);
                    set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
                    return NULL;
                }
            }
        }
    }

    cfl_list_foreach(head, &context->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        metric = create_metric_json(doc, context, counter->map);
        if (metric != NULL &&
            !flb_json_mut_arr_add_val(scope_metric_arrays[
                resolve_target_scope_index(context, counter->map,
                                           scope_counts, resource_count,
                                           total_scope_count)], metric)) {
            flb_free(scope_metric_arrays);
            flb_free(scope_counts);
            flb_json_mut_doc_destroy(doc);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }
    }

    cfl_list_foreach(head, &context->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        metric = create_metric_json(doc, context, gauge->map);
        if (metric != NULL &&
            !flb_json_mut_arr_add_val(scope_metric_arrays[
                resolve_target_scope_index(context, gauge->map,
                                           scope_counts, resource_count,
                                           total_scope_count)], metric)) {
            flb_free(scope_metric_arrays);
            flb_free(scope_counts);
            flb_json_mut_doc_destroy(doc);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }
    }

    cfl_list_foreach(head, &context->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        metric = create_metric_json(doc, context, untyped->map);
        if (metric != NULL &&
            !flb_json_mut_arr_add_val(scope_metric_arrays[
                resolve_target_scope_index(context, untyped->map,
                                           scope_counts, resource_count,
                                           total_scope_count)], metric)) {
            flb_free(scope_metric_arrays);
            flb_free(scope_counts);
            flb_json_mut_doc_destroy(doc);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }
    }

    cfl_list_foreach(head, &context->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        metric = create_metric_json(doc, context, summary->map);
        if (metric != NULL &&
            !flb_json_mut_arr_add_val(scope_metric_arrays[
                resolve_target_scope_index(context, summary->map,
                                           scope_counts, resource_count,
                                           total_scope_count)], metric)) {
            flb_free(scope_metric_arrays);
            flb_free(scope_counts);
            flb_json_mut_doc_destroy(doc);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }
    }

    cfl_list_foreach(head, &context->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        metric = create_metric_json(doc, context, histogram->map);
        if (metric != NULL &&
            !flb_json_mut_arr_add_val(scope_metric_arrays[
                resolve_target_scope_index(context, histogram->map,
                                           scope_counts, resource_count,
                                           total_scope_count)], metric)) {
            flb_free(scope_metric_arrays);
            flb_free(scope_counts);
            flb_json_mut_doc_destroy(doc);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }
    }

    cfl_list_foreach(head, &context->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        metric = create_metric_json(doc, context, exp_histogram->map);
        if (metric != NULL &&
            !flb_json_mut_arr_add_val(scope_metric_arrays[
                resolve_target_scope_index(context, exp_histogram->map,
                                           scope_counts, resource_count,
                                           total_scope_count)], metric)) {
            flb_free(scope_metric_arrays);
            flb_free(scope_counts);
            flb_json_mut_doc_destroy(doc);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }
    }

    flb_free(scope_metric_arrays);
    flb_free(scope_counts);

    json = otlp_doc_to_sds(doc, pretty);
    flb_json_mut_doc_destroy(doc);

    if (json == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    set_result(result, FLB_OPENTELEMETRY_OTLP_JSON_SUCCESS);

    return json;
}

flb_sds_t flb_opentelemetry_metrics_to_otlp_json(struct cmt *context,
                                                 int *result)
{
    return flb_opentelemetry_metrics_to_otlp_json_render(context,
                                                         FLB_FALSE,
                                                         result);
}

flb_sds_t flb_opentelemetry_metrics_msgpack_to_otlp_json(const void *data,
                                                         size_t size,
                                                         int *result)
{
    int       ret;
    int       first_entry;
    size_t    offset;
    flb_sds_t rendered;
    flb_sds_t json;
    flb_sds_t output;
    struct cmt *context;

    if (data == NULL || size == 0) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    rendered = NULL;
    json = NULL;
    output = flb_sds_create("{\"resourceMetrics\":[");
    offset = 0;
    first_entry = FLB_TRUE;

    if (output == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    while ((ret = cmt_decode_msgpack_create(&context, (char *) data, size, &offset)) ==
           CMT_DECODE_MSGPACK_SUCCESS) {
        rendered = flb_opentelemetry_metrics_to_otlp_json(context, result);
        cmt_destroy(context);

        if (rendered == NULL) {
            flb_sds_destroy(output);
            return NULL;
        }

        if (append_rendered_root_array_content(&output,
                                               &first_entry,
                                               rendered,
                                               "resourceMetrics") != 0) {
            flb_sds_destroy(rendered);
            flb_sds_destroy(output);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, EINVAL);
            return NULL;
        }

        flb_sds_destroy(rendered);
    }

    if (ret != CMT_DECODE_MSGPACK_INSUFFICIENT_DATA &&
        ret != CMT_DECODE_MSGPACK_SUCCESS) {
        flb_sds_destroy(output);
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    json = flb_sds_cat(output, "]}", 2);
    if (json == NULL) {
        flb_sds_destroy(output);
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    set_result(result, FLB_OPENTELEMETRY_OTLP_JSON_SUCCESS);

    return json;
}

static struct flb_json_mut_val *ctr_attributes_to_kv_array(struct flb_json_mut_doc *doc,
                                                  struct ctrace_attributes *attributes)
{
    if (attributes == NULL || attributes->kv == NULL) {
        return flb_json_mut_arr(doc);
    }

    return cfl_kvlist_to_otlp_kv_array(doc, attributes->kv);
}

static int add_trace_id_field(struct flb_json_mut_doc *doc,
                              struct flb_json_mut_val *obj,
                              const char *key,
                              struct ctrace_id *id)
{
    cfl_sds_t encoded;
    int       ret;

    if (id == NULL) {
        return 0;
    }

    encoded = ctr_id_to_lower_base16(id);
    if (encoded == NULL) {
        return -1;
    }

    ret = flb_json_mut_obj_add_strncpy(doc, obj, key, encoded, cfl_sds_len(encoded)) ? 0 : -1;
    cfl_sds_destroy(encoded);

    return ret;
}

static struct flb_json_mut_val *create_trace_status_json(struct flb_json_mut_doc *doc,
                                                struct ctrace_span_status *status)
{
    const char     *code_string;
    struct flb_json_mut_val *json;

    if (status == NULL) {
        return NULL;
    }

    if (status->code == CTRACE_SPAN_STATUS_CODE_UNSET &&
        !valid_sds_reference(status->message)) {
        return NULL;
    }

    json = flb_json_mut_obj(doc);
    if (json == NULL) {
        return NULL;
    }

    if (status->code == CTRACE_SPAN_STATUS_CODE_OK) {
        code_string = "OK";
    }
    else if (status->code == CTRACE_SPAN_STATUS_CODE_ERROR) {
        code_string = "ERROR";
    }
    else {
        code_string = "UNSET";
    }

    if (!flb_json_mut_obj_add_str(doc, json, "code", code_string)) {
        return NULL;
    }

    if (valid_sds_reference(status->message) &&
        !flb_json_mut_obj_add_strn(doc, json, "message",
                                 status->message, cfl_sds_len(status->message))) {
        return NULL;
    }

    return json;
}

static struct flb_json_mut_val *create_trace_event_json(struct flb_json_mut_doc *doc,
                                               struct ctrace_span_event *event)
{
    struct flb_json_mut_val *attributes;
    struct flb_json_mut_val *json;

    json = flb_json_mut_obj(doc);
    if (json == NULL ||
        !valid_sds_reference(event->name) ||
        !flb_json_mut_obj_add_strn(doc, json, "name",
                                   event->name, cfl_sds_len(event->name))) {
        return NULL;
    }

    if (event->time_unix_nano > 0 &&
        json_add_uint64_string(doc, json, "timeUnixNano",
                               event->time_unix_nano) != 0) {
        return NULL;
    }

    attributes = ctr_attributes_to_kv_array(doc, event->attr);
    if (attributes == NULL) {
        return NULL;
    }

    if (flb_json_mut_arr_size(attributes) > 0 &&
        !flb_json_mut_obj_add_val(doc, json, "attributes", attributes)) {
        return NULL;
    }

    if (event->dropped_attr_count > 0 &&
        !flb_json_mut_obj_add_uint(doc, json, "droppedAttributesCount",
                                 event->dropped_attr_count)) {
        return NULL;
    }

    return json;
}

static struct flb_json_mut_val *create_trace_link_json(struct flb_json_mut_doc *doc,
                                              struct ctrace_link *link)
{
    struct flb_json_mut_val *attributes;
    struct flb_json_mut_val *json;

    json = flb_json_mut_obj(doc);
    if (json == NULL ||
        add_trace_id_field(doc, json, "traceId", link->trace_id) != 0 ||
        add_trace_id_field(doc, json, "spanId", link->span_id) != 0) {
        return NULL;
    }

    if (valid_sds_reference(link->trace_state) &&
        !flb_json_mut_obj_add_strn(doc, json, "traceState",
                                   link->trace_state,
                                   cfl_sds_len(link->trace_state))) {
        return NULL;
    }

    attributes = ctr_attributes_to_kv_array(doc, link->attr);
    if (attributes == NULL) {
        return NULL;
    }

    if (flb_json_mut_arr_size(attributes) > 0 &&
        !flb_json_mut_obj_add_val(doc, json, "attributes", attributes)) {
        return NULL;
    }

    if (link->dropped_attr_count > 0 &&
        !flb_json_mut_obj_add_uint(doc, json, "droppedAttributesCount",
                                 link->dropped_attr_count)) {
        return NULL;
    }

    if (link->flags > 0 &&
        !flb_json_mut_obj_add_uint(doc, json, "flags", link->flags)) {
        return NULL;
    }

    return json;
}

static struct flb_json_mut_val *create_trace_span_json(struct flb_json_mut_doc *doc,
                                              struct ctrace_span *span)
{
    struct cfl_list     *head;
    struct flb_json_mut_val      *attributes;
    struct flb_json_mut_val      *events;
    struct flb_json_mut_val      *json;
    struct flb_json_mut_val      *links;
    struct flb_json_mut_val      *status;
    struct ctrace_link  *link;
    struct ctrace_span_event *event;

    json = flb_json_mut_obj(doc);
    if (json == NULL ||
        add_trace_id_field(doc, json, "traceId", span->trace_id) != 0 ||
        add_trace_id_field(doc, json, "spanId", span->span_id) != 0 ||
        !valid_sds_reference(span->name) ||
        !flb_json_mut_obj_add_strn(doc, json, "name",
                                   span->name, cfl_sds_len(span->name))) {
        return NULL;
    }

    if (add_trace_id_field(doc, json, "parentSpanId", span->parent_span_id) != 0) {
        return NULL;
    }

    if (valid_sds_reference(span->trace_state) &&
        !flb_json_mut_obj_add_strn(doc, json, "traceState",
                                   span->trace_state,
                                   cfl_sds_len(span->trace_state))) {
        return NULL;
    }

    if (span->flags > 0 &&
        !flb_json_mut_obj_add_uint(doc, json, "flags", span->flags)) {
        return NULL;
    }

    if (span->kind >= 0 &&
        !flb_json_mut_obj_add_int(doc, json, "kind", span->kind)) {
        return NULL;
    }

    if (span->start_time_unix_nano > 0 &&
        json_add_uint64_string(doc, json, "startTimeUnixNano",
                               span->start_time_unix_nano) != 0) {
        return NULL;
    }

    if (span->end_time_unix_nano > 0 &&
        json_add_uint64_string(doc, json, "endTimeUnixNano",
                               span->end_time_unix_nano) != 0) {
        return NULL;
    }

    attributes = ctr_attributes_to_kv_array(doc, span->attr);
    if (attributes == NULL) {
        return NULL;
    }

    if (flb_json_mut_arr_size(attributes) > 0 &&
        !flb_json_mut_obj_add_val(doc, json, "attributes", attributes)) {
        return NULL;
    }

    if (span->dropped_attr_count > 0 &&
        !flb_json_mut_obj_add_uint(doc, json, "droppedAttributesCount",
                                 span->dropped_attr_count)) {
        return NULL;
    }

    events = flb_json_mut_arr(doc);
    if (events == NULL) {
        return NULL;
    }

    cfl_list_foreach(head, &span->events) {
        event = cfl_list_entry(head, struct ctrace_span_event, _head);
        status = create_trace_event_json(doc, event);
        if (status == NULL || !flb_json_mut_arr_add_val(events, status)) {
            return NULL;
        }
    }

    if (flb_json_mut_arr_size(events) > 0 &&
        !flb_json_mut_obj_add_val(doc, json, "events", events)) {
        return NULL;
    }

    if (span->dropped_events_count > 0 &&
        !flb_json_mut_obj_add_uint(doc, json, "droppedEventsCount",
                                 span->dropped_events_count)) {
        return NULL;
    }

    links = flb_json_mut_arr(doc);
    if (links == NULL) {
        return NULL;
    }

    cfl_list_foreach(head, &span->links) {
        link = cfl_list_entry(head, struct ctrace_link, _head);
        status = create_trace_link_json(doc, link);
        if (status == NULL || !flb_json_mut_arr_add_val(links, status)) {
            return NULL;
        }
    }

    if (flb_json_mut_arr_size(links) > 0 &&
        !flb_json_mut_obj_add_val(doc, json, "links", links)) {
        return NULL;
    }

    if (span->dropped_links_count > 0 &&
        !flb_json_mut_obj_add_uint(doc, json, "droppedLinksCount",
                                 span->dropped_links_count)) {
        return NULL;
    }

    status = create_trace_status_json(doc, &span->status);
    if (status != NULL &&
        !flb_json_mut_obj_add_val(doc, json, "status", status)) {
        return NULL;
    }

    return json;
}

static struct flb_json_mut_val *create_trace_scope_json(struct flb_json_mut_doc *doc,
                                               struct ctrace_instrumentation_scope *scope)
{
    struct flb_json_mut_val *attributes;
    struct flb_json_mut_val *json;

    json = flb_json_mut_obj(doc);
    if (json == NULL) {
        return NULL;
    }

    if (scope == NULL) {
        return json;
    }

    if (valid_sds_reference(scope->name) &&
        !flb_json_mut_obj_add_strn(doc, json, "name",
                                   scope->name, cfl_sds_len(scope->name))) {
        return NULL;
    }

    if (valid_sds_reference(scope->version) &&
        !flb_json_mut_obj_add_strn(doc, json, "version",
                                   scope->version, cfl_sds_len(scope->version))) {
        return NULL;
    }

    attributes = ctr_attributes_to_kv_array(doc, scope->attr);
    if (attributes == NULL) {
        return NULL;
    }

    if (flb_json_mut_arr_size(attributes) > 0 &&
        !flb_json_mut_obj_add_val(doc, json, "attributes", attributes)) {
        return NULL;
    }

    if (scope->dropped_attr_count > 0 &&
        !flb_json_mut_obj_add_uint(doc, json, "droppedAttributesCount",
                                 scope->dropped_attr_count)) {
        return NULL;
    }

    return json;
}

static struct flb_json_mut_val *create_trace_resource_json(struct flb_json_mut_doc *doc,
                                                  struct ctrace_resource *resource)
{
    struct flb_json_mut_val *attributes;
    struct flb_json_mut_val *json;

    json = flb_json_mut_obj(doc);
    if (json == NULL) {
        return NULL;
    }

    if (resource == NULL) {
        return json;
    }

    attributes = ctr_attributes_to_kv_array(doc, resource->attr);
    if (attributes == NULL) {
        return NULL;
    }

    if (flb_json_mut_arr_size(attributes) > 0 &&
        !flb_json_mut_obj_add_val(doc, json, "attributes", attributes)) {
        return NULL;
    }

    if (resource->dropped_attr_count > 0 &&
        !flb_json_mut_obj_add_uint(doc, json, "droppedAttributesCount",
                                 resource->dropped_attr_count)) {
        return NULL;
    }

    return json;
}

flb_sds_t flb_opentelemetry_traces_to_otlp_json(struct ctrace *context,
                                                int *result)
{
    struct cfl_list            *resource_head;
    struct cfl_list            *scope_head;
    struct cfl_list            *span_head;
    struct ctrace_resource_span *resource_span;
    struct ctrace_scope_span   *scope_span;
    struct ctrace_span         *span;
    struct flb_json_mut_doc             *doc;
    struct flb_json_mut_val             *json;
    struct flb_json_mut_val             *resource;
    struct flb_json_mut_val             *resource_span_array;
    struct flb_json_mut_val             *resource_span_json;
    struct flb_json_mut_val             *scope;
    struct flb_json_mut_val             *scope_span_array;
    struct flb_json_mut_val             *scope_span_json;
    struct flb_json_mut_val             *spans;
    flb_sds_t                   output;

    if (context == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    doc = flb_json_mut_doc_create();
    json = flb_json_mut_obj(doc);
    resource_span_array = flb_json_mut_arr(doc);
    output = NULL;

    if (doc == NULL || json == NULL || resource_span_array == NULL ||
        !flb_json_mut_obj_add_val(doc, json, "resourceSpans", resource_span_array)) {
        if (doc != NULL) {
            flb_json_mut_doc_destroy(doc);
        }
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    flb_json_mut_doc_set_root(doc, json);

    cfl_list_foreach(resource_head, &context->resource_spans) {
        resource_span = cfl_list_entry(resource_head, struct ctrace_resource_span, _head);

        resource_span_json = flb_json_mut_obj(doc);
        resource = create_trace_resource_json(doc, resource_span->resource);
        scope_span_array = flb_json_mut_arr(doc);

        if (resource_span_json == NULL || resource == NULL || scope_span_array == NULL ||
            !flb_json_mut_obj_add_val(doc, resource_span_json, "resource", resource) ||
            !flb_json_mut_obj_add_val(doc, resource_span_json, "scopeSpans", scope_span_array) ||
            !flb_json_mut_arr_add_val(resource_span_array, resource_span_json)) {
            flb_json_mut_doc_destroy(doc);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }

        if (valid_sds_reference(resource_span->schema_url) &&
            !flb_json_mut_obj_add_strn(doc, resource_span_json, "schemaUrl",
                                     resource_span->schema_url,
                                     cfl_sds_len(resource_span->schema_url))) {
            flb_json_mut_doc_destroy(doc);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
            return NULL;
        }

        cfl_list_foreach(scope_head, &resource_span->scope_spans) {
            scope_span = cfl_list_entry(scope_head, struct ctrace_scope_span, _head);
            scope_span_json = flb_json_mut_obj(doc);
            scope = create_trace_scope_json(doc, scope_span->instrumentation_scope);
            spans = flb_json_mut_arr(doc);

            if (scope_span_json == NULL || scope == NULL || spans == NULL ||
                !flb_json_mut_obj_add_val(doc, scope_span_json, "scope", scope) ||
                !flb_json_mut_obj_add_val(doc, scope_span_json, "spans", spans) ||
                !flb_json_mut_arr_add_val(scope_span_array, scope_span_json)) {
                flb_json_mut_doc_destroy(doc);
                set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
                return NULL;
            }

            if (valid_sds_reference(scope_span->schema_url) &&
                !flb_json_mut_obj_add_strn(doc, scope_span_json, "schemaUrl",
                                         scope_span->schema_url,
                                         cfl_sds_len(scope_span->schema_url))) {
                flb_json_mut_doc_destroy(doc);
                set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
                return NULL;
            }

            cfl_list_foreach(span_head, &scope_span->spans) {
                span = cfl_list_entry(span_head, struct ctrace_span, _head);
                json = create_trace_span_json(doc, span);
                if (json == NULL || !flb_json_mut_arr_add_val(spans, json)) {
                    flb_json_mut_doc_destroy(doc);
                    set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
                    return NULL;
                }
            }
        }
    }

    output = otlp_doc_to_sds(doc, FLB_FALSE);
    flb_json_mut_doc_destroy(doc);

    if (output == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    set_result(result, FLB_OPENTELEMETRY_OTLP_JSON_SUCCESS);

    return output;
}


flb_sds_t flb_opentelemetry_traces_msgpack_to_otlp_json(const void *data,
                                                        size_t size,
                                                        int *result)
{
    int             ret;
    int             first_entry;
    size_t          offset;
    flb_sds_t       rendered;
    flb_sds_t       json;
    flb_sds_t       output;
    struct ctrace  *context;

    if (data == NULL || size == 0) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    rendered = NULL;
    json = NULL;
    output = flb_sds_create("{\"resourceSpans\":[");
    offset = 0;
    first_entry = FLB_TRUE;

    if (output == NULL) {
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    while ((ret = ctr_decode_msgpack_create(&context, (char *) data, size, &offset)) ==
           CTR_DECODE_MSGPACK_SUCCESS) {
        rendered = flb_opentelemetry_traces_to_otlp_json(context, result);
        ctr_destroy(context);

        if (rendered == NULL) {
            flb_sds_destroy(output);
            return NULL;
        }

        if (append_rendered_root_array_content(&output,
                                               &first_entry,
                                               rendered,
                                               "resourceSpans") != 0) {
            flb_sds_destroy(rendered);
            flb_sds_destroy(output);
            set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, EINVAL);
            return NULL;
        }

        flb_sds_destroy(rendered);
    }

    if (ret != CTR_DECODE_MSGPACK_SUCCESS &&
        !(ret == CTR_MPACK_ENGINE_ERROR && offset >= size)) {
        flb_sds_destroy(output);
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_INVALID_ARGUMENT, EINVAL);
        return NULL;
    }

    json = flb_sds_cat(output, "]}", 2);
    if (json == NULL) {
        flb_sds_destroy(output);
        set_error(result, FLB_OPENTELEMETRY_OTLP_JSON_NOT_SUPPORTED, ENOMEM);
        return NULL;
    }

    set_result(result, FLB_OPENTELEMETRY_OTLP_JSON_SUCCESS);

    return json;
}
