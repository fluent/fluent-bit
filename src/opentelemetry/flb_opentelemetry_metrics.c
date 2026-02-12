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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_base64.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_summary.h>

#include <cfl/cfl_hash.h>

#include <msgpack.h>

#define OTEL_METRICS_JSON_DECODER_ERROR CMT_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR

static void destroy_context_list(struct cfl_list *context_list)
{
    struct cfl_list *iterator;
    struct cfl_list *tmp;
    struct cmt      *context;

    if (context_list == NULL) {
        return;
    }

    cfl_list_foreach_safe(iterator, tmp, context_list) {
        context = cfl_list_entry(iterator, struct cmt, _head);
        cfl_list_del(&context->_head);
        cmt_destroy(context);
    }
}

static int parse_u64_value(msgpack_object *obj, uint64_t *value)
{
    if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        *value = (uint64_t) obj->via.u64;
        return 0;
    }
    else if (obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        if (obj->via.i64 < 0) {
            return -1;
        }
        *value = (uint64_t) obj->via.i64;
        return 0;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        *value = flb_otel_utils_convert_string_number_to_u64(
                   (char *) obj->via.str.ptr, obj->via.str.size);
        return 0;
    }

    return -1;
}

static int parse_double_value(msgpack_object *obj, double *value)
{
    char     *end;
    flb_sds_t string_value;

    if (obj->type == MSGPACK_OBJECT_FLOAT32) {
        *value = (double) obj->via.f64;
        return 0;
    }
    else if (obj->type == MSGPACK_OBJECT_FLOAT64) {
        *value = obj->via.f64;
        return 0;
    }
    else if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        *value = (double) obj->via.u64;
        return 0;
    }
    else if (obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        *value = (double) obj->via.i64;
        return 0;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        string_value = flb_sds_create_len(obj->via.str.ptr, obj->via.str.size);
        if (string_value == NULL) {
            return -1;
        }

        end = NULL;
        *value = strtod(string_value, &end);

        if (end == string_value || (end != NULL && *end != '\0')) {
            flb_sds_destroy(string_value);
            return -1;
        }

        flb_sds_destroy(string_value);

        return 0;
    }

    return -1;
}

static int parse_i32_value(msgpack_object *obj, int32_t *value)
{
    char     *end;
    flb_sds_t string_value;
    uint64_t temp_u64;
    int64_t  temp_i64;

    if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        temp_u64 = obj->via.u64;

        if (temp_u64 > INT32_MAX) {
            return -1;
        }

        *value = (int32_t) temp_u64;
        return 0;
    }
    else if (obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        temp_i64 = obj->via.i64;

        if (temp_i64 < INT32_MIN || temp_i64 > INT32_MAX) {
            return -1;
        }

        *value = (int32_t) temp_i64;
        return 0;
    }
    else if (obj->type == MSGPACK_OBJECT_STR) {
        string_value = flb_sds_create_len(obj->via.str.ptr, obj->via.str.size);
        if (string_value == NULL) {
            return -1;
        }

        end = NULL;
        temp_i64 = strtoll(string_value, &end, 10);

        if (end == string_value || (end != NULL && *end != '\0')) {
            flb_sds_destroy(string_value);
            return -1;
        }

        flb_sds_destroy(string_value);

        if (temp_i64 < INT32_MIN || temp_i64 > INT32_MAX) {
            return -1;
        }

        *value = (int32_t) temp_i64;
        return 0;
    }

    return -1;
}

static int get_metric_help_string(msgpack_object_map *metric_map,
                                  flb_sds_t *out_help)
{
    int             help_index;
    msgpack_object *help_object;

    *out_help = NULL;

    help_index = flb_otel_utils_find_map_entry_by_key(metric_map,
                                                       "description",
                                                       0,
                                                       FLB_TRUE);
    if (help_index < 0) {
        *out_help = flb_sds_create("-");
    }
    else {
        help_object = &metric_map->ptr[help_index].val;

        if (help_object->type != MSGPACK_OBJECT_STR) {
            return OTEL_METRICS_JSON_DECODER_ERROR;
        }

        if (help_object->via.str.size == 0) {
            *out_help = flb_sds_create("-");
        }
        else {
            *out_help = flb_sds_create_len(help_object->via.str.ptr,
                                           help_object->via.str.size);
        }
    }

    if (*out_help == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    return 0;
}

static int set_metric_unit(struct cmt_map *map, msgpack_object_map *metric_map)
{
    int             unit_index;
    msgpack_object *unit_object;

    unit_index = flb_otel_utils_find_map_entry_by_key(metric_map,
                                                       "unit",
                                                       0,
                                                       FLB_TRUE);
    if (unit_index < 0) {
        return 0;
    }

    unit_object = &metric_map->ptr[unit_index].val;
    if (unit_object->type != MSGPACK_OBJECT_STR) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    if (map->unit != NULL) {
        cfl_sds_destroy(map->unit);
        map->unit = NULL;
    }

    if (unit_object->via.str.size == 0) {
        return 0;
    }

    map->unit = cfl_sds_create_len(unit_object->via.str.ptr,
                                   unit_object->via.str.size);
    if (map->unit == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    return 0;
}

static char *map_type_to_key(int map_type)
{
    switch (map_type) {
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

static struct cfl_kvlist *get_or_create_external_metadata_kvlist(
    struct cfl_kvlist *root, char *key)
{
    struct cfl_variant *entry_variant;
    struct cfl_kvlist  *entry_kvlist;
    int                 result;

    entry_variant = cfl_kvlist_fetch(root, key);

    if (entry_variant == NULL) {
        entry_kvlist = cfl_kvlist_create();

        if (entry_kvlist == NULL) {
            return NULL;
        }

        result = cfl_kvlist_insert_kvlist(root, key, entry_kvlist);
        if (result != 0) {
            cfl_kvlist_destroy(entry_kvlist);
            return NULL;
        }
    }
    else {
        entry_kvlist = entry_variant->data.as_kvlist;
    }

    return entry_kvlist;
}

static uint64_t compute_metric_hash(struct cmt_map *map, struct cmt_metric *sample)
{
    struct cfl_list      *head;
    struct cmt_map_label *label_value;
    cfl_hash_state_t      hash_state;

    if (sample == NULL || map == NULL) {
        return 0;
    }

    if (cfl_list_size(&sample->labels) == 0) {
        return 0;
    }

    cfl_hash_64bits_reset(&hash_state);
    cfl_hash_64bits_update(&hash_state,
                           map->opts->fqname,
                           cfl_sds_len(map->opts->fqname));

    cfl_list_foreach(head, &sample->labels) {
        label_value = cfl_list_entry(head, struct cmt_map_label, _head);
        cfl_hash_64bits_update(&hash_state,
                               label_value->name,
                               cfl_sds_len(label_value->name));
    }

    return cfl_hash_64bits_digest(&hash_state);
}

static struct cfl_kvlist *get_or_create_metric_metadata_context(struct cmt *cmt,
                                                                 struct cmt_map *map)
{
    struct cfl_kvlist *otlp_root;
    struct cfl_kvlist *metrics_root;
    struct cfl_kvlist *type_root;

    if (cmt == NULL || map == NULL || map->opts == NULL || map->opts->fqname == NULL) {
        return NULL;
    }

    otlp_root = get_or_create_external_metadata_kvlist(cmt->external_metadata, "otlp");
    if (otlp_root == NULL) {
        return NULL;
    }

    metrics_root = get_or_create_external_metadata_kvlist(otlp_root, "metrics");
    if (metrics_root == NULL) {
        return NULL;
    }

    type_root = get_or_create_external_metadata_kvlist(metrics_root,
                                                       map_type_to_key(map->type));
    if (type_root == NULL) {
        return NULL;
    }

    return get_or_create_external_metadata_kvlist(type_root, map->opts->fqname);
}

static struct cfl_kvlist *get_or_create_data_point_metadata_context(
                                                struct cmt *cmt,
                                                struct cmt_map *map,
                                                struct cmt_metric *sample,
                                                uint64_t timestamp)
{
    char                key[128];
    struct cfl_kvlist  *metric_context;
    struct cfl_kvlist  *datapoints_context;

    if (sample != NULL && sample->hash == 0 && cfl_list_size(&sample->labels) > 0) {
        sample->hash = compute_metric_hash(map, sample);
    }

    metric_context = get_or_create_metric_metadata_context(cmt, map);
    if (metric_context == NULL) {
        return NULL;
    }

    datapoints_context = get_or_create_external_metadata_kvlist(metric_context,
                                                                "datapoints");
    if (datapoints_context == NULL) {
        return NULL;
    }

    snprintf(key, sizeof(key) - 1, "%llx:%llu",
             (unsigned long long) (sample != NULL ? sample->hash : 0),
             (unsigned long long) timestamp);

    return get_or_create_external_metadata_kvlist(datapoints_context, key);
}

static int object_to_sds(msgpack_object *obj, flb_sds_t *out)
{
    flb_sds_t value;

    value = NULL;

    if (obj->type == MSGPACK_OBJECT_STR) {
        value = flb_sds_create_len(obj->via.str.ptr, obj->via.str.size);
    }
    else if (obj->type == MSGPACK_OBJECT_BOOLEAN) {
        value = flb_sds_create_size(4);
        if (value != NULL) {
            flb_sds_printf(&value, "%d", obj->via.boolean ? 1 : 0);
        }
    }
    else if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        value = flb_sds_create_size(32);
        if (value != NULL) {
            flb_sds_printf(&value, "%llu",
                           (unsigned long long) obj->via.u64);
        }
    }
    else if (obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        value = flb_sds_create_size(32);
        if (value != NULL) {
            flb_sds_printf(&value, "%lld",
                           (long long) obj->via.i64);
        }
    }
    else if (obj->type == MSGPACK_OBJECT_FLOAT32 ||
             obj->type == MSGPACK_OBJECT_FLOAT64) {
        value = flb_sds_create_size(64);
        if (value != NULL) {
            flb_sds_printf(&value, "%.17g", obj->via.f64);
        }
    }
    else if (obj->type == MSGPACK_OBJECT_NIL) {
        value = flb_sds_create("");
    }

    if (value == NULL) {
        return -1;
    }

    *out = value;

    return 0;
}

static int otel_any_value_to_string(msgpack_object *wrapper, flb_sds_t *out)
{
    msgpack_object *value;
    int             type;
    int             result;

    result = flb_otel_utils_json_payload_get_wrapped_value(wrapper, &value, &type);
    if (result != 0 || value == NULL) {
        return -1;
    }

    return object_to_sds(value, out);
}

static void destroy_label_arrays(int count,
                                 flb_sds_t *keys,
                                 flb_sds_t *values)
{
    int index;

    if (keys != NULL) {
        for (index = 0 ; index < count ; index++) {
            if (keys[index] != NULL) {
                flb_sds_destroy(keys[index]);
            }
        }
        flb_free(keys);
    }

    if (values != NULL) {
        for (index = 0 ; index < count ; index++) {
            if (values[index] != NULL) {
                flb_sds_destroy(values[index]);
            }
        }
        flb_free(values);
    }
}

static int parse_datapoint_labels(msgpack_object *attributes_object,
                                  int *out_count,
                                  flb_sds_t **out_keys,
                                  flb_sds_t **out_values)
{
    int                 attribute_index;
    int                 key_index;
    int                 value_index;
    flb_sds_t          *keys;
    flb_sds_t          *values;
    msgpack_object     *entry;
    msgpack_object_map *entry_map;
    msgpack_object     *key_object;
    msgpack_object     *value_object;
    msgpack_object_array *attributes;
    int                 result;

    *out_count = 0;
    *out_keys = NULL;
    *out_values = NULL;

    if (attributes_object == NULL) {
        return 0;
    }

    if (attributes_object->type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    attributes = &attributes_object->via.array;
    if (attributes->size == 0) {
        return 0;
    }

    keys = flb_calloc(attributes->size, sizeof(flb_sds_t));
    if (keys == NULL) {
        flb_errno();
        return -1;
    }

    values = flb_calloc(attributes->size, sizeof(flb_sds_t));
    if (values == NULL) {
        flb_errno();
        destroy_label_arrays((int) attributes->size, keys, NULL);
        return -1;
    }

    for (attribute_index = 0 ; attribute_index < attributes->size ; attribute_index++) {
        entry = &attributes->ptr[attribute_index];
        if (entry->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        entry_map = &entry->via.map;
        key_index = flb_otel_utils_find_map_entry_by_key(entry_map, "key", 0, FLB_TRUE);
        value_index = flb_otel_utils_find_map_entry_by_key(entry_map, "value", 0, FLB_TRUE);

        if (key_index < 0 || value_index < 0) {
            continue;
        }

        key_object = &entry_map->ptr[key_index].val;
        value_object = &entry_map->ptr[value_index].val;

        if (key_object->type != MSGPACK_OBJECT_STR) {
            continue;
        }

        keys[*out_count] = flb_sds_create_len(key_object->via.str.ptr,
                                              key_object->via.str.size);
        if (keys[*out_count] == NULL) {
            destroy_label_arrays((int) attributes->size, keys, values);
            return -1;
        }

        result = otel_any_value_to_string(value_object, &values[*out_count]);
        if (result != 0) {
            values[*out_count] = flb_sds_create("");
        }

        if (values[*out_count] == NULL) {
            destroy_label_arrays((int) attributes->size, keys, values);
            return -1;
        }

        (*out_count)++;
    }

    *out_keys = keys;
    *out_values = values;

    return 0;
}

static int check_label_layout(int expected_count,
                              flb_sds_t *expected_keys,
                              int point_label_count,
                              flb_sds_t *point_keys)
{
    int index;

    if (expected_count != point_label_count) {
        return -1;
    }

    for (index = 0 ; index < expected_count ; index++) {
        if (strcmp(expected_keys[index], point_keys[index]) != 0) {
            return -1;
        }
    }

    return 0;
}

static int parse_number_datapoint_value(msgpack_object_map *point_map,
                                        double *value)
{
    int             result;
    msgpack_object *obj;

    result = flb_otel_utils_find_map_entry_by_key(point_map, "asDouble", 0, FLB_TRUE);
    if (result >= 0) {
        obj = &point_map->ptr[result].val;
        return parse_double_value(obj, value);
    }

    result = flb_otel_utils_find_map_entry_by_key(point_map, "asInt", 0, FLB_TRUE);
    if (result >= 0) {
        obj = &point_map->ptr[result].val;
        return parse_double_value(obj, value);
    }

    return -1;
}

static int parse_datapoint_timestamp(msgpack_object_map *point_map,
                                     uint64_t *timestamp)
{
    int             result;
    msgpack_object *obj;

    *timestamp = 0;

    result = flb_otel_utils_find_map_entry_by_key(point_map, "timeUnixNano", 0, FLB_TRUE);
    if (result < 0) {
        return 0;
    }

    obj = &point_map->ptr[result].val;
    return parse_u64_value(obj, timestamp);
}

static int clone_exemplars_to_kvlist(struct cfl_kvlist *target,
                                     msgpack_object *exemplars_object)
{
    int                  index;
    int                  time_unix_nano_index;
    int                  span_id_index;
    int                  trace_id_index;
    int                  as_double_index;
    int                  as_int_index;
    int                  filtered_attributes_index;
    int                  result;
    unsigned char        id_buffer[32];
    size_t               decoded_length;
    uint64_t             time_unix_nano;
    int64_t              as_int_value;
    double               as_double_value;
    msgpack_object      *exemplar_object;
    msgpack_object      *field_object;
    msgpack_object_map  *exemplar_map;
    msgpack_object_array *exemplar_array;
    struct cfl_array    *array;
    struct cfl_kvlist   *entry;
    struct cfl_kvlist   *filtered_attributes;

    if (target == NULL || exemplars_object == NULL) {
        return 0;
    }

    if (exemplars_object->type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    exemplar_array = &exemplars_object->via.array;
    if (exemplar_array->size == 0) {
        return 0;
    }

    array = cfl_array_create(exemplar_array->size);
    if (array == NULL) {
        return -1;
    }

    for (index = 0 ; index < exemplar_array->size ; index++) {
        exemplar_object = &exemplar_array->ptr[index];
        if (exemplar_object->type != MSGPACK_OBJECT_MAP) {
            cfl_array_destroy(array);
            return -1;
        }

        entry = cfl_kvlist_create();
        if (entry == NULL) {
            cfl_array_destroy(array);
            return -1;
        }

        exemplar_map = &exemplar_object->via.map;

        time_unix_nano_index = flb_otel_utils_find_map_entry_by_key(exemplar_map,
                                                                     "timeUnixNano",
                                                                     0,
                                                                     FLB_TRUE);
        if (time_unix_nano_index >= 0) {
            field_object = &exemplar_map->ptr[time_unix_nano_index].val;
            result = parse_u64_value(field_object, &time_unix_nano);
            if (result != 0 ||
                cfl_kvlist_insert_uint64(entry,
                                         "time_unix_nano",
                                         time_unix_nano) != 0) {
                cfl_kvlist_destroy(entry);
                cfl_array_destroy(array);
                return -1;
            }
        }

        span_id_index = flb_otel_utils_find_map_entry_by_key(exemplar_map,
                                                              "spanId",
                                                              0,
                                                              FLB_TRUE);
        if (span_id_index >= 0) {
            field_object = &exemplar_map->ptr[span_id_index].val;
            if (field_object->type == MSGPACK_OBJECT_STR) {
                if (field_object->via.str.size == 16 &&
                    flb_otel_utils_hex_to_id(field_object->via.str.ptr,
                                             field_object->via.str.size,
                                             id_buffer,
                                             8) == 0) {
                    result = cfl_kvlist_insert_bytes(entry,
                                                     "span_id",
                                                     (char *) id_buffer,
                                                     8,
                                                     CFL_FALSE);
                }
                else {
                    decoded_length = 0;
                    if (flb_base64_decode(id_buffer,
                                          sizeof(id_buffer),
                                          &decoded_length,
                                          (unsigned char *) field_object->via.str.ptr,
                                          field_object->via.str.size) == 0 &&
                        decoded_length > 0 &&
                        decoded_length <= sizeof(id_buffer)) {
                        result = cfl_kvlist_insert_bytes(entry,
                                                         "span_id",
                                                         (char *) id_buffer,
                                                         decoded_length,
                                                         CFL_FALSE);
                    }
                    else {
                        result = cfl_kvlist_insert_bytes(entry,
                                                         "span_id",
                                                         (char *) field_object->via.str.ptr,
                                                         field_object->via.str.size,
                                                         CFL_FALSE);
                    }
                }

                if (result != 0) {
                    cfl_kvlist_destroy(entry);
                    cfl_array_destroy(array);
                    return -1;
                }
            }
        }

        trace_id_index = flb_otel_utils_find_map_entry_by_key(exemplar_map,
                                                               "traceId",
                                                               0,
                                                               FLB_TRUE);
        if (trace_id_index >= 0) {
            field_object = &exemplar_map->ptr[trace_id_index].val;
            if (field_object->type == MSGPACK_OBJECT_STR) {
                if (field_object->via.str.size == 32 &&
                    flb_otel_utils_hex_to_id(field_object->via.str.ptr,
                                             field_object->via.str.size,
                                             id_buffer,
                                             16) == 0) {
                    result = cfl_kvlist_insert_bytes(entry,
                                                     "trace_id",
                                                     (char *) id_buffer,
                                                     16,
                                                     CFL_FALSE);
                }
                else {
                    decoded_length = 0;
                    if (flb_base64_decode(id_buffer,
                                          sizeof(id_buffer),
                                          &decoded_length,
                                          (unsigned char *) field_object->via.str.ptr,
                                          field_object->via.str.size) == 0 &&
                        decoded_length > 0 &&
                        decoded_length <= sizeof(id_buffer)) {
                        result = cfl_kvlist_insert_bytes(entry,
                                                         "trace_id",
                                                         (char *) id_buffer,
                                                         decoded_length,
                                                         CFL_FALSE);
                    }
                    else {
                        result = cfl_kvlist_insert_bytes(entry,
                                                         "trace_id",
                                                         (char *) field_object->via.str.ptr,
                                                         field_object->via.str.size,
                                                         CFL_FALSE);
                    }
                }

                if (result != 0) {
                    cfl_kvlist_destroy(entry);
                    cfl_array_destroy(array);
                    return -1;
                }
            }
        }

        as_double_index = flb_otel_utils_find_map_entry_by_key(exemplar_map,
                                                                "asDouble",
                                                                0,
                                                                FLB_TRUE);
        if (as_double_index >= 0) {
            field_object = &exemplar_map->ptr[as_double_index].val;
            if (parse_double_value(field_object, &as_double_value) == 0) {
                if (cfl_kvlist_insert_double(entry,
                                             "as_double",
                                             as_double_value) != 0) {
                    cfl_kvlist_destroy(entry);
                    cfl_array_destroy(array);
                    return -1;
                }
            }
        }
        else {
            as_int_index = flb_otel_utils_find_map_entry_by_key(exemplar_map,
                                                                 "asInt",
                                                                 0,
                                                                 FLB_TRUE);
            if (as_int_index >= 0) {
                flb_sds_t string_value;

                field_object = &exemplar_map->ptr[as_int_index].val;
                if (field_object->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                    as_int_value = field_object->via.i64;
                }
                else if (field_object->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    as_int_value = field_object->via.u64;
                }
                else if (field_object->type == MSGPACK_OBJECT_STR) {
                    string_value = flb_sds_create_len(field_object->via.str.ptr,
                                                      field_object->via.str.size);
                    if (string_value == NULL) {
                        cfl_kvlist_destroy(entry);
                        cfl_array_destroy(array);
                        return -1;
                    }

                    as_int_value = strtoll(string_value, NULL, 10);
                    flb_sds_destroy(string_value);
                }
                else {
                    as_int_value = 0;
                }

                if (cfl_kvlist_insert_int64(entry,
                                            "as_int",
                                            as_int_value) != 0) {
                    cfl_kvlist_destroy(entry);
                    cfl_array_destroy(array);
                    return -1;
                }
            }
        }

        filtered_attributes_index = flb_otel_utils_find_map_entry_by_key(
                                                            exemplar_map,
                                                            "filteredAttributes",
                                                            0,
                                                            FLB_TRUE);
        if (filtered_attributes_index >= 0) {
            filtered_attributes = cfl_kvlist_create();
            if (filtered_attributes == NULL) {
                cfl_kvlist_destroy(entry);
                cfl_array_destroy(array);
                return -1;
            }

            field_object = &exemplar_map->ptr[filtered_attributes_index].val;
            if (flb_otel_utils_clone_kvlist_from_otlp_json_array(
                    filtered_attributes,
                    field_object) != 0) {
                cfl_kvlist_destroy(filtered_attributes);
                cfl_kvlist_destroy(entry);
                cfl_array_destroy(array);
                return -1;
            }

            if (cfl_kvlist_insert_kvlist(entry,
                                         "filtered_attributes",
                                         filtered_attributes) != 0) {
                cfl_kvlist_destroy(filtered_attributes);
                cfl_kvlist_destroy(entry);
                cfl_array_destroy(array);
                return -1;
            }
        }

        if (cfl_array_append_kvlist(array, entry) != 0) {
            cfl_kvlist_destroy(entry);
            cfl_array_destroy(array);
            return -1;
        }
    }

    if (cfl_kvlist_insert_array(target, "exemplars", array) != 0) {
        cfl_array_destroy(array);
        return -1;
    }

    return 0;
}

static int parse_optional_datapoint_u64(msgpack_object_map *point_map,
                                        char *key,
                                        uint64_t *out_value)
{
    int             result;
    msgpack_object *value_object;

    result = flb_otel_utils_find_map_entry_by_key(point_map,
                                                   key,
                                                   0,
                                                   FLB_TRUE);
    if (result < 0) {
        return -1;
    }

    value_object = &point_map->ptr[result].val;
    if (parse_u64_value(value_object, out_value) != 0) {
        return -1;
    }

    return 0;
}

static void append_common_datapoint_metadata(struct cfl_kvlist *point_metadata,
                                             msgpack_object_map *point_map)
{
    int             result;
    uint64_t        start_time_unix_nano;
    uint64_t        flags;
    msgpack_object *exemplars_object;

    if (point_metadata == NULL || point_map == NULL) {
        return;
    }

    result = parse_optional_datapoint_u64(point_map,
                                          "startTimeUnixNano",
                                          &start_time_unix_nano);
    if (result == 0) {
        cfl_kvlist_insert_uint64(point_metadata,
                                 "start_time_unix_nano",
                                 start_time_unix_nano);
    }

    result = parse_optional_datapoint_u64(point_map, "flags", &flags);
    if (result == 0) {
        cfl_kvlist_insert_uint64(point_metadata, "flags", flags);
    }

    result = flb_otel_utils_find_map_entry_by_key(point_map,
                                                   "exemplars",
                                                   0,
                                                   FLB_TRUE);
    if (result >= 0) {
        exemplars_object = &point_map->ptr[result].val;
        clone_exemplars_to_kvlist(point_metadata, exemplars_object);
    }
}

static int clone_metric_metadata(struct cmt *context,
                                 struct cmt_map *map,
                                 msgpack_object_map *metric_map)
{
    int                metadata_index;
    msgpack_object    *metadata_object;
    struct cfl_kvlist *metric_context;
    struct cfl_kvlist *metadata_context;

    metadata_index = flb_otel_utils_find_map_entry_by_key(metric_map,
                                                           "metadata",
                                                           0,
                                                           FLB_TRUE);
    if (metadata_index < 0) {
        return 0;
    }

    metadata_object = &metric_map->ptr[metadata_index].val;
    if (metadata_object->type != MSGPACK_OBJECT_ARRAY) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    metric_context = get_or_create_metric_metadata_context(context, map);
    if (metric_context == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    metadata_context = get_or_create_external_metadata_kvlist(metric_context, "metadata");
    if (metadata_context == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    if (flb_otel_utils_clone_kvlist_from_otlp_json_array(
            metadata_context,
            metadata_object) != 0) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    return 0;
}

static int process_metric_gauge_data_points(struct cmt *context,
                                            msgpack_object_map *metric_map,
                                            msgpack_object *name_object,
                                            msgpack_object_array *data_points)
{
    struct cmt_gauge  *gauge;
    msgpack_object *point;
    msgpack_object *attributes_obj;
    msgpack_object_map *point_map;
    flb_sds_t      *metric_label_keys;
    int             metric_label_count;
    int             point_label_count;
    flb_sds_t      *point_label_keys;
    flb_sds_t      *point_label_values;
    uint64_t        timestamp;
    double          value;
    int             index;
    int             result;
    int             number_value_case;
    int             metric_initialized;
    flb_sds_t       metric_name;
    flb_sds_t       metric_help;
    struct cmt_metric *sample;
    struct cfl_kvlist *point_metadata;

    metric_label_keys = NULL;
    metric_label_count = 0;
    point_label_keys = NULL;
    point_label_values = NULL;
    gauge = NULL;
    metric_name = NULL;
    metric_help = NULL;
    sample = NULL;
    point_metadata = NULL;
    metric_initialized = FLB_FALSE;

    for (index = 0 ; index < data_points->size ; index++) {
        point = &data_points->ptr[index];
        if (point->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        point_map = &point->via.map;

        result = parse_number_datapoint_value(point_map, &value);
        if (result != 0) {
            continue;
        }

        result = parse_datapoint_timestamp(point_map, &timestamp);
        if (result != 0) {
            continue;
        }

        result = flb_otel_utils_find_map_entry_by_key(point_map, "attributes", 0, FLB_TRUE);
        if (result >= 0) {
            attributes_obj = &point_map->ptr[result].val;
        }
        else {
            attributes_obj = NULL;
        }

        point_label_count = 0;
        point_label_keys = NULL;
        point_label_values = NULL;

        result = parse_datapoint_labels(attributes_obj,
                                        &point_label_count,
                                        &point_label_keys,
                                        &point_label_values);
        if (result != 0) {
            destroy_label_arrays(point_label_count, point_label_keys, point_label_values);
            continue;
        }

        if (!metric_initialized) {
            metric_label_count = point_label_count;
            metric_label_keys = point_label_keys;
            point_label_keys = NULL;

            metric_name = flb_sds_create_len(name_object->via.str.ptr,
                                             name_object->via.str.size);
            if (metric_name == NULL) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            result = get_metric_help_string(metric_map, &metric_help);
            if (result != 0) {
                flb_sds_destroy(metric_name);
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                return result;
            }

            gauge = cmt_gauge_create(context, "", "",
                                     metric_name,
                                     metric_help, metric_label_count,
                                     (char **) metric_label_keys);
            flb_sds_destroy(metric_name);
            flb_sds_destroy(metric_help);
            metric_help = NULL;

            if (gauge == NULL) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            result = set_metric_unit(gauge->map, metric_map);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                cmt_gauge_destroy(gauge);
                return result;
            }

            result = clone_metric_metadata(context, gauge->map, metric_map);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                cmt_gauge_destroy(gauge);
                return result;
            }

            metric_initialized = FLB_TRUE;
        }
        else {
            result = check_label_layout(metric_label_count,
                                        metric_label_keys,
                                        point_label_count,
                                        point_label_keys);
            destroy_label_arrays(point_label_count, point_label_keys, NULL);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                continue;
            }
        }

        cmt_gauge_set(gauge, timestamp, value,
                      point_label_count,
                      (char **) point_label_values);

        sample = cmt_map_metric_get(&gauge->opts,
                                    gauge->map,
                                    point_label_count,
                                    (char **) point_label_values,
                                    CMT_FALSE);
        if (sample != NULL) {
            point_metadata = get_or_create_data_point_metadata_context(context,
                                                                       gauge->map,
                                                                       sample,
                                                                       timestamp);
            if (point_metadata != NULL) {
                append_common_datapoint_metadata(point_metadata, point_map);

                number_value_case = flb_otel_utils_find_map_entry_by_key(point_map,
                                                                          "asInt",
                                                                          0,
                                                                          FLB_TRUE);
                if (number_value_case >= 0) {
                    cfl_kvlist_insert_string(point_metadata,
                                             "number_value_case",
                                             "int");
                }
                else {
                    cfl_kvlist_insert_string(point_metadata,
                                             "number_value_case",
                                             "double");
                }
            }
        }

        destroy_label_arrays(point_label_count, NULL, point_label_values);
    }

    destroy_label_arrays(metric_label_count, metric_label_keys, NULL);

    return 0;
}

static int process_metric_sum_data_points(struct cmt *context,
                                          msgpack_object_map *metric_map,
                                          msgpack_object *name_object,
                                          int allow_reset,
                                          int aggregation_type,
                                          msgpack_object_array *data_points)
{
    struct cmt_counter *counter;
    msgpack_object *point;
    msgpack_object *attributes_obj;
    msgpack_object_map *point_map;
    flb_sds_t      *metric_label_keys;
    int             metric_label_count;
    int             point_label_count;
    flb_sds_t      *point_label_keys;
    flb_sds_t      *point_label_values;
    uint64_t        timestamp;
    double          value;
    int             index;
    int             result;
    int             number_value_case;
    int             metric_initialized;
    flb_sds_t       metric_name;
    flb_sds_t       metric_help;
    struct cmt_metric *sample;
    struct cfl_kvlist *point_metadata;

    metric_label_keys = NULL;
    metric_label_count = 0;
    point_label_keys = NULL;
    point_label_values = NULL;
    counter = NULL;
    metric_name = NULL;
    metric_help = NULL;
    sample = NULL;
    point_metadata = NULL;
    metric_initialized = FLB_FALSE;

    for (index = 0 ; index < data_points->size ; index++) {
        point = &data_points->ptr[index];
        if (point->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        point_map = &point->via.map;

        result = parse_number_datapoint_value(point_map, &value);
        if (result != 0) {
            continue;
        }

        result = parse_datapoint_timestamp(point_map, &timestamp);
        if (result != 0) {
            continue;
        }

        result = flb_otel_utils_find_map_entry_by_key(point_map, "attributes", 0, FLB_TRUE);
        if (result >= 0) {
            attributes_obj = &point_map->ptr[result].val;
        }
        else {
            attributes_obj = NULL;
        }

        point_label_count = 0;
        point_label_keys = NULL;
        point_label_values = NULL;

        result = parse_datapoint_labels(attributes_obj,
                                        &point_label_count,
                                        &point_label_keys,
                                        &point_label_values);
        if (result != 0) {
            destroy_label_arrays(point_label_count, point_label_keys, point_label_values);
            continue;
        }

        if (!metric_initialized) {
            metric_label_count = point_label_count;
            metric_label_keys = point_label_keys;
            point_label_keys = NULL;

            metric_name = flb_sds_create_len(name_object->via.str.ptr,
                                             name_object->via.str.size);
            if (metric_name == NULL) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            result = get_metric_help_string(metric_map, &metric_help);
            if (result != 0) {
                flb_sds_destroy(metric_name);
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                return result;
            }

            counter = cmt_counter_create(context, "", "",
                                         metric_name,
                                         metric_help, metric_label_count,
                                         (char **) metric_label_keys);
            flb_sds_destroy(metric_name);
            flb_sds_destroy(metric_help);
            metric_help = NULL;

            if (counter == NULL) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            result = set_metric_unit(counter->map, metric_map);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                cmt_counter_destroy(counter);
                return result;
            }

            result = clone_metric_metadata(context, counter->map, metric_map);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                cmt_counter_destroy(counter);
                return result;
            }

            if (allow_reset) {
                cmt_counter_allow_reset(counter);
            }

            counter->aggregation_type = aggregation_type;
            metric_initialized = FLB_TRUE;
        }
        else {
            result = check_label_layout(metric_label_count,
                                        metric_label_keys,
                                        point_label_count,
                                        point_label_keys);
            destroy_label_arrays(point_label_count, point_label_keys, NULL);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                continue;
            }
        }

        cmt_counter_set(counter, timestamp, value,
                        point_label_count,
                        (char **) point_label_values);

        sample = cmt_map_metric_get(&counter->opts,
                                    counter->map,
                                    point_label_count,
                                    (char **) point_label_values,
                                    CMT_FALSE);
        if (sample != NULL) {
            point_metadata = get_or_create_data_point_metadata_context(context,
                                                                       counter->map,
                                                                       sample,
                                                                       timestamp);
            if (point_metadata != NULL) {
                append_common_datapoint_metadata(point_metadata, point_map);

                number_value_case = flb_otel_utils_find_map_entry_by_key(point_map,
                                                                          "asInt",
                                                                          0,
                                                                          FLB_TRUE);
                if (number_value_case >= 0) {
                    cfl_kvlist_insert_string(point_metadata,
                                             "number_value_case",
                                             "int");
                }
                else {
                    cfl_kvlist_insert_string(point_metadata,
                                             "number_value_case",
                                             "double");
                }
            }
        }

        destroy_label_arrays(point_label_count, NULL, point_label_values);
    }

    destroy_label_arrays(metric_label_count, metric_label_keys, NULL);

    return 0;
}

static int parse_histogram_bounds(msgpack_object *explicit_bounds_object,
                                  double **out_bounds,
                                  size_t *out_count)
{
    size_t               index;
    msgpack_object      *bound_object;
    msgpack_object_array *bounds_array;
    double              *bounds;

    *out_bounds = NULL;
    *out_count = 0;

    if (explicit_bounds_object == NULL) {
        return -1;
    }

    if (explicit_bounds_object->type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    bounds_array = &explicit_bounds_object->via.array;

    if (bounds_array->size == 0) {
        return -1;
    }

    bounds = flb_calloc(bounds_array->size, sizeof(double));
    if (bounds == NULL) {
        flb_errno();
        return -1;
    }

    for (index = 0 ; index < bounds_array->size ; index++) {
        bound_object = &bounds_array->ptr[index];

        if (parse_double_value(bound_object, &bounds[index]) != 0) {
            flb_free(bounds);
            return -1;
        }
    }

    *out_bounds = bounds;
    *out_count = bounds_array->size;

    return 0;
}

static int parse_histogram_bucket_counts(msgpack_object *bucket_counts_object,
                                         uint64_t **out_bucket_counts,
                                         size_t *out_count)
{
    size_t               index;
    msgpack_object      *count_object;
    msgpack_object_array *counts_array;
    uint64_t            *bucket_counts;

    *out_bucket_counts = NULL;
    *out_count = 0;

    if (bucket_counts_object == NULL) {
        return -1;
    }

    if (bucket_counts_object->type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    counts_array = &bucket_counts_object->via.array;
    if (counts_array->size == 0) {
        return -1;
    }

    bucket_counts = flb_calloc(counts_array->size, sizeof(uint64_t));
    if (bucket_counts == NULL) {
        flb_errno();
        return -1;
    }

    for (index = 0 ; index < counts_array->size ; index++) {
        count_object = &counts_array->ptr[index];

        if (parse_u64_value(count_object, &bucket_counts[index]) != 0) {
            flb_free(bucket_counts);
            return -1;
        }
    }

    *out_bucket_counts = bucket_counts;
    *out_count = counts_array->size;

    return 0;
}

static int parse_u64_array(msgpack_object *array_object,
                           uint64_t **out_values,
                           size_t *out_count)
{
    size_t               index;
    msgpack_object      *item_object;
    msgpack_object_array *items_array;
    uint64_t            *values;

    *out_values = NULL;
    *out_count = 0;

    if (array_object == NULL) {
        return 0;
    }

    if (array_object->type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    items_array = &array_object->via.array;

    if (items_array->size == 0) {
        return 0;
    }

    values = flb_calloc(items_array->size, sizeof(uint64_t));
    if (values == NULL) {
        flb_errno();
        return -1;
    }

    for (index = 0 ; index < items_array->size ; index++) {
        item_object = &items_array->ptr[index];

        if (parse_u64_value(item_object, &values[index]) != 0) {
            flb_free(values);
            return -1;
        }
    }

    *out_values = values;
    *out_count = items_array->size;

    return 0;
}

static int parse_exponential_histogram_buckets(msgpack_object *bucket_object,
                                               int32_t *out_offset,
                                               uint64_t **out_counts,
                                               size_t *out_count)
{
    int               offset_index;
    int               bucket_counts_index;
    int               result;
    msgpack_object   *offset_object;
    msgpack_object   *bucket_counts_object;
    msgpack_object_map *bucket_map;

    *out_offset = 0;
    *out_counts = NULL;
    *out_count = 0;

    if (bucket_object == NULL) {
        return 0;
    }

    if (bucket_object->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    bucket_map = &bucket_object->via.map;

    offset_index = flb_otel_utils_find_map_entry_by_key(bucket_map,
                                                         "offset",
                                                         0,
                                                         FLB_TRUE);
    if (offset_index >= 0) {
        offset_object = &bucket_map->ptr[offset_index].val;

        if (parse_i32_value(offset_object, out_offset) != 0) {
            return -1;
        }
    }

    bucket_counts_index = flb_otel_utils_find_map_entry_by_key(bucket_map,
                                                                "bucketCounts",
                                                                0,
                                                                FLB_TRUE);
    if (bucket_counts_index < 0) {
        return 0;
    }

    bucket_counts_object = &bucket_map->ptr[bucket_counts_index].val;
    result = parse_u64_array(bucket_counts_object, out_counts, out_count);

    return result;
}

static int parse_summary_quantile_values(msgpack_object *quantile_values_object,
                                         double **out_quantiles,
                                         double **out_values,
                                         size_t *out_count)
{
    size_t               index;
    int                  quantile_index;
    int                  value_index;
    double              *quantiles;
    double              *values;
    msgpack_object      *entry_object;
    msgpack_object_map  *entry_map;
    msgpack_object_array *quantile_values_array;

    *out_quantiles = NULL;
    *out_values = NULL;
    *out_count = 0;

    if (quantile_values_object == NULL) {
        return 0;
    }

    if (quantile_values_object->type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    quantile_values_array = &quantile_values_object->via.array;
    if (quantile_values_array->size == 0) {
        return 0;
    }

    quantiles = flb_calloc(quantile_values_array->size, sizeof(double));
    values = flb_calloc(quantile_values_array->size, sizeof(double));
    if (quantiles == NULL || values == NULL) {
        if (quantiles == NULL) {
            flb_errno();
        }
        if (values == NULL) {
            flb_errno();
        }
        flb_free(quantiles);
        flb_free(values);
        return -1;
    }

    for (index = 0 ; index < quantile_values_array->size ; index++) {
        entry_object = &quantile_values_array->ptr[index];
        if (entry_object->type != MSGPACK_OBJECT_MAP) {
            flb_free(quantiles);
            flb_free(values);
            return -1;
        }

        entry_map = &entry_object->via.map;
        quantile_index = flb_otel_utils_find_map_entry_by_key(entry_map,
                                                               "quantile",
                                                               0,
                                                               FLB_TRUE);
        value_index = flb_otel_utils_find_map_entry_by_key(entry_map,
                                                            "value",
                                                            0,
                                                            FLB_TRUE);
        if (quantile_index < 0 || value_index < 0) {
            flb_free(quantiles);
            flb_free(values);
            return -1;
        }

        if (parse_double_value(&entry_map->ptr[quantile_index].val,
                               &quantiles[index]) != 0) {
            flb_free(quantiles);
            flb_free(values);
            return -1;
        }

        if (parse_double_value(&entry_map->ptr[value_index].val,
                               &values[index]) != 0) {
            flb_free(quantiles);
            flb_free(values);
            return -1;
        }
    }

    *out_quantiles = quantiles;
    *out_values = values;
    *out_count = quantile_values_array->size;

    return 0;
}

static int check_double_array_layout(size_t expected_count,
                                     double *expected_values,
                                     size_t actual_count,
                                     double *actual_values)
{
    size_t index;

    if (expected_count != actual_count) {
        return -1;
    }

    for (index = 0 ; index < expected_count ; index++) {
        if (expected_values[index] != actual_values[index]) {
            return -1;
        }
    }

    return 0;
}

static int process_metric_histogram_data_points(struct cmt *context,
                                                msgpack_object_map *metric_map,
                                                msgpack_object *name_object,
                                                int aggregation_type,
                                                msgpack_object_array *data_points)
{
    int                     index;
    int                     result;
    int                     metric_initialized;
    int                     point_label_count;
    int                     metric_label_count;
    int                     bucket_counts_index;
    int                     explicit_bounds_index;
    int                     count_index;
    int                     sum_index;
    int                     min_index;
    int                     max_index;
    int                     attributes_index;
    int                     has_sum;
    int                     has_min;
    int                     has_max;
    uint64_t                timestamp;
    uint64_t                count;
    size_t                  bucket_counts_count;
    size_t                  metric_bound_count;
    size_t                  point_bound_count;
    double                  sum;
    double                  min;
    double                  max;
    double                 *point_bounds;
    double                 *metric_bounds;
    flb_sds_t               metric_name;
    flb_sds_t               metric_help;
    flb_sds_t              *point_label_keys;
    flb_sds_t              *point_label_values;
    flb_sds_t              *metric_label_keys;
    msgpack_object         *point;
    msgpack_object         *attributes_obj;
    msgpack_object_map     *point_map;
    msgpack_object         *bucket_counts_object;
    msgpack_object         *explicit_bounds_object;
    msgpack_object         *count_object;
    msgpack_object         *sum_object;
    struct cmt_histogram_buckets *buckets;
    struct cmt_histogram   *histogram;
    struct cmt_metric      *sample;
    struct cfl_kvlist      *point_metadata;
    uint64_t               *bucket_counts;

    point_bounds = NULL;
    metric_bounds = NULL;
    bucket_counts = NULL;
    metric_name = NULL;
    point_label_keys = NULL;
    point_label_values = NULL;
    metric_label_keys = NULL;
    metric_label_count = 0;
    metric_bound_count = 0;
    histogram = NULL;
    buckets = NULL;
    metric_help = NULL;
    sample = NULL;
    point_metadata = NULL;
    metric_initialized = FLB_FALSE;

    for (index = 0 ; index < data_points->size ; index++) {
        point = &data_points->ptr[index];
        if (point->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        point_map = &point->via.map;

        bucket_counts_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                                    "bucketCounts",
                                                                    0,
                                                                    FLB_TRUE);
        explicit_bounds_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                                      "explicitBounds",
                                                                      0,
                                                                      FLB_TRUE);
        count_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                            "count",
                                                            0,
                                                            FLB_TRUE);
        sum_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                         "sum",
                                                         0,
                                                         FLB_TRUE);
        min_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                         "min",
                                                         0,
                                                         FLB_TRUE);
        max_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                         "max",
                                                         0,
                                                         FLB_TRUE);

        if (bucket_counts_index < 0 ||
            explicit_bounds_index < 0 ||
            count_index < 0) {
            continue;
        }

        bucket_counts_object = &point_map->ptr[bucket_counts_index].val;
        explicit_bounds_object = &point_map->ptr[explicit_bounds_index].val;
        count_object = &point_map->ptr[count_index].val;
        sum_object = NULL;
        if (sum_index >= 0) {
            sum_object = &point_map->ptr[sum_index].val;
        }
        has_sum = (sum_object != NULL);

        result = parse_histogram_bucket_counts(bucket_counts_object,
                                               &bucket_counts,
                                               &bucket_counts_count);
        if (result != 0) {
            continue;
        }

        result = parse_histogram_bounds(explicit_bounds_object,
                                        &point_bounds,
                                        &point_bound_count);
        if (result != 0) {
            flb_free(bucket_counts);
            bucket_counts = NULL;
            continue;
        }

        if (bucket_counts_count != point_bound_count + 1) {
            flb_free(bucket_counts);
            flb_free(point_bounds);
            bucket_counts = NULL;
            point_bounds = NULL;
            continue;
        }

        if (parse_u64_value(count_object, &count) != 0) {
            flb_free(bucket_counts);
            flb_free(point_bounds);
            bucket_counts = NULL;
            point_bounds = NULL;
            continue;
        }

        sum = 0.0;
        if (sum_object != NULL &&
            parse_double_value(sum_object, &sum) != 0) {
            flb_free(bucket_counts);
            flb_free(point_bounds);
            bucket_counts = NULL;
            point_bounds = NULL;
            continue;
        }

        has_min = FLB_FALSE;
        min = 0.0;
        if (min_index >= 0) {
            if (parse_double_value(&point_map->ptr[min_index].val, &min) != 0) {
                flb_free(bucket_counts);
                flb_free(point_bounds);
                bucket_counts = NULL;
                point_bounds = NULL;
                continue;
            }

            has_min = FLB_TRUE;
        }

        has_max = FLB_FALSE;
        max = 0.0;
        if (max_index >= 0) {
            if (parse_double_value(&point_map->ptr[max_index].val, &max) != 0) {
                flb_free(bucket_counts);
                flb_free(point_bounds);
                bucket_counts = NULL;
                point_bounds = NULL;
                continue;
            }

            has_max = FLB_TRUE;
        }

        result = parse_datapoint_timestamp(point_map, &timestamp);
        if (result != 0) {
            flb_free(bucket_counts);
            flb_free(point_bounds);
            bucket_counts = NULL;
            point_bounds = NULL;
            continue;
        }

        attributes_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                                 "attributes",
                                                                 0,
                                                                 FLB_TRUE);
        if (attributes_index >= 0) {
            attributes_obj = &point_map->ptr[attributes_index].val;
        }
        else {
            attributes_obj = NULL;
        }

        point_label_count = 0;
        point_label_keys = NULL;
        point_label_values = NULL;

        result = parse_datapoint_labels(attributes_obj,
                                        &point_label_count,
                                        &point_label_keys,
                                        &point_label_values);
        if (result != 0) {
            destroy_label_arrays(point_label_count,
                                 point_label_keys,
                                 point_label_values);
            flb_free(bucket_counts);
            flb_free(point_bounds);
            bucket_counts = NULL;
            point_bounds = NULL;
            continue;
        }

        if (!metric_initialized) {
            metric_label_count = point_label_count;
            metric_label_keys = point_label_keys;
            point_label_keys = NULL;
            metric_bounds = point_bounds;
            metric_bound_count = point_bound_count;
            point_bounds = NULL;

            metric_name = flb_sds_create_len(name_object->via.str.ptr,
                                             name_object->via.str.size);
            if (metric_name == NULL) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(metric_bounds);
                flb_free(bucket_counts);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            result = get_metric_help_string(metric_map, &metric_help);
            if (result != 0) {
                flb_sds_destroy(metric_name);
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(metric_bounds);
                flb_free(bucket_counts);
                return result;
            }

            buckets = cmt_histogram_buckets_create_size(metric_bounds,
                                                        metric_bound_count);
            if (buckets == NULL) {
                flb_sds_destroy(metric_name);
                flb_sds_destroy(metric_help);
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(metric_bounds);
                flb_free(bucket_counts);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            histogram = cmt_histogram_create(context,
                                             "",
                                             "",
                                             metric_name,
                                             metric_help,
                                             buckets,
                                             metric_label_count,
                                             (char **) metric_label_keys);
            flb_sds_destroy(metric_name);
            flb_sds_destroy(metric_help);
            metric_help = NULL;

            if (histogram == NULL) {
                cmt_histogram_buckets_destroy(buckets);
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(metric_bounds);
                flb_free(bucket_counts);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            result = set_metric_unit(histogram->map, metric_map);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(metric_bounds);
                flb_free(bucket_counts);
                cmt_histogram_destroy(histogram);
                return result;
            }

            result = clone_metric_metadata(context, histogram->map, metric_map);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(metric_bounds);
                flb_free(bucket_counts);
                cmt_histogram_destroy(histogram);
                return result;
            }

            histogram->aggregation_type = aggregation_type;
            metric_initialized = FLB_TRUE;
        }
        else {
            result = check_label_layout(metric_label_count,
                                        metric_label_keys,
                                        point_label_count,
                                        point_label_keys);
            if (result == 0) {
                result = check_double_array_layout(metric_bound_count,
                                                   metric_bounds,
                                                   point_bound_count,
                                                   point_bounds);
            }

            destroy_label_arrays(point_label_count, point_label_keys, NULL);
            flb_free(point_bounds);
            point_bounds = NULL;

            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                flb_free(bucket_counts);
                bucket_counts = NULL;
                continue;
            }
        }

        cmt_histogram_set_default(histogram,
                                  timestamp,
                                  bucket_counts,
                                  sum,
                                  count,
                                  point_label_count,
                                  (char **) point_label_values);

        sample = cmt_map_metric_get(&histogram->opts,
                                    histogram->map,
                                    point_label_count,
                                    (char **) point_label_values,
                                    CMT_FALSE);
        if (sample != NULL) {
            point_metadata = get_or_create_data_point_metadata_context(context,
                                                                       histogram->map,
                                                                       sample,
                                                                       timestamp);
            if (point_metadata != NULL) {
                append_common_datapoint_metadata(point_metadata, point_map);
                cfl_kvlist_insert_bool(point_metadata, "has_sum", has_sum);

                if (has_min) {
                    cfl_kvlist_insert_bool(point_metadata, "has_min", CFL_TRUE);
                    cfl_kvlist_insert_double(point_metadata, "min", min);
                }

                if (has_max) {
                    cfl_kvlist_insert_bool(point_metadata, "has_max", CFL_TRUE);
                    cfl_kvlist_insert_double(point_metadata, "max", max);
                }
            }
        }

        destroy_label_arrays(point_label_count, NULL, point_label_values);
        flb_free(bucket_counts);
        bucket_counts = NULL;
    }

    destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
    flb_free(metric_bounds);

    return 0;
}

static int process_metric_summary_data_points(struct cmt *context,
                                              msgpack_object_map *metric_map,
                                              msgpack_object *name_object,
                                              msgpack_object_array *data_points)
{
    int                 index;
    int                 result;
    int                 metric_initialized;
    int                 point_label_count;
    int                 metric_label_count;
    int                 quantile_values_index;
    int                 count_index;
    int                 sum_index;
    int                 attributes_index;
    uint64_t            timestamp;
    uint64_t            count;
    size_t              point_quantile_count;
    size_t              metric_quantile_count;
    double              sum;
    double             *point_quantiles;
    double             *point_quantile_values;
    double             *metric_quantiles;
    flb_sds_t           metric_name;
    flb_sds_t           metric_help;
    flb_sds_t          *point_label_keys;
    flb_sds_t          *point_label_values;
    flb_sds_t          *metric_label_keys;
    msgpack_object     *point;
    msgpack_object     *attributes_obj;
    msgpack_object_map *point_map;
    msgpack_object     *quantile_values_object;
    msgpack_object     *count_object;
    msgpack_object     *sum_object;
    struct cmt_summary *summary;
    struct cmt_metric  *sample;
    struct cfl_kvlist  *point_metadata;

    point_quantiles = NULL;
    point_quantile_values = NULL;
    metric_quantiles = NULL;
    metric_name = NULL;
    point_label_keys = NULL;
    point_label_values = NULL;
    metric_label_keys = NULL;
    metric_label_count = 0;
    metric_quantile_count = 0;
    summary = NULL;
    metric_help = NULL;
    sample = NULL;
    point_metadata = NULL;
    metric_initialized = FLB_FALSE;

    for (index = 0 ; index < data_points->size ; index++) {
        point = &data_points->ptr[index];
        if (point->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        point_map = &point->via.map;

        quantile_values_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                                      "quantileValues",
                                                                      0,
                                                                      FLB_TRUE);
        count_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                            "count",
                                                            0,
                                                            FLB_TRUE);
        sum_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                         "sum",
                                                         0,
                                                         FLB_TRUE);

        if (count_index < 0 || sum_index < 0) {
            continue;
        }

        if (quantile_values_index >= 0) {
            quantile_values_object = &point_map->ptr[quantile_values_index].val;
        }
        else {
            quantile_values_object = NULL;
        }

        count_object = &point_map->ptr[count_index].val;
        sum_object = &point_map->ptr[sum_index].val;

        result = parse_summary_quantile_values(quantile_values_object,
                                               &point_quantiles,
                                               &point_quantile_values,
                                               &point_quantile_count);
        if (result != 0) {
            continue;
        }

        if (parse_u64_value(count_object, &count) != 0) {
            flb_free(point_quantiles);
            flb_free(point_quantile_values);
            point_quantiles = NULL;
            point_quantile_values = NULL;
            continue;
        }

        if (parse_double_value(sum_object, &sum) != 0) {
            flb_free(point_quantiles);
            flb_free(point_quantile_values);
            point_quantiles = NULL;
            point_quantile_values = NULL;
            continue;
        }

        result = parse_datapoint_timestamp(point_map, &timestamp);
        if (result != 0) {
            flb_free(point_quantiles);
            flb_free(point_quantile_values);
            point_quantiles = NULL;
            point_quantile_values = NULL;
            continue;
        }

        attributes_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                                 "attributes",
                                                                 0,
                                                                 FLB_TRUE);
        if (attributes_index >= 0) {
            attributes_obj = &point_map->ptr[attributes_index].val;
        }
        else {
            attributes_obj = NULL;
        }

        point_label_count = 0;
        point_label_keys = NULL;
        point_label_values = NULL;

        result = parse_datapoint_labels(attributes_obj,
                                        &point_label_count,
                                        &point_label_keys,
                                        &point_label_values);
        if (result != 0) {
            destroy_label_arrays(point_label_count,
                                 point_label_keys,
                                 point_label_values);
            flb_free(point_quantiles);
            flb_free(point_quantile_values);
            point_quantiles = NULL;
            point_quantile_values = NULL;
            continue;
        }

        if (!metric_initialized) {
            metric_label_count = point_label_count;
            metric_label_keys = point_label_keys;
            point_label_keys = NULL;
            metric_quantiles = point_quantiles;
            metric_quantile_count = point_quantile_count;
            point_quantiles = NULL;

            metric_name = flb_sds_create_len(name_object->via.str.ptr,
                                             name_object->via.str.size);
            if (metric_name == NULL) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(metric_quantiles);
                flb_free(point_quantile_values);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            result = get_metric_help_string(metric_map, &metric_help);
            if (result != 0) {
                flb_sds_destroy(metric_name);
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(metric_quantiles);
                flb_free(point_quantile_values);
                return result;
            }

            summary = cmt_summary_create(context,
                                         "",
                                         "",
                                         metric_name,
                                         metric_help,
                                         metric_quantile_count,
                                         metric_quantiles,
                                         metric_label_count,
                                         (char **) metric_label_keys);
            flb_sds_destroy(metric_name);
            flb_sds_destroy(metric_help);
            metric_help = NULL;

            if (summary == NULL) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(metric_quantiles);
                flb_free(point_quantile_values);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            result = set_metric_unit(summary->map, metric_map);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(metric_quantiles);
                flb_free(point_quantile_values);
                cmt_summary_destroy(summary);
                return result;
            }

            result = clone_metric_metadata(context, summary->map, metric_map);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(metric_quantiles);
                flb_free(point_quantile_values);
                cmt_summary_destroy(summary);
                return result;
            }

            metric_initialized = FLB_TRUE;
        }
        else {
            result = check_label_layout(metric_label_count,
                                        metric_label_keys,
                                        point_label_count,
                                        point_label_keys);
            if (result == 0) {
                result = check_double_array_layout(metric_quantile_count,
                                                   metric_quantiles,
                                                   point_quantile_count,
                                                   point_quantiles);
            }

            destroy_label_arrays(point_label_count, point_label_keys, NULL);
            flb_free(point_quantiles);
            point_quantiles = NULL;

            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                flb_free(point_quantile_values);
                point_quantile_values = NULL;
                continue;
            }
        }

        cmt_summary_set_default(summary,
                                timestamp,
                                point_quantile_values,
                                sum,
                                count,
                                point_label_count,
                                (char **) point_label_values);

        sample = cmt_map_metric_get(&summary->opts,
                                    summary->map,
                                    point_label_count,
                                    (char **) point_label_values,
                                    CMT_FALSE);
        if (sample != NULL) {
            point_metadata = get_or_create_data_point_metadata_context(context,
                                                                       summary->map,
                                                                       sample,
                                                                       timestamp);
            if (point_metadata != NULL) {
                append_common_datapoint_metadata(point_metadata, point_map);
            }
        }

        destroy_label_arrays(point_label_count, NULL, point_label_values);
        flb_free(point_quantile_values);
        point_quantile_values = NULL;
    }

    destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
    flb_free(metric_quantiles);

    return 0;
}

static int process_metric_exponential_histogram_data_points(
                                                struct cmt *context,
                                                msgpack_object_map *metric_map,
                                                msgpack_object *name_object,
                                                int aggregation_type,
                                                msgpack_object_array *data_points)
{
    int                     index;
    int                     result;
    int                     metric_initialized;
    int                     point_label_count;
    int                     metric_label_count;
    int                     scale_index;
    int                     zero_count_index;
    int                     zero_threshold_index;
    int                     positive_index;
    int                     negative_index;
    int                     count_index;
    int                     sum_index;
    int                     min_index;
    int                     max_index;
    int                     attributes_index;
    int32_t                 scale;
    int32_t                 positive_offset;
    int32_t                 negative_offset;
    uint64_t                timestamp;
    uint64_t                count;
    uint64_t                zero_count;
    int                     sum_set;
    int                     has_min;
    int                     has_max;
    size_t                  positive_count;
    size_t                  negative_count;
    double                  sum;
    double                  zero_threshold;
    double                  min;
    double                  max;
    flb_sds_t               metric_name;
    flb_sds_t               metric_help;
    flb_sds_t              *point_label_keys;
    flb_sds_t              *point_label_values;
    flb_sds_t              *metric_label_keys;
    msgpack_object         *point;
    msgpack_object         *attributes_obj;
    msgpack_object_map     *point_map;
    msgpack_object         *positive_object;
    msgpack_object         *negative_object;
    msgpack_object         *scale_object;
    msgpack_object         *zero_count_object;
    msgpack_object         *zero_threshold_object;
    msgpack_object         *count_object;
    msgpack_object         *sum_object;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_metric      *sample;
    struct cfl_kvlist      *point_metadata;
    uint64_t               *positive_counts;
    uint64_t               *negative_counts;

    positive_counts = NULL;
    negative_counts = NULL;
    metric_name = NULL;
    metric_help = NULL;
    point_label_keys = NULL;
    point_label_values = NULL;
    metric_label_keys = NULL;
    metric_label_count = 0;
    exp_histogram = NULL;
    sample = NULL;
    point_metadata = NULL;
    metric_initialized = FLB_FALSE;

    for (index = 0 ; index < data_points->size ; index++) {
        point = &data_points->ptr[index];
        if (point->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        point_map = &point->via.map;

        scale_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                            "scale",
                                                            0,
                                                            FLB_TRUE);
        count_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                            "count",
                                                            0,
                                                            FLB_TRUE);
        sum_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                          "sum",
                                                          0,
                                                          FLB_TRUE);
        min_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                          "min",
                                                          0,
                                                          FLB_TRUE);
        max_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                          "max",
                                                          0,
                                                          FLB_TRUE);
        zero_count_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                                 "zeroCount",
                                                                 0,
                                                                 FLB_TRUE);
        zero_threshold_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                                     "zeroThreshold",
                                                                     0,
                                                                     FLB_TRUE);
        positive_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                               "positive",
                                                               0,
                                                               FLB_TRUE);
        negative_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                               "negative",
                                                               0,
                                                               FLB_TRUE);

        if (scale_index < 0 || count_index < 0) {
            continue;
        }

        scale_object = &point_map->ptr[scale_index].val;
        count_object = &point_map->ptr[count_index].val;
        sum_object = NULL;
        if (sum_index >= 0) {
            sum_object = &point_map->ptr[sum_index].val;
        }

        if (zero_count_index >= 0) {
            zero_count_object = &point_map->ptr[zero_count_index].val;
        }
        else {
            zero_count_object = NULL;
        }

        if (zero_threshold_index >= 0) {
            zero_threshold_object = &point_map->ptr[zero_threshold_index].val;
        }
        else {
            zero_threshold_object = NULL;
        }

        if (positive_index >= 0) {
            positive_object = &point_map->ptr[positive_index].val;
        }
        else {
            positive_object = NULL;
        }

        if (negative_index >= 0) {
            negative_object = &point_map->ptr[negative_index].val;
        }
        else {
            negative_object = NULL;
        }

        if (parse_i32_value(scale_object, &scale) != 0) {
            continue;
        }

        if (parse_u64_value(count_object, &count) != 0) {
            continue;
        }

        sum_set = FLB_FALSE;
        sum = 0.0;
        if (sum_object != NULL) {
            if (parse_double_value(sum_object, &sum) != 0) {
                continue;
            }
            sum_set = FLB_TRUE;
        }

        has_min = FLB_FALSE;
        min = 0.0;
        if (min_index >= 0) {
            if (parse_double_value(&point_map->ptr[min_index].val, &min) != 0) {
                continue;
            }
            has_min = FLB_TRUE;
        }

        has_max = FLB_FALSE;
        max = 0.0;
        if (max_index >= 0) {
            if (parse_double_value(&point_map->ptr[max_index].val, &max) != 0) {
                continue;
            }
            has_max = FLB_TRUE;
        }

        zero_count = 0;
        if (zero_count_object != NULL &&
            parse_u64_value(zero_count_object, &zero_count) != 0) {
            continue;
        }

        zero_threshold = 0.0;
        if (zero_threshold_object != NULL &&
            parse_double_value(zero_threshold_object, &zero_threshold) != 0) {
            continue;
        }

        result = parse_exponential_histogram_buckets(positive_object,
                                                     &positive_offset,
                                                     &positive_counts,
                                                     &positive_count);
        if (result != 0) {
            continue;
        }

        result = parse_exponential_histogram_buckets(negative_object,
                                                     &negative_offset,
                                                     &negative_counts,
                                                     &negative_count);
        if (result != 0) {
            flb_free(positive_counts);
            positive_counts = NULL;
            continue;
        }

        result = parse_datapoint_timestamp(point_map, &timestamp);
        if (result != 0) {
            flb_free(positive_counts);
            flb_free(negative_counts);
            positive_counts = NULL;
            negative_counts = NULL;
            continue;
        }

        attributes_index = flb_otel_utils_find_map_entry_by_key(point_map,
                                                                 "attributes",
                                                                 0,
                                                                 FLB_TRUE);
        if (attributes_index >= 0) {
            attributes_obj = &point_map->ptr[attributes_index].val;
        }
        else {
            attributes_obj = NULL;
        }

        point_label_count = 0;
        point_label_keys = NULL;
        point_label_values = NULL;

        result = parse_datapoint_labels(attributes_obj,
                                        &point_label_count,
                                        &point_label_keys,
                                        &point_label_values);
        if (result != 0) {
            destroy_label_arrays(point_label_count,
                                 point_label_keys,
                                 point_label_values);
            flb_free(positive_counts);
            flb_free(negative_counts);
            positive_counts = NULL;
            negative_counts = NULL;
            continue;
        }

        if (!metric_initialized) {
            metric_label_count = point_label_count;
            metric_label_keys = point_label_keys;
            point_label_keys = NULL;

            metric_name = flb_sds_create_len(name_object->via.str.ptr,
                                             name_object->via.str.size);
            if (metric_name == NULL) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(positive_counts);
                flb_free(negative_counts);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            result = get_metric_help_string(metric_map, &metric_help);
            if (result != 0) {
                flb_sds_destroy(metric_name);
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(positive_counts);
                flb_free(negative_counts);
                return result;
            }

            exp_histogram = cmt_exp_histogram_create(context,
                                                     "",
                                                     "",
                                                     metric_name,
                                                     metric_help,
                                                     metric_label_count,
                                                     (char **) metric_label_keys);
            flb_sds_destroy(metric_name);
            flb_sds_destroy(metric_help);
            metric_help = NULL;

            if (exp_histogram == NULL) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(positive_counts);
                flb_free(negative_counts);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            result = set_metric_unit(exp_histogram->map, metric_map);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(positive_counts);
                flb_free(negative_counts);
                cmt_exp_histogram_destroy(exp_histogram);
                return result;
            }

            result = clone_metric_metadata(context, exp_histogram->map, metric_map);
            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                flb_free(positive_counts);
                flb_free(negative_counts);
                cmt_exp_histogram_destroy(exp_histogram);
                return result;
            }

            exp_histogram->aggregation_type = aggregation_type;
            metric_initialized = FLB_TRUE;
        }
        else {
            result = check_label_layout(metric_label_count,
                                        metric_label_keys,
                                        point_label_count,
                                        point_label_keys);

            destroy_label_arrays(point_label_count, point_label_keys, NULL);

            if (result != 0) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                flb_free(positive_counts);
                flb_free(negative_counts);
                positive_counts = NULL;
                negative_counts = NULL;
                continue;
            }
        }

        result = cmt_exp_histogram_set_default(exp_histogram,
                                               timestamp,
                                               scale,
                                               zero_count,
                                               zero_threshold,
                                               positive_offset,
                                               positive_count,
                                               positive_counts,
                                               negative_offset,
                                               negative_count,
                                               negative_counts,
                                               sum_set,
                                               sum,
                                               count,
                                               point_label_count,
                                               (char **) point_label_values);
        if (result != 0) {
            destroy_label_arrays(point_label_count, NULL, point_label_values);
            flb_free(positive_counts);
            flb_free(negative_counts);
            return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        sample = cmt_map_metric_get(&exp_histogram->opts,
                                    exp_histogram->map,
                                    point_label_count,
                                    (char **) point_label_values,
                                    CMT_FALSE);
        if (sample != NULL) {
            point_metadata = get_or_create_data_point_metadata_context(context,
                                                                       exp_histogram->map,
                                                                       sample,
                                                                       timestamp);
            if (point_metadata != NULL) {
                append_common_datapoint_metadata(point_metadata, point_map);
                cfl_kvlist_insert_bool(point_metadata, "has_sum", sum_set);

                if (has_min) {
                    cfl_kvlist_insert_bool(point_metadata, "has_min", CFL_TRUE);
                    cfl_kvlist_insert_double(point_metadata, "min", min);
                }

                if (has_max) {
                    cfl_kvlist_insert_bool(point_metadata, "has_max", CFL_TRUE);
                    cfl_kvlist_insert_double(point_metadata, "max", max);
                }
            }
        }

        destroy_label_arrays(point_label_count, NULL, point_label_values);
        flb_free(positive_counts);
        flb_free(negative_counts);
        positive_counts = NULL;
        negative_counts = NULL;
    }

    destroy_label_arrays(metric_label_count, metric_label_keys, NULL);

    return 0;
}

static int decode_metric_gauge(struct cmt *context,
                               msgpack_object_map *metric_map,
                               msgpack_object *name_object)
{
    int                 result;
    int                 data_points_index;
    msgpack_object     *gauge_object;
    msgpack_object     *data_points_object;
    msgpack_object_map *gauge_map;

    result = flb_otel_utils_find_map_entry_by_key(metric_map, "gauge", 0, FLB_TRUE);
    if (result < 0) {
        return 0;
    }

    gauge_object = &metric_map->ptr[result].val;
    if (gauge_object->type != MSGPACK_OBJECT_MAP) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    gauge_map = &gauge_object->via.map;
    data_points_index = flb_otel_utils_find_map_entry_by_key(gauge_map,
                                                              "dataPoints",
                                                              0,
                                                              FLB_TRUE);
    if (data_points_index < 0) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    data_points_object = &gauge_map->ptr[data_points_index].val;
    if (data_points_object->type != MSGPACK_OBJECT_ARRAY) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    return process_metric_gauge_data_points(context,
                                            metric_map,
                                            name_object,
                                            &data_points_object->via.array);
}

static int decode_metric_sum(struct cmt *context,
                             msgpack_object_map *metric_map,
                             msgpack_object *name_object)
{
    int                   result;
    int                   data_points_index;
    int                   monotonic_index;
    int                   temporality_index;
    msgpack_object       *sum_object;
    msgpack_object       *data_points_object;
    msgpack_object_map   *sum_map;
    int                  allow_reset;
    int                  aggregation_type;

    result = flb_otel_utils_find_map_entry_by_key(metric_map, "sum", 0, FLB_TRUE);
    if (result < 0) {
        return 0;
    }

    sum_object = &metric_map->ptr[result].val;
    if (sum_object->type != MSGPACK_OBJECT_MAP) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    sum_map = &sum_object->via.map;
    data_points_index = flb_otel_utils_find_map_entry_by_key(sum_map,
                                                              "dataPoints",
                                                              0,
                                                              FLB_TRUE);
    if (data_points_index < 0) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    data_points_object = &sum_map->ptr[data_points_index].val;
    if (data_points_object->type != MSGPACK_OBJECT_ARRAY) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    allow_reset = FLB_FALSE;
    aggregation_type = CMT_AGGREGATION_TYPE_UNSPECIFIED;

    monotonic_index = flb_otel_utils_find_map_entry_by_key(sum_map,
                                                            "isMonotonic",
                                                            0,
                                                            FLB_TRUE);
    if (monotonic_index >= 0 &&
        sum_map->ptr[monotonic_index].val.type == MSGPACK_OBJECT_BOOLEAN &&
        !sum_map->ptr[monotonic_index].val.via.boolean) {
        allow_reset = FLB_TRUE;
    }

    temporality_index = flb_otel_utils_find_map_entry_by_key(sum_map,
                                                              "aggregationTemporality",
                                                              0,
                                                              FLB_TRUE);
    if (temporality_index >= 0) {
        if (sum_map->ptr[temporality_index].val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            if (sum_map->ptr[temporality_index].val.via.u64 == 1) {
                aggregation_type = CMT_AGGREGATION_TYPE_DELTA;
            }
            else if (sum_map->ptr[temporality_index].val.via.u64 == 2) {
                aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;
            }
        }
    }

    return process_metric_sum_data_points(context,
                                          metric_map,
                                          name_object,
                                          allow_reset,
                                          aggregation_type,
                                          &data_points_object->via.array);
}

static int decode_metric_histogram(struct cmt *context,
                                   msgpack_object_map *metric_map,
                                   msgpack_object *name_object)
{
    int                 result;
    int                 data_points_index;
    int                 temporality_index;
    int                 aggregation_type;
    msgpack_object     *histogram_object;
    msgpack_object     *data_points_object;
    msgpack_object_map *histogram_map;

    result = flb_otel_utils_find_map_entry_by_key(metric_map,
                                                   "histogram",
                                                   0,
                                                   FLB_TRUE);
    if (result < 0) {
        return 0;
    }

    histogram_object = &metric_map->ptr[result].val;
    if (histogram_object->type != MSGPACK_OBJECT_MAP) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    histogram_map = &histogram_object->via.map;
    data_points_index = flb_otel_utils_find_map_entry_by_key(histogram_map,
                                                              "dataPoints",
                                                              0,
                                                              FLB_TRUE);
    if (data_points_index < 0) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    data_points_object = &histogram_map->ptr[data_points_index].val;
    if (data_points_object->type != MSGPACK_OBJECT_ARRAY) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    aggregation_type = CMT_AGGREGATION_TYPE_UNSPECIFIED;
    temporality_index = flb_otel_utils_find_map_entry_by_key(histogram_map,
                                                              "aggregationTemporality",
                                                              0,
                                                              FLB_TRUE);
    if (temporality_index >= 0) {
        if (histogram_map->ptr[temporality_index].val.type ==
            MSGPACK_OBJECT_POSITIVE_INTEGER) {
            if (histogram_map->ptr[temporality_index].val.via.u64 == 1) {
                aggregation_type = CMT_AGGREGATION_TYPE_DELTA;
            }
            else if (histogram_map->ptr[temporality_index].val.via.u64 == 2) {
                aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;
            }
        }
    }

    return process_metric_histogram_data_points(context,
                                                metric_map,
                                                name_object,
                                                aggregation_type,
                                                &data_points_object->via.array);
}

static int decode_metric_summary(struct cmt *context,
                                 msgpack_object_map *metric_map,
                                 msgpack_object *name_object)
{
    int                 result;
    int                 data_points_index;
    msgpack_object     *summary_object;
    msgpack_object     *data_points_object;
    msgpack_object_map *summary_map;

    result = flb_otel_utils_find_map_entry_by_key(metric_map,
                                                   "summary",
                                                   0,
                                                   FLB_TRUE);
    if (result < 0) {
        return 0;
    }

    summary_object = &metric_map->ptr[result].val;
    if (summary_object->type != MSGPACK_OBJECT_MAP) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    summary_map = &summary_object->via.map;
    data_points_index = flb_otel_utils_find_map_entry_by_key(summary_map,
                                                              "dataPoints",
                                                              0,
                                                              FLB_TRUE);
    if (data_points_index < 0) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    data_points_object = &summary_map->ptr[data_points_index].val;
    if (data_points_object->type != MSGPACK_OBJECT_ARRAY) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    return process_metric_summary_data_points(context,
                                              metric_map,
                                              name_object,
                                              &data_points_object->via.array);
}

static int decode_metric_exponential_histogram(struct cmt *context,
                                               msgpack_object_map *metric_map,
                                               msgpack_object *name_object)
{
    int                 result;
    int                 data_points_index;
    int                 temporality_index;
    int                 aggregation_type;
    msgpack_object     *histogram_object;
    msgpack_object     *data_points_object;
    msgpack_object_map *histogram_map;

    result = flb_otel_utils_find_map_entry_by_key(metric_map,
                                                   "exponentialHistogram",
                                                   0,
                                                   FLB_TRUE);
    if (result < 0) {
        return 0;
    }

    histogram_object = &metric_map->ptr[result].val;
    if (histogram_object->type != MSGPACK_OBJECT_MAP) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    histogram_map = &histogram_object->via.map;
    data_points_index = flb_otel_utils_find_map_entry_by_key(histogram_map,
                                                              "dataPoints",
                                                              0,
                                                              FLB_TRUE);
    if (data_points_index < 0) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    data_points_object = &histogram_map->ptr[data_points_index].val;
    if (data_points_object->type != MSGPACK_OBJECT_ARRAY) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    aggregation_type = CMT_AGGREGATION_TYPE_UNSPECIFIED;
    temporality_index = flb_otel_utils_find_map_entry_by_key(histogram_map,
                                                              "aggregationTemporality",
                                                              0,
                                                              FLB_TRUE);
    if (temporality_index >= 0) {
        if (histogram_map->ptr[temporality_index].val.type ==
            MSGPACK_OBJECT_POSITIVE_INTEGER) {
            if (histogram_map->ptr[temporality_index].val.via.u64 == 1) {
                aggregation_type = CMT_AGGREGATION_TYPE_DELTA;
            }
            else if (histogram_map->ptr[temporality_index].val.via.u64 == 2) {
                aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;
            }
        }
    }

    return process_metric_exponential_histogram_data_points(
                                                context,
                                                metric_map,
                                                name_object,
                                                aggregation_type,
                                                &data_points_object->via.array);
}

static int decode_metric_entry(struct cmt *context, msgpack_object *metric_object)
{
    int               result;
    int               name_index;
    int               gauge_index;
    int               sum_index;
    int               histogram_index;
    int               summary_index;
    int               exponential_histogram_index;
    msgpack_object   *name_object;
    msgpack_object_map *metric_map;

    if (metric_object->type != MSGPACK_OBJECT_MAP) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    metric_map = &metric_object->via.map;

    name_index = flb_otel_utils_find_map_entry_by_key(metric_map, "name", 0, FLB_TRUE);
    if (name_index < 0) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    name_object = &metric_map->ptr[name_index].val;
    if (name_object->type != MSGPACK_OBJECT_STR) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    gauge_index = flb_otel_utils_find_map_entry_by_key(metric_map, "gauge", 0, FLB_TRUE);
    sum_index = flb_otel_utils_find_map_entry_by_key(metric_map, "sum", 0, FLB_TRUE);
    histogram_index = flb_otel_utils_find_map_entry_by_key(metric_map,
                                                            "histogram",
                                                            0,
                                                            FLB_TRUE);
    summary_index = flb_otel_utils_find_map_entry_by_key(metric_map,
                                                         "summary",
                                                         0,
                                                         FLB_TRUE);
    exponential_histogram_index = flb_otel_utils_find_map_entry_by_key(
                                                            metric_map,
                                                            "exponentialHistogram",
                                                            0,
                                                            FLB_TRUE);

    if (gauge_index < 0 && sum_index < 0 &&
        histogram_index < 0 && summary_index < 0 &&
        exponential_histogram_index < 0) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    if (gauge_index >= 0) {
        result = decode_metric_gauge(context, metric_map, name_object);
        if (result != 0) {
            return result;
        }
    }

    if (sum_index >= 0) {
        result = decode_metric_sum(context, metric_map, name_object);
        if (result != 0) {
            return result;
        }
    }

    if (histogram_index >= 0) {
        result = decode_metric_histogram(context, metric_map, name_object);
        if (result != 0) {
            return result;
        }
    }

    if (summary_index >= 0) {
        result = decode_metric_summary(context, metric_map, name_object);
        if (result != 0) {
            return result;
        }
    }

    if (exponential_histogram_index >= 0) {
        result = decode_metric_exponential_histogram(context,
                                                     metric_map,
                                                     name_object);
        if (result != 0) {
            return result;
        }
    }

    return 0;
}

static int decode_scope_metrics_entry(struct cfl_list *context_list,
                                      msgpack_object *scope_metrics_object)
{
    int                 index;
    int                 metrics_index;
    int                 result;
    msgpack_object     *metrics_object;
    msgpack_object_array *metrics_array;
    struct cmt         *context;

    if (scope_metrics_object->type != MSGPACK_OBJECT_MAP) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    metrics_index = flb_otel_utils_find_map_entry_by_key(&scope_metrics_object->via.map,
                                                          "metrics",
                                                          0,
                                                          FLB_TRUE);
    if (metrics_index < 0) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    metrics_object = &scope_metrics_object->via.map.ptr[metrics_index].val;
    if (metrics_object->type != MSGPACK_OBJECT_ARRAY) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    context = cmt_create();
    if (context == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    result = cfl_kvlist_insert_string(context->internal_metadata,
                                      "producer",
                                      "opentelemetry");
    if (result != 0) {
        cmt_destroy(context);
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    metrics_array = &metrics_object->via.array;

    for (index = 0 ; index < metrics_array->size ; index++) {
        result = decode_metric_entry(context, &metrics_array->ptr[index]);
        if (result != 0) {
            cmt_destroy(context);
            return result;
        }
    }

    cfl_list_add(&context->_head, context_list);

    return 0;
}

static int decode_resource_metrics_entry(struct cfl_list *context_list,
                                         msgpack_object *resource_metrics_object)
{
    int                 index;
    int                 scope_metrics_index;
    int                 result;
    msgpack_object     *scope_metrics_object;
    msgpack_object_array *scope_metrics_array;

    if (resource_metrics_object->type != MSGPACK_OBJECT_MAP) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    scope_metrics_index = flb_otel_utils_find_map_entry_by_key(&resource_metrics_object->via.map,
                                                                "scopeMetrics",
                                                                0,
                                                                FLB_TRUE);
    if (scope_metrics_index < 0) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    scope_metrics_object = &resource_metrics_object->via.map.ptr[scope_metrics_index].val;
    if (scope_metrics_object->type != MSGPACK_OBJECT_ARRAY) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    scope_metrics_array = &scope_metrics_object->via.array;
    for (index = 0 ; index < scope_metrics_array->size ; index++) {
        result = decode_scope_metrics_entry(context_list, &scope_metrics_array->ptr[index]);
        if (result != 0) {
            return result;
        }
    }

    return 0;
}

int flb_opentelemetry_metrics_json_to_cmt(struct cfl_list *context_list,
                                          const char *body, size_t len)
{
    int                  result;
    int                  index;
    int                  root_type;
    int                  resource_metrics_index;
    char                *msgpack_body;
    size_t               msgpack_body_size;
    size_t               off;
    msgpack_unpacked     result_set;
    msgpack_object      *root_object;
    msgpack_object      *resource_metrics_object;
    msgpack_object_array *resource_metrics;

    msgpack_body = NULL;
    msgpack_body_size = 0;
    off = 0;

    cfl_list_init(context_list);

    result = flb_pack_json(body, len, &msgpack_body, &msgpack_body_size,
                           &root_type, NULL);
    if (result != 0) {
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    msgpack_unpacked_init(&result_set);

    if (!msgpack_unpack_next(&result_set, msgpack_body, msgpack_body_size, &off)) {
        flb_free(msgpack_body);
        msgpack_unpacked_destroy(&result_set);
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    root_object = &result_set.data;
    if (root_object->type != MSGPACK_OBJECT_MAP) {
        flb_free(msgpack_body);
        msgpack_unpacked_destroy(&result_set);
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    resource_metrics_index = flb_otel_utils_find_map_entry_by_key(&root_object->via.map,
                                                                   "resourceMetrics",
                                                                   0,
                                                                   FLB_TRUE);
    if (resource_metrics_index < 0) {
        flb_free(msgpack_body);
        msgpack_unpacked_destroy(&result_set);
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    resource_metrics_object = &root_object->via.map.ptr[resource_metrics_index].val;
    if (resource_metrics_object->type != MSGPACK_OBJECT_ARRAY) {
        flb_free(msgpack_body);
        msgpack_unpacked_destroy(&result_set);
        return OTEL_METRICS_JSON_DECODER_ERROR;
    }

    resource_metrics = &resource_metrics_object->via.array;
    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == CMT_DECODE_OPENTELEMETRY_SUCCESS && index < resource_metrics->size ;
         index++) {
        result = decode_resource_metrics_entry(context_list,
                                               &resource_metrics->ptr[index]);
    }

    if (result != CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        destroy_context_list(context_list);
    }

    flb_free(msgpack_body);
    msgpack_unpacked_destroy(&result_set);

    return result;
}
