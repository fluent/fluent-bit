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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <cmetrics/cmt_gauge.h>

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

static int object_to_sds(msgpack_object *obj, flb_sds_t *out)
{
    flb_sds_t value;

    value = NULL;

    if (obj->type == MSGPACK_OBJECT_STR) {
        value = flb_sds_create_len(obj->via.str.ptr, obj->via.str.size);
    }
    else if (obj->type == MSGPACK_OBJECT_BOOLEAN) {
        if (obj->via.boolean) {
            value = flb_sds_create("true");
        }
        else {
            value = flb_sds_create("false");
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

static int process_metric_gauge_data_points(struct cmt *context,
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
    flb_sds_t       metric_name;

    metric_label_keys = NULL;
    metric_label_count = 0;
    point_label_keys = NULL;
    point_label_values = NULL;
    gauge = NULL;
    metric_name = NULL;

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

        if (metric_label_keys == NULL) {
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

            gauge = cmt_gauge_create(context, "", "",
                                     metric_name,
                                     "-", metric_label_count,
                                     (char **) metric_label_keys);
            flb_sds_destroy(metric_name);

            if (gauge == NULL) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }
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

        destroy_label_arrays(point_label_count, NULL, point_label_values);
    }

    destroy_label_arrays(metric_label_count, metric_label_keys, NULL);

    return 0;
}

static int process_metric_sum_data_points(struct cmt *context,
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
    flb_sds_t       metric_name;

    metric_label_keys = NULL;
    metric_label_count = 0;
    point_label_keys = NULL;
    point_label_values = NULL;
    counter = NULL;
    metric_name = NULL;

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

        if (metric_label_keys == NULL) {
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

            counter = cmt_counter_create(context, "", "",
                                         metric_name,
                                         "-", metric_label_count,
                                         (char **) metric_label_keys);
            flb_sds_destroy(metric_name);

            if (counter == NULL) {
                destroy_label_arrays(point_label_count, NULL, point_label_values);
                destroy_label_arrays(metric_label_count, metric_label_keys, NULL);
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            if (allow_reset) {
                cmt_counter_allow_reset(counter);
            }

            counter->aggregation_type = aggregation_type;
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

        destroy_label_arrays(point_label_count, NULL, point_label_values);
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
                                          name_object,
                                          allow_reset,
                                          aggregation_type,
                                          &data_points_object->via.array);
}

static int decode_metric_entry(struct cmt *context, msgpack_object *metric_object)
{
    int               result;
    int               name_index;
    int               gauge_index;
    int               sum_index;
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

    if (gauge_index < 0 && sum_index < 0) {
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
