/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_sds.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_compat.h>
#include <cmetrics/cmt_variant.h>
#include <cmetrics/cmt_decode_opentelemetry.h>

static struct cmt_variant *clone_variant(Opentelemetry__Proto__Common__V1__AnyValue *source);

static int clone_array(struct cmt_array *target,
                       Opentelemetry__Proto__Common__V1__ArrayValue *source);
static int clone_array_entry(struct cmt_array *target,
                             Opentelemetry__Proto__Common__V1__AnyValue *source);
static int clone_kvlist(struct cmt_kvlist *target,
                                Opentelemetry__Proto__Common__V1__KeyValueList *source);
static int clone_kvlist_entry(struct cmt_kvlist *target,
                           Opentelemetry__Proto__Common__V1__KeyValue *source);

static struct cmt_map_label *create_label(char *caption, size_t length);
static int append_new_map_label_key(struct cmt_map *map, char *name);
static int append_new_metric_label_value(struct cmt_metric *metric, char *name, size_t length);

static struct cmt_variant *clone_variant(Opentelemetry__Proto__Common__V1__AnyValue *source)
{
    struct cmt_kvlist  *new_child_kvlist;
    struct cmt_array   *new_child_array;
    struct cmt_variant *result_instance;
    int                 result;

    if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE) {
        result_instance = cmt_variant_create_from_string(source->string_value);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE) {
        result_instance = cmt_variant_create_from_bool(source->bool_value);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE) {
        result_instance = cmt_variant_create_from_int(source->int_value);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE) {
        result_instance = cmt_variant_create_from_double(source->double_value);
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
        new_child_kvlist = cmt_kvlist_create();

        if (new_child_kvlist == NULL) {
            return NULL;
        }

        result_instance = cmt_variant_create_from_kvlist(new_child_kvlist);

        if (result_instance == NULL) {
            cmt_kvlist_destroy(new_child_kvlist);

            return NULL;
        }

        result = clone_kvlist(new_child_kvlist, source->kvlist_value);

        if (result) {
            cmt_variant_destroy(result_instance);

            return NULL;
        }
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
        new_child_array = cmt_array_create(source->array_value->n_values);

        if (new_child_array == NULL) {
            return NULL;
        }

        result_instance = cmt_variant_create_from_array(new_child_array);

        if (result_instance == NULL) {
            cmt_array_destroy(new_child_array);

            return NULL;
        }

        result = clone_array(new_child_array, source->array_value);

        if (result) {
            cmt_variant_destroy(result_instance);

            return NULL;
        }
    }
    else if (source->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE) {
        result_instance = cmt_variant_create_from_bytes(source->bytes_value.data, source->bytes_value.len);
    }

    return result_instance;
}

static int clone_array(struct cmt_array *target,
                       Opentelemetry__Proto__Common__V1__ArrayValue *source)
{
    int    result;
    size_t index;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == CMT_DECODE_OPENTELEMETRY_SUCCESS &&
         index < source->n_values ;
         index++) {
        result = clone_array_entry(target, source->values[index]);
    }

    return result;
}

static int clone_array_entry(struct cmt_array *target,
                             Opentelemetry__Proto__Common__V1__AnyValue *source)
{
    struct cmt_variant *new_child_instance;
    int                 result;

    new_child_instance = clone_variant(source);

    if (new_child_instance == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    result = cmt_array_append(target, new_child_instance);

    if (result) {
        cmt_variant_destroy(new_child_instance);

        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    return CMT_DECODE_OPENTELEMETRY_SUCCESS;
}

static int clone_kvlist(struct cmt_kvlist *target,
                        Opentelemetry__Proto__Common__V1__KeyValueList *source)
{
    int    result;
    size_t index;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == CMT_DECODE_OPENTELEMETRY_SUCCESS &&
         index < source->n_values ;
         index++) {
        result = clone_kvlist_entry(target, source->values[index]);
    }

    return 0;
}

static int clone_kvlist_entry(struct cmt_kvlist *target,
                              Opentelemetry__Proto__Common__V1__KeyValue *source)
{
    struct cmt_variant *new_child_instance;
    int                 result;

    new_child_instance = clone_variant(source->value);

    if (new_child_instance == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    result = cmt_kvlist_insert(target, source->key, new_child_instance);

    if (result) {
        cmt_variant_destroy(new_child_instance);

        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    return CMT_DECODE_OPENTELEMETRY_SUCCESS;
}

static struct cmt_map_label *create_label(char *caption, size_t length)
{
    struct cmt_map_label *instance;

    instance = calloc(1, sizeof(struct cmt_map_label));

    if (instance != NULL) {
        if (caption != NULL) {
            if (length == 0) {
                length = strlen(caption);
            }

            instance->name = cmt_sds_create_len(caption, length);

            if (instance->name == NULL) {
                cmt_errno();

                free(instance);

                instance = NULL;
            }
        }
    }

    return instance;
}

static int append_new_map_label_key(struct cmt_map *map, char *name)
{
    struct cmt_map_label *label;

    label = create_label(name, 0);

    if (label == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    mk_list_add(&label->_head, &map->label_keys);
    map->label_count++;

    return CMT_DECODE_OPENTELEMETRY_SUCCESS;
}

static int append_new_metric_label_value(struct cmt_metric *metric, char *name, size_t length)
{
    struct cmt_map_label *label;

    label = create_label(name, length);

    if (label == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    mk_list_add(&label->_head, &metric->labels);

    return CMT_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_resource_entry(struct cmt *cmt,
    char *schema_url,
    Opentelemetry__Proto__Resource__V1__Resource *resource)
{
    struct cmt_variant *kvlist_value;
    struct cmt_kvlist  *attributes;
    struct cmt_array   *resources;
    int                 result;
    size_t              index;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    kvlist_value = cmt_kvlist_fetch(cmt->internal_metadata, "resource");

    if (kvlist_value == NULL) {
        return CMT_DECODE_OPENTELEMETRY_KVLIST_ACCESS_ERROR;
    }

    resources = kvlist_value->data.as_array;
    attributes = cmt_kvlist_create();

    if (attributes == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    result = cmt_array_append_kvlist(resources, attributes);

    if (result) {
        cmt_kvlist_destroy(attributes);

        return result;
    }

    /* from now on, if we fail, we don't want to destroy the kvlist because
     * the recursive destruction process will take care of it and any existing
     * keys
     */

    if (schema_url != NULL) {
        result = cmt_kvlist_insert_string(attributes,
                                          "__cmetrics__schema_url",
                                          schema_url);
    }

    if (resource != NULL) {
        for (index = 0 ;
             result == CMT_DECODE_OPENTELEMETRY_SUCCESS &&
             index < resource->n_attributes ;
             index++) {

            result = clone_kvlist_entry(attributes,
                                        resource->attributes[index]);
        }
    }

    return result;
}

static int decode_instrumentation_library(struct cmt *cmt,
    size_t resource_index,
    Opentelemetry__Proto__Common__V1__InstrumentationLibrary *instrumentation_library)
{
    struct cmt_variant *kvlist_value;
    struct cmt_variant *array_value;
    struct cmt_kvlist  *attributes;
    struct cmt_array   *resources;
    int                 result;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    if (instrumentation_library == NULL) {
        return CMT_DECODE_OPENTELEMETRY_SUCCESS;
    }

    kvlist_value = cmt_kvlist_fetch(cmt->internal_metadata, "resource");

    if (kvlist_value == NULL) {
        return CMT_DECODE_OPENTELEMETRY_KVLIST_ACCESS_ERROR;
    }

    resources = kvlist_value->data.as_array;
    array_value = cmt_array_fetch_by_index(resources, resource_index);

    if (array_value == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ARRAY_ACCESS_ERROR;
    }

    attributes = array_value->data.as_kvlist;

    if (attributes == NULL) {
        return CMT_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
    }

    if (instrumentation_library->name != NULL) {
        result = cmt_kvlist_insert_string(attributes,
                                          "__cmetrics__instrumentation_library_name",
                                          instrumentation_library->name);
    }

    if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        if (instrumentation_library->version != NULL) {
            result = cmt_kvlist_insert_string(attributes,
                                              "__cmetrics__instrumentation_library_version",
                                              instrumentation_library->version);

        }
    }

    return result;
}

static int decode_data_point_labels(struct cmt *cmt,
                                    struct cmt_map *map,
                                    struct cmt_metric *metric,
                                    size_t attribute_count,
                                    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list)
{
    char                                        dummy_label_value[32];
    void                                      **value_index_list;
    size_t                                      attribute_index;
    size_t                                      map_label_index;
    size_t                                      map_label_count;
    struct mk_list                             *label_iterator;
    struct cmt_map_label                       *current_label;
    size_t                                      label_index;
    int                                         label_found;
    Opentelemetry__Proto__Common__V1__KeyValue *attribute;
    int                                         result;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    if (attribute_count == 0) {
        return result;
    }

    if (attribute_count > 127) {
        return CMT_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
    }

    value_index_list = calloc(128, sizeof(void *));

    if (value_index_list == NULL) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    for (attribute_index = 0 ;
         result == CMT_DECODE_OPENTELEMETRY_SUCCESS &&
         attribute_index < attribute_count ;
         attribute_index++) {

        attribute = attribute_list[attribute_index];

        label_found = CMT_FALSE;
        label_index = 0;

        mk_list_foreach(label_iterator, &map->label_keys) {
            current_label = mk_list_entry(label_iterator, struct cmt_map_label, _head);

            if (strcmp(current_label->name, attribute->key) == 0) {
                label_found = CMT_TRUE;

                break;
            }

            label_index++;
        }

        if (label_found == CMT_FALSE) {
            result = append_new_map_label_key(map, attribute->key);
        }

        if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
            value_index_list[label_index] = (void *) attribute;
        }
    }

    map_label_count = mk_list_size(&map->label_keys);

    for (map_label_index = 0 ;
         result == CMT_DECODE_OPENTELEMETRY_SUCCESS &&
         map_label_index < map_label_count ;
         map_label_index++) {

        if (value_index_list[map_label_index] != NULL) {
            attribute = (Opentelemetry__Proto__Common__V1__KeyValue *)
                            value_index_list[map_label_index];

            if (attribute->value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE) {
                result = append_new_metric_label_value(metric, attribute->value->string_value, 0);
            }
            else if (attribute->value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE) {
                result = append_new_metric_label_value(metric,
                                                       attribute->value->bytes_value.data,
                                                       attribute->value->bytes_value.len);
            }
            else if (attribute->value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE) {
                snprintf(dummy_label_value, sizeof(dummy_label_value) - 1, "%d", attribute->value->bool_value);

                result = append_new_metric_label_value(metric, dummy_label_value, 0);
            }
            else if (attribute->value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE) {
                snprintf(dummy_label_value, sizeof(dummy_label_value) - 1, PRIi64, attribute->value->int_value);

                result = append_new_metric_label_value(metric, dummy_label_value, 0);
            }
            else if (attribute->value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE) {
                snprintf(dummy_label_value, sizeof(dummy_label_value) - 1, "%.17g", attribute->value->double_value);

                result = append_new_metric_label_value(metric, dummy_label_value, 0);
            }
            else {
                result = append_new_metric_label_value(metric, NULL, 0);
            }
        }
    }

    free(value_index_list);

    return result;
}

static int decode_numerical_data_point(struct cmt *cmt,
                                       struct cmt_map *map,
                                       Opentelemetry__Proto__Metrics__V1__NumberDataPoint *data_point)
{
    int                static_metric_detected;
    struct cmt_metric *sample;
    int                result;
    double             value;

    static_metric_detected = CMT_FALSE;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    if (data_point->n_attributes == 0) {
        if (map->metric_static_set == CMT_FALSE) {
            static_metric_detected = CMT_TRUE;
        }
    }

    if (static_metric_detected == CMT_FALSE) {
        sample = calloc(1, sizeof(struct cmt_metric));

        if (sample == NULL) {
            return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        mk_list_init(&sample->labels);

        result = decode_data_point_labels(cmt,
                                          map,
                                          sample,
                                          data_point->n_attributes,
                                          data_point->attributes);

        if (result) {
            destroy_label_list(&sample->labels);

            free(sample);
        }
        else {
            mk_list_add(&sample->_head, &map->metrics);
        }
    }
    else {
        sample = &map->metric;

        map->metric_static_set = CMT_TRUE;
    }

    if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        value = 0;

        if (data_point->value_case == OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT) {
            if (data_point->as_int < 0) {
                value = 0;
            }
            else {
                value = cmt_math_uint64_to_d64((uint64_t) data_point->as_int);
            }
        }
        else if (data_point->value_case == OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_DOUBLE) {
            value = data_point->as_double;
        }

        cmt_metric_set(sample, data_point->time_unix_nano, data_point->as_double);
    }

    return result;
}

static int decode_numerical_data_point_list(struct cmt *cmt,
                                            struct cmt_map *map,
                                            size_t data_point_count,
                                            Opentelemetry__Proto__Metrics__V1__NumberDataPoint **data_point_list)
{
    size_t index;
    int    result;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == 0 &&
         index < data_point_count ; index++) {
        result = decode_numerical_data_point(cmt, map, data_point_list[index]);
    }

    return result;
}

static int decode_summary_data_point(struct cmt *cmt,
                                     struct cmt_map *map,
                                     Opentelemetry__Proto__Metrics__V1__SummaryDataPoint *data_point)
{
    int                 static_metric_detected;
    struct cmt_summary *summary;
    struct cmt_metric  *sample;
    int                 result;
    size_t              index;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    summary = (struct cmt_summary *) map->parent;

    if (summary->quantiles == NULL) {
        summary->quantiles = calloc(data_point->n_quantile_values,
                                    sizeof(double));

        if (summary->quantiles == NULL) {
            return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        summary->quantiles_count = data_point->n_quantile_values;

        for (index = 0 ;
             index < data_point->n_quantile_values ;
             index++) {
            summary->quantiles[index] = data_point->quantile_values[index]->quantile;
        }
    }

    static_metric_detected = CMT_FALSE;

    if (data_point->n_attributes == 0) {
        if (map->metric_static_set == CMT_FALSE) {
            static_metric_detected = CMT_TRUE;
        }
    }

    if (static_metric_detected == CMT_FALSE) {
        sample = calloc(1, sizeof(struct cmt_metric));

        if (sample == NULL) {
            return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        mk_list_init(&sample->labels);

        result = decode_data_point_labels(cmt,
                                          map,
                                          sample,
                                          data_point->n_attributes,
                                          data_point->attributes);

        if (result) {
            destroy_label_list(&sample->labels);

            free(sample);

            return result;
        }
        else {
            mk_list_add(&sample->_head, &map->metrics);
        }
    }
    else {
        sample = &map->metric;

        map->metric_static_set = CMT_TRUE;
    }

    if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        if (sample->sum_quantiles_set == CMT_FALSE) {
            sample->sum_quantiles = calloc(data_point->n_quantile_values,
                                           sizeof(uint64_t));

            if (sample->sum_quantiles == NULL) {
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            sample->sum_quantiles_set = CMT_TRUE;
        }

        for (index = 0 ;
             index < data_point->n_quantile_values ;
             index++) {
            cmt_summary_quantile_set(sample, data_point->time_unix_nano,
                                     index, data_point->quantile_values[index]->value);
        }

        sample->sum_sum = cmt_math_d64_to_uint64(data_point->sum);
        sample->sum_count = data_point->count;
    }

    return result;
}

static int decode_summary_data_point_list(struct cmt *cmt,
                                          struct cmt_map *map,
                                          size_t data_point_count,
                                          Opentelemetry__Proto__Metrics__V1__SummaryDataPoint **data_point_list)
{
    size_t index;
    int    result;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == CMT_DECODE_OPENTELEMETRY_SUCCESS &&
         index < data_point_count ; index++) {
        result = decode_summary_data_point(cmt, map, data_point_list[index]);
    }

    return result;
}

static int decode_histogram_data_point(struct cmt *cmt,
                                       struct cmt_map *map,
                                       Opentelemetry__Proto__Metrics__V1__HistogramDataPoint *data_point)
{
    int                   static_metric_detected;
    struct cmt_histogram *histogram;
    struct cmt_metric    *sample;
    int                   result;
    size_t                index;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    histogram = (struct cmt_histogram *) map->parent;

    if (data_point->n_bucket_counts > data_point->n_explicit_bounds + 1) {
        return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    if (histogram->buckets == NULL) {
        histogram->buckets = cmt_histogram_buckets_create_size(data_point->explicit_bounds,
                                                               data_point->n_explicit_bounds);

        if (histogram->buckets == NULL) {
            return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }
    }

    static_metric_detected = CMT_FALSE;

    if (data_point->n_attributes == 0) {
        if (map->metric_static_set == CMT_FALSE) {
            static_metric_detected = CMT_TRUE;
        }
    }

    if (static_metric_detected == CMT_FALSE) {
        sample = calloc(1, sizeof(struct cmt_metric));

        if (sample == NULL) {
            return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        mk_list_init(&sample->labels);

        result = decode_data_point_labels(cmt,
                                          map,
                                          sample,
                                          data_point->n_attributes,
                                          data_point->attributes);

        if (result != 0) {
            destroy_label_list(&sample->labels);

            free(sample);

            return result;
        }
        else {
            mk_list_add(&sample->_head, &map->metrics);
        }
    }
    else {
        sample = &map->metric;

        map->metric_static_set = CMT_TRUE;
    }

    if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        if (sample->hist_buckets == NULL) {
            sample->hist_buckets = calloc(data_point->n_bucket_counts + 1,
                                          sizeof(uint64_t));

            if (sample->hist_buckets == NULL) {
                return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }
        }

        for (index = 0 ;
             index < data_point->n_bucket_counts;
             index++) {
            cmt_metric_hist_set(sample, data_point->time_unix_nano,
                                index, data_point->bucket_counts[index]);
        }

        sample->hist_sum = cmt_math_d64_to_uint64(data_point->sum);
        sample->hist_count = data_point->count;
    }

    return result;
}

static int decode_histogram_data_point_list(struct cmt *cmt,
                                            struct cmt_map *map,
                                            size_t data_point_count,
                                            Opentelemetry__Proto__Metrics__V1__HistogramDataPoint **data_point_list)
{
    size_t index;
    int    result;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    for (index = 0 ;
         result == 0 &&
         index < data_point_count ; index++) {
        result = decode_histogram_data_point(cmt, map, data_point_list[index]);
    }

    return result;
}

static int decode_counter_entry(struct cmt *cmt,
    void *instance,
    Opentelemetry__Proto__Metrics__V1__Sum *metric)
{
    struct cmt_counter *counter;
    int                 result;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    counter = (struct cmt_counter *) instance;

    counter->map->metric_static_set = 0;

    result = decode_numerical_data_point_list(cmt,
                                              counter->map,
                                              metric->n_data_points,
                                              metric->data_points);

    if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        if (metric->aggregation_temporality == OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_DELTA) {
            counter->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;
        }
        else  if (metric->aggregation_temporality == OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_CUMULATIVE) {
            counter->aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;
        }
        else {
            counter->aggregation_type = CMT_AGGREGATION_TYPE_UNSPECIFIED;
        }

        counter->allow_reset = !metric->is_monotonic;
    }

    return result;
}

static int decode_gauge_entry(struct cmt *cmt,
    void *instance,
    Opentelemetry__Proto__Metrics__V1__Gauge *metric)
{
    struct cmt_gauge *gauge;
    int               result;

    gauge = (struct cmt_gauge *) instance;

    gauge->map->metric_static_set = 0;

    result = decode_numerical_data_point_list(cmt,
                                              gauge->map,
                                              metric->n_data_points,
                                              metric->data_points);

    return result;
}

static int decode_summary_entry(struct cmt *cmt,
    void *instance,
    Opentelemetry__Proto__Metrics__V1__Summary *metric)
{
    struct cmt_summary *summary;
    int                 result;

    summary = (struct cmt_summary *) instance;

    if (summary->quantiles != NULL) {
        free(summary->quantiles);
    }

    summary->quantiles = NULL;
    summary->quantiles_count = 0;
    summary->map->metric_static_set = 0;

    result = decode_summary_data_point_list(cmt,
                                            summary->map,
                                            metric->n_data_points,
                                            metric->data_points);

    return result;
}

static int decode_histogram_entry(struct cmt *cmt,
    void *instance,
    Opentelemetry__Proto__Metrics__V1__Histogram *metric)
{
    struct cmt_histogram *histogram;
    int                   result;

    histogram = (struct cmt_histogram *) instance;

    histogram->buckets = NULL;
    histogram->map->metric_static_set = 0;

    result = decode_histogram_data_point_list(cmt,
                                              histogram->map,
                                              metric->n_data_points,
                                              metric->data_points);

    if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        if (metric->aggregation_temporality == OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_DELTA) {
            histogram->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;
        }
        else  if (metric->aggregation_temporality == OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_CUMULATIVE) {
            histogram->aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;
        }
        else {
            histogram->aggregation_type = CMT_AGGREGATION_TYPE_UNSPECIFIED;
        }
    }

    return result;
}

static int decode_metrics_entry(struct cmt *cmt,
    size_t resource_index,
    Opentelemetry__Proto__Metrics__V1__Metric *metric)
{
    char           *metric_description;
    char           *metric_namespace;
    char           *metric_subsystem;
    char           *metric_name;
    void           *instance;
    int             result;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    metric_name = metric->name;
    metric_namespace = "";
    metric_subsystem = "";
    metric_description = metric->description;

    if (metric_description == NULL) {
        metric_description = "-";
    }
    else if (strlen(metric_description) == 0) {
        metric_description = "-";
    }

    if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM) {
        instance = cmt_counter_create(cmt,
                                      metric_namespace,
                                      metric_subsystem,
                                      metric_name,
                                      metric_description,
                                      0, NULL);

        if (instance == NULL) {
            return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = decode_counter_entry(cmt, instance, metric->sum);

        if (result) {
            cmt_counter_destroy(instance);
        }
    }
    else if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE) {
        instance = cmt_gauge_create(cmt,
                                    metric_namespace,
                                    metric_subsystem,
                                    metric_name,
                                    metric_description,
                                    0, NULL);

        if (instance == NULL) {
            return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = decode_gauge_entry(cmt, instance, metric->gauge);

        if (result) {
            cmt_gauge_destroy(instance);
        }
    }
    else if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUMMARY) {
        instance = cmt_summary_create(cmt,
                                      metric_namespace,
                                      metric_subsystem,
                                      metric_name,
                                      metric_description,
                                      1, (double []) { 0.0 },
                                      0, NULL);

        if (instance == NULL) {
            return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        /* We are forced to create at least one quantile by the constructor but we
         * don't know the details about it at the moment so we just leave it "open"
         */

        result = decode_summary_entry(cmt, instance, metric->summary);

        if (result) {
            cmt_summary_destroy(instance);
        }
    }
    else if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_HISTOGRAM) {
        instance = cmt_histogram_create(cmt,
                                        metric_namespace,
                                        metric_subsystem,
                                        metric_name,
                                        metric_description,
                                        (struct cmt_histogram_buckets *) cmt,
                                        0, NULL);

        if (instance == NULL) {
            return CMT_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = decode_histogram_entry(cmt, instance, metric->histogram);

        if (result) {
            cmt_histogram_destroy(instance);
        }
    }

    return result;
}

static int decode_instrumentation_library_metrics_entry(struct cmt *cmt,
    size_t resource_index,
    Opentelemetry__Proto__Metrics__V1__InstrumentationLibraryMetrics *metrics)
{
    int result;
    size_t index;

    result = decode_instrumentation_library(cmt,
                                            resource_index,
                                            metrics->instrumentation_library);

    for (index = 0 ;
         result == CMT_DECODE_OPENTELEMETRY_SUCCESS &&
         index < metrics->n_metrics ;
         index++) {
        result = decode_metrics_entry(cmt,
                                      resource_index,
                                      metrics->metrics[index]);
    }

    return result;
}

static int decode_resource_metrics_entry(struct cmt *cmt,
    size_t resource_metrics_index,
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *resource_metrics)
{
    int                 result;
    size_t              index;

    result = decode_resource_entry(cmt,
                                   resource_metrics->schema_url,
                                   resource_metrics->resource);

    for (index = 0 ;
         result == CMT_DECODE_OPENTELEMETRY_SUCCESS &&
         index < resource_metrics->n_instrumentation_library_metrics ;
         index++) {
        result = decode_instrumentation_library_metrics_entry(cmt,
                    resource_metrics_index,
                    resource_metrics->instrumentation_library_metrics[index]);
    }

    return result;
}

static int decode_service_request(struct cmt *cmt,
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest *service_request)
{
    int                 result;
    size_t              index;

    result = CMT_DECODE_OPENTELEMETRY_SUCCESS;

    if (service_request->n_resource_metrics > 0) {
        result = cmt_kvlist_insert_new_array(cmt->internal_metadata,
                                             "resource", service_request->n_resource_metrics);
    }

    for (index = 0 ;
         result == CMT_DECODE_OPENTELEMETRY_SUCCESS &&
         index < service_request->n_resource_metrics ;
         index++) {
        result = decode_resource_metrics_entry(cmt, index,
                                               service_request->resource_metrics[index]);
    }

    return result;
}

int cmt_decode_opentelemetry_create(struct cmt **out_cmt, char *in_buf, size_t in_size,
                                    size_t *offset)
{
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest *service_request;
    int                                                                        result;
    struct cmt                                                                *cmt;

    cmt = cmt_create();

    result = cmt_kvlist_insert_string(cmt->internal_metadata,
                                      "producer", "opentelemetry");

    if (result != CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        cmt_destroy(cmt);

        return result;
    }

    service_request = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__unpack(NULL, in_size - *offset, &in_buf[*offset]);

    if (service_request != NULL) {
        result = decode_service_request(cmt, service_request);

        opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(service_request, NULL);
    }

    if (result != CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        return result;
    }

    *out_cmt = cmt;

    return 0;
}

void cmt_decode_opentelemetry_destroy(struct cmt *cmt)
{
    if (cmt != NULL) {
        cmt_destroy(cmt);
    }
}
