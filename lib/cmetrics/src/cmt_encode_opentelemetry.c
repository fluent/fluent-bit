/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_encode_opentelemetry.h>
#include <inttypes.h>

static Opentelemetry__Proto__Metrics__V1__ScopeMetrics **
    initialize_scope_metrics_list(
    size_t element_count);

static void destroy_scope_metric_list(
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics **metric_list);

struct cfl_kvlist *fetch_metadata_kvlist_key(struct cfl_kvlist *kvlist, char *key)
{
    struct cfl_variant *entry_variant;
    struct cfl_kvlist  *entry_kvlist;

    if (kvlist == NULL) {
        return NULL;
    }

    entry_variant = cfl_kvlist_fetch(kvlist, key);

    if (entry_variant != NULL) {
        entry_kvlist = entry_variant->data.as_kvlist;
    }
    else {
        entry_kvlist = NULL;
    }

    return entry_kvlist;
}

static struct cfl_array *fetch_metadata_array_key(struct cfl_kvlist *kvlist, char *key)
{
    struct cfl_variant *entry_variant;

    if (kvlist == NULL) {
        return NULL;
    }

    entry_variant = cfl_kvlist_fetch(kvlist, key);
    if (entry_variant == NULL || entry_variant->type != CFL_VARIANT_ARRAY) {
        return NULL;
    }

    return entry_variant->data.as_array;
}

static struct cfl_kvlist *fetch_array_kvlist_entry(struct cfl_array *array, size_t index)
{
    struct cfl_variant *entry_variant;

    if (array == NULL || index >= array->entry_count) {
        return NULL;
    }

    entry_variant = cfl_array_fetch_by_index(array, index);
    if (entry_variant == NULL || entry_variant->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    return entry_variant->data.as_kvlist;
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

static struct cfl_kvlist *get_metric_otlp_metadata_context(struct cmt *cmt, struct cmt_map *map)
{
    struct cfl_kvlist *otlp_root;
    struct cfl_kvlist *metrics_root;
    struct cfl_kvlist *type_root;

    if (cmt == NULL || map == NULL || map->opts == NULL || map->opts->fqname == NULL) {
        return NULL;
    }

    otlp_root = fetch_metadata_kvlist_key(cmt->external_metadata, "otlp");
    if (otlp_root == NULL) {
        return NULL;
    }

    metrics_root = fetch_metadata_kvlist_key(otlp_root, "metrics");
    if (metrics_root == NULL) {
        return NULL;
    }

    type_root = fetch_metadata_kvlist_key(metrics_root, map_type_to_key(map->type));
    if (type_root == NULL) {
        return NULL;
    }

    return fetch_metadata_kvlist_key(type_root, map->opts->fqname);
}

static struct cfl_kvlist *get_data_point_otlp_metadata_context(struct cmt *cmt,
                                                                struct cmt_map *map,
                                                                struct cmt_metric *sample)
{
    char key[128];
    struct cfl_kvlist *metric_context;
    struct cfl_kvlist *datapoints_context;

    metric_context = get_metric_otlp_metadata_context(cmt, map);
    if (metric_context == NULL) {
        return NULL;
    }

    datapoints_context = fetch_metadata_kvlist_key(metric_context, "datapoints");
    if (datapoints_context == NULL) {
        return NULL;
    }

    snprintf(key, sizeof(key) - 1, "%" PRIx64 ":%" PRIu64,
             sample != NULL ? sample->hash : 0,
             sample != NULL ? cmt_metric_get_timestamp(sample) : 0);

    return fetch_metadata_kvlist_key(datapoints_context, key);
}

static int kvlist_fetch_uint64(struct cfl_kvlist *kvlist, const char *key, uint64_t *out)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(kvlist, (char *) key);
    if (value == NULL) {
        return -1;
    }

    if (value->type == CFL_VARIANT_UINT) {
        *out = value->data.as_uint64;
        return 0;
    }

    if (value->type == CFL_VARIANT_INT && value->data.as_int64 >= 0) {
        *out = (uint64_t) value->data.as_int64;
        return 0;
    }

    return -1;
}

static int kvlist_fetch_double(struct cfl_kvlist *kvlist, const char *key, double *out)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(kvlist, (char *) key);
    if (value == NULL) {
        return -1;
    }

    if (value->type == CFL_VARIANT_DOUBLE) {
        *out = value->data.as_double;
        return 0;
    }
    else if (value->type == CFL_VARIANT_UINT) {
        *out = (double) value->data.as_uint64;
        return 0;
    }
    else if (value->type == CFL_VARIANT_INT) {
        *out = (double) value->data.as_int64;
        return 0;
    }

    return -1;
}

static int kvlist_fetch_bool(struct cfl_kvlist *kvlist, const char *key, int *out)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(kvlist, (char *) key);
    if (value == NULL) {
        return -1;
    }

    if (value->type == CFL_VARIANT_BOOL) {
        *out = value->data.as_bool ? CMT_TRUE : CMT_FALSE;
        return 0;
    }

    if (value->type == CFL_VARIANT_UINT) {
        *out = value->data.as_uint64 != 0 ? CMT_TRUE : CMT_FALSE;
        return 0;
    }

    if (value->type == CFL_VARIANT_INT) {
        *out = value->data.as_int64 != 0 ? CMT_TRUE : CMT_FALSE;
        return 0;
    }

    return -1;
}

static int kvlist_fetch_string(struct cfl_kvlist *kvlist, const char *key, char **out)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(kvlist, (char *) key);
    if (value == NULL) {
        return -1;
    }

    if (value->type == CFL_VARIANT_STRING && value->data.as_string != NULL) {
        *out = value->data.as_string;
        return 0;
    }

    return -1;
}

static inline void otlp_kvpair_list_destroy(Opentelemetry__Proto__Common__V1__KeyValue **pair_list,
                                            size_t entry_count);
static inline Opentelemetry__Proto__Common__V1__KeyValue **cfl_kvlist_to_otlp_kvpair_list(
    struct cfl_kvlist *kvlist);

static Opentelemetry__Proto__Metrics__V1__Exemplar *create_exemplar_from_kvlist(
    struct cfl_kvlist *kvlist)
{
    int result;
    size_t index;
    uint64_t uint64_value;
    Opentelemetry__Proto__Metrics__V1__Exemplar *exemplar;
    struct cfl_variant *variant;
    struct cfl_kvlist *filtered_attributes;

    exemplar = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__Exemplar));
    if (exemplar == NULL) {
        return NULL;
    }

    opentelemetry__proto__metrics__v1__exemplar__init(exemplar);

    result = kvlist_fetch_uint64(kvlist, "time_unix_nano", &uint64_value);
    if (result == 0) {
        exemplar->time_unix_nano = uint64_value;
    }

    variant = cfl_kvlist_fetch(kvlist, "span_id");
    if (variant != NULL && variant->type == CFL_VARIANT_BYTES) {
        exemplar->span_id.len = cfl_sds_len(variant->data.as_bytes);
        exemplar->span_id.data = calloc(1, exemplar->span_id.len);
        if (exemplar->span_id.data == NULL) {
            free(exemplar);
            return NULL;
        }
        memcpy(exemplar->span_id.data, variant->data.as_bytes, exemplar->span_id.len);
    }

    variant = cfl_kvlist_fetch(kvlist, "trace_id");
    if (variant != NULL && variant->type == CFL_VARIANT_BYTES) {
        exemplar->trace_id.len = cfl_sds_len(variant->data.as_bytes);
        exemplar->trace_id.data = calloc(1, exemplar->trace_id.len);
        if (exemplar->trace_id.data == NULL) {
            if (exemplar->span_id.data != NULL) {
                free(exemplar->span_id.data);
            }
            free(exemplar);
            return NULL;
        }
        memcpy(exemplar->trace_id.data, variant->data.as_bytes, exemplar->trace_id.len);
    }

    variant = cfl_kvlist_fetch(kvlist, "as_double");
    if (variant != NULL) {
        if (variant->type == CFL_VARIANT_DOUBLE) {
            exemplar->value_case = OPENTELEMETRY__PROTO__METRICS__V1__EXEMPLAR__VALUE_AS_DOUBLE;
            exemplar->as_double = variant->data.as_double;
        }
    }
    else {
        variant = cfl_kvlist_fetch(kvlist, "as_int");
        if (variant != NULL) {
            if (variant->type == CFL_VARIANT_INT) {
                exemplar->value_case = OPENTELEMETRY__PROTO__METRICS__V1__EXEMPLAR__VALUE_AS_INT;
                exemplar->as_int = variant->data.as_int64;
            }
            else if (variant->type == CFL_VARIANT_UINT) {
                exemplar->value_case = OPENTELEMETRY__PROTO__METRICS__V1__EXEMPLAR__VALUE_AS_INT;
                exemplar->as_int = (int64_t) variant->data.as_uint64;
            }
        }
    }

    filtered_attributes = fetch_metadata_kvlist_key(kvlist, "filtered_attributes");
    if (filtered_attributes != NULL && cfl_kvlist_count(filtered_attributes) > 0) {
        exemplar->filtered_attributes = cfl_kvlist_to_otlp_kvpair_list(filtered_attributes);
        if (exemplar->filtered_attributes == NULL) {
            if (exemplar->span_id.data != NULL) {
                free(exemplar->span_id.data);
            }
            if (exemplar->trace_id.data != NULL) {
                free(exemplar->trace_id.data);
            }
            free(exemplar);
            return NULL;
        }

        exemplar->n_filtered_attributes = cfl_kvlist_count(filtered_attributes);

        for (index = 0; index < exemplar->n_filtered_attributes; index++) {
            if (exemplar->filtered_attributes[index] == NULL) {
                otlp_kvpair_list_destroy(exemplar->filtered_attributes, exemplar->n_filtered_attributes);
                if (exemplar->span_id.data != NULL) {
                    free(exemplar->span_id.data);
                }
                if (exemplar->trace_id.data != NULL) {
                    free(exemplar->trace_id.data);
                }
                free(exemplar);
                return NULL;
            }
        }
    }

    return exemplar;
}

static void destroy_exemplar(Opentelemetry__Proto__Metrics__V1__Exemplar *exemplar)
{
    if (exemplar == NULL) {
        return;
    }

    if (exemplar->span_id.data != NULL) {
        free(exemplar->span_id.data);
    }

    if (exemplar->trace_id.data != NULL) {
        free(exemplar->trace_id.data);
    }

    if (exemplar->filtered_attributes != NULL) {
        otlp_kvpair_list_destroy(exemplar->filtered_attributes, exemplar->n_filtered_attributes);
    }

    free(exemplar);
}

static int initialize_exemplars_from_metadata(struct cfl_kvlist *point_metadata,
                                              Opentelemetry__Proto__Metrics__V1__Exemplar ***out_exemplars,
                                              size_t *out_count)
{
    size_t index;
    size_t dest_index;
    struct cfl_array *array;
    struct cfl_variant *variant;
    Opentelemetry__Proto__Metrics__V1__Exemplar **exemplars;

    *out_exemplars = NULL;
    *out_count = 0;

    variant = cfl_kvlist_fetch(point_metadata, "exemplars");
    if (variant == NULL || variant->type != CFL_VARIANT_ARRAY || variant->data.as_array == NULL) {
        return 0;
    }

    array = variant->data.as_array;
    if (array->entry_count == 0) {
        return 0;
    }

    exemplars = calloc(array->entry_count, sizeof(Opentelemetry__Proto__Metrics__V1__Exemplar *));
    if (exemplars == NULL) {
        return -1;
    }

    dest_index = 0;

    for (index = 0; index < array->entry_count; index++) {
        variant = cfl_array_fetch_by_index(array, index);
        if (variant == NULL || variant->type != CFL_VARIANT_KVLIST || variant->data.as_kvlist == NULL) {
            continue;
        }

        exemplars[dest_index] = create_exemplar_from_kvlist(variant->data.as_kvlist);
        if (exemplars[dest_index] == NULL) {
            while (dest_index > 0) {
                dest_index--;
                if (exemplars[dest_index] != NULL) {
                    destroy_exemplar(exemplars[dest_index]);
                }
            }
            free(exemplars);
            return -1;
        }

        dest_index++;
    }

    if (dest_index == 0) {
        free(exemplars);
        return 0;
    }

    *out_exemplars = exemplars;
    *out_count = dest_index;

    return 0;
}

static size_t compute_flat_scope_index(struct cmt_opentelemetry_context *context,
                                       size_t resource_index,
                                       size_t scope_index)
{
    size_t index;
    size_t offset;

    offset = 0;

    if (context == NULL || context->metrics_data == NULL) {
        return 0;
    }

    if (resource_index >= context->metrics_data->n_resource_metrics) {
        return 0;
    }

    for (index = 0; index < resource_index; index++) {
        offset += context->metrics_data->resource_metrics[index]->n_scope_metrics;
    }

    if (scope_index >= context->metrics_data->resource_metrics[resource_index]->n_scope_metrics) {
        return 0;
    }

    return offset + scope_index;
}

static size_t resolve_target_scope_index(struct cmt_opentelemetry_context *context,
                                         struct cmt_map *map)
{
    uint64_t flat_scope_index;
    uint64_t resource_index;
    uint64_t scope_index;
    int result;
    struct cfl_kvlist *metric_context;
    struct cfl_kvlist *metadata;

    if (context == NULL || context->scope_metrics_count == 0) {
        return 0;
    }

    metric_context = get_metric_otlp_metadata_context(context->cmt, map);
    if (metric_context == NULL) {
        return 0;
    }

    metadata = fetch_metadata_kvlist_key(metric_context, "metadata");
    if (metadata == NULL) {
        return 0;
    }

    result = kvlist_fetch_uint64(metadata, "scope_flat_index", &flat_scope_index);
    if (result == 0 && flat_scope_index < context->scope_metrics_count) {
        return (size_t) flat_scope_index;
    }

    result = kvlist_fetch_uint64(metadata, "resource_index", &resource_index);
    if (result != 0) {
        return 0;
    }

    result = kvlist_fetch_uint64(metadata, "scope_index", &scope_index);
    if (result != 0) {
        return 0;
    }

    flat_scope_index = compute_flat_scope_index(context, (size_t) resource_index, (size_t) scope_index);
    if (flat_scope_index < context->scope_metrics_count) {
        return (size_t) flat_scope_index;
    }

    return 0;
}

static void apply_metric_metadata_from_otlp_context(struct cmt *cmt,
                                                    struct cmt_map *map,
                                                    Opentelemetry__Proto__Metrics__V1__Metric *metric)
{
    struct cfl_kvlist *metric_context;
    struct cfl_kvlist *metadata;

    metric_context = get_metric_otlp_metadata_context(cmt, map);
    if (metric_context == NULL) {
        return;
    }

    metadata = fetch_metadata_kvlist_key(metric_context, "metadata");
    if (metadata == NULL || cfl_kvlist_count(metadata) == 0) {
        return;
    }

    metric->metadata = cfl_kvlist_to_otlp_kvpair_list(metadata);
    if (metric->metadata != NULL) {
        metric->n_metadata = cfl_kvlist_count(metadata);
    }
}

static void apply_data_point_metadata_from_otlp_context(struct cmt *cmt,
                                                        struct cmt_map *map,
                                                        struct cmt_metric *sample,
                                                        void *data_point)
{
    int bool_value;
    int result;
    uint64_t uint64_value;
    double double_value;
    size_t exemplar_count;
    Opentelemetry__Proto__Metrics__V1__Exemplar **exemplars;
    struct cfl_kvlist *point_metadata;

    point_metadata = get_data_point_otlp_metadata_context(cmt, map, sample);
    if (point_metadata == NULL || data_point == NULL) {
        return;
    }

    if (map->type == CMT_COUNTER ||
        map->type == CMT_GAUGE ||
        map->type == CMT_UNTYPED) {
        Opentelemetry__Proto__Metrics__V1__NumberDataPoint *number_data_point;
        char *number_value_case;

        number_data_point = (Opentelemetry__Proto__Metrics__V1__NumberDataPoint *) data_point;
        number_value_case = NULL;

        result = kvlist_fetch_uint64(point_metadata, "start_time_unix_nano", &uint64_value);
        if (result == 0) {
            number_data_point->start_time_unix_nano = uint64_value;
        }

        result = kvlist_fetch_uint64(point_metadata, "flags", &uint64_value);
        if (result == 0) {
            number_data_point->flags = (uint32_t) uint64_value;
        }

        if (cmt_metric_get_value_type(sample) == CMT_METRIC_VALUE_INT64) {
            number_data_point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT;
            number_data_point->as_int = cmt_metric_get_int64_value(sample);
        }
        else if (cmt_metric_get_value_type(sample) == CMT_METRIC_VALUE_UINT64) {
            if (cmt_metric_get_uint64_value(sample) <= INT64_MAX) {
                number_data_point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT;
                number_data_point->as_int = (int64_t) cmt_metric_get_uint64_value(sample);
            }
            else {
                number_data_point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_DOUBLE;
                number_data_point->as_double = (double) cmt_metric_get_uint64_value(sample);
            }
        }
        else {
            result = kvlist_fetch_string(point_metadata, "number_value_case", &number_value_case);
            if (result == 0 && strcmp(number_value_case, "int") == 0) {
                number_data_point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT;
                number_data_point->as_int = cmt_metric_get_int64_value(sample);
            }
            else {
                number_data_point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_DOUBLE;
                number_data_point->as_double = cmt_metric_get_value(sample);
            }
        }

        result = initialize_exemplars_from_metadata(point_metadata, &exemplars, &exemplar_count);
        if (result == 0 && exemplars != NULL) {
            number_data_point->exemplars = exemplars;
            number_data_point->n_exemplars = exemplar_count;
        }
    }
    else if (map->type == CMT_SUMMARY) {
        Opentelemetry__Proto__Metrics__V1__SummaryDataPoint *summary_data_point;

        summary_data_point = (Opentelemetry__Proto__Metrics__V1__SummaryDataPoint *) data_point;

        result = kvlist_fetch_uint64(point_metadata, "start_time_unix_nano", &uint64_value);
        if (result == 0) {
            summary_data_point->start_time_unix_nano = uint64_value;
        }

        result = kvlist_fetch_uint64(point_metadata, "flags", &uint64_value);
        if (result == 0) {
            summary_data_point->flags = (uint32_t) uint64_value;
        }
    }
    else if (map->type == CMT_HISTOGRAM) {
        Opentelemetry__Proto__Metrics__V1__HistogramDataPoint *histogram_data_point;

        histogram_data_point = (Opentelemetry__Proto__Metrics__V1__HistogramDataPoint *) data_point;

        result = kvlist_fetch_uint64(point_metadata, "start_time_unix_nano", &uint64_value);
        if (result == 0) {
            histogram_data_point->start_time_unix_nano = uint64_value;
        }

        result = kvlist_fetch_uint64(point_metadata, "flags", &uint64_value);
        if (result == 0) {
            histogram_data_point->flags = (uint32_t) uint64_value;
        }

        result = kvlist_fetch_bool(point_metadata, "has_sum", &bool_value);
        if (result == 0 && bool_value == CMT_FALSE) {
            histogram_data_point->has_sum = CMT_FALSE;
        }

        result = kvlist_fetch_bool(point_metadata, "has_min", &bool_value);
        if (result == 0 && bool_value == CMT_TRUE) {
            result = kvlist_fetch_double(point_metadata, "min", &double_value);
            if (result == 0) {
                histogram_data_point->has_min = CMT_TRUE;
                histogram_data_point->min = double_value;
            }
        }

        result = kvlist_fetch_bool(point_metadata, "has_max", &bool_value);
        if (result == 0 && bool_value == CMT_TRUE) {
            result = kvlist_fetch_double(point_metadata, "max", &double_value);
            if (result == 0) {
                histogram_data_point->has_max = CMT_TRUE;
                histogram_data_point->max = double_value;
            }
        }

        result = initialize_exemplars_from_metadata(point_metadata, &exemplars, &exemplar_count);
        if (result == 0 && exemplars != NULL) {
            histogram_data_point->exemplars = exemplars;
            histogram_data_point->n_exemplars = exemplar_count;
        }
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint *exp_data_point;

        exp_data_point = (Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint *) data_point;

        result = kvlist_fetch_uint64(point_metadata, "start_time_unix_nano", &uint64_value);
        if (result == 0) {
            exp_data_point->start_time_unix_nano = uint64_value;
        }

        result = kvlist_fetch_uint64(point_metadata, "flags", &uint64_value);
        if (result == 0) {
            exp_data_point->flags = (uint32_t) uint64_value;
        }

        result = kvlist_fetch_bool(point_metadata, "has_sum", &bool_value);
        if (result == 0 && bool_value == CMT_FALSE) {
            exp_data_point->has_sum = CMT_FALSE;
        }

        result = kvlist_fetch_bool(point_metadata, "has_min", &bool_value);
        if (result == 0 && bool_value == CMT_TRUE) {
            result = kvlist_fetch_double(point_metadata, "min", &double_value);
            if (result == 0) {
                exp_data_point->has_min = CMT_TRUE;
                exp_data_point->min = double_value;
            }
        }

        result = kvlist_fetch_bool(point_metadata, "has_max", &bool_value);
        if (result == 0 && bool_value == CMT_TRUE) {
            result = kvlist_fetch_double(point_metadata, "max", &double_value);
            if (result == 0) {
                exp_data_point->has_max = CMT_TRUE;
                exp_data_point->max = double_value;
            }
        }

        result = initialize_exemplars_from_metadata(point_metadata, &exemplars, &exemplar_count);
        if (result == 0 && exemplars != NULL) {
            exp_data_point->exemplars = exemplars;
            exp_data_point->n_exemplars = exemplar_count;
        }
    }
}


static int is_string_releaseable(char *address);

static int is_metric_empty(struct cmt_map *map);

static size_t get_metric_count(struct cmt *cmt);

static Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile *
    initialize_summary_value_at_quantile(
    double quantile, double value);

static void destroy_summary_value_at_quantile(
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile *value);

static Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile **
    initialize_summary_value_at_quantile_list(
    size_t element_count);

static void destroy_summary_value_at_quantile_list(
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile **list);


static void destroy_metrics_data(
    Opentelemetry__Proto__Metrics__V1__MetricsData *metrics_data);

static Opentelemetry__Proto__Metrics__V1__MetricsData *
    initialize_metrics_data(size_t resource_metrics_count);

static void destroy_resource(
    Opentelemetry__Proto__Resource__V1__Resource *resource);

static void destroy_resource_metrics(
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *resource_metrics);

static Opentelemetry__Proto__Metrics__V1__ResourceMetrics *
    initialize_resource_metrics(
    struct cfl_kvlist *resource_metrics_root,
    Opentelemetry__Proto__Resource__V1__Resource *resource,
    size_t instrumentation_library_metrics_element_count);

static void destroy_resource_metrics_list(
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics **resource_metrics_list);

static Opentelemetry__Proto__Metrics__V1__ResourceMetrics **
    initialize_resource_metrics_list(
    size_t element_count);

static Opentelemetry__Proto__Common__V1__InstrumentationScope *
    initialize_instrumentation_scope(
    struct cfl_kvlist *scope_root,
    int *error_detection_flag);

static void destroy_scope_metrics(
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *metric);

static Opentelemetry__Proto__Metrics__V1__ScopeMetrics *
    initialize_scope_metrics(
    struct cfl_kvlist *scope_metrics_root,
    size_t metric_element_count);

static int append_metric_to_scope_metrics(
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *instrumentation_scope_metrics,
    Opentelemetry__Proto__Metrics__V1__Metric *metric,
    size_t metric_slot_limit);

static void destroy_scope_metric_list(
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics **metric_list);

static void destroy_attribute(
    Opentelemetry__Proto__Common__V1__KeyValue *attribute);

static Opentelemetry__Proto__Common__V1__KeyValue *
    initialize_string_attribute(char *key, char *value);

static void destroy_attribute_list(
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list);

static Opentelemetry__Proto__Common__V1__KeyValue **
    initialize_attribute_list(
    size_t element_count);

static void destroy_numerical_data_point(
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint *data_point);

static void destroy_summary_data_point(
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint *data_point);

static void destroy_histogram_data_point(
    Opentelemetry__Proto__Metrics__V1__HistogramDataPoint *data_point);

static void destroy_exponential_histogram_data_point(
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint *data_point);

static void destroy_data_point(
    void *data_point,
    int data_point_type);

static void destroy_numerical_data_point_list(
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint **data_point_list);

static void destroy_summary_data_point_list(
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint **data_point_list);

static void destroy_histogram_data_point_list(
    Opentelemetry__Proto__Metrics__V1__HistogramDataPoint **data_point_list);

static void destroy_exponential_histogram_data_point_list(
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint **data_point_list);

static Opentelemetry__Proto__Metrics__V1__NumberDataPoint *
    initialize_numerical_data_point(
    uint64_t start_time,
    uint64_t timestamp,
    struct cmt_metric *sample,
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list,
    size_t attribute_count);

static Opentelemetry__Proto__Metrics__V1__SummaryDataPoint *
    initialize_summary_data_point(
    uint64_t start_time,
    uint64_t timestamp,
    uint64_t count,
    double sum,
    size_t quantile_count,
    double *quantile_list,
    size_t value_count,
    uint64_t *value_list,
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list,
    size_t attribute_count);

static Opentelemetry__Proto__Metrics__V1__HistogramDataPoint *
    initialize_histogram_data_point(
    uint64_t start_time,
    uint64_t timestamp,
    uint64_t count,
    double sum,
    size_t bucket_count,
    uint64_t *bucket_list,
    size_t boundary_count,
    double *boundary_list,
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list,
    size_t attribute_count);

static int append_attribute_to_numerical_data_point(
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint *data_point,
    Opentelemetry__Proto__Common__V1__KeyValue *attribute,
    size_t attribute_slot_hint);

static int append_attribute_to_summary_data_point(
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint *data_point,
    Opentelemetry__Proto__Common__V1__KeyValue *attribute,
    size_t attribute_slot_hint);

static int append_attribute_to_histogram_data_point(
    Opentelemetry__Proto__Metrics__V1__HistogramDataPoint *data_point,
    Opentelemetry__Proto__Common__V1__KeyValue *attribute,
    size_t attribute_slot_hint);

static int append_attribute_to_data_point(
    void *data_point,
    int data_point_type,
    Opentelemetry__Proto__Common__V1__KeyValue *attribute,
    size_t attribute_slot_hint);

static int append_attribute_to_data_point(
    void *data_point,
    int data_point_type,
    Opentelemetry__Proto__Common__V1__KeyValue *attribute,
    size_t attribute_slot_hint);

static Opentelemetry__Proto__Metrics__V1__NumberDataPoint **
    initialize_numerical_data_point_list(
    size_t element_count);

static Opentelemetry__Proto__Metrics__V1__HistogramDataPoint **
    initialize_histogram_data_point_list(
    size_t element_count);

static Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint **
    initialize_exponential_histogram_data_point_list(
    size_t element_count);

static void destroy_metric(
    Opentelemetry__Proto__Metrics__V1__Metric *metric);

static Opentelemetry__Proto__Metrics__V1__Metric *
    initialize_metric(int type,
                      char *name,
                      char *description,
                      char *unit,
                      int monotonism_flag,
                      int aggregation_temporality_type,
                      size_t data_point_count);

static int append_data_point_to_metric(
    Opentelemetry__Proto__Metrics__V1__Metric *metric,
    void *data_point,
    size_t data_point_slot_hint);

static void destroy_metric_list(
    Opentelemetry__Proto__Metrics__V1__Metric **metric_list);

static Opentelemetry__Proto__Metrics__V1__Metric **
    initialize_metric_list(
    size_t element_count);

void cmt_encode_opentelemetry_destroy(cfl_sds_t text);

static void destroy_opentelemetry_context(
    struct cmt_opentelemetry_context *context);

static struct cmt_opentelemetry_context *initialize_opentelemetry_context(
    struct cmt *cmt);

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_to_otlp_any_value(struct cfl_variant *value);
static inline Opentelemetry__Proto__Common__V1__KeyValue *cfl_variant_kvpair_to_otlp_kvpair(struct cfl_kvpair *input_pair);
static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_kvlist_to_otlp_any_value(struct cfl_variant *value);

static inline void otlp_any_value_destroy(Opentelemetry__Proto__Common__V1__AnyValue *value);
static inline void otlp_kvpair_destroy(Opentelemetry__Proto__Common__V1__KeyValue *kvpair);
static inline void otlp_kvlist_destroy(Opentelemetry__Proto__Common__V1__KeyValueList *kvlist);
static inline void otlp_array_destroy(Opentelemetry__Proto__Common__V1__ArrayValue *array);

static inline void otlp_kvpair_list_destroy(Opentelemetry__Proto__Common__V1__KeyValue **pair_list, size_t entry_count);

static inline void otlp_kvpair_destroy(Opentelemetry__Proto__Common__V1__KeyValue *kvpair)
{
    if (kvpair != NULL) {
        if (kvpair->key != NULL) {
            free(kvpair->key);
        }

        if (kvpair->value != NULL) {
            otlp_any_value_destroy(kvpair->value);
        }

        free(kvpair);
    }
}

static inline void otlp_kvlist_destroy(Opentelemetry__Proto__Common__V1__KeyValueList *kvlist)
{
    size_t index;

    if (kvlist != NULL) {
        if (kvlist->values != NULL) {
            for (index = 0 ; index < kvlist->n_values ; index++) {
                otlp_kvpair_destroy(kvlist->values[index]);
            }

            free(kvlist->values);
        }

        free(kvlist);
    }
}

static inline void otlp_array_destroy(Opentelemetry__Proto__Common__V1__ArrayValue *array)
{
    size_t index;

    if (array != NULL) {
        if (array->values != NULL) {
            for (index = 0 ; index < array->n_values ; index++) {
                otlp_any_value_destroy(array->values[index]);
            }

            free(array->values);
        }

        free(array);
    }
}

static inline void otlp_any_value_destroy(Opentelemetry__Proto__Common__V1__AnyValue *value)
{
    if (value != NULL) {
        if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE) {
            if (value->string_value != NULL) {
                free(value->string_value);
            }
        }
        else if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE) {
            if (value->array_value != NULL) {
                otlp_array_destroy(value->array_value);
            }
        }
        else if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
            if (value->kvlist_value != NULL) {
                otlp_kvlist_destroy(value->kvlist_value);
            }
        }
        else if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE) {
            if (value->bytes_value.data != NULL) {
                free(value->bytes_value.data);
            }
        }

        free(value);
    }
}

static inline Opentelemetry__Proto__Common__V1__KeyValue **otlp_kvpair_list_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__KeyValue **result;

    result = \
        calloc(entry_count, sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));

    return result;
}


static Opentelemetry__Proto__Common__V1__ArrayValue *otlp_array_value_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__ArrayValue *value;

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__ArrayValue));

    if (value != NULL) {
        opentelemetry__proto__common__v1__array_value__init(value);

        if (entry_count > 0) {
            value->values = \
                calloc(entry_count,
                       sizeof(Opentelemetry__Proto__Common__V1__AnyValue *));

            if (value->values == NULL) {
                free(value);

                value = NULL;
            }
            else {
                value->n_values = entry_count;
            }
        }
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__KeyValue *otlp_kvpair_value_initialize()
{
    Opentelemetry__Proto__Common__V1__KeyValue *value;

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__KeyValue));

    if (value != NULL) {
        opentelemetry__proto__common__v1__key_value__init(value);
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__KeyValueList *otlp_kvlist_value_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__KeyValueList *value;

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__KeyValueList));

    if (value != NULL) {
        opentelemetry__proto__common__v1__key_value_list__init(value);

        if (entry_count > 0) {
            value->values = \
                calloc(entry_count,
                       sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));

            if (value->values == NULL) {
                free(value);

                value = NULL;
            }
            else {
                value->n_values = entry_count;
            }
        }
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__AnyValue *otlp_any_value_initialize(int data_type, size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__AnyValue *value;

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__AnyValue));

    if (value == NULL) {
        return NULL;
    }

    opentelemetry__proto__common__v1__any_value__init(value);

    if (data_type == CFL_VARIANT_STRING) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    }
    else if (data_type == CFL_VARIANT_BOOL) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE;
    }
    else if (data_type == CFL_VARIANT_INT) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    }
    else if (data_type == CFL_VARIANT_DOUBLE) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE;
    }
    else if (data_type == CFL_VARIANT_ARRAY) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE;

        value->array_value = otlp_array_value_initialize(entry_count);

        if (value->array_value == NULL) {
            free(value);

            value = NULL;
        }
    }
    else if (data_type == CFL_VARIANT_KVLIST) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE;

        value->kvlist_value = otlp_kvlist_value_initialize(entry_count);

        if (value->kvlist_value == NULL) {
            free(value);

            value = NULL;
        }
    }
    else if (data_type == CFL_VARIANT_BYTES) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE;
    }
    else if (data_type == CFL_VARIANT_REFERENCE) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    }
    else {
        free(value);

        value = NULL;
    }

    return value;
}

static inline Opentelemetry__Proto__Common__V1__KeyValue *cfl_variant_kvpair_to_otlp_kvpair(struct cfl_kvpair *input_pair)
{
    Opentelemetry__Proto__Common__V1__KeyValue *pair;

    pair = otlp_kvpair_value_initialize();

    if (pair != NULL) {
        pair->key = strdup(input_pair->key);

        if (pair->key != NULL) {
            pair->value = cfl_variant_to_otlp_any_value(input_pair->val);

            if (pair->value == NULL) {
                free(pair->key);

                pair->key = NULL;
            }
        }

        if (pair->key == NULL) {
            free(pair);

            pair = NULL;
        }
    }

    return pair;
}

static inline void otlp_kvpair_list_destroy(Opentelemetry__Proto__Common__V1__KeyValue **pair_list, size_t entry_count)
{
    size_t index;

    if (pair_list != NULL) {
        for (index = 0 ; index < entry_count ; index++) {
            otlp_kvpair_destroy(pair_list[index]);
        }

        free(pair_list);
    }
}

static inline Opentelemetry__Proto__Common__V1__KeyValue **cfl_kvlist_to_otlp_kvpair_list(struct cfl_kvlist *kvlist)
{
    size_t                                       entry_count;
    Opentelemetry__Proto__Common__V1__KeyValue  *keyvalue;
    struct cfl_list                             *iterator;
    Opentelemetry__Proto__Common__V1__KeyValue **result;
    struct cfl_kvpair                           *kvpair;
    size_t                                       index;

    entry_count = cfl_kvlist_count(kvlist);

    result = otlp_kvpair_list_initialize(entry_count + 1);

    if (result != NULL) {
        index = 0;

        cfl_list_foreach(iterator, &kvlist->list) {
            kvpair = cfl_list_entry(iterator, struct cfl_kvpair, _head);

            keyvalue = cfl_variant_kvpair_to_otlp_kvpair(kvpair);

            if (keyvalue == NULL) {
                otlp_kvpair_list_destroy(result, entry_count);

                result = NULL;

                break;
            }

            result[index++] = keyvalue;
        }
    }

    return result;
}


static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_kvlist_to_otlp_any_value(struct cfl_variant *value)
{
    size_t                                      entry_count;
    Opentelemetry__Proto__Common__V1__KeyValue *keyvalue;
    struct cfl_list                            *iterator;
    Opentelemetry__Proto__Common__V1__AnyValue *result;
    struct cfl_kvpair                          *kvpair;
    struct cfl_kvlist                          *kvlist;
    size_t                                      index;


    kvlist = value->data.as_kvlist;

    entry_count = cfl_kvlist_count(kvlist);

    result = otlp_any_value_initialize(CFL_VARIANT_KVLIST, entry_count);

    if (result != NULL) {
        index = 0;

        cfl_list_foreach(iterator, &kvlist->list) {
            kvpair = cfl_list_entry(iterator, struct cfl_kvpair, _head);

            keyvalue = cfl_variant_kvpair_to_otlp_kvpair(kvpair);

            if (keyvalue == NULL) {
                otlp_any_value_destroy(result);

                result = NULL;

                break;
            }

            result->kvlist_value->values[index++] = keyvalue;
        }
    }

    return result;
}


static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_array_to_otlp_any_value(struct cfl_variant *value)
{
    size_t                                      entry_count;
    Opentelemetry__Proto__Common__V1__AnyValue *entry_value;
    Opentelemetry__Proto__Common__V1__AnyValue *result;
    struct cfl_array                           *array;
    size_t                                      index;

    array = value->data.as_array;

    entry_count = array->entry_count;

    result = otlp_any_value_initialize(CFL_VARIANT_ARRAY, entry_count);

    if (result != NULL) {
        index = 0;

        for (index = 0 ; index < entry_count ; index++) {
            entry_value = cfl_variant_to_otlp_any_value(cfl_array_fetch_by_index(array, index));

            if (entry_value == NULL) {
                otlp_any_value_destroy(result);

                result = NULL;

                break;
            }

            result->array_value->values[index] = entry_value;
        }
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_string_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_STRING, 0);

    if (result != NULL) {
        result->string_value = strdup(value->data.as_string);

        if (result->string_value == NULL) {
            otlp_any_value_destroy(result);

            result = NULL;
        }
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_boolean_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_BOOL, 0);

    if (result != NULL) {
        result->bool_value = value->data.as_bool;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_int64_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_INT, 0);

    if (result != NULL) {
        result->int_value = value->data.as_int64;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_double_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_DOUBLE, 0);

    if (result != NULL) {
        result->double_value = value->data.as_double;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_binary_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_BYTES, 0);

    if (result != NULL) {
        result->bytes_value.len = cfl_sds_len(value->data.as_bytes);
        result->bytes_value.data = calloc(result->bytes_value.len, sizeof(char));

        if (result->bytes_value.data) {
            memcpy(result->bytes_value.data, value->data.as_bytes, result->bytes_value.len);
        }
        else {
            otlp_any_value_destroy(result);
            result = NULL;
        }
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *cfl_variant_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    if (value->type == CFL_VARIANT_STRING) {
        result = cfl_variant_string_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_BOOL) {
        result = cfl_variant_boolean_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_INT) {
        result = cfl_variant_int64_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_DOUBLE) {
        result = cfl_variant_double_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_ARRAY) {
        result = cfl_variant_array_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_KVLIST) {
        result = cfl_variant_kvlist_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_BYTES) {
        result = cfl_variant_binary_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_REFERENCE) {
        result = cfl_variant_string_to_otlp_any_value(value);
    }
    else {
        result = NULL;
    }

    return result;
}

static char *fetch_metadata_string_key(struct cfl_kvlist *metadata, char *key_name, int *error_flag)
{
    struct cfl_variant *value;

    *error_flag = CMT_FALSE;

    value = cfl_kvlist_fetch(metadata, key_name);

    if (value == NULL) {
        return NULL;
    }

    if (value->type != CFL_VARIANT_STRING) {
        *error_flag = CMT_TRUE;

        return NULL;
    }

    return cfl_sds_create(value->data.as_string);
}

static int64_t fetch_metadata_int64_key(struct cfl_kvlist *metadata, char *key_name, int *error_flag)
{
    struct cfl_variant *value;

    *error_flag = CMT_FALSE;

    value = cfl_kvlist_fetch(metadata, key_name);

    if (value == NULL) {
        return 0;
    }

    if (value->type != CFL_VARIANT_INT) {
        *error_flag = CMT_TRUE;

        return 0;
    }

    return value->data.as_int64;
}

static int is_string_releaseable(char *address)
 {
    return (address != NULL &&
            address != protobuf_c_empty_string);
}

static int is_metric_empty(struct cmt_map *map)
{
    size_t sample_count;

    sample_count = cfl_list_size(&map->metrics);

    if (map->metric_static_set) {
        sample_count++;
    }

    return (sample_count == 0);
}

static size_t get_metric_count(struct cmt *cmt)
{
    size_t                metric_count;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    struct cmt_gauge     *gauge;
    struct cfl_list       *head;

    metric_count = 0;

    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);

        metric_count += !is_metric_empty(counter->map);
    }

    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);

        metric_count += !is_metric_empty(gauge->map);
    }

    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);

        metric_count += !is_metric_empty(untyped->map);
    }

    cfl_list_foreach(head, &cmt->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);

        metric_count += !is_metric_empty(summary->map);
    }

    cfl_list_foreach(head, &cmt->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);

        metric_count += !is_metric_empty(histogram->map);
    }

    cfl_list_foreach(head, &cmt->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);

        metric_count += !is_metric_empty(exp_histogram->map);
    }

    return metric_count;
}

static void destroy_metrics_data(
    Opentelemetry__Proto__Metrics__V1__MetricsData *metrics_data)
{
    if (metrics_data != NULL) {
        destroy_resource_metrics_list(metrics_data->resource_metrics);

        free(metrics_data);
    }
}

static Opentelemetry__Proto__Metrics__V1__MetricsData *
    initialize_metrics_data(size_t resource_metrics_count)
{
    Opentelemetry__Proto__Metrics__V1__MetricsData *metrics_data;

    metrics_data = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__MetricsData));

    if (metrics_data == NULL) {
        return NULL;
    }

    opentelemetry__proto__metrics__v1__metrics_data__init(metrics_data);

    metrics_data->resource_metrics = initialize_resource_metrics_list(resource_metrics_count);

    if (metrics_data->resource_metrics == NULL) {
        destroy_metrics_data(metrics_data);

        return NULL;
    }

    metrics_data->n_resource_metrics = resource_metrics_count;

    return metrics_data;
}

static void destroy_resource(
    Opentelemetry__Proto__Resource__V1__Resource *resource)
{
    if (resource != NULL) {
        if (resource->attributes != NULL) {
            otlp_kvpair_list_destroy(resource->attributes, resource->n_attributes);
        }

        free(resource);
    }
}

static void destroy_resource_metrics(
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *resource_metrics)
{
    if (resource_metrics != NULL) {
        if (is_string_releaseable(resource_metrics->schema_url)) {
            cfl_sds_destroy(resource_metrics->schema_url);
        }

        if (resource_metrics->resource != NULL) {
            destroy_resource(resource_metrics->resource);
        }

        if (resource_metrics->scope_metrics != NULL) {
            destroy_scope_metric_list(resource_metrics->scope_metrics);
        }

        free(resource_metrics);
    }
}

static Opentelemetry__Proto__Metrics__V1__ResourceMetrics *
    initialize_resource_metrics(
    struct cfl_kvlist *resource_metrics_root,
    Opentelemetry__Proto__Resource__V1__Resource *resource,
    size_t scope_metrics_element_count)
{
    int                                                 error_detection_flag;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *resource_metrics;
    struct cfl_kvlist                                  *metadata;

    metadata = fetch_metadata_kvlist_key(resource_metrics_root, "metadata");

    resource_metrics = \
        calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__ResourceMetrics));

    if (resource_metrics == NULL) {
        return NULL;
    }

    opentelemetry__proto__metrics__v1__resource_metrics__init(
        resource_metrics);

    if (metadata != NULL) {
        resource_metrics->schema_url = fetch_metadata_string_key(metadata, "schema_url", &error_detection_flag);
    }
    else {
        error_detection_flag = CMT_FALSE;
    }

    if (error_detection_flag) {
        destroy_resource_metrics(resource_metrics);

        return NULL;
    }

    resource_metrics->scope_metrics = \
        initialize_scope_metrics_list(
                scope_metrics_element_count);

    if (resource_metrics->scope_metrics == NULL) {
        destroy_resource_metrics(resource_metrics);

        return NULL;
    }

    resource_metrics->n_scope_metrics = \
        scope_metrics_element_count;

    resource_metrics->resource = resource;

    return resource_metrics;
}

static void destroy_resource_metrics_list(
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics **metric_list)
{
    size_t element_index;

    if (metric_list != NULL) {
        for (element_index = 0 ;
             metric_list[element_index] != NULL ;
             element_index++) {
            destroy_resource_metrics(metric_list[element_index]);

            metric_list[element_index] = NULL;
        }

        free(metric_list);
    }
}

static Opentelemetry__Proto__Metrics__V1__ResourceMetrics **
    initialize_resource_metrics_list(
    size_t element_count)
{
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics **metric_list;

    metric_list = calloc(element_count + 1,
                         sizeof(Opentelemetry__Proto__Metrics__V1__ResourceMetrics *));

    return metric_list;
}

void destroy_instrumentation_scope(Opentelemetry__Proto__Common__V1__InstrumentationScope *scope)
{
    if (scope->name != NULL) {
        cfl_sds_destroy(scope->name);
    }

    if (scope->version != NULL) {
        cfl_sds_destroy(scope->version);
    }

    if (scope->attributes != NULL) {
        destroy_attribute_list(scope->attributes);
    }

    free(scope);
}

static void destroy_scope_metrics(Opentelemetry__Proto__Metrics__V1__ScopeMetrics *metric)
{
    if (metric != NULL) {
        if (is_string_releaseable(metric->schema_url)) {
            cfl_sds_destroy(metric->schema_url);
            metric->schema_url = NULL;
        }
        if (metric->scope != NULL) {
            destroy_instrumentation_scope(metric->scope);
        }
        destroy_metric_list(metric->metrics);
        free(metric);
    }
}

static Opentelemetry__Proto__Common__V1__InstrumentationScope *
    initialize_instrumentation_scope(
    struct cfl_kvlist *scope_root,
    int *error_detection_flag)
{
    struct cfl_kvlist                                      *attributes;
    struct cfl_kvlist                                      *metadata;
    Opentelemetry__Proto__Common__V1__InstrumentationScope *scope;

    *error_detection_flag = CMT_FALSE;

    if (scope_root == NULL) {
        return NULL;
    }

    attributes = fetch_metadata_kvlist_key(scope_root, "attributes");
    metadata = fetch_metadata_kvlist_key(scope_root, "metadata");

    if (cfl_kvlist_count(attributes) == 0 &&
        cfl_kvlist_count(metadata) == 0) {
        return NULL;
    }

    scope = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__InstrumentationScope));
    if (scope == NULL) {
        *error_detection_flag = CMT_TRUE;

        return NULL;
    }

    opentelemetry__proto__common__v1__instrumentation_scope__init(scope);

    scope->attributes = cfl_kvlist_to_otlp_kvpair_list(attributes);

    if (scope->attributes == NULL) {
        *error_detection_flag = CMT_TRUE;
    }

    scope->n_attributes = cfl_kvlist_count(attributes);

    if (!(*error_detection_flag)) {
        scope->dropped_attributes_count = (uint32_t) fetch_metadata_int64_key(
                                                            metadata,
                                                            "dropped_attributes_count",
                                                            error_detection_flag);
    }

    if (!(*error_detection_flag)) {
        scope->name = fetch_metadata_string_key(metadata, "name", error_detection_flag);
    }

    if (!(*error_detection_flag)) {
        scope->version = fetch_metadata_string_key(metadata, "version", error_detection_flag);
    }

    if (*error_detection_flag &&
        scope != NULL) {
        destroy_instrumentation_scope(scope);

        scope = NULL;
    }

    return scope;
}

static Opentelemetry__Proto__Metrics__V1__ScopeMetrics *initialize_scope_metrics(
                                    struct cfl_kvlist *scope_metrics_root,
                                    size_t metric_element_count)
{
    int                                              error_detection_flag;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *scope_metrics;
    struct cfl_kvlist                               *metadata;

    metadata = fetch_metadata_kvlist_key(scope_metrics_root, "metadata");

    scope_metrics = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__ScopeMetrics));
    if (scope_metrics == NULL) {
        return NULL;
    }

    opentelemetry__proto__metrics__v1__scope_metrics__init(scope_metrics);

    error_detection_flag = CMT_FALSE;

    if (metric_element_count > 0) {
        scope_metrics->metrics = initialize_metric_list(metric_element_count);
        if (scope_metrics->metrics == NULL) {
            error_detection_flag = CMT_TRUE;
        }
    }

    if (!error_detection_flag && metadata != NULL) {
        scope_metrics->schema_url = fetch_metadata_string_key(metadata, "schema_url", &error_detection_flag);

    }

    if (error_detection_flag && scope_metrics != NULL) {
        destroy_scope_metrics(scope_metrics);
        scope_metrics = NULL;
    }

    return scope_metrics;
}

static int append_metric_to_scope_metrics(
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *metrics,
    Opentelemetry__Proto__Metrics__V1__Metric *metric,
    size_t metric_slot_limit)
{
    size_t metric_slot_index;

    for (metric_slot_index = 0 ;
         metric_slot_index < metric_slot_limit;
         metric_slot_index++) {
        if (metrics->metrics[metric_slot_index] == NULL) {
            metrics->metrics[metric_slot_index] = metric;
            if (metric_slot_index + 1 > metrics->n_metrics) {
                metrics->n_metrics = metric_slot_index + 1;
            }

            return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
        }
    }

    return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
}

static void destroy_scope_metric_list(
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics **metric_list)
{
    size_t element_index;

    if (metric_list != NULL) {
        for (element_index = 0 ;
             metric_list[element_index] != NULL ;
             element_index++) {
            destroy_scope_metrics(metric_list[element_index]);

            metric_list[element_index] = NULL;
        }

        free(metric_list);
    }
}

static Opentelemetry__Proto__Metrics__V1__ScopeMetrics **initialize_scope_metrics_list(size_t element_count)
{
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics **metric_list;

    metric_list = calloc(element_count + 1,
                         sizeof(Opentelemetry__Proto__Metrics__V1__ScopeMetrics *));

    return metric_list;
}

static void destroy_attribute(Opentelemetry__Proto__Common__V1__KeyValue *attribute)
{
    if (attribute != NULL) {
        if (attribute->value != NULL) {
            if (attribute->value->value_case == \
                OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE) {
                if (is_string_releaseable(attribute->value->string_value)) {
                    cfl_sds_destroy(attribute->value->string_value);
                }
            }

            free(attribute->value);
        }

        if (is_string_releaseable(attribute->key)) {
            cfl_sds_destroy(attribute->key);
        }

        free(attribute);
    }
}

static Opentelemetry__Proto__Common__V1__KeyValue *
    initialize_string_attribute(char *key, char *value)
{
    Opentelemetry__Proto__Common__V1__KeyValue *attribute;

    attribute = calloc(1,
                       sizeof(Opentelemetry__Proto__Common__V1__KeyValue));

    if (attribute == NULL) {
        return NULL;
    }

    opentelemetry__proto__common__v1__key_value__init(attribute);

    attribute->value = calloc(1,
                              sizeof(Opentelemetry__Proto__Common__V1__AnyValue));

    if (attribute->value == NULL) {
        destroy_attribute(attribute);

        return NULL;
    }

    opentelemetry__proto__common__v1__any_value__init(attribute->value);

    attribute->value->string_value = cfl_sds_create(value);

    if (attribute->value->string_value == NULL) {
        destroy_attribute(attribute);

        return NULL;
    }

    attribute->value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;

    attribute->key = cfl_sds_create(key);

    if (attribute->key == NULL) {
        destroy_attribute(attribute);

        return NULL;
    }

    return attribute;
}

static void destroy_attribute_list(
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list)
{
    size_t element_index;

    if (attribute_list != NULL) {
        for (element_index = 0 ;
             attribute_list[element_index] != NULL ;
             element_index++) {
            destroy_attribute(attribute_list[element_index]);

            attribute_list[element_index] = NULL;
        }

        free(attribute_list);
    }
}

static Opentelemetry__Proto__Common__V1__KeyValue **
    initialize_attribute_list(
    size_t element_count)
{
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list;

    attribute_list = calloc(element_count + 1,
                            sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));

    return attribute_list;
}

static void destroy_numerical_data_point(
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint *data_point)
{
    size_t index;

    if (data_point != NULL) {
        destroy_attribute_list(data_point->attributes);

        if (data_point->exemplars != NULL) {
            for (index = 0; index < data_point->n_exemplars; index++) {
                if (data_point->exemplars[index] != NULL) {
                    destroy_exemplar(data_point->exemplars[index]);
                }
            }

            free(data_point->exemplars);
        }

        free(data_point);
    }
}

static void destroy_summary_data_point(
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint *data_point)
{
    if (data_point != NULL) {
        destroy_attribute_list(data_point->attributes);

        if (data_point->quantile_values != NULL) {
            destroy_summary_value_at_quantile_list(data_point->quantile_values);
        }

        free(data_point);
    }
}

static void destroy_histogram_data_point(
    Opentelemetry__Proto__Metrics__V1__HistogramDataPoint *data_point)
{
    size_t index;

    if (data_point != NULL) {
        destroy_attribute_list(data_point->attributes);

        if (data_point->bucket_counts != NULL) {
            free(data_point->bucket_counts);
        }

        if (data_point->explicit_bounds != NULL) {
            free(data_point->explicit_bounds);
        }

        if (data_point->exemplars != NULL) {
            for (index = 0; index < data_point->n_exemplars; index++) {
                if (data_point->exemplars[index] != NULL) {
                    destroy_exemplar(data_point->exemplars[index]);
                }
            }

            free(data_point->exemplars);
        }

        free(data_point);
    }
}

static void destroy_exponential_histogram_data_point(
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint *data_point)
{
    size_t index;

    if (data_point != NULL) {
        destroy_attribute_list(data_point->attributes);

        if (data_point->positive != NULL) {
            if (data_point->positive->bucket_counts != NULL) {
                free(data_point->positive->bucket_counts);
            }
            free(data_point->positive);
        }

        if (data_point->negative != NULL) {
            if (data_point->negative->bucket_counts != NULL) {
                free(data_point->negative->bucket_counts);
            }
            free(data_point->negative);
        }

        if (data_point->exemplars != NULL) {
            for (index = 0; index < data_point->n_exemplars; index++) {
                if (data_point->exemplars[index] != NULL) {
                    destroy_exemplar(data_point->exemplars[index]);
                }
            }

            free(data_point->exemplars);
        }

        free(data_point);
    }
}

static void destroy_data_point(
    void *data_point,
    int data_point_type)
{
    switch (data_point_type) {
        case CMT_COUNTER:
        case CMT_GAUGE:
        case CMT_UNTYPED:
            return destroy_numerical_data_point(data_point);
        case CMT_SUMMARY:
            return destroy_summary_data_point(data_point);
        case CMT_HISTOGRAM:
            return destroy_histogram_data_point(data_point);
        case CMT_EXP_HISTOGRAM:
            return destroy_exponential_histogram_data_point(data_point);
    }
}

static void destroy_numerical_data_point_list(
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint **data_point_list)
{
    size_t element_index;

    if (data_point_list != NULL) {
        for (element_index = 0 ;
             data_point_list[element_index] != NULL ;
             element_index++) {
            destroy_numerical_data_point(data_point_list[element_index]);

            data_point_list[element_index] = NULL;
        }

        free(data_point_list);
    }
}

static void destroy_summary_data_point_list(
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint **data_point_list)
{
    size_t element_index;

    if (data_point_list != NULL) {
        for (element_index = 0 ;
             data_point_list[element_index] != NULL ;
             element_index++) {
            destroy_summary_data_point(data_point_list[element_index]);

            data_point_list[element_index] = NULL;
        }

        free(data_point_list);
    }
}

static void destroy_histogram_data_point_list(
    Opentelemetry__Proto__Metrics__V1__HistogramDataPoint **data_point_list)
{
    size_t element_index;

    if (data_point_list != NULL) {
        for (element_index = 0 ;
             data_point_list[element_index] != NULL ;
             element_index++) {
            destroy_histogram_data_point(data_point_list[element_index]);

            data_point_list[element_index] = NULL;
        }

        free(data_point_list);
    }
}

static void destroy_exponential_histogram_data_point_list(
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint **data_point_list)
{
    size_t element_index;

    if (data_point_list != NULL) {
        for (element_index = 0 ;
             data_point_list[element_index] != NULL ;
             element_index++) {
            destroy_exponential_histogram_data_point(data_point_list[element_index]);
            data_point_list[element_index] = NULL;
        }

        free(data_point_list);
    }
}

static Opentelemetry__Proto__Metrics__V1__NumberDataPoint *
    initialize_numerical_data_point(
    uint64_t start_time,
    uint64_t timestamp,
    struct cmt_metric *sample,
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list,
    size_t attribute_count)
{
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint *data_point;

    data_point = calloc(1,
                        sizeof(Opentelemetry__Proto__Metrics__V1__NumberDataPoint));

    if (data_point == NULL) {
        return NULL;
    }

    opentelemetry__proto__metrics__v1__number_data_point__init(data_point);

    data_point->start_time_unix_nano = start_time;
    data_point->time_unix_nano = timestamp;
    if (sample != NULL && cmt_metric_get_value_type(sample) == CMT_METRIC_VALUE_INT64) {
        data_point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT;
        data_point->as_int = cmt_metric_get_int64_value(sample);
    }
    else if (sample != NULL && cmt_metric_get_value_type(sample) == CMT_METRIC_VALUE_UINT64) {
        if (cmt_metric_get_uint64_value(sample) <= INT64_MAX) {
            data_point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT;
            data_point->as_int = (int64_t) cmt_metric_get_uint64_value(sample);
        }
        else {
            data_point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_DOUBLE;
            data_point->as_double = (double) cmt_metric_get_uint64_value(sample);
        }
    }
    else {
        data_point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_DOUBLE;
        data_point->as_double = sample != NULL ? cmt_metric_get_value(sample) : 0;
    }
    data_point->attributes = attribute_list;
    data_point->n_attributes = attribute_count;

    return data_point;
}

static Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile *
    initialize_summary_value_at_quantile(
    double quantile, double value)
{
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile *instance;

    instance = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile));

    if (instance != NULL) {
        opentelemetry__proto__metrics__v1__summary_data_point__value_at_quantile__init(instance);

        instance->quantile = quantile;
        instance->value = value;
    }

    return instance;
}

static void destroy_summary_value_at_quantile(
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile *value)
{
    if (value != NULL) {
        free(value);
    }
}

static Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile **
    initialize_summary_value_at_quantile_list(
    size_t element_count)
{
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile **list;

    list = calloc(element_count + 1,
                  sizeof(Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile *));

    return list;
}

static void destroy_summary_value_at_quantile_list(
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile **list)
{
    size_t index;

    if (list != NULL) {
        for (index = 0 ;
             list[index] != NULL ;
             index++) {
            destroy_summary_value_at_quantile(list[index]);

            list[index] = NULL;
        }

        free(list);
    }
}



static Opentelemetry__Proto__Metrics__V1__SummaryDataPoint *
    initialize_summary_data_point(
    uint64_t start_time,
    uint64_t timestamp,
    uint64_t count,
    double sum,
    size_t quantile_count,
    double *quantile_list,
    size_t value_count,
    uint64_t *value_list,
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list,
    size_t attribute_count)
{
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint  *data_point;
    size_t                                                index;

    data_point = calloc(1,
                        sizeof(Opentelemetry__Proto__Metrics__V1__SummaryDataPoint));

    if (data_point == NULL) {
        return NULL;
    }

    opentelemetry__proto__metrics__v1__summary_data_point__init(data_point);

    data_point->start_time_unix_nano = start_time;
    data_point->time_unix_nano = timestamp;

    data_point->count = count;
    data_point->sum = sum;
    data_point->n_quantile_values = quantile_count;

    data_point->quantile_values = initialize_summary_value_at_quantile_list(quantile_count);

    if (data_point->quantile_values == NULL) {
        cmt_errno();

        free(data_point);

        return NULL;
    }

    if (quantile_count > 0) {
        if (value_list != NULL) {
            for (index = 0 ; index < quantile_count ; index++) {
                data_point->quantile_values[index] =
                    initialize_summary_value_at_quantile(quantile_list[index],
                                                         cmt_math_uint64_to_d64(value_list[index]));

                if (data_point->quantile_values[index] == NULL) {
                    destroy_summary_value_at_quantile_list(data_point->quantile_values);

                    free(data_point);

                    return NULL;
                }
            }
        }
    }

    data_point->attributes = attribute_list;
    data_point->n_attributes = attribute_count;

    return data_point;
}

static Opentelemetry__Proto__Metrics__V1__HistogramDataPoint *
    initialize_histogram_data_point(
    uint64_t start_time,
    uint64_t timestamp,
    uint64_t count,
    double sum,
    size_t bucket_count,
    uint64_t *bucket_list,
    size_t boundary_count,
    double *boundary_list,
    Opentelemetry__Proto__Common__V1__KeyValue **attribute_list,
    size_t attribute_count)
{
    Opentelemetry__Proto__Metrics__V1__HistogramDataPoint  *data_point;
    size_t                                                  index;

    data_point = calloc(1,
                        sizeof(Opentelemetry__Proto__Metrics__V1__HistogramDataPoint));

    if (data_point == NULL) {
        return NULL;
    }

    opentelemetry__proto__metrics__v1__histogram_data_point__init(data_point);

    data_point->start_time_unix_nano = start_time;
    data_point->time_unix_nano = timestamp;

    data_point->count = count;
    data_point->n_bucket_counts = bucket_count;


    /*
     * In the OpenTelemetry Metrics protobuf definition, the `sum` field in HistogramDataPoint is
     * marked as `optional`. The generated C code uses a `has_sum` boolean to indicate presence.
     * Set both so the sum is included in the serialized output.
     */
    data_point->sum = sum;
    data_point->has_sum = 1;


    if (bucket_count > 0) {
        data_point->bucket_counts = calloc(bucket_count, sizeof(uint64_t));

        if (data_point->bucket_counts == NULL) {
            cmt_errno();

            free(data_point);

            return NULL;
        }

        if (bucket_list != NULL) {
            for (index = 0 ; index < bucket_count ; index++) {
                data_point->bucket_counts[index] = bucket_list[index];
            }
        }
    }

    data_point->n_explicit_bounds = boundary_count;

    if (boundary_count > 0) {
        data_point->explicit_bounds = calloc(boundary_count, sizeof(double));

        if (data_point->explicit_bounds == NULL) {
            cmt_errno();

            if (data_point->bucket_counts != NULL) {
                free(data_point->bucket_counts);
            }

            free(data_point);

            return NULL;
        }

        if (boundary_list != NULL) {
            for (index = 0 ; index < boundary_count ; index++) {
                data_point->explicit_bounds[index] = boundary_list[index];
            }
        }
    }

    data_point->attributes = attribute_list;
    data_point->n_attributes = attribute_count;

    return data_point;
}

static int append_attribute_to_numerical_data_point(
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint *data_point,
    Opentelemetry__Proto__Common__V1__KeyValue *attribute,
    size_t attribute_slot_hint)
{
    size_t attribute_slot_index;

    for (attribute_slot_index = attribute_slot_hint ;
         attribute_slot_index < data_point->n_attributes;
         attribute_slot_index++) {
        if (data_point->attributes[attribute_slot_index] == NULL) {
            data_point->attributes[attribute_slot_index] = attribute;

            return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
        }
    }

    return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
}

static int append_attribute_to_summary_data_point(
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint *data_point,
    Opentelemetry__Proto__Common__V1__KeyValue *attribute,
    size_t attribute_slot_hint)
{
    size_t attribute_slot_index;

    for (attribute_slot_index = attribute_slot_hint ;
         attribute_slot_index < data_point->n_attributes;
         attribute_slot_index++) {
        if (data_point->attributes[attribute_slot_index] == NULL) {
            data_point->attributes[attribute_slot_index] = attribute;

            return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
        }
    }

    return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
}

static int append_attribute_to_histogram_data_point(
    Opentelemetry__Proto__Metrics__V1__HistogramDataPoint *data_point,
    Opentelemetry__Proto__Common__V1__KeyValue *attribute,
    size_t attribute_slot_hint)
{
    size_t attribute_slot_index;

    for (attribute_slot_index = attribute_slot_hint ;
         attribute_slot_index < data_point->n_attributes;
         attribute_slot_index++) {
        if (data_point->attributes[attribute_slot_index] == NULL) {
            data_point->attributes[attribute_slot_index] = attribute;

            return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
        }
    }

    return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
}

static int append_attribute_to_exponential_histogram_data_point(
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint *data_point,
    Opentelemetry__Proto__Common__V1__KeyValue *attribute,
    size_t attribute_slot_hint)
{
    size_t attribute_slot_index;

    for (attribute_slot_index = attribute_slot_hint ;
         attribute_slot_index < data_point->n_attributes;
         attribute_slot_index++) {
        if (data_point->attributes[attribute_slot_index] == NULL) {
            data_point->attributes[attribute_slot_index] = attribute;

            return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
        }
    }

    return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
}

static int append_attribute_to_data_point(
    void *data_point,
    int data_point_type,
    Opentelemetry__Proto__Common__V1__KeyValue *attribute,
    size_t attribute_slot_hint)
{
    switch (data_point_type) {
        case CMT_COUNTER:
        case CMT_GAUGE:
        case CMT_UNTYPED:
            return append_attribute_to_numerical_data_point(data_point,
                                                            attribute,
                                                            attribute_slot_hint);
        case CMT_SUMMARY:
            return append_attribute_to_summary_data_point(data_point,
                                                          attribute,
                                                          attribute_slot_hint);
        case CMT_HISTOGRAM:
            return append_attribute_to_histogram_data_point(data_point,
                                                                attribute,
                                                                attribute_slot_hint);
        case CMT_EXP_HISTOGRAM:
            return append_attribute_to_exponential_histogram_data_point(data_point,
                                                                        attribute,
                                                                        attribute_slot_hint);
    }

    return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
}

static Opentelemetry__Proto__Metrics__V1__NumberDataPoint **
    initialize_numerical_data_point_list(
    size_t element_count)
{
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint **data_point_list;

    data_point_list = calloc(element_count + 1,
                         sizeof(Opentelemetry__Proto__Metrics__V1__NumberDataPoint *));

    return data_point_list;
}

static Opentelemetry__Proto__Metrics__V1__SummaryDataPoint **
    initialize_summary_data_point_list(
    size_t element_count)
{
    Opentelemetry__Proto__Metrics__V1__SummaryDataPoint **data_point_list;

    data_point_list = calloc(element_count + 1,
                         sizeof(Opentelemetry__Proto__Metrics__V1__SummaryDataPoint *));

    return data_point_list;
}

static Opentelemetry__Proto__Metrics__V1__HistogramDataPoint **
    initialize_histogram_data_point_list(
    size_t element_count)
{
    Opentelemetry__Proto__Metrics__V1__HistogramDataPoint **data_point_list;

    data_point_list = calloc(element_count + 1,
                         sizeof(Opentelemetry__Proto__Metrics__V1__HistogramDataPoint *));

    if (data_point_list == NULL) {
        return NULL;
    }

    return data_point_list;
}

static Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint **
    initialize_exponential_histogram_data_point_list(
    size_t element_count)
{
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint **data_point_list;

    data_point_list = calloc(element_count + 1,
                         sizeof(Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint *));

    if (data_point_list == NULL) {
        return NULL;
    }

    return data_point_list;
}

static void destroy_metric(
    Opentelemetry__Proto__Metrics__V1__Metric *metric)
{
    if (metric != NULL) {
        if (is_string_releaseable(metric->name)) {
            cfl_sds_destroy(metric->name);
            metric->name = NULL;
        }

        if (is_string_releaseable(metric->description)) {
            cfl_sds_destroy(metric->description);
            metric->description = NULL;
        }

        if (is_string_releaseable(metric->unit)) {
            cfl_sds_destroy(metric->unit);
            metric->unit = NULL;
        }

        if (metric->metadata != NULL) {
            otlp_kvpair_list_destroy(metric->metadata, metric->n_metadata);
            metric->metadata = NULL;
            metric->n_metadata = 0;
        }

        if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM) {
            destroy_numerical_data_point_list(metric->sum->data_points);

            free(metric->sum);
        }
        else if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE) {
            destroy_numerical_data_point_list(metric->gauge->data_points);

            free(metric->gauge);
        }
        else if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUMMARY) {
            destroy_summary_data_point_list(metric->summary->data_points);

            free(metric->summary);
        }
        else if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_HISTOGRAM) {
            destroy_histogram_data_point_list(metric->histogram->data_points);

            free(metric->histogram);
        }
        else if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_EXPONENTIAL_HISTOGRAM) {
            destroy_exponential_histogram_data_point_list(metric->exponential_histogram->data_points);

            free(metric->exponential_histogram);
        }

        free(metric);
    }
}

static Opentelemetry__Proto__Metrics__V1__Metric *
    initialize_metric(int type,
                      char *name,
                      char *description,
                      char *unit,
                      int monotonism_flag,
                      int aggregation_temporality_type,
                      size_t data_point_count)
{
    Opentelemetry__Proto__Metrics__V1__Metric *metric;

    metric = calloc(1,
                    sizeof(Opentelemetry__Proto__Metrics__V1__Metric));

    if (metric == NULL) {
        return NULL;
    }

    opentelemetry__proto__metrics__v1__metric__init(metric);

    metric->name = cfl_sds_create(name);

    if (metric->name == NULL) {
        destroy_metric(metric);

        return NULL;
    }

    if (description != NULL) {
        metric->description = cfl_sds_create(description);

        if (metric->description == NULL) {
            destroy_metric(metric);

            return NULL;
        }
    }

    if (unit != NULL) {
        metric->unit = cfl_sds_create(unit);

        if (metric->unit == NULL) {
            destroy_metric(metric);

            return NULL;
        }
    }

    if (type == CMT_COUNTER) {
        metric->sum = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__Sum));

        if (metric->sum == NULL) {
            destroy_metric(metric);

            return NULL;
        }

        opentelemetry__proto__metrics__v1__sum__init(metric->sum);

        metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM;
        metric->sum->data_points = initialize_numerical_data_point_list(data_point_count);

        if (metric->sum->data_points == NULL) {
            destroy_metric(metric);

            return NULL;
        }


        metric->sum->aggregation_temporality = aggregation_temporality_type;
        metric->sum->is_monotonic = monotonism_flag;
        metric->sum->n_data_points = data_point_count;
    }
    else if (type == CMT_UNTYPED) {
        metric->gauge = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__Gauge));

        if (metric->gauge == NULL) {
            destroy_metric(metric);

            return NULL;
        }

        opentelemetry__proto__metrics__v1__gauge__init(metric->gauge);

        metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE;
        metric->gauge->data_points = initialize_numerical_data_point_list(data_point_count);

        if (metric->gauge->data_points == NULL) {
            destroy_metric(metric);

            return NULL;
        }

        metric->gauge->n_data_points = data_point_count;
    }
    else if (type == CMT_GAUGE) {
        metric->gauge = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__Gauge));

        if (metric->gauge == NULL) {
            destroy_metric(metric);

            return NULL;
        }

        opentelemetry__proto__metrics__v1__gauge__init(metric->gauge);

        metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE;
        metric->gauge->data_points = initialize_numerical_data_point_list(data_point_count);

        if (metric->gauge->data_points == NULL) {
            destroy_metric(metric);

            return NULL;
        }

        metric->gauge->n_data_points = data_point_count;
    }
    else if (type == CMT_SUMMARY) {
        metric->summary = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__Summary));

        if (metric->summary == NULL) {
            destroy_metric(metric);

            return NULL;
        }

        opentelemetry__proto__metrics__v1__summary__init(metric->summary);

        metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUMMARY;
        metric->summary->data_points = initialize_summary_data_point_list(data_point_count);

        if (metric->summary->data_points == NULL) {
            destroy_metric(metric);

            return NULL;
        }

        metric->summary->n_data_points = data_point_count;
    }
    else if (type == CMT_HISTOGRAM) {
        metric->histogram = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__Histogram));

        if (metric->histogram == NULL) {
            destroy_metric(metric);

            return NULL;
        }

        opentelemetry__proto__metrics__v1__histogram__init(metric->histogram);

        metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_HISTOGRAM;
        metric->histogram->data_points = initialize_histogram_data_point_list(data_point_count);

        if (metric->histogram->data_points == NULL) {
            destroy_metric(metric);

            return NULL;
        }

        metric->histogram->n_data_points = data_point_count;
        metric->histogram->aggregation_temporality = aggregation_temporality_type;
    }
    else if (type == CMT_EXP_HISTOGRAM) {
        metric->exponential_histogram = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__ExponentialHistogram));

        if (metric->exponential_histogram == NULL) {
            destroy_metric(metric);

            return NULL;
        }

        opentelemetry__proto__metrics__v1__exponential_histogram__init(metric->exponential_histogram);

        metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_EXPONENTIAL_HISTOGRAM;
        metric->exponential_histogram->data_points = initialize_exponential_histogram_data_point_list(data_point_count);

        if (metric->exponential_histogram->data_points == NULL) {
            destroy_metric(metric);

            return NULL;
        }

        metric->exponential_histogram->n_data_points = data_point_count;
        metric->exponential_histogram->aggregation_temporality = aggregation_temporality_type;
    }

    return metric;
}

static int append_data_point_to_metric(
    Opentelemetry__Proto__Metrics__V1__Metric *metric,
    void *data_point,
    size_t data_point_slot_hint)
{
    void   **data_point_list;
    size_t   data_point_slot_index;
    size_t   data_point_slot_count;

    data_point_list = NULL;
    data_point_slot_count = 0;

    if (metric != NULL) {
        if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM) {
            data_point_list = (void **) metric->sum->data_points;
            data_point_slot_count = metric->sum->n_data_points;
        }
        else if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE) {
            data_point_list = (void **) metric->gauge->data_points;
            data_point_slot_count = metric->gauge->n_data_points;
        }
        else if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUMMARY) {
            data_point_list = (void **) metric->summary->data_points;
            data_point_slot_count = metric->summary->n_data_points;
        }
        else if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_HISTOGRAM) {
            data_point_list = (void **) metric->histogram->data_points;
            data_point_slot_count = metric->histogram->n_data_points;
        }
        else if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_EXPONENTIAL_HISTOGRAM) {
            data_point_list = (void **) metric->exponential_histogram->data_points;
            data_point_slot_count = metric->exponential_histogram->n_data_points;
        }
    }

    for (data_point_slot_index = data_point_slot_hint ;
         data_point_slot_index < data_point_slot_count;
         data_point_slot_index++) {
        if (data_point_list[data_point_slot_index] == NULL) {
            data_point_list[data_point_slot_index] = data_point;

            return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
        }
    }

    return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
}

static void destroy_metric_list(
    Opentelemetry__Proto__Metrics__V1__Metric **metric_list)
{
    size_t element_index;

    if (metric_list != NULL) {
        for (element_index = 0 ;
             metric_list[element_index] != NULL ;
             element_index++) {
            destroy_metric(metric_list[element_index]);

            metric_list[element_index] = NULL;
        }

        free(metric_list);
    }
}

static Opentelemetry__Proto__Metrics__V1__Metric **
    initialize_metric_list(
    size_t element_count)
{
    Opentelemetry__Proto__Metrics__V1__Metric **metric_list;

    metric_list = calloc(element_count + 1,
                         sizeof(Opentelemetry__Proto__Metrics__V1__Metric *));

    if (metric_list == NULL) {
        return NULL;
    }

    return metric_list;
}

static void destroy_opentelemetry_context(
    struct cmt_opentelemetry_context *context)
{
    if (context != NULL) {
        if (context->scope_metrics_list != NULL) {
            free(context->scope_metrics_list);
        }

        if (context->metrics_data != NULL) {
            destroy_metrics_data(context->metrics_data);
        }

        free(context);
    }
}

static Opentelemetry__Proto__Resource__V1__Resource *initialize_resource(struct cfl_kvlist *resource_root,
                                                                         int *error_detection_flag)
{
    struct cfl_kvlist                            *attributes;
    struct cfl_kvlist                            *metadata;
    Opentelemetry__Proto__Resource__V1__Resource *resource;

    *error_detection_flag = CMT_FALSE;

    if (resource_root == NULL) {
        return NULL;
    }

    attributes = fetch_metadata_kvlist_key(resource_root, "attributes");
    metadata = fetch_metadata_kvlist_key(resource_root, "metadata");

    if (cfl_kvlist_count(attributes) == 0 && cfl_kvlist_count(metadata) == 0) {
        return NULL;
    }

    resource = calloc(1, sizeof(Opentelemetry__Proto__Resource__V1__Resource));
    if (resource == NULL) {
        *error_detection_flag = CMT_TRUE;
        return NULL;
    }

    opentelemetry__proto__resource__v1__resource__init(resource);

    resource->attributes = cfl_kvlist_to_otlp_kvpair_list(attributes);

    if (resource->attributes == NULL) {
        *error_detection_flag = CMT_TRUE;
    }

    resource->n_attributes = cfl_kvlist_count(attributes);

    if (!(*error_detection_flag)) {
        resource->dropped_attributes_count = (uint32_t) fetch_metadata_int64_key(
                                                            metadata,
                                                            "dropped_attributes_count",
                                                            error_detection_flag);
    }

    if (*error_detection_flag &&
        resource != NULL) {
        destroy_resource(resource);

        resource = NULL;
    }

    return resource;
}

static struct cmt_opentelemetry_context *initialize_opentelemetry_context(
    struct cmt *cmt)
{
    struct cfl_array                             *resource_metrics_list;
    struct cfl_array                             *scope_metrics_list;
    struct cfl_kvlist                            *resource_entry;
    struct cfl_kvlist                            *scope_entry;
    struct cfl_kvlist                            *resource_metrics_root;
    struct cfl_kvlist                            *scope_metrics_root;
    struct cfl_kvlist                            *resource_root;
    struct cfl_kvlist                            *scope_root;
    Opentelemetry__Proto__Resource__V1__Resource *resource;
    struct cmt_opentelemetry_context             *context;
    size_t                                        resource_count;
    size_t                                        scope_count;
    size_t                                        total_scope_count;
    size_t                                        resource_index;
    size_t                                        scope_index;
    size_t                                        flat_scope_index;
    int                                           result;

    resource_metrics_root = fetch_metadata_kvlist_key(cmt->external_metadata, "resource_metrics");
    resource_root = fetch_metadata_kvlist_key(cmt->external_metadata, "resource");
    scope_metrics_root = fetch_metadata_kvlist_key(cmt->external_metadata, "scope_metrics");
    scope_root = fetch_metadata_kvlist_key(cmt->external_metadata, "scope");
    resource_metrics_list = fetch_metadata_array_key(cmt->external_metadata, "resource_metrics_list");

    result = CMT_ENCODE_OPENTELEMETRY_SUCCESS;
    total_scope_count = 0;

    context = calloc(1, sizeof(struct cmt_opentelemetry_context));

    if (context == NULL) {
        result = CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;

        goto cleanup;
    }

    memset(context, 0, sizeof(struct cmt_opentelemetry_context));

    context->cmt = cmt;

    if (resource_metrics_list != NULL && resource_metrics_list->entry_count > 0) {
        resource_count = resource_metrics_list->entry_count;
    }
    else {
        resource_count = 1;
    }

    context->metrics_data = initialize_metrics_data(resource_count);

    if (context->metrics_data == NULL) {
        result = CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;

        goto cleanup;
    }

    for (resource_index = 0; resource_index < resource_count; resource_index++) {
        resource_entry = NULL;
        scope_metrics_list = NULL;

        if (resource_metrics_list != NULL && resource_metrics_list->entry_count > 0) {
            resource_entry = fetch_array_kvlist_entry(resource_metrics_list, resource_index);
        }

        if (resource_entry != NULL) {
            resource_metrics_root = fetch_metadata_kvlist_key(resource_entry, "resource_metrics");
            resource_root = fetch_metadata_kvlist_key(resource_entry, "resource");
            scope_metrics_root = fetch_metadata_kvlist_key(resource_entry, "scope_metrics");
            scope_root = fetch_metadata_kvlist_key(resource_entry, "scope");
            scope_metrics_list = fetch_metadata_array_key(resource_entry, "scope_metrics_list");
        }
        else {
            resource_metrics_root = fetch_metadata_kvlist_key(cmt->external_metadata, "resource_metrics");
            resource_root = fetch_metadata_kvlist_key(cmt->external_metadata, "resource");
            scope_metrics_root = fetch_metadata_kvlist_key(cmt->external_metadata, "scope_metrics");
            scope_root = fetch_metadata_kvlist_key(cmt->external_metadata, "scope");
        }

        if (scope_metrics_list != NULL && scope_metrics_list->entry_count > 0) {
            scope_count = scope_metrics_list->entry_count;
        }
        else {
            scope_count = 1;
        }

        total_scope_count += scope_count;

        resource = initialize_resource(resource_root, &result);

        if (resource == NULL && result) {
            result = CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
            goto cleanup;
        }

        context->metrics_data->resource_metrics[resource_index] =
            initialize_resource_metrics(resource_metrics_root, resource, scope_count);

        if (context->metrics_data->resource_metrics[resource_index] == NULL) {
            result = CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
            goto cleanup;
        }

        for (scope_index = 0; scope_index < scope_count; scope_index++) {
            scope_entry = NULL;

            if (scope_metrics_list != NULL && scope_metrics_list->entry_count > 0) {
                scope_entry = fetch_array_kvlist_entry(scope_metrics_list, scope_index);
            }

            if (scope_entry != NULL) {
                scope_metrics_root = fetch_metadata_kvlist_key(scope_entry, "scope_metrics");
                scope_root = fetch_metadata_kvlist_key(scope_entry, "scope");
            }

            context->metrics_data->resource_metrics[resource_index]->scope_metrics[scope_index] =
                initialize_scope_metrics(scope_metrics_root, get_metric_count(cmt));

            if (context->metrics_data->resource_metrics[resource_index]->scope_metrics[scope_index] == NULL) {
                result = CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
                goto cleanup;
            }

            context->metrics_data->resource_metrics[resource_index]->scope_metrics[scope_index]->scope =
                initialize_instrumentation_scope(scope_root, &result);

            if (result) {
                result = CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
                goto cleanup;
            }
        }
    }

    context->scope_metrics_list =
        calloc(total_scope_count, sizeof(Opentelemetry__Proto__Metrics__V1__ScopeMetrics *));
    if (context->scope_metrics_list == NULL) {
        result = CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        goto cleanup;
    }

    context->scope_metrics_count = total_scope_count;
    flat_scope_index = 0;
    for (resource_index = 0; resource_index < resource_count; resource_index++) {
        for (scope_index = 0;
             scope_index < context->metrics_data->resource_metrics[resource_index]->n_scope_metrics;
             scope_index++) {
            context->scope_metrics_list[flat_scope_index++] =
                context->metrics_data->resource_metrics[resource_index]->scope_metrics[scope_index];
        }
    }

cleanup:
    if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        if (context != NULL) {
            destroy_opentelemetry_context(context);

            context = NULL;
        }
    }

    return context;
}

int append_sample_to_metric(struct cmt_opentelemetry_context *context,
                            Opentelemetry__Proto__Metrics__V1__Metric *metric,
                            struct cmt_map *map,
                            struct cmt_metric *sample,
                            size_t sample_index)
{
    size_t                                              attribute_index;
    size_t                                              attribute_count;
    Opentelemetry__Proto__Common__V1__KeyValue        **attribute_list;
    struct cmt_label                                   *static_label;
    struct cmt_map_label                               *label_value;
    struct cmt_map_label                               *label_name;
    void                                               *data_point = NULL;
    Opentelemetry__Proto__Common__V1__KeyValue         *attribute;
    struct cmt_histogram                               *histogram;
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint *exponential_data_point;
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint__Buckets *positive;
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint__Buckets *negative;
    struct cmt_summary                                 *summary;
    int                                                 result;
    struct cfl_list                                     *head;

    attribute_count = cfl_list_size(&context->cmt->static_labels->list) +
                      cfl_list_size(&sample->labels);

    attribute_list = initialize_attribute_list(attribute_count);

    if (attribute_list == NULL) {
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    if (map->type == CMT_COUNTER   ||
        map->type == CMT_GAUGE     ||
        map->type == CMT_UNTYPED   ) {
        data_point = initialize_numerical_data_point(0,
                                                     cmt_metric_get_timestamp(sample),
                                                     sample,
                                                     attribute_list,
                                                     attribute_count);
    }
    else if (map->type == CMT_SUMMARY) {
        summary = (struct cmt_summary *) map->parent;

        data_point = initialize_summary_data_point(0,
                                                   cmt_metric_get_timestamp(sample),
                                                   cmt_summary_get_count_value(sample),
                                                   cmt_summary_get_sum_value(sample),
                                                   summary->quantiles_count,
                                                   summary->quantiles,
                                                   summary->quantiles_count,
                                                   sample->sum_quantiles,
                                                   attribute_list,
                                                   attribute_count);
    }
    else if (map->type == CMT_HISTOGRAM) {
        histogram = (struct cmt_histogram *) map->parent;

        data_point = initialize_histogram_data_point(0,
                                                     cmt_metric_get_timestamp(sample),
                                                     cmt_metric_hist_get_count_value(sample),
                                                     cmt_metric_hist_get_sum_value(sample),
                                                     histogram->buckets->count + 1,
                                                     sample->hist_buckets,
                                                     histogram->buckets->count,
                                                     histogram->buckets->upper_bounds,
                                                     attribute_list,
                                                     attribute_count);
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        exponential_data_point = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint));
        if (exponential_data_point == NULL) {
            destroy_attribute_list(attribute_list);
            return CMT_ENCODE_OPENTELEMETRY_DATA_POINT_INIT_ERROR;
        }

        opentelemetry__proto__metrics__v1__exponential_histogram_data_point__init(exponential_data_point);

        exponential_data_point->start_time_unix_nano = 0;
        exponential_data_point->time_unix_nano = cmt_metric_get_timestamp(sample);
        exponential_data_point->count = sample->exp_hist_count;
        exponential_data_point->scale = sample->exp_hist_scale;
        exponential_data_point->zero_count = sample->exp_hist_zero_count;
        exponential_data_point->zero_threshold = sample->exp_hist_zero_threshold;
        exponential_data_point->attributes = attribute_list;
        exponential_data_point->n_attributes = attribute_count;

        if (sample->exp_hist_sum_set) {
            exponential_data_point->has_sum = CMT_TRUE;
            exponential_data_point->sum = cmt_math_uint64_to_d64(sample->exp_hist_sum);
        }

        if (sample->exp_hist_positive_count > 0) {
            positive = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint__Buckets));
            if (positive == NULL) {
                destroy_data_point(exponential_data_point, map->type);
                return CMT_ENCODE_OPENTELEMETRY_DATA_POINT_INIT_ERROR;
            }

            opentelemetry__proto__metrics__v1__exponential_histogram_data_point__buckets__init(positive);
            positive->offset = sample->exp_hist_positive_offset;
            positive->n_bucket_counts = sample->exp_hist_positive_count;
            positive->bucket_counts = calloc(sample->exp_hist_positive_count, sizeof(uint64_t));
            if (positive->bucket_counts == NULL) {
                free(positive);
                destroy_data_point(exponential_data_point, map->type);
                return CMT_ENCODE_OPENTELEMETRY_DATA_POINT_INIT_ERROR;
            }
            memcpy(positive->bucket_counts, sample->exp_hist_positive_buckets,
                   sizeof(uint64_t) * sample->exp_hist_positive_count);
            exponential_data_point->positive = positive;
        }

        if (sample->exp_hist_negative_count > 0) {
            negative = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint__Buckets));
            if (negative == NULL) {
                destroy_data_point(exponential_data_point, map->type);
                return CMT_ENCODE_OPENTELEMETRY_DATA_POINT_INIT_ERROR;
            }

            opentelemetry__proto__metrics__v1__exponential_histogram_data_point__buckets__init(negative);
            negative->offset = sample->exp_hist_negative_offset;
            negative->n_bucket_counts = sample->exp_hist_negative_count;
            negative->bucket_counts = calloc(sample->exp_hist_negative_count, sizeof(uint64_t));
            if (negative->bucket_counts == NULL) {
                free(negative);
                destroy_data_point(exponential_data_point, map->type);
                return CMT_ENCODE_OPENTELEMETRY_DATA_POINT_INIT_ERROR;
            }
            memcpy(negative->bucket_counts, sample->exp_hist_negative_buckets,
                   sizeof(uint64_t) * sample->exp_hist_negative_count);
            exponential_data_point->negative = negative;
        }

        data_point = exponential_data_point;
    }

    if (data_point == NULL) {
        destroy_attribute_list(attribute_list);

        return CMT_ENCODE_OPENTELEMETRY_DATA_POINT_INIT_ERROR;
    }

    attribute_index = 0;

    cfl_list_foreach(head, &context->cmt->static_labels->list) {
        static_label = cfl_list_entry(head, struct cmt_label, _head);

        attribute = initialize_string_attribute(static_label->key,
                                                static_label->val);

        if (attribute == NULL) {
            destroy_data_point(data_point, map->type);

            return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = append_attribute_to_data_point(data_point,
                                                map->type,
                                                attribute,
                                                attribute_index++);

        if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS)
        {
            destroy_data_point(data_point, map->type);

            return result;
        }
    }

    label_name = cfl_list_entry_first(&map->label_keys, struct cmt_map_label, _head);

    cfl_list_foreach(head, &sample->labels) {
        label_value = cfl_list_entry(head, struct cmt_map_label, _head);

        attribute = initialize_string_attribute(label_name->name,
                                                label_value->name);

        if (attribute == NULL) {
            destroy_data_point(data_point, map->type);

            return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = append_attribute_to_data_point(data_point,
                                                map->type,
                                                attribute,
                                                attribute_index++);

        if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS)
        {
            destroy_data_point(data_point, map->type);

            return result;
        }

        label_name = cfl_list_entry_next(&label_name->_head, struct cmt_map_label,
                                        _head, &map->label_keys);
    }

    apply_data_point_metadata_from_otlp_context(context->cmt, map, sample, data_point);

    result = append_data_point_to_metric(metric, (void *) data_point, sample_index);

    if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        destroy_data_point(data_point, map->type);

        return result;
    }

    return result;
}

int pack_basic_type(struct cmt_opentelemetry_context *context,
                    struct cmt_map *map,
                    size_t *metric_index)
{
    int                                        aggregation_temporality_type;
    int                                        monotonism_flag;
    size_t                                     sample_index;
    size_t                                     sample_count;
    struct cmt_counter                        *counter;
    struct cmt_histogram                      *histogram;
    struct cmt_exp_histogram                  *exp_histogram;
    struct cmt_metric                         *sample;
    Opentelemetry__Proto__Metrics__V1__Metric *metric;
    int                                        result;
    struct cfl_list                            *head;
    size_t                                     target_scope_index;

    sample_count = 0;

    if (map->metric_static_set) {
        sample_count++;
    }

    sample_count += cfl_list_size(&map->metrics);

    if (sample_count == 0) {
        return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
    }

    aggregation_temporality_type = OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_UNSPECIFIED;
    monotonism_flag = CMT_FALSE;

    if (map->type == CMT_COUNTER) {
        if (map->parent != NULL) {
            counter = (struct cmt_counter *) map->parent;

            if (counter->aggregation_type == CMT_AGGREGATION_TYPE_DELTA) {
                aggregation_temporality_type = OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_DELTA;
            }
            else if (counter->aggregation_type == CMT_AGGREGATION_TYPE_CUMULATIVE) {
                aggregation_temporality_type = OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_CUMULATIVE;
            }

            monotonism_flag = !counter->allow_reset;
        }
    }
    else if (map->type == CMT_HISTOGRAM) {
        if (map->parent != NULL) {
            histogram = (struct cmt_histogram *) map->parent;

            if (histogram->aggregation_type == CMT_AGGREGATION_TYPE_DELTA) {
                aggregation_temporality_type = OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_DELTA;
            }
            else if (histogram->aggregation_type == CMT_AGGREGATION_TYPE_CUMULATIVE) {
                aggregation_temporality_type = OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_CUMULATIVE;
            }
        }
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        if (map->parent != NULL) {
            exp_histogram = (struct cmt_exp_histogram *) map->parent;

            if (exp_histogram->aggregation_type == CMT_AGGREGATION_TYPE_DELTA) {
                aggregation_temporality_type = OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_DELTA;
            }
            else if (exp_histogram->aggregation_type == CMT_AGGREGATION_TYPE_CUMULATIVE) {
                aggregation_temporality_type = OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_CUMULATIVE;
            }
        }
    }

    target_scope_index = resolve_target_scope_index(context, map);
    if (target_scope_index >= context->scope_metrics_count) {
        return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
    }

    metric = initialize_metric(map->type,
                               map->opts->fqname,
                               map->opts->description,
                               map->unit,
                               monotonism_flag,
                               aggregation_temporality_type,
                               sample_count);

    if (metric == NULL) {
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    apply_metric_metadata_from_otlp_context(context->cmt, map, metric);

    sample_index = 0;

    if (map->metric_static_set) {
        result = append_sample_to_metric(context,
                                         metric,
                                         map,
                                         &map->metric,
                                         sample_index++);

        if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_metric(metric);

            return result;
        }
    }

    cfl_list_foreach(head, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);

        result = append_sample_to_metric(context,
                                         metric,
                                         map,
                                         sample,
                                         sample_index++);

        if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
            destroy_metric(metric);

            return result;
        }
    }

    result = append_metric_to_scope_metrics(context->scope_metrics_list[target_scope_index],
                                            metric,
                                            get_metric_count(context->cmt));

    if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        destroy_metric(metric);

        return result;
    }

    (*metric_index)++;

    return result;
}

static cfl_sds_t render_opentelemetry_context_to_sds(
    struct cmt_opentelemetry_context *context)
{
    cfl_sds_t result_buffer;
    size_t    result_size;

    result_size = opentelemetry__proto__metrics__v1__metrics_data__get_packed_size(
                    context->metrics_data);

    result_buffer = cfl_sds_create_size(result_size);

    if(result_buffer != NULL) {
        opentelemetry__proto__metrics__v1__metrics_data__pack(
            context->metrics_data,
            (uint8_t *) result_buffer);

        cfl_sds_set_len(result_buffer, result_size);
    }

    return result_buffer;
}

cfl_sds_t cmt_encode_opentelemetry_create(struct cmt *cmt)
{
    size_t                            metric_index;
    struct cmt_opentelemetry_context *context;
    struct cmt_histogram             *histogram;
    struct cmt_exp_histogram         *exp_histogram;
    struct cmt_summary               *summary;
    struct cmt_untyped               *untyped;
    struct cmt_counter               *counter;
    int                               result;
    struct cmt_gauge                 *gauge;
    struct cfl_list                   *head;
    cfl_sds_t                         buf;

    buf = NULL;
    result = 0;

    context = initialize_opentelemetry_context(cmt);

    if (context == NULL) {
        return NULL;
    }

    metric_index = 0;

    if (result == CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        cfl_list_foreach(head, &cmt->counters) {
            counter = cfl_list_entry(head, struct cmt_counter, _head);
            result = pack_basic_type(context, counter->map, &metric_index);

            if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
                break;
            }
        }
    }

    if (result == CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        cfl_list_foreach(head, &cmt->gauges) {
            gauge = cfl_list_entry(head, struct cmt_gauge, _head);
            result = pack_basic_type(context, gauge->map, &metric_index);

            if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
                break;
            }
        }
    }

    if (result == CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        cfl_list_foreach(head, &cmt->untypeds) {
            untyped = cfl_list_entry(head, struct cmt_untyped, _head);
            result = pack_basic_type(context, untyped->map, &metric_index);

            if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
                break;
            }
        }
    }

    if (result == CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        cfl_list_foreach(head, &cmt->summaries) {
            summary = cfl_list_entry(head, struct cmt_summary, _head);
            result = pack_basic_type(context, summary->map, &metric_index);

            if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
                break;
            }
        }
    }

    if (result == CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        cfl_list_foreach(head, &cmt->histograms) {
            histogram = cfl_list_entry(head, struct cmt_histogram, _head);
            result = pack_basic_type(context, histogram->map, &metric_index);

            if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
                break;
            }
        }
    }

    if (result == CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        cfl_list_foreach(head, &cmt->exp_histograms) {
            exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
            result = pack_basic_type(context, exp_histogram->map, &metric_index);

            if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
                break;
            }
        }
    }

    if (result == CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        buf = render_opentelemetry_context_to_sds(context);
    }

    destroy_opentelemetry_context(context);

    return buf;
}

void cmt_encode_opentelemetry_destroy(cfl_sds_t text)
{
    cfl_sds_destroy(text);
}
