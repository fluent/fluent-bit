/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2026 The CMetrics Authors
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

/*
 * OTLP traffic through the transformations Fluent Bit applies to it:
 *
 *   direct  : in_opentelemetry -> out_opentelemetry in one process
 *   chunk   : OTLP -> MessagePack chunk -> OTLP (storage, output processors)
 *   forward : two MessagePack hops (agent -> forward -> aggregator -> OTLP)
 *   cat     : chunk decoded and merged with cmt_cat (batching, processors)
 *
 * Every data point of the input request is reduced to a canonical line that
 * includes its resource, scope, metric and point fields with exact bit
 * patterns for doubles and typed, order independent attributes. A pipeline is
 * lossless when the output request produces the same multiset of lines.
 */

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_cat.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_opentelemetry.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <cmetrics/cmt_otlp_metadata.h>
#include <cmetrics/cmt_variant_utils.h>
#include <fluent-otel-proto/fluent-otel.h>

#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "cmt_tests.h"

/* Builder and canonicalization allocations: abort rather than flood the
 * check log, these are test infrastructure, not behavior under test. */
static void *require(void *pointer)
{
    if (pointer == NULL) {
        abort();
    }
    return pointer;
}

typedef Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest otlp_request;
typedef Opentelemetry__Proto__Metrics__V1__ResourceMetrics otlp_resource_metrics;
typedef Opentelemetry__Proto__Metrics__V1__ScopeMetrics otlp_scope_metrics;
typedef Opentelemetry__Proto__Metrics__V1__Metric otlp_metric;
typedef Opentelemetry__Proto__Metrics__V1__NumberDataPoint otlp_number_point;
typedef Opentelemetry__Proto__Metrics__V1__HistogramDataPoint otlp_histogram_point;
typedef Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint otlp_exp_point;
typedef Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint__Buckets otlp_exp_buckets;
typedef Opentelemetry__Proto__Metrics__V1__SummaryDataPoint otlp_summary_point;
typedef Opentelemetry__Proto__Metrics__V1__SummaryDataPoint__ValueAtQuantile otlp_quantile;
typedef Opentelemetry__Proto__Metrics__V1__Exemplar otlp_exemplar;
typedef Opentelemetry__Proto__Common__V1__KeyValue otlp_kv;
typedef Opentelemetry__Proto__Common__V1__AnyValue otlp_any;

#define TEMPORALITY_DELTA \
    OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_DELTA
#define TEMPORALITY_CUMULATIVE \
    OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_CUMULATIVE

enum pipeline {
    PIPELINE_DIRECT = 0,
    PIPELINE_CHUNK,
    PIPELINE_FORWARD,
    PIPELINE_CAT,
    PIPELINE_COUNT
};

static const char *pipeline_names[] = {"direct", "chunk", "forward", "cat"};

/* Every builder allocation is released at once after a case. */
static void **allocations;
static size_t allocation_count;
static size_t allocation_size;

static void *test_alloc(size_t size)
{
    void **grown;
    void *memory;

    if (allocation_count == allocation_size) {
        allocation_size = allocation_size ? allocation_size * 2 : 64;
        grown = require(realloc(allocations, allocation_size * sizeof(*allocations)));
        allocations = grown;
    }
    memory = require(calloc(1, size ? size : 1));
    allocations[allocation_count++] = memory;
    return memory;
}

static void test_alloc_release(void)
{
    size_t index;

    for (index = 0; index < allocation_count; index++) {
        free(allocations[index]);
    }
    free(allocations);
    allocations = NULL;
    allocation_count = 0;
    allocation_size = 0;
}

static void **pointer_list(size_t count, va_list arguments)
{
    void **list;
    size_t index;

    list = test_alloc(sizeof(void *) * count);
    for (index = 0; index < count; index++) {
        list[index] = va_arg(arguments, void *);
    }
    return list;
}

/* AnyValue and KeyValue builders */

static otlp_any *any_string(const char *value)
{
    otlp_any *any = test_alloc(sizeof(*any));

    opentelemetry__proto__common__v1__any_value__init(any);
    any->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    any->string_value = (char *) value;
    return any;
}

static otlp_any *any_int(int64_t value)
{
    otlp_any *any = test_alloc(sizeof(*any));

    opentelemetry__proto__common__v1__any_value__init(any);
    any->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    any->int_value = value;
    return any;
}

static otlp_any *any_double(double value)
{
    otlp_any *any = test_alloc(sizeof(*any));

    opentelemetry__proto__common__v1__any_value__init(any);
    any->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE;
    any->double_value = value;
    return any;
}

static otlp_any *any_bool(int value)
{
    otlp_any *any = test_alloc(sizeof(*any));

    opentelemetry__proto__common__v1__any_value__init(any);
    any->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE;
    any->bool_value = value;
    return any;
}

static otlp_any *any_bytes(const char *value, size_t length)
{
    otlp_any *any = test_alloc(sizeof(*any));

    opentelemetry__proto__common__v1__any_value__init(any);
    any->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE;
    any->bytes_value.data = (uint8_t *) value;
    any->bytes_value.len = length;
    return any;
}

static otlp_any *any_array(size_t count, ...)
{
    va_list arguments;
    otlp_any *any = test_alloc(sizeof(*any));
    Opentelemetry__Proto__Common__V1__ArrayValue *array = test_alloc(sizeof(*array));

    opentelemetry__proto__common__v1__any_value__init(any);
    opentelemetry__proto__common__v1__array_value__init(array);
    va_start(arguments, count);
    array->values = (otlp_any **) pointer_list(count, arguments);
    va_end(arguments);
    array->n_values = count;
    any->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE;
    any->array_value = array;
    return any;
}

static otlp_any *any_kvlist(size_t count, ...)
{
    va_list arguments;
    otlp_any *any = test_alloc(sizeof(*any));
    Opentelemetry__Proto__Common__V1__KeyValueList *list = test_alloc(sizeof(*list));

    opentelemetry__proto__common__v1__any_value__init(any);
    opentelemetry__proto__common__v1__key_value_list__init(list);
    va_start(arguments, count);
    list->values = (otlp_kv **) pointer_list(count, arguments);
    va_end(arguments);
    list->n_values = count;
    any->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE;
    any->kvlist_value = list;
    return any;
}

static otlp_kv *kv(const char *key, otlp_any *value)
{
    otlp_kv *pair = test_alloc(sizeof(*pair));

    opentelemetry__proto__common__v1__key_value__init(pair);
    pair->key = (char *) key;
    pair->value = value;
    return pair;
}

static otlp_kv **kv_list(size_t count, ...)
{
    va_list arguments;
    otlp_kv **list;

    va_start(arguments, count);
    list = (otlp_kv **) pointer_list(count, arguments);
    va_end(arguments);
    return list;
}

/* Data point builders */

static otlp_number_point *number_int(uint64_t start, uint64_t time, int64_t value,
                                     size_t attribute_count, otlp_kv **attributes)
{
    otlp_number_point *point = test_alloc(sizeof(*point));

    opentelemetry__proto__metrics__v1__number_data_point__init(point);
    point->start_time_unix_nano = start;
    point->time_unix_nano = time;
    point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT;
    point->as_int = value;
    point->n_attributes = attribute_count;
    point->attributes = attributes;
    return point;
}

static otlp_number_point *number_double(uint64_t start, uint64_t time, double value,
                                        size_t attribute_count, otlp_kv **attributes)
{
    otlp_number_point *point = number_int(start, time, 0, attribute_count, attributes);

    point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_DOUBLE;
    point->as_double = value;
    return point;
}

static otlp_exemplar *exemplar_double(uint64_t time, double value, const char *trace_id,
                                      const char *span_id, size_t attribute_count,
                                      otlp_kv **attributes)
{
    otlp_exemplar *exemplar = test_alloc(sizeof(*exemplar));

    opentelemetry__proto__metrics__v1__exemplar__init(exemplar);
    exemplar->time_unix_nano = time;
    exemplar->value_case = OPENTELEMETRY__PROTO__METRICS__V1__EXEMPLAR__VALUE_AS_DOUBLE;
    exemplar->as_double = value;
    if (trace_id != NULL) {
        exemplar->trace_id.data = (uint8_t *) trace_id;
        exemplar->trace_id.len = 16;
    }
    if (span_id != NULL) {
        exemplar->span_id.data = (uint8_t *) span_id;
        exemplar->span_id.len = 8;
    }
    exemplar->n_filtered_attributes = attribute_count;
    exemplar->filtered_attributes = attributes;
    return exemplar;
}

static otlp_exemplar *exemplar_int(uint64_t time, int64_t value)
{
    otlp_exemplar *exemplar = exemplar_double(time, 0, NULL, NULL, 0, NULL);

    exemplar->value_case = OPENTELEMETRY__PROTO__METRICS__V1__EXEMPLAR__VALUE_AS_INT;
    exemplar->as_int = value;
    return exemplar;
}

static otlp_exemplar **exemplar_list(size_t count, ...)
{
    va_list arguments;
    otlp_exemplar **list;

    va_start(arguments, count);
    list = (otlp_exemplar **) pointer_list(count, arguments);
    va_end(arguments);
    return list;
}

static otlp_histogram_point *histogram_point(uint64_t start, uint64_t time,
                                             size_t bound_count, const double *bounds,
                                             const uint64_t *counts,
                                             size_t attribute_count, otlp_kv **attributes)
{
    otlp_histogram_point *point = test_alloc(sizeof(*point));
    size_t index;

    opentelemetry__proto__metrics__v1__histogram_data_point__init(point);
    point->start_time_unix_nano = start;
    point->time_unix_nano = time;
    point->n_explicit_bounds = bound_count;
    point->explicit_bounds = test_alloc(sizeof(double) * (bound_count + 1));
    if (bound_count > 0) {
        memcpy(point->explicit_bounds, bounds, sizeof(double) * bound_count);
    }
    point->n_bucket_counts = bound_count + 1;
    point->bucket_counts = test_alloc(sizeof(uint64_t) * (bound_count + 1));
    memcpy(point->bucket_counts, counts, sizeof(uint64_t) * (bound_count + 1));
    for (index = 0; index <= bound_count; index++) {
        point->count += counts[index];
    }
    point->n_attributes = attribute_count;
    point->attributes = attributes;
    return point;
}

static otlp_exp_buckets *exp_buckets(int32_t offset, size_t count, const uint64_t *counts)
{
    otlp_exp_buckets *buckets = test_alloc(sizeof(*buckets));

    opentelemetry__proto__metrics__v1__exponential_histogram_data_point__buckets__init(buckets);
    buckets->offset = offset;
    buckets->n_bucket_counts = count;
    buckets->bucket_counts = test_alloc(sizeof(uint64_t) * (count + 1));
    memcpy(buckets->bucket_counts, counts, sizeof(uint64_t) * count);
    return buckets;
}

static otlp_exp_point *exp_point(uint64_t start, uint64_t time, int32_t scale,
                                 uint64_t zero_count, double zero_threshold,
                                 otlp_exp_buckets *positive, otlp_exp_buckets *negative,
                                 size_t attribute_count, otlp_kv **attributes)
{
    otlp_exp_point *point = test_alloc(sizeof(*point));
    size_t index;

    opentelemetry__proto__metrics__v1__exponential_histogram_data_point__init(point);
    point->start_time_unix_nano = start;
    point->time_unix_nano = time;
    point->scale = scale;
    point->zero_count = zero_count;
    point->zero_threshold = zero_threshold;
    point->positive = positive;
    point->negative = negative;
    point->count = zero_count;
    for (index = 0; positive != NULL && index < positive->n_bucket_counts; index++) {
        point->count += positive->bucket_counts[index];
    }
    for (index = 0; negative != NULL && index < negative->n_bucket_counts; index++) {
        point->count += negative->bucket_counts[index];
    }
    point->n_attributes = attribute_count;
    point->attributes = attributes;
    return point;
}

static otlp_summary_point *summary_point(uint64_t start, uint64_t time, uint64_t count,
                                         double sum, size_t quantile_count,
                                         const double *quantiles, const double *values,
                                         size_t attribute_count, otlp_kv **attributes)
{
    otlp_summary_point *point = test_alloc(sizeof(*point));
    size_t index;

    opentelemetry__proto__metrics__v1__summary_data_point__init(point);
    point->start_time_unix_nano = start;
    point->time_unix_nano = time;
    point->count = count;
    point->sum = sum;
    point->n_quantile_values = quantile_count;
    point->quantile_values = test_alloc(sizeof(otlp_quantile *) * (quantile_count + 1));
    for (index = 0; index < quantile_count; index++) {
        point->quantile_values[index] = test_alloc(sizeof(otlp_quantile));
        opentelemetry__proto__metrics__v1__summary_data_point__value_at_quantile__init(
            point->quantile_values[index]);
        point->quantile_values[index]->quantile = quantiles[index];
        point->quantile_values[index]->value = values[index];
    }
    point->n_attributes = attribute_count;
    point->attributes = attributes;
    return point;
}

/* Metric builders: points are passed as a count and a variadic list. */

static otlp_metric *metric_base(const char *name, const char *description, const char *unit)
{
    otlp_metric *metric = test_alloc(sizeof(*metric));

    opentelemetry__proto__metrics__v1__metric__init(metric);
    metric->name = (char *) name;
    metric->description = (char *) (description ? description : "");
    metric->unit = (char *) (unit ? unit : "");
    return metric;
}

static otlp_metric *metric_gauge(const char *name, const char *description, const char *unit,
                                 size_t count, ...)
{
    va_list arguments;
    otlp_metric *metric = metric_base(name, description, unit);
    Opentelemetry__Proto__Metrics__V1__Gauge *gauge = test_alloc(sizeof(*gauge));

    opentelemetry__proto__metrics__v1__gauge__init(gauge);
    va_start(arguments, count);
    gauge->data_points = (otlp_number_point **) pointer_list(count, arguments);
    va_end(arguments);
    gauge->n_data_points = count;
    metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE;
    metric->gauge = gauge;
    return metric;
}

static otlp_metric *metric_sum(const char *name, const char *description, const char *unit,
                               int temporality, int monotonic, size_t count, ...)
{
    va_list arguments;
    otlp_metric *metric = metric_base(name, description, unit);
    Opentelemetry__Proto__Metrics__V1__Sum *sum = test_alloc(sizeof(*sum));

    opentelemetry__proto__metrics__v1__sum__init(sum);
    va_start(arguments, count);
    sum->data_points = (otlp_number_point **) pointer_list(count, arguments);
    va_end(arguments);
    sum->n_data_points = count;
    sum->aggregation_temporality = temporality;
    sum->is_monotonic = monotonic;
    metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM;
    metric->sum = sum;
    return metric;
}

static otlp_metric *metric_histogram(const char *name, const char *unit, int temporality,
                                     size_t count, ...)
{
    va_list arguments;
    otlp_metric *metric = metric_base(name, "histogram", unit);
    Opentelemetry__Proto__Metrics__V1__Histogram *histogram = test_alloc(sizeof(*histogram));

    opentelemetry__proto__metrics__v1__histogram__init(histogram);
    va_start(arguments, count);
    histogram->data_points = (otlp_histogram_point **) pointer_list(count, arguments);
    va_end(arguments);
    histogram->n_data_points = count;
    histogram->aggregation_temporality = temporality;
    metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_HISTOGRAM;
    metric->histogram = histogram;
    return metric;
}

static otlp_metric *metric_exp_histogram(const char *name, int temporality, size_t count, ...)
{
    va_list arguments;
    otlp_metric *metric = metric_base(name, "exponential histogram", "s");
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogram *histogram =
        test_alloc(sizeof(*histogram));

    opentelemetry__proto__metrics__v1__exponential_histogram__init(histogram);
    va_start(arguments, count);
    histogram->data_points = (otlp_exp_point **) pointer_list(count, arguments);
    va_end(arguments);
    histogram->n_data_points = count;
    histogram->aggregation_temporality = temporality;
    metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_EXPONENTIAL_HISTOGRAM;
    metric->exponential_histogram = histogram;
    return metric;
}

static otlp_metric *metric_summary(const char *name, size_t count, ...)
{
    va_list arguments;
    otlp_metric *metric = metric_base(name, "summary", "ms");
    Opentelemetry__Proto__Metrics__V1__Summary *summary = test_alloc(sizeof(*summary));

    opentelemetry__proto__metrics__v1__summary__init(summary);
    va_start(arguments, count);
    summary->data_points = (otlp_summary_point **) pointer_list(count, arguments);
    va_end(arguments);
    summary->n_data_points = count;
    metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUMMARY;
    metric->summary = summary;
    return metric;
}

static otlp_scope_metrics *scope(const char *name, const char *version,
                                 size_t attribute_count, otlp_kv **attributes,
                                 size_t count, ...)
{
    va_list arguments;
    otlp_scope_metrics *scope_metrics = test_alloc(sizeof(*scope_metrics));
    Opentelemetry__Proto__Common__V1__InstrumentationScope *instrumentation;

    opentelemetry__proto__metrics__v1__scope_metrics__init(scope_metrics);
    if (name != NULL) {
        instrumentation = test_alloc(sizeof(*instrumentation));
        opentelemetry__proto__common__v1__instrumentation_scope__init(instrumentation);
        instrumentation->name = (char *) name;
        instrumentation->version = (char *) (version ? version : "");
        instrumentation->n_attributes = attribute_count;
        instrumentation->attributes = attributes;
        scope_metrics->scope = instrumentation;
    }
    va_start(arguments, count);
    scope_metrics->metrics = (otlp_metric **) pointer_list(count, arguments);
    va_end(arguments);
    scope_metrics->n_metrics = count;
    return scope_metrics;
}

static otlp_resource_metrics *resource(size_t attribute_count, otlp_kv **attributes,
                                       size_t count, ...)
{
    va_list arguments;
    otlp_resource_metrics *resource_metrics = test_alloc(sizeof(*resource_metrics));
    Opentelemetry__Proto__Resource__V1__Resource *resource_value =
        test_alloc(sizeof(*resource_value));

    opentelemetry__proto__metrics__v1__resource_metrics__init(resource_metrics);
    opentelemetry__proto__resource__v1__resource__init(resource_value);
    resource_value->n_attributes = attribute_count;
    resource_value->attributes = attributes;
    resource_metrics->resource = resource_value;
    va_start(arguments, count);
    resource_metrics->scope_metrics = (otlp_scope_metrics **) pointer_list(count, arguments);
    va_end(arguments);
    resource_metrics->n_scope_metrics = count;
    return resource_metrics;
}

static otlp_request *request(size_t count, ...)
{
    va_list arguments;
    otlp_request *value = test_alloc(sizeof(*value));

    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__init(value);
    va_start(arguments, count);
    value->resource_metrics = (otlp_resource_metrics **) pointer_list(count, arguments);
    va_end(arguments);
    value->n_resource_metrics = count;
    return value;
}

/* Canonical form */

/* cmt_cat merges metric families only; context metadata (resource, scope)
 * is not merged by design, so the cat pipeline compares families alone. */
static int canon_include_context = CMT_TRUE;

struct lines {
    cfl_sds_t *entries;
    size_t count;
    size_t size;
};

static void lines_add(struct lines *lines, cfl_sds_t line)
{
    cfl_sds_t *grown;

    if (lines->count == lines->size) {
        lines->size = lines->size ? lines->size * 2 : 16;
        grown = require(realloc(lines->entries, lines->size * sizeof(*grown)));
        lines->entries = grown;
    }
    lines->entries[lines->count++] = line;
}

static void lines_destroy(struct lines *lines)
{
    size_t index;

    for (index = 0; index < lines->count; index++) {
        cfl_sds_destroy(lines->entries[index]);
    }
    free(lines->entries);
    memset(lines, 0, sizeof(*lines));
}

static cfl_sds_t sds_printf(cfl_sds_t buffer, const char *format, ...)
{
    va_list arguments;
    char stack[512];
    int length;

    va_start(arguments, format);
    length = vsnprintf(stack, sizeof(stack), format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t) length >= sizeof(stack)) {
        abort();
    }
    return require(cfl_sds_cat(buffer, stack, length));
}

static cfl_sds_t canon_double(cfl_sds_t buffer, double value)
{
    uint64_t bits;

    memcpy(&bits, &value, sizeof(bits));
    return sds_printf(buffer, "%016" PRIx64, bits);
}

static cfl_sds_t canon_bytes(cfl_sds_t buffer, const uint8_t *data, size_t length)
{
    size_t index;

    for (index = 0; index < length; index++) {
        buffer = sds_printf(buffer, "%02x", data[index]);
    }
    return buffer;
}

static int compare_strings(const void *left, const void *right)
{
    return strcmp(*(const char **) left, *(const char **) right);
}

static cfl_sds_t canon_attributes(cfl_sds_t buffer, size_t count, otlp_kv **attributes);

static cfl_sds_t canon_any(cfl_sds_t buffer, otlp_any *value)
{
    size_t index;

    if (value == NULL) {
        return cfl_sds_cat(buffer, "none", 4);
    }
    switch (value->value_case) {
    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE:
        buffer = cfl_sds_cat(buffer, "s:", 2);
        return cfl_sds_cat(buffer, value->string_value, strlen(value->string_value));
    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE:
        return sds_printf(buffer, "i:%" PRId64, value->int_value);
    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE:
        buffer = cfl_sds_cat(buffer, "d:", 2);
        return canon_double(buffer, value->double_value);
    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE:
        return sds_printf(buffer, "b:%d", value->bool_value ? 1 : 0);
    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE:
        buffer = cfl_sds_cat(buffer, "x:", 2);
        return canon_bytes(buffer, value->bytes_value.data, value->bytes_value.len);
    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE:
        buffer = cfl_sds_cat(buffer, "[", 1);
        for (index = 0; index < value->array_value->n_values; index++) {
            buffer = canon_any(buffer, value->array_value->values[index]);
            buffer = cfl_sds_cat(buffer, ",", 1);
        }
        return cfl_sds_cat(buffer, "]", 1);
    case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE:
        return canon_attributes(buffer, value->kvlist_value->n_values,
                                value->kvlist_value->values);
    default:
        return cfl_sds_cat(buffer, "unset", 5);
    }
}

/* Attributes are a set in OTLP: canonicalize independently of order. */
static cfl_sds_t canon_attributes(cfl_sds_t buffer, size_t count, otlp_kv **attributes)
{
    cfl_sds_t *entries;
    size_t index;

    entries = require(calloc(count + 1, sizeof(*entries)));
    for (index = 0; index < count; index++) {
        entries[index] = cfl_sds_create(attributes[index]->key);
        entries[index] = cfl_sds_cat(entries[index], "=", 1);
        entries[index] = canon_any(entries[index], attributes[index]->value);
    }
    qsort(entries, count, sizeof(*entries), compare_strings);
    buffer = cfl_sds_cat(buffer, "{", 1);
    for (index = 0; index < count; index++) {
        buffer = cfl_sds_cat(buffer, entries[index], cfl_sds_len(entries[index]));
        buffer = cfl_sds_cat(buffer, ";", 1);
        cfl_sds_destroy(entries[index]);
    }
    free(entries);
    return cfl_sds_cat(buffer, "}", 1);
}

static cfl_sds_t canon_exemplars(cfl_sds_t buffer, size_t count, otlp_exemplar **exemplars)
{
    size_t index;
    otlp_exemplar *exemplar;

    buffer = cfl_sds_cat(buffer, " ex=[", 5);
    for (index = 0; index < count; index++) {
        exemplar = exemplars[index];
        buffer = sds_printf(buffer, "t%" PRIu64 ",", exemplar->time_unix_nano);
        if (exemplar->value_case == OPENTELEMETRY__PROTO__METRICS__V1__EXEMPLAR__VALUE_AS_INT) {
            buffer = sds_printf(buffer, "i%" PRId64, exemplar->as_int);
        }
        else {
            buffer = cfl_sds_cat(buffer, "d", 1);
            buffer = canon_double(buffer, exemplar->as_double);
        }
        buffer = cfl_sds_cat(buffer, ",tr", 3);
        buffer = canon_bytes(buffer, exemplar->trace_id.data, exemplar->trace_id.len);
        buffer = cfl_sds_cat(buffer, ",sp", 3);
        buffer = canon_bytes(buffer, exemplar->span_id.data, exemplar->span_id.len);
        buffer = canon_attributes(buffer, exemplar->n_filtered_attributes,
                                  exemplar->filtered_attributes);
        buffer = cfl_sds_cat(buffer, ";", 1);
    }
    return cfl_sds_cat(buffer, "]", 1);
}

static cfl_sds_t canon_point_common(cfl_sds_t buffer, size_t attribute_count,
                                    otlp_kv **attributes, uint64_t start, uint64_t time,
                                    uint32_t flags)
{
    buffer = cfl_sds_cat(buffer, " attrs=", 7);
    buffer = canon_attributes(buffer, attribute_count, attributes);
    return sds_printf(buffer, " st=%" PRIu64 " t=%" PRIu64 " flags=%u", start, time, flags);
}

static cfl_sds_t canon_optional_double(cfl_sds_t buffer, const char *name,
                                       int present, double value)
{
    buffer = sds_printf(buffer, " %s=", name);
    if (!present) {
        return cfl_sds_cat(buffer, "-", 1);
    }
    return canon_double(buffer, value);
}

static void canon_metric(struct lines *lines, cfl_sds_t prefix, otlp_metric *metric)
{
    size_t index;
    size_t bucket;
    cfl_sds_t line;
    otlp_number_point **numbers = NULL;
    size_t number_count = 0;
    otlp_number_point *number;
    otlp_histogram_point *histogram;
    otlp_exp_point *exp;
    otlp_summary_point *summary;

    prefix = cfl_sds_create_len(prefix, cfl_sds_len(prefix));
    prefix = sds_printf(prefix, "|metric name=%s desc=%s unit=%s meta=",
                        metric->name, metric->description, metric->unit);
    prefix = canon_attributes(prefix, metric->n_metadata, metric->metadata);

    switch (metric->data_case) {
    case OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE:
        prefix = cfl_sds_cat(prefix, " gauge", 6);
        numbers = metric->gauge->data_points;
        number_count = metric->gauge->n_data_points;
        break;
    case OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM:
        prefix = sds_printf(prefix, " sum temporality=%d monotonic=%d",
                            metric->sum->aggregation_temporality,
                            metric->sum->is_monotonic ? 1 : 0);
        numbers = metric->sum->data_points;
        number_count = metric->sum->n_data_points;
        break;
    case OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_HISTOGRAM:
        prefix = sds_printf(prefix, " histogram temporality=%d",
                            metric->histogram->aggregation_temporality);
        for (index = 0; index < metric->histogram->n_data_points; index++) {
            histogram = metric->histogram->data_points[index];
            line = cfl_sds_create_len(prefix, cfl_sds_len(prefix));
            line = canon_point_common(line, histogram->n_attributes, histogram->attributes,
                                      histogram->start_time_unix_nano,
                                      histogram->time_unix_nano, histogram->flags);
            line = sds_printf(line, " count=%" PRIu64 " bounds=", histogram->count);
            for (bucket = 0; bucket < histogram->n_explicit_bounds; bucket++) {
                line = canon_double(line, histogram->explicit_bounds[bucket]);
                line = cfl_sds_cat(line, ",", 1);
            }
            line = cfl_sds_cat(line, " buckets=", 9);
            for (bucket = 0; bucket < histogram->n_bucket_counts; bucket++) {
                line = sds_printf(line, "%" PRIu64 ",", histogram->bucket_counts[bucket]);
            }
            line = canon_optional_double(line, "sum", histogram->has_sum, histogram->sum);
            line = canon_optional_double(line, "min", histogram->has_min, histogram->min);
            line = canon_optional_double(line, "max", histogram->has_max, histogram->max);
            line = canon_exemplars(line, histogram->n_exemplars, histogram->exemplars);
            lines_add(lines, line);
        }
        break;
    case OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_EXPONENTIAL_HISTOGRAM:
        prefix = sds_printf(prefix, " exp_histogram temporality=%d",
                            metric->exponential_histogram->aggregation_temporality);
        for (index = 0; index < metric->exponential_histogram->n_data_points; index++) {
            exp = metric->exponential_histogram->data_points[index];
            line = cfl_sds_create_len(prefix, cfl_sds_len(prefix));
            line = canon_point_common(line, exp->n_attributes, exp->attributes,
                                      exp->start_time_unix_nano, exp->time_unix_nano,
                                      exp->flags);
            line = sds_printf(line, " count=%" PRIu64 " scale=%d zero=%" PRIu64 " zt=",
                              exp->count, exp->scale, exp->zero_count);
            line = canon_double(line, exp->zero_threshold);
            /* Absent and empty bucket ranges carry the same information. */
            if (exp->positive != NULL && exp->positive->n_bucket_counts > 0) {
                line = sds_printf(line, " pos@%d:", exp->positive->offset);
                for (bucket = 0; bucket < exp->positive->n_bucket_counts; bucket++) {
                    line = sds_printf(line, "%" PRIu64 ",", exp->positive->bucket_counts[bucket]);
                }
            }
            if (exp->negative != NULL && exp->negative->n_bucket_counts > 0) {
                line = sds_printf(line, " neg@%d:", exp->negative->offset);
                for (bucket = 0; bucket < exp->negative->n_bucket_counts; bucket++) {
                    line = sds_printf(line, "%" PRIu64 ",", exp->negative->bucket_counts[bucket]);
                }
            }
            line = canon_optional_double(line, "sum", exp->has_sum, exp->sum);
            line = canon_optional_double(line, "min", exp->has_min, exp->min);
            line = canon_optional_double(line, "max", exp->has_max, exp->max);
            line = canon_exemplars(line, exp->n_exemplars, exp->exemplars);
            lines_add(lines, line);
        }
        break;
    case OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUMMARY:
        prefix = cfl_sds_cat(prefix, " summary", 8);
        for (index = 0; index < metric->summary->n_data_points; index++) {
            summary = metric->summary->data_points[index];
            line = cfl_sds_create_len(prefix, cfl_sds_len(prefix));
            line = canon_point_common(line, summary->n_attributes, summary->attributes,
                                      summary->start_time_unix_nano,
                                      summary->time_unix_nano, summary->flags);
            line = sds_printf(line, " count=%" PRIu64 " sum=", summary->count);
            line = canon_double(line, summary->sum);
            line = cfl_sds_cat(line, " q=", 3);
            for (bucket = 0; bucket < summary->n_quantile_values; bucket++) {
                line = canon_double(line, summary->quantile_values[bucket]->quantile);
                line = cfl_sds_cat(line, ":", 1);
                line = canon_double(line, summary->quantile_values[bucket]->value);
                line = cfl_sds_cat(line, ",", 1);
            }
            lines_add(lines, line);
        }
        break;
    default:
        prefix = cfl_sds_cat(prefix, " unset", 6);
        break;
    }

    for (index = 0; index < number_count; index++) {
        number = numbers[index];
        line = cfl_sds_create_len(prefix, cfl_sds_len(prefix));
        line = canon_point_common(line, number->n_attributes, number->attributes,
                                  number->start_time_unix_nano, number->time_unix_nano,
                                  number->flags);
        if (number->value_case == OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT) {
            line = sds_printf(line, " int=%" PRId64, number->as_int);
        }
        else {
            line = cfl_sds_cat(line, " double=", 8);
            line = canon_double(line, number->as_double);
        }
        line = canon_exemplars(line, number->n_exemplars, number->exemplars);
        lines_add(lines, line);
    }
    cfl_sds_destroy(prefix);
}

static void canon_request(struct lines *lines, otlp_request *value)
{
    size_t resource_index;
    size_t scope_index;
    size_t metric_index;
    otlp_resource_metrics *resource_metrics;
    otlp_scope_metrics *scope_metrics;
    cfl_sds_t resource_prefix;
    cfl_sds_t scope_prefix;

    for (resource_index = 0; resource_index < value->n_resource_metrics; resource_index++) {
        resource_metrics = value->resource_metrics[resource_index];
        resource_prefix = cfl_sds_create("resource=");
        if (!canon_include_context) {
            resource_prefix = cfl_sds_cat(resource_prefix, "*", 1);
        }
        else if (resource_metrics->resource != NULL) {
            resource_prefix = canon_attributes(resource_prefix,
                                               resource_metrics->resource->n_attributes,
                                               resource_metrics->resource->attributes);
            resource_prefix = sds_printf(resource_prefix, " dropped=%u",
                                         resource_metrics->resource->dropped_attributes_count);
        }
        resource_prefix = sds_printf(resource_prefix, " schema=%s",
                                     !canon_include_context ? "*" :
                                     resource_metrics->schema_url ?
                                     resource_metrics->schema_url : "");
        for (scope_index = 0; scope_index < resource_metrics->n_scope_metrics; scope_index++) {
            scope_metrics = resource_metrics->scope_metrics[scope_index];
            scope_prefix = cfl_sds_create_len(resource_prefix, cfl_sds_len(resource_prefix));
            scope_prefix = cfl_sds_cat(scope_prefix, "|scope=", 7);
            if (!canon_include_context) {
                scope_prefix = cfl_sds_cat(scope_prefix, "*", 1);
            }
            else if (scope_metrics->scope != NULL) {
                scope_prefix = sds_printf(scope_prefix, "%s@%s dropped=%u ",
                                          scope_metrics->scope->name,
                                          scope_metrics->scope->version,
                                          scope_metrics->scope->dropped_attributes_count);
                scope_prefix = canon_attributes(scope_prefix,
                                                scope_metrics->scope->n_attributes,
                                                scope_metrics->scope->attributes);
            }
            scope_prefix = sds_printf(scope_prefix, " schema=%s",
                                      !canon_include_context ? "*" :
                                      scope_metrics->schema_url ? scope_metrics->schema_url : "");
            for (metric_index = 0; metric_index < scope_metrics->n_metrics; metric_index++) {
                canon_metric(lines, scope_prefix, scope_metrics->metrics[metric_index]);
            }
            cfl_sds_destroy(scope_prefix);
        }
        cfl_sds_destroy(resource_prefix);
    }
}

/* Pipelines */

static struct cmt *msgpack_hop(struct cmt *context, int destroy_source)
{
    struct cmt *decoded = NULL;
    char *buffer;
    size_t size;
    size_t offset = 0;
    int result;

    result = cmt_encode_msgpack_create(context, &buffer, &size);
    TEST_CHECK(result == 0);
    if (result != 0) {
        return NULL;
    }
    result = cmt_decode_msgpack_create(&decoded, buffer, size, &offset);
    TEST_CHECK(result == CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(offset == size);
    cmt_encode_msgpack_destroy(buffer);
    if (destroy_source) {
        cmt_decode_msgpack_destroy(context);
    }
    return result == CMT_DECODE_MSGPACK_SUCCESS ? decoded : NULL;
}

/* Run one pipeline on a decoded context and append the OTLP output lines. */
static int run_pipeline(struct lines *lines, struct cmt *context, int pipeline)
{
    struct cmt *current;
    struct cmt *merged;
    cfl_sds_t wire;
    otlp_request *output;

    current = context;
    merged = NULL;
    if (pipeline != PIPELINE_DIRECT) {
        current = msgpack_hop(context, CMT_FALSE);
        if (current == NULL) {
            return -1;
        }
    }
    if (pipeline == PIPELINE_FORWARD) {
        current = msgpack_hop(current, CMT_TRUE);
        if (current == NULL) {
            return -1;
        }
    }
    if (pipeline == PIPELINE_CAT) {
        merged = cmt_create();
        TEST_ASSERT(merged != NULL);
        TEST_CHECK(cmt_cat(merged, current) == 0);
        cmt_decode_msgpack_destroy(current);
        current = merged;
    }

    wire = cmt_encode_opentelemetry_create(current);
    TEST_CHECK(wire != NULL);
    if (wire != NULL) {
        output = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__unpack(
            NULL, cfl_sds_len(wire), (const uint8_t *) wire);
        TEST_CHECK(output != NULL);
        if (output != NULL) {
            canon_request(lines, output);
            opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(
                output, NULL);
        }
        cmt_encode_opentelemetry_destroy(wire);
    }

    if (merged != NULL) {
        cmt_destroy(merged);
    }
    else if (current != context) {
        cmt_decode_msgpack_destroy(current);
    }
    return wire != NULL ? 0 : -1;
}

static cfl_sds_t pack_request(otlp_request *value)
{
    size_t size;
    uint8_t *buffer;
    cfl_sds_t payload;

    size = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__get_packed_size(value);
    buffer = require(calloc(1, size + 1));
    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__pack(value, buffer);
    payload = cfl_sds_create_len((char *) buffer, size);
    free(buffer);
    TEST_ASSERT(payload != NULL);
    return payload;
}

static void compare_lines(struct lines *expected, struct lines *actual, const char *pipeline)
{
    size_t index;
    int equal;

    if (expected->count > 1) {
        qsort(expected->entries, expected->count, sizeof(cfl_sds_t), compare_strings);
    }
    if (actual->count > 1) {
        qsort(actual->entries, actual->count, sizeof(cfl_sds_t), compare_strings);
    }
    equal = expected->count == actual->count;
    for (index = 0; equal && index < expected->count; index++) {
        equal = strcmp(expected->entries[index], actual->entries[index]) == 0;
    }
    TEST_CHECK_(equal, "pipeline %s reproduces every data point", pipeline);
    if (!equal) {
        for (index = 0; index < expected->count; index++) {
            TEST_MSG("expected: %s", expected->entries[index]);
        }
        for (index = 0; index < actual->count; index++) {
            TEST_MSG("actual:   %s", actual->entries[index]);
        }
    }
}

/*
 * Decode the request as in_opentelemetry does and check that every requested
 * pipeline reproduces it. The canonical lines of 'expected' default to the
 * input itself; a case passes its own expectation when a transformation is
 * intentionally lossy.
 */
static void check_pipelines(otlp_request *input, otlp_request *expected, unsigned int pipelines)
{
    struct cfl_list contexts;
    struct cfl_list *head;
    struct lines expected_lines;
    struct lines actual_lines;
    struct cmt *context;
    cfl_sds_t payload;
    size_t offset;
    int pipeline;
    int result;

    payload = pack_request(input);

    for (pipeline = 0; pipeline < PIPELINE_COUNT; pipeline++) {
        if ((pipelines & (1u << pipeline)) == 0) {
            continue;
        }
        offset = 0;
        result = cmt_decode_opentelemetry_create(&contexts, payload, cfl_sds_len(payload),
                                                 &offset);
        TEST_CHECK_(result == CMT_DECODE_OPENTELEMETRY_SUCCESS,
                    "OTLP decode (result %d)", result);
        if (result != CMT_DECODE_OPENTELEMETRY_SUCCESS) {
            break;
        }
        canon_include_context = pipeline != PIPELINE_CAT;
        memset(&expected_lines, 0, sizeof(expected_lines));
        memset(&actual_lines, 0, sizeof(actual_lines));
        canon_request(&expected_lines, expected != NULL ? expected : input);
        cfl_list_foreach(head, &contexts) {
            context = cfl_list_entry(head, struct cmt, _head);
            TEST_CHECK(run_pipeline(&actual_lines, context, pipeline) == 0);
        }
        compare_lines(&expected_lines, &actual_lines, pipeline_names[pipeline]);
        canon_include_context = CMT_TRUE;
        lines_destroy(&expected_lines);
        lines_destroy(&actual_lines);
        cmt_decode_opentelemetry_destroy(&contexts);
    }

    cfl_sds_destroy(payload);
}

#define ALL_PIPELINES ((1u << PIPELINE_COUNT) - 1)

/* Cases */

#define RESOURCE_ATTRIBUTES \
    2, kv_list(2, kv("service.name", any_string("checkout")), \
                  kv("host.name", any_string("node-1")))

static otlp_request *single_metric(otlp_metric *metric)
{
    return request(1, resource(RESOURCE_ATTRIBUTES, 1,
                               scope("io.opentelemetry.runtime", "1.2.0", 0, NULL, 1, metric)));
}

static otlp_kv **attrs1(const char *key, otlp_any *value)
{
    return kv_list(1, kv(key, value));
}

static double double_from_bits(uint64_t bits)
{
    double value;

    memcpy(&value, &bits, sizeof(value));
    return value;
}

static void run_case(otlp_request *input)
{
    check_pipelines(input, NULL, ALL_PIPELINES);
    test_alloc_release();
}

/* Counter: monotonic cumulative sum with integer and double points. */
static void test_sum_monotonic_cumulative(void)
{
    run_case(single_metric(
        metric_sum("http.server.requests", "requests", "{request}", TEMPORALITY_CUMULATIVE, 1, 2,
            number_int(1000, 2000, 42, 1, attrs1("http.route", any_string("/a"))),
            number_int(1000, 2000, 7, 1, attrs1("http.route", any_string("/b"))))));
}

/* UpDownCounter: non-monotonic sums must not become monotonic counters. */
static void test_sum_non_monotonic(void)
{
    run_case(single_metric(
        metric_sum("queue.items", "items", "{item}", TEMPORALITY_CUMULATIVE, 0, 2,
            number_int(1000, 2000, -5, 1, attrs1("queue", any_string("in"))),
            number_double(1000, 2000, -0.25, 1, attrs1("queue", any_string("out"))))));
}

/* SDKs configured for delta temporality (common with some backends). */
static void test_sum_delta(void)
{
    run_case(single_metric(
        metric_sum("bytes.sent", "bytes", "By", TEMPORALITY_DELTA, 1, 1,
            number_int(1000, 2000, 512, 1, attrs1("peer", any_string("db"))))));
}

static void test_gauge_integer_extremes(void)
{
    run_case(single_metric(
        metric_gauge("extremes", "integer extremes", "1", 4,
            number_int(0, 100, INT64_MIN, 1, attrs1("v", any_string("min"))),
            number_int(0, 100, INT64_MAX, 1, attrs1("v", any_string("max"))),
            number_int(0, 100, -1, 1, attrs1("v", any_string("minus_one"))),
            number_int(0, 100, 9007199254740993LL, 1, attrs1("v", any_string("2^53+1"))))));
}

/* Prometheus receivers emit staleness markers (0x7ff0000000000002) and
 * applications report NaN, infinities and negative zero. */
static void test_gauge_special_doubles(void)
{
    run_case(single_metric(
        metric_gauge("specials", "special doubles", "1", 6,
            number_double(0, 100, double_from_bits(0x7ff8000000000000ULL), 1,
                          attrs1("v", any_string("nan"))),
            number_double(0, 100, double_from_bits(0x7ff0000000000002ULL), 1,
                          attrs1("v", any_string("stale"))),
            number_double(0, 100, INFINITY, 1, attrs1("v", any_string("+inf"))),
            number_double(0, 100, -INFINITY, 1, attrs1("v", any_string("-inf"))),
            number_double(0, 100, -0.0, 1, attrs1("v", any_string("-0"))),
            number_double(0, 100, 4.9406564584124654e-324, 1, attrs1("v", any_string("denormal"))))));
}

static void test_point_flags_and_timestamps(void)
{
    otlp_number_point *missing;

    missing = number_double(10, 20, 0, 1, attrs1("v", any_string("no_value")));
    missing->flags = 1;
    run_case(single_metric(
        metric_gauge("timestamps", "flags and timestamps", "1", 3,
            missing,
            number_double(0, 9223372036854775813ULL, 1, 1, attrs1("v", any_string("late"))),
            number_double(500, 400, 2, 1, attrs1("v", any_string("start_after_time"))))));
}

static void test_histogram_explicit_bounds(void)
{
    static const double bounds[] = {0.005, 0.01, 0.1, 1, 10};
    static const uint64_t counts_a[] = {1, 2, 3, 4, 5, 6};
    static const uint64_t counts_b[] = {0, 0, 0, 0, 0, 9};
    otlp_histogram_point *a;
    otlp_histogram_point *b;

    a = histogram_point(1000, 2000, 5, bounds, counts_a, 1,
                        attrs1("http.route", any_string("/a")));
    a->has_sum = 1;
    a->sum = 123.5;
    a->has_min = 1;
    a->min = 0.001;
    a->has_max = 1;
    a->max = 42;
    a->n_exemplars = 2;
    a->exemplars = exemplar_list(2,
        exemplar_double(1500, 0.007, "0123456789abcdef", "01234567", 1,
                        attrs1("user", any_string("u1"))),
        exemplar_int(1600, 3));
    b = histogram_point(1000, 2000, 5, bounds, counts_b, 1,
                        attrs1("http.route", any_string("/b")));
    b->has_sum = 1;
    b->sum = 900;
    run_case(single_metric(metric_histogram("http.server.duration", "s",
                                            TEMPORALITY_CUMULATIVE, 2, a, b)));
}

static void test_histogram_delta_without_sum(void)
{
    static const double bounds[] = {1, 2};
    static const uint64_t counts[] = {3, 0, 1};

    run_case(single_metric(metric_histogram("latency.delta", "ms", TEMPORALITY_DELTA, 1,
        histogram_point(1000, 2000, 2, bounds, counts, 1,
                        attrs1("op", any_string("get"))))));
}

/*
 * A histogram with no explicit bounds has a single +Inf bucket (SDK views use
 * it to keep only count and sum). CMetrics cannot represent it: the request is
 * rejected. Accepting it would also emit a zero-bucket MessagePack histogram
 * that every released reader rejects, so this is pinned until decided.
 */
static void test_histogram_without_bounds_is_rejected(void)
{
    static const uint64_t counts[] = {17};
    struct cfl_list contexts;
    cfl_sds_t payload;
    size_t offset = 0;
    int result;

    payload = pack_request(single_metric(metric_histogram("single.bucket", "s",
        TEMPORALITY_CUMULATIVE, 1, histogram_point(1000, 2000, 0, NULL, counts, 0, NULL))));
    result = cmt_decode_opentelemetry_create(&contexts, payload, cfl_sds_len(payload), &offset);
    TEST_CHECK(result != CMT_DECODE_OPENTELEMETRY_SUCCESS);
    if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        cmt_decode_opentelemetry_destroy(&contexts);
    }
    cfl_sds_destroy(payload);
    test_alloc_release();
}

static void test_exponential_histogram_layouts(void)
{
    static const uint64_t positive[] = {1, 0, 4, 2};
    static const uint64_t negative[] = {3, 1};
    static const uint64_t fine[] = {5};
    otlp_exp_point *coarse;
    otlp_exp_point *precise;
    otlp_exp_point *zeros;

    coarse = exp_point(1000, 2000, -3, 2, 1e-9, exp_buckets(-5, 4, positive),
                       exp_buckets(2, 2, negative), 1, attrs1("layout", any_string("coarse")));
    coarse->has_sum = 1;
    coarse->sum = -12.5;
    coarse->has_min = 1;
    coarse->min = -40;
    coarse->has_max = 1;
    coarse->max = 300;
    precise = exp_point(1000, 2000, 20, 0, 0, exp_buckets(1048576, 1, fine), NULL, 1,
                        attrs1("layout", any_string("precise")));
    precise->has_sum = 1;
    precise->sum = 10;
    zeros = exp_point(1000, 2000, 0, 6, 0.5, NULL, NULL, 1,
                      attrs1("layout", any_string("zeros")));
    run_case(single_metric(metric_exp_histogram("rpc.duration", TEMPORALITY_DELTA, 3,
                                                coarse, precise, zeros)));
}

static void test_summary_quantiles(void)
{
    static const double quantiles[] = {0, 0.5, 0.99, 1};
    static const double values[] = {0.1, 2.5, 9.75, 12};

    run_case(single_metric(metric_summary("gc.pause", 2,
        summary_point(1000, 2000, 40, 100.5, 4, quantiles, values, 1,
                      attrs1("gen", any_string("young"))),
        summary_point(1000, 2000, 2, 30, 4, quantiles, values, 1,
                      attrs1("gen", any_string("old"))))));
}

static void test_summary_without_quantiles(void)
{
    run_case(single_metric(metric_summary("requests.summary", 1,
        summary_point(1000, 2000, 5, 12.5, 0, NULL, NULL, 1,
                      attrs1("route", any_string("/"))))));
}

/* Attribute values of every OTLP type keep their type end to end. */
static void test_typed_attributes(void)
{
    run_case(single_metric(metric_gauge("typed", "typed attributes", "1", 1,
        number_double(0, 100, 1, 9, kv_list(9,
            kv("string", any_string("value")),
            kv("empty", any_string("")),
            kv("unicode", any_string("caf\xc3\xa9 \xe2\x82\xac")),
            kv("int", any_int(-42)),
            kv("double", any_double(2.5)),
            kv("bool", any_bool(1)),
            kv("bytes", any_bytes("\x00\xff\x10", 3)),
            kv("array", any_array(3, any_string("a"), any_int(1), any_bool(0))),
            kv("map", any_kvlist(2, kv("inner", any_string("x")), kv("n", any_double(0.5)))))))));
}

static otlp_request *type_identity_request(int collapsed)
{
    if (collapsed) {
        return single_metric(metric_gauge("identity", "type identity", "1", 1,
            number_double(0, 100, 3, 1, attrs1("k", any_double(7)))));
    }
    return single_metric(metric_gauge("identity", "type identity", "1", 3,
        number_double(0, 100, 1, 1, attrs1("k", any_int(7))),
        number_double(0, 100, 2, 1, attrs1("k", any_string("7"))),
        number_double(0, 100, 3, 1, attrs1("k", any_double(7)))));
}

/*
 * int 7, string "7" and double 7 are three OTLP series and stay three through
 * OTLP and MessagePack. cmt_cat matches series by their string labels, which
 * are identical, so it merges them and the last point wins. Pinned: series
 * identity in cmt_cat does not consider attribute types.
 */
static void test_attribute_type_identity(void)
{
    check_pipelines(type_identity_request(CMT_FALSE), NULL,
                    ALL_PIPELINES & ~(1u << PIPELINE_CAT));
    check_pipelines(type_identity_request(CMT_FALSE), type_identity_request(CMT_TRUE),
                    1u << PIPELINE_CAT);
    test_alloc_release();
}

/* Native metadata as a released relay carries it: opaque context metadata
 * written back unchanged, whatever it does to the points. */
static struct cfl_kvlist *relay_copy(struct cmt *context, int internal)
{
    struct cfl_kvlist *copy = NULL;
    mpack_writer_t writer;
    mpack_reader_t reader;
    char *buffer = NULL;
    size_t size = 0;
    int result;

    mpack_writer_init_growable(&writer, &buffer, &size);
    result = internal ? cmt_otlp_metadata_pack(&writer, context) :
                        cmt_otlp_metadata_pack_external(&writer, context);
    TEST_ASSERT(mpack_writer_destroy(&writer) == mpack_ok && result == 0);
    mpack_reader_init_data(&reader, buffer, size);
    result = unpack_cfl_kvlist(&reader, &copy);
    TEST_ASSERT(mpack_reader_destroy(&reader) == mpack_ok && result == 0);
    free(buffer);
    return copy;
}

/* Distribution points that differ only by attribute type, count and sum,
 * but not by distribution, stay distinct through every hop. */
static void test_distribution_type_identity(void)
{
    static const double bounds[] = {1, 2};
    static const uint64_t buckets_a[] = {1, 0, 1};
    static const uint64_t buckets_b[] = {0, 2, 0};
    static const double quantiles[] = {0.5};
    static const double quantile_a[] = {1};
    static const double quantile_b[] = {2};
    static const uint64_t positive_a[] = {1, 1};
    static const uint64_t positive_b[] = {2, 0};
    unsigned int mask = ALL_PIPELINES & ~(1u << PIPELINE_CAT);
    otlp_histogram_point *histogram[2];
    otlp_summary_point *summary[2];
    otlp_exp_point *exp[2];
    int index;

    histogram[0] = histogram_point(0, 100, 2, bounds, buckets_a, 1, attrs1("k", any_int(7)));
    histogram[1] = histogram_point(0, 100, 2, bounds, buckets_b, 1, attrs1("k", any_string("7")));
    summary[0] = summary_point(0, 100, 2, 3, 1, quantiles, quantile_a, 1, attrs1("k", any_int(7)));
    summary[1] = summary_point(0, 100, 2, 3, 1, quantiles, quantile_b, 1,
                               attrs1("k", any_string("7")));
    exp[0] = exp_point(0, 100, 0, 0, 0, exp_buckets(0, 2, positive_a), NULL, 1,
                       attrs1("k", any_int(7)));
    exp[1] = exp_point(0, 100, 0, 0, 0, exp_buckets(0, 2, positive_b), NULL, 1,
                       attrs1("k", any_string("7")));
    for (index = 0; index < 2; index++) {
        histogram[index]->has_sum = 1;
        histogram[index]->sum = 3;
        exp[index]->has_sum = 1;
        exp[index]->sum = 3;
    }
    histogram[0]->flags = 1;
    summary[0]->flags = 1;
    exp[0]->flags = 1;

    check_pipelines(single_metric(metric_histogram("latency", "s", TEMPORALITY_CUMULATIVE, 2,
                                                   histogram[0], histogram[1])), NULL, mask);
    check_pipelines(single_metric(metric_summary("rpc", 2, summary[0], summary[1])), NULL, mask);
    check_pipelines(single_metric(metric_exp_histogram("exp", TEMPORALITY_CUMULATIVE, 2,
                                                       exp[0], exp[1])), NULL, mask);
    test_alloc_release();
}

struct typed_relay {
    struct cfl_list contexts;
    struct cmt *decoded;
    char *buffer;
    cfl_sds_t payload;
    cfl_sds_t wire;
    otlp_request *output;
};

/* Points of one series and time that differ only by attribute type: integer
 * 7, string "7" and double 7.0. */
static otlp_request *typed_points(const double *values, const uint32_t *flags)
{
    otlp_request *request;
    otlp_metric *metric;
    size_t index;

    request = single_metric(metric_gauge("identity", "type identity", "1", 3,
        number_double(0, 100, values[0], 1, attrs1("k", any_int(7))),
        number_double(0, 100, values[1], 1, attrs1("k", any_string("7"))),
        number_double(0, 100, values[2], 1, attrs1("k", any_double(7)))));
    metric = request->resource_metrics[0]->scope_metrics[0]->metrics[0];
    for (index = 0; index < 3; index++) {
        metric->gauge->data_points[index]->flags = flags[index];
    }
    return request;
}

/* Decode the request, then act as a released relay: keep native metadata as
 * opaque context metadata and either drop the point at drop_index or swap
 * the first two points, then decode the relayed chunk and export it. */
static void typed_relay_run(struct typed_relay *relay, otlp_request *input,
                            int drop_index, int swap)
{
    struct cfl_list *head;
    struct cfl_list *first;
    struct cmt *context;
    struct cmt_gauge *gauge;
    struct cmt_metric *sample;
    struct cfl_kvlist *internal;
    struct cfl_kvlist *external;
    size_t size;
    size_t offset = 0;
    int index = 0;

    memset(relay, 0, sizeof(*relay));
    relay->payload = pack_request(input);
    TEST_ASSERT(cmt_decode_opentelemetry_create(&relay->contexts, relay->payload,
                                                cfl_sds_len(relay->payload), &offset) ==
                CMT_DECODE_OPENTELEMETRY_SUCCESS);
    context = cfl_list_entry_first(&relay->contexts, struct cmt, _head);
    gauge = cfl_list_entry_first(&context->gauges, struct cmt_gauge, _head);
    TEST_ASSERT(cfl_list_size(&gauge->map->metrics) == 3);

    internal = relay_copy(context, CMT_TRUE);
    external = relay_copy(context, CMT_FALSE);
    cfl_kvlist_destroy(gauge->map->otlp_metadata);
    gauge->map->otlp_metadata = NULL;
    cfl_list_foreach(head, &gauge->map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);
        cfl_kvlist_destroy(sample->otlp_metadata);
        sample->otlp_metadata = NULL;
    }
    cfl_kvlist_destroy(context->internal_metadata);
    context->internal_metadata = internal;
    cfl_kvlist_destroy(context->external_metadata);
    context->external_metadata = external;

    if (swap) {
        first = gauge->map->metrics.next;
        cfl_list_del(first);
        cfl_list_add_after(first, gauge->map->metrics.next, &gauge->map->metrics);
    }
    cfl_list_foreach(head, &gauge->map->metrics) {
        if (index++ == drop_index) {
            cmt_map_metric_destroy(cfl_list_entry(head, struct cmt_metric, _head));
            break;
        }
    }

    TEST_ASSERT(cmt_encode_msgpack_create(context, &relay->buffer, &size) == 0);
    offset = 0;
    TEST_ASSERT(cmt_decode_msgpack_create(&relay->decoded, relay->buffer, size, &offset) == 0);
    relay->wire = cmt_encode_opentelemetry_create(relay->decoded);
    TEST_ASSERT(relay->wire != NULL);
    relay->output = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__unpack(
        NULL, cfl_sds_len(relay->wire), (const uint8_t *) relay->wire);
    TEST_ASSERT(relay->output != NULL);
}

static void typed_relay_destroy(struct typed_relay *relay)
{
    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(
        relay->output, NULL);
    cmt_encode_opentelemetry_destroy(relay->wire);
    cmt_decode_msgpack_destroy(relay->decoded);
    cmt_encode_msgpack_destroy(relay->buffer);
    cmt_decode_opentelemetry_destroy(&relay->contexts);
    cfl_sds_destroy(relay->payload);
}

/* Each exported point carries the flags and attribute type recorded for its
 * value, or, when values cannot tell points apart, neither. */
static void check_typed_points(struct typed_relay *relay, size_t expected_points,
                               const double *values, const uint32_t *flags,
                               int distinguishable)
{
    static const int cases[] = {
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE,
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE,
        OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE
    };
    otlp_metric *metric;
    otlp_number_point *point;
    size_t index;
    size_t source;

    metric = relay->output->resource_metrics[0]->scope_metrics[0]->metrics[0];
    TEST_CHECK(metric->gauge->n_data_points == expected_points);
    for (index = 0; index < metric->gauge->n_data_points; index++) {
        point = metric->gauge->data_points[index];
        TEST_ASSERT(point->n_attributes == 1);
        if (!distinguishable) {
            TEST_CHECK_(point->flags == 0, "point %g carries no recorded flags",
                        point->as_double);
            TEST_CHECK_(point->attributes[0]->value->value_case == cases[1],
                        "point %g keeps its label-derived attribute", point->as_double);
            continue;
        }
        for (source = 0; source < 3 && values[source] != point->as_double; source++);
        TEST_ASSERT(source < 3);
        TEST_CHECK_(point->flags == flags[source], "point %g keeps its own flags",
                    point->as_double);
        TEST_CHECK_(point->attributes[0]->value->value_case == cases[source],
                    "point %g keeps its own attribute type", point->as_double);
    }
}

/* Points that differ only by attribute type share labels; their values tell
 * them apart through any relay edit. Points identical in value too cannot be
 * told apart, so none of them may take metadata recorded for another, from
 * the native sidecar or from the legacy tree. */
static void test_attribute_type_identity_after_relay(void)
{
    static const double distinct[] = {1, 2, 3};
    static const double equal[] = {5, 5, 5};
    static const uint32_t first_flagged[] = {1, 0, 0};
    static const uint32_t last_flagged[] = {0, 0, 1};
    struct typed_relay relay;

    /* drop the first point */
    typed_relay_run(&relay, typed_points(distinct, first_flagged), 0, CMT_FALSE);
    check_typed_points(&relay, 2, distinct, first_flagged, CMT_TRUE);
    typed_relay_destroy(&relay);

    /* swap the first two points: count and identities are unchanged */
    typed_relay_run(&relay, typed_points(distinct, first_flagged), -1, CMT_TRUE);
    check_typed_points(&relay, 3, distinct, first_flagged, CMT_TRUE);
    typed_relay_destroy(&relay);
    typed_relay_run(&relay, typed_points(equal, first_flagged), -1, CMT_TRUE);
    check_typed_points(&relay, 3, equal, first_flagged, CMT_FALSE);
    typed_relay_destroy(&relay);

    /* drop the flagged last point: its legacy entry shares the survivors'
     * series hash and time */
    typed_relay_run(&relay, typed_points(distinct, last_flagged), 2, CMT_FALSE);
    check_typed_points(&relay, 2, distinct, last_flagged, CMT_TRUE);
    typed_relay_destroy(&relay);
    typed_relay_run(&relay, typed_points(equal, last_flagged), 2, CMT_FALSE);
    check_typed_points(&relay, 2, equal, last_flagged, CMT_FALSE);
    typed_relay_destroy(&relay);

    test_alloc_release();
}

/* SDKs do not order attributes; series with the same keys in a different
 * order must keep their own values. */
static void test_attribute_order(void)
{
    run_case(single_metric(metric_gauge("order", "attribute order", "1", 2,
        number_double(0, 100, 1, 2, kv_list(2, kv("a", any_string("1")), kv("b", any_string("2")))),
        number_double(0, 100, 2, 2, kv_list(2, kv("b", any_string("3")), kv("a", any_string("4")))))));
}

/* Points of one metric with different attribute key sets. */
static void test_attribute_key_sets(void)
{
    run_case(single_metric(metric_gauge("key_sets", "key sets", "1", 3,
        number_double(0, 100, 1, 0, NULL),
        number_double(0, 100, 2, 1, attrs1("a", any_string("x"))),
        number_double(0, 100, 3, 2, kv_list(2, kv("a", any_string("x")),
                                            kv("b", any_string("y")))))));
}

/* A collector forwarding several services in one request. */
static void test_multiple_resources_and_scopes(void)
{
    run_case(request(2,
        resource(1, attrs1("service.name", any_string("cart")), 2,
            scope("lib.http", "1.0", 0, NULL, 1,
                metric_gauge("shared.name", "from http", "1", 1,
                    number_double(0, 100, 1, 0, NULL))),
            scope("lib.db", "2.0", 1, attrs1("db.system", any_string("postgresql")), 1,
                metric_sum("shared.name", "from db", "1", TEMPORALITY_CUMULATIVE, 1, 1,
                    number_int(0, 100, 5, 0, NULL)))),
        resource(1, attrs1("service.name", any_string("payment")), 1,
            scope("lib.http", "1.0", 0, NULL, 1,
                metric_gauge("shared.name", "from http", "1", 1,
                    number_double(0, 100, 2, 0, NULL))))));
}

static otlp_request *details_request(const char *description)
{
    otlp_request *input;

    input = single_metric(metric_gauge("details", description, "", 1,
                                       number_double(0, 100, 1, 0, NULL)));
    input->resource_metrics[0]->schema_url = "https://opentelemetry.io/schemas/1.24.0";
    input->resource_metrics[0]->resource->dropped_attributes_count = 3;
    input->resource_metrics[0]->scope_metrics[0]->schema_url =
        "https://opentelemetry.io/schemas/1.21.0";
    input->resource_metrics[0]->scope_metrics[0]->scope->dropped_attributes_count = 1;
    input->resource_metrics[0]->scope_metrics[0]->scope->n_attributes = 1;
    input->resource_metrics[0]->scope_metrics[0]->scope->attributes =
        attrs1("scope.kind", any_string("auto"));
    return input;
}

/* Schema URLs, dropped counts and scope attributes. CMetrics families require
 * a description, so an empty one is emitted as "-" (pinned). */
static void test_resource_and_scope_details(void)
{
    check_pipelines(details_request(""), details_request("-"), ALL_PIPELINES);
    test_alloc_release();
}

static void test_metric_metadata(void)
{
    otlp_metric *metric;

    metric = metric_gauge("with.metadata", "has metadata", "By", 1,
                          number_double(0, 100, 1, 0, NULL));
    metric->n_metadata = 2;
    metric->metadata = kv_list(2, kv("prometheus.type", any_string("gauge")),
                               kv("weight", any_int(3)));
    run_case(single_metric(metric));
}

static void test_number_exemplars(void)
{
    otlp_number_point *point;

    point = number_int(1000, 2000, 10, 1, attrs1("route", any_string("/")));
    point->n_exemplars = 2;
    point->exemplars = exemplar_list(2,
        exemplar_int(1500, 4),
        exemplar_double(1600, 6.5, "fedcba9876543210", "76543210", 2,
                        kv_list(2, kv("user", any_string("u2")), kv("n", any_int(1)))));
    run_case(single_metric(metric_sum("exemplars", "with exemplars", "1",
                                      TEMPORALITY_CUMULATIVE, 1, 1, point)));
}

/* Large cardinality as produced by busy collectors. */
static void test_many_series(void)
{
    otlp_metric *metric;
    char *values;
    size_t index;

    metric = metric_gauge("many.series", "cardinality", "1", 0);
    metric->gauge->n_data_points = 2000;
    metric->gauge->data_points = test_alloc(sizeof(otlp_number_point *) * 2000);
    values = test_alloc(2000 * 8);
    for (index = 0; index < 2000; index++) {
        snprintf(&values[index * 8], 8, "%zu", index);
        metric->gauge->data_points[index] =
            number_double(0, 100, (double) index, 1,
                          attrs1("series", any_string(&values[index * 8])));
    }
    run_case(single_metric(metric));
}

/* Every prefix and single byte corruption of a real request must be handled
 * without crashing; whatever decodes must also survive a MessagePack hop. */
static void test_truncated_and_corrupted_requests(void)
{
    static const double bounds[] = {1, 2};
    static const uint64_t counts[] = {1, 2, 3};
    struct cfl_list contexts;
    struct cfl_list *head;
    struct cmt *context;
    struct cmt *decoded;
    cfl_sds_t payload;
    cfl_sds_t copy;
    size_t length;
    size_t offset;
    int result;

    payload = pack_request(request(1, resource(RESOURCE_ATTRIBUTES, 1,
        scope("s", "1", 1, attrs1("k", any_string("v")), 3,
            metric_sum("c", "d", "1", TEMPORALITY_CUMULATIVE, 1, 1,
                number_int(1, 2, 3, 1, attrs1("a", any_int(1)))),
            metric_histogram("h", "s", TEMPORALITY_CUMULATIVE, 1,
                histogram_point(1, 2, 2, bounds, counts, 1, attrs1("a", any_bool(1)))),
            metric_exp_histogram("e", TEMPORALITY_DELTA, 1,
                exp_point(1, 2, 1, 1, 0, exp_buckets(-1, 3, counts), NULL, 0, NULL))))));

    for (length = 0; length <= cfl_sds_len(payload) * 2; length++) {
        copy = cfl_sds_create_len(payload, length <= cfl_sds_len(payload) ?
                                           length : cfl_sds_len(payload));
        if (length > cfl_sds_len(payload)) {
            copy[length - cfl_sds_len(payload) - 1] ^= 0x5a;
        }
        offset = 0;
        result = cmt_decode_opentelemetry_create(&contexts, copy, cfl_sds_len(copy), &offset);
        if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
            cfl_list_foreach(head, &contexts) {
                context = cfl_list_entry(head, struct cmt, _head);
                decoded = msgpack_hop(context, CMT_FALSE);
                if (decoded != NULL) {
                    cmt_decode_msgpack_destroy(decoded);
                }
            }
            cmt_decode_opentelemetry_destroy(&contexts);
        }
        cfl_sds_destroy(copy);
    }
    cfl_sds_destroy(payload);
    test_alloc_release();
}

/* Containers without data must not produce data points or fail. */
static void test_empty_containers(void)
{
    otlp_request *input;

    input = request(3,
        resource(RESOURCE_ATTRIBUTES, 0),
        resource(RESOURCE_ATTRIBUTES, 1, scope("empty", "1", 0, NULL, 0)),
        resource(RESOURCE_ATTRIBUTES, 1, scope("s", "1", 0, NULL, 1,
            metric_gauge("no.points", "", "", 0))));
    check_pipelines(input, request(0), ALL_PIPELINES);
    test_alloc_release();
}

TEST_LIST = {
    {"sum_monotonic_cumulative", test_sum_monotonic_cumulative},
    {"sum_non_monotonic", test_sum_non_monotonic},
    {"sum_delta", test_sum_delta},
    {"gauge_integer_extremes", test_gauge_integer_extremes},
    {"gauge_special_doubles", test_gauge_special_doubles},
    {"point_flags_and_timestamps", test_point_flags_and_timestamps},
    {"histogram_explicit_bounds", test_histogram_explicit_bounds},
    {"histogram_delta_without_sum", test_histogram_delta_without_sum},
    {"histogram_without_bounds_is_rejected", test_histogram_without_bounds_is_rejected},
    {"exponential_histogram_layouts", test_exponential_histogram_layouts},
    {"summary_quantiles", test_summary_quantiles},
    {"summary_without_quantiles", test_summary_without_quantiles},
    {"typed_attributes", test_typed_attributes},
    {"attribute_type_identity", test_attribute_type_identity},
    {"attribute_type_identity_after_relay", test_attribute_type_identity_after_relay},
    {"distribution_type_identity", test_distribution_type_identity},
    {"attribute_order", test_attribute_order},
    {"attribute_key_sets", test_attribute_key_sets},
    {"multiple_resources_and_scopes", test_multiple_resources_and_scopes},
    {"resource_and_scope_details", test_resource_and_scope_details},
    {"metric_metadata", test_metric_metadata},
    {"number_exemplars", test_number_exemplars},
    {"many_series", test_many_series},
    {"truncated_and_corrupted_requests", test_truncated_and_corrupted_requests},
    {"empty_containers", test_empty_containers},
    {0}
};
