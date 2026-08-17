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

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmetrics/cmt_encode_opentelemetry.h>

struct metrics_batch_view {
    size_t data_point_count;
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest request;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *active_resource;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *active_scope;
    const Opentelemetry__Proto__Metrics__V1__ResourceMetrics *source_resource;
    const Opentelemetry__Proto__Metrics__V1__ScopeMetrics *source_scope;
};

static void set_result(int *result, int value)
{
    if (result != NULL) {
        *result = value;
    }
}

static void metrics_batch_view_init(struct metrics_batch_view *batch)
{
    memset(batch, 0, sizeof(struct metrics_batch_view));
    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__init(
        &batch->request);
}

static void metric_view_destroy(Opentelemetry__Proto__Metrics__V1__Metric *metric)
{
    if (metric == NULL) {
        return;
    }

    if (metric->data_case ==
        OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE) {
        free(metric->gauge);
    }
    else if (metric->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM) {
        free(metric->sum);
    }
    else if (metric->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_HISTOGRAM) {
        free(metric->histogram);
    }
    else if (metric->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_EXPONENTIAL_HISTOGRAM) {
        free(metric->exponential_histogram);
    }
    else if (metric->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUMMARY) {
        free(metric->summary);
    }

    free(metric);
}

static void metrics_batch_view_destroy(struct metrics_batch_view *batch)
{
    size_t resource_index;
    size_t scope_index;
    size_t metric_index;
    Opentelemetry__Proto__Metrics__V1__Metric *metric;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *scope;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *resource;

    for (resource_index = 0;
         resource_index < batch->request.n_resource_metrics;
         resource_index++) {
        resource = batch->request.resource_metrics[resource_index];

        for (scope_index = 0;
             scope_index < resource->n_scope_metrics;
             scope_index++) {
            scope = resource->scope_metrics[scope_index];

            for (metric_index = 0;
                 metric_index < scope->n_metrics;
                 metric_index++) {
                metric = scope->metrics[metric_index];
                metric_view_destroy(metric);
            }

            free(scope->metrics);
            free(scope);
        }

        free(resource->scope_metrics);
        free(resource);
    }

    free(batch->request.resource_metrics);
    metrics_batch_view_init(batch);
}

void cmt_encode_opentelemetry_destroy_batches(
    struct cmt_opentelemetry_batches *batches)
{
    size_t index;

    if (batches == NULL) {
        return;
    }

    for (index = 0; index < batches->count; index++) {
        cfl_sds_destroy(batches->entries[index].payload);
    }

    free(batches->entries);
    free(batches);
}

static int batches_append(struct cmt_opentelemetry_batches *batches,
                          cfl_sds_t payload,
                          size_t data_point_count)
{
    size_t count;
    struct cmt_opentelemetry_batch *entries;

    count = batches->count;
    if (count >= SIZE_MAX / sizeof(struct cmt_opentelemetry_batch)) {
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    entries = realloc(
                  batches->entries,
                  (count + 1) * sizeof(struct cmt_opentelemetry_batch));
    if (entries == NULL) {
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    entries[count].payload = payload;
    entries[count].data_point_count = data_point_count;
    batches->entries = entries;
    batches->count++;

    return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int batch_add_resource(
    struct metrics_batch_view *batch,
    const Opentelemetry__Proto__Metrics__V1__ResourceMetrics *source)
{
    size_t count;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *resource;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics **resources;

    resource = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__ResourceMetrics));
    if (resource == NULL) {
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    *resource = *source;
    resource->n_scope_metrics = 0;
    resource->scope_metrics = NULL;

    count = batch->request.n_resource_metrics;
    if (count >= SIZE_MAX / sizeof(Opentelemetry__Proto__Metrics__V1__ResourceMetrics *)) {
        free(resource);
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    resources = realloc(
                    batch->request.resource_metrics,
                    (count + 1) *
                    sizeof(Opentelemetry__Proto__Metrics__V1__ResourceMetrics *));
    if (resources == NULL) {
        free(resource);
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    resources[count] = resource;
    batch->request.resource_metrics = resources;
    batch->request.n_resource_metrics++;
    batch->active_resource = resource;
    batch->active_scope = NULL;
    batch->source_resource = source;
    batch->source_scope = NULL;

    return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int batch_ensure_resource(
    struct metrics_batch_view *batch,
    const Opentelemetry__Proto__Metrics__V1__ResourceMetrics *source)
{
    if (batch->source_resource == source && batch->active_resource != NULL) {
        return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
    }

    return batch_add_resource(batch, source);
}

static int batch_add_scope(
    struct metrics_batch_view *batch,
    const Opentelemetry__Proto__Metrics__V1__ScopeMetrics *source)
{
    size_t count;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *scope;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics **scopes;

    scope = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__ScopeMetrics));
    if (scope == NULL) {
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    *scope = *source;
    scope->n_metrics = 0;
    scope->metrics = NULL;

    count = batch->active_resource->n_scope_metrics;
    if (count >= SIZE_MAX / sizeof(Opentelemetry__Proto__Metrics__V1__ScopeMetrics *)) {
        free(scope);
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    scopes = realloc(
                 batch->active_resource->scope_metrics,
                 (count + 1) * sizeof(Opentelemetry__Proto__Metrics__V1__ScopeMetrics *));
    if (scopes == NULL) {
        free(scope);
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    scopes[count] = scope;
    batch->active_resource->scope_metrics = scopes;
    batch->active_resource->n_scope_metrics++;
    batch->active_scope = scope;
    batch->source_scope = source;

    return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int batch_ensure_scope(
    struct metrics_batch_view *batch,
    const Opentelemetry__Proto__Metrics__V1__ResourceMetrics *source_resource,
    const Opentelemetry__Proto__Metrics__V1__ScopeMetrics *source_scope)
{
    int result;

    result = batch_ensure_resource(batch, source_resource);
    if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        return result;
    }

    if (batch->source_scope == source_scope && batch->active_scope != NULL) {
        return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
    }

    return batch_add_scope(batch, source_scope);
}

static int metric_data_point_count(
    const Opentelemetry__Proto__Metrics__V1__Metric *metric,
    size_t *count)
{
    *count = 0;

    if (metric == NULL) {
        return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
    }

    if (metric->data_case ==
        OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA__NOT_SET) {
        return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
    }
    else if (metric->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE) {
        if (metric->gauge == NULL) {
            return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
        *count = metric->gauge->n_data_points;
        if (*count > 0 && metric->gauge->data_points == NULL) {
            return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }
    else if (metric->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM) {
        if (metric->sum == NULL) {
            return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
        *count = metric->sum->n_data_points;
        if (*count > 0 && metric->sum->data_points == NULL) {
            return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }
    else if (metric->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_HISTOGRAM) {
        if (metric->histogram == NULL) {
            return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
        *count = metric->histogram->n_data_points;
        if (*count > 0 && metric->histogram->data_points == NULL) {
            return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }
    else if (metric->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_EXPONENTIAL_HISTOGRAM) {
        if (metric->exponential_histogram == NULL) {
            return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
        *count = metric->exponential_histogram->n_data_points;
        if (*count > 0 && metric->exponential_histogram->data_points == NULL) {
            return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }
    else if (metric->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUMMARY) {
        if (metric->summary == NULL) {
            return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
        *count = metric->summary->n_data_points;
        if (*count > 0 && metric->summary->data_points == NULL) {
            return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }
    else {
        /* Preserve metric types added by newer OTLP schemas. */
        *count = 0;
    }

    return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
}

static Opentelemetry__Proto__Metrics__V1__Metric *metric_view_create(
    const Opentelemetry__Proto__Metrics__V1__Metric *source,
    size_t offset,
    size_t count)
{
    Opentelemetry__Proto__Metrics__V1__Metric *metric;
    Opentelemetry__Proto__Metrics__V1__Gauge *gauge;
    Opentelemetry__Proto__Metrics__V1__Sum *sum;
    Opentelemetry__Proto__Metrics__V1__Histogram *histogram;
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogram *exp_histogram;
    Opentelemetry__Proto__Metrics__V1__Summary *summary;

    metric = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__Metric));
    if (metric == NULL) {
        return NULL;
    }

    *metric = *source;

    if (source->data_case ==
        OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE) {
        gauge = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__Gauge));
        if (gauge == NULL) {
            free(metric);
            return NULL;
        }
        *gauge = *source->gauge;
        gauge->n_data_points = count;
        gauge->data_points = count > 0 ? source->gauge->data_points + offset : NULL;
        metric->gauge = gauge;
    }
    else if (source->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM) {
        sum = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__Sum));
        if (sum == NULL) {
            free(metric);
            return NULL;
        }
        *sum = *source->sum;
        sum->n_data_points = count;
        sum->data_points = count > 0 ? source->sum->data_points + offset : NULL;
        metric->sum = sum;
    }
    else if (source->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_HISTOGRAM) {
        histogram = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__Histogram));
        if (histogram == NULL) {
            free(metric);
            return NULL;
        }
        *histogram = *source->histogram;
        histogram->n_data_points = count;
        histogram->data_points = count > 0 ? source->histogram->data_points + offset : NULL;
        metric->histogram = histogram;
    }
    else if (source->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_EXPONENTIAL_HISTOGRAM) {
        exp_histogram = calloc(
                            1,
                            sizeof(Opentelemetry__Proto__Metrics__V1__ExponentialHistogram));
        if (exp_histogram == NULL) {
            free(metric);
            return NULL;
        }
        *exp_histogram = *source->exponential_histogram;
        exp_histogram->n_data_points = count;
        exp_histogram->data_points = count > 0 ?
                                     source->exponential_histogram->data_points + offset :
                                     NULL;
        metric->exponential_histogram = exp_histogram;
    }
    else if (source->data_case ==
             OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUMMARY) {
        summary = calloc(1, sizeof(Opentelemetry__Proto__Metrics__V1__Summary));
        if (summary == NULL) {
            free(metric);
            return NULL;
        }
        *summary = *source->summary;
        summary->n_data_points = count;
        summary->data_points = count > 0 ? source->summary->data_points + offset : NULL;
        metric->summary = summary;
    }

    return metric;
}

static int batch_add_metric(
    struct metrics_batch_view *batch,
    const Opentelemetry__Proto__Metrics__V1__ResourceMetrics *source_resource,
    const Opentelemetry__Proto__Metrics__V1__ScopeMetrics *source_scope,
    const Opentelemetry__Proto__Metrics__V1__Metric *source_metric,
    size_t offset,
    size_t count)
{
    int result;
    size_t metric_count;
    Opentelemetry__Proto__Metrics__V1__Metric *metric;
    Opentelemetry__Proto__Metrics__V1__Metric **metrics;

    result = batch_ensure_scope(batch, source_resource, source_scope);
    if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        return result;
    }

    metric = metric_view_create(source_metric, offset, count);
    if (metric == NULL) {
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    metric_count = batch->active_scope->n_metrics;
    if (metric_count >= SIZE_MAX / sizeof(Opentelemetry__Proto__Metrics__V1__Metric *)) {
        metric_view_destroy(metric);
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    metrics = realloc(
                  batch->active_scope->metrics,
                  (metric_count + 1) * sizeof(Opentelemetry__Proto__Metrics__V1__Metric *));
    if (metrics == NULL) {
        metric_view_destroy(metric);
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    metrics[metric_count] = metric;
    batch->active_scope->metrics = metrics;
    batch->active_scope->n_metrics++;
    batch->data_point_count += count;

    return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int batch_pack(struct metrics_batch_view *batch,
                      struct cmt_opentelemetry_batches *batches)
{
    int result;
    size_t payload_size;
    size_t packed_size;
    cfl_sds_t payload;

    if (batch->request.n_resource_metrics == 0) {
        return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
    }

    payload_size =
        opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__get_packed_size(
            &batch->request);
    payload = cfl_sds_create_size(payload_size);
    if (payload == NULL) {
        metrics_batch_view_destroy(batch);
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    packed_size =
        opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__pack(
            &batch->request,
            (uint8_t *) payload);
    if (packed_size != payload_size) {
        cfl_sds_destroy(payload);
        metrics_batch_view_destroy(batch);
        return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
    }

    cfl_sds_len_set(payload, packed_size);
    result = batches_append(batches, payload, batch->data_point_count);
    if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        cfl_sds_destroy(payload);
    }

    metrics_batch_view_destroy(batch);

    return result;
}

static int request_data_point_count(
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest *request,
    size_t *total)
{
    int result;
    size_t resource_index;
    size_t scope_index;
    size_t metric_index;
    size_t count;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *scope;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *resource;

    *total = 0;

    for (resource_index = 0; resource_index < request->n_resource_metrics; resource_index++) {
        resource = request->resource_metrics[resource_index];
        if (resource == NULL) {
            return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }

        for (scope_index = 0; scope_index < resource->n_scope_metrics; scope_index++) {
            scope = resource->scope_metrics[scope_index];
            if (scope == NULL) {
                return CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
            }

            for (metric_index = 0; metric_index < scope->n_metrics; metric_index++) {
                result = metric_data_point_count(scope->metrics[metric_index], &count);
                if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
                    return result;
                }
                if (count > SIZE_MAX - *total) {
                    return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
                }
                *total += count;
            }
        }
    }

    return CMT_ENCODE_OPENTELEMETRY_SUCCESS;
}

static int append_original_payload(
    struct cmt_opentelemetry_batches *batches,
    const void *payload,
    size_t payload_size,
    size_t data_point_count)
{
    int result;
    cfl_sds_t copy;

    copy = cfl_sds_create_size(payload_size);
    if (copy == NULL) {
        return CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    memcpy(copy, payload, payload_size);
    cfl_sds_len_set(copy, payload_size);
    result = batches_append(batches, copy, data_point_count);
    if (result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        cfl_sds_destroy(copy);
    }

    return result;
}

struct cmt_opentelemetry_batches *
cmt_encode_opentelemetry_split_payload(const void *payload,
                                       size_t payload_size,
                                       size_t max_data_points,
                                       int *result)
{
    int local_result;
    size_t resource_index;
    size_t scope_index;
    size_t metric_index;
    size_t data_point_count;
    size_t offset;
    size_t remaining;
    size_t batch_count;
    size_t total_data_points;
    Opentelemetry__Proto__Metrics__V1__Metric *metric;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *scope;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *resource;
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest *request;
    struct cmt_opentelemetry_batches *batches;
    struct metrics_batch_view batch;

    if (payload == NULL || payload_size == 0) {
        errno = EINVAL;
        set_result(result, CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR);
        return NULL;
    }

    batches = calloc(1, sizeof(struct cmt_opentelemetry_batches));
    if (batches == NULL) {
        errno = ENOMEM;
        set_result(result, CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR);
        return NULL;
    }

    request =
        opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__unpack(
            NULL,
            payload_size,
            (const uint8_t *) payload);
    if (request == NULL) {
        errno = EINVAL;
        set_result(result, CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR);
        cmt_encode_opentelemetry_destroy_batches(batches);
        return NULL;
    }

    local_result = request_data_point_count(request, &total_data_points);
    if (local_result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        goto error;
    }

    if (max_data_points == 0 || total_data_points <= max_data_points) {
        local_result = append_original_payload(batches,
                                               payload,
                                               payload_size,
                                               total_data_points);
        if (local_result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
            goto error;
        }

        opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(
            request,
            NULL);
        set_result(result, CMT_ENCODE_OPENTELEMETRY_SUCCESS);
        return batches;
    }

    local_result = CMT_ENCODE_OPENTELEMETRY_SUCCESS;
    metrics_batch_view_init(&batch);

    for (resource_index = 0;
         resource_index < request->n_resource_metrics &&
         local_result == CMT_ENCODE_OPENTELEMETRY_SUCCESS;
         resource_index++) {
        resource = request->resource_metrics[resource_index];

        if (resource->n_scope_metrics == 0) {
            local_result = batch_ensure_resource(&batch, resource);
            continue;
        }

        for (scope_index = 0;
             scope_index < resource->n_scope_metrics &&
             local_result == CMT_ENCODE_OPENTELEMETRY_SUCCESS;
             scope_index++) {
            scope = resource->scope_metrics[scope_index];

            if (scope->n_metrics == 0) {
                local_result = batch_ensure_scope(&batch, resource, scope);
                continue;
            }

            for (metric_index = 0;
                 metric_index < scope->n_metrics &&
                 local_result == CMT_ENCODE_OPENTELEMETRY_SUCCESS;
                 metric_index++) {
                metric = scope->metrics[metric_index];
                local_result = metric_data_point_count(metric, &data_point_count);
                if (local_result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
                    break;
                }

                if (data_point_count == 0) {
                    local_result = batch_add_metric(&batch,
                                                    resource,
                                                    scope,
                                                    metric,
                                                    0,
                                                    0);
                    continue;
                }

                offset = 0;
                while (offset < data_point_count &&
                       local_result == CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
                    if (batch.data_point_count == max_data_points) {
                        local_result = batch_pack(&batch, batches);
                        if (local_result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
                            break;
                        }
                    }

                    remaining = data_point_count - offset;
                    batch_count = max_data_points - batch.data_point_count;
                    if (batch_count > remaining) {
                        batch_count = remaining;
                    }

                    local_result = batch_add_metric(&batch,
                                                    resource,
                                                    scope,
                                                    metric,
                                                    offset,
                                                    batch_count);
                    offset += batch_count;
                }
            }
        }
    }

    if (local_result == CMT_ENCODE_OPENTELEMETRY_SUCCESS &&
        batch.request.n_resource_metrics > 0) {
        local_result = batch_pack(&batch, batches);
    }
    else {
        metrics_batch_view_destroy(&batch);
    }

    if (local_result != CMT_ENCODE_OPENTELEMETRY_SUCCESS) {
        goto error;
    }

    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(
        request,
        NULL);
    set_result(result, CMT_ENCODE_OPENTELEMETRY_SUCCESS);
    return batches;

error:
    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(
        request,
        NULL);
    cmt_encode_opentelemetry_destroy_batches(batches);
    if (local_result == CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR) {
        errno = ENOMEM;
    }
    else {
        errno = EINVAL;
    }
    set_result(result, local_result);
    return NULL;
}

static struct cmt_opentelemetry_batches *empty_batches_create(int *result)
{
    struct cmt_opentelemetry_batches *batches;

    batches = calloc(1, sizeof(struct cmt_opentelemetry_batches));
    if (batches == NULL) {
        errno = ENOMEM;
        set_result(result, CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR);
        return NULL;
    }

    set_result(result, CMT_ENCODE_OPENTELEMETRY_SUCCESS);
    return batches;
}

struct cmt_opentelemetry_batches *
cmt_encode_opentelemetry_create_batches(struct cmt *context,
                                        size_t max_data_points,
                                        int *result)
{
    cfl_sds_t payload;
    struct cmt_opentelemetry_batches *batches;

    if (context == NULL) {
        errno = EINVAL;
        set_result(result, CMT_ENCODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR);
        return NULL;
    }

    payload = cmt_encode_opentelemetry_create(context);
    if (payload == NULL) {
        errno = ENOMEM;
        set_result(result, CMT_ENCODE_OPENTELEMETRY_ALLOCATION_ERROR);
        return NULL;
    }

    if (cfl_sds_len(payload) == 0) {
        cmt_encode_opentelemetry_destroy(payload);
        return empty_batches_create(result);
    }

    batches = cmt_encode_opentelemetry_split_payload(payload,
                                                     cfl_sds_len(payload),
                                                     max_data_points,
                                                     result);
    cmt_encode_opentelemetry_destroy(payload);

    return batches;
}
