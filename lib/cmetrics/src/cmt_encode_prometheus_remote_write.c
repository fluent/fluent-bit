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
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_encode_prometheus_remote_write.h>

#define SYNTHETIC_METRIC_SUMMARY_COUNT_SEQUENCE_DELTA   10000000
#define SYNTHETIC_METRIC_SUMMARY_SUM_SEQUENCE_DELTA     100000000

#define SYNTHETIC_METRIC_HISTOGRAM_COUNT_SEQUENCE_DELTA 10000000
#define SYNTHETIC_METRIC_HISTOGRAM_SUM_SEQUENCE_DELTA   100000000

static cfl_sds_t render_remote_write_context_to_sds(
    struct cmt_prometheus_remote_write_context *context);

static void destroy_prometheus_label_list(Prometheus__Label **label_list,
                                          size_t entry_count);

static void destroy_prometheus_sample_list(Prometheus__Sample **sample_list,
                                           size_t entry_count);

static void cmt_destroy_prometheus_remote_write_context(
    struct cmt_prometheus_remote_write_context *context);

static uint64_t calculate_label_set_hash(struct cfl_list *label_values, uint64_t seed);

static size_t count_metrics_with_matching_label_set(struct cfl_list *metrics,
                                                    uint64_t sequence_number,
                                                    uint64_t desired_hash);

static int append_entry_to_prometheus_label_list(Prometheus__Label **label_list,
                                                 size_t *index,
                                                 char *name,
                                                 char *value);

static int set_up_time_series_for_label_set(
                                    struct cmt_prometheus_remote_write_context *context,
                                    struct cmt_map *map,
                                    struct cmt_metric *metric,
                                    struct cmt_prometheus_time_series **time_series);

static int pack_metric_metadata(struct cmt_prometheus_remote_write_context *context,
                                struct cmt_map *map,
                                struct cmt_metric *metric);

static int append_metric_to_timeseries(struct cmt_prometheus_time_series *time_series,
                                       struct cmt_metric *metric);

static int pack_basic_type(struct cmt_prometheus_remote_write_context *context,
                           struct cmt_map *map);

static void destroy_label(struct cmt_map_label *instance)
{
    if (instance != NULL) {
        if (instance->name != NULL) {
            cfl_sds_destroy(instance->name);
        }

        free(instance);
    }
}

static struct cmt_map_label *create_label(char *caption)
{
    struct cmt_map_label *instance;

    instance = calloc(1, sizeof(struct cmt_map_label));

    if (instance != NULL) {
        if (caption != NULL) {
            instance->name = cfl_sds_create(caption);

            if (instance->name == NULL) {
                cmt_errno();

                free(instance);

                instance = NULL;
            }
        }
    }

    return instance;
}

cfl_sds_t render_remote_write_context_to_sds(
    struct cmt_prometheus_remote_write_context *context)
{
    size_t                                 write_request_size;
    struct cmt_prometheus_time_series     *time_series_entry;
    struct cmt_prometheus_metric_metadata *metadata_entry;
    cfl_sds_t                              result_buffer;
    size_t                                 entry_index;
    struct cfl_list                        *head;

    context->write_request.n_timeseries = cfl_list_size(&context->time_series_entries);
    context->write_request.n_metadata   = cfl_list_size(&context->metadata_entries);

    context->write_request.timeseries = calloc(context->write_request.n_timeseries,
                                               sizeof(Prometheus__TimeSeries *));

    if (context->write_request.timeseries == NULL) {
        cmt_errno();

        return NULL;
    }

    context->write_request.metadata = calloc(context->write_request.n_metadata,
                                             sizeof(Prometheus__TimeSeries *));

    if (context->write_request.metadata == NULL) {
        cmt_errno();

        free(context->write_request.timeseries);

        return NULL;
    }

    entry_index = 0;

    cfl_list_foreach(head, &context->time_series_entries) {
        time_series_entry = cfl_list_entry(head, struct cmt_prometheus_time_series, _head);

        context->write_request.timeseries[entry_index++] = &time_series_entry->data;
    }

    entry_index = 0;

    cfl_list_foreach(head, &context->metadata_entries) {
        metadata_entry = cfl_list_entry(head, struct cmt_prometheus_metric_metadata, _head);

        context->write_request.metadata[entry_index++] = &metadata_entry->data;
    }

    write_request_size = prometheus__write_request__get_packed_size(&context->write_request);

    result_buffer = cfl_sds_create_size(write_request_size);

    if(result_buffer != NULL) {
        prometheus__write_request__pack(&context->write_request, (uint8_t *) result_buffer);

        cfl_sds_set_len(result_buffer, write_request_size);
    }

    free(context->write_request.timeseries);

    free(context->write_request.metadata);

    return result_buffer;
}

void cmt_destroy_prometheus_remote_write_context(
    struct cmt_prometheus_remote_write_context *context)
{
    struct cmt_prometheus_time_series     *time_series_entry;
    struct cmt_prometheus_metric_metadata *metadata_entry;
    struct cfl_list                        *head;
    struct cfl_list                        *tmp;

    cfl_list_foreach_safe(head, tmp, &context->time_series_entries) {
        time_series_entry = cfl_list_entry(head, struct cmt_prometheus_time_series, _head);

        if (time_series_entry->data.labels != NULL) {
            destroy_prometheus_label_list(time_series_entry->data.labels,
                                          time_series_entry->data.n_labels);

            time_series_entry->data.labels = NULL;
        }

        if (time_series_entry->data.samples != NULL) {
            destroy_prometheus_sample_list(time_series_entry->data.samples,
                                          time_series_entry->data.n_samples);

            time_series_entry->data.samples = NULL;
        }

        cfl_list_del(&time_series_entry->_head);

        free(time_series_entry);
    }

    cfl_list_foreach_safe(head, tmp, &context->metadata_entries) {
        metadata_entry = cfl_list_entry(head, struct cmt_prometheus_metric_metadata, _head);

        if (metadata_entry->data.metric_family_name != NULL) {
            cfl_sds_destroy(metadata_entry->data.metric_family_name);
        }

        if (metadata_entry->data.help != NULL) {
            cfl_sds_destroy(metadata_entry->data.help);
        }

        if (metadata_entry->data.unit != NULL) {
            cfl_sds_destroy(metadata_entry->data.unit);
        }

        cfl_list_del(&metadata_entry->_head);

        free(metadata_entry);
    }
}

uint64_t calculate_label_set_hash(struct cfl_list *label_values, uint64_t seed)
{
    struct cmt_map_label *label_value;
    cfl_hash_state_t      state;
    struct cfl_list       *head;

    cfl_hash_64bits_reset(&state);
    cfl_hash_64bits_update(&state, &seed, sizeof(uint64_t));

    cfl_list_foreach(head, label_values) {
        label_value = cfl_list_entry(head, struct cmt_map_label, _head);

        if (label_value->name == NULL) {
            cfl_hash_64bits_update(&state, "_NULL_", 6);
        }
        else {
            cfl_hash_64bits_update(&state, label_value->name, cfl_sds_len(label_value->name));
        }
    }

    return cfl_hash_64bits_digest(&state);
}

size_t count_metrics_with_matching_label_set(struct cfl_list *metrics,
                                             uint64_t sequence_number,
                                             uint64_t desired_hash)
{
    uint64_t           label_set_hash;
    size_t             matches;
    struct cmt_metric *metric;
    struct cfl_list    *head;

    matches = 0;

    cfl_list_foreach(head, metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);

        label_set_hash = calculate_label_set_hash(&metric->labels, sequence_number);

        if (label_set_hash == desired_hash) {
            matches++;
        }
    }

    return matches;
}

int append_entry_to_prometheus_label_list(Prometheus__Label **label_list,
                                          size_t *index,
                                          char *name,
                                          char *value)
{
    label_list[*index] = calloc(1, sizeof(Prometheus__Label));

    if (label_list[*index] == NULL) {
        cmt_errno();

        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    prometheus__label__init(label_list[*index]);

    label_list[*index]->name = cfl_sds_create(name);

    if (label_list[*index]->name == NULL) {
        free(label_list[*index]);

        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    label_list[*index]->value = cfl_sds_create(value);

    if (label_list[*index]->value == NULL) {
        cfl_sds_destroy(label_list[*index]->name);
        free(label_list[*index]);

        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    (*index)++;

    return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;
}

void destroy_prometheus_sample_list(Prometheus__Sample **sample_list,
                                    size_t entry_count)
{
    size_t index;

    if (sample_list != NULL) {
        for (index = 0 ; index < entry_count ; index++) {
            if (sample_list[index] != NULL) {
                free(sample_list[index]);
                sample_list[index] = NULL;
            }
        }

        free(sample_list);
    }
}

void destroy_prometheus_label_list(Prometheus__Label **label_list,
                                   size_t entry_count)
{
    size_t index;

    if (label_list != NULL) {
        for (index = 0 ; index < entry_count ; index++) {
            if (label_list[index] != NULL) {
                if (label_list[index]->name != NULL) {
                    cfl_sds_destroy(label_list[index]->name);
                    label_list[index]->name = NULL;
                }

                if (label_list[index]->value != NULL) {
                    cfl_sds_destroy(label_list[index]->value);
                    label_list[index]->value = NULL;
                }

                free(label_list[index]);
                label_list[index] = NULL;
            }
        }

        free(label_list);
    }
}

int set_up_time_series_for_label_set(struct cmt_prometheus_remote_write_context *context,
                                     struct cmt_map *map,
                                     struct cmt_metric *metric,
                                     struct cmt_prometheus_time_series **time_series)
{
    uint8_t                            time_series_match_found;
    size_t                             label_set_hash_matches;
    struct cmt_prometheus_time_series *time_series_entry;
    uint64_t                           label_set_hash;
    struct cmt_label                  *static_label;
    size_t                             label_index;
    size_t                             label_count;
    struct cmt_map_label              *label_value;
    struct cmt_map_label              *label_name;
    Prometheus__Label                **label_list;
    Prometheus__Sample               **value_list;
    int                                result;
    struct cfl_list                    *head;

    label_set_hash = calculate_label_set_hash(&metric->labels, context->sequence_number);

    /* Determine if there is an existing time series for this label set */
    time_series_match_found = CMT_FALSE;

    cfl_list_foreach(head, &context->time_series_entries) {
        time_series_entry = cfl_list_entry(head, struct cmt_prometheus_time_series, _head);

        if (time_series_entry->label_set_hash == label_set_hash) {
            time_series_match_found = CMT_TRUE;

            break;
        }
    }

    if (time_series_match_found == CMT_TRUE) {
        *time_series = time_series_entry;

        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;
    }

    /* Find out how many samples share these label values */
    label_set_hash_matches = count_metrics_with_matching_label_set(&map->metrics,
                                                                   context->sequence_number,
                                                                   label_set_hash);

    if (label_set_hash_matches == 0)
    {
        label_set_hash_matches++;
    }

    /* Allocate the memory required for the label and value lists, we need to add
     * one for the fixed __name__ label
     */
    label_count = cfl_list_size(&context->cmt->static_labels->list) +
                  cfl_list_size(&metric->labels) +
                  1;


    time_series_entry = calloc(1, sizeof(struct cmt_prometheus_time_series));

    if (time_series_entry == NULL) {
        cmt_errno();

        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    label_list = calloc(label_count, sizeof(Prometheus__Label *));

    if (label_list == NULL) {
        cmt_errno();

        free(time_series_entry);

        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    value_list = calloc(label_set_hash_matches, sizeof(Prometheus__Sample *));

    if (value_list == NULL) {
        cmt_errno();

        free(time_series_entry);
        free(label_list);

        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    /* Initialize the time series */
    prometheus__time_series__init(&time_series_entry->data);

    time_series_entry->data.n_labels  = label_count;
    time_series_entry->data.labels    = label_list;
    time_series_entry->data.n_samples = label_set_hash_matches;
    time_series_entry->data.samples   = value_list;

    time_series_entry->label_set_hash = label_set_hash;
    time_series_entry->entries_set = 0;

    /* Initialize the label list */
    label_index = 0;

    /* Add the __name__ label */
    result = append_entry_to_prometheus_label_list(label_list,
                                                   &label_index,
                                                   "__name__",
                                                   map->opts->fqname);

    if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS)
    {
        free(time_series_entry);
        free(label_list);
        free(value_list);

        return result;
    }

    /* Add the static labels */
    result = CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    cfl_list_foreach(head, &context->cmt->static_labels->list) {
        static_label = cfl_list_entry(head, struct cmt_label, _head);

        result = append_entry_to_prometheus_label_list(label_list,
                                                       &label_index,
                                                       static_label->key,
                                                       static_label->val);

        if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS)
        {
            break;
        }
    }

    /* Add the specific labels */
    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS && label_count > 0) {
        label_name = cfl_list_entry_first(&map->label_keys, struct cmt_map_label, _head);

        cfl_list_foreach(head, &metric->labels) {
            label_value = cfl_list_entry(head, struct cmt_map_label, _head);

            result = append_entry_to_prometheus_label_list(label_list,
                                                           &label_index,
                                                           label_name->name,
                                                           label_value->name);

            if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS)
            {
                break;
            }

            label_name = cfl_list_entry_next(&label_name->_head, struct cmt_map_label,
                                            _head, &map->label_keys);
        }
    }

    if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        destroy_prometheus_label_list(label_list, label_index);
        free(time_series_entry);
        free(value_list);

        return result;
    }

    /* Add the time series to the context so we can find it when we try to format
     * a metric with these same labels;
     */
    cfl_list_add(&time_series_entry->_head, &context->time_series_entries);

    *time_series = time_series_entry;

    return result;
}


int pack_metric_metadata(struct cmt_prometheus_remote_write_context *context,
                         struct cmt_map *map,
                         struct cmt_metric *metric)
{
    struct cmt_prometheus_metric_metadata *metadata_entry;

    metadata_entry = calloc(1, sizeof(struct cmt_prometheus_metric_metadata));

    if (metadata_entry == NULL) {
        cmt_errno();

        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    prometheus__metric_metadata__init(&metadata_entry->data);

    if (map->type == CMT_COUNTER) {
        metadata_entry->data.type = PROMETHEUS__METRIC_METADATA__METRIC_TYPE__COUNTER;
    }
    else if (map->type == CMT_GAUGE) {
        metadata_entry->data.type = PROMETHEUS__METRIC_METADATA__METRIC_TYPE__GAUGE;
    }
    else if (map->type == CMT_UNTYPED) {
        metadata_entry->data.type = PROMETHEUS__METRIC_METADATA__METRIC_TYPE__UNKNOWN;
    }
    else if (map->type == CMT_SUMMARY) {
        metadata_entry->data.type = PROMETHEUS__METRIC_METADATA__METRIC_TYPE__SUMMARY;
    }
    else if (map->type == CMT_HISTOGRAM || map->type == CMT_EXP_HISTOGRAM) {
        metadata_entry->data.type = PROMETHEUS__METRIC_METADATA__METRIC_TYPE__HISTOGRAM;
    }
    else {
        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_UNEXPECTED_METRIC_TYPE;
    }

    if (map->opts->fqname == NULL) {
        metadata_entry->data.metric_family_name = cfl_sds_create("");
    }
    else {
        metadata_entry->data.metric_family_name = cfl_sds_create(map->opts->fqname);
    }

    if (metadata_entry->data.metric_family_name == NULL) {
        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    if (map->opts->description == NULL) {
        metadata_entry->data.help = cfl_sds_create("");
    }
    else {
        metadata_entry->data.help = cfl_sds_create(map->opts->description);
    }

    if (metadata_entry->data.help == NULL) {
        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    if (map->unit == NULL) {
        metadata_entry->data.unit = cfl_sds_create("");
    }
    else {
        metadata_entry->data.unit = cfl_sds_create(map->unit);
    }

    if (metadata_entry->data.unit == NULL) {
        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    cfl_list_add(&metadata_entry->_head, &context->metadata_entries);

    return 0;
}

int append_metric_to_timeseries(struct cmt_prometheus_time_series *time_series,
                                struct cmt_metric *metric)
{
    uint64_t ts;
    Prometheus__Sample *sample;

    sample = calloc(1, sizeof(Prometheus__Sample));

    if (sample == NULL) {
        cmt_errno();

        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    prometheus__sample__init(sample);

    sample->value = cmt_metric_get_value(metric);

    ts = cmt_metric_get_timestamp(metric);
    sample->timestamp = ts / 1000000;
    time_series->data.samples[time_series->entries_set++] = sample;

    return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;
}

int pack_basic_metric_sample(struct cmt_prometheus_remote_write_context *context,
                             struct cmt_map *map,
                             struct cmt_metric *metric,
                             int add_metadata)
{
    struct cmt_prometheus_time_series *time_series;
    int                                result;

    result = set_up_time_series_for_label_set(context, map, metric, &time_series);

    if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        return result;
    }

    if (add_metadata == CMT_TRUE) {
        result = pack_metric_metadata(context, map, metric);

        if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            return result;
        }
    }

    return append_metric_to_timeseries(time_series, metric);
}

static int check_staled_timestamp(struct cmt_metric *metric, uint64_t now, uint64_t cutoff)
{
    uint64_t ts;
    uint64_t diff;

    ts = cmt_metric_get_timestamp(metric);
    diff = now - ts;

    return diff > cutoff;
}

int pack_basic_type(struct cmt_prometheus_remote_write_context *context,
                    struct cmt_map *map)
{
    int                add_metadata;
    struct cmt_metric *metric;
    int                result;
    struct cfl_list    *head;
    uint64_t            now;

    context->sequence_number++;
    add_metadata = CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ADD_METADATA;

    now = cfl_time_now();

    if (map->metric_static_set == CMT_TRUE) {
        if (check_staled_timestamp(&map->metric, now,
                                   CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_THRESHOLD)) {
            /* Skip processing metrics which are staled over the threshold */
            return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_ERROR;
        }

        result = pack_basic_metric_sample(context, map, &map->metric, add_metadata);

        if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            return result;
        }
    }

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);

        if (check_staled_timestamp(metric, now,
                                   CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_THRESHOLD)) {
            /* Skip processing metrics which are staled over over the threshold */
            return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_ERROR;
        }

        result = pack_basic_metric_sample(context, map, metric, add_metadata);

        if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            return result;
        }

        if (add_metadata == CMT_TRUE) {
            add_metadata = CMT_FALSE;
        }
    }

    return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;
}

int pack_complex_metric_sample(struct cmt_prometheus_remote_write_context *context,
                               struct cmt_map *map,
                               struct cmt_metric *metric,
                               int add_metadata)
{
    size_t                             original_label_value_count = 0;
    cfl_sds_t                          synthetized_metric_name;
    cfl_sds_t                          original_metric_name;
    size_t                             label_value_count = 0;
    cfl_sds_t                          additional_label_caption;
    size_t                             label_key_count;
    struct cmt_map_label              *additional_label;
    struct cmt_metric                  dummy_metric;
    struct cmt_prometheus_time_series *time_series;
    struct cmt_map_label              *dummy_label;
    struct cmt_histogram              *histogram = NULL;
    struct cmt_summary                *summary;
    double                            *exp_upper_bounds;
    uint64_t                          *exp_bucket_counts;
    size_t                             exp_upper_bounds_count;
    size_t                             exp_bucket_count;
    size_t                             bucket_count;
    double                             bucket_value;
    double                             sum_value;
    double                             count_value;
    int                                result;
    size_t                             index;
    uint64_t                           now;

    now = cfl_time_now();
    exp_upper_bounds = NULL;
    exp_bucket_counts = NULL;
    exp_upper_bounds_count = 0;
    exp_bucket_count = 0;

    if (check_staled_timestamp(metric, now,
                               CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_THRESHOLD)) {
        /* Skip processing metrics which are staled over the threshold */
        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_ERROR;
    }

    additional_label_caption = cfl_sds_create_len(NULL, 128);

    if (additional_label_caption == NULL) {
        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    synthetized_metric_name = cfl_sds_create_len(NULL,
                                                 cfl_sds_alloc(map->opts->fqname) + 16);

    if (synthetized_metric_name == NULL) {
        cfl_sds_destroy(additional_label_caption);

        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    original_metric_name = map->opts->fqname;

    result = CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    memset(&dummy_metric, 0, sizeof(struct cmt_metric));
    memcpy(&dummy_metric.labels, &metric->labels, sizeof(struct cfl_list));

    dummy_metric.timestamp = metric->timestamp;

    if (map->type == CMT_SUMMARY) {
        summary = (struct cmt_summary *) map->parent;

        context->sequence_number += SYNTHETIC_METRIC_SUMMARY_COUNT_SEQUENCE_DELTA;

        map->opts->fqname = synthetized_metric_name;

        cfl_sds_len_set(synthetized_metric_name,
                        snprintf(synthetized_metric_name,
                                 cfl_sds_alloc(synthetized_metric_name) -1,
                                 "%s_count",
                                 original_metric_name));

        cmt_metric_set(&dummy_metric,
                       dummy_metric.timestamp,
                       cmt_summary_get_count_value(metric));

        result = set_up_time_series_for_label_set(context, map, metric, &time_series);

        if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            if (add_metadata == CMT_TRUE) {
                result = pack_metric_metadata(context, map, &dummy_metric);
            }

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                result = append_metric_to_timeseries(time_series, &dummy_metric);
            }
        }

        context->sequence_number -= SYNTHETIC_METRIC_SUMMARY_COUNT_SEQUENCE_DELTA;

        if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            context->sequence_number += SYNTHETIC_METRIC_SUMMARY_SUM_SEQUENCE_DELTA;
            cfl_sds_len_set(synthetized_metric_name,
                            snprintf(synthetized_metric_name,
                                     cfl_sds_alloc(synthetized_metric_name) -1,
                                     "%s_sum",
                                     original_metric_name));

            cmt_metric_set(&dummy_metric,
                           dummy_metric.timestamp,
                           cmt_summary_get_sum_value(metric));

            result = set_up_time_series_for_label_set(context, map, metric, &time_series);

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                if (add_metadata == CMT_TRUE) {
                    result = pack_metric_metadata(context, map, &dummy_metric);
                }

                if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                    result = append_metric_to_timeseries(time_series, &dummy_metric);
                }
            }

            context->sequence_number -= SYNTHETIC_METRIC_SUMMARY_SUM_SEQUENCE_DELTA;
        }

        map->opts->fqname = original_metric_name;

        if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            label_key_count = cfl_list_size(&map->label_keys);
            original_label_value_count = cfl_list_size(&metric->labels);

            for (label_value_count = original_label_value_count ;
                 result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS &&
                 label_value_count < label_key_count;
                 label_value_count++) {
                dummy_label = create_label(NULL);

                if (dummy_label == NULL) {
                    result = CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
                }

                cfl_list_add(&dummy_label->_head, &metric->labels);
            }

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                additional_label = cfl_list_entry_last(&metric->labels, struct cmt_map_label, _head);

                if (additional_label == NULL) {
                    result = CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
                }

                if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                    additional_label->name = (cfl_sds_t) additional_label_caption;

                    for(index = 0 ;
                        result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS &&
                        index < summary->quantiles_count ;
                        index++) {
                        cfl_sds_len_set(additional_label_caption,
                                        snprintf(additional_label_caption,
                                        cfl_sds_alloc(additional_label_caption) - 1,
                                        "%.17g", summary->quantiles[index]));

                        dummy_metric.val = cmt_math_d64_to_uint64(cmt_summary_quantile_get_value(metric, index));

                        result = set_up_time_series_for_label_set(context, map, metric, &time_series);

                        if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                            if (add_metadata == CMT_TRUE) {
                                result = pack_metric_metadata(context, map, &dummy_metric);
                            }

                            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                                result = append_metric_to_timeseries(time_series, &dummy_metric);
                            }
                        }
                    }
                }
            }
        }
    }
    else if (map->type == CMT_HISTOGRAM || map->type == CMT_EXP_HISTOGRAM) {
        if (map->type == CMT_HISTOGRAM) {
            histogram = (struct cmt_histogram *) map->parent;
            bucket_count = histogram->buckets->count;
        }
        else {
            result = cmt_exp_histogram_to_explicit(metric,
                                                   &exp_upper_bounds,
                                                   &exp_upper_bounds_count,
                                                   &exp_bucket_counts,
                                                   &exp_bucket_count);
            if (result != 0) {
                result = CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
            }
            else {
                bucket_count = exp_upper_bounds_count;
            }
        }

        if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            context->sequence_number += SYNTHETIC_METRIC_HISTOGRAM_COUNT_SEQUENCE_DELTA;
            map->opts->fqname = synthetized_metric_name;

            cfl_sds_len_set(synthetized_metric_name,
                            snprintf(synthetized_metric_name,
                                     cfl_sds_alloc(synthetized_metric_name) -1,
                                     "%s_count",
                                     original_metric_name));

            if (map->type == CMT_HISTOGRAM) {
                count_value = cmt_metric_hist_get_count_value(metric);
            }
            else {
                count_value = metric->exp_hist_count;
            }

            cmt_metric_set(&dummy_metric, dummy_metric.timestamp, count_value);
            result = set_up_time_series_for_label_set(context, map, metric, &time_series);

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                if (add_metadata == CMT_TRUE) {
                    result = pack_metric_metadata(context, map, &dummy_metric);
                }

                if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                    result = append_metric_to_timeseries(time_series, &dummy_metric);
                }
            }

            context->sequence_number -= SYNTHETIC_METRIC_HISTOGRAM_COUNT_SEQUENCE_DELTA;
        }

        if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS &&
            (map->type == CMT_HISTOGRAM ||
             (map->type == CMT_EXP_HISTOGRAM && metric->exp_hist_sum_set == CMT_TRUE))) {
            context->sequence_number += SYNTHETIC_METRIC_HISTOGRAM_SUM_SEQUENCE_DELTA;

            cfl_sds_len_set(synthetized_metric_name,
                            snprintf(synthetized_metric_name,
                                     cfl_sds_alloc(synthetized_metric_name) -1,
                                     "%s_sum",
                                     original_metric_name));

            if (map->type == CMT_HISTOGRAM) {
                sum_value = cmt_metric_hist_get_sum_value(metric);
            }
            else {
                sum_value = cmt_math_uint64_to_d64(metric->exp_hist_sum);
            }

            cmt_metric_set(&dummy_metric, dummy_metric.timestamp, sum_value);
            result = set_up_time_series_for_label_set(context, map, metric, &time_series);

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                if (add_metadata == CMT_TRUE) {
                    result = pack_metric_metadata(context, map, &dummy_metric);
                }

                if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                    result = append_metric_to_timeseries(time_series, &dummy_metric);
                }
            }

            context->sequence_number -= SYNTHETIC_METRIC_HISTOGRAM_SUM_SEQUENCE_DELTA;
        }

        if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            cfl_sds_len_set(synthetized_metric_name,
                            snprintf(synthetized_metric_name,
                                     cfl_sds_alloc(synthetized_metric_name) - 1,
                                     "%s_bucket",
                                     original_metric_name));

            label_key_count = cfl_list_size(&map->label_keys);
            original_label_value_count = cfl_list_size(&metric->labels);

            for (label_value_count = original_label_value_count ;
                 result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS &&
                 label_value_count < label_key_count;
                 label_value_count++) {
                dummy_label = create_label(NULL);

                if (dummy_label == NULL) {
                    result = CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
                }

                cfl_list_add(&dummy_label->_head, &metric->labels);
            }

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                additional_label = cfl_list_entry_last(&metric->labels, struct cmt_map_label, _head);
                additional_label->name = (cfl_sds_t) additional_label_caption;

                for(index = 0 ;
                    result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS &&
                    index <= bucket_count ;
                    index++) {
                    if (index < bucket_count) {
                        if (map->type == CMT_HISTOGRAM) {
                            cfl_sds_len_set(additional_label_caption,
                                            snprintf(additional_label_caption,
                                                     cfl_sds_alloc(additional_label_caption) - 1,
                                                     "%.17g",
                                                     histogram->buckets->upper_bounds[index]));
                        }
                        else {
                            cfl_sds_len_set(additional_label_caption,
                                            snprintf(additional_label_caption,
                                                     cfl_sds_alloc(additional_label_caption) - 1,
                                                     "%.17g",
                                                     exp_upper_bounds[index]));
                        }
                    }
                    else {
                        cfl_sds_len_set(additional_label_caption,
                                        snprintf(additional_label_caption,
                                                 cfl_sds_alloc(additional_label_caption) - 1,
                                                 "+Inf"));
                    }

                    if (map->type == CMT_HISTOGRAM) {
                        bucket_value = cmt_metric_hist_get_value(metric, index);
                    }
                    else {
                        bucket_value = exp_bucket_counts[index];
                    }

                    dummy_metric.val = cmt_math_d64_to_uint64(bucket_value);
                    result = set_up_time_series_for_label_set(context, map, metric, &time_series);

                    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                        if (add_metadata == CMT_TRUE) {
                            result = pack_metric_metadata(context, map, &dummy_metric);
                        }

                        if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                            result = append_metric_to_timeseries(time_series, &dummy_metric);
                        }
                    }
                }
            }
        }

        map->opts->fqname = original_metric_name;
    }

    for ( ;
         label_value_count > original_label_value_count;
         label_value_count--) {
        additional_label = cfl_list_entry_last(&metric->labels, struct cmt_map_label, _head);

        if (additional_label != NULL) {
            cfl_list_del(&additional_label->_head);

            if (additional_label->name == additional_label_caption) {
                additional_label_caption = NULL;
            }

            destroy_label(additional_label);
        }
    }

    free(exp_upper_bounds);
    free(exp_bucket_counts);

    if (additional_label_caption != NULL) {
        cfl_sds_destroy(additional_label_caption);
    }

    cfl_sds_destroy(synthetized_metric_name);

    return result;
}

int pack_complex_type(struct cmt_prometheus_remote_write_context *context,
                      struct cmt_map *map)
{
    struct cmt_map_label  additional_label;
    int                   add_metadata;
    struct cmt_metric    *metric;
    int                   result;
    struct cfl_list       *head;

    context->sequence_number++;

    add_metadata = CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ADD_METADATA;
    result = CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    if (map->type == CMT_SUMMARY ||
        map->type == CMT_HISTOGRAM ||
        map->type == CMT_EXP_HISTOGRAM) {
        if (map->type == CMT_SUMMARY) {
            additional_label.name = (cfl_sds_t) "quantile";
        }
        else {
            additional_label.name = (cfl_sds_t) "le";
        }

        /*
         * Suppress GCC/Clang warning for storing the address of a stack-allocated label in a list. We are
         * safe here because the label is removed before function exit.
         *
         * This avoids a -Wdangling-pointer false positive.
         */
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdangling-pointer"


        cfl_list_add(&additional_label._head, &map->label_keys);

        #pragma GCC diagnostic pop
    }

    if (map->metric_static_set == CMT_TRUE) {
        result = pack_complex_metric_sample(context, map, &map->metric, add_metadata);
    }

    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        cfl_list_foreach(head, &map->metrics) {
            metric = cfl_list_entry(head, struct cmt_metric, _head);

            result = pack_complex_metric_sample(context, map, metric, add_metadata);

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                if (add_metadata == CMT_TRUE) {
                    add_metadata = CMT_FALSE;
                }
            }
        }
    }

    if (map->type == CMT_SUMMARY ||
        map->type == CMT_HISTOGRAM ||
        map->type == CMT_EXP_HISTOGRAM) {
        cfl_list_del(&additional_label._head);
    }

    return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;
}

/* Format all the registered metrics in Prometheus Text format */
cfl_sds_t cmt_encode_prometheus_remote_write_create(struct cmt *cmt)
{
    struct cmt_histogram                      *histogram;
    struct cmt_exp_histogram                  *exp_histogram;
    struct cmt_prometheus_remote_write_context context;
    struct cmt_untyped                        *untyped;
    struct cmt_counter                        *counter;
    struct cmt_summary                        *summary;
    int                                        result;
    struct cmt_gauge                          *gauge;
    struct cfl_list                            *head;
    cfl_sds_t                                  buf;

    result = CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;
    buf = NULL;

    memset(&context, 0, sizeof(struct cmt_prometheus_remote_write_context));

    prometheus__write_request__init(&context.write_request);

    context.cmt = cmt;

    cfl_list_init(&context.time_series_entries);
    cfl_list_init(&context.metadata_entries);

    /* Counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        result = pack_basic_type(&context, counter->map);

        if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_ERROR) {
            continue;
        }

        if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            break;
        }
    }

    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        /* Gauges */
        cfl_list_foreach(head, &cmt->gauges) {
            gauge = cfl_list_entry(head, struct cmt_gauge, _head);
            result = pack_basic_type(&context, gauge->map);

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_ERROR) {
                continue;
            }

            if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                break;
            }
        }
    }

    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        /* Untyped */
        cfl_list_foreach(head, &cmt->untypeds) {
            untyped = cfl_list_entry(head, struct cmt_untyped, _head);
            pack_basic_type(&context, untyped->map);

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_ERROR) {
                continue;
            }
        }
    }

    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        /* Summaries */
        cfl_list_foreach(head, &cmt->summaries) {
            summary = cfl_list_entry(head, struct cmt_summary, _head);
            result = pack_complex_type(&context, summary->map);

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_ERROR) {
                continue;
            }

            if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                break;
            }
        }
    }

    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        /* Histograms */
        cfl_list_foreach(head, &cmt->histograms) {
            histogram = cfl_list_entry(head, struct cmt_histogram, _head);
            result = pack_complex_type(&context, histogram->map);

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_ERROR) {
                continue;
            }

            if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                break;
            }
        }
    }

    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        /* Exponential Histograms */
        cfl_list_foreach(head, &cmt->exp_histograms) {
            exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
            result = pack_complex_type(&context, exp_histogram->map);

            if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_ERROR) {
                continue;
            }

            if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                break;
            }
        }
    }

    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS ||
        result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_CUTOFF_ERROR) {
        buf = render_remote_write_context_to_sds(&context);
    }

    cmt_destroy_prometheus_remote_write_context(&context);

    return buf;
}

void cmt_encode_prometheus_remote_write_destroy(cfl_sds_t text)
{
    cfl_sds_destroy(text);
}
