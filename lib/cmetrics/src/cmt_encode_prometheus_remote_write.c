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
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_hash.h> 
#include <cmetrics/cmt_encode_prometheus_remote_write.h>

static cmt_sds_t render_remote_write_context_to_sds(
    struct cmt_prometheus_remote_write_context *context);

static void destroy_prometheus_label_list(Prometheus__Label **label_list,
                                          size_t entry_count);

static void destroy_prometheus_sample_list(Prometheus__Sample **sample_list,
                                           size_t entry_count);

static void cmt_destroy_prometheus_remote_write_context(
    struct cmt_prometheus_remote_write_context *context);

static uint64_t calculate_label_set_hash(struct mk_list *label_values, uint64_t seed);

static size_t count_metrics_with_matching_label_set(struct mk_list *metrics,
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

static int pack_metric_sample(struct cmt_prometheus_remote_write_context *context,
                              struct cmt_map *map,
                              struct cmt_metric *metric,
                              int add_metadata);

static int pack_basic_type(struct cmt_prometheus_remote_write_context *context,
                           struct cmt_map *map);

cmt_sds_t render_remote_write_context_to_sds(
    struct cmt_prometheus_remote_write_context *context)
{
    size_t                                 write_request_size;
    struct cmt_prometheus_time_series     *time_series_entry;
    struct cmt_prometheus_metric_metadata *metadata_entry;
    cmt_sds_t                              result_buffer;
    size_t                                 entry_index;
    struct mk_list                        *head;

    context->write_request.n_timeseries = mk_list_size(&context->time_series_entries);
    context->write_request.n_metadata   = mk_list_size(&context->metadata_entries);

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

    mk_list_foreach(head, &context->time_series_entries) {
        time_series_entry = mk_list_entry(head, struct cmt_prometheus_time_series, _head);

        context->write_request.timeseries[entry_index++] = &time_series_entry->data;
    }

    entry_index = 0;

    mk_list_foreach(head, &context->metadata_entries) {
        metadata_entry = mk_list_entry(head, struct cmt_prometheus_metric_metadata, _head);

        context->write_request.metadata[entry_index++] = &metadata_entry->data;
    }

    write_request_size = prometheus__write_request__get_packed_size(&context->write_request);

    result_buffer = cmt_sds_create_size(write_request_size);

    if(result_buffer != NULL) {
        prometheus__write_request__pack(&context->write_request, (uint8_t *) result_buffer);

        cmt_sds_set_len(result_buffer, write_request_size);
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
    struct mk_list                        *head;
    struct mk_list                        *tmp;

    mk_list_foreach_safe(head, tmp, &context->time_series_entries) {
        time_series_entry = mk_list_entry(head, struct cmt_prometheus_time_series, _head);

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

        mk_list_del(&time_series_entry->_head);

        free(time_series_entry);
    }

    mk_list_foreach_safe(head, tmp, &context->metadata_entries) {
        metadata_entry = mk_list_entry(head, struct cmt_prometheus_metric_metadata, _head);

        mk_list_del(&metadata_entry->_head);

        free(metadata_entry);
    }
}

uint64_t calculate_label_set_hash(struct mk_list *label_values, uint64_t seed)
{
    struct cmt_map_label *label_value;
    XXH64_state_t         state;
    struct mk_list       *head;

    XXH64_reset(&state, 0);

    XXH64_update(&state, &seed, sizeof(uint64_t)); 

    mk_list_foreach(head, label_values) {
        label_value = mk_list_entry(head, struct cmt_map_label, _head);

        XXH64_update(&state, label_value->name, cmt_sds_len(label_value->name)); 
    }

    return XXH64_digest(&state);
}

size_t count_metrics_with_matching_label_set(struct mk_list *metrics,
                                             uint64_t sequence_number,
                                             uint64_t desired_hash)
{
    uint64_t           label_set_hash;
    size_t             matches;
    struct cmt_metric *metric;
    struct mk_list    *head;

    matches = 0;

    mk_list_foreach(head, metrics) {
        metric = mk_list_entry(head, struct cmt_metric, _head);

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

    label_list[*index]->name = cmt_sds_create(name);

    if (label_list[*index]->name == NULL) {
        free(label_list[*index]);

        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    label_list[*index]->value = cmt_sds_create(value);

    if (label_list[*index]->value == NULL) {
        cmt_sds_destroy(label_list[*index]->name);
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
                    cmt_sds_destroy(label_list[index]->name);
                    label_list[index]->name = NULL;
                }

                if (label_list[index]->value != NULL) {
                    cmt_sds_destroy(label_list[index]->value);
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
    struct mk_list                    *head;

    label_set_hash = calculate_label_set_hash(&metric->labels, context->sequence_number);

    /* Determine if there is an existing time series for this label set */
    time_series_match_found = CMT_FALSE;

    mk_list_foreach(head, &context->time_series_entries) {
        time_series_entry = mk_list_entry(head, struct cmt_prometheus_time_series, _head);

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
    label_count = mk_list_size(&context->cmt->static_labels->list) +
                  mk_list_size(&metric->labels) +
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

    mk_list_foreach(head, &context->cmt->static_labels->list) {
        static_label = mk_list_entry(head, struct cmt_label, _head);

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
        label_name = mk_list_entry_first(&map->label_keys, struct cmt_map_label, _head);

        mk_list_foreach(head, &metric->labels) {
            label_value = mk_list_entry(head, struct cmt_map_label, _head);

            result = append_entry_to_prometheus_label_list(label_list,
                                                           &label_index,
                                                           label_name->name,
                                                           label_value->name);

            if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS)
            {
                break;
            }

            label_name = mk_list_entry_next(&label_name->_head, struct cmt_map_label,
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
    mk_list_add(&time_series_entry->_head, &context->time_series_entries);

    *time_series = time_series_entry;

    return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;
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
    else {
        return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_UNEXPECTED_METRIC_TYPE;
    }

    metadata_entry->data.metric_family_name = map->opts->fqname;
    metadata_entry->data.help = map->opts->fqname;
    metadata_entry->data.unit = "unit";

    mk_list_add(&metadata_entry->_head, &context->metadata_entries);

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

int pack_metric_sample(struct cmt_prometheus_remote_write_context *context,
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

int pack_basic_type(struct cmt_prometheus_remote_write_context *context,
                    struct cmt_map *map)
{
    int                add_metadata;
    struct cmt_metric *metric;
    int                result;
    struct mk_list    *head;

    context->sequence_number++;
    add_metadata = CMT_TRUE;

    if (map->metric_static_set == CMT_TRUE) {
        result = pack_metric_sample(context, map, &map->metric, add_metadata);

        if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            return result;
        }
    }

    mk_list_foreach(head, &map->metrics) {
        metric = mk_list_entry(head, struct cmt_metric, _head);

        result = pack_metric_sample(context, map, metric, add_metadata);

        if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            return result;
        }

        if (add_metadata == CMT_TRUE) {
            add_metadata = CMT_FALSE;
        }
    }

    return CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;
}

/* Format all the registered metrics in Prometheus Text format */
cmt_sds_t cmt_encode_prometheus_remote_write_create(struct cmt *cmt)
{
    struct cmt_prometheus_remote_write_context context;
    struct cmt_untyped                        *untyped;
    struct cmt_counter                        *counter;
    int                                        result;
    struct cmt_gauge                          *gauge;
    struct mk_list                            *head;
    cmt_sds_t                                  buf;

    buf = NULL;

    memset(&context, 0, sizeof(struct cmt_prometheus_remote_write_context));

    prometheus__write_request__init(&context.write_request);

    context.cmt = cmt;

    mk_list_init(&context.time_series_entries);
    mk_list_init(&context.metadata_entries);

    /* Counters */
    mk_list_foreach(head, &cmt->counters) {
        counter = mk_list_entry(head, struct cmt_counter, _head);
        result = pack_basic_type(&context, counter->map);

        if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            break;
        }
    }

    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        /* Gauges */
        mk_list_foreach(head, &cmt->gauges) {
            gauge = mk_list_entry(head, struct cmt_gauge, _head);
            result = pack_basic_type(&context, gauge->map);

            if (result != CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
                break;
            }
        }

    }

    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        /* Untyped */
        mk_list_foreach(head, &cmt->untypeds) {
            untyped = mk_list_entry(head, struct cmt_untyped, _head);
            pack_basic_type(&context, untyped->map);
        }
    }

    if (result == CMT_ENCODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        buf = render_remote_write_context_to_sds(&context);
    }

    cmt_destroy_prometheus_remote_write_context(&context);

    return buf;
}

void cmt_encode_prometheus_remote_write_destroy(cmt_sds_t text)
{
    cmt_sds_destroy(text);
}
