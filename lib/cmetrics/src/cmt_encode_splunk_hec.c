/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2022 The CMetrics Authors
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
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_atomic.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_time.h>
#include <cmetrics/cmt_compat.h>
#include <cmetrics/cmt_encode_splunk_hec.h>

static cfl_sds_t double_to_string(double val)
{
    int len;
    cfl_sds_t str;

    str = cfl_sds_create_size(64);
    if (!str) {
        return NULL;
    }

    len = snprintf(str, 64, "%g", val);
    if (strstr(str, "e+")) {
        len = snprintf(str, 64, "%e", val);
        cfl_sds_len_set(str, len);
    } else {
        cfl_sds_len_set(str, len);
    }

    if (!strchr(str, '.')) {
        cfl_sds_cat_safe(&str, ".0", 2);
    }

    return str;
}

static void destroy_temporary_metric_labels(struct cmt_metric *metric)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cmt_map_label *label;

    cfl_list_foreach_safe(head, tmp, &metric->labels) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        cfl_list_del(&label->_head);
        cfl_sds_destroy(label->name);
        free(label);
    }
}

static int initialize_temporary_metric(struct cmt_metric *destination,
                                       struct cmt_metric *source)
{
    struct cfl_list *head;
    struct cmt_map_label *source_label;
    struct cmt_map_label *destination_label;

    memset(destination, 0, sizeof(struct cmt_metric));
    cfl_list_init(&destination->labels);

    cfl_list_foreach(head, &source->labels) {
        source_label = cfl_list_entry(head, struct cmt_map_label, _head);

        destination_label = calloc(1, sizeof(struct cmt_map_label));
        if (destination_label == NULL) {
            destroy_temporary_metric_labels(destination);
            return -1;
        }

        destination_label->name = cfl_sds_create(source_label->name);
        if (destination_label->name == NULL) {
            free(destination_label);
            destroy_temporary_metric_labels(destination);
            return -1;
        }

        cfl_list_add(&destination_label->_head, &destination->labels);
    }

    cmt_metric_set_timestamp(destination, cmt_metric_get_timestamp(source));

    return 0;
}

static void format_metric_name(cfl_sds_t *buf, struct cmt_map *map, const char *suffix)
{
    int mlen = 0;
    int slen = 0;
    cfl_sds_t metric_name = NULL;
    struct cmt_opts *opts;

    opts = map->opts;

    if (cfl_sds_len(opts->subsystem) > 0) {
        /* Calculate length for "metric_name:subsystem.name": */
        mlen = 13 + cfl_sds_len(opts->subsystem) + 1 + cfl_sds_len(opts->name) + 2;
        metric_name = cfl_sds_create_size(mlen);
        cfl_sds_cat_safe(&metric_name, "\"metric_name:", 13);
        cfl_sds_cat_safe(&metric_name, opts->subsystem, cfl_sds_len(opts->subsystem));
        cfl_sds_cat_safe(&metric_name, ".", 1);
        cfl_sds_cat_safe(&metric_name, opts->name, cfl_sds_len(opts->name));
    }
    else {
        /* Calculate length for "metric_name:subsystem.name": */
        mlen = 13 + cfl_sds_len(opts->name) + 2;
        metric_name = cfl_sds_create_size(mlen);
        cfl_sds_cat_safe(&metric_name, "\"metric_name:", 13);
        cfl_sds_cat_safe(&metric_name, opts->name, cfl_sds_len(opts->name));
    }
    if (suffix != NULL) {
        slen = strlen(suffix);
        mlen += slen;
        cfl_sds_cat_safe(&metric_name, suffix, slen);
    }
    cfl_sds_cat_safe(&metric_name, "\":", 2);
    cfl_sds_cat_safe(buf, metric_name, mlen);
    cfl_sds_destroy(metric_name);
}

static void format_metric_type(cfl_sds_t *buf, const char *metric_type_name)
{
    int len = 0;
    char tmp[32];

    len = snprintf(tmp, sizeof(tmp) - 1, ",\"metric_type\":\"%s\"", metric_type_name);
    cfl_sds_cat_safe(buf, tmp, len);
}

static void append_metric_value(cfl_sds_t *buf, struct cmt_map *map,
                                struct cmt_metric *metric)
{
    int len;
    double val;
    char tmp[128];
    cfl_sds_t metric_val;

    /* Retreive metric name */
    format_metric_name(buf, map, NULL);

    /* Retrieve metric value */
    val = cmt_metric_get_value(metric);
    metric_val = double_to_string(val);

    len = snprintf(tmp, sizeof(tmp) - 1, "%s", metric_val);
    cfl_sds_cat_safe(buf, tmp, len);
    cfl_sds_destroy(metric_val);
}

static void format_context_common(struct cmt_splunk_hec_context *context, cfl_sds_t *buf, struct cmt_map *map,
                                  struct cmt_metric *metric)
{
    int len;
    int tlen;
    int result = CMT_ENCODE_SPLUNK_HEC_ALLOCATION_ERROR;
    uint64_t ts;
    char hostname[256], timestamp[128];
    char *index = NULL;
    char *source = NULL;
    char *source_type = NULL;
    struct timespec tms;

    /* Open parenthesis */
    cfl_sds_cat_safe(buf, "{", 1);

    /* host */
    len = snprintf(hostname, sizeof(hostname) - 1, "\"host\":\"%s\",", context->host);
    cfl_sds_cat_safe(buf, hostname, len);

    /* timestamp (RFC3339Nano) */
    ts = cmt_metric_get_timestamp(metric);
    cmt_time_from_ns(&tms, ts);

    /* timestamp (floting point) */
    len = snprintf(timestamp, sizeof(timestamp) - 1, "\"time\":%09lu.%09lu,", tms.tv_sec, tms.tv_nsec);
    cfl_sds_cat_safe(buf, timestamp, len);

    /* event type: metric */
    cfl_sds_cat_safe(buf, "\"event\":\"metric\",", 17);

    /* index */
    if (context->index != NULL) {
        tlen = strlen(context->index) + 12; /* adding snprintf template character length */
        index = malloc(tlen);
        if (index == NULL) {
            cmt_errno();
            result = CMT_ENCODE_SPLUNK_HEC_ALLOCATION_ERROR;

            goto cleanup;
        }
        len = snprintf(index, tlen, "\"index\":\"%s\",", context->index);
        cfl_sds_cat_safe(buf, index, len);
        free(index);
        index = NULL;
    }

    /* source */
    if (context->source != NULL) {
        tlen = strlen(context->source) + 13; /* adding snprintf template character length */
        source = malloc(tlen);
        if (source == NULL) {
            cmt_errno();
            result = CMT_ENCODE_SPLUNK_HEC_ALLOCATION_ERROR;

            goto cleanup;
        }
        len = snprintf(source, tlen, "\"source\":\"%s\",", context->source);
        cfl_sds_cat_safe(buf, source, len);
        free(source);
        source = NULL;
    }

    /* sourcetype */
    if (context->source_type != NULL) {
        tlen = strlen(context->source_type) + 18; /* adding snprintf template character length */
        source_type = malloc(tlen);
        if (source_type == NULL) {
            cmt_errno();
            result = CMT_ENCODE_SPLUNK_HEC_ALLOCATION_ERROR;

            goto cleanup;
        }
        len = snprintf(source_type, tlen, "\"sourcetype\":\"%s\",", context->source_type);
        cfl_sds_cat_safe(buf, source_type, len);
        free(source_type);
        source_type = NULL;
    }

    return;

cleanup:
    if (result != CMT_ENCODE_SPLUNK_HEC_SUCCESS) {
        if (index != NULL) {
            free(index);
        }
        if (source != NULL) {
            free(source);
        }
        if (source_type != NULL) {
            free(source_type);
        }
    }
}

static void format_metric_labels(struct cmt_splunk_hec_context *context, cfl_sds_t *buf, struct cmt_map *map,
                                 struct cmt_metric *metric)
{
    int i;
    int n;
    int count = 0;
    int static_labels = 0;

    struct cmt_map_label *label_k;
    struct cmt_map_label *label_v;
    struct cfl_list *head;
    struct cmt_label *slabel;

    /* Static labels */
    static_labels = cmt_labels_count(context->cmt->static_labels);
    if (static_labels > 0) {
        cfl_sds_cat_safe(buf, ",", 1);
        cfl_list_foreach(head, &context->cmt->static_labels->list) {
            count++;
            cfl_sds_cat_safe(buf, "\"", 1);
            slabel = cfl_list_entry(head, struct cmt_label, _head);
            cfl_sds_cat_safe(buf, slabel->key, cfl_sds_len(slabel->key));
            cfl_sds_cat_safe(buf, "\":\"", 3);
            cfl_sds_cat_safe(buf, slabel->val, cfl_sds_len(slabel->val));
            cfl_sds_cat_safe(buf, "\"", 1);

            if (count < static_labels) {
                cfl_sds_cat_safe(buf, ",", 1);
            }
        }
    }

    n = cfl_list_size(&metric->labels);
    if (n > 0) {
        cfl_sds_cat_safe(buf, ",", 1);
        label_k = cfl_list_entry_first(&map->label_keys, struct cmt_map_label, _head);

        i = 0;
        cfl_list_foreach(head, &metric->labels) {
            label_v = cfl_list_entry(head, struct cmt_map_label, _head);

            cfl_sds_cat_safe(buf, "\"", 1);
            cfl_sds_cat_safe(buf, label_k->name, cfl_sds_len(label_k->name));
            cfl_sds_cat_safe(buf, "\":\"", 3);
            cfl_sds_cat_safe(buf, label_v->name, cfl_sds_len(label_v->name));
            cfl_sds_cat_safe(buf, "\"", 1);
            i++;

            label_k = cfl_list_entry_next(&label_k->_head, struct cmt_map_label,
                                         _head, &map->label_keys);
            if (i < n) {
                cfl_sds_cat_safe(buf, ",", 1);
            }
        }
    }
}

static void append_bucket_metric(cfl_sds_t *buf, struct cmt_map *map,
                                 struct cmt_metric *metric, int index)
{
    int len = 0;
    double val;
    char tmp[128];
    cfl_sds_t metric_val;

    /* metric name for bucket */
    format_metric_name(buf, map, "_bucket");

    /* Retrieve metric value */
    val = cmt_metric_hist_get_value(metric, index);
    metric_val = double_to_string(val);

    len = snprintf(tmp, sizeof(tmp) - 1, "%s", metric_val);
    cfl_sds_cat_safe(buf, tmp, len);
    cfl_sds_destroy(metric_val);
}

static void format_histogram_bucket(struct cmt_splunk_hec_context *context, cfl_sds_t *buf, struct cmt_map *map,
                                    struct cmt_metric *metric)
{
    int index;
    int len = 0;
    char tmp[128];
    cfl_sds_t val;
    double metric_val;
    struct cmt_histogram *histogram;
    struct cmt_histogram_buckets *buckets;
    cfl_sds_t metric_str;

    histogram = (struct cmt_histogram *) map->parent;
    buckets = histogram->buckets;

    for (index = 0; index <= buckets->count; index++) {
        /* Common fields */
        format_context_common(context, buf, map, metric);

        /* Other fields */
        cfl_sds_cat_safe(buf, "\"fields\":{", 10);

        /* bucket metric */
        append_bucket_metric(buf, map, metric, index);

        /* upper bound */
        cfl_sds_cat_safe(buf, ",\"le\":", 6);

        if (index < buckets->count) {
            cfl_sds_cat_safe(buf, "\"", 1);
            val = double_to_string(buckets->upper_bounds[index]);
            cfl_sds_cat_safe(buf, val, cfl_sds_len(val));
            cfl_sds_destroy(val);
            cfl_sds_cat_safe(buf, "\"", 1);
        }
        else {
            cfl_sds_cat_safe(buf, "\"+Inf\"", 6);
        }

        /* Format labels */
        format_metric_labels(context, buf, map, metric);

        /* Format metric type */
        format_metric_type(buf, "Histogram");

        /* Close parenthesis for fields */
        cfl_sds_cat_safe(buf, "}", 1);

        /* Close parenthesis */
        cfl_sds_cat_safe(buf, "}", 1);
    }

    /* Format histogram sum */
    {
        /* Common fields */
        format_context_common(context, buf, map, metric);

        /* Other fields */
        cfl_sds_cat_safe(buf, "\"fields\":{", 10);

        /* metric name for bucket */
        format_metric_name(buf, map, "_sum");

        /* Retrieve metric value */
        metric_val = cmt_metric_hist_get_sum_value(metric);
        metric_str = double_to_string(metric_val);

        len = snprintf(tmp, sizeof(tmp) - 1, "%s", metric_str);
        cfl_sds_cat_safe(buf, tmp, len);
        cfl_sds_destroy(metric_str);

        /* Format labels */
        format_metric_labels(context, buf, map, metric);

        /* Format metric type */
        format_metric_type(buf, "Histogram");

        /* Close parenthesis for fields */
        cfl_sds_cat_safe(buf, "}", 1);

        /* Close parenthesis */
        cfl_sds_cat_safe(buf, "}", 1);
    }

    /* Format histogram sum */
    {
        /* Common fields */
        format_context_common(context, buf, map, metric);

        /* Other fields */
        cfl_sds_cat_safe(buf, "\"fields\":{", 10);

        /* metric name for bucket */
        format_metric_name(buf, map, "_count");

        /* Retrieve metric value */
        metric_val = cmt_metric_hist_get_count_value(metric);
        metric_str = double_to_string(metric_val);

        len = snprintf(tmp, sizeof(tmp) - 1, "%s", metric_str);
        cfl_sds_cat_safe(buf, tmp, len);
        cfl_sds_destroy(metric_str);

        /* Format labels */
        format_metric_labels(context, buf, map, metric);

        /* Format metric type */
        format_metric_type(buf, "Histogram");

        /* Close parenthesis for fields */
        cfl_sds_cat_safe(buf, "}", 1);

        /* Close parenthesis */
        cfl_sds_cat_safe(buf, "}", 1);
    }
}

static void append_quantiles_metric(cfl_sds_t *buf, struct cmt_map *map,
                                    struct cmt_metric *metric, int index)
{
    int len = 0;
    double val;
    char tmp[128];
    cfl_sds_t metric_val;

    /* metric name for bucket */
    format_metric_name(buf, map, NULL);

    /* Retrieve metric value */
    val = cmt_summary_quantile_get_value(metric, index);
    metric_val = double_to_string(val);

    len = snprintf(tmp, sizeof(tmp) - 1, "%s", metric_val);
    cfl_sds_cat_safe(buf, tmp, len);
    cfl_sds_destroy(metric_val);
}

static void format_summary_metric(struct cmt_splunk_hec_context *context, cfl_sds_t *buf, struct cmt_map *map,
                                  struct cmt_metric *metric)
{
    int index;
    int len = 0;
    char tmp[128];
    cfl_sds_t val;
    uint64_t metric_val;
    struct cmt_summary *summary;
    cfl_sds_t metric_str;

    summary = (struct cmt_summary *) map->parent;

    if (cmt_atomic_load(&metric->sum_quantiles_set)) {
        for (index = 0; index < summary->quantiles_count; index++) {
            /* Common fields */
            format_context_common(context, buf, map, metric);

            /* Other fields */
            cfl_sds_cat_safe(buf, "\"fields\":{", 10);

            /* bucket metric */
            append_quantiles_metric(buf, map, metric, index);

            /* quantiles */
            cfl_sds_cat_safe(buf, ",\"qt\":\"", 7);
            val = double_to_string(summary->quantiles[index]);
            cfl_sds_cat_safe(buf, val, cfl_sds_len(val));
            cfl_sds_destroy(val);
            cfl_sds_cat_safe(buf, "\"", 1);

            /* Format labels */
            format_metric_labels(context, buf, map, metric);

            /* Format metric type */
            format_metric_type(buf, "Summary");

            /* Close parenthesis for fields */
            cfl_sds_cat_safe(buf, "}", 1);

            /* Close parenthesis */
            cfl_sds_cat_safe(buf, "}", 1);
        }
    }

    /* Format Summary sum */
    {
        /* Common fields */
        format_context_common(context, buf, map, metric);

        /* Other fields */
        cfl_sds_cat_safe(buf, "\"fields\":{", 10);

        /* metric name for bucket */
        format_metric_name(buf, map, "_sum");

        /* Retrieve metric value */
        metric_val = cmt_summary_get_sum_value(metric);
        metric_str = double_to_string(metric_val);

        len = snprintf(tmp, sizeof(tmp) - 1, "%s", metric_str);
        cfl_sds_cat_safe(buf, tmp, len);
        cfl_sds_destroy(metric_str);

        /* Format labels */
        format_metric_labels(context, buf, map, metric);

        /* Format metric type */
        format_metric_type(buf, "Summary");

        /* Close parenthesis for fields */
        cfl_sds_cat_safe(buf, "}", 1);

        /* Close parenthesis */
        cfl_sds_cat_safe(buf, "}", 1);
    }

    /* Format summary count */
    {
        /* Common fields */
        format_context_common(context, buf, map, metric);

        /* Other fields */
        cfl_sds_cat_safe(buf, "\"fields\":{", 10);

        /* metric name for bucket */
        format_metric_name(buf, map, "_count");

        /* Retrieve metric value */
        metric_val = cmt_summary_get_count_value(metric);
        metric_str = double_to_string(metric_val);

        len = snprintf(tmp, sizeof(tmp) - 1, "%s", metric_str);
        cfl_sds_cat_safe(buf, tmp, len);
        cfl_sds_destroy(metric_str);

        /* Format labels */
        format_metric_labels(context, buf, map, metric);

        /* Format metric type */
        format_metric_type(buf, "Summary");

        /* Close parenthesis for fields */
        cfl_sds_cat_safe(buf, "}", 1);

        /* Close parenthesis */
        cfl_sds_cat_safe(buf, "}", 1);
    }
}

static void format_metric_data_points(struct cmt_splunk_hec_context *context, cfl_sds_t *buf, struct cmt_map *map,
                                      struct cmt_metric *metric)
{
    /* Common fields */
    format_context_common(context, buf, map, metric);

    /* Other fields */
    cfl_sds_cat_safe(buf, "\"fields\":{", 10);

    /* Metric name and value */
    append_metric_value(buf, map, metric);

    /* Format labels */
    format_metric_labels(context, buf, map, metric);

    /* Close parenthesis for fields */
    cfl_sds_cat_safe(buf, "}", 1);

    /* Close parenthesis */
    cfl_sds_cat_safe(buf, "}", 1);
}

static void format_metric(struct cmt_splunk_hec_context *context, cfl_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric)
{
    if (map->type == CMT_HISTOGRAM) {
        return format_histogram_bucket(context, buf, map, metric);
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        struct cmt_map fake_map;
        struct cmt_metric fake_metric;
        struct cmt_histogram fake_histogram;
        struct cmt_histogram_buckets fake_buckets;
        uint64_t *bucket_counts = NULL;
        double *upper_bounds = NULL;
        size_t upper_bounds_count = 0;
        size_t bucket_count = 0;

        if (cmt_exp_histogram_to_explicit(metric,
                                          &upper_bounds,
                                          &upper_bounds_count,
                                          &bucket_counts,
                                          &bucket_count) != 0) {
            return;
        }

        fake_buckets.count = upper_bounds_count;
        fake_buckets.upper_bounds = upper_bounds;
        fake_histogram.buckets = &fake_buckets;

        memcpy(&fake_map, map, sizeof(struct cmt_map));
        fake_map.type = CMT_HISTOGRAM;
        fake_map.parent = &fake_histogram;
        if (initialize_temporary_metric(&fake_metric, metric) != 0) {
            free(bucket_counts);
            free(upper_bounds);
            return;
        }

        fake_metric.hist_buckets = bucket_counts;
        fake_metric.hist_count = bucket_counts[bucket_count - 1];
        fake_metric.hist_sum = cmt_atomic_load(&metric->exp_hist_sum);

        format_histogram_bucket(context, buf, &fake_map, &fake_metric);

        destroy_temporary_metric_labels(&fake_metric);
        free(bucket_counts);
        free(upper_bounds);

        return;
    }
    else if (map->type == CMT_SUMMARY) {
        return format_summary_metric(context, buf, map, metric);
    }
    else {
        /* For Counter, Gauge, and Untyped types */
        return format_metric_data_points(context, buf, map, metric);
    }
}

static void format_metrics(struct cmt_splunk_hec_context *context, cfl_sds_t *buf, struct cmt_map *map)
{
    struct cfl_list *head;
    struct cmt_metric *metric;

    /* Simple metric, no labels */
    if (map->metric_static_set == 1) {
        format_metric(context, buf, map, &map->metric);
    }

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        format_metric(context, buf, map, metric);
    }
}

static void destroy_splunk_hec_context(struct cmt_splunk_hec_context *context)
{
    if (context != NULL) {
        free(context);
    }
}

static struct cmt_splunk_hec_context
*initialize_splunk_hec_context(struct cmt *cmt, const char *host,
                               const char *index, const char *source, const char *source_type)
{
    int result = CMT_ENCODE_SPLUNK_HEC_SUCCESS;
    struct cmt_splunk_hec_context *context = NULL;

    context = calloc(1, sizeof(struct cmt_splunk_hec_context));
    if (context == NULL) {
        result = CMT_ENCODE_SPLUNK_HEC_ALLOCATION_ERROR;
        goto cleanup;
    }

    /* host parameter is mandatory. */
    if (host == NULL) {
        result = CMT_ENCODE_SPLUNK_HEC_INVALID_ARGUMENT_ERROR;
        goto cleanup;
    }

    memset(context, 0, sizeof(struct cmt_splunk_hec_context));
    context->cmt = cmt;
    context->host = host;
    context->index = NULL;
    context->source = NULL;
    context->source_type = NULL;

    /* Setting up optional members. */
    if (index != NULL) {
        context->index = index;
    }
    if (source != NULL) {
        context->source = source;
    }
    if (source_type != NULL) {
        context->source_type = source_type;
    }

cleanup:
    if (result != CMT_ENCODE_SPLUNK_HEC_SUCCESS) {
        if (context != NULL) {
            destroy_splunk_hec_context(context);
            context = NULL;
        }
    }

    return context;
}

/* Format all the registered metrics in Splunk HEC JSON format */
cfl_sds_t cmt_encode_splunk_hec_create(struct cmt *cmt, const char *host,
                                       const char *index, const char *source, const char *source_type)
{
    cfl_sds_t buf;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_splunk_hec_context *context;

    context = initialize_splunk_hec_context(cmt, host, index, source, source_type);

    if (context == NULL) {
        return NULL;
    }

    /* Allocate a 1KB of buffer */
    buf = cfl_sds_create_size(1024);
    if (!buf) {
        destroy_splunk_hec_context(context);
        return NULL;
    }

    /* Counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        format_metrics(context, &buf, counter->map);
    }

    /* Gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        format_metrics(context, &buf, gauge->map);
    }

    /* Summaries */
    cfl_list_foreach(head, &cmt->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        format_metrics(context, &buf, summary->map);
    }

    /* Histograms */
    cfl_list_foreach(head, &cmt->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        format_metrics(context, &buf, histogram->map);
    }

    /* Exponential Histograms */
    cfl_list_foreach(head, &cmt->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        format_metrics(context, &buf, exp_histogram->map);
    }

    /* Untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        format_metrics(context, &buf, untyped->map);
    }

    if (context != NULL) {
      destroy_splunk_hec_context(context);
    }

    return buf;
}

void cmt_encode_splunk_hec_destroy(cfl_sds_t text)
{
    cfl_sds_destroy(text);
}
