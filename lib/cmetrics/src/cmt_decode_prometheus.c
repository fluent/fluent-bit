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

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_decode_prometheus.h>

#include <cmt_decode_prometheus_parser.h>
#include <stdio.h>
#include <string.h>
#include <cmetrics/cmt_map.h>

static void reset_context(struct cmt_decode_prometheus_context *context,
                          bool reset_summary)
{
    int i;
    struct cmt_decode_prometheus_context_sample *sample;

    while (!cfl_list_is_empty(&context->metric.samples)) {
        sample = cfl_list_entry_first(&context->metric.samples,
                                     struct cmt_decode_prometheus_context_sample, _head);
        for (i = 0; i < context->metric.label_count; i++) {
            cfl_sds_destroy(sample->label_values[i]);
        }
        cfl_list_del(&sample->_head);
        free(sample);
    }

    for (i = 0; i < context->metric.label_count; i++) {
        cfl_sds_destroy(context->metric.labels[i]);
    }

    if (context->metric.ns) {
        if ((void *) context->metric.ns != (void *) "") {
            /* when namespace is empty, "name" contains a pointer to the
             * allocated string.
             *
             * Note : When the metric name doesn't include the namespace
             * ns is set to a constant empty string and we need to
             * differentiate that case from the case where an empty
             * namespace is provided.
             */

            free(context->metric.ns);
        }
        else {
            free(context->metric.name);
        }
    }

    cfl_sds_destroy(context->strbuf);
    context->strbuf = NULL;
    if (reset_summary) {
        context->current.summary = NULL;
    }
    cfl_sds_destroy(context->metric.name_orig);
    cfl_sds_destroy(context->metric.docstring);
    memset(&context->metric,
            0,
            sizeof(struct cmt_decode_prometheus_context_metric));
    cfl_list_init(&context->metric.samples);
}


int cmt_decode_prometheus_create(
        struct cmt **out_cmt,
        const char *in_buf,
        size_t in_size,
        struct cmt_decode_prometheus_parse_opts *opts)
{
    yyscan_t scanner;
    YY_BUFFER_STATE buf;
    struct cmt *cmt;
    struct cmt_decode_prometheus_context context;
    int result;

    cmt = cmt_create();

    if (cmt == NULL) {
        return CMT_DECODE_PROMETHEUS_ALLOCATION_ERROR;
    }

    memset(&context, 0, sizeof(context));
    context.cmt = cmt;
    if (opts) {
        context.opts = *opts;
    }
    cfl_list_init(&(context.metric.samples));
    cmt_decode_prometheus_lex_init(&scanner);
    if (!in_size) {
        in_size = strlen(in_buf);
    }
    buf = cmt_decode_prometheus__scan_bytes((char *)in_buf, in_size, scanner);
    if (!buf) {
        cmt_destroy(cmt);
        return CMT_DECODE_PROMETHEUS_ALLOCATION_ERROR;
    }

    result = cmt_decode_prometheus_parse(scanner, &context);

    if (result == 0) {
        *out_cmt = cmt;
    }
    else {
        cmt_destroy(cmt);
        if (context.errcode) {
            result = context.errcode;
        }
        reset_context(&context, true);
    }

    cmt_decode_prometheus__delete_buffer(buf, scanner);
    cmt_decode_prometheus_lex_destroy(scanner);

    return result;
}

void cmt_decode_prometheus_destroy(struct cmt *cmt)
{
    cmt_destroy(cmt);
}

static int report_error(struct cmt_decode_prometheus_context *context,
                         int errcode,
                         const char *format, ...)
{
    va_list args;
    va_start(args, format);
    context->errcode = errcode;
    if (context->opts.errbuf && context->opts.errbuf_size) {
        vsnprintf(context->opts.errbuf, context->opts.errbuf_size - 1, format, args);
    }
    va_end(args);
    return errcode;
}

static int split_metric_name(struct cmt_decode_prometheus_context *context,
        cfl_sds_t metric_name, char **ns,
        char **subsystem, char **name)
{
    /* split the name */
    *ns = strdup(metric_name);
    if (!*ns) {
        return report_error(context,
                CMT_DECODE_PROMETHEUS_ALLOCATION_ERROR,
                "memory allocation failed");
    }
    *subsystem = strchr(*ns, '_');
    if (!(*subsystem)) {
        *name = *ns;
        *ns = "";
    }
    else {
        **subsystem = 0;  /* split */
        (*subsystem)++;
        *name = strchr(*subsystem, '_');
        if (!(*name)) {
            *name = *subsystem;
            *subsystem = "";
        }
        else {
            **name = 0;
            (*name)++;
        }
    }
    return 0;
}

/* Use this helper function to return a stub value for docstring when it is not
 * available. This is necessary for now because the metric constructors require
 * a docstring, even though it is not required by prometheus spec. */
static char *get_docstring(struct cmt_decode_prometheus_context *context)
{
    return context->metric.docstring && strlen(context->metric.docstring) ?
        context->metric.docstring : " ";
}

static int parse_uint64(const char *in, uint64_t *out)
{
    char *end;
    int64_t val;

    errno = 0;
    val = strtoll(in, &end, 10);
    if (end == in || *end != 0 || errno)  {
        return -1;
    }

    /* Even though prometheus text format supports negative numbers, cmetrics
     * doesn't, so we truncate to 0 */
    if (val < 0) {
        val = 0;
    }
    *out = val;
    return 0;
}

static int parse_double(const char *in, double *out)
{
    char *end;
    double val;
    errno = 0;
    val = strtod(in, &end);
    if (end == in || *end != 0 || errno) {
        return -1;
    }
    *out = val;
    return 0;
}

static int parse_timestamp(struct cmt_decode_prometheus_context *context,
                           char *data_source, uint64_t *timestamp)
{
    int result;

    result = CMT_DECODE_PROMETHEUS_SUCCESS;

    if (data_source != NULL && strlen(data_source) > 0) {
        result = parse_uint64(data_source, timestamp);

        if (result) {
            result = report_error(context,
                                  CMT_DECODE_PROMETHEUS_PARSE_TIMESTAMP_FAILED,
                                  "failed to parse sample: \"%s\" is not a valid "
                                  "timestamp", data_source);
        }
        else {
            /* prometheus text format timestamps are expressed in milliseconds,
             * while cmetrics expresses them in nanoseconds, so multiply by 10e5
             */

            *timestamp *= 10e5;
        }
    }

    return result;
}

static int parse_value_timestamp(
        struct cmt_decode_prometheus_context *context,
        struct cmt_decode_prometheus_context_sample *sample,
        double *value,
        uint64_t *timestamp)
{

    if (parse_double(sample->value1, value)) {
        return report_error(context,
                CMT_DECODE_PROMETHEUS_PARSE_VALUE_FAILED,
                "failed to parse sample: \"%s\" is not a valid "
                "value", sample->value1);
    }

    if (context->opts.override_timestamp) {
        *timestamp = context->opts.override_timestamp;
    }
    else if (!strlen(sample->value2)) {
        /* No timestamp was specified, use default value */
        *timestamp = context->opts.default_timestamp;
        return 0;
    }
    else if (parse_uint64(sample->value2, timestamp)) {
        return report_error(context,
                CMT_DECODE_PROMETHEUS_PARSE_TIMESTAMP_FAILED,
                "failed to parse sample: \"%s\" is not a valid "
                "timestamp", sample->value2);
    }

    /* prometheus text format timestamps are in milliseconds, while cmetrics is in
     * nanoseconds, so multiply by 10e5 */
    *timestamp = *timestamp * 10e5;

    return 0;
}

static int add_metric_counter(struct cmt_decode_prometheus_context *context)
{
    int ret;
    size_t label_count;
    struct cmt_counter *c;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cmt_decode_prometheus_context_sample *sample;
    double value;
    uint64_t timestamp;

    c = cmt_counter_create(context->cmt,
            context->metric.ns,
            context->metric.subsystem,
            context->metric.name,
            get_docstring(context),
            context->metric.label_count,
            context->metric.labels);

    if (!c) {
        return report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "cmt_counter_create failed");
    }

    cfl_list_foreach_safe(head, tmp, &context->metric.samples) {
        sample = cfl_list_entry(head, struct cmt_decode_prometheus_context_sample, _head);
        label_count = context->metric.label_count;
        ret = parse_value_timestamp(context, sample, &value, &timestamp);
        if (ret) {
            return ret;
        }
        if (cmt_counter_set(c,
                    timestamp,
                    value,
                    label_count,
                    label_count ? sample->label_values : NULL)) {
            return report_error(context,
                    CMT_DECODE_PROMETHEUS_CMT_SET_ERROR,
                    "cmt_counter_set failed");
        }
    }

    return 0;
}

static int add_metric_gauge(struct cmt_decode_prometheus_context *context)
{
    int ret;
    size_t label_count;
    struct cmt_gauge *c;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cmt_decode_prometheus_context_sample *sample;
    double value;
    uint64_t timestamp;

    c = cmt_gauge_create(context->cmt,
            context->metric.ns,
            context->metric.subsystem,
            context->metric.name,
            get_docstring(context),
            context->metric.label_count,
            context->metric.labels);

    if (!c) {
        return report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "cmt_gauge_create failed");
    }

    cfl_list_foreach_safe(head, tmp, &context->metric.samples) {
        sample = cfl_list_entry(head, struct cmt_decode_prometheus_context_sample, _head);
        label_count = context->metric.label_count;
        ret = parse_value_timestamp(context, sample, &value, &timestamp);
        if (ret) {
            return ret;
        }
        if (cmt_gauge_set(c,
                    timestamp,
                    value,
                    label_count,
                    label_count ? sample->label_values : NULL)) {
            return report_error(context,
                    CMT_DECODE_PROMETHEUS_CMT_SET_ERROR,
                    "cmt_gauge_set failed");
        }
    }

    return 0;
}

static int add_metric_untyped(struct cmt_decode_prometheus_context *context)
{
    int ret;
    size_t label_count;
    struct cmt_untyped *c;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cmt_decode_prometheus_context_sample *sample;
    double value;
    uint64_t timestamp;

    c = cmt_untyped_create(context->cmt,
            context->metric.ns,
            context->metric.subsystem,
            context->metric.name,
            get_docstring(context),
            context->metric.label_count,
            context->metric.labels);

    if (!c) {
        return report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "cmt_untyped_create failed");
    }

    cfl_list_foreach_safe(head, tmp, &context->metric.samples) {
        sample = cfl_list_entry(head, struct cmt_decode_prometheus_context_sample, _head);
        label_count = context->metric.label_count;
        ret = parse_value_timestamp(context, sample, &value, &timestamp);
        if (ret) {
            return ret;
        }
        if (cmt_untyped_set(c,
                    timestamp,
                    value,
                    label_count,
                    label_count ? sample->label_values : NULL)) {
            return report_error(context,
                    CMT_DECODE_PROMETHEUS_CMT_SET_ERROR,
                    "cmt_untyped_set failed");
        }
    }

    return 0;
}

static int add_metric_histogram(struct cmt_decode_prometheus_context *context)
{
    int ret = 0;
    int i;
    size_t bucket_count;
    size_t bucket_index;
    double *buckets = NULL;
    uint64_t *bucket_defaults = NULL;
    double sum = 0;
    uint64_t count = 0;
    double count_dbl;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cmt_decode_prometheus_context_sample *sample;
    size_t le_label_index = 0;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *cmt_buckets;
    cfl_sds_t *labels_without_le = NULL;
    cfl_sds_t *values_without_le = NULL;
    int label_i;
    uint64_t timestamp = 0;

    if (cfl_list_size(&context->metric.samples) < 3) {
        return report_error(context,
                CMT_DECODE_PROMETHEUS_SYNTAX_ERROR,
                "not enough samples for histogram");
    }

    /* bucket_count = sample count - 3:
     * - "Inf" bucket
     * - sum
     * - count */
    bucket_count = cfl_list_size(&context->metric.samples) - 3;
    if (context->opts.override_timestamp) {
        timestamp = context->opts.override_timestamp;
    }

    bucket_defaults = calloc(bucket_count + 1, sizeof(*bucket_defaults));
    if (!bucket_defaults) {
        ret = report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "failed to allocate bucket defaults");
        goto end;
    }
    buckets = calloc(bucket_count, sizeof(*buckets));
    if (!buckets) {
        ret = report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "failed to allocate buckets");
        goto end;
    }
    labels_without_le = calloc(context->metric.label_count - 1, sizeof(*labels_without_le));
    if (!labels_without_le) {
        ret = report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "failed to allocate labels_without_le");
        goto end;
    }
    values_without_le = calloc(context->metric.label_count - 1, sizeof(*labels_without_le));
    if (!values_without_le) {
        ret = report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "failed to allocate values_without_le");
        goto end;
    }


    label_i = 0;
    sample = cfl_list_entry_first(&context->metric.samples, struct cmt_decode_prometheus_context_sample, _head);
    for (i = 0; i < context->metric.label_count; i++) {
        if (!strcmp(context->metric.labels[i], "le")) {
            le_label_index = i;
        } else {
            labels_without_le[label_i] = context->metric.labels[i];
            values_without_le[label_i] = sample->label_values[i];
            label_i++;
        }
    }

    bucket_index = 0;
    cfl_list_foreach_safe(head, tmp, &context->metric.samples) {
        sample = cfl_list_entry(head, struct cmt_decode_prometheus_context_sample, _head);
        switch (sample->type) {
            case CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_BUCKET:
                if (bucket_index == bucket_count) {
                    /* probably last bucket, which has "Inf" */
                    break;
                }
                if (parse_double(sample->label_values[le_label_index],
                            buckets + bucket_index)) {
                    ret = report_error(context,
                            CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                            "failed to parse bucket");
                    goto end;
                }
                if (parse_uint64(sample->value1,
                            bucket_defaults + bucket_index)) {
                    /* Count is supposed to be integer, but apparently
                     * some tools can generate count in a floating format.
                     * Try to parse as a double and then cast to uint64_t */
                    if (parse_double(sample->value1, &count_dbl) || count_dbl < 0) {
                        ret = report_error(context,
                                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                                "failed to parse count");
                        goto end;
                    } else {
                        *(bucket_defaults + bucket_index) = (uint64_t)count_dbl;
                    }
                }
                bucket_index++;

                if (!timestamp) {
                    ret = parse_timestamp(context, sample->value2, &timestamp);

                    if (ret) {
                        goto end;
                    }
                }

                break;
            case CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_SUM:
                if (parse_double(sample->value1, &sum)) {
                    ret = report_error(context,
                            CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                            "failed to parse sum");
                    goto end;
                }

                if (!timestamp) {
                    ret = parse_timestamp(context, sample->value2, &timestamp);

                    if (ret) {
                        goto end;
                    }
                }

                break;
            case CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_COUNT:
                if (parse_uint64(sample->value1, &count)) {
                    /* Count is supposed to be integer, but apparently
                     * some tools can generate count in a floating format.
                     * Try to parse as a double and then cast to uint64_t */
                    if (parse_double(sample->value1, &count_dbl) || count_dbl < 0) {
                        ret = report_error(context,
                                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                                "failed to parse count");
                        goto end;
                    } else {
                        count = (uint64_t)count_dbl;
                    }
                }
                bucket_defaults[bucket_index] = count;

                if (!timestamp) {
                    ret = parse_timestamp(context, sample->value2, &timestamp);

                    if (ret) {
                        goto end;
                    }
                }

                break;
        }
    }

    if (!timestamp) {
        /* No timestamp was specified, use default value */
        timestamp = context->opts.default_timestamp;
    }

    h = context->current.histogram;
    if (!h || label_i != h->map->label_count) {
        cmt_buckets = cmt_histogram_buckets_create_size(buckets, bucket_count);
        if (!cmt_buckets) {
            ret = report_error(context,
                               CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                               "cmt_histogram_buckets_create_size failed");
            goto end;
        }

        h = cmt_histogram_create(context->cmt,
                                 context->metric.ns,
                                 context->metric.subsystem,
                                 context->metric.name,
                                 get_docstring(context),
                                 cmt_buckets,
                                 label_i,
                                 label_i ? labels_without_le : NULL);

        if (!h) {
            ret = report_error(context,
                    CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                    "cmt_histogram_create failed");
            goto end;
        }

        context->current.histogram = h;
    }


    if (cmt_histogram_set_default(h, timestamp, bucket_defaults, sum, count,
                label_i,
                label_i ? values_without_le : NULL)) {
        ret = report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "cmt_histogram_set_default failed");
    }


end:
    if (buckets) {
        free(buckets);
    }
    if (bucket_defaults) {
        free(bucket_defaults);
    }
    if (labels_without_le) {
        free(labels_without_le);
    }
    if (values_without_le) {
        free(values_without_le);
    }

    return ret;
}

static int add_metric_summary(struct cmt_decode_prometheus_context *context)
{
    int ret = 0;
    int i;
    size_t quantile_count;
    size_t quantile_index;
    double *quantiles = NULL;
    double *quantile_defaults = NULL;
    double sum = 0.0;
    double count_dbl;
    size_t label_count;
    uint64_t count = 0;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cmt_decode_prometheus_context_sample *sample;
    size_t quantile_label_index = 0;
    struct cmt_summary *s;
    cfl_sds_t *labels_without_quantile = NULL;
    cfl_sds_t *values_without_quantile = NULL;
    int label_i;
    uint64_t timestamp = 0;

    if (cfl_list_size(&context->metric.samples) < 2) {
        return report_error(context,
                CMT_DECODE_PROMETHEUS_SYNTAX_ERROR,
                "not enough samples for summary");
    }

    /* quantile_count = sample count - 2:
     * - sum
     * - count */
    quantile_count = cfl_list_size(&context->metric.samples) - 2;
    if (context->opts.override_timestamp) {
        timestamp = context->opts.override_timestamp;
    }

    quantile_defaults = calloc(quantile_count, sizeof(*quantile_defaults));
    if (!quantile_defaults) {
        ret = report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "failed to allocate quantile defaults");
        goto end;
    }
    quantiles = calloc(quantile_count, sizeof(*quantiles));
    if (!quantiles) {
        ret = report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "failed to allocate quantiles");
        goto end;
    }

    label_count = 0;
    for (i = 0; i < context->metric.label_count; i++) {
        if (strcmp(context->metric.labels[i], "quantile")) {
            /* quantile is not a label */
            label_count++;
        }
    }

    labels_without_quantile = calloc(label_count, sizeof(*labels_without_quantile));
    if (!labels_without_quantile) {
        ret = report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "failed to allocate labels_without_quantile");
        goto end;
    }
    values_without_quantile = calloc(label_count, sizeof(*labels_without_quantile));
    if (!values_without_quantile) {
        ret = report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "failed to allocate values_without_quantile");
        goto end;
    }

    label_i = 0;
    sample = cfl_list_entry_first(&context->metric.samples,
            struct cmt_decode_prometheus_context_sample, _head);
    for (i = 0; i < context->metric.label_count; i++) {
        if (!strcmp(context->metric.labels[i], "quantile")) {
            quantile_label_index = i;
            break;
        } else {
            labels_without_quantile[label_i] = context->metric.labels[i];
            values_without_quantile[label_i] = sample->label_values[i];
            label_i++;
        }
    }

    quantile_index = 0;
    cfl_list_foreach_safe(head, tmp, &context->metric.samples) {
        sample = cfl_list_entry(head, struct cmt_decode_prometheus_context_sample, _head);
        switch (sample->type) {
            case CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_NORMAL:
                if (parse_double(sample->label_values[quantile_label_index],
                            quantiles + quantile_index)) {
                    ret = report_error(context,
                            CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                            "failed to parse bucket");
                    goto end;
                }
                if (parse_double(sample->value1,
                            quantile_defaults + quantile_index)) {
                    ret = report_error(context,
                            CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                            "failed to parse quantile value");
                    goto end;
                }
                quantile_index++;

                if (!timestamp) {
                    ret = parse_timestamp(context, sample->value2, &timestamp);

                    if (ret) {
                        goto end;
                    }
                }

                break;
            case CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_SUM:
                if (parse_double(sample->value1, &sum)) {
                    ret = report_error(context,
                            CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                            "failed to parse summary sum");
                    goto end;
                }

                if (!timestamp) {
                    ret = parse_timestamp(context, sample->value2, &timestamp);

                    if (ret) {
                        goto end;
                    }
                }

                break;

            case CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_COUNT:
                if (parse_uint64(sample->value1, &count)) {
                    /* Count is supposed to be integer, but apparently
                     * some tools can generate count in a floating format.
                     * Try to parse as a double and then cast to uint64_t */
                    if (parse_double(sample->value1, &count_dbl) || count_dbl < 0) {
                        ret = report_error(context,
                                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                                "failed to parse count");
                        goto end;
                    } else {
                        count = (uint64_t)count_dbl;
                    }
                }

                if (!timestamp) {
                    ret = parse_timestamp(context, sample->value2, &timestamp);

                    if (ret) {
                        goto end;
                    }
                }

                break;
        }
    }

    if (!timestamp) {
        /* No timestamp was specified, use default value */
        timestamp = context->opts.default_timestamp;
    }

    s = context->current.summary;
    if (!s || label_i != s->map->label_count) {
        s = cmt_summary_create(context->cmt,
                               context->metric.ns,
                               context->metric.subsystem,
                               context->metric.name,
                               get_docstring(context),
                               quantile_count,
                               quantiles,
                               label_i,
                               label_i ? labels_without_quantile : NULL);

        if (!s) {
            ret = report_error(context,
                    CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                    "cmt_summary_create failed");
            goto end;
        }

        context->current.summary = s;
    }

    if (cmt_summary_set_default(s, timestamp, quantile_defaults, sum, count,
                label_i,
                label_i ? values_without_quantile : NULL)) {
        ret = report_error(context,
                CMT_DECODE_PROMETHEUS_CMT_CREATE_ERROR,
                "cmt_summary_set_default failed");
    }


end:
    if (quantile_defaults) {
        free(quantile_defaults);
    }
    if (quantiles) {
        free(quantiles);
    }
    if (labels_without_quantile) {
        free(labels_without_quantile);
    }
    if (values_without_quantile) {
        free(values_without_quantile);
    }

    return ret;
}

static int finish_metric(struct cmt_decode_prometheus_context *context,
                         bool reset_summary,
                         cfl_sds_t current_metric_name)
{
    int rv = 0;

    if (cfl_list_is_empty(&context->metric.samples)) {
        goto end;
    }

    switch (context->metric.type) {
        case COUNTER:
            rv = add_metric_counter(context);
            break;
        case GAUGE:
            rv = add_metric_gauge(context);
            break;
        case HISTOGRAM:
            rv = add_metric_histogram(context);
            break;
        case SUMMARY:
            rv = add_metric_summary(context);
            break;
        default:
            rv = add_metric_untyped(context);
            break;
    }

end:
    reset_context(context, reset_summary);

    if (current_metric_name) {
        context->metric.name_orig = current_metric_name;
        rv = split_metric_name(context,
                               current_metric_name,
                               &(context->metric.ns),
                               &(context->metric.subsystem),
                               &(context->metric.name));
    }
    return rv;
}

/* special case for summary */
static int finish_duplicate_histogram_summary_sum_count(
        struct cmt_decode_prometheus_context *context,
        cfl_sds_t metric_name,
        int type)
{
    int rv;
    int current_metric_type;
    cfl_sds_t current_metric_docstring;

    if (type == CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_COUNT) {
        cfl_sds_set_len(metric_name, cfl_sds_len(metric_name) - 6);
    } else if (type == CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_SUM) {
        cfl_sds_set_len(metric_name, cfl_sds_len(metric_name) - 4);
    } else if (type == CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_BUCKET) {
        cfl_sds_set_len(metric_name, cfl_sds_len(metric_name) - 7);
    }
    metric_name[cfl_sds_len(metric_name)] = 0;

    current_metric_type = context->metric.type;
    current_metric_docstring = cfl_sds_create(context->metric.docstring);

    rv = finish_metric(context, false, metric_name);
    if (rv) {
        cfl_sds_destroy(current_metric_docstring);
        return rv;
    }

    context->metric.type = current_metric_type;
    context->metric.docstring = current_metric_docstring;
    context->metric.current_sample_type = type;

    return 0;
}

static int parse_histogram_summary_name(
        struct cmt_decode_prometheus_context *context,
        cfl_sds_t metric_name)
{
    bool sum_found;
    bool count_found;
    bool has_buckets;
    bool is_previous_sum_or_count;
    bool name_matched = false;
    struct cfl_list *head;
    struct cfl_list *tmp;
    size_t current_name_len;
    size_t parsed_name_len;
    struct cmt_decode_prometheus_context_sample *sample;

    current_name_len = strlen(metric_name);
    parsed_name_len = strlen(context->metric.name_orig);
    if (current_name_len < parsed_name_len) {
        /* current name length cannot be less than the length already parsed. That means
         * another metric has started */
        return finish_metric(context, true, metric_name);
    }

    if (strncmp(context->metric.name_orig, metric_name, parsed_name_len)) {
        /* the name prefix must be the same or we are starting a new metric */
        return finish_metric(context, true, metric_name);
    }
    else if (parsed_name_len == current_name_len) {
        name_matched = true;
    }

    sum_found = false;
    count_found = false;
    has_buckets = false;

    cfl_list_foreach_safe(head, tmp, &context->metric.samples) {
        sample = cfl_list_entry(head, struct cmt_decode_prometheus_context_sample, _head);

        switch (sample->type) {
            case CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_SUM:
                sum_found = true;
                break;
            case CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_COUNT:
                count_found = true;
                break;
            default:
                has_buckets = true;
                break;
        }
    }

    sample = cfl_list_entry_last(&context->metric.samples,
            struct cmt_decode_prometheus_context_sample, _head);
    is_previous_sum_or_count = sample->type == CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_SUM ||
        sample->type == CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_COUNT;

    if (name_matched) {
        if (sum_found && count_found) {
            /* finish instance of the summary/histogram */
            return finish_duplicate_histogram_summary_sum_count(context, metric_name, -1);
        }
        else {
            /* parsing HELP after TYPE */
            cfl_sds_destroy(metric_name);
            return 0;
        }
    }

    /* invalid histogram/summary suffix, treat it as a different metric */
    if (!strcmp(metric_name + parsed_name_len, "_bucket")) {
        if (sum_found && count_found && has_buckets && is_previous_sum_or_count) {
            /* already found both sum and count, so this is a new metric */
            return finish_duplicate_histogram_summary_sum_count(
                    context,
                    metric_name,
                    CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_BUCKET);
        }
        context->metric.current_sample_type = CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_BUCKET;
    }
    else if (!strcmp(metric_name + parsed_name_len, "_sum")) {
        if (sum_found) {
            /* already found a `_sum` for this metric, so this must necessarily be a new
             * one */
            return finish_duplicate_histogram_summary_sum_count(
                    context,
                    metric_name,
                    CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_SUM);
        }
        context->metric.current_sample_type = CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_SUM;
        sum_found = true;
    }
    else if (!strcmp(metric_name + parsed_name_len, "_count")) {
        if (count_found) {
            /* already found a `_count` for this metric, so this must necessarily be a new
             * one */
            return finish_duplicate_histogram_summary_sum_count(
                    context,
                    metric_name,
                    CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_COUNT);
        }
        context->metric.current_sample_type = CMT_DECODE_PROMETHEUS_CONTEXT_SAMPLE_TYPE_COUNT;
        count_found = true;
    }
    else {
        /* invalid histogram/summary suffix, treat it as a different metric */
        return finish_metric(context, true, metric_name);
    }

    /* still in the same metric */
    cfl_sds_destroy(metric_name);
    return 0;
}

static int parse_metric_name(
        struct cmt_decode_prometheus_context *context,
        cfl_sds_t metric_name)
{
    int ret = 0;

    if (context->metric.name_orig) {
        if (context->metric.type == HISTOGRAM || context->metric.type == SUMMARY) {
            ret = parse_histogram_summary_name(context, metric_name);
            if (!ret) {
                /* bucket/sum/count parsed */
                return ret;
            }
        }
        else if (strcmp(context->metric.name_orig, metric_name)) {
            /* new metric name means the current metric is finished */
            return finish_metric(context, true, metric_name);
        }
        else {
            /* same metric with name already allocated, destroy and return */
            cfl_sds_destroy(metric_name);
            return ret;
        }
    }

    if (!ret) {
        context->metric.name_orig = metric_name;
        ret = split_metric_name(context, metric_name,
                &(context->metric.ns),
                &(context->metric.subsystem),
                &(context->metric.name));
    }
    else {
        cfl_sds_destroy(metric_name);
    }

    return ret;
}

static int parse_label(
        struct cmt_decode_prometheus_context *context,
        cfl_sds_t name, cfl_sds_t value)
{
    int i;
    struct cmt_decode_prometheus_context_sample *sample;

    if (context->metric.label_count >= CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT) {
        cfl_sds_destroy(name);
        cfl_sds_destroy(value);
        return report_error(context,
                CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT_EXCEEDED,
                "maximum number of labels exceeded");
    }

    /* check if the label is already registered */
    for (i = 0; i < context->metric.label_count; i++) {
        if (!strcmp(name, context->metric.labels[i])) {
            /* found, free the name memory and use the existing one */
            cfl_sds_destroy(name);
            name = context->metric.labels[i];
            break;
        }
    }
    if (i == context->metric.label_count) {
        /* didn't found the label, add it now */
        context->metric.labels[i] = name;
        context->metric.label_count++;
    }

    sample = cfl_list_entry_last(&context->metric.samples,
            struct cmt_decode_prometheus_context_sample, _head);
    sample->label_values[i] = value;
    return 0;
}

static int sample_start(struct cmt_decode_prometheus_context *context)
{
    struct cmt_decode_prometheus_context_sample *sample;

    sample = malloc(sizeof(*sample));
    if (!sample) {
        return report_error(context,
                CMT_DECODE_PROMETHEUS_ALLOCATION_ERROR,
                "memory allocation failed");
    }

    memset(sample, 0, sizeof(*sample));
    sample->type = context->metric.current_sample_type;
    cfl_list_add(&sample->_head, &context->metric.samples);
    return 0;
}

static int parse_sample(struct cmt_decode_prometheus_context *context,
                        const char *value1,
                        const char *value2)
{
    int len;
    struct cmt_decode_prometheus_context_sample *sample;
    sample = cfl_list_entry_last(&context->metric.samples,
            struct cmt_decode_prometheus_context_sample, _head);

    /* value1 */
    len = strlen(value1);
    if (len >= sizeof(sample->value1) - 1) {
        return report_error(context,
                CMT_DECODE_PROMETHEUS_SAMPLE_VALUE_TOO_LONG,
                "sample value is too long (max %zu characters)", sizeof(sample->value1) - 1);
    }

    memcpy(sample->value1, value1, len);
    sample->value1[len] = 0;

    /* value2 */
    len = strlen(value2);
    if (len >= sizeof(sample->value2) - 1) {
        return report_error(context,
                CMT_DECODE_PROMETHEUS_SAMPLE_VALUE_TOO_LONG,
                "sample value is too long (max %zu characters)", sizeof(sample->value2) - 1);
    }
    memcpy(sample->value2, value2, len);
    sample->value2[len] = 0;

    return 0;
}

/* called automatically by the generated parser code on error */
static int cmt_decode_prometheus_error(void *yyscanner,
                                       struct cmt_decode_prometheus_context *context,
                                       const char *msg)
{
    report_error(context, CMT_DECODE_PROMETHEUS_SYNTAX_ERROR, msg);
    return 0;
}
