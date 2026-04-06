/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2024 The CMetrics Authors
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
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_filter.h>

static int compare_label_keys(struct cmt_map *src, const char *label_key,
                              void *compare_ctx, int (*compare)(void *compare_ctx, const char *str, size_t slen),
                              int flags)
{
    struct cfl_list *head;
    struct cmt_map_label *label;
    size_t label_key_size = 0;

    if (flags & CMT_FILTER_PREFIX) {
        if (label_key == NULL) {
            return CMT_FALSE;
        }

        label_key_size = strlen(label_key);
    }

    cfl_list_foreach(head, &src->label_keys) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        /* compare label_keys for prefix */
        if (flags & CMT_FILTER_PREFIX) {
            if (strncmp(label->name, label_key, label_key_size) == 0) {
                return (flags & CMT_FILTER_EXCLUDE) ? CMT_FALSE : CMT_TRUE;
            }

            return (flags & CMT_FILTER_EXCLUDE) ? CMT_TRUE : CMT_FALSE;
        }

        /* compare label_keys for substring */
        if (flags & CMT_FILTER_SUBSTRING) {
            if (strstr(label->name, label_key) != NULL) {
                return (flags & CMT_FILTER_EXCLUDE) ? CMT_FALSE : CMT_TRUE;
            }

            return (flags & CMT_FILTER_EXCLUDE) ? CMT_TRUE : CMT_FALSE;
        }

        /* Compare with an external context (e.g. Onigmo).
         * flb_regex_match should take three arguments that are
         * flb_regex context, string and its string length.
         * The length of string is changed by the callback and not determined by label_key.
         */
        if (compare_ctx != NULL && compare != NULL) {
            return compare(compare_ctx, label->name, strlen(label->name));
        }
    }

    return CMT_FALSE;
}

static int filter_context_label_key(struct cmt *dst, struct cmt *src,
                                    const char *label_key,
                                    void *compare_ctx, int (*compare)(void *compare_ctx, const char *str, size_t slen),
                                    int flags)
{
    int ret;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary *summary;

     /* Counters */
    cfl_list_foreach(head, &src->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);

        if (compare_label_keys(counter->map, label_key, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_counter(dst, counter, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Gauges */
    cfl_list_foreach(head, &src->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);

        if (compare_label_keys(gauge->map, label_key, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_gauge(dst, gauge, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Untyped */
    cfl_list_foreach(head, &src->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);

        if (compare_label_keys(untyped->map, label_key, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_untyped(dst, untyped, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Histogram */
    cfl_list_foreach(head, &src->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);

        if (compare_label_keys(histogram->map, label_key, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_histogram(dst, histogram, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Exponential Histogram */
    cfl_list_foreach(head, &src->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);

        if (compare_label_keys(exp_histogram->map, label_key, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_exp_histogram(dst, exp_histogram, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Summary */
    cfl_list_foreach(head, &src->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);

        if (compare_label_keys(summary->map, label_key, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_summary(dst, summary, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    return CMT_FILTER_SUCCESS;
}

static int filter_get_label_index(struct cmt_map *src, const char *label_key)
{
    struct cfl_list *head;
    struct cmt_map_label *label;
    size_t index = 0;

    cfl_list_foreach(head, &src->label_keys) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        if (strncmp(label->name, label_key, strlen(label->name)) == 0) {
           return index;
        }

        index++;
    }

    return -1;
}

int metrics_check_label_value_existence(struct cmt_metric *metric,
                                        size_t label_index,
                                        const char *label_value)
{
    struct cfl_list      *iterator;
    size_t                index;
    struct cmt_map_label *label = NULL;

    index = 0;

    cfl_list_foreach(iterator, &metric->labels) {
        label = cfl_list_entry(iterator, struct cmt_map_label, _head);

        if (label_index == index) {
            break;
        }

        index++;
    }

    if (label_index != index) {
        return CMT_FALSE;
    }

    if (label == NULL) {
        return CMT_FALSE;
    }

    if (label->name == NULL) {
        return CMT_FALSE;
    }

    if (strncmp(label->name, label_value, strlen(label->name)) == 0) {
        return CMT_TRUE;
    }

    return CMT_FALSE;
}

static int metrics_map_drop_label_value_pairs(struct cmt_map *map,
                                              size_t label_index,
                                              const char *label_value)
{
    struct cfl_list   *head;
    struct cmt_metric *metric;
    int                result;

    result = CMT_FALSE;

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);

        result = metrics_check_label_value_existence(metric,
                                                     label_index,
                                                     label_value);

        if (result == CMT_TRUE) {
            result = CMT_TRUE;
            break;
        }
    }

    if (result == CMT_TRUE) {
        cmt_map_metric_destroy(metric);
    }

    return result;
}

static int filter_context_label_key_value(struct cmt *dst, struct cmt *src,
                                          const char *label_key, const char *label_value)
{
    int ret;
    char **labels = NULL;
    struct cfl_list *head;
    struct cmt_map *map;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary *summary;
    size_t index = 0;

     /* Counters */
    cfl_list_foreach(head, &src->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);

        ret = cmt_cat_copy_label_keys(counter->map, (char **) &labels);
        if (ret == -1) {
            return -1;
        }

        map = cmt_map_create(CMT_COUNTER, &counter->opts,
                             counter->map->label_count,
                             labels, (void *) counter);
        free(labels);
        if (!map) {
            cmt_log_error(src, "unable to allocate map for counter");
            return -1;
        }

        ret = cmt_cat_copy_map(&counter->opts, map, counter->map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        index = filter_get_label_index(map, label_key);
        if (index != -1) {
            metrics_map_drop_label_value_pairs(map, index, label_value);
        }

        ret = cmt_cat_counter(dst, counter, map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        cmt_map_destroy(map);
    }

    /* Gauges */
    cfl_list_foreach(head, &src->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);

        ret = cmt_cat_copy_label_keys(gauge->map, (char **) &labels);
        if (ret == -1) {
            return -1;
        }

        map = cmt_map_create(CMT_GAUGE, &gauge->opts,
                             gauge->map->label_count,
                             labels, (void *) gauge);
        free(labels);
        if (!map) {
            cmt_log_error(src, "unable to allocate map for gauge");
            return -1;
        }

        ret = cmt_cat_copy_map(&gauge->opts, map, gauge->map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        index = filter_get_label_index(map, label_key);
        if (index != -1) {
            metrics_map_drop_label_value_pairs(map, index, label_value);
        }

        ret = cmt_cat_gauge(dst, gauge, map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        cmt_map_destroy(map);
    }

    /* Untyped */
    cfl_list_foreach(head, &src->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);

        ret = cmt_cat_copy_label_keys(untyped->map, (char **) &labels);
        if (ret == -1) {
            return -1;
        }

        map = cmt_map_create(CMT_UNTYPED, &untyped->opts,
                             untyped->map->label_count,
                             labels, (void *) untyped);
        free(labels);
        if (!map) {
            cmt_log_error(src, "unable to allocate map for untyped");
            return -1;
        }

        ret = cmt_cat_copy_map(&untyped->opts, map, untyped->map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        index = filter_get_label_index(map, label_key);
        if (index != -1) {
            metrics_map_drop_label_value_pairs(map, index, label_value);
        }

        ret = cmt_cat_untyped(dst, untyped, map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        cmt_map_destroy(map);
    }

    /* Histogram */
    cfl_list_foreach(head, &src->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);

        ret = cmt_cat_copy_label_keys(histogram->map, (char **) &labels);
        if (ret == -1) {
            return -1;
        }

        map = cmt_map_create(CMT_HISTOGRAM, &histogram->opts,
                             histogram->map->label_count,
                             labels, (void *) histogram);
        free(labels);
        if (!map) {
            cmt_log_error(src, "unable to allocate map for histogram");
            return -1;
        }

        ret = cmt_cat_copy_map(&histogram->opts, map, histogram->map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        index = filter_get_label_index(map, label_key);
        if (index != -1) {
            metrics_map_drop_label_value_pairs(map, index, label_value);
        }

        ret = cmt_cat_histogram(dst, histogram, map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        cmt_map_destroy(map);
    }

    /* Exponential Histogram */
    cfl_list_foreach(head, &src->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);

        ret = cmt_cat_copy_label_keys(exp_histogram->map, (char **) &labels);
        if (ret == -1) {
            return -1;
        }

        map = cmt_map_create(CMT_EXP_HISTOGRAM, &exp_histogram->opts,
                             exp_histogram->map->label_count,
                             labels, (void *) exp_histogram);
        free(labels);
        if (!map) {
            cmt_log_error(src, "unable to allocate map for exponential histogram");
            return -1;
        }

        ret = cmt_cat_copy_map(&exp_histogram->opts, map, exp_histogram->map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        index = filter_get_label_index(map, label_key);
        if (index != -1) {
            metrics_map_drop_label_value_pairs(map, index, label_value);
        }

        ret = cmt_cat_exp_histogram(dst, exp_histogram, map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        cmt_map_destroy(map);
    }

    /* Summary */
    cfl_list_foreach(head, &src->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);

        ret = cmt_cat_copy_label_keys(summary->map, (char **) &labels);
        if (ret == -1) {
            return -1;
        }

        map = cmt_map_create(CMT_SUMMARY, &summary->opts,
                             summary->map->label_count,
                             labels, (void *) summary);
        free(labels);
        if (!map) {
            cmt_log_error(src, "unable to allocate map for summary");
            return -1;
        }

        ret = cmt_cat_copy_map(&summary->opts, map, summary->map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        index = filter_get_label_index(map, label_key);
        if (index != -1) {
            metrics_map_drop_label_value_pairs(map, index, label_value);
        }

        ret = cmt_cat_summary(dst, summary, map);
        if (ret == -1) {
            cmt_map_destroy(map);
            return -1;
        }

        cmt_map_destroy(map);
    }

    return CMT_FILTER_SUCCESS;
}

static int compare_fqname(struct cmt_opts *src, const char *fqname,
                          void *compare_ctx, int (*compare)(void *compare_ctx, const char *str, size_t slen),
                          int flags)
{
    size_t fqname_size;

    if (flags & CMT_FILTER_PREFIX) {
        if (fqname == NULL) {
            return CMT_FALSE;
        }

        fqname_size = strlen(fqname);
    }
    else if (compare_ctx != NULL && compare != NULL) {
        fqname_size = strlen(src->fqname);
    }

    /* compare fqname for prefix */
    if (flags & CMT_FILTER_PREFIX) {
        if (strncmp(src->fqname, fqname, fqname_size) == 0) {
            return (flags & CMT_FILTER_EXCLUDE) ? CMT_FALSE : CMT_TRUE;
        }

        return (flags & CMT_FILTER_EXCLUDE) ? CMT_TRUE : CMT_FALSE;
    }

    /* compare fqname for substring */
    if (flags & CMT_FILTER_SUBSTRING) {
        if (strstr(src->fqname, fqname) != NULL) {
            return (flags & CMT_FILTER_EXCLUDE) ? CMT_FALSE : CMT_TRUE;
        }

        return (flags & CMT_FILTER_EXCLUDE) ? CMT_TRUE : CMT_FALSE;
    }

    /* Compare with an external context (e.g. Onigmo). */
    if (compare_ctx != NULL && compare != NULL) {
        return compare(compare_ctx, src->fqname, fqname_size);
    }

    return CMT_FALSE;
}

static int filter_context_fqname(struct cmt *dst, struct cmt *src,
                                 const char *fqname,
                                 void *compare_ctx, int (*compare)(void *compare_ctx, const char *str, size_t slen),
                                 int flags)
{
    int ret;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary *summary;

     /* Counters */
    cfl_list_foreach(head, &src->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);

        if (compare_fqname(counter->map->opts, fqname, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_counter(dst, counter, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Gauges */
    cfl_list_foreach(head, &src->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        if (compare_fqname(gauge->map->opts, fqname, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_gauge(dst, gauge, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Untyped */
    cfl_list_foreach(head, &src->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        if (compare_fqname(untyped->map->opts, fqname, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_untyped(dst, untyped, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Histogram */
    cfl_list_foreach(head, &src->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        if (compare_fqname(histogram->map->opts, fqname, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_histogram(dst, histogram, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Exponential Histogram */
    cfl_list_foreach(head, &src->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        if (compare_fqname(exp_histogram->map->opts, fqname, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_exp_histogram(dst, exp_histogram, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    /* Summary */
    cfl_list_foreach(head, &src->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        if (compare_fqname(summary->map->opts, fqname, compare_ctx, compare, flags) == CMT_FALSE) {
            continue;
        }

        ret = cmt_cat_summary(dst, summary, NULL);
        if (ret == -1) {
            return -1;
        }
    }

    return CMT_FILTER_SUCCESS;
}

int cmt_filter_with_label_pair(struct cmt *dst, struct cmt *src,
                               const char *label_key,
                               const char *label_value)
{
    int ret = CMT_FILTER_SUCCESS;

    if (!dst) {
        return CMT_FILTER_INVALID_ARGUMENT;
    }

    if (!src) {
        return CMT_FILTER_INVALID_ARGUMENT;
    }

    if (label_key == NULL) {
        return CMT_FILTER_INVALID_ARGUMENT;
    }

    if (label_value == NULL) {
        return CMT_FILTER_INVALID_ARGUMENT;
    }

    if (label_key != NULL && label_value != NULL) {
        ret = filter_context_label_key_value(dst, src, label_key, label_value);
    }

    if (ret != CMT_FILTER_SUCCESS) {
        return CMT_FILTER_FAILED_OPERATION;
    }

    return ret;
}

int cmt_filter(struct cmt *dst, struct cmt *src,
               const char *fqname, const char *label_key,
               void *compare_ctx, int (*compare)(void *compare_ctx, const char *str, size_t slen),
               int flags)
{
    int ret = CMT_FILTER_SUCCESS;

    if (!dst) {
        return CMT_FILTER_INVALID_ARGUMENT;
    }

    if (!src) {
        return CMT_FILTER_INVALID_ARGUMENT;
    }

    if ((flags & CMT_FILTER_PREFIX) &&
        (flags & CMT_FILTER_SUBSTRING)) {
        return CMT_FILTER_INVALID_FLAGS;
    }

    if (fqname != NULL || (compare_ctx != NULL && compare != NULL)) {
        ret = filter_context_fqname(dst, src, fqname, compare_ctx, compare, flags);
    }

    if (ret != CMT_FILTER_SUCCESS) {
        return CMT_FILTER_FAILED_OPERATION;
    }

    /* On callback mode, labels are not searched by default. */
    if (label_key != NULL ||
        (compare_ctx != NULL && compare != NULL && flags & CMT_FILTER_REGEX_SEARCH_LABELS)) {
        ret = filter_context_label_key(dst, src, label_key, compare_ctx, compare, flags);
    }

    if (ret != CMT_FILTER_SUCCESS) {
        return CMT_FILTER_FAILED_OPERATION;
    }

    return ret;
}
