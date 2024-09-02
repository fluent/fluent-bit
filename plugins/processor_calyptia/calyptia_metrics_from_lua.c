/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_untyped.h>
#include <fluent-bit/flb_processor_plugin.h>

#include "calyptia_metrics_from_lua.h"
#include "lua_to_cfl.h"

struct metrics_header {
    char fqname_buf[0xfff];
    char *ns;
    char *subsystem;
    char *name;
};

static void free_labels(char **labels, size_t label_count)
{
    int i;
    if (!labels) {
        return;
    }
    for (i = 0; i < label_count; i++) {
        if (labels[i]) {
            free(labels[i]);
        }
    }
    free(labels);
}

static void split_fqname(const char *fqname, struct metrics_header *header)
{
    strcpy(header->fqname_buf, fqname);
    header->ns = header->fqname_buf;
    header->subsystem = strchr(header->fqname_buf, '_');
    if (!header->subsystem) {
        header->name = header->fqname_buf;
        header->ns = "";
    }
    else {
        *header->subsystem = 0; /* split */
        header->subsystem++;
        header->name = strchr(header->subsystem, '_');
        if (!header->name) {
            header->name = header->subsystem;
            header->subsystem = "";
        }
        else {
            *header->name = 0; /* split */
            header->name++;
        }
    }
}

static int assign_label(char **keys, size_t key_count, char **values,
                        const char *key, const char *value)
{
    size_t i;
    for (i = 0; i < key_count; i++) {
        if (!strcmp(keys[i], key)) {
            values[i] = strdup(value);
            if (!values[i]) {
                return -1;
            }
            return 0;
        }
    }
    return -1;
}

static char **lua_to_labels(struct flb_processor_instance *ins, lua_State *L,
                            char **label_keys, size_t label_count)
{
    if (lua_type(L, -1) != LUA_TTABLE) {
        return NULL;
    }

    char **labels = calloc(label_count, sizeof(char *));
    if (!labels) {
        flb_plg_error(ins, "could not allocate memory for labels");
        return NULL;
    }

    lua_pushnil(L); // first key
    while (lua_next(L, -2) != 0) {
        if (assign_label(label_keys, label_count, labels, lua_tostring(L, -2),
                         lua_tostring(L, -1))) {
            flb_plg_error(ins, "could not assign label %s:%s",
                          lua_tostring(L, -2), lua_tostring(L, -1));
            lua_pop(L, 2); /* remove key/value */
            goto err;
        }
        /* removes 'value'; keeps 'key' for next iteration */
        lua_pop(L, 1);
    }

    return labels;

err:
    free_labels(labels, label_count);
    return NULL;
}

static int double_cmp(const void *a, const void *b)
{
    double x = *(double *) a;
    double y = *(double *) b;

    if (x < y) {
        return -1;
    }
    else if (x > y) {
        return 1;
    }
    else {
        return 0;
    }
}

static double *lua_to_quantile_values(struct flb_processor_instance *ins,
                                      lua_State *L, double *quantile_keys,
                                      int count)
{
    int i;
    double *quantile_values = calloc(count, sizeof(*quantile_values));
    if (!quantile_values) {
        flb_plg_error(ins, "could not allocate memory for quantile values");
        return NULL;
    }

    for (i = 0; i < count; i++) {
        lua_pushnumber(L, quantile_keys[i]);
        lua_gettable(L, -2);
        quantile_values[i] = lua_to_double(L, -1);
        lua_pop(L, 1);
    }

    return quantile_values;
}

static uint64_t *lua_to_bucket_values(struct flb_processor_instance *ins,
                                      lua_State *L, double *bucket_keys,
                                      int count)
{
    int i;
    uint64_t *values = calloc(count, sizeof(*values));
    if (!values) {
        flb_plg_error(ins, "could not allocate memory for bucket values");
        return NULL;
    }

    for (i = 0; i < count; i++) {
        lua_pushnumber(L, bucket_keys[i]);
        lua_gettable(L, -2);
        values[i] = lua_to_uint(L);
        lua_pop(L, 1);
    }

    return values;
}

static double *lua_to_quantiles_buckets(struct flb_processor_instance *ins,
                                        lua_State *L, int *count)
{
    int i;
    double *keys;
    *count = 0;
    if (lua_type(L, -1) != LUA_TTABLE) {
        return NULL;
    }

    // assumes a quantiles or buckets table is at the top of the stack
    lua_pushnil(L); // first key
    while (lua_next(L, -2) != 0) {
        lua_pop(L, 1);
        *count += 1;
    }

    keys = calloc(*count, sizeof(*keys));
    if (!keys) {
        flb_plg_error(ins, "could not allocate memory for quantiles/buckets");
        return NULL;
    }

    lua_pushnil(L); // first key
    i = 0;
    while (lua_next(L, -2) != 0) {
        keys[i] = lua_to_double(L, -2);
        i++;
        // removes 'value'; keeps 'key' for next iteration
        lua_pop(L, 1);
    }

    qsort(keys, *count, sizeof(*keys), double_cmp);

    return keys;
}

static double *lua_to_quantile_bucket_keys(struct flb_processor_instance *ins,
                                           lua_State *L, const char *kind,
                                           int *count)
{
    int i;
    int sample_count;
    double *keys;

    *count = 0;
    if (lua_type(L, -2) != LUA_TTABLE) {
        flb_plg_error(ins, "expected metric to be a table");
        return NULL;
    }

    lua_getfield(L, -2, "metrics");
    sample_count = lua_objlen(L, -1);
    int found = 0;

    /* find the first sample that has quantiles */
    for (i = 1; i <= sample_count; i++) {
        lua_rawgeti(L, -1, i);
        lua_getfield(L, -1, kind);
        if (lua_type(L, -1) == LUA_TTABLE) {
            found = 1;
            break;
        }
        lua_pop(L, 2); /* pop "quantiles" table and the sample */
    }

    if (!found) {
        lua_pop(L, 1); /* pop "metrics" */
        return NULL;
    }

    keys = lua_to_quantiles_buckets(ins, L, count);

    lua_pop(L,
            3); /* pop "quantiles"/"buckets" table, metric and metrics array */

    return keys;
}

static char **append_label(char **labels, size_t *labels_size,
                           size_t *label_index, const char *label)
{
    size_t i;
    for (i = 0; i < *label_index; i++) {
        if (!strcmp(labels[i], label)) {
            /* don't do anything if the label is already in the array */
            return labels;
        }
    }

    if (*label_index == *labels_size) {
        if (!*labels_size) {
            *labels_size = 8;
        }
        else {
            *labels_size *= 2;
        }
        labels = realloc(labels, *labels_size * sizeof(char *));
        if (!labels) {
            return NULL;
        }
    }

    labels[*label_index] = strdup(label);
    if (!labels[*label_index]) {
        return NULL;
    }

    *label_index += 1;
    return labels;
}

static char **lua_to_label_keys(struct flb_processor_instance *ins,
                                lua_State *L, int *label_count)
{
    int i;
    int sample_count;
    char **label_keys;
    size_t label_index;
    size_t labels_size;

    *label_count = 0;
    if (lua_type(L, -1) != LUA_TTABLE) {
        flb_plg_error(ins, "expected metric to be a table");
        return NULL;
    }

    lua_getfield(L, -1, "metrics");
    sample_count = lua_objlen(L, -1);
    if (lua_type(L, -1) != LUA_TTABLE || !sample_count) {
        flb_plg_error(ins, "samples should be in a \"metrics\" array with at "
                           "least one element");
        return NULL;
    }

    label_keys = NULL;
    labels_size = 0;
    label_index = 0;

    for (i = 1; i <= sample_count; i++) {
        lua_rawgeti(L, -1, i);
        if (lua_type(L, -1) != LUA_TTABLE) {
            free_labels(label_keys, label_index);
            flb_plg_error(ins, "expected sample to be a table");
            return NULL;
        }

        lua_getfield(L, -1, "labels");
        if (lua_type(L, -1) == LUA_TTABLE) {
            lua_pushnil(L); /* first key */
            while (lua_next(L, -2) != 0) {
                label_keys = append_label(label_keys, &labels_size,
                                          &label_index, lua_tostring(L, -2));
                lua_pop(L, 1); /* pop value, keep key for next iteration */
            }
        }

        lua_pop(L, 2); /* pop "labels" table and the sample */
    }
    lua_pop(L, 1); /* pop "metrics" */

    *label_count = label_index;

    if (!label_index) {
        return NULL;
    }

    return label_keys;
}

/* This is a big function because if I had split into multiple utility functions
 * to conver the specific metric types, there would be a lot of repeated code
 * for the common parts. Another option would be to use big macros to reduce
 * repetition, but this is the more maintainable/debuggable option */
int calyptia_metrics_from_lua(struct flb_processor_instance *ins, lua_State *L,
                              struct cmt *cmt)
{
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_summary *summary;
    struct cmt_histogram_buckets *cmt_buckets;
    struct cmt_histogram *histogram;
    struct cmt_untyped *untyped;
    struct metrics_header header;
    double *quantiles;
    double *quantile_values;
    double *buckets;
    uint64_t *bucket_values;
    double sum;
    double value;
    uint64_t count;
    int quantile_count;
    int bucket_count;
    int type;
    int sample_count;
    int metric_count;
    const char *help;
    char **label_keys;
    char **label_vals;
    int label_count;
    uint64_t timestamp;
    int i;
    int j;

    if (lua_type(L, -1) != LUA_TTABLE) {
        flb_plg_error(ins, "expected metrics array");
        return -1;
    }

    metric_count = lua_objlen(L, -1);

    for (i = 1; i <= metric_count; i++) {
        lua_rawgeti(L, -1, i);

        label_keys = lua_to_label_keys(ins, L, &label_count);
        timestamp = 0;

        lua_getfield(L, -1, "type");
        if (lua_type(L, -1) != LUA_TSTRING) {
            flb_plg_error(ins, "metric type must be a string");
            return -1;
        }

        const char *metric_type = lua_tostring(L, -1);

        if (!strcasecmp(metric_type, "COUNTER")) {
            type = CMT_COUNTER;
        }
        else if (!strcasecmp(metric_type, "GAUGE")) {
            type = CMT_GAUGE;
        }
        else if (!strcasecmp(metric_type, "SUMMARY")) {
            type = CMT_SUMMARY;
        }
        else if (!strcasecmp(metric_type, "HISTOGRAM")) {
            type = CMT_HISTOGRAM;
        }
        else if (!strcasecmp(metric_type, "UNTYPED")) {
            type = CMT_UNTYPED;
        }
        else {
            cmt_destroy(cmt);
            flb_plg_error(ins, "invalid metric type: \"%s\"", metric_type);
            return -1;
        }

        lua_pop(L, 1); /* pop "type" */

        lua_getfield(L, -1, "name");
        if (lua_type(L, -1) != LUA_TSTRING) {
            flb_plg_error(ins, "metric name must be a string");
            return -1;
        }

        const char *fqname = lua_tostring(L, -1);
        split_fqname(fqname, &header);
        lua_pop(L, 1); /* pop "name" */

        lua_getfield(L, -1, "help");
        if (lua_type(L, -1) != LUA_TSTRING) {
            flb_plg_error(ins, "metric help must be a string");
            return -1;
        }
        help = lua_tostring(L, -1);

        switch (type) {
        case CMT_COUNTER:
            counter = cmt_counter_create(cmt, header.ns, header.subsystem,
                                         header.name, (char *) help,
                                         label_count, label_keys);
            break;
        case CMT_GAUGE:
            gauge = cmt_gauge_create(cmt, header.ns, header.subsystem,
                                     header.name, (char *) help, label_count,
                                     label_keys);
            break;
        case CMT_SUMMARY:
            quantiles = lua_to_quantile_bucket_keys(ins, L, "quantiles",
                                                    &quantile_count);
            summary = cmt_summary_create(
                cmt, header.ns, header.subsystem, header.name, (char *) help,
                quantile_count, quantiles, label_count, label_keys);
            break;
        case CMT_HISTOGRAM:
            buckets
                = lua_to_quantile_bucket_keys(ins, L, "buckets", &bucket_count);
            cmt_buckets
                = cmt_histogram_buckets_create_size(buckets, bucket_count - 1);
            histogram = cmt_histogram_create(
                cmt, header.ns, header.subsystem, header.name, (char *) help,
                cmt_buckets, label_count, label_keys);
            break;
        case CMT_UNTYPED:
            untyped = cmt_untyped_create(cmt, header.ns, header.subsystem,
                                         header.name, (char *) help,
                                         label_count, label_keys);
            break;
        }

        /* pop "help" only after creating the metric instance, as it was already
         * copied */
        lua_pop(L, 1);

        /* load samples */
        lua_getfield(L, -1, "metrics");
        sample_count = lua_objlen(L, -1);
        if (sample_count == 0) {
            flb_plg_error(ins, "no samples found for metric \"%s\"", fqname);
            return -1;
        }

        for (j = 1; j <= sample_count; j++) {
            label_vals = NULL;

            /* get sample */
            lua_rawgeti(L, -1, j);
            if (lua_type(L, -1) != LUA_TTABLE) {
                flb_plg_error(ins, "expected sample to be a table");
                return -1;
            }

            lua_getfield(L, -1, "labels");
            label_vals = lua_to_labels(ins, L, label_keys, label_count);
            lua_pop(L, 1); /* pop labels */

            lua_getfield(L, -1, "timestamp");
            timestamp = lua_to_uint(L);
            lua_pop(L, 1); /* pop timestamp */

            if (type == CMT_SUMMARY || type == CMT_HISTOGRAM) {
                lua_getfield(L, -1, "sum");
                sum = lua_to_double(L, -1);
                lua_pop(L, 1); /* pop sum */

                lua_getfield(L, -1, "count");
                count = lua_to_uint(L);
                lua_pop(L, 1); /* pop count */
            }

            if (type == CMT_SUMMARY) {

                lua_getfield(L, -1, "quantiles");
                quantile_values
                    = lua_to_quantile_values(ins, L, quantiles, quantile_count);
                lua_pop(L, 1); /* pop quantiles */

                if (cmt_summary_set_default(
                        summary, timestamp, quantile_values, sum, count,
                        label_vals ? label_count : 0, label_vals)) {
                    return -1;
                }

            }
            else if (type == CMT_HISTOGRAM) {

                lua_getfield(L, -1, "buckets");
                bucket_values
                    = lua_to_bucket_values(ins, L, buckets, bucket_count);
                lua_pop(L, 1); /* pop buckets */

                if (cmt_histogram_set_default(
                        histogram, timestamp, bucket_values, sum, count,
                        label_vals ? label_count : 0, label_vals)) {
                    return -1;
                }

            }
            else {

                lua_getfield(L, -1, "value");
                value = lua_to_double(L, -1);
                lua_pop(L, 1); /* pop value */

                if (type == CMT_COUNTER) {
                    if (cmt_counter_set(counter, timestamp, value,
                                        label_vals ? label_count : 0,
                                        label_vals)) {
                        return -1;
                    }
                }
                else if (type == CMT_GAUGE) {
                    if (cmt_gauge_set(gauge, timestamp, value,
                                      label_vals ? label_count : 0,
                                      label_vals)) {
                        return -1;
                    }
                }
                else {
                    if (cmt_untyped_set(untyped, timestamp, value,
                                        label_vals ? label_count : 0,
                                        label_vals)) {
                        return -1;
                    }
                }
            }

            if (label_vals) {
                free_labels(label_vals, label_count);
            }

            if (type == CMT_SUMMARY) {
                free(quantile_values);
            }
            else if (type == CMT_HISTOGRAM) {
                free(bucket_values);
            }

            lua_pop(L, 1); /* pop sample */
        }

        free_labels(label_keys, label_count);

        if (type == CMT_SUMMARY) {
            free(quantiles);
        }
        else if (type == CMT_HISTOGRAM) {
            free(buckets);
        }

        lua_pop(L, 2); /* pop samples and metric */
    }

    return 0;
}
