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

#include <float.h> /* for DBL_EPSILON */
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_decode_statsd.h>
#include <cmetrics/cmt_compat.h>

static struct cmt_map_label *create_map_label(char *caption, size_t length)
{
    struct cmt_map_label *map_label;

    map_label = calloc(1, sizeof(struct cmt_map_label));
    if (!map_label) {
        return NULL;
    }

    if (map_label != NULL) {
        if (caption != NULL) {
            if (length == 0) {
                length = strlen(caption);
            }

            map_label->name = cfl_sds_create_len(caption, length);

            if (map_label->name == NULL) {
                cmt_errno();

                free(map_label);

                map_label = NULL;
            }
        }
    }

    return map_label;
}

static int append_new_map_label_key(struct cmt_map *map, char *name)
{
    struct cmt_map_label *label;

    label = create_map_label(name, 0);

    if (label == NULL) {
        return CMT_DECODE_STATSD_ALLOCATION_ERROR;
    }

    cfl_list_add(&label->_head, &map->label_keys);
    map->label_count++;

    return CMT_DECODE_STATSD_SUCCESS;
}

static int append_new_metric_label_value(struct cmt_metric *metric, char *name, size_t length)
{
    struct cmt_map_label *label;

    label = create_map_label(name, length);

    if (label == NULL) {
        return CMT_DECODE_STATSD_ALLOCATION_ERROR;
    }

    cfl_list_add(&label->_head, &metric->labels);

    return CMT_DECODE_STATSD_SUCCESS;
}

static int is_incremental(char *str)
{
    return (*str == '+' || *str == '-');
}

static int decode_labels(struct cmt *cmt,
                         struct cmt_map *map,
                         struct cmt_metric *metric,
                         char *labels, int incremental)
{
    void                 **value_index_list;
    size_t                 map_label_index;
    size_t                 map_label_count;
    struct cfl_list       *label_iterator;
    struct cmt_map_label  *current_label;
    size_t                 label_index;
    int                    label_found;
    char                  *label_kv, *colon;
    cfl_sds_t              label_k = NULL, label_v = NULL, tmp = NULL;
    int                    result;
    struct cfl_list *head = NULL;
    struct cfl_list *kvs = NULL;
    struct cfl_split_entry *cur = NULL;

    result = CMT_DECODE_STATSD_SUCCESS;

    value_index_list = calloc(128, sizeof(void *));

    if (value_index_list == NULL) {
        return CMT_DECODE_STATSD_ALLOCATION_ERROR;
    }

    label_found = CMT_FALSE;
    label_index = 0;

    if (incremental) {
        label_k = cfl_sds_create("incremental");
        if (label_k != NULL) {
            result = append_new_map_label_key(map, label_k);
            cfl_sds_destroy(label_k);

            if (result == CMT_DECODE_STATSD_SUCCESS) {
                tmp = (void *) cfl_sds_create("true");
                if (tmp != NULL) {
                    value_index_list[label_index] = tmp;
                }
            }
        }
    }

    if (labels != NULL) {
        kvs = cfl_utils_split(labels, ',', -1 );
        if (kvs == NULL) {
            goto split_error;
        }

        cfl_list_foreach(head, kvs) {
        retry:
            cur = cfl_list_entry(head, struct cfl_split_entry, _head);
            label_kv = cur->value;

            colon = strchr(label_kv, ':');
            if (colon == NULL) {
                goto retry;
            }
            label_k = cfl_sds_create_len(label_kv, colon - label_kv);
            if (label_k == NULL) {
                for (label_index = 0 ; label_index < 128 ; label_index++) {
                    if (value_index_list[label_index] != NULL) {
                        cfl_sds_destroy(value_index_list[label_index]);
                    }
                }

                free(value_index_list);

                if (kvs != NULL) {
                    cfl_utils_split_free(kvs);
                }

                return CMT_DECODE_STATSD_INVALID_TAG_FORMAT_ERROR;
            }
            label_v = cfl_sds_create_len(colon + 1, strlen(label_kv) - strlen(label_k) - 1);
            if (label_v == NULL) {
                cfl_sds_destroy(label_k);

                for (label_index = 0 ; label_index < 128 ; label_index++) {
                    if (value_index_list[label_index] != NULL) {
                        cfl_sds_destroy(value_index_list[label_index]);
                    }
                }

                free(value_index_list);

                if (kvs != NULL) {
                    cfl_utils_split_free(kvs);
                }

                return CMT_DECODE_STATSD_INVALID_TAG_FORMAT_ERROR;
            }

            cfl_list_foreach(label_iterator, &map->label_keys) {
                current_label = cfl_list_entry(label_iterator, struct cmt_map_label, _head);

                if (strcmp(current_label->name, label_k) == 0) {
                    label_found = CMT_TRUE;

                    break;
                }

                label_index++;
            }

            if (label_index > 127) {
                cfl_sds_destroy(label_k);
                cfl_sds_destroy(label_v);

                for (label_index = 0 ; label_index < 128 ; label_index++) {
                    if (value_index_list[label_index] != NULL) {
                        cfl_sds_destroy(value_index_list[label_index]);
                    }
                }

                free(value_index_list);

                if (kvs != NULL) {
                    cfl_utils_split_free(kvs);
                }

                return CMT_DECODE_STATSD_INVALID_ARGUMENT_ERROR;
            }

            if (label_found == CMT_FALSE) {
                result = append_new_map_label_key(map, label_k);
            }

            if (result == CMT_DECODE_STATSD_SUCCESS) {
                value_index_list[label_index] = (void *) cfl_sds_create_len(label_v,
                                                                            cfl_sds_len(label_v));
            }

            cfl_sds_destroy(label_k);
            cfl_sds_destroy(label_v);
        }
    }

split_error: /* Nop for adding labels */

    map_label_count = cfl_list_size(&map->label_keys);

    for (map_label_index = 0 ;
         result == CMT_DECODE_STATSD_SUCCESS &&
         map_label_index < map_label_count ;
         map_label_index++) {

        if (value_index_list[map_label_index] != NULL) {
            label_v = (char *) value_index_list[map_label_index];
            result = append_new_metric_label_value(metric, label_v, 0);
        }
    }

    for (label_index = 0 ; label_index < 128 ; label_index++) {
        if (value_index_list[label_index] != NULL) {
            cfl_sds_destroy(value_index_list[label_index]);
        }
    }

    free(value_index_list);

    if (kvs != NULL) {
        cfl_utils_split_free(kvs);
    }

    return result;
}

static int decode_numerical_message(struct cmt *cmt,
                                    struct cmt_map *map,
                                    struct cmt_statsd_message *m)
{
    struct cmt_metric *metric;
    int                result;
    uint64_t           ts;
    int                incremental = 0;

    ts = cfl_time_now();

    result = CMT_DECODE_STATSD_SUCCESS;

    metric = calloc(1, sizeof(struct cmt_metric));

    if (metric == NULL) {
        return CMT_DECODE_STATSD_ALLOCATION_ERROR;
    }

    cfl_list_init(&metric->labels);

    incremental = is_incremental(m->value);

    result = decode_labels(cmt,
                           map,
                           metric,
                           m->labels,
                           incremental);

    if (result) {
        destroy_label_list(&metric->labels);

        free(metric);
    }
    else {
        cfl_list_add(&metric->_head, &map->metrics);
    }

    if (result == CMT_DECODE_STATSD_SUCCESS) {
        if ((m->sample_rate - 0.0) > DBL_EPSILON &&
            (1.0 - m->sample_rate) > DBL_EPSILON) {
            cmt_metric_set(metric, ts, strtod(m->value, NULL) / m->sample_rate);
        }
        else {
            cmt_metric_set(metric, ts, strtod(m->value, NULL));
        }
    }

    return result;
}

static int decode_counter_entry(struct cmt *cmt,
                                void *instance,
                                struct cmt_statsd_message *m)
{
    struct cmt_counter *counter;
    int                 result;

    result = CMT_DECODE_STATSD_SUCCESS;

    counter = (struct cmt_counter *) instance;

    counter->map->metric_static_set = 0;

    result = decode_numerical_message(cmt,
                                      counter->map,
                                      m);

    return result;
}

static int decode_gauge_entry(struct cmt *cmt,
                              void *instance,
                              struct cmt_statsd_message *m)
{
    struct cmt_gauge *gauge;
    int               result;

    result = CMT_DECODE_STATSD_SUCCESS;

    gauge = (struct cmt_gauge *) instance;

    gauge->map->metric_static_set = 0;

    result = decode_numerical_message(cmt,
                                      gauge->map,
                                      m);

    return result;
}

static int decode_untyped_entry(struct cmt *cmt,
                                void *instance,
                                struct cmt_statsd_message *m)
{
    struct cmt_untyped *untyped;
    int                 result;

    result = CMT_DECODE_STATSD_SUCCESS;

    untyped = (struct cmt_untyped *) instance;

    untyped->map->metric_static_set = 0;

    result = decode_numerical_message(cmt,
                                      untyped->map,
                                      m);

    return result;
}

static int decode_statsd_message(struct cmt *cmt,
                                 struct cmt_statsd_message *m,
                                 int flags)
{
    char *metric_name = NULL;
    char *metric_subsystem   = NULL;
    char *metric_namespace   = NULL;
    char *metric_description = NULL;
    void *instance;
    int   result;

    result = CMT_DECODE_STATSD_SUCCESS;

    metric_description = "-";
    metric_name = cfl_sds_create_len(m->bucket, m->bucket_len);
    if (metric_name == NULL) {
        return CMT_DECODE_STATSD_ALLOCATION_ERROR;
    }
    metric_namespace = "";
    metric_subsystem = "";

    switch (m->type) {
    case CMT_DECODE_STATSD_TYPE_COUNTER:
        instance = cmt_counter_create(cmt,
                                      metric_namespace,
                                      metric_subsystem,
                                      metric_name,
                                      metric_description,
                                      0, NULL);

        if (instance == NULL) {
            cfl_sds_destroy(metric_name);
            return CMT_DECODE_STATSD_ALLOCATION_ERROR;
        }

        result = decode_counter_entry(cmt, instance, m);

        if (result) {
            cfl_sds_destroy(metric_name);
            cmt_counter_destroy(instance);
        }
        break;
    case CMT_DECODE_STATSD_TYPE_GAUGE:
        instance = cmt_gauge_create(cmt,
                                    metric_namespace,
                                    metric_subsystem,
                                    metric_name,
                                    metric_description,
                                    0, NULL);

        if (instance == NULL) {
            cfl_sds_destroy(metric_name);
            return CMT_DECODE_STATSD_ALLOCATION_ERROR;
        }

        result = decode_gauge_entry(cmt, instance, m);

        if (result) {
            cfl_sds_destroy(metric_name);
            cmt_gauge_destroy(instance);
        }
        break;
    case CMT_DECODE_STATSD_TYPE_SET:
        /* Set type will be translated as an untyped */
        instance = cmt_untyped_create(cmt,
                                      metric_namespace,
                                      metric_subsystem,
                                      metric_name,
                                      metric_description,
                                      0, NULL);

        if (instance == NULL) {
            cfl_sds_destroy(metric_name);
            return CMT_DECODE_STATSD_ALLOCATION_ERROR;
        }

        result = decode_untyped_entry(cmt, instance, m);

        if (result) {
            cfl_sds_destroy(metric_name);
            cmt_untyped_destroy(instance);
        }
        break;
    case CMT_DECODE_STATSD_TYPE_TIMER:
        /* TODO: Add histogram observer */
        if (flags & CMT_DECODE_STATSD_GAUGE_OBSERVER) {
            instance = cmt_gauge_create(cmt,
                                        metric_namespace,
                                        metric_subsystem,
                                        metric_name,
                                        metric_description,
                                        0, NULL);

            if (instance == NULL) {
                cfl_sds_destroy(metric_name);
                return CMT_DECODE_STATSD_ALLOCATION_ERROR;
            }

            result = decode_gauge_entry(cmt, instance, m);

            if (result) {
                cfl_sds_destroy(metric_name);
                cmt_gauge_destroy(instance);
            }
        }
        break;
    default:
        result = CMT_DECODE_STATSD_UNSUPPORTED_METRIC_TYPE;
        break;
    }

    cfl_sds_destroy(metric_name);

    return result;
}

static int cmt_get_statsd_type(char *str)
{
    switch (*str) {
    case 'g':
        return CMT_DECODE_STATSD_TYPE_GAUGE;
    case 's':
        return CMT_DECODE_STATSD_TYPE_SET;
    case 'c':
        return CMT_DECODE_STATSD_TYPE_COUNTER;
    case 'm':
        if (*(str + 1) == 's') {
            return CMT_DECODE_STATSD_TYPE_TIMER;
        }
    }
    return CMT_DECODE_STATSD_TYPE_COUNTER;
}

static int statsd_process_line(struct cmt *cmt, char *line, int flags)
{
    char *colon = NULL, *bar = NULL, *atmark = NULL, *labels = NULL;
    struct cmt_statsd_message m = {0};

    /*
     * bucket:value|type|@sample_rate|#key1:value1,key2:value2,...
     * ------
     */
    colon = strchr(line, ':');
    if (colon == NULL) {
        return CMT_DECODE_STATSD_INVALID_ARGUMENT_ERROR;
    }
    m.bucket = line;
    m.bucket_len = (colon - line);

    /*
     * bucket:value|type|@sample_rate|#key1:value1,key2:value2,...
     *              ----
     */
    bar = strchr(colon + 1, '|');
    if (bar == NULL) {
        return CMT_DECODE_STATSD_INVALID_ARGUMENT_ERROR;
    }
    m.type = cmt_get_statsd_type(bar + 1);

    /*
     * bucket:value|type|@sample_rate|#key1:value1,key2:value2,...
     *        -----
     */
    m.value = colon + 1;
    m.value_len = (bar - colon - 1);

    /*
     * bucket:value|type|@sample_rate|#key1:value1,key2:value2,...
     *                   ------------
     */
    atmark = strstr(bar + 1, "|@");
    if (atmark == NULL || atof(atmark + 2) == 0) {
        m.sample_rate = 1.0;
    }
    else {
        m.sample_rate = atof(atmark + 2);
    }

    /*
     * bucket:value|type|@sample_rate|#key1:value1,key2:value2,...
     *                                ------------
     */
    labels = strstr(bar + 1, "|#");
    if (labels != NULL) {
        m.labels = labels + 2;
    }

    return decode_statsd_message(cmt, &m, flags);
}

static int decode_metrics_lines(struct cmt *cmt,
                                char *in_buf, size_t in_size,
                                int flags)
{
    int ret = CMT_DECODE_STATSD_SUCCESS;
    struct cfl_list *head = NULL;
    struct cfl_list *kvs = NULL;
    struct cfl_split_entry *cur = NULL;

    kvs = cfl_utils_split(in_buf, '\n', -1 );
    if (kvs == NULL) {
        goto split_error;
    }

    cfl_list_foreach(head, kvs) {
retry:
        cur = cfl_list_entry(head, struct cfl_split_entry, _head);
        /* StatsD format always has | at least one. */
        if (strstr(cur->value, "|") == NULL) {
            goto retry;
        }

        ret = statsd_process_line(cmt, cur->value, flags);
        if (ret != CMT_DECODE_STATSD_SUCCESS) {
            ret = CMT_DECODE_STATSD_DECODE_ERROR;

            break;
        }
    }

    if (kvs != NULL) {
        cfl_utils_split_free(kvs);
    }

    return ret;

split_error:
    return -1;
}

int cmt_decode_statsd_create(struct cmt **out_cmt, char *in_buf, size_t in_size, int flags)
{
    int         result = CMT_DECODE_STATSD_INVALID_ARGUMENT_ERROR;
    struct cmt *cmt    = NULL;

    cmt = cmt_create();

    if (cmt == NULL) {
        return CMT_DECODE_STATSD_ALLOCATION_ERROR;
    }

    result = decode_metrics_lines(cmt, in_buf, in_size, flags);
    if (result != CMT_DECODE_STATSD_SUCCESS) {
        cmt_destroy(cmt);
        result = CMT_DECODE_STATSD_DECODE_ERROR;

        return result;
    }

    *out_cmt = cmt;

    return result;
}

void cmt_decode_statsd_destroy(struct cmt *cmt)
{
    cmt_destroy(cmt);
}
