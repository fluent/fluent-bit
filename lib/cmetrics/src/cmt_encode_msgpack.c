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

#include <mpack/mpack.h>

static void pack_header(mpack_writer_t *writer, struct cmt_map *map)
{
    struct mk_list *head;
    struct cmt_map_label *label;
    struct cmt_opts *opts = map->opts;

    mpack_start_map(writer, 4);

    /* 'type' */
    mpack_write_cstr(writer, "type");
    mpack_write_uint(writer, 0);

    /* 'opts' */
    mpack_write_cstr(writer, "opts");
    mpack_start_map(writer, 5);

    /* opts['namespace'] */
    mpack_write_cstr(writer, "ns");
    mpack_write_cstr(writer, opts->namespace);

    /* opts['subsystem'] */
    mpack_write_cstr(writer, "ss");
    mpack_write_cstr(writer, opts->subsystem);

    /* opts['name'] */
    mpack_write_cstr(writer, "name");
    mpack_write_cstr(writer, opts->name);

    /* opts['description'] */
    mpack_write_cstr(writer, "desc");
    mpack_write_cstr(writer, opts->description);

    /* opts['fqname'] */
    mpack_write_cstr(writer, "fqname");
    mpack_write_cstr(writer, opts->fqname);

    mpack_finish_map(writer);

    /* 'labels' (label keys) */
    mpack_write_cstr(writer, "labels");
    mpack_start_array(writer, map->label_count);
    mk_list_foreach(head, &map->label_keys) {
        label = mk_list_entry(head, struct cmt_map_label, _head);
        mpack_write_cstr(writer, label->name);
    }
    mpack_finish_array(writer);
}

static int pack_metric(mpack_writer_t *writer, int type, struct cmt_metric *metric)
{
    int c_labels;
    int s;
    double val;
    struct mk_list *head;
    struct cmt_map_label *label;

    /* FYI: ONLY SUPPORTS COUNTER & GAUGE FOR NOW */

    c_labels = mk_list_size(&metric->labels);

    s = 2;
    if (c_labels > 0) {
        s++;
    }

    mpack_start_map(writer, s);

    mpack_write_cstr(writer, "ts");
    mpack_write_uint(writer, metric->timestamp);

    mpack_write_cstr(writer, "value");
    val = cmt_metric_get_value(metric);
    mpack_write_double(writer, val);

    s = mk_list_size(&metric->labels);
    if (s > 0) {
        mpack_write_cstr(writer, "labels");
        mpack_start_array(writer, c_labels);
        mk_list_foreach(head, &metric->labels) {
            label = mk_list_entry(head, struct cmt_map_label, _head);
            mpack_write_cstr(writer, label->name);
        }
        mpack_finish_array(writer);
    }
    mpack_finish_map(writer);
}

static int pack_basic_type(mpack_writer_t *writer, struct cmt_map *map)
{
    int values_size = 0;
    struct mk_list *head;
    struct cmt_metric *metric;

    pack_header(writer, map);

    if (map->metric_static_set) {
        values_size++;
    }
    values_size += mk_list_size(&map->metrics);

    mpack_write_cstr(writer, "values");
    mpack_start_array(writer, values_size);

    if (map->metric_static_set) {
        pack_metric(writer, map->type, &map->metric);
    }

    mk_list_foreach(head, &map->metrics) {
        metric = mk_list_entry(head, struct cmt_metric, _head);
        pack_metric(writer, map->type, metric);
    }
    mpack_finish_array(writer);

    mpack_finish_map(writer);

}

/* Takes a cmetrics context and serialize it using msgpack */
int cmt_encode_msgpack_to_msgpack(struct cmt *cmt, char **out_buf, size_t *out_size)
{
    char *data;
    size_t size;
    mpack_writer_t writer;
    struct mk_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;

    /*
     * CMetrics data schema
     * {
     *  'type' => INTEGER
     *            '0' = counter
     *            '1' = gauge
     *            '2' = histogram (WIP)
     *  'opts' => {
     *             'namespace'   => namespace
     *             'subsystem'   => subsystem
     *             'name'        => name
     *             'description' => description
     *             'fqname'      => metric full name
     *            },
     *  'labels' => ['',...]
     *  'values' => [
     *                {
     *                 'ts'   : nanosec timestamp,
     *                 'value': float64 value
     *                 'labels': []
     *                }
     *              ]
     *
     */

    mpack_writer_init_growable(&writer, &data, &size);

    /* Counters */
    mk_list_foreach(head, &cmt->counters) {
        counter = mk_list_entry(head, struct cmt_counter, _head);
        pack_basic_type(&writer, counter->map);
    }

    /* Gauges */
    mk_list_foreach(head, &cmt->gauges) {
        gauge = mk_list_entry(head, struct cmt_gauge, _head);
        pack_basic_type(&writer, gauge->map);
    }

    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");
        return -1;
    }

    *out_buf = data;
    *out_size = size;

    return 0;
}

/* Convert cmetrics msgpack payload and generate a CMetrics context */
struct cmt *cmt_encode_msgpack_to_cmetrics(void *buf, size_t size)
{

}
