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
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_encode_influx.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_encode_prometheus_remote_write.h>
#include <cmetrics/cmt_encode_splunk_hec.h>

#include <prometheus_remote_write/remote.pb-c.h>

#include "cmt_tests.h"

void test_labels()
{
    int ret;
    double val = 1;
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_counter *c;

    cmt = cmt_create();
    c = cmt_counter_create(cmt, "test", "dummy", "labels", "testing labels",
                           6, (char *[]) {"A", "B", "C", "D", "E", "F"});

    ts = cfl_time_now();

    ret = cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK(ret == -1);
    TEST_CHECK((uint64_t) val == 1);

    cmt_counter_inc(c, ts, 0, NULL);
    cmt_counter_add(c, ts, 2, 0, NULL);
    cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK((uint64_t) val == 3);

    /* --- case 1 --- */
    cmt_counter_inc(c, ts, 6, (char *[]) {"1", NULL, "98", NULL, NULL, NULL});

    /* check retrieval with no labels */
    cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK((uint64_t) val == 3);

    /* check real value */
    cmt_counter_get_val(c, 6, (char *[]) {"1", NULL, "98", NULL, NULL, NULL}, &val);
    TEST_CHECK((uint64_t) val == 1);


    /* --- case 2 --- */
    cmt_counter_set(c, ts, 5, 6, (char *[]) {"1", "2", "98", "100", "200", "300"});

    /* check retrieval with no labels */
    cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK((uint64_t) val == 3);

    /* check real value */
    cmt_counter_get_val(c, 6, (char *[]) {"1", "2", "98", "100", "200", "300"}, &val);
    TEST_CHECK((uint64_t) val == 5);

    /* --- check that 'case 1' still matches --- */
    cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK((uint64_t) val == 3);

    /* check real value */
    cmt_counter_get_val(c, 6, (char *[]) {"1", NULL, "98", NULL, NULL, NULL}, &val);
    TEST_CHECK((uint64_t) val == 1);

    cmt_destroy(cmt);
}

void test_encoding()
{
    cfl_sds_t result;
    struct cmt *cmt;
    struct cmt_counter *c;
    struct cmt_metric *metric;
    struct cmt_map_label *label;
    uint64_t ts;

    cmt = cmt_create();
    c = cmt_counter_create(cmt, "test", "dummy", "labels", "testing labels",
                           6, (char *[]) {"A", "B", "C", "D", "E", "F"});

    cmt_counter_inc(c, 0, 6, (char *[]) {NULL,NULL,NULL,NULL,NULL,NULL});
    cmt_counter_inc(c, 0, 6, (char *[]) {NULL,NULL,NULL,NULL,NULL,NULL});
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result,
        "# HELP test_dummy_labels testing labels\n"
        "# TYPE test_dummy_labels counter\n"
        "test_dummy_labels 2 0\n"
        ) == 0);
    cfl_sds_destroy(result);

    cmt_counter_inc(c, 0, 6, (char *[]) {NULL,"b",NULL,NULL,NULL,NULL});
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result,
        "# HELP test_dummy_labels testing labels\n"
        "# TYPE test_dummy_labels counter\n"
        "test_dummy_labels 2 0\n"
        "test_dummy_labels{B=\"b\"} 1 0\n"
        ) == 0);
    cfl_sds_destroy(result);

    cmt_counter_inc(c, 0, 6, (char *[]) {NULL,"b",NULL,NULL,NULL,NULL});
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result,
        "# HELP test_dummy_labels testing labels\n"
        "# TYPE test_dummy_labels counter\n"
        "test_dummy_labels 2 0\n"
        "test_dummy_labels{B=\"b\"} 2 0\n"
        ) == 0);
    cfl_sds_destroy(result);


    cmt_counter_inc(c, 0, 6, (char *[]) {NULL,"",NULL,NULL,NULL,NULL});
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strstr(result, "test_dummy_labels{B=\"\"} 1 0\n") != NULL);
    cfl_sds_destroy(result);


    cmt_counter_set(c, 0, 5, 6, (char *[]) {NULL,NULL,NULL,"d",NULL,NULL});
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result,
        "# HELP test_dummy_labels testing labels\n"
        "# TYPE test_dummy_labels counter\n"
        "test_dummy_labels 2 0\n"
        "test_dummy_labels{B=\"b\"} 2 0\n"
        "test_dummy_labels{B=\"\"} 1 0\n"
        "test_dummy_labels{D=\"d\"} 5 0\n"
        ) == 0);
    cfl_sds_destroy(result);

    cmt_counter_set(c, 0, 50, 6, (char *[]) {NULL,"b",NULL,"d",NULL,"f"});
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result,
        "# HELP test_dummy_labels testing labels\n"
        "# TYPE test_dummy_labels counter\n"
        "test_dummy_labels 2 0\n"
        "test_dummy_labels{B=\"b\"} 2 0\n"
        "test_dummy_labels{B=\"\"} 1 0\n"
        "test_dummy_labels{D=\"d\"} 5 0\n"
        "test_dummy_labels{B=\"b\",D=\"d\",F=\"f\"} 50 0\n"
        ) == 0);
    cfl_sds_destroy(result);

    cmt_counter_inc(c, 0, 6, (char *[]) {"a","b","c","d","e","f"});
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result,
        "# HELP test_dummy_labels testing labels\n"
        "# TYPE test_dummy_labels counter\n"
        "test_dummy_labels 2 0\n"
        "test_dummy_labels{B=\"b\"} 2 0\n"
        "test_dummy_labels{B=\"\"} 1 0\n"
        "test_dummy_labels{D=\"d\"} 5 0\n"
        "test_dummy_labels{B=\"b\",D=\"d\",F=\"f\"} 50 0\n"
        "test_dummy_labels{A=\"a\",B=\"b\",C=\"c\",D=\"d\",E=\"e\",F=\"f\"} 1 0\n"
        ) == 0);
    cfl_sds_destroy(result);

    result = cmt_encode_influx_create(cmt);
    TEST_CHECK(result != NULL);
    if (result != NULL) {
        TEST_CHECK(strstr(result, ", ") == NULL);
        TEST_CHECK(strstr(result, ",,") == NULL);
        TEST_CHECK(strstr(result, "B=b") != NULL);
        cmt_encode_influx_destroy(result);
    }

    result = cmt_encode_splunk_hec_create(cmt, "localhost", "main", NULL, NULL);
    TEST_CHECK(result != NULL);
    if (result != NULL) {
        TEST_CHECK(strstr(result, ",,") == NULL);
        TEST_CHECK(strstr(result, ",}") == NULL);
        TEST_CHECK(strstr(result, "\"B\":\"b\"") != NULL);
        cmt_encode_splunk_hec_destroy(result);
    }

    cmt_destroy(cmt);

    cmt = cmt_create();
    c = cmt_counter_create(cmt, "test", "influx", "labels", "testing influx labels",
                           1, (char *[]) {"A"});

    cmt_counter_inc(c, 0, 1, (char *[]) {"a"});
    metric = cfl_list_entry_first(&c->map->metrics, struct cmt_metric, _head);
    TEST_CHECK(metric != NULL);
    if (metric != NULL) {
        label = calloc(1, sizeof(struct cmt_map_label));
        TEST_CHECK(label != NULL);
        if (label != NULL) {
            label->name = cfl_sds_create("extra");
            TEST_CHECK(label->name != NULL);
            if (label->name != NULL) {
                cfl_list_add(&label->_head, &metric->labels);
            }
            else {
                free(label);
            }
        }
    }

    result = cmt_encode_influx_create(cmt);
    TEST_CHECK(result != NULL);
    if (result != NULL) {
        TEST_CHECK(cfl_sds_len(result) == 0);
        cmt_encode_influx_destroy(result);
    }

    cmt_destroy(cmt);

    cmt = cmt_create();
    c = cmt_counter_create(cmt, "test", "remote", "labels", "testing remote-write labels",
                           3, (char *[]) {"A", "B", "C"});
    ts = cfl_time_now();

    cmt_counter_inc(c, ts, 3, (char *[]) {NULL, NULL, NULL});
    cmt_counter_inc(c, ts, 3, (char *[]) {NULL, "", NULL});
    cmt_counter_inc(c, ts, 3, (char *[]) {NULL, "b", NULL});
    cmt_counter_inc(c, ts, 3, (char *[]) {"a", "b", "c"});

    result = cmt_encode_prometheus_remote_write_create(cmt);
    TEST_CHECK(result != NULL);
    if (result != NULL) {
        Prometheus__WriteRequest *request;
        size_t series_index;
        size_t label_index;
        size_t label_a_count;
        size_t label_b_count;
        size_t label_c_count;
        size_t label_d_count;
        size_t label_e_count;
        size_t label_f_count;

        request = prometheus__write_request__unpack(NULL,
                                                    cfl_sds_len(result),
                                                    (uint8_t *) result);
        TEST_CHECK(request != NULL);
        if (request != NULL) {
            label_a_count = 0;
            label_b_count = 0;
            label_c_count = 0;
            label_d_count = 0;
            label_e_count = 0;
            label_f_count = 0;

            for (series_index = 0; series_index < request->n_timeseries; series_index++) {
                for (label_index = 0;
                     label_index < request->timeseries[series_index]->n_labels;
                     label_index++) {
                    if (strcmp(request->timeseries[series_index]->labels[label_index]->name, "A") == 0) {
                        label_a_count++;
                    }
                    else if (strcmp(request->timeseries[series_index]->labels[label_index]->name, "B") == 0) {
                        label_b_count++;
                    }
                    else if (strcmp(request->timeseries[series_index]->labels[label_index]->name, "C") == 0) {
                        label_c_count++;
                    }
                    else if (strcmp(request->timeseries[series_index]->labels[label_index]->name, "D") == 0) {
                        label_d_count++;
                    }
                    else if (strcmp(request->timeseries[series_index]->labels[label_index]->name, "E") == 0) {
                        label_e_count++;
                    }
                    else if (strcmp(request->timeseries[series_index]->labels[label_index]->name, "F") == 0) {
                        label_f_count++;
                    }
                }
            }

            TEST_CHECK(label_a_count == 1);
            TEST_CHECK(label_b_count == 3);
            TEST_CHECK(label_c_count == 1);
            TEST_CHECK(label_d_count == 0);
            TEST_CHECK(label_e_count == 0);
            TEST_CHECK(label_f_count == 0);
            prometheus__write_request__free_unpacked(request, NULL);
        }
        cmt_encode_prometheus_remote_write_destroy(result);
    }

    cmt_destroy(cmt);

    cmt = cmt_create();
    c = cmt_counter_create(cmt, "test", "remote_nil", "labels",
                           "testing remote-write nil labels",
                           1, (char *[]) {"A"});

    cmt_counter_inc(c, ts, 1, (char *[]) {NULL});
    label = cfl_list_entry_first(&c->map->label_keys, struct cmt_map_label, _head);
    TEST_CHECK(label != NULL);
    if (label != NULL) {
        cfl_sds_destroy(label->name);
        label->name = NULL;
    }

    result = cmt_encode_prometheus_remote_write_create(cmt);
    TEST_CHECK(result != NULL);
    if (result != NULL) {
        Prometheus__WriteRequest *request;

        request = prometheus__write_request__unpack(NULL,
                                                    cfl_sds_len(result),
                                                    (uint8_t *) result);
        TEST_CHECK(request != NULL);
        if (request != NULL) {
            TEST_CHECK(request->n_timeseries == 1);
            if (request->n_timeseries == 1) {
                TEST_CHECK(request->timeseries[0]->n_labels == 1);
                TEST_CHECK(strcmp(request->timeseries[0]->labels[0]->name, "__name__") == 0);
            }
            prometheus__write_request__free_unpacked(request, NULL);
        }
        cmt_encode_prometheus_remote_write_destroy(result);
    }

    cmt_destroy(cmt);
}

TEST_LIST = {
    {"labels", test_labels},
    {"encoding", test_encoding},
    { 0 }
};
