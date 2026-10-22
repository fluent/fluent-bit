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
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_cat.h>
#include <cmetrics/cmt_metric.h>

#include <string.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>

#include "cmt_tests.h"

/* values to observe in a histogram */
double hist_observe_values[10] = {
                                  0.0 , 1.02, 2.04, 3.06,
                                  4.08, 5.10, 6.12, 7.14,
                                  8.16, 9.18
                                 };

/*
 * histogram bucket values: the values computed in the buckets,
 * all of them are uint64_t.
 *
 * Note that on all examples we use the default buckets values, created manually
 * and through the API:
 *
 * - 11 bucket values
 * -  1 +Inf bucket value
 */
uint64_t hist_buckets_values[12] = {1, 1, 1, 1, 1, 1, 1, 1,
                                    3, 5, 10, 10};
/* histogram _count value */
uint64_t hist_count = 10;

/* histogram _sum value */
double hist_sum = 45.9;

void test_cat()
{
    int i;
    int ret;
    uint64_t val;
    uint64_t ts;
    cfl_sds_t text;
    double sum;
    uint64_t count;
    double q[6];
    double r[6];
    struct cmt *cmt1;
    struct cmt *cmt2;
    struct cmt *cmt3;
    struct cmt *cmt4;
    struct cmt *cmt5;
    struct cmt_counter *c;
    struct cmt_gauge *g;
    struct cmt_untyped *u;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *buckets;
    struct cmt_summary *s;

    /* cmetrics 1 */
    cmt1 = cmt_create();
    TEST_CHECK(cmt1 != NULL);

    c = cmt_counter_create(cmt1, "cmetrics", "test", "cat_counter", "first counter",
                           2, (char *[]) {"label1", "label2"});
    TEST_CHECK(c != NULL);

    g = cmt_gauge_create(cmt1, "cmetrics", "test", "cat_gauge", "first gauge",
                         2, (char *[]) {"label3", "label4"});
    TEST_CHECK(g != NULL);

    u = cmt_untyped_create(cmt1, "cmetrics", "test", "cat_untyped", "first untyped",
                           2, (char *[]) {"label5", "label6"});
    TEST_CHECK(u != NULL);


    ts = cfl_time_now();
    cmt_counter_set(c, ts, 1.1, 2, (char *[]) {"aaa", "bbb"});

    ts = cfl_time_now();
    cmt_gauge_set(g, ts, 1.2, 2, (char *[]) {"yyy", "xxx"});

    ts = cfl_time_now();
    cmt_untyped_set(u, ts, 1.3, 2, (char *[]) {"qwe", "asd"});

    /* cmetrics 2 */
    cmt2 = cmt_create();
    TEST_CHECK(cmt2 != NULL);

    c = cmt_counter_create(cmt2, "cmetrics", "test", "cat_counter", "second counter",
                           2, (char *[]) {"label1", "label2"});
    TEST_CHECK(c != NULL);

    g = cmt_gauge_create(cmt1, "cmetrics", "test", "cat_gauge", "first gauge",
                         2, (char *[]) {"label3", "label4"});
    TEST_CHECK(g != NULL);

    ts = cfl_time_now();
    cmt_counter_set(c, ts, 2.1, 2, (char *[]) {"ccc", "ddd"});

    /* no labels */
    cmt_counter_set(c, ts, 5, 0, NULL);

    ts = cfl_time_now();
    cmt_gauge_add(g, ts, 10, 2, (char *[]) {"tyu", "iop"});

    /*
     * CAT
     * ---
     */

    cmt3 = cmt_create();
    TEST_CHECK(cmt3 != NULL);

    ret = cmt_cat(cmt3, cmt1);
    TEST_CHECK(ret == 0);

    ret = cmt_cat(cmt3, cmt2);
    TEST_CHECK(ret == 0);

    /* Create buckets */
    buckets = cmt_histogram_buckets_create(11,
                                           0.005, 0.01, 0.025, 0.05,
                                           0.1, 0.25, 0.5, 1.0, 2.5,
                                           5.0, 10.0);
    TEST_CHECK(buckets != NULL);

    cmt4 = cmt_create();
    TEST_CHECK(cmt4 != NULL);

    /* Create a histogram metric type */
    h = cmt_histogram_create(cmt4,
                             "k8s", "network", "load", "Network load",
                             buckets,
                             1, (char *[]) {"my_label"});
    TEST_CHECK(h != NULL);

    ts = cfl_time_now();
    for (i = 0; i < sizeof(hist_observe_values)/(sizeof(double)); i++) {
        val = hist_observe_values[i];
        cmt_histogram_observe(h, ts, val, 1, (char *[]) {"my_label"});
    }

    ret = cmt_cat(cmt4, cmt3);
    TEST_CHECK(ret == 0);

    cmt5 = cmt_create();
    TEST_CHECK(cmt5 != NULL);

    ts = cfl_time_now();

    /* set quantiles */
    q[0] = 0.1;
    q[1] = 0.2;
    q[2] = 0.3;
    q[3] = 0.4;
    q[4] = 0.5;
    q[5] = 1.0;

    r[0] = 1;
    r[1] = 2;
    r[2] = 3;
    r[3] = 4;
    r[4] = 5;
    r[5] = 6;

    /* Create a gauge metric type */
    s = cmt_summary_create(cmt5,
                           "spring", "kafka_listener", "seconds", "Kafka Listener Timer",
                           6, q,
                           3, (char *[]) {"exception", "name", "result"});
    TEST_CHECK(s != NULL);

    /* no quantiles, labels */
    sum = 0.0;
    count = 1;

    cmt_summary_set_default(s, ts, NULL, sum, count,
                            3, (char *[]) {"ListenerExecutionFailedException",
                                           "org.springframework.kafka.KafkaListenerEndpointContainer#0-0",
                                           "failure"});

    /* no quantiles, labels */
    sum = 0.1;
    count = 2;
    cmt_summary_set_default(s, ts, NULL, sum, count,
                            3, (char *[]) {"none",
                                          "org.springframework.kafka.KafkaListenerEndpointContainer#0-0",
                                          "success"});

    /* quantiles, labels */
    sum = 0.2;
    count = 3;
    cmt_summary_set_default(s, ts, r, sum, count,
                            3, (char *[]) {"extra test",
                                           "org.springframework.kafka.KafkaListenerEndpointContainer#0-0",
                                           "success"});

    ret = cmt_cat(cmt5, cmt4);
    TEST_CHECK(ret == 0);

    /* check output */
    text = cmt_encode_text_create(cmt5);
    printf("====>\n%s\n", text);

    cmt_encode_text_destroy(text);

    /* destroy contexts */
    cmt_destroy(cmt1);
    cmt_destroy(cmt2);
    cmt_destroy(cmt3);
    cmt_destroy(cmt4);
    cmt_destroy(cmt5);
}


void test_duplicate_metrics()
{
    int i;
    int ret;
    double val;
    struct cmt *cmt1;
    struct cmt *cmt2;
    struct cmt *final;
    struct cmt_counter *c;
    struct cmt_gauge *g;
    struct cmt_untyped *u;
    struct cmt_summary *s;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *buckets1;
    struct cmt_histogram_buckets *buckets2;
    double sum;
    int count;
    uint64_t ts;

    cfl_sds_t text;

    /* context 1 */
    cmt1 = cmt_create();
    TEST_CHECK(cmt1 != NULL);

    c = cmt_counter_create(cmt1, "cmetrics", "test", "cat_counter", "first counter",
                           2, (char *[]) {"label1", "label2"});
    TEST_CHECK(c != NULL);
    cmt_counter_set(c, cfl_time_now(), 10, 0, NULL  );
    cmt_counter_inc(c, cfl_time_now(), 2, (char *[]) {"aaa", "bbb"});


    g = cmt_gauge_create(cmt1, "cmetrics", "test", "cat_gauge", "first gauge",
                         2, (char *[]) {"label3", "label4"});
    TEST_CHECK(g != NULL);
    cmt_gauge_inc(g, cfl_time_now(), 2, (char *[]) {"yyy", "xxx"});

    u = cmt_untyped_create(cmt1, "cmetrics", "test", "cat_untyped", "first untyped",
                           2, (char *[]) {"label5", "label6"});
    TEST_CHECK(u != NULL);
    cmt_untyped_set(u, cfl_time_now(), 10, 2, (char *[]) {"qwe", "asd"});

    s = cmt_summary_create(cmt1,
                           "spring", "kafka_listener", "seconds", "Kafka Listener Timer",
                           6, (double[]) {0.1, 0.2, 0.3, 0.4, 0.5, 1.0},
                           3, (char *[]) {"exception", "name", "result"});

    ts = cfl_time_now();

    /* Summary
     * -------
     */
    /* no quantiles, labels */
    sum = 0.0;
    count = 1;

    cmt_summary_set_default(s, ts, NULL, sum, count,
                            3, (char *[]) {"ListenerExecutionFailedException",
                                           "org.springframework.kafka.KafkaListenerEndpointContainer#0-0",
                                           "failure"});

    /* no quantiles, labels */
    sum = 0.1;
    count = 2;
    cmt_summary_set_default(s, ts, NULL, sum, count,
                            3, (char *[]) {"none",
                                          "org.springframework.kafka.KafkaListenerEndpointContainer#0-0",
                                          "success"});

    /* quantiles, labels */
    sum = 0.2;
    count = 3;
    cmt_summary_set_default(s, ts, NULL, sum, count,
                            3, (char *[]) {"extra test",
                                           "org.springframework.kafka.KafkaListenerEndpointContainer#0-0",
                                           "success"});

    /*
     * Histogram
     * ---------
     */
    buckets1 = cmt_histogram_buckets_create(11,
                                            0.005, 0.01, 0.025, 0.05,
                                            0.1, 0.25, 0.5, 1.0, 2.5,
                                            5.0, 10.0);

    h = cmt_histogram_create(cmt1,
                             "k8s", "network", "load", "Network load",
                             buckets1,
                             1, (char *[]) {"my_label"});
    TEST_CHECK(h != NULL);

    ts = cfl_time_now();
    for (i = 0; i < sizeof(hist_observe_values)/(sizeof(double)); i++) {
        val = hist_observe_values[i];
        cmt_histogram_observe(h, ts, val, 1, (char *[]) {"my_label"});
    }

    /* duplicate counter */
    cmt2 = cmt_create();
    TEST_CHECK(cmt2 != NULL);

    c = cmt_counter_create(cmt2, "cmetrics", "test", "cat_counter", "first counter",
                           2, (char *[]) {"label1", "label2"});
    TEST_CHECK(c != NULL);
    cmt_counter_set(c, cfl_time_now(), 11, 0, NULL  );
    cmt_counter_inc(c, cfl_time_now(), 2, (char *[]) {"ddd", "eee"});

    /* duplicate gauge */
    g = cmt_gauge_create(cmt2, "cmetrics", "test", "cat_gauge", "first gauge",
                         2, (char *[]) {"label3", "label4"});
    TEST_CHECK(g != NULL);
    cmt_gauge_inc(g, cfl_time_now(), 2, (char *[]) {"zzz", "xxx"});

    /* duplicate untyped */
    u = cmt_untyped_create(cmt2, "cmetrics", "test", "cat_untyped", "first untyped",
                           2, (char *[]) {"label5", "label6"});
    TEST_CHECK(u != NULL);
    cmt_untyped_set(u, cfl_time_now(), 20, 2, (char *[]) {"rty", "asd"});

    buckets2 = cmt_histogram_buckets_create(11,
                                            0.005, 0.01, 0.025, 0.05,
                                            0.1, 0.25, 0.5, 1.0, 2.5,
                                            5.0, 10.0);
    h = cmt_histogram_create(cmt2,
                             "k8s", "network", "load", "Network load",
                             buckets2,
                             1, (char *[]) {"my_label2"});
    TEST_CHECK(h != NULL);

    ts = cfl_time_now();

    for (i = 0; i < sizeof(hist_observe_values)/(sizeof(double)); i++) {
        val = hist_observe_values[i];
        cmt_histogram_observe(h, ts, val, 1, (char *[]) {"my_label"});
    }

    /* concatenate cmt1 + cmt2 */
    final = cmt_create();
    ret = cmt_cat(final, cmt1);
    TEST_CHECK(ret == 0);

    ret = cmt_cat(final, cmt2);
    TEST_CHECK(ret == 0);

    /* prometheus format */
    text = cmt_encode_prometheus_create(final, CMT_FALSE);
    printf("Prometheus Text====>\n%s\n", text);
    cfl_sds_destroy(text);


    cmt_destroy(cmt1);
    cmt_destroy(cmt2);
    cmt_destroy(final);

}

void test_histogram_empty_concatenation()
{
    int ret;
    struct cmt *cmt1;
    struct cmt *cmt2;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *buckets;

    /* Test concatenating an empty histogram (no observations, NULL hist_buckets) */
    cmt1 = cmt_create();
    TEST_CHECK(cmt1 != NULL);

    buckets = cmt_histogram_buckets_create(11,
                                           0.005, 0.01, 0.025, 0.05,
                                           0.1, 0.25, 0.5, 1.0, 2.5,
                                           5.0, 10.0);
    TEST_CHECK(buckets != NULL);

    /* Create histogram but never observe - hist_buckets will be NULL */
    h = cmt_histogram_create(cmt1,
                             "test", "histogram", "empty", "Empty histogram test",
                             buckets,
                             0, NULL);
    TEST_CHECK(h != NULL);

    /* Create destination context */
    cmt2 = cmt_create();
    TEST_CHECK(cmt2 != NULL);

    /* Concatenate empty histogram - should handle NULL hist_buckets gracefully */
    ret = cmt_cat(cmt2, cmt1);
    TEST_CHECK(ret == 0);

    cmt_destroy(cmt1);
    cmt_destroy(cmt2);
}

void test_histogram_mismatched_buckets()
{
    int ret;
    int i;
    double val;
    uint64_t ts;
    struct cmt *cmt1;
    struct cmt *cmt2;
    struct cmt_histogram *h1;
    struct cmt_histogram *h2;
    struct cmt_histogram_buckets *buckets1;
    struct cmt_histogram_buckets *buckets2;

    /* Test concatenating histograms with different bucket structures */
    cmt1 = cmt_create();
    TEST_CHECK(cmt1 != NULL);

    /* Create histogram with 11 buckets */
    buckets1 = cmt_histogram_buckets_create(11,
                                            0.005, 0.01, 0.025, 0.05,
                                            0.1, 0.25, 0.5, 1.0, 2.5,
                                            5.0, 10.0);
    TEST_CHECK(buckets1 != NULL);

    h1 = cmt_histogram_create(cmt1,
                               "test", "histogram", "mismatch", "Mismatched buckets test",
                               buckets1,
                              0, NULL);
    TEST_CHECK(h1 != NULL);

    ts = cfl_time_now();
    for (i = 0; i < sizeof(hist_observe_values)/(sizeof(double)); i++) {
        val = hist_observe_values[i];
        cmt_histogram_observe(h1, ts, val, 0, NULL);
    }

    /* Create second context with different bucket structure */
    cmt2 = cmt_create();
    TEST_CHECK(cmt2 != NULL);

    /* Create histogram with 5 buckets (different structure) */
    buckets2 = cmt_histogram_buckets_create(5,
                                             0.1, 0.5, 1.0, 5.0, 10.0);
    TEST_CHECK(buckets2 != NULL);

    h2 = cmt_histogram_create(cmt2,
                               "test", "histogram", "mismatch", "Mismatched buckets test",
                               buckets2,
                               0, NULL);
    TEST_CHECK(h2 != NULL);

    ts = cfl_time_now();
    for (i = 0; i < sizeof(hist_observe_values)/(sizeof(double)); i++) {
        val = hist_observe_values[i];
        cmt_histogram_observe(h2, ts, val, 0, NULL);
    }

    /* Try to concatenate - should fail due to bucket mismatch */
    ret = cmt_cat(cmt1, cmt2);
    TEST_CHECK(ret == -1);

    cmt_destroy(cmt1);
    cmt_destroy(cmt2);
}

void test_histogram_empty_to_populated()
{
    int ret;
    int i;
    double val;
    uint64_t ts;
    struct cmt *cmt1;
    struct cmt *cmt2;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *buckets1;
    struct cmt_histogram_buckets *buckets2;

    /* Test concatenating empty histogram to one with data */
    cmt1 = cmt_create();
    TEST_CHECK(cmt1 != NULL);

    buckets1 = cmt_histogram_buckets_create(11,
                                             0.005, 0.01, 0.025, 0.05,
                                             0.1, 0.25, 0.5, 1.0, 2.5,
                                             5.0, 10.0);
    TEST_CHECK(buckets1 != NULL);

    /* Create empty histogram (no observations) */
    h = cmt_histogram_create(cmt1,
                              "test", "histogram", "empty_to_full", "Empty to populated test",
                              buckets1,
                              0, NULL);
    TEST_CHECK(h != NULL);

    /* Create second context with populated histogram */
    cmt2 = cmt_create();
    TEST_CHECK(cmt2 != NULL);

    buckets2 = cmt_histogram_buckets_create(11,
                                            0.005, 0.01, 0.025, 0.05,
                                            0.1, 0.25, 0.5, 1.0, 2.5,
                                            5.0, 10.0);
    TEST_CHECK(buckets2 != NULL);

    h = cmt_histogram_create(cmt2,
                              "test", "histogram", "empty_to_full", "Empty to populated test",
                              buckets2,
                              0, NULL);
    TEST_CHECK(h != NULL);

    ts = cfl_time_now();
    for (i = 0; i < sizeof(hist_observe_values)/(sizeof(double)); i++) {
        val = hist_observe_values[i];
        cmt_histogram_observe(h, ts, val, 0, NULL);
    }

    /* Concatenate empty to populated - should succeed */
    ret = cmt_cat(cmt1, cmt2);
    TEST_CHECK(ret == 0);

    cmt_destroy(cmt1);
    cmt_destroy(cmt2);
}

void test_histogram_populated_to_empty()
{
    int ret;
    int i;
    double val;
    uint64_t ts;
    struct cmt *cmt1;
    struct cmt *cmt2;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *buckets1;
    struct cmt_histogram_buckets *buckets2;

    /* Test concatenating populated histogram to empty one */
    cmt1 = cmt_create();
    TEST_CHECK(cmt1 != NULL);

    buckets1 = cmt_histogram_buckets_create(11,
                                             0.005, 0.01, 0.025, 0.05,
                                             0.1, 0.25, 0.5, 1.0, 2.5,
                                             5.0, 10.0);
    TEST_CHECK(buckets1 != NULL);

    h = cmt_histogram_create(cmt1,
                              "test", "histogram", "full_to_empty", "Populated to empty test",
                              buckets1,
                              0, NULL);
    TEST_CHECK(h != NULL);

    ts = cfl_time_now();
    for (i = 0; i < sizeof(hist_observe_values)/(sizeof(double)); i++) {
        val = hist_observe_values[i];
        cmt_histogram_observe(h, ts, val, 0, NULL);
    }

    /* Create second context with empty histogram */
    cmt2 = cmt_create();
    TEST_CHECK(cmt2 != NULL);

    buckets2 = cmt_histogram_buckets_create(11,
                                            0.005, 0.01, 0.025, 0.05,
                                            0.1, 0.25, 0.5, 1.0, 2.5,
                                            5.0, 10.0);
    TEST_CHECK(buckets2 != NULL);

    /* Create empty histogram (no observations) */
    h = cmt_histogram_create(cmt2,
                              "test", "histogram", "full_to_empty", "Populated to empty test",
                              buckets2,
                              0, NULL);
    TEST_CHECK(h != NULL);

    /* Concatenate populated to empty - should succeed */
    ret = cmt_cat(cmt1, cmt2);
    TEST_CHECK(ret == 0);

    cmt_destroy(cmt1);
    cmt_destroy(cmt2);
}

void test_exp_histogram_preserves_aggregation_type()
{
    int ret;
    uint64_t ts;
    uint64_t positive_buckets[] = {1, 2};
    struct cmt *src;
    struct cmt *dst;
    struct cmt_exp_histogram *src_histogram;
    struct cmt_exp_histogram *dst_histogram;

    src = cmt_create();
    TEST_CHECK(src != NULL);

    dst = cmt_create();
    TEST_CHECK(dst != NULL);

    src_histogram = cmt_exp_histogram_create(src,
                                             "test", "exp", "aggregation_type",
                                             "Exponential histogram aggregation type test",
                                             1, (char *[]) {"label"});
    TEST_CHECK(src_histogram != NULL);

    ts = cfl_time_now();

    ret = cmt_exp_histogram_set_default(src_histogram,
                                        ts,
                                        1,
                                        0,
                                        0.0,
                                        0,
                                        2,
                                        positive_buckets,
                                        0,
                                        0,
                                        NULL,
                                        CMT_TRUE,
                                        3.0,
                                        3,
                                        1,
                                        (char *[]) {"value"});
    TEST_CHECK(ret == 0);

    src_histogram->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;

    ret = cmt_cat(dst, src);
    TEST_CHECK(ret == 0);

    dst_histogram = cfl_list_entry_first(&dst->exp_histograms,
                                         struct cmt_exp_histogram, _head);
    TEST_CHECK(dst_histogram != NULL);
    TEST_CHECK(dst_histogram->aggregation_type == CMT_AGGREGATION_TYPE_DELTA);

    cmt_destroy(src);
    cmt_destroy(dst);
}

void test_summary_concatenation_preserves_series()
{
    int                   ret;
    int                   found_first;
    int                   found_second;
    double                quantiles[] = {0.5, 0.9};
    double                values[] = {5.0, 9.0};
    struct cfl_list      *head;
    struct cfl_list      *label_head;
    struct cmt           *dst;
    struct cmt           *src_first;
    struct cmt           *src_second;
    struct cmt_summary   *summary;
    struct cmt_metric    *metric;
    struct cmt_map_label *label;

    dst = cmt_create();
    src_first = cmt_create();
    src_second = cmt_create();
    TEST_ASSERT(dst != NULL);
    TEST_ASSERT(src_first != NULL);
    TEST_ASSERT(src_second != NULL);

    summary = cmt_summary_create(src_first, "test", "cat", "summary",
                                 "Summary concatenation", 2, quantiles,
                                 1, (char *[]) {"kind"});
    TEST_ASSERT(summary != NULL);
    ret = cmt_summary_set_default(summary, 10, values, 14.0, 7,
                                  1, (char *[]) {"first"});
    TEST_ASSERT(ret == 0);

    ret = cmt_cat(dst, src_first);
    TEST_ASSERT(ret == 0);
    TEST_CHECK(cfl_list_size(&dst->summaries) == 1);

    summary = cfl_list_entry_first(&dst->summaries,
                                   struct cmt_summary, _head);
    TEST_CHECK(cfl_list_size(&summary->map->metrics) == 1);

    metric = cfl_list_entry_first(&summary->map->metrics,
                                  struct cmt_metric, _head);
    label = cfl_list_entry_first(&metric->labels,
                                 struct cmt_map_label, _head);
    TEST_CHECK(strcmp(label->name, "first") == 0);
    TEST_CHECK(cmt_summary_get_count_value(metric) == 7);

    summary = cmt_summary_create(src_second, "test", "cat", "summary",
                                 "Summary concatenation", 2, quantiles,
                                 1, (char *[]) {"kind"});
    TEST_ASSERT(summary != NULL);
    ret = cmt_summary_set_default(summary, 20, values, 18.0, 9,
                                  1, (char *[]) {"second"});
    TEST_ASSERT(ret == 0);

    ret = cmt_cat(dst, src_second);
    TEST_ASSERT(ret == 0);
    TEST_CHECK(cfl_list_size(&dst->summaries) == 1);

    summary = cfl_list_entry_first(&dst->summaries,
                                   struct cmt_summary, _head);
    TEST_CHECK(cfl_list_size(&summary->map->metrics) == 2);

    found_first = CMT_FALSE;
    found_second = CMT_FALSE;
    cfl_list_foreach(head, &summary->map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        label_head = metric->labels.next;
        label = cfl_list_entry(label_head, struct cmt_map_label, _head);

        TEST_CHECK(strcmp(label->name, "kind") != 0);
        if (strcmp(label->name, "first") == 0) {
            found_first = CMT_TRUE;
        }
        else if (strcmp(label->name, "second") == 0) {
            found_second = CMT_TRUE;
        }
    }

    TEST_CHECK(found_first == CMT_TRUE);
    TEST_CHECK(found_second == CMT_TRUE);

    cmt_destroy(src_second);
    cmt_destroy(src_first);
    cmt_destroy(dst);
}

void test_summary_concatenation_rejects_mismatched_label_schema()
{
    int ret;
    double quantiles[] = {0.5, 0.9};
    struct cmt *dst;
    struct cmt *src;
    struct cmt_summary *summary;

    dst = cmt_create();
    src = cmt_create();
    TEST_ASSERT(dst != NULL);
    TEST_ASSERT(src != NULL);

    summary = cmt_summary_create(dst, "test", "cat", "schema",
                                 "schema validation", 2, quantiles, 2,
                                 (char *[]) {"method", "status"});
    TEST_ASSERT(summary != NULL);

    summary = cmt_summary_create(src, "test", "cat", "schema",
                                 "schema validation", 2, quantiles, 2,
                                 (char *[]) {"status", "method"});
    TEST_ASSERT(summary != NULL);

    TEST_ASSERT(cmt_label_add(src, "pending", "discarded on failure") == 0);
    ret = cmt_cat(dst, src);
    TEST_CHECK(ret == -1);
    TEST_CHECK(cfl_list_size(&dst->summaries) == 1);
    TEST_CHECK(cmt_labels_count(dst->static_labels) == 0);
    TEST_CHECK(cmt_labels_count(src->static_labels) == 1);

    cmt_destroy(src);
    cmt_destroy(dst);
}

static struct cmt_label *find_static_label(struct cmt *cmt, char *key)
{
    struct cfl_list *head;
    struct cmt_label *label;

    cfl_list_foreach(head, &cmt->static_labels->list) {
        label = cfl_list_entry(head, struct cmt_label, _head);
        if (strcmp(label->key, key) == 0) {
            return label;
        }
    }
    return NULL;
}

void test_cat_static_labels_chain()
{
    struct cmt *src;
    struct cmt *intermediate;
    struct cmt *dst;
    struct cmt_gauge *gauge;
    struct cmt_label *source_label;
    struct cmt_label *copied_label;
    cfl_sds_t text;

    src = cmt_create();
    intermediate = cmt_create();
    dst = cmt_create();
    TEST_ASSERT(src != NULL && intermediate != NULL && dst != NULL);
    TEST_ASSERT(cmt_label_add(src, "upstream", "") == 0);
    gauge = cmt_gauge_create(src, "", "", "test_metric", "test metric",
                             1, (char *[]) {"original"});
    TEST_ASSERT(gauge != NULL);
    TEST_ASSERT(cmt_gauge_set(gauge, 0, 1.0, 1, (char *[]) {"value"}) == 0);

    TEST_ASSERT(cmt_cat(intermediate, src) == 0);
    TEST_ASSERT(cmt_label_add(intermediate, "first", "one") == 0);
    TEST_ASSERT(cmt_cat(dst, intermediate) == 0);
    TEST_ASSERT(cmt_label_add(dst, "second", "two") == 0);
    TEST_CHECK(cmt_labels_count(src->static_labels) == 1);
    TEST_CHECK(cmt_labels_count(intermediate->static_labels) == 2);
    TEST_CHECK(cmt_labels_count(dst->static_labels) == 3);
    source_label = find_static_label(intermediate, "first");
    copied_label = find_static_label(dst, "first");
    TEST_ASSERT(source_label != NULL && copied_label != NULL);
    TEST_CHECK(source_label != copied_label);
    TEST_CHECK(source_label->key != copied_label->key);
    TEST_CHECK(source_label->val != copied_label->val);
    cmt_destroy(src);
    cmt_destroy(intermediate);

    text = cmt_encode_prometheus_create(dst, 0);
    TEST_ASSERT(text != NULL);
    TEST_CHECK(strstr(text, "test_metric{upstream=\"\",first=\"one\",second=\"two\","
                            "original=\"value\"} 1") != NULL);
    cmt_encode_prometheus_destroy(text);
    cmt_destroy(dst);
}

void test_cat_static_labels_merge()
{
    struct cmt *src;
    struct cmt *dst;
    struct cmt_label *label;
    struct cmt_gauge *gauge;
    cfl_sds_t text;

    src = cmt_create();
    dst = cmt_create();
    TEST_ASSERT(src != NULL && dst != NULL);
    gauge = cmt_gauge_create(dst, "", "", "existing_metric", "existing metric", 0, NULL);
    TEST_ASSERT(gauge != NULL);
    TEST_ASSERT(cmt_gauge_set(gauge, 0, 1.0, 0, NULL) == 0);
    gauge = cmt_gauge_create(src, "", "", "new_metric", "new metric", 0, NULL);
    TEST_ASSERT(gauge != NULL);
    TEST_ASSERT(cmt_gauge_set(gauge, 0, 2.0, 0, NULL) == 0);
    TEST_ASSERT(cmt_label_add(dst, "existing", "preserved") == 0);
    TEST_ASSERT(cmt_label_add(dst, "shared", "same") == 0);
    TEST_ASSERT(cmt_label_add(src, "shared", "same") == 0);
    TEST_ASSERT(cmt_label_add(src, "new", "copied") == 0);
    TEST_ASSERT(cmt_label_add(src, "new", "copied") == 0);
    TEST_ASSERT(cmt_label_add(src, "NEW", "case-sensitive") == 0);
    TEST_ASSERT(cmt_cat(dst, src) == 0);
    TEST_ASSERT(cmt_cat(dst, src) == 0);
    TEST_CHECK(cmt_labels_count(dst->static_labels) == 4);
    label = cfl_list_entry_first(&dst->static_labels->list, struct cmt_label, _head);
    TEST_CHECK(strcmp(label->key, "existing") == 0);
    TEST_CHECK(strcmp(label->val, "preserved") == 0);
    label = find_static_label(dst, "new");
    TEST_ASSERT(label != NULL);
    TEST_CHECK(strcmp(label->val, "copied") == 0);
    label = find_static_label(dst, "NEW");
    TEST_ASSERT(label != NULL);
    TEST_CHECK(strcmp(label->val, "case-sensitive") == 0);
    cmt_destroy(src);
    TEST_CHECK(cfl_list_size(&dst->gauges) == 2);
    text = cmt_encode_prometheus_create(dst, 0);
    TEST_ASSERT(text != NULL);
    TEST_CHECK(strstr(text, "existing_metric{existing=\"preserved\",shared=\"same\","
                            "new=\"copied\",NEW=\"case-sensitive\"} 1") != NULL);
    TEST_CHECK(strstr(text, "new_metric{existing=\"preserved\",shared=\"same\","
                            "new=\"copied\",NEW=\"case-sensitive\"} 2") != NULL);
    cmt_encode_prometheus_destroy(text);
    cmt_destroy(dst);
}

void test_cat_static_labels_conflict()
{
    struct cmt *src;
    struct cmt *dst;
    struct cmt_gauge *gauge;
    struct cmt_label *label;

    src = cmt_create();
    dst = cmt_create();
    TEST_ASSERT(src != NULL && dst != NULL);
    TEST_ASSERT(cmt_label_add(dst, "shared", "destination") == 0);
    TEST_ASSERT(cmt_label_add(src, "new", "must not be added") == 0);
    TEST_ASSERT(cmt_label_add(src, "shared", "source") == 0);
    gauge = cmt_gauge_create(src, "", "", "test_metric", "test metric", 0, NULL);
    TEST_ASSERT(gauge != NULL);
    TEST_ASSERT(cmt_gauge_set(gauge, 0, 1.0, 0, NULL) == 0);
    TEST_CHECK(cmt_cat(dst, src) == -1);
    TEST_CHECK(cmt_labels_count(dst->static_labels) == 1);
    TEST_CHECK(cfl_list_size(&dst->gauges) == 0);
    label = find_static_label(dst, "shared");
    TEST_ASSERT(label != NULL);
    TEST_CHECK(strcmp(label->val, "destination") == 0);
    cmt_destroy(dst);

    /* Conflicting duplicate keys within the source are rejected too. */
    dst = cmt_create();
    TEST_ASSERT(dst != NULL);
    TEST_ASSERT(cmt_label_add(src, "shared", "conflicting") == 0);
    TEST_CHECK(cmt_cat(dst, src) == -1);
    TEST_CHECK(cmt_labels_count(dst->static_labels) == 0);
    TEST_CHECK(cfl_list_size(&dst->gauges) == 0);
    cmt_destroy(src);
    cmt_destroy(dst);
}

void test_cat_static_labels_dynamic_conflict()
{
    int type;
    struct cmt *src;
    struct cmt *dst;
    struct cmt_gauge *gauge;
    char *keys[] = {"other", "region"};
    char *values[] = {"value", "west"};
    cfl_sds_t before;
    cfl_sds_t after;

    for (type = CMT_COUNTER; type <= CMT_EXP_HISTOGRAM; type++) {
        src = cmt_create();
        dst = cmt_create();
        TEST_ASSERT(src != NULL && dst != NULL);
        TEST_ASSERT(cmt_label_add(dst, "existing", "preserved") == 0);
        TEST_ASSERT(cmt_label_add(src, "pending", "must not be added") == 0);
        TEST_ASSERT(cmt_label_add(src, "region", "east") == 0);
        TEST_ASSERT(cmt_gauge_create(src, "", "", "new_metric", "new metric",
                                     0, NULL) != NULL);

        /* Even schemas without samples must reject a colliding static key. */
        switch (type) {
        case CMT_COUNTER:
            TEST_ASSERT(cmt_counter_create(dst, "", "", "metric", "metric",
                                           2, keys) != NULL);
            break;
        case CMT_GAUGE:
            gauge = cmt_gauge_create(dst, "", "", "metric", "metric", 2, keys);
            TEST_ASSERT(gauge != NULL);
            TEST_ASSERT(cmt_gauge_set(gauge, 0, 1.0, 2, values) == 0);
            break;
        case CMT_HISTOGRAM:
            TEST_ASSERT(cmt_histogram_create(dst, "", "", "metric", "metric",
                                             NULL, 2, keys) != NULL);
            break;
        case CMT_SUMMARY:
            TEST_ASSERT(cmt_summary_create(dst, "", "", "metric", "metric",
                                           0, NULL, 2, keys) != NULL);
            break;
        case CMT_UNTYPED:
            TEST_ASSERT(cmt_untyped_create(dst, "", "", "metric", "metric",
                                           2, keys) != NULL);
            break;
        case CMT_EXP_HISTOGRAM:
            TEST_ASSERT(cmt_exp_histogram_create(dst, "", "", "metric", "metric",
                                                 2, keys) != NULL);
            break;
        }

        before = cmt_encode_prometheus_create(dst, 0);
        TEST_ASSERT(before != NULL);
        TEST_CHECK(cmt_cat(dst, src) == -1);
        TEST_CHECK(cmt_labels_count(dst->static_labels) == 1);
        TEST_CHECK(cmt_labels_count(src->static_labels) == 2);
        TEST_CHECK(cfl_list_size(&dst->gauges) == (type == CMT_GAUGE ? 1 : 0));
        after = cmt_encode_prometheus_create(dst, 0);
        TEST_ASSERT(after != NULL);
        TEST_CHECK(strcmp(before, after) == 0);
        cmt_encode_prometheus_destroy(before);
        cmt_encode_prometheus_destroy(after);
        cmt_destroy(src);

        /* Key comparison is case-sensitive. */
        src = cmt_create();
        TEST_ASSERT(src != NULL);
        TEST_ASSERT(cmt_label_add(src, "Region", "east") == 0);
        TEST_CHECK(cmt_cat(dst, src) == 0);
        TEST_CHECK(cmt_labels_count(dst->static_labels) == 2);
        cmt_destroy(src);
        cmt_destroy(dst);
    }
}

void test_cat_static_labels_source_dynamic_conflict()
{
    int shared;
    int populated;
    struct cmt *src;
    struct cmt *dst;
    struct cmt_gauge *gauge;
    char *keys[] = {"other", "region"};
    char *values[] = {"value", "west"};
    cfl_sds_t src_before;
    cfl_sds_t dst_before;
    cfl_sds_t after;

    for (shared = 0; shared <= 1; shared++) {
        for (populated = 0; populated <= 1; populated++) {
            src = cmt_create();
            dst = cmt_create();
            TEST_ASSERT(src != NULL && dst != NULL);
            TEST_ASSERT(cmt_label_add(dst, "existing", "preserved") == 0);
            if (shared) {
                TEST_ASSERT(cmt_label_add(dst, "region", "east") == 0);
            }
            TEST_ASSERT(cmt_label_add(src, "pending", "must not be added") == 0);
            TEST_ASSERT(cmt_label_add(src, "region", "east") == 0);
            gauge = cmt_gauge_create(dst, "", "", "existing_metric",
                                     "existing metric", 0, NULL);
            TEST_ASSERT(gauge != NULL);
            TEST_ASSERT(cmt_gauge_set(gauge, 0, 1.0, 0, NULL) == 0);
            gauge = cmt_gauge_create(src, "", "", "new_metric",
                                     "new metric", 2, keys);
            TEST_ASSERT(gauge != NULL);
            if (populated) {
                TEST_ASSERT(cmt_gauge_set(gauge, 0, 2.0, 2, values) == 0);
            }

            src_before = cmt_encode_prometheus_create(src, 0);
            dst_before = cmt_encode_prometheus_create(dst, 0);
            TEST_ASSERT(src_before != NULL && dst_before != NULL);
            TEST_CHECK(cmt_cat(dst, src) == -1);
            TEST_CHECK(cmt_labels_count(dst->static_labels) == 1 + shared);
            TEST_CHECK(cmt_labels_count(src->static_labels) == 2);
            TEST_CHECK(cfl_list_size(&dst->gauges) == 1);
            TEST_CHECK(cfl_list_size(&src->gauges) == 1);

            /* Rejection must preserve metric identity and label ordering. */
            after = cmt_encode_prometheus_create(dst, 0);
            TEST_ASSERT(after != NULL);
            TEST_CHECK(strcmp(dst_before, after) == 0);
            cmt_encode_prometheus_destroy(after);
            after = cmt_encode_prometheus_create(src, 0);
            TEST_ASSERT(after != NULL);
            TEST_CHECK(strcmp(src_before, after) == 0);
            cmt_encode_prometheus_destroy(after);
            cmt_encode_prometheus_destroy(src_before);
            cmt_encode_prometheus_destroy(dst_before);
            cmt_destroy(src);
            cmt_destroy(dst);
        }
    }
}

void test_cat_static_labels_empty()
{
    struct cmt *src;
    struct cmt *dst;

    src = cmt_create();
    dst = cmt_create();
    TEST_ASSERT(src != NULL && dst != NULL);
    TEST_CHECK(cmt_cat(dst, src) == 0);
    TEST_CHECK(cmt_labels_count(dst->static_labels) == 0);
    TEST_ASSERT(cmt_label_add(dst, "existing", "preserved") == 0);
    TEST_CHECK(cmt_cat(dst, src) == 0);
    TEST_CHECK(cmt_labels_count(dst->static_labels) == 1);
    TEST_CHECK(cmt_cat(NULL, src) == -1);
    TEST_CHECK(cmt_cat(dst, NULL) == -1);
    cmt_destroy(src);
    cmt_destroy(dst);
}

/* Decode into a fresh map, whose series have not entered the lookup index. */
static struct cmt *decode_copy(struct cmt *source)
{
    char *buffer;
    size_t size;
    size_t offset = 0;
    struct cmt *decoded = NULL;

    TEST_ASSERT(cmt_encode_msgpack_create(source, &buffer, &size) == 0);
    TEST_ASSERT(cmt_decode_msgpack_create(&decoded, buffer, size, &offset) == 0);
    cmt_encode_msgpack_destroy(buffer);
    return decoded;
}

void test_cat_decoded_index_lifecycle()
{
    struct cmt *source;
    struct cmt *destination;
    struct cmt *appended;
    struct cmt_gauge *gauge;
    struct cmt_gauge *merged;
    struct cmt_gauge *extra;
    struct cmt_metric *metric;
    struct cfl_list *head;
    struct cfl_list *tmp;
    double value;
    char *keys[] = {"first", "second"};
    char *left[] = {"ab", "c"};
    char *right[] = {"a", "bc"};
    char *late[] = {"late", NULL};
    char *missing[] = {"missing", ""};

    source = cmt_create();
    TEST_ASSERT(source != NULL);
    gauge = cmt_gauge_create(source, "test", "cat", "index", "Index lifecycle", 2, keys);
    TEST_ASSERT(gauge != NULL);
    /* These label tuples deliberately produce the same concatenated hash input. */
    TEST_ASSERT(cmt_gauge_set(gauge, 10, 1, 2, left) == 0);
    TEST_ASSERT(cmt_gauge_set(gauge, 10, 2, 2, right) == 0);
    destination = decode_copy(source);
    merged = cfl_list_entry(destination->gauges.next, struct cmt_gauge, _head);
    TEST_CHECK(merged->map->indexed_metric_count == 0);
    TEST_ASSERT(cmt_gauge_get_val(merged, 2, left, &value) == 0);
    TEST_CHECK(value == 1);
    TEST_ASSERT(cmt_gauge_get_val(merged, 2, right, &value) == 0);
    TEST_CHECK(value == 2);
    TEST_CHECK(merged->map->indexed_metric_count == 2);
    TEST_CHECK(cmt_gauge_get_val(merged, 2, missing, &value) != 0);
    TEST_ASSERT(cmt_cat(destination, source) == 0);
    TEST_CHECK(cfl_list_size(&merged->map->metrics) == 2);
    cmt_destroy(source);

    source = cmt_create();
    TEST_ASSERT(source != NULL);
    gauge = cmt_gauge_create(source, "test", "cat", "index", "Index lifecycle", 2, keys);
    TEST_ASSERT(gauge != NULL);
    TEST_ASSERT(cmt_gauge_set(gauge, 20, 3, 2, late) == 0);
    appended = decode_copy(source);
    extra = cfl_list_entry(appended->gauges.next, struct cmt_gauge, _head);
    /* Exercise a decoder-style append after lookups have already indexed a prefix. */
    cfl_list_foreach_safe(head, tmp, &extra->map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        TEST_CHECK(!metric->hash_indexed);
        cfl_list_del(head);
        cfl_list_add(head, &merged->map->metrics);
    }
    cmt_destroy(appended);
    cmt_destroy(source);
    TEST_ASSERT(cmt_gauge_get_val(merged, 2, late, &value) == 0);
    TEST_CHECK(value == 3);
    TEST_CHECK(merged->map->indexed_metric_count == 3);
    metric = cmt_map_metric_get(&merged->opts, merged->map, 2, late, CMT_FALSE);
    TEST_ASSERT(metric != NULL);
    cmt_map_metric_destroy(metric);
    TEST_CHECK(cmt_gauge_get_val(merged, 2, late, &value) != 0);
    TEST_ASSERT(cmt_gauge_get_val(merged, 2, right, &value) == 0);
    TEST_CHECK(value == 2);
    TEST_ASSERT(cmt_gauge_set(merged, 30, 4, 2, missing) == 0);
    cmt_map_metrics_expire(merged->map, 20);
    TEST_CHECK(cfl_list_size(&merged->map->metrics) == 1);
    TEST_CHECK(cmt_gauge_get_val(merged, 2, left, &value) != 0);
    TEST_ASSERT(cmt_gauge_get_val(merged, 2, missing, &value) == 0);
    TEST_CHECK(value == 4);
    cmt_map_metrics_expire(merged->map, 40);
    TEST_CHECK(cfl_list_size(&merged->map->metrics) == 0);
    TEST_ASSERT(cmt_gauge_set(merged, 50, 5, 2, late) == 0);
    TEST_ASSERT(cmt_gauge_get_val(merged, 2, late, &value) == 0);
    TEST_CHECK(value == 5);
    cmt_destroy(destination);
}

void test_cat_many_contexts()
{
    int batch;
    int index;
    double value;
    char label[32];
    char *keys[] = {"series"};
    char *values[] = {label};
    struct cmt *source;
    struct cmt *destination;
    struct cmt_gauge *gauge;

    destination = cmt_create();
    TEST_ASSERT(destination != NULL);
    for (batch = 0; batch < 10; batch++) {
        source = cmt_create();
        TEST_ASSERT(source != NULL);
        gauge = cmt_gauge_create(source, "test", "cat", "many", "Many series", 1, keys);
        TEST_ASSERT(gauge != NULL);
        for (index = 0; index < 1000; index++) {
            snprintf(label, sizeof(label), "%d", batch * 1000 + index);
            TEST_ASSERT(cmt_gauge_set(gauge, 100, batch * 1000 + index, 1, values) == 0);
        }
        TEST_ASSERT(cmt_cat(destination, source) == 0);
        /* Repeated concatenation must update existing identities, not duplicate them. */
        TEST_ASSERT(cmt_cat(destination, source) == 0);
        cmt_destroy(source);
    }
    TEST_CHECK(cfl_list_size(&destination->gauges) == 1);
    gauge = cfl_list_entry(destination->gauges.next, struct cmt_gauge, _head);
    TEST_CHECK(cfl_list_size(&gauge->map->metrics) == 10000);
    for (index = 0; index < 10000; index++) {
        snprintf(label, sizeof(label), "%d", index);
        TEST_ASSERT(cmt_gauge_get_val(gauge, 1, values, &value) == 0);
        TEST_CHECK(value == index);
    }
    cmt_destroy(destination);
}

static struct cmt *create_otlp_gauge_context(char *label, double value, uint64_t flags)
{
    struct cmt *cmt;
    struct cmt_gauge *gauge;
    struct cmt_metric *sample;

    cmt = cmt_create();
    if (cmt == NULL) {
        return NULL;
    }

    gauge = cmt_gauge_create(cmt, "", "", "otlp_gauge", "otlp gauge",
                             1, (char *[]) {"key"});
    if (gauge == NULL ||
        cmt_gauge_set(gauge, 100, value, 1, (char *[]) {label}) != 0) {
        cmt_destroy(cmt);
        return NULL;
    }

    sample = cfl_list_entry_first(&gauge->map->metrics, struct cmt_metric, _head);
    sample->otlp_metadata = cfl_kvlist_create();
    if (sample->otlp_metadata == NULL ||
        cfl_kvlist_insert_uint64(sample->otlp_metadata, "flags", flags) != 0) {
        cmt_destroy(cmt);
        return NULL;
    }

    return cmt;
}

static uint64_t sample_flags(struct cmt_metric *sample)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(sample->otlp_metadata, "flags");
    if (value == NULL) {
        return UINT64_MAX;
    }
    if (value->type == CFL_VARIANT_UINT) {
        return value->data.as_uint64;
    }
    if (value->type == CFL_VARIANT_INT) {
        return (uint64_t) value->data.as_int64;
    }
    return UINT64_MAX;
}

/* Samples carrying OTLP metadata must merge by labels, never duplicate. */
void test_cat_otlp_metadata_samples_merge_by_labels()
{
    int ret;
    struct cmt *first;
    struct cmt *second;
    struct cmt *other;
    struct cmt *final;
    struct cmt_gauge *gauge;
    struct cmt_metric *sample;
    struct cmt_map_label *label;
    struct cfl_list *head;
    int found_v;
    int found_w;

    first = create_otlp_gauge_context("v", 1.0, 1);
    second = create_otlp_gauge_context("v", 2.0, 2);
    other = create_otlp_gauge_context("w", 3.0, 3);
    final = cmt_create();
    TEST_ASSERT(first != NULL && second != NULL && other != NULL && final != NULL);

    ret = cmt_cat(final, first);
    TEST_CHECK(ret == 0);
    ret = cmt_cat(final, second);
    TEST_CHECK(ret == 0);
    ret = cmt_cat(final, second);
    TEST_CHECK(ret == 0);

    TEST_CHECK(cfl_list_size(&final->gauges) == 1);
    gauge = cfl_list_entry_first(&final->gauges, struct cmt_gauge, _head);
    TEST_ASSERT(gauge != NULL);
    TEST_CHECK(cfl_list_size(&gauge->map->metrics) == 1);

    sample = cfl_list_entry_first(&gauge->map->metrics, struct cmt_metric, _head);
    TEST_CHECK(cmt_metric_get_value(sample) == 2.0);
    TEST_CHECK(sample_flags(sample) == 2);

    /* The merged sample remains reachable through the label index. */
    ret = cmt_gauge_set(gauge, 200, 5.0, 1, (char *[]) {"v"});
    TEST_CHECK(ret == 0);
    TEST_CHECK(cfl_list_size(&gauge->map->metrics) == 1);
    TEST_CHECK(cmt_metric_get_value(sample) == 5.0);

    /* A distinct label set is still appended. */
    ret = cmt_cat(final, other);
    TEST_CHECK(ret == 0);
    TEST_CHECK(cfl_list_size(&gauge->map->metrics) == 2);

    found_v = 0;
    found_w = 0;
    cfl_list_foreach(head, &gauge->map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);
        label = cfl_list_entry_first(&sample->labels, struct cmt_map_label, _head);
        if (strcmp(label->name, "v") == 0) {
            found_v++;
            TEST_CHECK(sample_flags(sample) == 2);
        }
        else if (strcmp(label->name, "w") == 0) {
            found_w++;
            TEST_CHECK(sample_flags(sample) == 3);
            TEST_CHECK(cmt_metric_get_value(sample) == 3.0);
        }
    }
    TEST_CHECK(found_v == 1);
    TEST_CHECK(found_w == 1);

    cmt_destroy(first);
    cmt_destroy(second);
    cmt_destroy(other);
    cmt_destroy(final);
}

/* Distinct OTLP data points of one series (different time windows) are kept,
 * but concatenating them again must not duplicate either of them. */
void test_cat_otlp_metadata_distinct_points_kept()
{
    int ret;
    int pass;
    struct cmt *source;
    struct cmt *final;
    struct cmt_gauge *gauge;
    struct cmt_metric *first;
    struct cmt_metric *second;
    struct cmt_map_label *label;
    struct cfl_list *head;
    uint64_t timestamps;

    source = create_otlp_gauge_context("v", 1.0, 1);
    TEST_ASSERT(source != NULL);

    /* Add a second data point of the same series at a later time, the way
     * the OTLP decoder appends independent points. */
    gauge = cfl_list_entry_first(&source->gauges, struct cmt_gauge, _head);
    first = cfl_list_entry_first(&gauge->map->metrics, struct cmt_metric, _head);
    second = calloc(1, sizeof(struct cmt_metric));
    TEST_ASSERT(second != NULL);
    cfl_list_init(&second->labels);
    cfl_list_init(&second->_hash_head);
    second->map = gauge->map;
    second->hash = first->hash;
    cfl_list_add(&second->_head, &gauge->map->metrics);
    TEST_ASSERT(cmt_map_metric_get(&gauge->opts, gauge->map, 1, (char *[]) {"v"},
                                   CMT_FALSE) == first);
    label = calloc(1, sizeof(struct cmt_map_label));
    TEST_ASSERT(label != NULL);
    label->name = cfl_sds_create("v");
    TEST_ASSERT(label->name != NULL);
    cfl_list_add(&label->_head, &second->labels);
    cmt_metric_set_double(second, 200, 2.0);
    second->otlp_metadata = cfl_kvlist_create();
    TEST_ASSERT(second->otlp_metadata != NULL);
    TEST_ASSERT(cfl_kvlist_insert_uint64(second->otlp_metadata, "flags", 2) == 0);

    final = cmt_create();
    TEST_ASSERT(final != NULL);

    for (pass = 0; pass < 2; pass++) {
        ret = cmt_cat(final, source);
        TEST_CHECK(ret == 0);

        gauge = cfl_list_entry_first(&final->gauges, struct cmt_gauge, _head);
        TEST_ASSERT(gauge != NULL);
        TEST_CHECK(cfl_list_size(&gauge->map->metrics) == 2);

        timestamps = 0;
        cfl_list_foreach(head, &gauge->map->metrics) {
            first = cfl_list_entry(head, struct cmt_metric, _head);
            timestamps += cmt_metric_get_timestamp(first);
            if (cmt_metric_get_timestamp(first) == 100) {
                TEST_CHECK(sample_flags(first) == 1);
                TEST_CHECK(cmt_metric_get_value(first) == 1.0);
            }
            else {
                TEST_CHECK(sample_flags(first) == 2);
                TEST_CHECK(cmt_metric_get_value(first) == 2.0);
            }
        }
        TEST_CHECK(timestamps == 300);
    }

    cmt_destroy(source);
    cmt_destroy(final);
}

TEST_LIST = {
    {"cat_otlp_metadata_distinct_points_kept", test_cat_otlp_metadata_distinct_points_kept},
    {"cat_otlp_metadata_samples_merge_by_labels", test_cat_otlp_metadata_samples_merge_by_labels},
    {"cat_many_contexts", test_cat_many_contexts},
    {"cat_decoded_index_lifecycle", test_cat_decoded_index_lifecycle},
    {"cat_static_labels_source_dynamic_conflict", test_cat_static_labels_source_dynamic_conflict},
    {"cat_static_labels_dynamic_conflict", test_cat_static_labels_dynamic_conflict},
    {"cat_static_labels_chain", test_cat_static_labels_chain},
    {"cat_static_labels_merge", test_cat_static_labels_merge},
    {"cat_static_labels_conflict", test_cat_static_labels_conflict},
    {"cat_static_labels_empty", test_cat_static_labels_empty},
    {"cat", test_cat},
    {"duplicate_metrics", test_duplicate_metrics},
    {"histogram_empty_concatenation", test_histogram_empty_concatenation},
    {"histogram_mismatched_buckets", test_histogram_mismatched_buckets},
    {"histogram_empty_to_populated", test_histogram_empty_to_populated},
    {"histogram_populated_to_empty", test_histogram_populated_to_empty},
    {"exp_histogram_preserves_aggregation_type", test_exp_histogram_preserves_aggregation_type},
    {"summary_concatenation_preserves_series", test_summary_concatenation_preserves_series},
    {"summary_concatenation_rejects_mismatched_label_schema",
     test_summary_concatenation_rejects_mismatched_label_schema},
    { 0 }
};
