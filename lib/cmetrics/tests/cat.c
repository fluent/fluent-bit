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
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_cat.h>

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

TEST_LIST = {
    {"cat", test_cat},
    { 0 }
};
