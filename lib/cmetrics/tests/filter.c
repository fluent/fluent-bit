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
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_filter.h>

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

struct cmt *generate_filter_test_data()
{
    int i;
    struct cmt *cmt;
    uint64_t val;
    uint64_t ts;
    double sum;
    uint64_t count;
    double q[6];
    double r[6];

    struct cmt_counter *c;
    struct cmt_gauge *g;
    struct cmt_untyped *u;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *buckets;
    struct cmt_summary *s;

    /* cmetrics */
    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    c = cmt_counter_create(cmt, "cmetrics", "test", "cat_counter", "first counter",
                           2, (char *[]) {"label1", "label2"});
    TEST_CHECK(c != NULL);

    g = cmt_gauge_create(cmt, "cmetrics", "test", "cat_gauge", "first gauge",
                         2, (char *[]) {"label3", "label4"});
    TEST_CHECK(g != NULL);

    u = cmt_untyped_create(cmt, "cmetrics", "test", "cat_untyped", "first untyped",
                           2, (char *[]) {"hostname", "net"});
    TEST_CHECK(u != NULL);


    ts = cfl_time_now();
    cmt_counter_set(c, ts, 1.1, 2, (char *[]) {"aaa", "bbb"});

    ts = cfl_time_now();
    cmt_gauge_set(g, ts, 1.2, 2, (char *[]) {"yyy", "xxx"});

    ts = cfl_time_now();
    cmt_untyped_set(u, ts, 1.3, 2, (char *[]) {"localhost", "eth0"});

    ts = cfl_time_now();
    cmt_untyped_set(u, ts, 1.8, 2, (char *[]) {"dev", "enp1s0"});

    c = cmt_counter_create(cmt, "cmetrics", "test", "cat_counter", "second counter",
                           2, (char *[]) {"label1", "label2"});
    TEST_CHECK(c != NULL);

    g = cmt_gauge_create(cmt, "cmetrics", "test", "cat_gauge", "second gauge",
                         2, (char *[]) {"label3", "label4"});
    TEST_CHECK(g != NULL);

    ts = cfl_time_now();
    cmt_counter_set(c, ts, 2.1, 2, (char *[]) {"ccc", "ddd"});

    /* no labels */
    cmt_counter_set(c, ts, 5, 0, NULL);

    ts = cfl_time_now();
    cmt_gauge_add(g, ts, 10, 2, (char *[]) {"tyu", "iop"});

    /* Create buckets */
    buckets = cmt_histogram_buckets_create(11,
                                           0.005, 0.01, 0.025, 0.05,
                                           0.1, 0.25, 0.5, 1.0, 2.5,
                                           5.0, 10.0);
    TEST_CHECK(buckets != NULL);

    /* Create a histogram metric type */
    h = cmt_histogram_create(cmt,
                             "k8s", "network", "load", "Network load",
                             buckets,
                             1, (char *[]) {"my_label"});
    TEST_CHECK(h != NULL);

    ts = cfl_time_now();

    for (i = 0; i < sizeof(hist_observe_values)/(sizeof(double)); i++) {
        val = hist_observe_values[i];
        cmt_histogram_observe(h, ts, val, 1, (char *[]) {"another_hist"});
    }

    for (i = 0; i < sizeof(hist_observe_values)/(sizeof(double)); i++) {
        val = hist_observe_values[i];
        cmt_histogram_observe(h, ts, val, 1, (char *[]) {"my_label"});
    }

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

    /* Create a summary metric type */
    s = cmt_summary_create(cmt,
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

    return cmt;
}

void test_filter()
{
    int ret;
    cfl_sds_t text;
    struct cmt *cmt;
    struct cmt *cmt2;
    struct cmt *cmt3;
    struct cmt *cmt4;
    struct cmt *cmt5;
    struct cmt *cmt6;
    int flags = 0;
    char *fqname;
    char *label_key;

    cmt = generate_filter_test_data();

    text = cmt_encode_text_create(cmt);
    printf("[Not filtered] ====>\n%s\n", text);

    cmt_encode_text_destroy(text);

    cmt2 = cmt_create();
    TEST_CHECK(cmt2 != NULL);

    /* filter with fqname (SUBSTRING) */
    fqname = "counter";
    flags |= CMT_FILTER_SUBSTRING;
    ret = cmt_filter(cmt2, cmt, fqname, NULL,
                     NULL, NULL, flags);
    TEST_CHECK(ret == 0);
    /* check output (fqname) */
    text = cmt_encode_text_create(cmt2);
    printf("[substring matched with \"%s\" in fqname] ====>\n%s\n", fqname, text);

    cmt_encode_text_destroy(text);

    /* reset flags */
    flags = 0;

    cmt3 = cmt_create();
    TEST_CHECK(cmt3 != NULL);

    /* filter with fqname (INCLUDE & PREFIX) */
    fqname = "spring";
    flags |= CMT_FILTER_PREFIX;
    ret = cmt_filter(cmt3, cmt, fqname, NULL,
                     NULL, NULL, flags);
    TEST_CHECK(ret == 0);

    /* check output (fqname) */
    text = cmt_encode_text_create(cmt3);
    printf("[prefix matched with \"%s\" in fqname] ====>\n%s\n", fqname, text);

    cmt_encode_text_destroy(text);

    /* reset flags */
    flags = 0;

    cmt4 = cmt_create();
    TEST_CHECK(cmt4 != NULL);

    /* filter with fqname (INCLUDE & SUBSTRING) */
    fqname = "load";
    flags |= CMT_FILTER_SUBSTRING;
    ret = cmt_filter(cmt4, cmt, fqname, NULL,
                     NULL, NULL, flags);
    TEST_CHECK(ret == 0);

    /* check output (fqname) */
    text = cmt_encode_text_create(cmt4);
    printf("[substring matched with \"%s\" in fqname] ====>\n%s\n", fqname, text);

    cmt_encode_text_destroy(text);

    cmt5 = cmt_create();
    TEST_CHECK(cmt5 != NULL);

    /* reset flags */
    flags = 0;

    /* filter with label_key (EXCLUDE & PREFIX) */
    label_key = "host";
    flags |= CMT_FILTER_PREFIX;
    ret = cmt_filter(cmt5, cmt, NULL, label_key,
                     NULL, NULL, flags);
    TEST_CHECK(ret == 0);

    /* check output (label_key) */
    text = cmt_encode_text_create(cmt5);
    printf("[prefix matched with \"%s\" in label key] ====>\n%s\n", label_key, text);

    cmt_encode_text_destroy(text);

    cmt6 = cmt_create();
    TEST_CHECK(cmt6 != NULL);

    /* reset flags */
    flags = 0;

    /* filter with label_key (EXCLUDE & SUBSTRING) */
    label_key = "label";
    flags |= CMT_FILTER_EXCLUDE;
    flags |= CMT_FILTER_SUBSTRING;
    ret = cmt_filter(cmt6, cmt, NULL, label_key,
                     NULL, NULL, flags);
    TEST_CHECK(ret == 0);

    /* check output (label_key) */
    text = cmt_encode_text_create(cmt6);
    printf("[exclude with \"%s\" in label key] ====>\n%s\n", label_key, text);

    cmt_encode_text_destroy(text);

    /* destroy contexts */
    cmt_destroy(cmt);
    cmt_destroy(cmt2);
    cmt_destroy(cmt3);
    cmt_destroy(cmt4);
    cmt_destroy(cmt5);
    cmt_destroy(cmt6);
}

void test_filter_with_label_key_value_pairs()
{
    int ret;
    cfl_sds_t text;
    struct cmt *cmt;
    struct cmt *cmt2;
    struct cmt *cmt3;
    struct cmt *cmt4;
    struct cmt *cmt5;
    struct cmt *cmt6;
    char *label_key;
    char *label_value;
    char *tmp = NULL;

    cmt = generate_filter_test_data();

    text = cmt_encode_text_create(cmt);
    printf("[Not filtered] ====>\n%s\n", text);

    cmt_encode_text_destroy(text);

    cmt2 = cmt_create();
    TEST_CHECK(cmt2 != NULL);

    label_key = "label3";
    label_value = "tyu";

    /* filter with label key-value */
    ret = cmt_filter_with_label_pair(cmt2, cmt, label_key, label_value);
    TEST_CHECK(ret == 0);
    /* check output (fqname) */
    text = cmt_encode_text_create(cmt2);
    printf("[label matched with label key-value pair: \"%s\", \"%s\" ] ====>\n%s\n",
           label_key, label_value, text);

    tmp = strstr(text, "label3=\"tyu\"");
    TEST_CHECK(tmp == NULL);
    tmp = strstr(text, "label3=\"yyy\"");
    TEST_CHECK(tmp != NULL);

    cmt_encode_text_destroy(text);

    cmt3 = cmt_create();
    TEST_CHECK(cmt3 != NULL);

    label_key = "label1";
    label_value = "aaa";

    /* filter with label key-value */
    ret = cmt_filter_with_label_pair(cmt3, cmt, label_key, label_value);
    TEST_CHECK(ret == 0);
    /* check output (fqname) */
    text = cmt_encode_text_create(cmt3);
    printf("[label matched with label key-value pair: \"%s\", \"%s\" ] ====>\n%s\n",
           label_key, label_value, text);

    tmp = strstr(text, "label1=\"aaa\"");
    TEST_CHECK(tmp == NULL);
    tmp = strstr(text, "label1=\"ccc\"");
    TEST_CHECK(tmp != NULL);

    cmt_encode_text_destroy(text);

    cmt4 = cmt_create();
    TEST_CHECK(cmt4 != NULL);

    label_key = "net";
    label_value = "enp1s0";

    /* filter with label key-value */
    ret = cmt_filter_with_label_pair(cmt4, cmt, label_key, label_value);
    TEST_CHECK(ret == 0);
    /* check output (fqname) */
    text = cmt_encode_text_create(cmt4);
    printf("[label matched with label key-value pair: \"%s\", \"%s\" ] ====>\n%s\n",
           label_key, label_value, text);

    tmp = strstr(text, "net=\"enp1s0\"");
    TEST_CHECK(tmp == NULL);
    tmp = strstr(text, "net=\"eth0\"");
    TEST_CHECK(tmp != NULL);

    cmt_encode_text_destroy(text);

    cmt5 = cmt_create();
    TEST_CHECK(cmt5 != NULL);

    label_key = "exception";
    label_value = "none";

    /* filter with label key-value */
    ret = cmt_filter_with_label_pair(cmt5, cmt, label_key, label_value);
    TEST_CHECK(ret == 0);
    /* check output (fqname) */
    text = cmt_encode_text_create(cmt5);
    printf("[label matched with label key-value pair: \"%s\", \"%s\" ] ====>\n%s\n",
           label_key, label_value, text);

    tmp = strstr(text, "exception=\"none\"");
    TEST_CHECK(tmp == NULL);
    tmp = strstr(text, "net=\"eth0\"");
    TEST_CHECK(tmp != NULL);

    cmt_encode_text_destroy(text);

    cmt6 = cmt_create();
    TEST_CHECK(cmt6 != NULL);

    label_key = "my_label";
    label_value = "another_hist";

    /* filter with label key-value */
    ret = cmt_filter_with_label_pair(cmt6, cmt, label_key, label_value);
    TEST_CHECK(ret == 0);
    /* check output (fqname) */
    text = cmt_encode_text_create(cmt6);
    printf("[label matched with label key-value pair: \"%s\", \"%s\" ] ====>\n%s\n",
           label_key, label_value, text);

    tmp = strstr(text, "my_label=\"another_hist\"");
    TEST_CHECK(tmp == NULL);
    tmp = strstr(text, "my_label=\"my_label\"");
    TEST_CHECK(tmp != NULL);

    cmt_encode_text_destroy(text);

    /* destroy contexts */
    cmt_destroy(cmt);
    cmt_destroy(cmt2);
    cmt_destroy(cmt3);
    cmt_destroy(cmt4);
    cmt_destroy(cmt5);
    cmt_destroy(cmt6);
}


TEST_LIST = {
    {"filter", test_filter},
    {"filter_with_label_pair", test_filter_with_label_key_value_pairs},
    { 0 }
};
