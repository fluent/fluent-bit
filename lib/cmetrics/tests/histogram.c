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
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_map.h>
#include "cmt_tests.h"

#include <math.h>
#include <float.h>
#include <stdbool.h>

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

bool fequal(double a, double b)
{
    return (fabs(a - b) < (DBL_EPSILON * fabs(a + b)));
}

static void histogram_check(struct cmt_histogram *h,
                            int labels_count, char **labels_vals)
{
    int i;
    int ret;
    uint64_t val;
    struct cmt_metric *metric;

    /* retrieve the metric context */
    metric = cmt_map_metric_get(&h->opts, h->map,
                                labels_count, labels_vals, CMT_TRUE);
    TEST_CHECK(metric != NULL);

    /* check bucket values */
    for (i = 0; i < (sizeof(hist_buckets_values)/sizeof(uint64_t)); i++) {
        val = cmt_metric_hist_get_value(metric, i);
        TEST_CHECK(val == hist_buckets_values[i]);
    }

    /* check _count */
    TEST_CHECK(hist_count == cmt_metric_hist_get_count_value(metric));

    /* check _sum */
    ret = fequal(hist_sum, cmt_metric_hist_get_sum_value(metric));
    TEST_CHECK(ret != 0);
}

static int histogram_observe_all(struct cmt_histogram *h,
                                 uint64_t timestamp,
                                 int labels_count, char **labels_vals)
{
    int i;
    double val;

    for (i = 0; i < sizeof(hist_observe_values)/(sizeof(double)); i++) {
        val = hist_observe_values[i];
        cmt_histogram_observe(h, timestamp, val, labels_count, labels_vals);
    }

    return i;
}

static void prometheus_encode_test(struct cmt *cmt)
{
    cfl_sds_t buf;

    buf = cmt_encode_prometheus_create(cmt, CMT_FALSE);
    printf("\n%s\n", buf);
    cmt_encode_prometheus_destroy(buf);
}


void test_histogram()
{
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *buckets;

    cmt_initialize();

    /* Timestamp */
    ts = cfl_time_now();

    /* CMetrics context */
    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create buckets */
    buckets = cmt_histogram_buckets_create(11,
                                           0.005, 0.01, 0.025, 0.05,
                                           0.1, 0.25, 0.5, 1.0, 2.5,
                                           5.0, 10.0);
    TEST_CHECK(buckets != NULL);

    /* Create a gauge metric type */
    h = cmt_histogram_create(cmt,
                             "k8s", "network", "load", "Network load",
                             buckets,
                             1, (char *[]) {"my_label"});
    TEST_CHECK(h != NULL);

    /* no labels */
    histogram_observe_all(h, ts, 0, NULL);
    histogram_check(h, 0, NULL);
    prometheus_encode_test(cmt);

    /* static label: register static label for the context */
    cmt_label_add(cmt, "static", "test");
    histogram_check(h, 0, NULL);
    prometheus_encode_test(cmt);

    /* defined labels: add a custom label value */
    histogram_observe_all(h, ts, 1, (char *[]) {"val"});
    histogram_check(h, 1, (char *[]) {"val"});
    prometheus_encode_test(cmt);

    cmt_destroy(cmt);
}

void test_set_defaults()
{
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *buckets;

    cmt_initialize();

    /* Timestamp */
    ts = cfl_time_now();

    /* CMetrics context */
    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create buckets */
    buckets = cmt_histogram_buckets_default_create();
    TEST_CHECK(buckets != NULL);

    /* Create a gauge metric type */
    h = cmt_histogram_create(cmt,
                             "k8s", "network", "load", "Network load",
                             buckets,
                             1, (char *[]) {"my_label"});
    TEST_CHECK(h != NULL);

    /* set default buckets values / no labels */
    cmt_histogram_set_default(h, ts,
                              hist_buckets_values,
                              hist_sum, hist_count, 0, NULL);
    histogram_check(h, 0, NULL);
    prometheus_encode_test(cmt);

    /* static label: register static label for the context */
    cmt_label_add(cmt, "static", "test");
    histogram_check(h, 0, NULL);
    prometheus_encode_test(cmt);

    /* perform observation with labels */
    histogram_observe_all(h, ts, 1, (char *[]) {"val"});
    histogram_check(h, 1, (char *[]) {"val"});
    prometheus_encode_test(cmt);

    cmt_destroy(cmt);
}

TEST_LIST = {
    {"histogram"   , test_histogram},
    {"set_defaults", test_set_defaults},
    { 0 }
};
