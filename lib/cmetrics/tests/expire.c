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
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_encode_prometheus.h>

#include "cmt_tests.h"

void test_expire_counter()
{
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_counter *c;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create a counter metric type */
    c = cmt_counter_create(cmt, "k8s", "network", "uptime", "Network Uptime", 1, (char *[]) {"host"});
    TEST_CHECK(c != NULL);

    /* Timestamp */
    ts = cfl_time_now();

    cmt_counter_inc(c, ts, 1, (char *[]){"valid"});
    cmt_counter_inc(c, ts-10, 1, (char *[]){"expire"});

    TEST_CHECK(cfl_list_size(&c->map->metrics) == 2);
    cmt_expire(cmt, ts-1);
    TEST_CHECK(cfl_list_size(&c->map->metrics) == 1);

    cmt_destroy(cmt);
}

void test_expire_gauge()
{
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_gauge *g;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create a gauge metric type */
    g = cmt_gauge_create(cmt, "k8s", "network", "load", "Network load", 1, (char *[]) {"host"});
    TEST_CHECK(g != NULL);

    /* Timestamp */
    ts = cfl_time_now();

    cmt_gauge_set(g, ts, 50, 1, (char *[]){"valid"});
    cmt_gauge_set(g, ts-10, 50, 1, (char *[]){"expire"});

    TEST_CHECK(cfl_list_size(&g->map->metrics) == 2);
    cmt_expire(cmt, ts-1);
    TEST_CHECK(cfl_list_size(&g->map->metrics) == 1);

    cmt_destroy(cmt);
}

void test_expire_histogram()
{
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_histogram *h;
    struct cmt_histogram_buckets *buckets;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create buckets */
    buckets = cmt_histogram_buckets_create(11,
                                           0.005, 0.01, 0.025, 0.05,
                                           0.1, 0.25, 0.5, 1.0, 2.5,
                                           5.0, 10.0);
    TEST_CHECK(buckets != NULL);

    /* Create a histogram metric type */
    h = cmt_histogram_create(cmt,
                             "k8s", "network", "uptime", "Network Uptime",
                             buckets,
                             1, (char *[]) {"host"});
    TEST_CHECK(h != NULL);

    /* Timestamp */
    ts = cfl_time_now();

    cmt_histogram_observe(h, ts, 1.0, 1, (char *[]){"valid"});
    cmt_histogram_observe(h, ts-10, 1.0, 1, (char *[]){"expire"});

    TEST_CHECK(cfl_list_size(&h->map->metrics) == 2);
    cmt_expire(cmt, ts-1);
    TEST_CHECK(cfl_list_size(&h->map->metrics) == 1);

    cmt_destroy(cmt);
}

void test_expire_summary()
{
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_summary *s;
    double quantiles[6];
    double revised[6];
    double sum;
    uint64_t count;

    /* set quantiles, no labels */
    quantiles[0] = 0.1;
    quantiles[1] = 0.2;
    quantiles[2] = 0.3;
    quantiles[3] = 0.4;
    quantiles[4] = 0.5;
    quantiles[5] = 1.0;

    revised[0] = 1.0;
    revised[1] = 2.0;
    revised[2] = 3.0;
    revised[3] = 4.0;
    revised[4] = 5.0;
    revised[5] = 6.0;

    count = 10;
    sum   = 51.612894511314444;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create a summary metric type */
    s = cmt_summary_create(cmt,
                             "k8s", "network", "uptime", "Network Uptime",
                             6,
                             quantiles,
                             1, (char *[]) {"host"});
    TEST_CHECK(s != NULL);

    /* Timestamp */
    ts = cfl_time_now();

    cmt_summary_set_default(s, ts, revised, sum, count, 1, (char *[]){"valid"});
    cmt_summary_set_default(s, ts-10, revised, sum, count, 1, (char *[]){"expire"});

    TEST_CHECK(cfl_list_size(&s->map->metrics) == 2);
    cmt_expire(cmt, ts-1);
    TEST_CHECK(cfl_list_size(&s->map->metrics) == 1);

    cmt_destroy(cmt);
}

void test_expire_untyped()
{
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_untyped *u;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    u = cmt_untyped_create(cmt, "cmetrics", "test", "cat_untyped", "first untyped",
                           2, (char *[]) {"label5", "label6"});
    TEST_CHECK(u != NULL);

    /* Timestamp */
    ts = cfl_time_now();

    cmt_untyped_set(u, ts, 1.3, 2, (char *[]) {"first", "valid"});
    cmt_untyped_set(u, ts-10, 1.3, 2, (char *[]) {"second", "expire"});

    TEST_CHECK(cfl_list_size(&u->map->metrics) == 2);
    cmt_expire(cmt, ts-1);
    TEST_CHECK(cfl_list_size(&u->map->metrics) == 1);

    cmt_destroy(cmt);
}

void test_epxire_exp_histogram()
{
    uint64_t ts;
    struct cmt *cmt;
    uint64_t positive[3] = {3, 5, 7};
    uint64_t negative[2] = {2, 1};
    int result;
    struct cmt_exp_histogram *exp_histogram;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    exp_histogram = cmt_exp_histogram_create(cmt,
                                             "cm", "native", "exp_hist", "native exp histogram",
                                             1, (char *[]) {"endpoint"});
    TEST_CHECK(exp_histogram != NULL);

    if (exp_histogram == NULL) {
        return;
    }

    /* Timestamp */
    ts = cfl_time_now();

    result = cmt_exp_histogram_set_default(exp_histogram,
                                           ts,
                                           2,
                                           11,
                                           0.0,
                                           -2,
                                           3,
                                           positive,
                                           -1,
                                           2,
                                           negative,
                                           CMT_TRUE,
                                           42.25,
                                           29,
                                           1,
                                           (char *[]) {"api"});
    TEST_CHECK(result == 0);
    result = cmt_exp_histogram_set_default(exp_histogram,
                                           ts-10,
                                           2,
                                           11,
                                           0.0,
                                           -2,
                                           3,
                                           positive,
                                           -1,
                                           2,
                                           negative,
                                           CMT_TRUE,
                                           42.25,
                                           29,
                                           1,
                                           (char *[]) {"http"});
    TEST_CHECK(result == 0);

    TEST_CHECK(cfl_list_size(&exp_histogram->map->metrics) == 2);
    cmt_expire(cmt, ts-1);
    TEST_CHECK(cfl_list_size(&exp_histogram->map->metrics) == 1);

    cmt_destroy(cmt);
}

void test_expire_off_by_one()
{
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_counter *c;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create a counter metric type */
    c = cmt_counter_create(cmt, "k8s", "network", "uptime", "Network Uptime", 1, (char *[]) {"host"});
    TEST_CHECK(c != NULL);

    /* Timestamp */
    ts = cfl_time_now();

    cmt_counter_inc(c, ts, 1, (char *[]){"fullyvalid"});
    cmt_counter_inc(c, ts-1, 1, (char *[]){"bordervalid"});
    cmt_counter_inc(c, ts-2, 1, (char *[]){"borderexpire"});

    TEST_CHECK(cfl_list_size(&c->map->metrics) == 3);
    cmt_expire(cmt, ts-2);
    TEST_CHECK(cfl_list_size(&c->map->metrics) == 3);
    cmt_expire(cmt, ts-1);
    TEST_CHECK(cfl_list_size(&c->map->metrics) == 2);
    cmt_expire(cmt, ts);
    TEST_CHECK(cfl_list_size(&c->map->metrics) == 1);
    cmt_expire(cmt, ts+1);
    TEST_CHECK(cfl_list_size(&c->map->metrics) == 0);

    cmt_destroy(cmt);
}

void test_expire_static_metrics()
{
    uint64_t                      ts;
    struct cmt                   *cmt;
    struct cmt_counter           *counter;
    struct cmt_histogram         *histogram;
    struct cmt_histogram_buckets *buckets;

    cmt = cmt_create();
    TEST_ASSERT(cmt != NULL);
    ts = cfl_time_now();

    counter = cmt_counter_create(cmt, "test", "expire", "static_counter",
                                 "Static counter expiration", 0, NULL);
    TEST_ASSERT(counter != NULL);
    TEST_ASSERT(cmt_counter_set(counter, ts - 10, 3, 0, NULL) == 0);

    buckets = cmt_histogram_buckets_create(2, 1.0, 5.0);
    TEST_ASSERT(buckets != NULL);
    histogram = cmt_histogram_create(cmt, "test", "expire", "static_histogram",
                                     "Static histogram expiration", buckets,
                                     0, NULL);
    TEST_ASSERT(histogram != NULL);
    TEST_ASSERT(cmt_histogram_observe(histogram, ts - 10, 2.0,
                                     0, NULL) == 0);
    TEST_CHECK(histogram->map->metric.hist_buckets != NULL);

    cmt_expire(cmt, ts - 1);

    TEST_CHECK(counter->map->metric_static_set == CMT_FALSE);
    TEST_CHECK(histogram->map->metric_static_set == CMT_FALSE);
    TEST_CHECK(histogram->map->metric.hist_buckets == NULL);

    TEST_ASSERT(cmt_counter_set(counter, ts, 4, 0, NULL) == 0);
    TEST_ASSERT(cmt_histogram_observe(histogram, ts, 2.0, 0, NULL) == 0);
    TEST_CHECK(counter->map->metric_static_set == CMT_TRUE);
    TEST_CHECK(histogram->map->metric_static_set == CMT_TRUE);
    TEST_CHECK(histogram->map->metric.hist_buckets != NULL);
    TEST_CHECK(cmt_metric_get_timestamp(&counter->map->metric) == ts);
    TEST_CHECK(cmt_metric_get_timestamp(&histogram->map->metric) == ts);

    cmt_destroy(cmt);
}

void test_destroy_unindexed_last_metric()
{
    struct cmt *cmt;
    struct cmt_counter *counter;
    struct cmt_metric *metric;

    cmt = cmt_create();
    TEST_ASSERT(cmt != NULL);
    counter = cmt_counter_create(cmt, "test", "map", "unindexed",
                                 "Unindexed metric destruction", 1,
                                 (char *[]) {"label"});
    TEST_ASSERT(counter != NULL);

    metric = calloc(1, sizeof(struct cmt_metric));
    TEST_ASSERT(metric != NULL);
    cfl_list_init(&metric->labels);
    cfl_list_init(&metric->_hash_head);
    metric->map = counter->map;
    cfl_list_add(&metric->_head, &counter->map->metrics);
    counter->map->last_metric = metric;

    cmt_map_metric_destroy(metric);

    TEST_CHECK(counter->map->last_metric == NULL);
    TEST_CHECK(cfl_list_size(&counter->map->metrics) == 0);

    cmt_destroy(cmt);
}

TEST_LIST = {
    {"expire_counter"    ,   test_expire_counter},
    {"expire_gauge",         test_expire_gauge},
    {"expire_histogram",     test_expire_histogram},
    {"expire_summary",       test_expire_summary},
    {"expire_untyped",       test_expire_untyped},
    {"expire_exp_histogram", test_epxire_exp_histogram},
    {"expire_off_by_one",    test_expire_off_by_one},
    {"expire_static_metrics", test_expire_static_metrics},
    {"destroy_unindexed_last_metric", test_destroy_unindexed_last_metric},
    { 0 }
};
