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
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_encode_prometheus.h>

#include "cmt_tests.h"

void test_gauge()
{
    int ret;
    double val;
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_gauge *g;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create a gauge metric type */
    g = cmt_gauge_create(cmt, "kubernetes", "network", "load", "Network load", 0, NULL);
    TEST_CHECK(g != NULL);

    /* Timestamp */
    ts = cfl_time_now();

    /* Default value */
    ret = cmt_gauge_get_val(g, 0, NULL, &val);
    TEST_CHECK(val == 0.0);

    /* Set a value of two */
    cmt_gauge_set(g, ts, 2.0, 0, NULL);
    ret = cmt_gauge_get_val(g, 0, NULL, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 2.0);

    /* Increment one */
    cmt_gauge_inc(g, ts, 0, NULL);
    ret = cmt_gauge_get_val(g, 0, NULL, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 3.0);

    /* Substract 2 */
    ret = cmt_gauge_sub(g, ts, 2, 0, NULL);
    TEST_CHECK(ret == 0);

    ret = cmt_gauge_get_val(g, 0, NULL, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 1.0);

    /* Decrement by one */
    ret = cmt_gauge_dec(g, ts, 0, NULL);
    TEST_CHECK(ret == 0);

    ret = cmt_gauge_get_val(g, 0, NULL, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 0.0);

    cmt_destroy(cmt);
}

void test_labels()
{
    int ret;
    double val;
    uint64_t ts;
    cfl_sds_t prom;
    struct cmt *cmt;
    struct cmt_gauge *g;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create a counter metric type */
    g = cmt_gauge_create(cmt, "kubernetes", "network", "load", "Network load",
                         2, (char *[]) {"hostname", "app"});
    TEST_CHECK(g != NULL);

    /* Timestamp */
    ts = cfl_time_now();

    /*
     * Test 1: hash zero (no labels)
     * -----------------------------
     */

    /* Default value for hash zero */
    ret = cmt_gauge_get_val(g, 0, NULL, &val);
    TEST_CHECK(ret == -1);

    /* Increment hash zero by 1 */
    ret = cmt_gauge_inc(g, ts, 0, NULL);
    TEST_CHECK(ret == 0);

    /* Check the new value */
    ret = cmt_gauge_get_val(g, 0, NULL, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 1.0);

    /* Add two */
    ret = cmt_gauge_add(g, ts, 2, 0, NULL);
    TEST_CHECK(ret == 0);

    /* Check that hash zero val is 3.0 */
    ret = cmt_gauge_get_val(g, 0, NULL, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 3.0);

    /*
     * Test 2: custom labels
     * ---------------------
     */

    /* Increment custom metric */
    ret = cmt_gauge_inc(g, ts, 2, (char *[]) {"localhost", "cmetrics"});
    TEST_CHECK(ret == 0);

    /* Check ret = 1 */
    ret = cmt_gauge_get_val(g, 2, (char *[]) {"localhost", "cmetrics"}, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 1.000);

    /* Add 10 to another metric using a different second label */
    ret = cmt_gauge_add(g, ts, 10, 2, (char *[]) {"localhost", "test"});
    TEST_CHECK(ret == 0);

    /* Validate the value */
    ret = cmt_gauge_get_val(g, 2, (char *[]) {"localhost", "test"}, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 10.00);

    /* Substract two */
    ret = cmt_gauge_sub(g, ts, 2.5, 2, (char *[]) {"localhost", "test"});
    TEST_CHECK(ret == 0);

    /* Validate the value */
    ret = cmt_gauge_get_val(g, 2, (char *[]) {"localhost", "test"}, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 7.50);

    printf("\n");
    prom = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    printf("%s\n", prom);
    cmt_encode_prometheus_destroy(prom);

    cmt_destroy(cmt);
}

TEST_LIST = {
    {"basic" , test_gauge},
    {"labels", test_labels},
    { 0 }
};
