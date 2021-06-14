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
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_encode_prometheus.h>

#include "cmt_tests.h"

void test_counter()
{
    int ret;
    double val = 1;
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_counter *c;

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create a counter metric type */
    c = cmt_counter_create(cmt, "kubernetes", "network", "load", "Network load",
                           0, NULL);
    TEST_CHECK(c != NULL);

    /* Timestamp */
    ts = cmt_time_now();

    /* Default value */
    ret = cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 0.0);

    /* Increment by one */
    cmt_counter_inc(c, ts, 0, NULL);
    ret = cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK(val == 1.0);

    /* Add two */
    cmt_counter_add(c, ts, 2, 0, NULL);
    ret = cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 3.0);

    cmt_destroy(cmt);
}

void test_labels()
{
    int ret;
    double val;
    uint64_t ts;
    cmt_sds_t prom;
    struct cmt *cmt;
    struct cmt_counter *c;

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create a counter metric type */
    c = cmt_counter_create(cmt, "kubernetes", "network", "load", "Network load",
                           2, (char *[]) {"hostname", "app"});
    TEST_CHECK(c != NULL);

    /* Timestamp */
    ts = cmt_time_now();

    /*
     * Test 1: hash zero (no labels)
     * -----------------------------
     */

    /* Default value for hash zero */
    ret = cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 0.0);

    /* Increment hash zero by 1 */
    ret = cmt_counter_inc(c, ts, 0, NULL);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 0.0);

    /* Add two */
    ret = cmt_counter_add(c, ts, 2, 0, NULL);
    TEST_CHECK(ret == 0);

    /* Check that hash zero val is 3.0 */
    ret = cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 3.0);

    /*
     * Test 2: custom labels
     * ---------------------
     */

    /* Increment custom metric */
    ret = cmt_counter_inc(c, ts, 2, (char *[]) {"localhost", "cmetrics"});
    TEST_CHECK(ret == 0);

    /* Check val = 1 */
    ret = cmt_counter_get_val(c, 2, (char *[]) {"localhost", "cmetrics"}, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 1.000);

    /* Add 10 to another metric using a different second label */
    ret = cmt_counter_add(c, ts, 10.55, 2, (char *[]) {"localhost", "test"});
    TEST_CHECK(ret == 0);

    /* Validate the value */
    ret = cmt_counter_get_val(c, 2, (char *[]) {"localhost", "test"}, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 10.55);

    /* Valid counter set */
    ret = cmt_counter_set(c, ts, 12.15, 2, (char *[]) {"localhost", "test"});
    TEST_CHECK(ret == 0);

    /* Invalid counter set */
    ret = cmt_counter_set(c, ts, 1, 2, (char *[]) {"localhost", "test"});
    TEST_CHECK(ret == -1);

    printf("\n");

    prom = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    printf("%s\n", prom);
    cmt_encode_prometheus_destroy(prom);
    cmt_destroy(cmt);
}

TEST_LIST = {
    {"basic", test_counter},
    {"labels", test_labels},
    { 0 }
};
