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
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_encode_text.h>

#include "cmt_tests.h"

static struct cmt *generate_encoder_test_data()
{
    double val;
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_counter *c;

    printf("version: %s", cmt_version());
    cmt = cmt_create();

    c = cmt_counter_create(cmt, "kubernetes", "network", "load", "Network load",
                           2, (char *[]) {"hostname", "app"});

    ts = cfl_time_now();

    cmt_counter_get_val(c, 0, NULL, &val);
    cmt_counter_inc(c, ts, 0, NULL);
    cmt_counter_add(c, ts, 2, 0, NULL);
    cmt_counter_get_val(c, 0, NULL, &val);

    cmt_counter_inc(c, ts, 2, (char *[]) {"localhost", "cmetrics"});
    cmt_counter_get_val(c, 2, (char *[]) {"localhost", "cmetrics"}, &val);
    cmt_counter_add(c, ts, 10.55, 2, (char *[]) {"localhost", "test"});
    cmt_counter_get_val(c, 2, (char *[]) {"localhost", "test"}, &val);
    cmt_counter_set(c, ts, 12.15, 2, (char *[]) {"localhost", "test"});
    cmt_counter_set(c, ts, 1, 2, (char *[]) {"localhost", "test"});

    return cmt;
}

void test_msgpack()
{
    struct cmt *cmt = NULL;
    struct cmt *cmt2 = NULL;
    int         result = 0;
    size_t      offset = 0;
    char       *msgpack_buffer_a = NULL;
    char       *msgpack_buffer_b = NULL;
    size_t      msgpack_buffer_size_a = 0;
    size_t      msgpack_buffer_size_b = 0;

    cmt_initialize();

    cmt = generate_encoder_test_data();
    TEST_CHECK(NULL != cmt);

    result = cmt_encode_msgpack_create(cmt, &msgpack_buffer_a, &msgpack_buffer_size_a);
    TEST_CHECK(0 == result);

    result = cmt_decode_msgpack_create(&cmt2, msgpack_buffer_a, msgpack_buffer_size_a,
                                       &offset);
    TEST_CHECK(0 == result);

    result = cmt_encode_msgpack_create(cmt, &msgpack_buffer_b, &msgpack_buffer_size_b);
    TEST_CHECK(0 == result);

    TEST_CHECK(msgpack_buffer_size_a == msgpack_buffer_size_b);

    result = memcmp(msgpack_buffer_a, msgpack_buffer_b, msgpack_buffer_size_a);

    cmt_destroy(cmt);
    cmt_decode_msgpack_destroy(cmt2);
    cmt_encode_msgpack_destroy(msgpack_buffer_a);
    cmt_encode_msgpack_destroy(msgpack_buffer_b);
}

void test_prometheus()
{
    struct cmt *cmt = NULL;
    cfl_sds_t   prom = NULL;

    cmt_initialize();

    cmt = generate_encoder_test_data();
    TEST_CHECK(NULL != cmt);

    prom = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(NULL != prom);
    printf("%s\n", prom);

    cmt_destroy(cmt);
    cmt_encode_prometheus_destroy(prom);
}

void test_text()
{
    struct cmt *cmt = NULL;
    cfl_sds_t   text = NULL;

    cmt_initialize();

    cmt = generate_encoder_test_data();
    TEST_CHECK(cmt != NULL);

    text = cmt_encode_text_create(cmt);
    TEST_CHECK(text != NULL);

    cmt_destroy(cmt);
    cmt_encode_text_destroy(text);
}


void test_counter()
{
    int ret;
    double val = 1;
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_counter *c;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create a counter metric type */
    c = cmt_counter_create(cmt, "kubernetes", "network", "load", "Network load",
                           0, NULL);
    TEST_CHECK(c != NULL);

    /* Timestamp */
    ts = cfl_time_now();

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
    struct cmt *cmt;
    struct cmt_counter *c;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    /* Create a counter metric type */
    c = cmt_counter_create(cmt, "kubernetes", "network", "load", "Network load",
                           2, (char *[]) {"hostname", "app"});
    TEST_CHECK(c != NULL);

    /* Timestamp */
    ts = cfl_time_now();

    /*
     * Test 1: hash zero (no labels)
     * -----------------------------
     */

    /*
     * Default value: this call should fail since the metric has not been
     * initialized.
     */
    ret = cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK(ret == -1);

    /* Increment hash zero by 1 */
    ret = cmt_counter_inc(c, ts, 0, NULL);
    TEST_CHECK(ret == 0);

    /* validate value */
    ret = cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val == 1.0);

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

    cmt_destroy(cmt);
}

TEST_LIST = {
    {"basic", test_counter},
    {"labels", test_labels},
    {"msgpack", test_msgpack},
    {"prometheus", test_prometheus},
    {"text", test_text},
    { 0 }
};
