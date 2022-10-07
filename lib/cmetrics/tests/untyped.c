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
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_encode_influx.h>

#include "cmt_tests.h"

static struct cmt *generate_encoder_test_data()
{
    int ret;
    double val;
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_untyped *u;

    printf("version: %s\n\n", cmt_version());
    cmt = cmt_create();

    u = cmt_untyped_create(cmt, "kubernetes", "network", "load", "Network load",
                           2, (char *[]) {"hostname", "app"});

    ts = cfl_time_now();

    ret = cmt_untyped_get_val(u, 0, NULL, &val);
    TEST_CHECK(ret == -1);

    cmt_untyped_set(u, ts, 2, 0, NULL);
    cmt_untyped_get_val(u, 0, NULL, &val);
    TEST_CHECK(val == 2.0);

    cmt_untyped_get_val(u, 2, (char *[]) {"localhost", "cmetrics"}, &val);
    cmt_untyped_get_val(u, 2, (char *[]) {"localhost", "test"}, &val);
    cmt_untyped_set(u, ts, 12.15, 2, (char *[]) {"localhost", "test"});
    cmt_untyped_set(u, ts, 1, 2, (char *[]) {"localhost", "test"});

    return cmt;
}

void test_prometheus()
{
    struct cmt *cmt = NULL;
    cfl_sds_t   prom = NULL;

    cmt_initialize();

    cmt = generate_encoder_test_data();
    TEST_CHECK(cmt != NULL);

    prom = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(prom != NULL);
    printf("%s\n", prom);

    cmt_encode_prometheus_destroy(prom);
    cmt_destroy(cmt);
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

    printf("%s\n", text);

    cmt_encode_text_destroy(text);
    cmt_destroy(cmt);
}

void test_influx()
{
    struct cmt *cmt = NULL;
    cfl_sds_t   text = NULL;

    cmt_initialize();

    cmt = generate_encoder_test_data();
    TEST_CHECK(cmt != NULL);

    text = cmt_encode_influx_create(cmt);
    TEST_CHECK(text != NULL);

    printf("%s\n", text);

    cmt_encode_influx_destroy(text);
    cmt_destroy(cmt);
}

TEST_LIST = {
    {"prometheus", test_prometheus},
    {"text"      , test_text},
    {"influx"    , test_influx},
    { 0 }
};
