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
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_decode_prometheus_remote_write.h>
#include <cmetrics/cmt_decode_statsd.h>

#include "cmt_tests.h"


void test_prometheus_remote_write()
{
    int ret;
    struct cmt *decoded_context;
    cfl_sds_t payload = read_file(CMT_TESTS_DATA_PATH "/remote_write_dump_originally_from_node_exporter.bin");

    cmt_initialize();

    ret = cmt_decode_prometheus_remote_write_create(&decoded_context, payload, cfl_sds_len(payload));
    TEST_CHECK(ret == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS);

    cmt_decode_prometheus_remote_write_destroy(decoded_context);

    cfl_sds_destroy(payload);
}

void test_statsd()
{
    int ret;
    struct cmt *decoded_context;
    cfl_sds_t payload = read_file(CMT_TESTS_DATA_PATH "/statsd_payload.txt");
    size_t len = 0;
    cfl_sds_t text = NULL;
    int flags = 0;

    /* For strtok_r, fill the last byte as \0. */
    len = cfl_sds_len(payload);
    cfl_sds_set_len(payload, len + 1);
    payload[len] = '\0';

    cmt_initialize();

    flags |= CMT_DECODE_STATSD_GAUGE_OBSERVER;

    ret = cmt_decode_statsd_create(&decoded_context, payload, cfl_sds_len(payload), flags);
    TEST_CHECK(ret == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS);
    text = cmt_encode_prometheus_create(decoded_context, CMT_FALSE);

    printf("%s\n", text);
    cmt_encode_prometheus_destroy(text);

    cmt_decode_statsd_destroy(decoded_context);

    cfl_sds_destroy(payload);
}


TEST_LIST = {
    {"prometheus_remote_write", test_prometheus_remote_write},
    {"statsd", test_statsd},
    { 0 }
};
