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
#include <cmetrics/cmt_encode_text.h>

#include "cmt_tests.h"

static struct cmt *sample_data()
{
    double val;
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_counter *c1;
    struct cmt_counter *c2;

    cmt = cmt_create();

    c1 = cmt_counter_create(cmt, "kubernetes", "network", "load", "Network load",
                            2, (char *[]) {"hostname", "app"});

    ts = 0;

    cmt_counter_get_val(c1, 0, NULL, &val);
    cmt_counter_inc(c1, ts, 0, NULL);
    cmt_counter_add(c1, ts, 2, 0, NULL);
    cmt_counter_get_val(c1, 0, NULL, &val);

    cmt_counter_inc(c1, ts, 2, (char *[]) {"localhost", "cmetrics"});
    cmt_counter_get_val(c1, 2, (char *[]) {"localhost", "cmetrics"}, &val);
    cmt_counter_add(c1, ts, 10.55, 2, (char *[]) {"localhost", "test"});
    cmt_counter_get_val(c1, 2, (char *[]) {"localhost", "test"}, &val);
    cmt_counter_set(c1, ts, 12.15, 2, (char *[]) {"localhost", "test"});
    cmt_counter_set(c1, ts, 1, 2, (char *[]) {"localhost", "test"});


    c2 = cmt_counter_create(cmt, "kubernetes", "network", "cpu", "CPU load",
                            2, (char *[]) {"hostname", "app"});

    ts = 0;

    cmt_counter_get_val(c2, 0, NULL, &val);
    cmt_counter_inc(c2, ts, 0, NULL);
    cmt_counter_add(c2, ts, 2, 0, NULL);
    cmt_counter_get_val(c2, 0, NULL, &val);

    cmt_counter_inc(c2, ts, 2, (char *[]) {"localhost", "cmetrics"});
    cmt_counter_get_val(c2, 2, (char *[]) {"localhost", "cmetrics"}, &val);
    cmt_counter_add(c2, ts, 10.55, 2, (char *[]) {"localhost", "test"});
    cmt_counter_get_val(c2, 2, (char *[]) {"localhost", "test"}, &val);
    cmt_counter_set(c2, ts, 12.15, 2, (char *[]) {"localhost", "test"});
    cmt_counter_set(c2, ts, 1, 2, (char *[]) {"localhost", "test"});

    return cmt;
}

void test_basic()
{
    int ret;
    int error;
    size_t off = 0;
    cfl_sds_t text1;
    cfl_sds_t text2;
    char *mp_buf;
    size_t mp_size;
    struct cmt *cmt1;
    struct cmt *cmt2;

    cmt1 = sample_data();
    TEST_CHECK(cmt1 != NULL);

    /* encode to text */
    text1 = cmt_encode_text_create(cmt1);
    TEST_CHECK(text1 != NULL);

    /* encode to msgpack */
    ret = cmt_encode_msgpack_create(cmt1, &mp_buf, &mp_size);
    TEST_CHECK(ret == 0);

    /* decode msgpack into cmt2 */
    ret = cmt_decode_msgpack_create(&cmt2, mp_buf, mp_size, &off);
    TEST_CHECK(ret == 0);

    /* encode cmt2 to text */
    text2 = cmt_encode_text_create(cmt2);
    TEST_CHECK(text2 != NULL);

    /* compate both texts */
    error = 0;
    if ((cfl_sds_len(text1) != cfl_sds_len(text2)) ||
        strcmp(text1, text2) != 0) {

        printf("\n");
        printf("====== EXPECTED OUTPUT =====\n%s", text1);
        printf("\n\n");
        printf("====== RECEIVED OUTPUT =====\n%s\n", text2);
        error = 1;
    }
    TEST_CHECK(error == 0);

    cmt_encode_msgpack_destroy(mp_buf);
    cmt_encode_text_destroy(text1);
    cmt_encode_text_destroy(text2);
    cmt_destroy(cmt1);
    cmt_destroy(cmt2);
}

TEST_LIST = {
    {"basic", test_basic},
    { 0 }
};
