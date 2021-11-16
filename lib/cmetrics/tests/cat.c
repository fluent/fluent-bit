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
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_cat.h>

#include "cmt_tests.h"

void test_cat()
{
    int ret;
    uint64_t ts;
    cmt_sds_t text;
    struct cmt *cmt1;
    struct cmt *cmt2;
    struct cmt *cmt3;
    struct cmt_counter *c;
    struct cmt_gauge *g;
    struct cmt_untyped *u;

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


    ts = cmt_time_now();
    cmt_counter_set(c, ts, 1.1, 2, (char *[]) {"aaa", "bbb"});

    ts = cmt_time_now();
    cmt_gauge_set(g, ts, 1.2, 2, (char *[]) {"yyy", "xxx"});

    ts = cmt_time_now();
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

    ts = cmt_time_now();
    cmt_counter_set(c, ts, 2.1, 2, (char *[]) {"ccc", "ddd"});

    /* no labels */
    cmt_counter_set(c, ts, 5, 0, NULL);

    ts = cmt_time_now();
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

    /* check output */
    text = cmt_encode_text_create(cmt3);
    printf("====>\n%s\n", text);

    cmt_encode_text_destroy(text);

    /* destroy contexts */
    cmt_destroy(cmt1);
    cmt_destroy(cmt2);
    cmt_destroy(cmt3);
}

TEST_LIST = {
    {"cat", test_cat},
    { 0 }
};
