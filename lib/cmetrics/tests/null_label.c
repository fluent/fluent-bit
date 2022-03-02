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

#include "cmt_tests.h"

void test_labels()
{
    double val;
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_counter *c;

    cmt = cmt_create();
    c = cmt_counter_create(cmt, "test", "dummy", "labels", "testing labels",
                           6, (char *[]) {"A", "B", "C", "D", "E", "F"});

    ts = cmt_time_now();

    cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK((uint64_t) val == 0);

    cmt_counter_inc(c, ts, 0, NULL);
    cmt_counter_add(c, ts, 2, 0, NULL);
    cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK((uint64_t) val == 3);

    /* --- case 1 --- */
    cmt_counter_inc(c, ts, 6, (char *[]) {"1", NULL, "98", NULL, NULL, NULL});

    /* check retrieval with no labels */
    cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK((uint64_t) val == 3);

    /* check real value */
    cmt_counter_get_val(c, 6, (char *[]) {"1", NULL, "98", NULL, NULL, NULL}, &val);
    TEST_CHECK((uint64_t) val == 1);


    /* --- case 2 --- */
    cmt_counter_set(c, ts, 5, 6, (char *[]) {"1", "2", "98", "100", "200", "300"});

    /* check retrieval with no labels */
    cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK((uint64_t) val == 3);

    /* check real value */
    cmt_counter_get_val(c, 6, (char *[]) {"1", "2", "98", "100", "200", "300"}, &val);
    TEST_CHECK((uint64_t) val == 5);

    /* --- check that 'case 1' still matches --- */
    cmt_counter_get_val(c, 0, NULL, &val);
    TEST_CHECK((uint64_t) val == 3);

    /* check real value */
    cmt_counter_get_val(c, 6, (char *[]) {"1", NULL, "98", NULL, NULL, NULL}, &val);
    TEST_CHECK((uint64_t) val == 1);
}

TEST_LIST = {
    {"labels", test_labels},
    { 0 }
};
