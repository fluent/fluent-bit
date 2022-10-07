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
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <cmetrics/cmt_encode_opentelemetry.h>

#include "cmt_tests.h"

static struct cmt *generate_encoder_test_data()
{
    double                        quantiles[5];
    struct cmt_histogram_buckets *buckets;
    double                        val;
    struct cmt                   *cmt;
    uint64_t                      ts;
    struct cmt_gauge             *g1;
    struct cmt_counter           *c1;
    struct cmt_summary           *s1;
    struct cmt_histogram         *h1;

    ts = 0;
    cmt = cmt_create();

    c1 = cmt_counter_create(cmt, "kubernetes", "network", "load_counter", "Network load counter",
                            2, (char *[]) {"hostname", "app"});

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

    g1 = cmt_gauge_create(cmt, "kubernetes", "network", "load_gauge", "Network load gauge", 0, NULL);

    cmt_gauge_get_val(g1, 0, NULL, &val);
    cmt_gauge_set(g1, ts, 2.0, 0, NULL);
    cmt_gauge_get_val(g1, 0, NULL, &val);
    cmt_gauge_inc(g1, ts, 0, NULL);
    cmt_gauge_get_val(g1, 0, NULL, &val);
    cmt_gauge_sub(g1, ts, 2, 0, NULL);
    cmt_gauge_get_val(g1, 0, NULL, &val);
    cmt_gauge_dec(g1, ts, 0, NULL);
    cmt_gauge_get_val(g1, 0, NULL, &val);
    cmt_gauge_inc(g1, ts, 0, NULL);

    buckets = cmt_histogram_buckets_create(3, 0.05, 5.0, 10.0);

    h1 = cmt_histogram_create(cmt,
                              "k8s", "network", "load_histogram", "Network load histogram",
                              buckets,
                              1, (char *[]) {"my_label"});

    cmt_histogram_observe(h1, ts, 0.001, 0, NULL);
    cmt_histogram_observe(h1, ts, 0.020, 0, NULL);
    cmt_histogram_observe(h1, ts, 5.0, 0, NULL);
    cmt_histogram_observe(h1, ts, 8.0, 0, NULL);
    cmt_histogram_observe(h1, ts, 1000, 0, NULL);

    cmt_histogram_observe(h1, ts, 0.001, 1, (char *[]) {"my_val"});
    cmt_histogram_observe(h1, ts, 0.020, 1, (char *[]) {"my_val"});
    cmt_histogram_observe(h1, ts, 5.0, 1, (char *[]) {"my_val"});
    cmt_histogram_observe(h1, ts, 8.0, 1, (char *[]) {"my_val"});
    cmt_histogram_observe(h1, ts, 1000, 1, (char *[]) {"my_val"});;

    quantiles[0] = 0.1;
    quantiles[1] = 0.2;
    quantiles[2] = 0.3;
    quantiles[3] = 0.4;
    quantiles[4] = 0.5;

    s1 = cmt_summary_create(cmt,
                            "k8s", "disk", "load_summary", "Disk load summary",
                            5, quantiles,
                            1, (char *[]) {"my_label"});

    quantiles[0] = 1.1;
    quantiles[1] = 2.2;
    quantiles[2] = 3.3;
    quantiles[3] = 4.4;
    quantiles[4] = 5.5;

    cmt_summary_set_default(s1, ts, quantiles, 51.612894511314444, 10, 0, NULL);

    quantiles[0] = 11.11;
    quantiles[1] = 0;
    quantiles[2] = 33.33;
    quantiles[3] = 44.44;
    quantiles[4] = 55.55;

    cmt_summary_set_default(s1, ts, quantiles, 51.612894511314444, 10, 1, (char *[]) {"my_val"});

    return cmt;
}

void test_opentelemetry()
{
    cfl_sds_t        reference_prometheus_context;
    cfl_sds_t        opentelemetry_context;
    struct cfl_list  decoded_context_list;
    cfl_sds_t        prometheus_context;
    struct cmt      *decoded_context;
    size_t           offset;
    int              result;
    struct cmt      *cmt;

    offset = 0;

    cmt_initialize();

    cmt = generate_encoder_test_data();
    TEST_CHECK(cmt != NULL);

    reference_prometheus_context = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(reference_prometheus_context != NULL);

    if (reference_prometheus_context != NULL) {
        opentelemetry_context = cmt_encode_opentelemetry_create(cmt);
        TEST_CHECK(opentelemetry_context != NULL);

        if (opentelemetry_context != NULL) {
            result = cmt_decode_opentelemetry_create(&decoded_context_list,
                                                     opentelemetry_context,
                                                     cfl_sds_len(opentelemetry_context),
                                                     &offset);

            if (TEST_CHECK(result == 0)) {
                decoded_context = cfl_list_entry_first(&decoded_context_list, struct cmt, _head);

                if (TEST_CHECK(result == 0)) {
                    prometheus_context = cmt_encode_prometheus_create(decoded_context,
                                                                      CMT_TRUE);
                    TEST_CHECK(prometheus_context != NULL);

                    if (prometheus_context != NULL) {
                        TEST_CHECK(strcmp(prometheus_context,
                                          reference_prometheus_context) == 0);

                        cmt_encode_prometheus_destroy(prometheus_context);
                    }
                }

                cmt_decode_opentelemetry_destroy(&decoded_context_list);
            }
        }

        cmt_encode_opentelemetry_destroy(opentelemetry_context);
        cmt_encode_prometheus_destroy(reference_prometheus_context);
    }

    cmt_destroy(cmt);
}

TEST_LIST = {
    {"opentelemetry", test_opentelemetry},
    { 0 }
};
