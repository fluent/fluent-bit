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
#ifdef __GNUC__
#define _GNU_SOURCE
#endif

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_prometheus_remote_write.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_encode_opentelemetry.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_encode_influx.h>

#include "cmt_tests.h"

static struct cmt *generate_simple_encoder_test_data()
{
    double val;
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_counter *c;

    cmt = cmt_create();

    c = cmt_counter_create(cmt, "kubernetes", "network", "load", "Network load",
                           2, (char *[]) {"hostname", "app"});

    ts = 0;

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

    cmt_summary_set_default(s1, ts, quantiles, 10, 51.612894511314444, 0, NULL);

    quantiles[0] = 11.11;
    quantiles[1] = 0;
    quantiles[2] = 33.33;
    quantiles[3] = 44.44;
    quantiles[4] = 55.55;

    cmt_summary_set_default(s1, ts, quantiles, 10, 51.612894511314444, 1, (char *[]) {"my_val"});

    return cmt;
}

/*
 * perform the following data encoding and compare msgpack buffsers
 *
 * CMT -> MSGPACK -> CMT -> MSGPACK
 *          |                  |
 *          |---> compare <----|
 */

void test_cmt_to_msgpack()
{
    int ret;
    size_t offset = 0;
    char *mp1_buf = NULL;
    size_t mp1_size = 0;
    char *mp2_buf = NULL;
    size_t mp2_size = 0;
    struct cmt *cmt1 = NULL;
    struct cmt *cmt2 = NULL;

    cmt_initialize();

    /* Generate context with data */
    cmt1 = generate_encoder_test_data();
    TEST_CHECK(cmt1 != NULL);

    /* CMT1 -> Msgpack */
    ret = cmt_encode_msgpack_create(cmt1, &mp1_buf, &mp1_size);
    TEST_CHECK(ret == 0);

    /* Msgpack -> CMT2 */
    ret = cmt_decode_msgpack_create(&cmt2, mp1_buf, mp1_size, &offset);
    TEST_CHECK(ret == 0);

    /* CMT2 -> Msgpack */
    ret = cmt_encode_msgpack_create(cmt2, &mp2_buf, &mp2_size);
    TEST_CHECK(ret == 0);

    /* Compare msgpacks */
    TEST_CHECK(mp1_size == mp2_size);
    if (mp1_size == mp2_size) {
        TEST_CHECK(memcmp(mp1_buf, mp2_buf, mp1_size) == 0);
    }

    cmt_destroy(cmt1);
    cmt_decode_msgpack_destroy(cmt2);
    cmt_encode_msgpack_destroy(mp1_buf);
    cmt_encode_msgpack_destroy(mp2_buf);
}

/*
 * Encode a context, corrupt the last metric in the msgpack packet
 * and invoke the decoder to verify if there are any leaks.
 *
 * CMT -> MSGPACK -> CMT
 *
 * Note: this function is meant to be executed in linux while using
 * valgrind
 */

void test_cmt_to_msgpack_cleanup_on_error()
{
#ifdef __linux__
    int ret;
    size_t offset = 0;
    char *mp1_buf = NULL;
    size_t mp1_size = 0;
    struct cmt *cmt1 = NULL;
    struct cmt *cmt2 = NULL;
    char *key_buffer = NULL;
    char *key_haystack = NULL;

    cmt_initialize();

    /* Generate context with data */
    cmt1 = generate_encoder_test_data();
    TEST_CHECK(cmt1 != NULL);

    /* CMT1 -> Msgpack */
    ret = cmt_encode_msgpack_create(cmt1, &mp1_buf, &mp1_size);
    TEST_CHECK(ret == 0);

    key_haystack = &mp1_buf[mp1_size - 32];
    key_buffer = memmem(key_haystack, 32, "hash", 4);

    TEST_CHECK(key_buffer != NULL);

    /* This turns the last 'hash' entry into 'hasq' which causes
     * the map consumer in the decoder to detect an unprocessed entry
     * and abort in `unpack_metric` which means a lot of allocations
     * have been made including but not limited to temporary
     * histogram bucket arrays and completely decoded histograms
     */
    key_buffer[3] = 'q';

    /* Msgpack -> CMT2 */
    ret = cmt_decode_msgpack_create(&cmt2, mp1_buf, mp1_size, &offset);

    cmt_destroy(cmt1);
    cmt_encode_msgpack_destroy(mp1_buf);

    TEST_CHECK(ret != 0);
    TEST_CHECK(cmt2 == NULL);

#endif
}

/*
 * perform the following data encoding and compare msgpack buffsers
 *
 * CMT -> MSGPACK -> CMT -> TEXT
 * CMT -> TEXT
 *          |                  |
 *          |---> compare <----|
 */
void test_cmt_to_msgpack_integrity()
{
    int ret;
    size_t offset = 0;
    char *mp1_buf = NULL;
    size_t mp1_size = 0;
    char *text1_buf = NULL;
    size_t text1_size = 0;
    char *text2_buf = NULL;
    size_t text2_size = 0;
    struct cmt *cmt1 = NULL;
    struct cmt *cmt2 = NULL;

    /* Generate context with data */
    cmt1 = generate_encoder_test_data();
    TEST_CHECK(cmt1 != NULL);

    /* CMT1 -> Msgpack */
    ret = cmt_encode_msgpack_create(cmt1, &mp1_buf, &mp1_size);
    TEST_CHECK(ret == 0);

    /* Msgpack -> CMT2 */
    ret = cmt_decode_msgpack_create(&cmt2, mp1_buf, mp1_size, &offset);
    TEST_CHECK(ret == 0);

    /* CMT1 -> Text */
    text1_buf = cmt_encode_text_create(cmt1);
    TEST_CHECK(text1_buf != NULL);
    text1_size = cmt_sds_len(text1_buf);

    /* CMT2 -> Text */
    text2_buf = cmt_encode_text_create(cmt2);
    TEST_CHECK(text2_buf != NULL);
    text2_size = cmt_sds_len(text2_buf);

    /* Compare msgpacks */
    TEST_CHECK(text1_size == text2_size);
    TEST_CHECK(memcmp(text1_buf, text2_buf, text1_size) == 0);

    cmt_destroy(cmt1);

    cmt_decode_msgpack_destroy(cmt2);
    cmt_encode_msgpack_destroy(mp1_buf);

    cmt_encode_text_destroy(text1_buf);
    cmt_encode_text_destroy(text2_buf);
}

void test_cmt_msgpack_partial_processing()
{
    int ret = 0;
    int iteration = 0;
    size_t offset = 0;
    char *mp1_buf = NULL;
    size_t mp1_size = 0;
    struct cmt *cmt1 = NULL;
    struct cmt *cmt2 = NULL;
    double base_counter_value = 0;
    size_t expected_gauge_count = 0;
    double current_counter_value = 0;
    size_t expected_counter_count = 0;
    struct cmt_counter *first_counter = NULL;
    cmt_sds_t serialized_data_buffer = NULL;
    size_t serialized_data_buffer_length = 0;

    /* Generate an encoder context with more than one counter */
    cmt1 = generate_encoder_test_data();
    TEST_CHECK(NULL != cmt1);

    /* Find the first counter so we can get its value before re-encoding it N times
     * for the test, that way we can ensure that the decoded contexts we get in the
     * next phase are individual ones and not just a glitch
     */

    first_counter = mk_list_entry_first(&cmt1->counters, struct cmt_counter, _head);
    TEST_CHECK(NULL != first_counter);

    ret = cmt_counter_get_val(first_counter, 0, NULL, &base_counter_value);
    TEST_CHECK(0 == ret);

    expected_counter_count = mk_list_size(&cmt1->counters);
    expected_gauge_count = mk_list_size(&cmt1->gauges);

    /* Since we are modifying the counter on each iteration we have to re-encode it */
    for (iteration = 0 ;
         iteration < MSGPACK_PARTIAL_PROCESSING_ELEMENT_COUNT ;
         iteration++) {

        ret = cmt_counter_inc(first_counter, 0, 0, NULL);
        TEST_CHECK(0 == ret);

        ret = cmt_encode_msgpack_create(cmt1, &mp1_buf, &mp1_size);
        TEST_CHECK(0 == ret);

        if (NULL == serialized_data_buffer) {
            serialized_data_buffer = cmt_sds_create_len(mp1_buf, mp1_size);
            TEST_CHECK(NULL != serialized_data_buffer);
        }
        else {
            cmt_sds_cat_safe(&serialized_data_buffer, mp1_buf, mp1_size);
            /* TEST_CHECK(0 == ret); */
        }

        cmt_encode_msgpack_destroy(mp1_buf);
    }

    cmt_destroy(cmt1);

    /* In this phase we invoke the decoder with until it retunrs an error indicating that
     * there is not enough data in the input buffer, for each cycle we compare the value
     * for the first counter which should be be incremental.
     *
     * We also check that the iteration count matches the pre established count.
     */

    ret = 0;
    offset = 0;
    iteration = 0;
    serialized_data_buffer_length = cmt_sds_len(serialized_data_buffer);

    while (CMT_DECODE_MSGPACK_SUCCESS == ret) {
        ret = cmt_decode_msgpack_create(&cmt2, serialized_data_buffer,
                                        serialized_data_buffer_length, &offset);

        if (CMT_DECODE_MSGPACK_INSUFFICIENT_DATA == ret) {
            break;
        }
        else if (CMT_DECODE_MSGPACK_SUCCESS != ret) {
            break;
        }

        TEST_CHECK(0 == ret);

        first_counter = mk_list_entry_first(&cmt2->counters, struct cmt_counter, _head);
        TEST_CHECK(NULL != first_counter);

        ret = cmt_counter_get_val(first_counter, 0, NULL, &current_counter_value);
        TEST_CHECK(0 == ret);

        TEST_CHECK(base_counter_value == (current_counter_value - iteration - 1));

        TEST_CHECK(expected_counter_count == mk_list_size(&cmt2->counters));
        TEST_CHECK(expected_gauge_count == mk_list_size(&cmt2->gauges));

        cmt_decode_msgpack_destroy(cmt2);

        iteration++;
    }

    TEST_CHECK(MSGPACK_PARTIAL_PROCESSING_ELEMENT_COUNT == iteration);

    cmt_sds_destroy(serialized_data_buffer);
}

void test_cmt_to_msgpack_stability()
{
    int ret = 0;
    int iteration = 0;
    size_t offset = 0;
    char *mp1_buf = NULL;
    size_t mp1_size = 0;
    struct cmt *cmt1 = NULL;
    struct cmt *cmt2 = NULL;

    for (iteration = 0 ; iteration < MSGPACK_STABILITY_TEST_ITERATION_COUNT ; iteration++) {
        cmt1 = generate_encoder_test_data();
        TEST_CHECK(cmt1 != NULL);

        ret = cmt_encode_msgpack_create(cmt1, &mp1_buf, &mp1_size);
        TEST_CHECK(ret == 0);

        offset = 0;
        ret = cmt_decode_msgpack_create(&cmt2, mp1_buf, mp1_size, &offset);
        TEST_CHECK(ret == 0);

        cmt_destroy(cmt1);
        cmt_decode_msgpack_destroy(cmt2);
        cmt_encode_msgpack_destroy(mp1_buf);
    }

}

void test_cmt_to_msgpack_labels()
{
    int ret;
    size_t offset = 0;
    char *mp1_buf = NULL;
    size_t mp1_size = 1;
    char *mp2_buf = NULL;
    size_t mp2_size = 2;
    struct cmt *cmt1 = NULL;
    struct cmt *cmt2 = NULL;
    cmt_sds_t text_result;
    const char expected_text[] = "1970-01-01T00:00:00.000000000Z kubernetes_network_load{dev=\"Calyptia\",lang=\"C\"} = 3\n" \
                                 "1970-01-01T00:00:00.000000000Z kubernetes_network_load{dev=\"Calyptia\",lang=\"C\",hostname=\"localhost\",app=\"cmetrics\"} = 1\n" \
                                 "1970-01-01T00:00:00.000000000Z kubernetes_network_load{dev=\"Calyptia\",lang=\"C\",hostname=\"localhost\",app=\"test\"} = 12.15\n";

    cmt_initialize();

    /* Generate context with data */
    cmt1 = generate_simple_encoder_test_data();
    TEST_CHECK(NULL != cmt1);

    /* CMT1 -> Msgpack */
    ret = cmt_encode_msgpack_create(cmt1, &mp1_buf, &mp1_size);
    TEST_CHECK(0 == ret);

    /* Msgpack -> CMT2 */
    ret = cmt_decode_msgpack_create(&cmt2, mp1_buf, mp1_size, &offset);
    TEST_CHECK(0 == ret);

    /* CMT2 -> Msgpack */
    ret = cmt_encode_msgpack_create(cmt2, &mp2_buf, &mp2_size);
    TEST_CHECK(0 == ret);

    /* Compare msgpacks */
    TEST_CHECK(mp1_size == mp2_size);
    TEST_CHECK(0 == memcmp(mp1_buf, mp2_buf, mp1_size));

    /* append static labels */
    cmt_label_add(cmt2, "dev", "Calyptia");
    cmt_label_add(cmt2, "lang", "C");

    text_result = cmt_encode_text_create(cmt2);
    TEST_CHECK(NULL != text_result);
    TEST_CHECK(0 == strcmp(text_result, expected_text));

    cmt_destroy(cmt1);
    cmt_encode_text_destroy(text_result);
    cmt_decode_msgpack_destroy(cmt2);
    cmt_encode_msgpack_destroy(mp1_buf);
    cmt_encode_msgpack_destroy(mp2_buf);
}

void test_prometheus_remote_write()
{
    struct cmt *cmt;
    cmt_sds_t   payload;
    FILE       *sample_file;

    cmt_initialize();

    cmt = generate_encoder_test_data();

    payload = cmt_encode_prometheus_remote_write_create(cmt);
    TEST_CHECK(NULL != payload);

    if (payload == NULL) {
        cmt_destroy(cmt);

        return;
    }

    printf("\n\nDumping remote write payload to prometheus_remote_write_payload.bin, in order to test it \
we need to compress it using snappys scmd :\n\
scmd -c prometheus_remote_write_payload.bin prometheus_remote_write_payload.snp\n\n\
and then send it using curl :\n\
curl -v 'http://localhost:9090/receive' -H 'Content-Type: application/x-protobuf' \
-H 'X-Prometheus-Remote-Write-Version: 0.1.0' -H 'User-Agent: metrics-worker' \
--data-binary '@prometheus_remote_write_payload.snp'\n\n");

    sample_file = fopen("prometheus_remote_write_payload.bin", "wb+");

    fwrite(payload, 1, cmt_sds_len(payload), sample_file);

    fclose(sample_file);

    cmt_encode_prometheus_remote_write_destroy(payload);

    cmt_destroy(cmt);
}

void test_opentelemetry()
{
    cmt_sds_t payload;
    struct cmt *cmt;
    FILE *sample_file;

    cmt_initialize();

    cmt = generate_encoder_test_data();

    payload = cmt_encode_opentelemetry_create(cmt);
    TEST_CHECK(NULL != payload);

    if (payload == NULL) {
        cmt_destroy(cmt);

        return;
    }

    printf("\n\nDumping remote write payload to opentelemetry_payload.bin, in order to test it \
we need to send it to our opentelemetry http endpoint using curl :\n\
curl -v 'http://localhost:9090/v1/metrics' -H 'Content-Type: application/x-protobuf' \
-H 'User-Agent: metrics-worker' \
--data-binary '@opentelemetry_payload.bin'\n\n");

    sample_file = fopen("opentelemetry_payload.bin", "wb+");

    fwrite(payload, 1, cmt_sds_len(payload), sample_file);

    fclose(sample_file);

    cmt_encode_prometheus_remote_write_destroy(payload);

    cmt_destroy(cmt);
}

void test_prometheus()
{
    uint64_t ts;
    cmt_sds_t text;
    struct cmt *cmt;
    struct cmt_counter *c;

    char *out1 = "# HELP cmt_labels_test \"Static\\\\ labels \\ntest\n"
                 "# TYPE cmt_labels_test counter\n"
                 "cmt_labels_test 1 0\n"
                 "cmt_labels_test{host=\"calyptia.com\",app=\"cmetrics\"} 2 0\n"
                 "cmt_labels_test{host=\"\\\"calyptia.com\\\"\",app=\"cme\\\\tr\\nics\"} 1 0\n";

    char *out2 = "# HELP cmt_labels_test \"Static\\\\ labels \\ntest\n"
        "# TYPE cmt_labels_test counter\n"
        "cmt_labels_test{dev=\"Calyptia\",lang=\"C\\\"\\\\\\n\"} 1 0\n"
        "cmt_labels_test{dev=\"Calyptia\",lang=\"C\\\"\\\\\\n\",host=\"calyptia.com\",app=\"cmetrics\"} 2 0\n"
        "cmt_labels_test{dev=\"Calyptia\",lang=\"C\\\"\\\\\\n\",host=\"\\\"calyptia.com\\\"\",app=\"cme\\\\tr\\nics\"} 1 0\n";

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    c = cmt_counter_create(cmt, "cmt", "labels", "test", "\"Static\\ labels \ntest",
                           2, (char *[]) {"host", "app"});

    ts = 0;
    cmt_counter_inc(c, ts, 0, NULL);
    cmt_counter_inc(c, ts, 2, (char *[]) {"calyptia.com", "cmetrics"});
    cmt_counter_inc(c, ts, 2, (char *[]) {"calyptia.com", "cmetrics"});
    cmt_counter_inc(c, ts, 2, (char *[]) {"\"calyptia.com\"", "cme\\tr\nics"});

    /* Encode to prometheus (no static labels) */
    text = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    printf("\n%s\n", text);
    TEST_CHECK(strcmp(text, out1) == 0);
    cmt_encode_prometheus_destroy(text);

    /* append static labels */
    cmt_label_add(cmt, "dev", "Calyptia");
    cmt_label_add(cmt, "lang", "C\"\\\n");

    text = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    printf("%s\n", text);
    TEST_CHECK(strcmp(text, out2) == 0);
    cmt_encode_prometheus_destroy(text);

    cmt_destroy(cmt);
}

void test_text()
{
    uint64_t ts;
    cmt_sds_t text;
    struct cmt *cmt;
    struct cmt_counter *c;

    char *out1 = \
        "1970-01-01T00:00:00.000000000Z cmt_labels_test = 1\n"
        "1970-01-01T00:00:00.000000000Z cmt_labels_test{host=\"calyptia.com\",app=\"cmetrics\"} = 2\n";

    char *out2 = \
        "1970-01-01T00:00:00.000000000Z cmt_labels_test{dev=\"Calyptia\",lang=\"C\"} = 1\n"
        "1970-01-01T00:00:00.000000000Z cmt_labels_test{dev=\"Calyptia\",lang=\"C\",host=\"calyptia.com\",app=\"cmetrics\"} = 2\n";

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    c = cmt_counter_create(cmt, "cmt", "labels", "test", "Static labels test",
                           2, (char *[]) {"host", "app"});

    ts = 0;
    cmt_counter_inc(c, ts, 0, NULL);
    cmt_counter_inc(c, ts, 2, (char *[]) {"calyptia.com", "cmetrics"});
    cmt_counter_inc(c, ts, 2, (char *[]) {"calyptia.com", "cmetrics"});

    /* Encode to prometheus (no static labels) */
    text = cmt_encode_text_create(cmt);
    printf("\n%s\n", text);
    TEST_CHECK(strcmp(text, out1) == 0);
    cmt_encode_text_destroy(text);

    /* append static labels */
    cmt_label_add(cmt, "dev", "Calyptia");
    cmt_label_add(cmt, "lang", "C");

    text = cmt_encode_text_create(cmt);
    printf("%s\n", text);
    TEST_CHECK(strcmp(text, out2) == 0);
    cmt_encode_text_destroy(text);

    cmt_destroy(cmt);
}

void test_influx()
{
    uint64_t ts;
    cmt_sds_t text;
    struct cmt *cmt;
    struct cmt_counter *c1;
    struct cmt_counter *c2;

    char *out1 = \
        "cmt_labels test=1 1435658235000000123\n"
        "cmt_labels,host=calyptia.com,app=cmetrics test=2 1435658235000000123\n"
        "cmt,host=aaa,app=bbb nosubsystem=1 1435658235000000123\n";

    char *out2 = \
        "cmt_labels,dev=Calyptia,lang=C test=1 1435658235000000123\n"
        "cmt_labels,dev=Calyptia,lang=C,host=calyptia.com,app=cmetrics test=2 1435658235000000123\n"
        "cmt,dev=Calyptia,lang=C,host=aaa,app=bbb nosubsystem=1 1435658235000000123\n";

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    c1 = cmt_counter_create(cmt, "cmt", "labels", "test", "Static labels test",
                            2, (char *[]) {"host", "app"});

    ts = 1435658235000000123;
    cmt_counter_inc(c1, ts, 0, NULL);
    cmt_counter_inc(c1, ts, 2, (char *[]) {"calyptia.com", "cmetrics"});
    cmt_counter_inc(c1, ts, 2, (char *[]) {"calyptia.com", "cmetrics"});

    c2 = cmt_counter_create(cmt, "cmt", "", "nosubsystem", "No subsystem",
                            2, (char *[]) {"host", "app"});

    cmt_counter_inc(c2, ts, 2, (char *[]) {"aaa", "bbb"});

    /* Encode to prometheus (no static labels) */
    text = cmt_encode_influx_create(cmt);
    printf("%s\n", text);
    TEST_CHECK(strcmp(text, out1) == 0);
    cmt_encode_influx_destroy(text);

    /* append static labels */
    cmt_label_add(cmt, "dev", "Calyptia");
    cmt_label_add(cmt, "lang", "C");

    text = cmt_encode_influx_create(cmt);
    printf("%s\n", text);
    TEST_CHECK(strcmp(text, out2) == 0);
    cmt_encode_influx_destroy(text);

    cmt_destroy(cmt);
}

TEST_LIST = {
    {"cmt_msgpack_cleanup_on_error",   test_cmt_to_msgpack_cleanup_on_error},
    {"cmt_msgpack_partial_processing", test_cmt_msgpack_partial_processing},
    {"prometheus_remote_write",        test_prometheus_remote_write},
    {"cmt_msgpack_stability",          test_cmt_to_msgpack_stability},
    {"cmt_msgpack_integrity",          test_cmt_to_msgpack_integrity},
    {"cmt_msgpack_labels",             test_cmt_to_msgpack_labels},
    {"cmt_msgpack",                    test_cmt_to_msgpack},
    {"opentelemetry",                  test_opentelemetry},
    {"prometheus",                     test_prometheus},
    {"text",                           test_text},
    {"influx",                         test_influx},
    { 0 }
};
