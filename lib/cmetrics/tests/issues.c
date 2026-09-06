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
#include <cmetrics/cmt_decode_prometheus.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_mpack_utils.h>
#include <cmetrics/cmt_variant_utils.h>
#include <mpack/mpack.h>

#include "cmt_tests.h"

static struct cmt *generate_encoder_test_data()
{
    uint64_t ts;
    struct cmt *cmt;
    struct cmt_counter *c1;
    struct cmt_counter *c2;

    ts = 0;
    cmt = cmt_create();

    c1 = cmt_counter_create(cmt, "kubernetes", "", "load", "Network load",
                            2, (char *[]) {"hostname", "app"});
    cmt_counter_set(c1, ts, 10, 0, NULL);

    c2 = cmt_counter_create(cmt, "kubernetes", "", "cpu", "CPU load",
                            2, (char *[]) {"hostname", "app"});
    cmt_counter_set(c2, ts, 10, 0, NULL);

    return cmt;
}


void test_issue_54()
{
    const char  expected_text[] = "1970-01-01T00:00:00.000000000Z kubernetes_load{tag1=\"tag1\",tag2=\"tag2\"} = 10\n" \
                                  "1970-01-01T00:00:00.000000000Z kubernetes_cpu{tag1=\"tag1\",tag2=\"tag2\"} = 10\n";
    cfl_sds_t   text_result;
    size_t      mp1_size;
    char       *mp1_buf;
    size_t      offset;
    int         result;
    struct cmt *cmt2;
    struct cmt *cmt1;

    cmt_initialize();

    /* Generate context with data */
    cmt1 = generate_encoder_test_data();
    TEST_CHECK(NULL != cmt1);

    /* append static labels */
    cmt_label_add(cmt1, "tag1", "tag1");
    cmt_label_add(cmt1, "tag2", "tag2");

    /* CMT1 -> Msgpack */
    result = cmt_encode_msgpack_create(cmt1, &mp1_buf, &mp1_size);
    TEST_CHECK(0 == result);

    /* Msgpack -> CMT2 */
    offset = 0;
    result = cmt_decode_msgpack_create(&cmt2, mp1_buf, mp1_size, &offset);
    TEST_CHECK(0 == result);

    text_result = cmt_encode_text_create(cmt2);

    TEST_CHECK(NULL != text_result);
    TEST_CHECK(0 == strcmp(text_result, expected_text));

    cmt_encode_text_destroy(text_result);
    cmt_decode_msgpack_destroy(cmt2);
    cmt_encode_msgpack_destroy(mp1_buf);
    cmt_destroy(cmt1);
}

static void check_long_label_round_trip(size_t label_length)
{
    char                 *label_value;
    char                 *label_values[1];
    char                 *label_keys[1] = {"command"};
    char                 *msgpack_buffer;
    size_t                msgpack_size;
    size_t                offset;
    int                   result;
    struct cmt           *source;
    struct cmt           *decoded;
    struct cmt_counter   *counter;
    struct cmt_metric    *metric;
    struct cmt_map_label *label;

    label_value = malloc(label_length + 1);
    TEST_ASSERT(label_value != NULL);

    memset(label_value, 'a', label_length);
    label_value[label_length] = '\0';
    label_values[0] = label_value;

    source = cmt_create();
    TEST_ASSERT(source != NULL);

    counter = cmt_counter_create(source, "test", "", "long_label",
                                 "Long label round-trip", 1, label_keys);
    TEST_ASSERT(counter != NULL);
    TEST_CHECK(cmt_counter_set(counter, 0, 1, 1, label_values) == 0);

    result = cmt_encode_msgpack_create(source, &msgpack_buffer, &msgpack_size);
    TEST_ASSERT(result == 0);

    offset = 0;
    result = cmt_decode_msgpack_create(&decoded, msgpack_buffer, msgpack_size,
                                       &offset);
    TEST_ASSERT(result == 0);
    TEST_CHECK(offset == msgpack_size);

    counter = cfl_list_entry_first(&decoded->counters,
                                   struct cmt_counter, _head);
    metric = cfl_list_entry_first(&counter->map->metrics,
                                  struct cmt_metric, _head);
    label = cfl_list_entry_first(&metric->labels,
                                 struct cmt_map_label, _head);

    TEST_CHECK(cfl_sds_len(label->name) == label_length);
    TEST_CHECK(memcmp(label->name, label_value, label_length) == 0);

    cmt_decode_msgpack_destroy(decoded);
    cmt_encode_msgpack_destroy(msgpack_buffer);
    cmt_destroy(source);
    free(label_value);
}

void test_long_msgpack_labels()
{
    check_long_label_round_trip(1024);
    check_long_label_round_trip(1025);
    check_long_label_round_trip(2048);
    check_long_label_round_trip(65536);
}

void test_truncated_msgpack_string()
{
    char             *output;
    int               result;
    mpack_error_t     error;
    mpack_reader_t    reader;
    const char        input[] = {
        (char) 0xdb, (char) 0xff, (char) 0xff, (char) 0xff, (char) 0xff
    };

    output = NULL;
    mpack_reader_init_data(&reader, input, sizeof(input));

    result = cmt_mpack_consume_string_tag(&reader, &output);
    error = mpack_reader_destroy(&reader);

    TEST_CHECK(result == CMT_MPACK_ENGINE_ERROR);
    TEST_CHECK(error != mpack_ok);
    TEST_CHECK(output == NULL);
}

static void check_variant_nesting_limit(int use_maps, size_t nesting_depth,
                                        int expected_result)
{
    char *buffer;
    size_t size;
    size_t index;
    int result;
    mpack_writer_t writer;
    mpack_reader_t reader;
    struct cfl_variant *variant;

    buffer = NULL;
    size = 0;
    variant = NULL;

    mpack_writer_init_growable(&writer, &buffer, &size);

    for (index = 0; index < nesting_depth; index++) {
        if (use_maps) {
            mpack_start_map(&writer, 1);
            mpack_write_cstr(&writer, "key");
        }
        else {
            mpack_start_array(&writer, 1);
        }
    }

    mpack_write_i64(&writer, 1);

    for (index = 0; index < nesting_depth; index++) {
        if (use_maps) {
            mpack_finish_map(&writer);
        }
        else {
            mpack_finish_array(&writer);
        }
    }

    TEST_ASSERT(mpack_writer_destroy(&writer) == mpack_ok);

    mpack_reader_init_data(&reader, buffer, size);
    result = unpack_cfl_variant(&reader, &variant);
    TEST_CHECK((result == 0) == (expected_result == 0));

    if (variant != NULL) {
        cfl_variant_destroy(variant);
    }

    mpack_reader_destroy(&reader);
    free(buffer);
}

void test_msgpack_variant_nesting_limit()
{
    check_variant_nesting_limit(CFL_FALSE,
                                CFL_VARIANT_UTILS_MAXIMUM_NESTING_DEPTH, 0);
    check_variant_nesting_limit(CFL_FALSE,
                                CFL_VARIANT_UTILS_MAXIMUM_NESTING_DEPTH + 1, -1);
    check_variant_nesting_limit(CFL_TRUE,
                                CFL_VARIANT_UTILS_MAXIMUM_NESTING_DEPTH, 0);
    check_variant_nesting_limit(CFL_TRUE,
                                CFL_VARIANT_UTILS_MAXIMUM_NESTING_DEPTH + 1, -1);
}

#ifdef CMT_HAVE_PROMETHEUS_TEXT_DECODER

/* issue: https://github.com/fluent/fluent-bit/issues/10761 */
void test_prometheus_metric_no_subsystem()
{
    const char text[] =
        "# HELP up A simple example metric no subsystem\n"
        "# TYPE up gauge\n"
        "up{job=\"42\"} 1\n";
    struct cmt *cmt;
    cfl_sds_t result;
    int ret;

    cmt_initialize();

    ret = cmt_decode_prometheus_create(&cmt, text, strlen(text), NULL);
    TEST_CHECK(ret == CMT_DECODE_PROMETHEUS_SUCCESS);
    if (ret == CMT_DECODE_PROMETHEUS_SUCCESS) {
        result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
        TEST_CHECK(result != NULL);
        if (result) {
            TEST_CHECK(strstr(result, "up{job=\"42\"} 1") != NULL);
            cmt_encode_prometheus_destroy(result);
        }
        cmt_decode_prometheus_destroy(cmt);
    }
}

#endif

TEST_LIST = {
    {"issue_54", test_issue_54},
    {"long_msgpack_labels", test_long_msgpack_labels},
    {"truncated_msgpack_string", test_truncated_msgpack_string},
    {"msgpack_variant_nesting_limit", test_msgpack_variant_nesting_limit},
#ifdef CMT_HAVE_PROMETHEUS_TEXT_DECODER
    {"prometheus_metric_no_subsystem", test_prometheus_metric_no_subsystem},
#endif
    { 0 }
};
