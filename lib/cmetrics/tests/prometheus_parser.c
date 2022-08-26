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
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_decode_prometheus.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <stdio.h>

#include "cmetrics/cmt_counter.h"
#include "cmetrics/cmt_sds.h"
#include "cmetrics/cmt_summary.h"
#include "cmt_decode_prometheus_parser.h"
#include "cmt_tests.h"
#include "lib/acutest/acutest.h"
#include "tests/cmt_tests_config.h"

struct fixture {
    yyscan_t scanner;
    YY_BUFFER_STATE buf;
    YYSTYPE lval;
    struct cmt_decode_prometheus_context context;
    const char *text;
};

struct fixture *init(int start_token, const char *test)
{
    cmt_initialize();
    struct fixture *f = malloc(sizeof(*f));
    memset(f, 0, sizeof(*f));
    f->context.cmt = cmt_create();
    f->context.opts.start_token = start_token;
    mk_list_init(&(f->context.metric.samples));
    cmt_decode_prometheus_lex_init(&f->scanner);
    f->buf = cmt_decode_prometheus__scan_string(test, f->scanner);
    return f;
}

void destroy(struct fixture *f)
{
    cmt_decode_prometheus__delete_buffer(f->buf, f->scanner);
    cmt_decode_prometheus_lex_destroy(f->scanner);
    cmt_destroy(f->context.cmt);
    free(f);
}

int parse(struct fixture *f)
{
    return cmt_decode_prometheus_parse(f->scanner, &f->context);
}

void test_header_help()
{
    struct fixture *f = init(START_HEADER,
            "# HELP cmt_labels_test Static labels test\n"
            );

    TEST_CHECK(parse(f) == 0);

    TEST_CHECK(strcmp(f->context.metric.ns, "cmt") == 0);
    TEST_CHECK(strcmp(f->context.metric.subsystem, "labels") == 0);
    TEST_CHECK(strcmp(f->context.metric.name, "test") == 0);
    TEST_CHECK(strcmp(f->context.metric.docstring, "Static labels test") == 0);
    TEST_CHECK(f->context.metric.type == 0);
    cmt_sds_destroy(f->context.metric.name_orig);
    cmt_sds_destroy(f->context.metric.docstring);
    free(f->context.metric.ns);

    destroy(f);
}

void test_header_type()
{
    struct fixture *f = init(START_HEADER,
            "# TYPE cmt_labels_test counter\n"
            );
    TEST_CHECK(parse(f) == 0);

    TEST_CHECK(strcmp(f->context.metric.ns, "cmt") == 0);
    TEST_CHECK(strcmp(f->context.metric.subsystem, "labels") == 0);
    TEST_CHECK(strcmp(f->context.metric.name, "test") == 0);
    TEST_CHECK(f->context.metric.type == COUNTER);
    TEST_CHECK(f->context.metric.docstring == NULL);
    cmt_sds_destroy(f->context.metric.name_orig);
    free(f->context.metric.ns);

    destroy(f);
}

void test_header_help_type()
{
    struct fixture *f = init(START_HEADER,
            "# HELP cmt_labels_test Static labels test\n"
            "# TYPE cmt_labels_test summary\n"
            );

    TEST_CHECK(parse(f) == 0);

    TEST_CHECK(strcmp(f->context.metric.docstring, "Static labels test") == 0);
    TEST_CHECK(strcmp(f->context.metric.ns, "cmt") == 0);
    TEST_CHECK(strcmp(f->context.metric.subsystem, "labels") == 0);
    TEST_CHECK(strcmp(f->context.metric.name, "test") == 0);
    TEST_CHECK(f->context.metric.type == SUMMARY);
    cmt_sds_destroy(f->context.metric.name_orig);
    cmt_sds_destroy(f->context.metric.docstring);
    free(f->context.metric.ns);

    destroy(f);
}

void test_header_type_help()
{
    struct fixture *f = init(START_HEADER,
            "# TYPE cmt_labels_test gauge\n"
            "# HELP cmt_labels_test Static labels test\n"
            );

    TEST_CHECK(parse(f) == 0);

    TEST_CHECK(strcmp(f->context.metric.docstring, "Static labels test") == 0);
    TEST_CHECK(strcmp(f->context.metric.ns, "cmt") == 0);
    TEST_CHECK(strcmp(f->context.metric.subsystem, "labels") == 0);
    TEST_CHECK(strcmp(f->context.metric.name, "test") == 0);
    TEST_CHECK(f->context.metric.type == GAUGE);
    cmt_sds_destroy(f->context.metric.name_orig);
    cmt_sds_destroy(f->context.metric.docstring);
    free(f->context.metric.ns);

    destroy(f);
}

struct cmt_decode_prometheus_context_sample *add_empty_sample(struct fixture *f)
{
    struct cmt_decode_prometheus_context_sample *sample;
    sample = malloc(sizeof(*sample));
    memset(sample, 0, sizeof(*sample));
    mk_list_add(&sample->_head, &f->context.metric.samples);
    return sample;
}

void test_labels()
{
    struct fixture *f = init(START_LABELS, "dev=\"Calyptia\",lang=\"C\"");
    struct cmt_decode_prometheus_context_sample *sample = add_empty_sample(f);
    TEST_CHECK(parse(f) == 0);
    TEST_CHECK(f->context.metric.label_count == 2);
    TEST_CHECK(strcmp(f->context.metric.labels[0], "dev") == 0);
    TEST_CHECK(strcmp(sample->label_values[0], "Calyptia") == 0);
    TEST_CHECK(strcmp(f->context.metric.labels[1], "lang") == 0);
    TEST_CHECK(strcmp(sample->label_values[1], "C") == 0);
    cmt_sds_destroy(f->context.metric.labels[0]);
    cmt_sds_destroy(sample->label_values[0]);
    cmt_sds_destroy(f->context.metric.labels[1]);
    cmt_sds_destroy(sample->label_values[1]);
    free(sample);
    destroy(f);
}

void test_labels_trailing_comma()
{
    struct fixture *f = init(START_LABELS, "dev=\"Calyptia\",lang=\"C\",");
    struct cmt_decode_prometheus_context_sample *sample = add_empty_sample(f);
    TEST_CHECK(parse(f) == 0);
    TEST_CHECK(f->context.metric.label_count == 2);
    TEST_CHECK(strcmp(f->context.metric.labels[0], "dev") == 0);
    TEST_CHECK(strcmp(sample->label_values[0], "Calyptia") == 0);
    TEST_CHECK(strcmp(f->context.metric.labels[1], "lang") == 0);
    TEST_CHECK(strcmp(sample->label_values[1], "C") == 0);
    cmt_sds_destroy(f->context.metric.labels[0]);
    cmt_sds_destroy(sample->label_values[0]);
    cmt_sds_destroy(f->context.metric.labels[1]);
    cmt_sds_destroy(sample->label_values[1]);
    free(sample);
    destroy(f);
}

void test_sample()
{
    cmt_sds_t result;
    const char expected[] = (
            "# HELP cmt_labels_test some docstring\n"
            "# TYPE cmt_labels_test counter\n"
            "cmt_labels_test{dev=\"Calyptia\",lang=\"C\"} 1 0\n"
            );

    struct fixture *f = init(0,
            "# HELP cmt_labels_test some docstring\n"
            "# TYPE cmt_labels_test counter\n"
            "cmt_labels_test{dev=\"Calyptia\",lang=\"C\",} 1 0\n"
            );

    TEST_CHECK(parse(f) == 0);
    result = cmt_encode_prometheus_create(f->context.cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result, expected) == 0);
    cmt_sds_destroy(result);

    destroy(f);
}

void test_samples()
{
    cmt_sds_t result;
    const char expected[] = (
            "# HELP cmt_labels_test some docstring\n"
            "# TYPE cmt_labels_test gauge\n"
            "cmt_labels_test{dev=\"Calyptia\",lang=\"C\"} 5 999999\n"
            "cmt_labels_test{dev=\"Calyptia\",lang=\"C++\"} 6 7777\n"

            );

    struct fixture *f = init(0,
            "# HELP cmt_labels_test some docstring\n"
            "# TYPE cmt_labels_test gauge\n"
            "cmt_labels_test{dev=\"Calyptia\",lang=\"C\",} 5 999999\n"
            "cmt_labels_test{dev=\"Calyptia\",lang=\"C++\"} 6 7777\n"
            );

    TEST_CHECK(parse(f) == 0);
    result = cmt_encode_prometheus_create(f->context.cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result, expected) == 0);
    cmt_sds_destroy(result);

    destroy(f);
}

void test_escape_sequences()
{
    cmt_sds_t result;
    const char expected[] = (
        "# HELP msdos_file_access_time_seconds\n"
        "# TYPE msdos_file_access_time_seconds untyped\n"
        "msdos_file_access_time_seconds{path=\"C:\\\\DIR\\\\FILE.TXT\",error=\"Cannot find file:\\n\\\"FILE.TXT\\\"\"} 1458255915 0\n"
        );

    struct fixture *f = init(0,
        "# Escaping in label values:\n"
        "msdos_file_access_time_seconds{path=\"C:\\\\DIR\\\\FILE.TXT\",error=\"Cannot find file:\\n\\\"FILE.TXT\\\"\"} 1.458255915e9\n"
        );

    TEST_CHECK(parse(f) == 0);
    result = cmt_encode_prometheus_create(f->context.cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result, expected) == 0);
    cmt_sds_destroy(result);

    destroy(f);
}

void test_metric_without_labels()
{ 
    cmt_sds_t result;

    const char expected[] =
        "# HELP metric_without_timestamp_and_labels\n"
        "# TYPE metric_without_timestamp_and_labels untyped\n"
        "metric_without_timestamp_and_labels 12.470000000000001 0\n"
        ;

    struct fixture *f = init(0,
        "# Minimalistic line:\n"
        "metric_without_timestamp_and_labels 12.47\n"
        );

    TEST_CHECK(parse(f) == 0);
    result = cmt_encode_prometheus_create(f->context.cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result, expected) == 0);
    cmt_sds_destroy(result);

    destroy(f);
}

void test_prometheus_spec_example()
{
    char errbuf[256];
    int status;
    cmt_sds_t result;
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.errbuf = errbuf;
    opts.errbuf_size = sizeof(errbuf);
    const char in_buf[] =
        "# TYPE http_requests_total counter\n"
        "# HELP http_requests_total The total number of HTTP requests.\n"
        "http_requests_total{method=\"post\",code=\"200\"} 1027 1395066363000\n"
        "http_requests_total{method=\"post\",code=\"400\"}    3 1395066363000\n"
        "\n"
        "# Escaping in label values:\n"
        "msdos_file_access_time_seconds{path=\"C:\\\\DIR\\\\FILE.TXT\",error=\"Cannot find file:\\n\\\"FILE.TXT\\\"\"} 1.458255915e9\n"
        "\n"
        "# Minimalistic line:\n"
        "metric_without_timestamp_and_labels 12.47\n"
        "\n"
        "# A weird metric from before the epoch:\n"
        "something_weird{problem=\"division by zero\"} +Inf -3982045\n"
        "\n"
        "# A histogram, which has a pretty complex representation in the text format:\n"
        "# HELP http_request_duration_seconds_bucket A histogram of the request duration.\n"
        "# TYPE http_request_duration_seconds_bucket counter\n"
        "http_request_duration_seconds_bucket{le=\"0.05\"} 24054\n"
        "http_request_duration_seconds_bucket{le=\"0.1\"} 33444\n"
        "http_request_duration_seconds_bucket{le=\"0.2\"} 100392\n"
        "http_request_duration_seconds_bucket{le=\"0.5\"} 129389\n"
        "http_request_duration_seconds_bucket{le=\"1\"} 133988\n"
        "http_request_duration_seconds_bucket{le=\"+Inf\"} 144320\n"
        "http_request_duration_seconds_sum 53423\n"
        "http_request_duration_seconds_count 144320\n"
        "\n"
        "# Finally a summary, which has a complex representation, too:\n"
        "# HELP rpc_duration_seconds A summary of the RPC duration in seconds.\n"
        "# TYPE rpc_duration_seconds gauge\n"
        "rpc_duration_seconds{quantile=\"0.01\"} 3102\n"
        "rpc_duration_seconds{quantile=\"0.05\"} 3272\n"
        "rpc_duration_seconds{quantile=\"0.5\"} 4773\n"
        "rpc_duration_seconds{quantile=\"0.9\"} 9001\n"
        "rpc_duration_seconds{quantile=\"0.99\"} 76656\n"
        "rpc_duration_seconds_sum 1.7560473e+07\n"
        "rpc_duration_seconds_count 2693\n"
        ;
    const char expected[] =
        "# HELP http_requests_total The total number of HTTP requests.\n"
        "# TYPE http_requests_total counter\n"
        "http_requests_total{method=\"post\",code=\"200\"} 1027 1395066363000\n"
        "http_requests_total{method=\"post\",code=\"400\"} 3 1395066363000\n"
        "# HELP http_request_duration_seconds_bucket A histogram of the request duration.\n"
        "# TYPE http_request_duration_seconds_bucket counter\n"
        "http_request_duration_seconds_bucket{le=\"0.05\"} 24054 0\n"
        "http_request_duration_seconds_bucket{le=\"0.1\"} 33444 0\n"
        "http_request_duration_seconds_bucket{le=\"0.2\"} 100392 0\n"
        "http_request_duration_seconds_bucket{le=\"0.5\"} 129389 0\n"
        "http_request_duration_seconds_bucket{le=\"1\"} 133988 0\n"
        "http_request_duration_seconds_bucket{le=\"+Inf\"} 144320 0\n"
        "# HELP rpc_duration_seconds A summary of the RPC duration in seconds.\n"
        "# TYPE rpc_duration_seconds gauge\n"
        "rpc_duration_seconds{quantile=\"0.01\"} 3102 0\n"
        "rpc_duration_seconds{quantile=\"0.05\"} 3272 0\n"
        "rpc_duration_seconds{quantile=\"0.5\"} 4773 0\n"
        "rpc_duration_seconds{quantile=\"0.9\"} 9001 0\n"
        "rpc_duration_seconds{quantile=\"0.99\"} 76656 0\n"
        "# HELP msdos_file_access_time_seconds\n"
        "# TYPE msdos_file_access_time_seconds untyped\n"
        "msdos_file_access_time_seconds{path=\"C:\\\\DIR\\\\FILE.TXT\",error=\"Cannot find file:\\n\\\"FILE.TXT\\\"\"} 1458255915 0\n"
        "# HELP metric_without_timestamp_and_labels\n"
        "# TYPE metric_without_timestamp_and_labels untyped\n"
        "metric_without_timestamp_and_labels 12.470000000000001 0\n"
        "# HELP something_weird\n"
        "# TYPE something_weird untyped\n"
        "something_weird{problem=\"division by zero\"} inf 0\n"
        "# HELP http_request_duration_seconds_sum\n"
        "# TYPE http_request_duration_seconds_sum untyped\n"
        "http_request_duration_seconds_sum 53423 0\n"
        "# HELP http_request_duration_seconds_count\n"
        "# TYPE http_request_duration_seconds_count untyped\n"
        "http_request_duration_seconds_count 144320 0\n"
        "# HELP rpc_duration_seconds_sum\n"
        "# TYPE rpc_duration_seconds_sum untyped\n"
        "rpc_duration_seconds_sum 17560473 0\n"
        "# HELP rpc_duration_seconds_count\n"
        "# TYPE rpc_duration_seconds_count untyped\n"
        "rpc_duration_seconds_count 2693 0\n"
        ;

    cmt_initialize();
    status = cmt_decode_prometheus_create(&cmt, in_buf, 0, &opts);
    TEST_CHECK(status == 0);
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result, expected) == 0);
    cmt_sds_destroy(result);
    cmt_decode_prometheus_destroy(cmt);
}

void test_bison_parsing_error()
{
    // Note that in this test I commented checks for the error message. The
    // reason is that the message is different depending on which bison
    // version is used to generate the parser, so not fully deterministic.
    int status;
    char errbuf[256];
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.errbuf = errbuf;
    opts.errbuf_size = sizeof(errbuf);

    status = cmt_decode_prometheus_create(&cmt, "", 0, &opts);
    TEST_CHECK(status == CMT_DECODE_PROMETHEUS_SYNTAX_ERROR);
    // TEST_CHECK(strcmp(errbuf,
    //             "syntax error, unexpected end of file") == 0);

    status = cmt_decode_prometheus_create(&cmt,
            "# HELP metric_name some docstring\n"
            "# TYPE metric_name counter\n"
            "metric_name", 0, &opts);
    TEST_CHECK(status == CMT_DECODE_PROMETHEUS_SYNTAX_ERROR);
    // TEST_CHECK(strcmp(errbuf,
    //             "syntax error, unexpected end of file, expecting '{' "
    //             "or FPOINT or INTEGER") == 0);

    status = cmt_decode_prometheus_create(&cmt,
            "# HELP metric_name some docstring\n"
            "# TYPE metric_name counter\n"
            "metric_name {key", 0, &opts);
    TEST_CHECK(status == CMT_DECODE_PROMETHEUS_SYNTAX_ERROR);
    // TEST_CHECK(strcmp(errbuf,
    //             "syntax error, unexpected end of file, expecting '='") == 0);

    status = cmt_decode_prometheus_create(&cmt,
            "# HELP metric_name some docstring\n"
            "# TYPE metric_name counter\n"
            "metric_name {key=", 0, &opts);
    TEST_CHECK(status == CMT_DECODE_PROMETHEUS_SYNTAX_ERROR);
    // TEST_CHECK(strcmp(errbuf,
    //             "syntax error, unexpected end of file, expecting QUOTED") == 0);

    status = cmt_decode_prometheus_create(&cmt,
            "# HELP metric_name some docstring\n"
            "# TYPE metric_name counter\n"
            "metric_name {key=\"abc\"", 0, &opts);
    TEST_CHECK(status == CMT_DECODE_PROMETHEUS_SYNTAX_ERROR);
    // TEST_CHECK(strcmp(errbuf,
    //             "syntax error, unexpected end of file, expecting '}'") == 0);

    status = cmt_decode_prometheus_create(&cmt,
            "# HELP metric_name some docstring\n"
            "# TYPE metric_name counter\n"
            "metric_name {key=\"abc\"}", 0, &opts);
    TEST_CHECK(status == CMT_DECODE_PROMETHEUS_SYNTAX_ERROR);
    // TEST_CHECK(strcmp(errbuf,
    //             "syntax error, unexpected end of file, expecting "
    //             "FPOINT or INTEGER") == 0);
}

void test_label_limits()
{
    int i;
    int status;
    struct cmt_counter *counter;
    char errbuf[256];
    struct cmt *cmt;
    char inbuf[65535];
    int pos;
    struct cmt_decode_prometheus_parse_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.errbuf = errbuf;
    opts.errbuf_size = sizeof(errbuf);

    pos = snprintf(inbuf, sizeof(inbuf),
            "# HELP many_labels_metric reaches maximum number labels\n"
            "# TYPE many_labels_metric counter\n"
            "many_labels_metric {");
    for (i = 0; i < CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT && pos < sizeof(inbuf); i++) {
        pos += snprintf(inbuf + pos, sizeof(inbuf) - pos, "l%d=\"%d\",", i, i);
    }
    snprintf(inbuf + pos, sizeof(inbuf) - pos, "} 55 0\n");

    status = cmt_decode_prometheus_create(&cmt, inbuf, 0, &opts);
    TEST_CHECK(status == 0);
    counter = mk_list_entry_first(&cmt->counters, struct cmt_counter, _head);
    TEST_CHECK(counter->map->label_count == CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT);
    cmt_decode_prometheus_destroy(cmt);

    // write one more label to exceed limit
    snprintf(inbuf + pos, sizeof(inbuf) - pos, "last=\"val\"} 55 0\n");
    status = cmt_decode_prometheus_create(&cmt, inbuf, 0, &opts);
    TEST_CHECK(status == CMT_DECODE_PROMETHEUS_MAX_LABEL_COUNT_EXCEEDED);
    TEST_CHECK(strcmp(errbuf, "maximum number of labels exceeded") == 0);
}

void test_invalid_value()
{
    int status;
    char errbuf[256];
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.errbuf = errbuf;
    opts.errbuf_size = sizeof(errbuf);

    status = cmt_decode_prometheus_create(&cmt,
            "# HELP metric_name some docstring\n"
            "# TYPE metric_name counter\n"
            "metric_name {key=\"abc\"} 10e", 0, &opts);
    TEST_CHECK(status == CMT_DECODE_PROMETHEUS_PARSE_VALUE_FAILED);
    TEST_CHECK(strcmp(errbuf,
                "failed to parse sample: \"10e\" is not a valid value") == 0);
}

void test_invalid_timestamp()
{
    int status;
    char errbuf[256];
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.errbuf = errbuf;
    opts.errbuf_size = sizeof(errbuf);

    status = cmt_decode_prometheus_create(&cmt,
            "# HELP metric_name some docstring\n"
            "# TYPE metric_name counter\n"
            "metric_name {key=\"abc\"} 10 3e", 0, &opts);
    TEST_CHECK(status == CMT_DECODE_PROMETHEUS_PARSE_TIMESTAMP_FAILED);
    TEST_CHECK(strcmp(errbuf,
                "failed to parse sample: \"3e\" is not a valid timestamp") == 0);
}

void test_default_timestamp()
{
    int status;
    cmt_sds_t result;
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.default_timestamp = 557 * 10e5;


    status = cmt_decode_prometheus_create(&cmt,
            "# HELP metric_name some docstring\n"
            "# TYPE metric_name counter\n"
            "metric_name {key=\"abc\"} 10", 0, &opts);
    TEST_CHECK(status == 0);
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result,
            "# HELP metric_name some docstring\n"
            "# TYPE metric_name counter\n"
            "metric_name{key=\"abc\"} 10 557\n") == 0);
    cmt_sds_destroy(result);
    cmt_decode_prometheus_destroy(cmt);
}

void test_values()
{
    int status;
    cmt_sds_t result;
    struct cmt *cmt;

    status = cmt_decode_prometheus_create(&cmt,
            "# HELP metric_name some docstring\n"
            "# TYPE metric_name gauge\n"
            "metric_name {key=\"simple integer\"} 54\n"
            "metric_name {key=\"simple float\"} 12.47\n"
            "metric_name {key=\"scientific notation 1\"} 1.7560473e+07\n"
            "metric_name {key=\"scientific notation 2\"} 17560473e-07\n"
            "metric_name {key=\"Positive \\\"not a number\\\"\"} +NAN\n"
            "metric_name {key=\"Negative \\\"not a number\\\"\"} -NaN\n"
            "metric_name {key=\"Positive infinity\"} +INF\n"
            "metric_name {key=\"Negative infinity\"} -iNf\n", 0, NULL);
    TEST_CHECK(status == 0);
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result,
            "# HELP metric_name some docstring\n"
            "# TYPE metric_name gauge\n"
            "metric_name{key=\"simple integer\"} 54 0\n"
            "metric_name{key=\"simple float\"} 12.470000000000001 0\n"
            "metric_name{key=\"scientific notation 1\"} 17560473 0\n"
            "metric_name{key=\"scientific notation 2\"} 1.7560473000000001 0\n"
            "metric_name{key=\"Positive \\\"not a number\\\"\"} nan 0\n"
            "metric_name{key=\"Negative \\\"not a number\\\"\"} -nan 0\n"
            "metric_name{key=\"Positive infinity\"} inf 0\n"
            "metric_name{key=\"Negative infinity\"} -inf 0\n") == 0);
    cmt_sds_destroy(result);
    cmt_decode_prometheus_destroy(cmt);
}

void test_in_size()
{
    int status;
    cmt_sds_t result;
    struct cmt *cmt;
    cmt_sds_t in_buf;
    size_t in_size;

    in_buf = cmt_sds_create("metric_name {key=\"1\"} 1\n");
    in_size = cmt_sds_len(in_buf);
    in_buf = cmt_sds_cat(in_buf, "metric_name {key=\"2\"} 2\n", in_size);

    status = cmt_decode_prometheus_create(&cmt, in_buf, in_size, NULL);
    TEST_CHECK(status == 0);
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result,
                "# HELP metric_name\n"
                "# TYPE metric_name untyped\n"
                "metric_name{key=\"1\"} 1 0\n") == 0);
    cmt_sds_destroy(result);
    cmt_sds_destroy(in_buf);
    cmt_decode_prometheus_destroy(cmt);
}

// reproduces https://github.com/calyptia/cmetrics/issues/71
void test_issue_71()
{
    int status;
    struct cmt *cmt;
    cmt_sds_t in_buf = read_file(CMT_TESTS_DATA_PATH "/issue_71.txt");
    size_t in_size = cmt_sds_len(in_buf);

    status = cmt_decode_prometheus_create(&cmt, in_buf, in_size, NULL);
    TEST_CHECK(status == 0);
    cmt_sds_destroy(in_buf);
    cmt_decode_prometheus_destroy(cmt);
}

void test_histogram()
{
    int status;
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    cmt_sds_t result;
    memset(&opts, 0, sizeof(opts));

    status = cmt_decode_prometheus_create(&cmt,
            "# HELP http_request_duration_seconds A histogram of the request duration.\n"
            "# TYPE http_request_duration_seconds histogram\n"
            "http_request_duration_seconds_bucket{le=\"0.05\"} 24054\n"
            "http_request_duration_seconds_bucket{le=\"0.1\"} 33444\n"
            "http_request_duration_seconds_bucket{le=\"0.2\"} 100392\n"
            "http_request_duration_seconds_bucket{le=\"0.5\"} 129389\n"
            "http_request_duration_seconds_bucket{le=\"1\"} 133988\n"
            "http_request_duration_seconds_bucket{le=\"+Inf\"} 144320\n"
            "http_request_duration_seconds_sum 53423\n"
            "http_request_duration_seconds_count 144320\n", 0, &opts);
    TEST_CHECK(status == 0);
    result = cmt_encode_prometheus_create(cmt, CMT_FALSE);
    TEST_CHECK(strcmp(result,
            "# HELP http_request_duration_seconds A histogram of the request duration.\n"
            "# TYPE http_request_duration_seconds histogram\n"
            "http_request_duration_seconds_bucket{le=\"0.05\"} 24054\n"
            "http_request_duration_seconds_bucket{le=\"0.1\"} 33444\n"
            "http_request_duration_seconds_bucket{le=\"0.2\"} 100392\n"
            "http_request_duration_seconds_bucket{le=\"0.5\"} 129389\n"
            "http_request_duration_seconds_bucket{le=\"1.0\"} 133988\n"
            "http_request_duration_seconds_bucket{le=\"+Inf\"} 144320\n"
            "http_request_duration_seconds_sum 53423\n"
            "http_request_duration_seconds_count 144320\n") == 0);
    cmt_sds_destroy(result);
    cmt_decode_prometheus_destroy(cmt);
}

void test_histogram_labels()
{
    int status;
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    memset(&opts, 0, sizeof(opts));
    cmt_sds_t result;

    status = cmt_decode_prometheus_create(&cmt,
            "# HELP http_request_duration_seconds A histogram of the request duration.\n"
            "# TYPE http_request_duration_seconds histogram\n"
            "http_request_duration_seconds_bucket{label1=\"val1\",le=\"0.05\",label2=\"val2\"} 24054\n"
            "http_request_duration_seconds_bucket{label1=\"val1\",le=\"0.1\",label2=\"val2\"} 33444\n"
            "http_request_duration_seconds_bucket{label1=\"val1\",le=\"0.2\",label2=\"val2\"} 100392\n"
            "http_request_duration_seconds_bucket{label1=\"val1\",le=\"0.5\",label2=\"val2\"} 129389\n"
            "http_request_duration_seconds_bucket{label1=\"val1\",le=\"1\",label2=\"val2\"} 133988\n"
            "http_request_duration_seconds_bucket{label1=\"val1\",le=\"+Inf\",label2=\"val2\"} 144320\n"
            "http_request_duration_seconds_sum{label1=\"val1\",label2=\"val2\"} 53423\n"
            "http_request_duration_seconds_count{label1=\"val1\",label2=\"val2\"}144320\n", 0, &opts);
    TEST_CHECK(status == 0);
    result = cmt_encode_prometheus_create(cmt, CMT_FALSE);
    TEST_CHECK(strcmp(result,
            "# HELP http_request_duration_seconds A histogram of the request duration.\n"
            "# TYPE http_request_duration_seconds histogram\n"
            "http_request_duration_seconds_bucket{le=\"0.05\",label1=\"val1\",label2=\"val2\"} 24054\n"
            "http_request_duration_seconds_bucket{le=\"0.1\",label1=\"val1\",label2=\"val2\"} 33444\n"
            "http_request_duration_seconds_bucket{le=\"0.2\",label1=\"val1\",label2=\"val2\"} 100392\n"
            "http_request_duration_seconds_bucket{le=\"0.5\",label1=\"val1\",label2=\"val2\"} 129389\n"
            "http_request_duration_seconds_bucket{le=\"1.0\",label1=\"val1\",label2=\"val2\"} 133988\n"
            "http_request_duration_seconds_bucket{le=\"+Inf\",label1=\"val1\",label2=\"val2\"} 144320\n"
            "http_request_duration_seconds_sum{label1=\"val1\",label2=\"val2\"} 53423\n"
            "http_request_duration_seconds_count{label1=\"val1\",label2=\"val2\"} 144320\n") == 0);
    cmt_sds_destroy(result);
    cmt_decode_prometheus_destroy(cmt);
}

void test_summary()
{
    int status;
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    cmt_sds_t result;
    memset(&opts, 0, sizeof(opts));

    status = cmt_decode_prometheus_create(&cmt,
        "# HELP rpc_duration_seconds A summary of the RPC duration in seconds.\n"
        "# TYPE rpc_duration_seconds summary\n"
        "rpc_duration_seconds{quantile=\"0.01\"} 3102\n"
        "rpc_duration_seconds{quantile=\"0.05\"} 3272\n"
        "rpc_duration_seconds{quantile=\"0.5\"} 4773\n"
        "rpc_duration_seconds{quantile=\"0.9\"} 9001\n"
        "rpc_duration_seconds{quantile=\"0.99\"} 76656\n"
        "rpc_duration_seconds_sum 1.7560473e+07\n"
        "rpc_duration_seconds_count 2693\n", 0, &opts);
    TEST_CHECK(status == 0);
    result = cmt_encode_prometheus_create(cmt, CMT_FALSE);
    TEST_CHECK(strcmp(result,
        "# HELP rpc_duration_seconds A summary of the RPC duration in seconds.\n"
        "# TYPE rpc_duration_seconds summary\n"
        "rpc_duration_seconds{quantile=\"0.01\"} 3102\n"
        "rpc_duration_seconds{quantile=\"0.05\"} 3272\n"
        "rpc_duration_seconds{quantile=\"0.5\"} 4773\n"
        "rpc_duration_seconds{quantile=\"0.9\"} 9001\n"
        "rpc_duration_seconds{quantile=\"0.99\"} 76656\n"
        "rpc_duration_seconds_sum 17560473\n"
        "rpc_duration_seconds_count 2693\n") == 0);
    cmt_sds_destroy(result);
    cmt_decode_prometheus_destroy(cmt);
}

void test_null_labels()
{
    int status;
    cmt_sds_t result;
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    memset(&opts, 0, sizeof(opts));
    const char in_buf[] =
        "# TYPE ns_ss_name counter\n"
        "# HELP ns_ss_name Example with null labels.\n"
        "ns_ss_name{A=\"a\",B=\"b\",C=\"c\"} 1027 1395066363000\n"
        "ns_ss_name{C=\"c\",D=\"d\",E=\"e\"} 1027 1395066363000\n"
        ;
    const char expected[] =
        "# HELP ns_ss_name Example with null labels.\n"
        "# TYPE ns_ss_name counter\n"
        "ns_ss_name{A=\"a\",B=\"b\",C=\"c\"} 1027 1395066363000\n"
        "ns_ss_name{C=\"c\",D=\"d\",E=\"e\"} 1027 1395066363000\n"
        ;

    cmt_initialize();
    status = cmt_decode_prometheus_create(&cmt, in_buf, 0, &opts);
    TEST_CHECK(status == 0);
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result, expected) == 0);
    cmt_sds_destroy(result);
    cmt_decode_prometheus_destroy(cmt);
}

// reproduces https://github.com/fluent/fluent-bit/issues/5541
void test_issue_fluent_bit_5541()
{
    int status;
    char *result;
    struct cmt *cmt;
    cmt_sds_t in_buf = read_file(CMT_TESTS_DATA_PATH "/issue_fluent_bit_5541.txt");
    size_t in_size = cmt_sds_len(in_buf);

    const char expected[] =
        "# HELP http_request_duration_seconds HTTP request latency (seconds)\n"
        "# TYPE http_request_duration_seconds histogram\n"
        "http_request_duration_seconds_bucket{le=\"0.005\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"0.01\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"0.025\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"0.05\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"0.075\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"0.1\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"0.25\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"0.5\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"0.75\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"1.0\"} 2 0\n" 
        "http_request_duration_seconds_bucket{le=\"2.5\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"5.0\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"7.5\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"10.0\"} 2 0\n"
        "http_request_duration_seconds_bucket{le=\"+Inf\"} 2 0\n"
        "http_request_duration_seconds_sum 0.00069131026975810528 0\n"
        "http_request_duration_seconds_count 2 0\n"
        ;

    status = cmt_decode_prometheus_create(&cmt, in_buf, in_size, NULL);
    TEST_CHECK(status == 0);

    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result, expected) == 0);

    cmt_sds_destroy(in_buf);
    cmt_sds_destroy(result);
    cmt_decode_prometheus_destroy(cmt);
}

// reproduces https://github.com/fluent/fluent-bit/issues/5894
void test_issue_fluent_bit_5894()
{
    char errbuf[256];
    int status;
    cmt_sds_t result;
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.errbuf = errbuf;
    opts.errbuf_size = sizeof(errbuf);
    cmt_sds_t in_buf = read_file(CMT_TESTS_DATA_PATH "/issue_fluent_bit_5894.txt");
    size_t in_size = cmt_sds_len(in_buf);

    const char expected[] =
        "# HELP hikaricp_connections_timeout_total Connection timeout total count\n"
        "# TYPE hikaricp_connections_timeout_total counter\n"
        "hikaricp_connections_timeout_total{pool=\"mcadb\"} 0 0\n"
        "# HELP rabbitmq_consumed_total\n"
        "# TYPE rabbitmq_consumed_total counter\n"
        "rabbitmq_consumed_total{name=\"rabbit\"} 0 0\n"
        "# HELP rabbitmq_failed_to_publish_total\n"
        "# TYPE rabbitmq_failed_to_publish_total counter\n"
        "rabbitmq_failed_to_publish_total{name=\"rabbit\"} 0 0\n"
        "# HELP rabbitmq_acknowledged_published_total\n"
        "# TYPE rabbitmq_acknowledged_published_total counter\n"
        "rabbitmq_acknowledged_published_total{name=\"rabbit\"} 0 0\n"
        "# HELP tomcat_sessions_rejected_sessions_total\n"
        "# TYPE tomcat_sessions_rejected_sessions_total counter\n"
        "tomcat_sessions_rejected_sessions_total 0 0\n"

        "# HELP process_start_time_seconds Start time of the process since unix epoch.\n"
        "# TYPE process_start_time_seconds gauge\n"
        "process_start_time_seconds 1660594096.832 0\n"
        "# HELP spring_kafka_listener_seconds_max Kafka Listener Timer\n"
        "# TYPE spring_kafka_listener_seconds_max gauge\n"
        "spring_kafka_listener_seconds_max{exception=\"ListenerExecutionFailedException\",name=\"org.springframework.kafka.KafkaListenerEndpointContainer#0-0\",result=\"failure\"} 0 0\n"
        "spring_kafka_listener_seconds_max{exception=\"none\",name=\"org.springframework.kafka.KafkaListenerEndpointContainer#0-0\",result=\"success\"} 0 0\n"
        "# HELP process_files_max_files The maximum file descriptor count\n"
        "# TYPE process_files_max_files gauge\n"
        "process_files_max_files 1048576 0\n"
        "# HELP hikaricp_connections_pending Pending threads\n"
        "# TYPE hikaricp_connections_pending gauge\n"
        "hikaricp_connections_pending{pool=\"mcadb\"} 0 0\n"
        "# HELP jvm_memory_committed_bytes The amount of memory in bytes that is committed for the Java virtual machine to use\n"
        "# TYPE jvm_memory_committed_bytes gauge\n"
        "jvm_memory_committed_bytes{area=\"nonheap\",id=\"CodeHeap 'profiled nmethods'\"} 16056320 0\n"
        "jvm_memory_committed_bytes{area=\"heap\",id=\"G1 Survivor Space\"} 20971520 0\n"
        "jvm_memory_committed_bytes{area=\"heap\",id=\"G1 Old Gen\"} 232783872 0\n"
        "jvm_memory_committed_bytes{area=\"nonheap\",id=\"Metaspace\"} 103374848 0\n"
        "jvm_memory_committed_bytes{area=\"nonheap\",id=\"CodeHeap 'non-nmethods'\"} 4390912 0\n"
        "jvm_memory_committed_bytes{area=\"heap\",id=\"G1 Eden Space\"} 373293056 0\n"
        "jvm_memory_committed_bytes{area=\"nonheap\",id=\"Compressed Class Space\"} 13500416 0\n"
        "jvm_memory_committed_bytes{area=\"nonheap\",id=\"CodeHeap 'non-profiled nmethods'\"} 4521984 0\n"
        "# HELP process_files_open_files The open file descriptor count\n"
        "# TYPE process_files_open_files gauge\n"
        "process_files_open_files 290 0\n"
        "# HELP kafka_consumer_sync_time_max_seconds The max time taken for a group sync.\n"
        "# TYPE kafka_consumer_sync_time_max_seconds gauge\n"
        "kafka_consumer_sync_time_max_seconds{client_id=\"consumer-1\"} nan 0\n"
        "# HELP kafka_consumer_fetch_latency_avg_seconds The average time taken for a fetch request.\n"
        "# TYPE kafka_consumer_fetch_latency_avg_seconds gauge\n"
        "kafka_consumer_fetch_latency_avg_seconds{client_id=\"consumer-1\"} nan 0\n"
        "# HELP rabbitmq_channels\n"
        "# TYPE rabbitmq_channels gauge\n"
        "rabbitmq_channels{name=\"rabbit\"} 0 0\n"
        "# HELP kafka_consumer_sync_rate_syncs The number of group syncs per second. Group synchronization is the second and last phase of the rebalance protocol. A large value indicates group instability.\n"
        "# TYPE kafka_consumer_sync_rate_syncs gauge\n"
        "kafka_consumer_sync_rate_syncs{client_id=\"consumer-1\"} 0 0\n"
        "# HELP jvm_classes_loaded_classes The number of classes that are currently loaded in the Java virtual machine\n"
        "# TYPE jvm_classes_loaded_classes gauge\n"
        "jvm_classes_loaded_classes 17220 0\n"
        "# HELP jdbc_connections_min\n"
        "# TYPE jdbc_connections_min gauge\n"
        "jdbc_connections_min{name=\"dataSource\"} 10 0\n"
        "# HELP kafka_consumer_fetch_throttle_time_avg_seconds The average throttle time. When quotas are enabled, the broker may delay fetch requests in order to throttle a consumer which has exceeded its limit. This metric indicates how throttling time has been added to fetch requests on average.\n"
        "# TYPE kafka_consumer_fetch_throttle_time_avg_seconds gauge\n"
        "kafka_consumer_fetch_throttle_time_avg_seconds{client_id=\"consumer-1\"} nan 0\n"
        "# HELP tomcat_sessions_active_max_sessions\n"
        "# TYPE tomcat_sessions_active_max_sessions gauge\n"
        "tomcat_sessions_active_max_sessions 0 0\n"
        "# HELP process_cpu_usage The \"recent cpu usage\" for the Java Virtual Machine process\n"
        "# TYPE process_cpu_usage gauge\n"
        "process_cpu_usage 0.00070793903055696016 0\n"
        "# HELP jvm_buffer_total_capacity_bytes An estimate of the total capacity of the buffers in this pool\n"
        "# TYPE jvm_buffer_total_capacity_bytes gauge\n"
        "jvm_buffer_total_capacity_bytes{id=\"mapped\"} 0 0\n"
        "jvm_buffer_total_capacity_bytes{id=\"direct\"} 81920 0\n"
        "# HELP kafka_consumer_fetch_throttle_time_max_seconds The maximum throttle time.\n"
        "# TYPE kafka_consumer_fetch_throttle_time_max_seconds gauge\n"
        "kafka_consumer_fetch_throttle_time_max_seconds{client_id=\"consumer-1\"} nan 0\n"
        "# HELP system_load_average_1m The sum of the number of runnable entities queued to available processors and the number of runnable entities running on the available processors averaged over a period of time\n"
        "# TYPE system_load_average_1m gauge\n"
        "system_load_average_1m 0.52000000000000002 0\n"
        "# HELP kafka_consumer_join_time_avg_seconds The average time taken for a group rejoin. This value can get as high as the configured session timeout for the consumer, but should usually be lower.\n"
        "# TYPE kafka_consumer_join_time_avg_seconds gauge\n"
        "kafka_consumer_join_time_avg_seconds{client_id=\"consumer-1\"} nan 0\n"
        "# HELP jdbc_connections_max\n"
        "# TYPE jdbc_connections_max gauge\n"
        "jdbc_connections_max{name=\"dataSource\"} 10 0\n"
        "# HELP kafka_consumer_assigned_partitions The number of partitions currently assigned to this consumer.\n"
        "# TYPE kafka_consumer_assigned_partitions gauge\n"
        "kafka_consumer_assigned_partitions{client_id=\"consumer-1\"} 0 0\n"
        "# HELP kafka_consumer_heartbeat_response_time_max_seconds The max time taken to receive a response to a heartbeat request.\n"
        "# TYPE kafka_consumer_heartbeat_response_time_max_seconds gauge\n"
        "kafka_consumer_heartbeat_response_time_max_seconds{client_id=\"consumer-1\"} nan 0\n"
        "# HELP jvm_threads_daemon_threads The current number of live daemon threads\n"
        "# TYPE jvm_threads_daemon_threads gauge\n"
        "jvm_threads_daemon_threads 20 0\n"
        "# HELP system_cpu_count The number of processors available to the Java virtual machine\n"
        "# TYPE system_cpu_count gauge\n"
        "system_cpu_count 16 0\n"
        "# HELP jvm_buffer_count_buffers An estimate of the number of buffers in the pool\n"
        "# TYPE jvm_buffer_count_buffers gauge\n"
        "jvm_buffer_count_buffers{id=\"mapped\"} 0 0\n"
        "jvm_buffer_count_buffers{id=\"direct\"} 10 0\n"
        "# HELP kafka_consumer_io_wait_time_avg_seconds The average length of time the I/O thread spent waiting for a socket to be ready for reads or writes.\n"
        "# TYPE kafka_consumer_io_wait_time_avg_seconds gauge\n"
        "kafka_consumer_io_wait_time_avg_seconds{client_id=\"consumer-1\"} 0.047184790159065626 0\n"
        "# HELP jvm_memory_max_bytes The maximum amount of memory in bytes that can be used for memory management\n"
        "# TYPE jvm_memory_max_bytes gauge\n"
        "jvm_memory_max_bytes{area=\"nonheap\",id=\"CodeHeap 'profiled nmethods'\"} 122028032 0\n"
        "jvm_memory_max_bytes{area=\"heap\",id=\"G1 Survivor Space\"} -1 0\n"
        "jvm_memory_max_bytes{area=\"heap\",id=\"G1 Old Gen\"} 8331984896 0\n"
        "jvm_memory_max_bytes{area=\"nonheap\",id=\"Metaspace\"} -1 0\n"
        "jvm_memory_max_bytes{area=\"nonheap\",id=\"CodeHeap 'non-nmethods'\"} 7598080 0\n"
        "jvm_memory_max_bytes{area=\"heap\",id=\"G1 Eden Space\"} -1 0\n"
        "jvm_memory_max_bytes{area=\"nonheap\",id=\"Compressed Class Space\"} 1073741824 0\n"
        "jvm_memory_max_bytes{area=\"nonheap\",id=\"CodeHeap 'non-profiled nmethods'\"} 122032128 0\n"
        "# HELP jvm_gc_pause_seconds_max Time spent in GC pause\n"
        "# TYPE jvm_gc_pause_seconds_max gauge\n"
        "jvm_gc_pause_seconds_max{action=\"end of minor GC\",cause=\"Metadata GC Threshold\"} 0.02 0\n"
        "jvm_gc_pause_seconds_max{action=\"end of minor GC\",cause=\"G1 Evacuation Pause\"} 0 0\n"
        "# HELP kafka_consumer_connection_count_connections The current number of active connections.\n"
        "# TYPE kafka_consumer_connection_count_connections gauge\n"
        "kafka_consumer_connection_count_connections{client_id=\"consumer-1\"} 0 0\n"
        "# HELP jdbc_connections_active\n"
        "# TYPE jdbc_connections_active gauge\n"
        "jdbc_connections_active{name=\"dataSource\"} 0 0\n"

        "# HELP spring_kafka_listener_seconds Kafka Listener Timer\n"
        "# TYPE spring_kafka_listener_seconds summary\n"
        "spring_kafka_listener_seconds_sum{exception=\"ListenerExecutionFailedException\",name=\"org.springframework.kafka.KafkaListenerEndpointContainer#0-0\",result=\"failure\"} 0 0\n"
        "spring_kafka_listener_seconds_count{exception=\"ListenerExecutionFailedException\",name=\"org.springframework.kafka.KafkaListenerEndpointContainer#0-0\",result=\"failure\"} 0 0\n"
        "spring_kafka_listener_seconds_sum{exception=\"none\",name=\"org.springframework.kafka.KafkaListenerEndpointContainer#0-0\",result=\"success\"} 0 0\n"
        "spring_kafka_listener_seconds_count{exception=\"none\",name=\"org.springframework.kafka.KafkaListenerEndpointContainer#0-0\",result=\"success\"} 0 0\n"
        "# HELP hikaricp_connections_usage_seconds Connection usage time\n"
        "# TYPE hikaricp_connections_usage_seconds summary\n"
        "hikaricp_connections_usage_seconds_sum{pool=\"mcadb\"} 0 0\n"
        "hikaricp_connections_usage_seconds_count{pool=\"mcadb\"} 0 0\n"
        "# HELP jvm_gc_pause_seconds Time spent in GC pause\n"
        "# TYPE jvm_gc_pause_seconds summary\n"
        "jvm_gc_pause_seconds_sum{action=\"end of minor GC\",cause=\"Metadata GC Threshold\"} 0.031 0\n"
        "jvm_gc_pause_seconds_count{action=\"end of minor GC\",cause=\"Metadata GC Threshold\"} 2 0\n"
        "jvm_gc_pause_seconds_sum{action=\"end of minor GC\",cause=\"G1 Evacuation Pause\"} 0.016 0\n"
        "jvm_gc_pause_seconds_count{action=\"end of minor GC\",cause=\"G1 Evacuation Pause\"} 1 0\n"
        ;

    status = cmt_decode_prometheus_create(&cmt, in_buf, in_size, &opts);
    TEST_CHECK(status == 0);
    if (status) {
        fprintf(stderr, "PARSE ERROR:\n======\n%s\n======\n", errbuf);
    } else {
        result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
        status = strcmp(result, expected);
        TEST_CHECK(status == 0);
        if (status) {
            fprintf(stderr, "EXPECTED:\n======\n%s\n======\nRESULT:\n======\n%s\n======\n", expected, result);
        }
    }

    cmt_sds_destroy(in_buf);
    cmt_sds_destroy(result);
    cmt_decode_prometheus_destroy(cmt);
}

void test_empty_metrics()
{
    int status;
    cmt_sds_t result;
    struct cmt *cmt;
    struct cmt_decode_prometheus_parse_opts opts;
    memset(&opts, 0, sizeof(opts));
    const char in_buf[] =
        "# HELP kube_cronjob_annotations Kubernetes annotations converted to Prometheus labels.\n"
        "# TYPE kube_cronjob_annotations gauge\n"
        "# HELP kube_cronjob_labels Kubernetes labels converted to Prometheus labels.\n"
        "# TYPE kube_cronjob_labels gauge\n"
        "# HELP kube_cronjob_info Info about cronjob.\n"
        "# TYPE kube_cronjob_info gauge\n"
        "# HELP kube_cronjob_created Unix creation timestamp\n"
        "# TYPE kube_cronjob_created gauge\n"
        "# HELP kube_cronjob_status_active Active holds pointers to currently running jobs.\n"
        "# TYPE kube_cronjob_status_active gauge\n"
        "# HELP kube_cronjob_status_last_schedule_time LastScheduleTime keeps information of when was the last time the job was successfully scheduled.\n"
        "# TYPE kube_cronjob_status_last_schedule_time gauge\n"
        "# HELP kube_cronjob_status_last_successful_time LastSuccessfulTime keeps information of when was the last time the job was completed successfully.\n"
        "# TYPE kube_cronjob_status_last_successful_time gauge\n"
        "# HELP kube_cronjob_spec_suspend Suspend flag tells the controller to suspend subsequent executions.\n"
        "# TYPE kube_cronjob_spec_suspend gauge\n"
        "# HELP kube_cronjob_spec_starting_deadline_seconds Deadline in seconds for starting the job if it misses scheduled time for any reason.\n"
        "# TYPE kube_cronjob_spec_starting_deadline_seconds gauge\n"
        "# HELP kube_cronjob_next_schedule_time Next time the cronjob should be scheduled. The time after lastScheduleTime, or after the cron job's creation time if it's never been scheduled. Use this to determine if the job is delayed.\n"
        "# TYPE kube_cronjob_next_schedule_time gauge\n"
        "# HELP kube_cronjob_metadata_resource_version Resource version representing a specific version of the cronjob.\n"
        "# TYPE kube_cronjob_metadata_resource_version gauge\n"
        "# HELP kube_cronjob_spec_successful_job_history_limit Successful job history limit tells the controller how many completed jobs should be preserved.\n"
        "# TYPE kube_cronjob_spec_successful_job_history_limit gauge\n"
        "# HELP kube_cronjob_spec_failed_job_history_limit Failed job history limit tells the controller how many failed jobs should be preserved.\n"
        "# TYPE kube_cronjob_spec_failed_job_history_limit gauge\n"
        ;

    const char expected[] = "";

    cmt_initialize();
    status = cmt_decode_prometheus_create(&cmt, in_buf, 0, &opts);
    TEST_CHECK(status == 0);
    result = cmt_encode_prometheus_create(cmt, CMT_TRUE);
    TEST_CHECK(strcmp(result, expected) == 0);
    cmt_sds_destroy(result);
    cmt_decode_prometheus_destroy(cmt);
}

TEST_LIST = {
    {"header_help", test_header_help},
    {"header_type", test_header_type},
    {"header_help_type", test_header_help_type},
    {"header_type_help", test_header_type_help},
    {"labels", test_labels},
    {"labels_trailing_comma", test_labels_trailing_comma},
    {"sample", test_sample},
    {"samples", test_samples},
    {"escape_sequences", test_escape_sequences},
    {"metric_without_labels", test_metric_without_labels},
    {"prometheus_spec_example", test_prometheus_spec_example},
    {"bison_parsing_error", test_bison_parsing_error},
    {"label_limits", test_label_limits},
    {"invalid_value", test_invalid_value},
    {"invalid_timestamp", test_invalid_timestamp},
    {"default_timestamp", test_default_timestamp},
    {"values", test_values},
    {"in_size", test_in_size},
    {"issue_71", test_issue_71},
    {"histogram", test_histogram},
    {"histogram_labels", test_histogram_labels},
    {"summary", test_summary},
    {"null_labels", test_null_labels},
    {"issue_fluent_bit_5541", test_issue_fluent_bit_5541},
    {"issue_fluent_bit_5894", test_issue_fluent_bit_5894},
    {"empty_metrics", test_empty_metrics},
    { 0 }
};
