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
        "# HELP msdos_file_access_time_seconds (no information)\n"
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
        "# HELP metric_without_timestamp_and_labels (no information)\n"
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
        "# HELP msdos_file_access_time_seconds (no information)\n"
        "# TYPE msdos_file_access_time_seconds untyped\n"
        "msdos_file_access_time_seconds{path=\"C:\\\\DIR\\\\FILE.TXT\",error=\"Cannot find file:\\n\\\"FILE.TXT\\\"\"} 1458255915 0\n"
        "# HELP metric_without_timestamp_and_labels (no information)\n"
        "# TYPE metric_without_timestamp_and_labels untyped\n"
        "metric_without_timestamp_and_labels 12.470000000000001 0\n"
        "# HELP something_weird (no information)\n"
        "# TYPE something_weird untyped\n"
        "something_weird{problem=\"division by zero\"} inf 0\n"
        "# HELP http_request_duration_seconds_sum (no information)\n"
        "# TYPE http_request_duration_seconds_sum untyped\n"
        "http_request_duration_seconds_sum 53423 0\n"
        "# HELP http_request_duration_seconds_count (no information)\n"
        "# TYPE http_request_duration_seconds_count untyped\n"
        "http_request_duration_seconds_count 144320 0\n"
        "# HELP rpc_duration_seconds_sum (no information)\n"
        "# TYPE rpc_duration_seconds_sum untyped\n"
        "rpc_duration_seconds_sum 17560473 0\n"
        "# HELP rpc_duration_seconds_count (no information)\n"
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
            "# TYPE metric_name counter", 0, &opts);
    TEST_CHECK(status == CMT_DECODE_PROMETHEUS_SYNTAX_ERROR);
    // TEST_CHECK(strcmp(errbuf,
    //             "syntax error, unexpected end of file, "
    //             "expecting IDENTIFIER") == 0);

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
                "# HELP metric_name (no information)\n"
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
    { 0 }
};
