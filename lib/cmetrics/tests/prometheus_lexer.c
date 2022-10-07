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
#include <cmetrics/cmt_decode_prometheus.h>
#include <cmetrics/cmt_encode_prometheus_remote_write.h>
#include <stdio.h>

#include "cmt_decode_prometheus_parser.h"
#include "cmt_tests.h"

struct fixture {
    yyscan_t scanner;
    YY_BUFFER_STATE buf;
    YYSTYPE lval;
    struct cmt_decode_prometheus_context context;
    const char *text;
};

struct fixture *init(const char *test)
{
    struct fixture *f = malloc(sizeof(*f));
    memset(f, 0, sizeof(*f));
    cmt_decode_prometheus_lex_init(&f->scanner);
    f->buf = cmt_decode_prometheus__scan_string(test, f->scanner);
    return f;
}

void destroy(struct fixture *f)
{
    cmt_decode_prometheus__delete_buffer(f->buf, f->scanner);
    cmt_decode_prometheus_lex_destroy(f->scanner);
    free(f);
}

int lex(struct fixture *f)
{
    return cmt_decode_prometheus_lex(&f->lval, f->scanner, &(f->context));
}

void test_comment()
{
    struct fixture *f = init("# this is just a comment");
    TEST_CHECK(lex(f) == 0);  // 0 means EOF
    destroy(f);
}

void test_help()
{
    struct fixture *f = init("# HELP cmt_labels_test Static \\\\labels\\n test");

    TEST_CHECK(lex(f) == HELP);
    TEST_CHECK(strcmp(f->lval.str, "cmt_labels_test") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == METRIC_DOC);
    TEST_CHECK(strcmp(f->lval.str, "Static \\labels\n test") == 0);
    cfl_sds_destroy(f->lval.str);

    destroy(f);

    f = init("# HELP cmt_labels_test Static \\\\labels\\n test\n");

    TEST_CHECK(lex(f) == HELP);
    TEST_CHECK(strcmp(f->lval.str, "cmt_labels_test") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == METRIC_DOC);
    TEST_CHECK(strcmp(f->lval.str, "Static \\labels\n test") == 0);
    cfl_sds_destroy(f->lval.str);

    destroy(f);
}

void test_type()
{
    struct fixture *f = init("# TYPE metric_name gauge");

    TEST_CHECK(lex(f) == TYPE);
    TEST_CHECK(strcmp(f->lval.str, "metric_name") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == GAUGE);

    destroy(f);
}

void test_simple()
{
    struct fixture *f = init(
            "# HELP cmt_labels_test Static labels test\n"
            "# TYPE cmt_labels_test counter\n"
            "cmt_labels_test 1 0\n"
            "metric2{host=\"calyptia.com\",app=\"cmetrics \\n \\\\ \\\"\"} 2.5 0\n"
            "# HELP metric1 Second HELP tag\n"
            "metric1{escapes=\"\\n \\\\ \\\"\"} 4.12 5\n"
            );

    TEST_CHECK(lex(f) == HELP);
    TEST_CHECK(strcmp(f->lval.str, "cmt_labels_test") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == METRIC_DOC);
    TEST_CHECK(strcmp(f->lval.str, "Static labels test") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == TYPE);
    TEST_CHECK(strcmp(f->lval.str, "cmt_labels_test") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == COUNTER);

    TEST_CHECK(lex(f) == IDENTIFIER);
    TEST_CHECK(strcmp(f->lval.str, "cmt_labels_test") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == NUMSTR);
    TEST_CHECK(strcmp(f->lval.numstr, "1") == 0);

    TEST_CHECK(lex(f) == NUMSTR);
    TEST_CHECK(strcmp(f->lval.numstr, "0") == 0);

    TEST_CHECK(lex(f) == IDENTIFIER);
    TEST_CHECK(strcmp(f->lval.str, "metric2") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == '{');

    TEST_CHECK(lex(f) == IDENTIFIER);
    TEST_CHECK(strcmp(f->lval.str, "host") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == '=');

    TEST_CHECK(lex(f) == QUOTED);
    TEST_CHECK(strcmp(f->lval.str, "calyptia.com") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == ',');

    TEST_CHECK(lex(f) == IDENTIFIER);
    TEST_CHECK(strcmp(f->lval.str, "app") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == '=');

    TEST_CHECK(lex(f) == QUOTED);
    TEST_CHECK(strcmp(f->lval.str, "cmetrics \n \\ \"") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == '}');

    TEST_CHECK(lex(f) == NUMSTR);
    TEST_CHECK(strcmp(f->lval.numstr, "2.5") == 0);

    TEST_CHECK(lex(f) == NUMSTR);
    TEST_CHECK(strcmp(f->lval.numstr, "0") == 0);

    TEST_CHECK(lex(f) == HELP);
    TEST_CHECK(strcmp(f->lval.str, "metric1") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == METRIC_DOC);
    TEST_CHECK(strcmp(f->lval.str, "Second HELP tag") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == IDENTIFIER);
    TEST_CHECK(strcmp(f->lval.str, "metric1") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == '{');

    TEST_CHECK(lex(f) == IDENTIFIER);
    TEST_CHECK(strcmp(f->lval.str, "escapes") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == '=');

    TEST_CHECK(lex(f) == QUOTED);
    TEST_CHECK(strcmp(f->lval.str, "\n \\ \"") == 0);
    cfl_sds_destroy(f->lval.str);

    TEST_CHECK(lex(f) == '}');

    TEST_CHECK(lex(f) == NUMSTR);
    TEST_CHECK(strcmp(f->lval.numstr, "4.12") == 0);

    TEST_CHECK(lex(f) == NUMSTR);
    TEST_CHECK(strcmp(f->lval.numstr, "5") == 0);

    destroy(f);
}


TEST_LIST = {
    {"test_comment", test_comment},
    {"test_help", test_help},
    {"test_type", test_type},
    {"test_simple", test_simple},
    { 0 }
};
