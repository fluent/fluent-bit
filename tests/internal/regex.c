/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <string.h>
#include <fluent-bit/flb_regex.h>
#include "flb_tests_internal.h"

struct kv_list {
    int index;
    size_t size;
    char **lists;
};
static void cb_kv(const char *name, const char *value,
                  size_t vlen, void *data)
{
    size_t len;
    struct kv_list *l = (struct kv_list*)data;

    if (!TEST_CHECK(name != NULL && value != NULL && data != NULL)) {
        TEST_MSG("input is NULL");
        return;
    }
    len = strlen(name);

    if (!TEST_CHECK(len == strlen(l->lists[l->index * 2]))) {
        TEST_MSG("name: lenght error. got:%zu expect:%zu", len, strlen(l->lists[l->index * 2]));
        TEST_MSG("name: got:%s expect:%s", name, l->lists[l->index * 2]);
        goto cb_kv_end;
    }
    if (!TEST_CHECK(strncmp(name, l->lists[l->index * 2], len) == 0)) {
        TEST_MSG("name: mismatch. got:%s expect:%s", name, l->lists[l->index * 2]);
        goto cb_kv_end;
    }

    if (!TEST_CHECK(vlen == strlen(l->lists[l->index * 2+1]))) {
        TEST_MSG("value: lenght error. got:%zu expect:%zu", vlen, strlen(l->lists[l->index * 2+1]));
        TEST_MSG("value: got:%s expect:%s", value, l->lists[l->index * 2+1]);
        goto cb_kv_end;
    }
    if (!TEST_CHECK(strncmp(value, l->lists[l->index * 2+1], vlen) == 0)) {
        TEST_MSG("value: mismatch. got:%s expect:%s", value, l->lists[l->index * 2+1]);
        goto cb_kv_end;
    }
 cb_kv_end:
    l->index++;
}

static void test_basic()
{
    struct flb_regex *regex = NULL;
    struct flb_regex_search result;
    int ret;
    ssize_t size;
    const char *input = "string 1234 2022/10/24";

    char *expected_strs[] = {"str","string", "num","1234", "time","2022/10/24"};
    struct kv_list expected = {
        .index = 0,
        .size = sizeof(expected_strs)/sizeof(char *),
        .lists = &expected_strs[0],
    };

    regex = flb_regex_create("/(?<str>[a-z]+) (?<num>\\d+) (?<time>\\d{4}/\\d{2}/\\d{2})/");
    if (!TEST_CHECK(regex != NULL)) {
        TEST_MSG("flb_regex_create failed");
        exit(1);
    }

    size = flb_regex_do(regex, input, strlen(input), &result);
    if (!TEST_CHECK(size >= 0)) {
        TEST_MSG("flb_regex_do failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_parse(regex, &result, cb_kv, &expected);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_regex_parse failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_destroy(regex);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_regex_destroy failed");
        exit(1);
    }
}

/* test uri to check if misunderstanding "/pattern/option" */
static void test_uri()
{
    struct flb_regex *regex = NULL;
    struct flb_regex_search result;
    int ret;
    ssize_t size;
    const char *input = "/uri/is/hoge";

    char *expected_strs[] = {"middle","is"};
    struct kv_list expected = {
        .index = 0,
        .size = sizeof(expected_strs)/sizeof(char *),
        .lists = &expected_strs[0],
    };

    regex = flb_regex_create("/uri/(?<middle>[a-z]+)/hoge");
    if (!TEST_CHECK(regex != NULL)) {
        TEST_MSG("flb_regex_create failed");
        exit(1);
    }

    size = flb_regex_do(regex, input, strlen(input), &result);
    if (!TEST_CHECK(size >= 0)) {
        TEST_MSG("flb_regex_do failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_parse(regex, &result, cb_kv, &expected);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_regex_parse failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_destroy(regex);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_regex_destroy failed");
        exit(1);
    }
}

/* test "/pattern/i"  */
static void test_option_ignore_case()
{
    struct flb_regex *regex = NULL;
    struct flb_regex_search result;
    int ret;
    ssize_t size;
    const char *input = "STRING";

    char *expected_strs[] = {"str","STRING"};
    struct kv_list expected = {
        .index = 0,
        .size = sizeof(expected_strs)/sizeof(char *),
        .lists = &expected_strs[0],
    };

    regex = flb_regex_create("/(?<str>[a-z]+)/i");
    if (!TEST_CHECK(regex != NULL)) {
        TEST_MSG("flb_regex_create failed");
        exit(1);
    }

    size = flb_regex_do(regex, input, strlen(input), &result);
    if (!TEST_CHECK(size >= 0)) {
        TEST_MSG("flb_regex_do failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_parse(regex, &result, cb_kv, &expected);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_regex_parse failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_destroy(regex);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_regex_destroy failed");
        exit(1);
    }
}

/* test "/pattern/m" */
static void test_option_multiline()
{
    struct flb_regex *regex = NULL;
    struct flb_regex_search result;
    int ret;
    ssize_t size;
    const char *input = "string\n1234\nstring";

    char *expected_strs[] = {"full_str","string\n1234\nstring"};
    struct kv_list expected = {
        .index = 0,
        .size = sizeof(expected_strs)/sizeof(char *),
        .lists = &expected_strs[0],
    };

    regex = flb_regex_create("/(?<full_str>.+)/m");
    if (!TEST_CHECK(regex != NULL)) {
        TEST_MSG("flb_regex_create failed");
        exit(1);
    }

    size = flb_regex_do(regex, input, strlen(input), &result);
    if (!TEST_CHECK(size >= 0)) {
        TEST_MSG("flb_regex_do failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_parse(regex, &result, cb_kv, &expected);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_regex_parse failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_destroy(regex);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_regex_destroy failed");
        exit(1);
    }
}

/* test "/pattern/x" */
static void test_option_extend()
{
    struct flb_regex *regex = NULL;
    struct flb_regex_search result;
    int ret;
    ssize_t size;
    const char *input = "3.14";

    char *expected_strs[] = {"pi","3.14"};
    struct kv_list expected = {
        .index = 0,
        .size = sizeof(expected_strs)/sizeof(char *),
        .lists = &expected_strs[0],
    };

    regex = flb_regex_create("/(?<pi>\\d  \\. 14)/x");
    if (!TEST_CHECK(regex != NULL)) {
        TEST_MSG("flb_regex_create failed");
        exit(1);
    }

    size = flb_regex_do(regex, input, strlen(input), &result);
    if (!TEST_CHECK(size >= 0)) {
        TEST_MSG("flb_regex_do failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_parse(regex, &result, cb_kv, &expected);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_regex_parse failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_destroy(regex);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_regex_destroy failed");
        exit(1);
    }
}

/* test "/pattern/ix" */
static void test_option_i_x()
{
    struct flb_regex *regex = NULL;
    struct flb_regex_search result;
    int ret;
    ssize_t size;
    const char *input = "3.14pi";

    char *expected_strs[] = {"full_str","3.14pi"};
    struct kv_list expected = {
        .index = 0,
        .size = sizeof(expected_strs)/sizeof(char *),
        .lists = &expected_strs[0],
    };

    regex = flb_regex_create("/(?<full_str>\\d  \\. 14PI)/ix");
    if (!TEST_CHECK(regex != NULL)) {
        TEST_MSG("flb_regex_create failed");
        exit(1);
    }

    size = flb_regex_do(regex, input, strlen(input), &result);
    if (!TEST_CHECK(size >= 0)) {
        TEST_MSG("flb_regex_do failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_parse(regex, &result, cb_kv, &expected);
    if (!TEST_CHECK(ret != -1)) {
        TEST_MSG("flb_regex_parse failed");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_destroy(regex);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_regex_destroy failed");
        exit(1);
    }
}

TEST_LIST = {
    { "basic" , test_basic},
    { "uri" , test_uri},
    { "option_ignore_case", test_option_ignore_case},
    { "option_multiline" , test_option_multiline},
    { "option_extend" , test_option_extend},
    { "option_i_x" , test_option_i_x},
    { 0 }
};
