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
#include <onigmo.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_thread_storage.h>
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

static void test_literal_slash()
{
    struct flb_regex *regex = NULL;
    int ret;

    regex = flb_regex_create("/");
    if (!TEST_CHECK(regex != NULL)) {
        TEST_MSG("flb_regex_create failed");
        exit(1);
    }

    ret = flb_regex_match(regex, (unsigned char *) "/tmp", 4);
    if (!TEST_CHECK(ret == 1)) {
        TEST_MSG("literal slash did not match");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_match(regex, (unsigned char *) "tmp", 3);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("literal slash matched string without slash");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_destroy(regex);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_regex_destroy failed");
        exit(1);
    }
}

static void test_slash_delimited_pattern()
{
    struct flb_regex *regex = NULL;
    int ret;

    regex = flb_regex_create("/tmp/");
    if (!TEST_CHECK(regex != NULL)) {
        TEST_MSG("flb_regex_create failed");
        exit(1);
    }

    ret = flb_regex_match(regex, (unsigned char *) "tmp", 3);
    if (!TEST_CHECK(ret == 1)) {
        TEST_MSG("slash-delimited pattern did not match");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_destroy(regex);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_regex_destroy failed");
        exit(1);
    }
}

static void test_slash_delimited_literal_slashes()
{
    struct flb_regex *regex = NULL;
    int ret;

    regex = flb_regex_create("//tmp//");
    if (!TEST_CHECK(regex != NULL)) {
        TEST_MSG("flb_regex_create failed");
        exit(1);
    }

    ret = flb_regex_match(regex, (unsigned char *) "/tmp/", 5);
    if (!TEST_CHECK(ret == 1)) {
        TEST_MSG("slash-delimited literal slash pattern did not match");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_match(regex, (unsigned char *) "tmp", 3);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("slash-delimited literal slash pattern matched string without slashes");
        flb_regex_destroy(regex);
        exit(1);
    }

    ret = flb_regex_destroy(regex);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_regex_destroy failed");
        exit(1);
    }
}

static void test_operation_limit(void)
{
    struct flb_regex *regex;
    struct flb_regex_search result;
    char text[65];

    TEST_CHECK(flb_regex_init() == 0);
    TEST_CHECK(onig_get_match_operation_limit() == 10000000UL);
    memset(text, 'a', sizeof(text) - 2);
    text[sizeof(text) - 2] = '!';
    text[sizeof(text) - 1] = '\0';
    regex = flb_regex_create("^(a+)+\\1$");
    TEST_ASSERT(regex != NULL);
    TEST_CHECK(flb_regex_match(regex, (unsigned char *) text, strlen(text)) ==
               ONIGERR_MATCH_OPERATION_LIMIT_OVER);
    TEST_CHECK(flb_regex_do(regex, text, strlen(text), &result) ==
               ONIGERR_MATCH_OPERATION_LIMIT_OVER);
    TEST_CHECK(result.region == NULL);
    TEST_CHECK(flb_regex_match(regex, (unsigned char *) "aaaa", 4) == 1);
    TEST_CHECK(flb_regex_match(regex, (unsigned char *) "!", 1) == 0);
    flb_regex_destroy(regex);
}

static void test_operation_limit_linear(void)
{
    struct flb_regex *regex;
    struct flb_regex_search result;
    const char *prefix = "2026-11-05T00:00:00Z stdout F ";
    char *text;
    size_t length = 600000;
    size_t prefix_length;

    TEST_CHECK(flb_regex_init() == 0);
    text = flb_malloc(length);
    TEST_ASSERT(text != NULL);
    prefix_length = strlen(prefix);
    memcpy(text, prefix, prefix_length);
    memset(text + prefix_length, 'a', length - prefix_length);
    /* Same expression as the built-in CRI multiline parser. */
    regex = flb_regex_create("^(?<time>.+?) (?<stream>stdout|stderr) (?<_p>F|P) (?<log>.*)$");
    TEST_ASSERT(regex != NULL);
    TEST_CHECK(flb_regex_do(regex, text, length, &result) == 4);
    if (result.region != NULL) {
        flb_regex_results_release(&result);
    }
    flb_regex_destroy(regex);
    flb_free(text);
}

static void test_cached_operation_limit(void)
{
    struct flb_regex *regex;
    struct flb_regex_search result;
    char text[1002];

    TEST_CHECK(flb_regex_init() == 0);
    memset(text, 'a', sizeof(text) - 2);
    text[sizeof(text) - 2] = '!';
    text[sizeof(text) - 1] = '\0';
    regex = flb_regex_create("^(a+)+$");
    TEST_ASSERT(regex != NULL);
    TEST_CHECK(flb_regex_match(regex, (unsigned char *) text, strlen(text)) == 0);
    TEST_CHECK(flb_regex_do(regex, text, strlen(text), &result) == -1);
    TEST_CHECK(result.region == NULL);
    TEST_CHECK(flb_regex_match(regex, (unsigned char *) "aaaa", 4) == 1);
    flb_regex_destroy(regex);
}

struct regex_init_worker {
    struct flb_regex *regex;
    int failed;
};

static void *regex_init_match_worker(void *data)
{
    struct regex_init_worker *worker = data;
    int i;

    for (i = 0; i < 2000; i++) {
        if (onig_get_match_operation_limit() != 10000000UL ||
            flb_regex_match(worker->regex, (unsigned char *) "aaaaaaaaaaaaaaab", 16) != 1) {
            worker->failed = 1;
            break;
        }
    }
    return NULL;
}

static void test_operation_limit_initialization(void)
{
    struct regex_init_worker worker = {0};
    struct flb_config *config;
    pthread_t thread;
    unsigned long saved_limit;
    int i;

    /* The budget exists even before the first explicit backend init. */
    saved_limit = onig_get_match_operation_limit();
    TEST_CHECK(saved_limit == 10000000UL);
    TEST_CHECK(flb_regex_init() == 0);
    worker.regex = flb_regex_create("^(a|aa){3,10}b$");
    TEST_ASSERT(worker.regex != NULL);
    TEST_ASSERT(pthread_create(&thread, NULL, regex_init_match_worker, &worker) == 0);
    for (i = 0; i < 2000; i++) {
        TEST_CHECK(flb_regex_init() == 0);
    }
    TEST_CHECK(pthread_join(thread, NULL) == 0);
    TEST_CHECK(worker.failed == 0);
    flb_regex_destroy(worker.regex);

    /* Sequential overrides must not be overwritten by context creation. */
    onig_set_match_operation_limit(saved_limit - 1);
    config = flb_config_init();
    TEST_CHECK(config != NULL);
    TEST_CHECK(onig_get_match_operation_limit() == saved_limit - 1);
    if (config != NULL) {
        flb_config_exit(config);
    }
    onig_set_match_operation_limit(saved_limit);
}

TEST_LIST = {
    { "operation_limit_initialization", test_operation_limit_initialization},
    { "cached_operation_limit", test_cached_operation_limit},
    { "operation_limit_linear", test_operation_limit_linear},
    { "operation_limit", test_operation_limit},
    { "basic" , test_basic},
    { "uri" , test_uri},
    { "option_ignore_case", test_option_ignore_case},
    { "option_multiline" , test_option_multiline},
    { "option_extend" , test_option_extend},
    { "option_i_x" , test_option_i_x},
    { "literal_slash" , test_literal_slash},
    { "slash_delimited_pattern" , test_slash_delimited_pattern},
    { "slash_delimited_literal_slashes" , test_slash_delimited_literal_slashes},
    { 0 }
};
