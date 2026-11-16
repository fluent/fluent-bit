/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "flb_tests_internal.h"

/* Regular expression used by the 'cri' multiline parser before this backend */
#define CRI_REGEX "^(?<time>.+?) (?<stream>stdout|stderr) (?<_p>F|P) (?<log>.*)$"
#define CRI_TIME  "%Y-%m-%dT%H:%M:%S.%L%z"
#define CRI_LINE  "2019-05-07T18:57:50.904275087+00:00 stdout F "

struct input {
    const char *buf;
    size_t len;      /* 0: use strlen */
};

#define S(x) { x, 0 }
#define B(x) { x, sizeof(x) - 1 }

static struct input inputs[] = {
    S("2019-05-07T18:57:50.904275087+00:00 stdout F message"),
    S("2019-05-07T18:57:50.904275087+00:00 stderr P partial"),
    S("2019-05-07T18:57:50.904275087Z stdout F zulu"),
    S("2019-05-07T18:57:50.904275087-03:00 stdout F offset"),
    S("2019-05-07T18:57:50+00:00 stdout F no fraction"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout F "),
    S("2019-05-07T18:57:50.904275087+00:00 stdout F"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout F  leading space"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout X bad flag"),
    S("2019-05-07T18:57:50.904275087+00:00 stdxxx F bad stream"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout FF bad flag"),
    S("not-a-time stdout F message"),
    S("two words stdout F message"),
    S(" stdout F message"),
    S("stdout F message"),
    S(""),
    S(" "),
    S("x"),
    S("         "),
    S("          "),
    S("2019 stdout F"),
    S("2019 stdout F "),
    S("a stdout stdout F stderr P x"),
    S("a  stderr P  "),
    S("2019-05-07T18:57:50.904275087+00:00 stdout F progress 10%\rprogress 20%\rdone"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout F carriage\r"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout F line one\nline two"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout F trailing nl\n"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout F crlf\r\n"),
    B("2019-05-07T18:57:50.904275087+00:00 stdout F nul\0inside"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout F a stdout F b"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout P stderr F nested"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout F \xc3\xa9\xe2\x82\xac utf8"),
    S("2019-05-07T18:57:50.904275087+00:00 stdout F \xff\xfe invalid utf8"),
    S("2019-05-07T18:57:50.904275087+00:00\tstdout\tF\ttabs"),
    S("2019-05-07T18:57:50.904275087+00:00  stdout F double space"),
    S("99999999999999999999999999999999999999999999999999999999999999999999999999 "
      "stdout F long time token"),
};

static struct flb_parser *parser_create(struct flb_config *config, char *name,
                                        char *format, char *regex, int time_keep)
{
    return flb_parser_create(name, format, regex, FLB_FALSE, CRI_TIME, "time", NULL,
                             time_keep, FLB_FALSE, FLB_FALSE, FLB_FALSE,
                             NULL, 0, NULL, config);
}

/* Copy without terminator, so a read past the input is caught by sanitizers */
static char *exact_copy(const char *buf, size_t len)
{
    char *copy;

    copy = malloc(len > 0 ? len : 1);
    if (copy != NULL) {
        memcpy(copy, buf, len);
    }

    return copy;
}

static int check_str(msgpack_object map, int pos, const char *key,
                     const char *val, size_t val_len)
{
    msgpack_object k;
    msgpack_object v;

    if (map.type != MSGPACK_OBJECT_MAP || pos >= map.via.map.size) {
        return FLB_FALSE;
    }

    k = map.via.map.ptr[pos].key;
    v = map.via.map.ptr[pos].val;
    if (k.type != MSGPACK_OBJECT_STR || v.type != MSGPACK_OBJECT_STR) {
        return FLB_FALSE;
    }

    if (k.via.str.size != strlen(key) || memcmp(k.via.str.ptr, key, strlen(key)) != 0) {
        return FLB_FALSE;
    }

    if (v.via.str.size != val_len || memcmp(v.via.str.ptr, val, val_len) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

/* Every input must produce the same result of the regex backend */
static void test_regex_parity(void)
{
    int i;
    int keep;
    int r1;
    int r2;
    int same;
    size_t len;
    size_t s1;
    size_t s2;
    char *copy;
    void *b1;
    void *b2;
    struct flb_time t1;
    struct flb_time t2;
    struct flb_config *config;
    struct flb_parser *re;
    struct flb_parser *cri;

    for (keep = 0; keep < 2; keep++) {
        config = flb_config_init();
        TEST_CHECK(config != NULL);

        re = parser_create(config, "re", "regex", CRI_REGEX, keep);
        cri = parser_create(config, "cri", "cri", NULL, keep);
        TEST_CHECK(re != NULL);
        TEST_CHECK(cri != NULL);

        for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
            len = inputs[i].len ? inputs[i].len : strlen(inputs[i].buf);
            copy = exact_copy(inputs[i].buf, len);
            TEST_CHECK(copy != NULL);

            b1 = NULL;
            b2 = NULL;
            s1 = 0;
            s2 = 0;
            flb_time_zero(&t1);
            flb_time_zero(&t2);

            r1 = flb_parser_do(re, copy, len, &b1, &s1, &t1);
            r2 = flb_parser_do(cri, copy, len, &b2, &s2, &t2);

            same = (r1 == r2);
            if (same && r1 >= 0) {
                same = (s1 == s2 && memcmp(b1, b2, s1) == 0 &&
                        flb_time_equal(&t1, &t2));
            }

            TEST_CHECK(same);
            TEST_MSG("input %d (time_keep=%d): '%.*s' regex=%d cri=%d",
                     i, keep, (int) len, inputs[i].buf, r1, r2);

            if (r1 >= 0) {
                flb_free(b1);
            }
            if (r2 >= 0) {
                flb_free(b2);
            }
            free(copy);
        }

        flb_parser_exit(config);
        flb_config_exit(config);
    }
}

static void test_fields(void)
{
    int ret;
    size_t off = 0;
    size_t size = 0;
    void *buf = NULL;
    const char *line = CRI_LINE "hello world";
    char *copy;
    struct flb_time tm;
    struct flb_config *config;
    struct flb_parser *cri;
    msgpack_unpacked result;

    config = flb_config_init();
    cri = parser_create(config, "cri", "cri", NULL, FLB_TRUE);
    TEST_CHECK(cri != NULL);

    copy = exact_copy(line, strlen(line));
    flb_time_zero(&tm);

    ret = flb_parser_do(cri, copy, strlen(line), &buf, &size, &tm);
    TEST_CHECK(ret == strlen(line));
    TEST_CHECK(tm.tm.tv_sec == 1557255470);
    TEST_CHECK(tm.tm.tv_nsec == 904275087);

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(result.data.type == MSGPACK_OBJECT_MAP);
    TEST_CHECK(result.data.via.map.size == 4);
    TEST_CHECK(check_str(result.data, 0, "time",
                         "2019-05-07T18:57:50.904275087+00:00", 35));
    TEST_CHECK(check_str(result.data, 1, "stream", "stdout", 6));
    TEST_CHECK(check_str(result.data, 2, "_p", "F", 1));
    TEST_CHECK(check_str(result.data, 3, "log", "hello world", 11));

    msgpack_unpacked_destroy(&result);
    flb_free(buf);
    free(copy);
    flb_parser_exit(config);
    flb_config_exit(config);
}

/* A carriage return is part of the content, it does not end the record */
static void test_carriage_return(void)
{
    int ret;
    size_t off = 0;
    size_t size = 0;
    void *buf = NULL;
    const char *line = CRI_LINE "10%\r20%\rdone\r";
    char *copy;
    struct flb_time tm;
    struct flb_config *config;
    struct flb_parser *cri;
    msgpack_unpacked result;

    config = flb_config_init();
    cri = parser_create(config, "cri", "cri", NULL, FLB_TRUE);
    TEST_CHECK(cri != NULL);

    copy = exact_copy(line, strlen(line));
    flb_time_zero(&tm);

    ret = flb_parser_do(cri, copy, strlen(line), &buf, &size, &tm);
    TEST_CHECK(ret == strlen(line));

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(check_str(result.data, 3, "log", "10%\r20%\rdone\r", 13));

    msgpack_unpacked_destroy(&result);
    flb_free(buf);
    free(copy);
    flb_parser_exit(config);
    flb_config_exit(config);
}

static void test_time_keep_off(void)
{
    int ret;
    size_t off = 0;
    size_t size = 0;
    void *buf = NULL;
    const char *line = CRI_LINE "hello";
    char *copy;
    struct flb_time tm;
    struct flb_config *config;
    struct flb_parser *cri;
    msgpack_unpacked result;

    config = flb_config_init();
    cri = parser_create(config, "cri", "cri", NULL, FLB_FALSE);
    TEST_CHECK(cri != NULL);

    copy = exact_copy(line, strlen(line));
    flb_time_zero(&tm);

    ret = flb_parser_do(cri, copy, strlen(line), &buf, &size, &tm);
    TEST_CHECK(ret == strlen(line));
    TEST_CHECK(tm.tm.tv_sec == 1557255470);

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(result.data.via.map.size == 3);
    TEST_CHECK(check_str(result.data, 0, "stream", "stdout", 6));
    TEST_CHECK(check_str(result.data, 1, "_p", "F", 1));
    TEST_CHECK(check_str(result.data, 2, "log", "hello", 5));

    msgpack_unpacked_destroy(&result);
    flb_free(buf);
    free(copy);
    flb_parser_exit(config);
    flb_config_exit(config);
}

/* Lines that are not CRI must be rejected at any truncation point */
static void test_truncated(void)
{
    int ret;
    size_t len;
    size_t size;
    void *buf;
    const char *line = CRI_LINE "x";
    char *copy;
    struct flb_time tm;
    struct flb_config *config;
    struct flb_parser *cri;

    config = flb_config_init();
    cri = parser_create(config, "cri", "cri", NULL, FLB_TRUE);
    TEST_CHECK(cri != NULL);

    /* the shortest valid line ends right after the flag delimiter */
    for (len = 0; len <= strlen(line); len++) {
        copy = exact_copy(line, len);
        buf = NULL;
        size = 0;

        ret = flb_parser_do(cri, copy, len, &buf, &size, &tm);
        if (len < strlen(CRI_LINE)) {
            TEST_CHECK(ret == -1);
            TEST_MSG("length %zu was accepted", len);
        }
        else {
            TEST_CHECK(ret == len);
            flb_free(buf);
        }
        free(copy);
    }

    flb_parser_exit(config);
    flb_config_exit(config);
}

TEST_LIST = {
    { "regex_parity", test_regex_parity},
    { "fields", test_fields},
    { "carriage_return", test_carriage_return},
    { "time_keep_off", test_time_keep_off},
    { "truncated", test_truncated},
    { 0 }
};
