/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>

#include "flb_tests_internal.h"

static void test_sds_usage()
{
    flb_sds_t s;

    s = flb_sds_create("test");
    TEST_CHECK(s != NULL);
    TEST_CHECK(flb_sds_len(s) == 4);
    TEST_CHECK(flb_sds_alloc(s) == 4);
    TEST_CHECK(strcmp("test", s) == 0);

    s = flb_sds_cat(s, ",cat message", 12);
    TEST_CHECK(strcmp("test,cat message", s) == 0);

    flb_sds_destroy(s);
}

static void test_sds_printf()
{
    int len;
    flb_sds_t s;
    flb_sds_t tmp;
    char *str = "0123456789ABCDEFGHIJQLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvewxyz";

    s = flb_sds_create_size(10);
    tmp = flb_sds_printf(&s, "%s=%s", str, str);

    len = (strlen(str) * 2) + 1;
    TEST_CHECK(tmp == s);
    TEST_CHECK(flb_sds_len(s) == len);
    flb_sds_destroy(s);
}

static void test_sds_printf_larger()
{
    flb_sds_t buf;
    int len = 69;
    char *str = "This is a text string that is exactly 69 (sixty-nine) characters long";

    /* Test 1: buffer larger than copied string */
    buf = flb_sds_create_size(len + 2);
    buf = flb_sds_printf(&buf, "%s", str);
    TEST_CHECK(buf[len - 1] == 'g');
    flb_sds_destroy(buf);
}

static void test_sds_printf_smaller()
{
    flb_sds_t buf;
    int len = 69;
    char *str = "This is a text string that is exactly 69 (sixty-nine) characters long";

    /* Test 2: buffer smaller than copied string */
    buf = flb_sds_create_size(len - 2);
    buf = flb_sds_printf(&buf, "%s", str);
    TEST_CHECK(buf[len - 1] == 'g');
    flb_sds_destroy(buf);
}

static void test_sds_printf_exact()
{
    flb_sds_t buf;
    int len = 69;
    char *str = "This is a text string that is exactly 69 (sixty-nine) characters long";

    /* Test 3: buffer same size as copied string */
    buf = flb_sds_create_size(len);
    buf = flb_sds_printf(&buf, "%s", str);
    TEST_CHECK(buf[len - 1] == 'g');
    flb_sds_destroy(buf);
}

static void test_sds_cat_utf8()
{
    flb_sds_t s;
    char *utf8_str = "\xe8\x9f\xb9\xf0\x9f\xa6\x80";

    s = flb_sds_create("");
    flb_sds_cat_utf8(&s, utf8_str, strlen(utf8_str));

    TEST_CHECK(strcmp(s, "\\u87f9\\u1f980") == 0);
    flb_sds_destroy(s);
}

TEST_LIST = {
    { "sds_usage" , test_sds_usage },
    { "sds_printf", test_sds_printf },
    { "sds_printf_larger", test_sds_printf_larger },
    { "sds_printf_smaller", test_sds_printf_smaller },
    { "sds_printf_exact", test_sds_printf_exact },
    { "sds_cat_utf8", test_sds_cat_utf8 },
    { 0 }
};
