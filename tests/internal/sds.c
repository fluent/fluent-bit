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

/* https://github.com/fluent/fluent-bit/issues/7143 */
static void test_sds_printf_7143_off_by_1()
{
    flb_sds_t tmp;
    flb_sds_t test;
    flb_sds_t test2;
    int len;

    /* 66 char final string, not impacted by bug */
    test = flb_sds_create_size(64);
    TEST_CHECK(test != NULL);
    tmp = flb_sds_printf(&test, "A0123456789 %s", "this-is-54-chars-1234567890-abcdefghijklmnopqrstuvwxyz");
    TEST_CHECK(tmp != NULL);
    len = flb_sds_len(test);
    TEST_CHECK(len == 66);
    TEST_CHECK(test[len -1] == 'z');
    flb_sds_destroy(test);

    /* 65 char final string, impacted by bug */
    test2 = flb_sds_create_size(64);
    TEST_CHECK(test2 != NULL);
    tmp = flb_sds_printf(&test2, "0123456789 %s", "this-is-54-chars-1234567890-abcdefghijklmnopqrstuvwxyz");
    TEST_CHECK(tmp != NULL);
    len = flb_sds_len(test2);
    TEST_CHECK(len == 65);
    TEST_CHECK(test2[len -1] == 'z');
    flb_sds_destroy(test2);

}

static void test_sds_cat_utf8()
{
    int ret;
    flb_sds_t s;
    char *utf8_str = "\xe8\x9f\xb9\xf0\x9f\xa6\x80";
    char *expected = "\\u87f9\\ud83e\\udd80";

    s = flb_sds_create("");
    flb_sds_cat_utf8(&s, utf8_str, strlen(utf8_str));

    ret = strcmp(s, expected);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        printf("Expected: %s\n", expected);
        printf("Received: %s\n", s);
    }
    flb_sds_destroy(s);
}

TEST_LIST = {
    { "sds_usage" , test_sds_usage},
    { "sds_printf", test_sds_printf},
    { "sds_cat_utf8", test_sds_cat_utf8},
    { "test_sds_printf_7143_off_by_1", test_sds_printf_7143_off_by_1},
    { 0 }
};
