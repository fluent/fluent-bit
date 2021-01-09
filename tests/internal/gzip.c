/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_gzip.h>

#include "flb_tests_internal.h"

/* Sample data */
char *morpheus = "This is your last chance. After this, there is no "
    "turning back. You take the blue pill - the story ends, you wake up in "
    "your bed and believe whatever you want to believe. You take the red pill,"
    "you stay in Wonderland and I show you how deep the rabbit-hole goes.";

void test_compress()
{
    int ret;
    int sample_len;
    char *in_data = morpheus;
    size_t in_len;
    void *str;
    size_t len;

    sample_len = strlen(morpheus);
    in_len = sample_len;
    ret = flb_gzip_compress(in_data, in_len, &str, &len);
    TEST_CHECK(ret == 0);

    in_data = str;
    in_len = len;

    ret = flb_gzip_uncompress(in_data, in_len, &str, &len);
    TEST_CHECK(ret == 0);

    TEST_CHECK(sample_len == len);
    ret = memcmp(morpheus, str, sample_len);
    TEST_CHECK(ret == 0);

    flb_free(in_data);
    flb_free(str);
}

TEST_LIST = {
    {"compress", test_compress},
    { 0 }
};
