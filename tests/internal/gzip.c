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

void test_concatenated_gzip_count()
{
    int ret;
    int sample_len;
    char *in_data = morpheus;
    size_t in_len;
    void *str;
    size_t len;
    flb_sds_t payload = NULL;
    flb_sds_t payload2 = NULL;
    size_t border_count = 0;

    sample_len = strlen(morpheus);
    in_len = sample_len;
    ret = flb_gzip_compress(in_data, in_len, &str, &len);
    TEST_CHECK(ret == 0);

    payload = flb_sds_create_len((char *)str, len);
    payload2 = flb_sds_create_len((char *)str, len);
    ret = flb_sds_cat_safe(&payload, payload2, flb_sds_len(payload2));
    TEST_CHECK(ret == 0);

    border_count = flb_gzip_count(payload, flb_sds_len(payload), NULL, 0);
    TEST_CHECK(border_count == 2);

    flb_free(str);
    flb_sds_destroy(payload);
    flb_sds_destroy(payload2);
}

void test_not_overflow_for_concatenated_gzip()
{
    const char data[] = {
        0x00, 0x00, /* Initial padding */
        0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, /* First gzip header (valid header) */
        0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, /* Second gzip header (valid header) */
        0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, /* Third gzip header (valid header) */
    };
    size_t len = sizeof(data);
    size_t *borders = NULL;
    size_t border_count = 0;
    size_t count = 0;

    /* Vaild gzip payloads have to 18 bytes lentgh at least.
     * So, we get only 2 of vaild parts.
     */
    border_count = flb_gzip_count(data, len, NULL, 0);
    TEST_CHECK(border_count == 2);

    borders = (size_t *)flb_calloc(1, sizeof(size_t) * (border_count + 1));
    TEST_CHECK(borders != NULL);

    count = flb_gzip_count(data, len, &borders, border_count);
    TEST_CHECK(count == 2);

    if (borders != NULL) {
        free(borders);
    }
}


void test_decompress_concatenated()
{
    int ret;
    char *in_data = morpheus;
    size_t in_len = strlen(morpheus);
    void *gz1, *gz2;
    size_t len1, len2;
    flb_sds_t full_payload;
    void *out;
    size_t out_len;

    ret = flb_gzip_compress(in_data, in_len, &gz1, &len1);
    TEST_CHECK(ret == 0);

    ret = flb_gzip_compress(in_data, in_len, &gz2, &len2);
    TEST_CHECK(ret == 0);

    full_payload = flb_sds_create_len((char *)gz1, len1);
    ret = flb_sds_cat_safe(&full_payload, gz2, len2);
    TEST_CHECK(ret == 0);

    int count = flb_gzip_count(full_payload, flb_sds_len(full_payload), NULL, 0);
    TEST_CHECK(count == 2);

    ret = flb_gzip_uncompress(full_payload, flb_sds_len(full_payload), &out, &out_len);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out_len == 2 * in_len);
    TEST_CHECK(memcmp(out, morpheus, in_len) == 0);
    TEST_CHECK(memcmp((char *)out + in_len, morpheus, in_len) == 0);

    flb_free(gz1);
    flb_free(gz2);
    flb_sds_destroy(full_payload);
    flb_free(out);
}

TEST_LIST = {
    {"compress", test_compress},
    {"count",  test_concatenated_gzip_count},
    {"not_overflow", test_not_overflow_for_concatenated_gzip},
    {"decompress_concatenated", test_decompress_concatenated},
    { 0 }
};
