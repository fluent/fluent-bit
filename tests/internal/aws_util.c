/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_mem.h>

#include "flb_tests_internal.h"

#define S3_KEY_FORMAT_TAG_PART "logs/$TAG[2]/$TAG[0]/%Y/%m/%d"
#define S3_OBJECT_KEY_TAG_PART "logs/ccc/aa/2020/08/15"

#define S3_KEY_FORMAT_FULL_TAG "logs/$TAG/%Y/%m/%d"
#define S3_OBJECT_KEY_FULL_TAG "logs/aa.bb.ccc/2020/08/15"

#define S3_KEY_FORMAT_SPECIAL_CHARCATERS_TAG "logs/my.great_photos-2020:jan/$TAG/%Y/%m/%d"
#define S3_OBJECT_KEY_SPECIAL_CHARCATERS_TAG "logs/my.great_photos-2020:jan/aa.bb.ccc/2020/08/15"

#define S3_OBJECT_KEY_INVALID_DELIMITER "logs/aa.bb-ccc[2]/aa.bb-ccc/2020/08/15"

#define S3_KEY_FORMAT_INVALID_TAG "logs/$TAG[2]/$TAG[-1]/%Y/%m/%d"
#define S3_OBJECY_KEY_INVALID_TAG "logs/ccc/aa.bb.ccc[-1]/2020/08/15"

#define S3_KEY_FORMAT_OUT_OF_BOUNDS_TAG "logs/$TAG[2]/$TAG[]/%Y/%m/%d"

#define TAG "aa.bb.ccc"
#define MULTI_DELIMITER_TAG "aa.bb-ccc"
#define TAG_DELIMITER "."
#define TAG_DELIMITERS ".-"
#define INVALID_TAG_DELIMITERS ",/"


static void test_flb_aws_error()
{
    flb_sds_t error_type;
    char *api_response =  "{\"__type\":\"IncompleteSignatureException\","
                          "\"message\": \"Credential must have exactly 5 "
                          "slash-delimited elements, e.g. keyid/date/region/"
                          "service/term, got '<Credential>'\"}";
    char *garbage = "garbage"; /* something that can't be parsed */

    error_type = flb_aws_error(api_response, strlen(api_response));

    TEST_CHECK(strcmp("IncompleteSignatureException", error_type) == 0);

    flb_sds_destroy(error_type);

    error_type = flb_aws_error(garbage, strlen(garbage));

    TEST_CHECK(error_type == NULL);

    flb_sds_destroy(error_type);
}

static void test_flb_aws_endpoint()
{
    char *endpoint;

    endpoint = flb_aws_endpoint("cloudwatch", "ap-south-1");

    TEST_CHECK(strcmp("cloudwatch.ap-south-1.amazonaws.com",
                      endpoint) == 0);
    flb_free(endpoint);

    /* China regions have a different TLD */
    endpoint = flb_aws_endpoint("cloudwatch", "cn-north-1");

    TEST_CHECK(strcmp("cloudwatch.cn-north-1.amazonaws.com.cn",
                      endpoint) == 0);
    flb_free(endpoint);

}

static void test_flb_get_s3_key_multi_tag_exists()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t = mktime(&day);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_TAG_PART, t, TAG, TAG_DELIMITER);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_TAG_PART) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_full_tag()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t = mktime(&day);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_FULL_TAG, t, TAG, TAG_DELIMITER);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_FULL_TAG) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_tag_special_characters()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t = mktime(&day);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_SPECIAL_CHARCATERS_TAG, t, TAG, TAG_DELIMITER);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_SPECIAL_CHARCATERS_TAG) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_multi_tag_delimiter()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t = mktime(&day);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_TAG_PART, t, MULTI_DELIMITER_TAG, TAG_DELIMITERS);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_TAG_PART) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_invalid_tag_delimiter()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t = mktime(&day);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_TAG_PART, t, MULTI_DELIMITER_TAG, INVALID_TAG_DELIMITERS);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_INVALID_DELIMITER)  == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_invalid_tag_index()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t = mktime(&day);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_INVALID_TAG, t, TAG, TAG_DELIMITER);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECY_KEY_INVALID_TAG) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_invalid_key_length()
{
    int i;
    char buf[1100] = "";
    char tmp[1024] = "";
    flb_sds_t s3_key_format = NULL;

    for (i = 0; i <= 975; i++){
        tmp[i] = 'a';
    }
    snprintf(buf, sizeof(buf), "%s%s", S3_KEY_FORMAT_SPECIAL_CHARCATERS_TAG, tmp);
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t = mktime(&day);
    s3_key_format = flb_get_s3_key(buf, t, TAG, TAG_DELIMITER);
    TEST_CHECK(strlen(s3_key_format) <= 1024);

    flb_sds_destroy(s3_key_format);
}

TEST_LIST = {
    { "parse_api_error" , test_flb_aws_error},
    { "flb_aws_endpoint" , test_flb_aws_endpoint},
    {"flb_get_s3_key_multi_tag_exists", test_flb_get_s3_key_multi_tag_exists},
    {"flb_get_s3_key_full_tag", test_flb_get_s3_key_full_tag},
    {"flb_get_s3_key_tag_special_characters", test_flb_get_s3_key_tag_special_characters},
    {"flb_get_s3_key_multi_tag_delimiter", test_flb_get_s3_key_multi_tag_delimiter},
    {"flb_get_s3_key_invalid_tag_delimiter", test_flb_get_s3_key_invalid_tag_delimiter},
    {"flb_get_s3_key_invalid_tag_index", test_flb_get_s3_key_invalid_tag_index},
    {"flb_get_s3_key_invalid_key_length", test_flb_get_s3_key_invalid_key_length},
    { 0 }
};
