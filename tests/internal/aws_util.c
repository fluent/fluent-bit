/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_aws_util.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pthread.h>

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

#define S3_KEY_FORMAT_STATIC_STRING "logs/fluent-bit"

#define S3_KEY_FORMAT_UUID "logs/$UUID"
#define S3_OBJECT_KEY_UUID "logs/"

#define S3_KEY_FORMAT_ALL_OPTIONS "logs/$TAG[2]/$TAG[1]/$TAG[0]/%Y/%m/%d/file-$INDEX-$UUID"
#define S3_OBJECT_KEY_ALL_OPTIONS "logs/ccc/bb/aa/2020/08/15/file-0-"

#define S3_KEY_FORMAT_VALID_INDEX "logs/a-$INDEX-b-c"
#define S3_OBJECT_KEY_VALID_INDEX "logs/a-12-b-c"
#define S3_OBJECT_KEY_PRE_OVERFLOW_INDEX "logs/a-18446744073709551615-b-c"
#define S3_OBJECT_KEY_POST_OVERFLOW_INDEX "logs/a-0-b-c"

#define S3_KEY_FORMAT_MIXED_TIMESTAMP "logs/%Y/m/%m/d/%d/%q"
#ifdef FLB_SYSTEM_MACOS
/* macOS's strftime throws away for % character for % and suqsequent invalid format character. */
#define S3_OBJECT_KEY_MIXED_TIMESTAMP "logs/2020/m/08/d/15/q"
#else
#define S3_OBJECT_KEY_MIXED_TIMESTAMP "logs/2020/m/08/d/15/%q"
#endif

#define NO_TAG ""
#define TAG "aa.bb.ccc"
#define MULTI_DELIMITER_TAG "aa.bb-ccc"
#define TAG_DELIMITER "."
#define TAG_DELIMITERS ".-"
#define INVALID_TAG_DELIMITERS ",/"
#define VALID_SEQ_INDEX 0

static void initialization_crutch()
{
    struct flb_config *config;

    config = flb_config_init();

    if (config == NULL) {
        return;
    }

    flb_config_exit(config);
}


pthread_mutex_t env_mutex = PTHREAD_MUTEX_INITIALIZER;
static int mktime_utc(struct tm *day, time_t *tm)
{
    int ret;
    char *tzvar = NULL;
    char orig_tz[256] = {0};
    time_t t;

    if (!TEST_CHECK(day != NULL)) {
        TEST_MSG("struct tm is null");
        return -1;
    }
    if (!TEST_CHECK(tm != NULL)) {
        TEST_MSG("time_t is null");
        return -1;
    }

    pthread_mutex_lock(&env_mutex);

    /* save current TZ var */
    tzvar = getenv("TZ");
    if (tzvar != NULL) {
        if (!TEST_CHECK(strlen(tzvar) <= sizeof(orig_tz))) {
            TEST_MSG("TZ is large. len=%ld TZ=%s", strlen(tzvar), tzvar);
            pthread_mutex_unlock(&env_mutex);
            return -1;
        }
        strncpy(&orig_tz[0], tzvar, sizeof(orig_tz));
    }

    /* setenv is not thread safe */
    ret = setenv("TZ", "UTC", 1);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("setenv failed");
        pthread_mutex_unlock(&env_mutex);
        return -1;
    }

    t = mktime(day);
    *tm = t;

    /* restore TZ */
    if (tzvar != NULL) {
        ret = setenv("TZ", &orig_tz[0], 1);
    }
    else {
        ret = unsetenv("TZ");
    }

    pthread_mutex_unlock(&env_mutex);

    return ret;
}

static void test_flb_aws_error()
{
    flb_sds_t error_type;
    char *api_response =  "{\"__type\":\"IncompleteSignatureException\","
                          "\"message\": \"Credential must have exactly 5 "
                          "slash-delimited elements, e.g. keyid/date/region/"
                          "service/term, got '<Credential>'\"}";
    char *garbage = "garbage"; /* something that can't be parsed */

    initialization_crutch();

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

    initialization_crutch();

    endpoint = flb_aws_endpoint("cloudwatch", "ap-south-1");

    TEST_CHECK(strcmp("cloudwatch.ap-south-1.amazonaws.com",
                      endpoint) == 0);
    flb_free(endpoint);

    /* China regions have a different TLD */
    endpoint = flb_aws_endpoint("cloudwatch", "cn-north-1");

    TEST_CHECK(strcmp("cloudwatch.cn-north-1.amazonaws.com.cn",
                      endpoint) == 0);
    flb_free(endpoint);

    /* EU Sovereign Cloud regions have a different domain */
    endpoint = flb_aws_endpoint("cloudwatch", "eusc-de-east-1");

    TEST_CHECK(strcmp("cloudwatch.eusc-de-east-1.amazonaws.eu",
                      endpoint) == 0);
    flb_free(endpoint);

}

static void test_flb_get_s3_key_multi_tag_exists()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;

    initialization_crutch();

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_TAG_PART, t, TAG, TAG_DELIMITER, 0);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_TAG_PART) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_full_tag()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;

    initialization_crutch();

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_FULL_TAG, t, TAG, TAG_DELIMITER, 0);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_FULL_TAG) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_tag_special_characters()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;

    initialization_crutch();

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_SPECIAL_CHARCATERS_TAG, t, TAG,
                                   TAG_DELIMITER, 0);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_SPECIAL_CHARCATERS_TAG) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_multi_tag_delimiter()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;

    initialization_crutch();

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_TAG_PART, t, MULTI_DELIMITER_TAG,
                                   TAG_DELIMITERS, 0);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_TAG_PART) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_invalid_tag_delimiter()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;

    initialization_crutch();

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_TAG_PART, t, MULTI_DELIMITER_TAG,
                                   INVALID_TAG_DELIMITERS, 0);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_INVALID_DELIMITER)  == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_invalid_tag_index()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;

    initialization_crutch();

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_INVALID_TAG, t, TAG, TAG_DELIMITER, 0);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECY_KEY_INVALID_TAG) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_invalid_key_length()
{
    int i;
    char buf[1100] = "";
    char tmp[1024] = "";
    flb_sds_t s3_key_format = NULL;

    initialization_crutch();

    for (i = 0; i <= 975; i++){
        tmp[i] = 'a';
    }
    snprintf(buf, sizeof(buf), "%s%s", S3_KEY_FORMAT_SPECIAL_CHARCATERS_TAG, tmp);
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(buf, t, TAG, TAG_DELIMITER, 0);
    TEST_CHECK(strlen(s3_key_format) <= 1024);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_static_string()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;

    initialization_crutch();

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_STATIC_STRING, t, NO_TAG,
                                   TAG_DELIMITER, 0);
    TEST_CHECK(strcmp(s3_key_format, S3_KEY_FORMAT_STATIC_STRING) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_valid_index()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;

    initialization_crutch();

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_VALID_INDEX, t, NO_TAG,
                                   TAG_DELIMITER, 12);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_VALID_INDEX) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_increment_index()
{
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;
    flb_sds_t s3_key_format = NULL;

    initialization_crutch();

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_VALID_INDEX, t, NO_TAG,
                                    TAG_DELIMITER, 5);

    TEST_CHECK(strcmp(s3_key_format, "logs/a-5-b-c") == 0);

    flb_sds_destroy(s3_key_format);

    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_VALID_INDEX, t, NO_TAG,
                                    TAG_DELIMITER, 10);

    TEST_CHECK(strcmp(s3_key_format, "logs/a-10-b-c") == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_index_overflow()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;
    uint64_t index = 18446744073709551615U;

    initialization_crutch();

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_VALID_INDEX, t, NO_TAG,
                                   TAG_DELIMITER, index);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_PRE_OVERFLOW_INDEX) == 0);
    flb_sds_destroy(s3_key_format);

    index++;
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_VALID_INDEX, t, NO_TAG,
                                   TAG_DELIMITER, index);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_POST_OVERFLOW_INDEX) == 0);

    flb_sds_destroy(s3_key_format);
}

static void test_flb_get_s3_key_mixed_timestamp()
{
    flb_sds_t s3_key_format = NULL;
    struct tm day = { 0, 0, 0, 15, 7, 120};
    time_t t;

    initialization_crutch();

    mktime_utc(&day, &t);
    s3_key_format = flb_get_s3_key(S3_KEY_FORMAT_MIXED_TIMESTAMP, t, NO_TAG,
                                   TAG_DELIMITER, 12);
    TEST_CHECK(strcmp(s3_key_format, S3_OBJECT_KEY_MIXED_TIMESTAMP) == 0);

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
    {"flb_get_s3_key_static_string", test_flb_get_s3_key_static_string},
    {"flb_get_s3_key_valid_index", test_flb_get_s3_key_valid_index},
    {"flb_get_s3_key_increment_index", test_flb_get_s3_key_increment_index},
    {"flb_get_s3_key_index_overflow", test_flb_get_s3_key_index_overflow},
    {"flb_get_s3_key_mixed_timestamp", test_flb_get_s3_key_mixed_timestamp},
    { 0 }
};
