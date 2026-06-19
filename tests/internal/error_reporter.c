/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <monkey/mk_core/mk_list.h>

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/aws/flb_aws_error_reporter.h>

#include "flb_tests_internal.h"

#ifdef FLB_SYSTEM_WINDOWS
#define TEST_ERROR_FILE_PATH "error.log"
#define TEST_INVALID_ERROR_FILE_PATH "NUL\\error.log"

static int test_setenv(const char *name, const char *value, int overwrite)
{
    if (overwrite == 0 && getenv(name) != NULL) {
        return 0;
    }

    return _putenv_s(name, value);
}
#else
#define TEST_ERROR_FILE_PATH "/tmp/error.log"
#define TEST_INVALID_ERROR_FILE_PATH "/dev/null/error.log"
#define test_setenv(name, value, overwrite) setenv(name, value, overwrite)
#endif

const char* file_path = TEST_ERROR_FILE_PATH;
const char* error_message_1 = "[engine] scheduler could not start";
const char* error_message_2 = "[engine] scheduler could not stop";


void test_flb_aws_error_reporter_create() {

    test_setenv(STATUS_MESSAGE_FILE_PATH_ENV, file_path, 1);
    struct flb_aws_error_reporter *error_reporter = flb_aws_error_reporter_create();
    TEST_CHECK((void*) error_reporter != NULL);
    TEST_CHECK((void*)error_reporter->file_path != NULL);
    TEST_CHECK(flb_sds_cmp(error_reporter->file_path, file_path, strlen(file_path)) == 0);
    TEST_CHECK(error_reporter->ttl == STATUS_MESSAGE_TTL_DEFAULT);
    TEST_CHECK(error_reporter->max_size == STATUS_MESSAGE_MAX_BYTE_LENGTH_DEFAULT);
    flb_aws_error_reporter_destroy(error_reporter);
}

void test_flb_aws_error_reporter_write() {

    int size;
    char error_message_3[1041];
    for (int i = 0; i < 1040; i++) {
        error_message_3[i] = 'a';
    }
    error_message_3[1040] = '\0';

    test_setenv(STATUS_MESSAGE_FILE_PATH_ENV, file_path, 1);

    struct flb_aws_error_reporter *error_reporter = flb_aws_error_reporter_create();
    flb_aws_error_reporter_write(error_reporter, error_message_1);
    size = mk_list_size(&error_reporter->messages);
    TEST_CHECK(size == 1);
    /* message same with the latest one will be combined*/
    flb_aws_error_reporter_write(error_reporter, error_message_1);
    size = mk_list_size(&error_reporter->messages);
    TEST_CHECK(size == 1);

    /* message different of the latest one will be combined*/
    flb_aws_error_reporter_write(error_reporter, error_message_2);
    size = mk_list_size(&error_reporter->messages);
    TEST_CHECK(size == 2);

    /* message larger than max size limit*/
    flb_aws_error_reporter_write(error_reporter, error_message_3);
    size = mk_list_size(&error_reporter->messages);
    TEST_CHECK(size == 1);

    flb_aws_error_reporter_destroy(error_reporter);
}

void test_flb_aws_error_reporter_clean() {

    test_setenv(STATUS_MESSAGE_FILE_PATH_ENV, file_path, 1);
    struct flb_aws_error_reporter *error_reporter = flb_aws_error_reporter_create();
    flb_aws_error_reporter_write(error_reporter, error_message_1);
    time_t start = time(NULL);
    while (time(NULL) - start <= error_reporter->ttl) {
        flb_aws_error_reporter_clean(error_reporter);
    }
    TEST_CHECK(mk_list_size(&error_reporter->messages) == 0);

    flb_aws_error_reporter_destroy(error_reporter);
}

void test_flb_aws_error_reporter_write_open_failure()
{
    int ret;
    struct flb_aws_error_reporter *error_reporter;

    test_setenv(STATUS_MESSAGE_FILE_PATH_ENV,
                TEST_INVALID_ERROR_FILE_PATH, 1);

    error_reporter = flb_aws_error_reporter_create();
    TEST_CHECK(error_reporter != NULL);

    ret = flb_aws_error_reporter_write(error_reporter, error_message_1);
    TEST_CHECK(ret == -1);
    TEST_CHECK(mk_list_size(&error_reporter->messages) == 0);
    TEST_CHECK(error_reporter->file_size == 0);

    flb_aws_error_reporter_destroy(error_reporter);
}

TEST_LIST = {
    { "test_flb_aws_error_reporter_create", test_flb_aws_error_reporter_create},
    {"test_flb_aws_error_reporter_write", test_flb_aws_error_reporter_write},
    {"test_flb_aws_error_reporter_clean", test_flb_aws_error_reporter_clean},
    {"test_flb_aws_error_reporter_write_open_failure",
     test_flb_aws_error_reporter_write_open_failure},
    { 0 }
};
