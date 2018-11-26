/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */
#include "data/common/json_long.h"    /* JSON_LONG    */
#include "data/common/json_small.h"   /* JSON_SMALL   */

/* Test functions */
void flb_test_file_json_invalid(void);
void flb_test_file_json_long(void);
void flb_test_file_json_small(void);
void flb_test_file_format_csv(void);
void flb_test_file_format_ltsv(void);
void flb_test_file_format_invalid(void);

/* Test list */
TEST_LIST = {
    {"json_invalid",    flb_test_file_json_invalid   },
    {"json_long",       flb_test_file_json_long      },
    {"json_small",      flb_test_file_json_small     },
    {"format_csv",      flb_test_file_format_csv     },
    {"format_ltsv",     flb_test_file_format_ltsv    },
    {"format_invalid",  flb_test_file_format_invalid },
    {NULL, NULL}
};


#define TEST_LOGFILE "flb_test_file_dummy.log"

void flb_test_file_json_invalid(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_INVALID;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_INVALID) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp == NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

/* It writes a very long JSON map (> 100KB) byte by byte */
void flb_test_file_json_long(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_LONG) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_json_small(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_format_csv(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "Format", "csv", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "comma", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_format_ltsv(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "Format", "ltsv", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "tab", NULL);
    flb_output_set(ctx, out_ffd, "label_delimiter", "comma", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}

void flb_test_file_format_invalid(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    FILE *fp;

    remove(TEST_LOGFILE);

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "file", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Path", TEST_LOGFILE, NULL);
    flb_output_set(ctx, out_ffd, "Format", "xxx", NULL);
    flb_output_set(ctx, out_ffd, "delimiter", "yyy", NULL);
    flb_output_set(ctx, out_ffd, "label_delimiter", "zzz", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);

    fp = fopen(TEST_LOGFILE, "r");
    TEST_CHECK(fp != NULL);
    if (fp != NULL) {
        fclose(fp);
        remove(TEST_LOGFILE);
    }
}
