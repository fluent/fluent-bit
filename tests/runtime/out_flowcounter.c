/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/common/json_invalid.h" /* JSON_INVALID */
#include "data/common/json_long.h"    /* JSON_LONG    */
#include "data/common/json_small.h"   /* JSON_SMALL   */

/* Test functions */
void flb_test_flowcounter_json_invalid(void);
void flb_test_flowcounter_json_long(void);
void flb_test_flowcounter_json_small(void);
void flb_test_flowcounter_unit_second(void);
void flb_test_flowcounter_unit_minute(void);
void flb_test_flowcounter_unit_hour(void);
void flb_test_flowcounter_unit_day(void);
void flb_test_flowcounter_unit_invalid(void);

/* Test list */
TEST_LIST = {
    {"json_invalid",    flb_test_flowcounter_json_invalid },
    {"json_long",       flb_test_flowcounter_json_long    },
    {"json_small",      flb_test_flowcounter_json_small   },
    {"unit_second",     flb_test_flowcounter_unit_second  },
    {"unit_minute",     flb_test_flowcounter_unit_minute  },
    {"unit_hour",       flb_test_flowcounter_unit_hour    },
    {"unit_day",        flb_test_flowcounter_unit_day     },
    {"unit_invalid",    flb_test_flowcounter_unit_invalid },
    {NULL, NULL}
};


void flb_test_flowcounter_json_invalid(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_INVALID;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "flowcounter", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_INVALID) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* It writes a very long JSON map (> 100KB) byte by byte */
void flb_test_flowcounter_json_long(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_LONG;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "flowcounter", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_LONG) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_flowcounter_json_small(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "flowcounter", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_flowcounter_unit_second(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "flowcounter", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Unit", "second", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_flowcounter_unit_minute(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "flowcounter", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Unit", "minute", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_flowcounter_unit_hour(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "flowcounter", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Unit", "hour", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_flowcounter_unit_day(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "flowcounter", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Unit", "day", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_flowcounter_unit_invalid(void)
{
    int i;
    int ret;
    int bytes;
    char *p = (char *) JSON_SMALL;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "flowcounter", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    flb_output_set(ctx, out_ffd, "Unit", "xxx", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < (int) sizeof(JSON_SMALL) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}
