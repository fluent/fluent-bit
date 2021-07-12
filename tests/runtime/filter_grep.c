/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"

/* Output callback to count events. */

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int count = 0;

int callback_count(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        flb_debug("[test_filter_nest] received message: %s", data);
        pthread_mutex_lock(&mutex);
        count++;
        pthread_mutex_unlock(&mutex);
    }
    return 0;
}

/* Test data */

/* Test functions */
void flb_test_filter_grep_regex(void);
void flb_test_filter_grep_exclude(void);
void flb_test_filter_grep_invalid(void);
void flb_test_filter_grep_multi(void);

void flb_test_filter_grep_regex(void)
{
    int i;
    int ret;
    int bytes;
    char p[100];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Regex", "val 1", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 256; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"END_KEY\": \"JSON_END\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_grep_exclude(void)
{
    int i;
    int ret;
    int bytes;
    char p[100];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Exclude", "val 1", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    for (i = 0; i < 256; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"END_KEY\": \"JSON_END\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_grep_invalid(void)
{
    int i;
    int ret;
    int bytes;
    char p[100];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Regex", "val", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Exclude", "val", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == -1);

    for (i = 0; i < 256; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"END_KEY\": \"JSON_END\"}]", i, (i * i));
        bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
        TEST_CHECK(bytes == -1);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_grep_multi(void)
{
    int ret;
    int bytes;
    char* p;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb;
    int expected = 1;

    pthread_mutex_lock(&mutex);
    count = 0;
    pthread_mutex_unlock(&mutex);

    cb.cb = callback_count;
    cb.data = NULL;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace" "1", "Log_Level", "debug", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", "format", "json", NULL);

    filter_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Regex", "w 1", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Regex", "x 1", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Exclude", "y 1", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "Exclude", "z 1", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Matches rule 1 and 2 but not 3 or 4; should be included. */
    p = "[1448403340, {\"w\":\"1\", \"x\":\"1\", \"y\":\"2\", \"z\":\"2\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    /* Matches rule 1 but not 2; should be excluded. */
    p = "[1448403340, {\"w\":\"1\", \"x\":\"2\", \"y\":\"2\", \"z\":\"2\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    /* Matches rule 1, 2, and 3; should be excluded. */
    p = "[1448403340, {\"w\":\"1\", \"x\":\"1\", \"y\":\"1\", \"z\":\"2\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    /* Matches rule 1, 2, and 4 but not 3; should be excluded. */
    p = "[1448403340, {\"w\":\"1\", \"x\":\"1\", \"y\":\"2\", \"z\":\"1\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */

    pthread_mutex_lock(&mutex);
    TEST_CHECK_(count == expected, "Expected %d events, got %d", expected,
                count);
    pthread_mutex_unlock(&mutex);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"regex",   flb_test_filter_grep_regex   },
    {"exclude", flb_test_filter_grep_exclude },
    {"invalid", flb_test_filter_grep_invalid },
    {"multi",   flb_test_filter_grep_multi   },
    {NULL, NULL}
};
