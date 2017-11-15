/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */

/* Test functions */
void flb_test_filter_ratelimit(void);

/* Test list */
TEST_LIST = {
    {"ratelimit", flb_test_filter_ratelimit },
    {NULL, NULL}
};

/* Utility functions */
pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
struct output {
    char *val[8];
    int count;
};
struct output *output = NULL;

void set_output(char *val)
{
    pthread_mutex_lock(&result_mutex);
    if (output == NULL) {
        output = flb_malloc(sizeof(struct output));
        output->count = 0;
    }
    output->val[output->count] = val;
    output->count++;
    pthread_mutex_unlock(&result_mutex);
}

struct output *get_output(void)
{
    struct output *val;

    pthread_mutex_lock(&result_mutex);
    val = output;
    pthread_mutex_unlock(&result_mutex);

    return val;
}

void free_output(void)
{
    int i;

    pthread_mutex_lock(&result_mutex);
    if (output == NULL) {
        return;
    }

    for (i = 0; i < output->count; i++) {
        free(output->val[i]);
    }

    free(output);
    output = NULL;
    pthread_mutex_unlock(&result_mutex);
}

int output_callback(void* data, size_t size)
{
    if (size > 0) {
        flb_debug("[test_filter_ratelimit] received message: %s", data);
        set_output(data); /* success */
    }
    return 0;
}

/* Tests */
void flb_test_filter_ratelimit(void)
{
    int ret;
    int bytes;
    char *p;
    struct output *output;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    ctx = flb_create();

    /* Setup lib input plugin */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "Tag", "test", NULL);

    /* Setup lib output plugin */
    out_ffd = flb_output(ctx, (char *) "lib", (void*)output_callback);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "Match", "test", "format", "json", NULL);

    /* Setup service */
    flb_service_set(ctx, "Flush", "1", "Log_Level", "debug", NULL);

    /* Setup ratelimit filter */
    filter_ffd = flb_filter(ctx, (char *) "ratelimit", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "Bucket_Key", "filename",
                         "Records_Per_Second", "1",
                         "Records_Burst", "2",
                         "Initial_Delay_Seconds", "1",
                         "Log_Period_Seconds", "0",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start flb */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Send log messages during initial delay - all should go through */
    p = "[0, {\"log\":\"01\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    p = "[0, {\"log\":\"02\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    p = "[0, {\"log\":\"03\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    /* Sleep for 1 second - initial delay over */
    sleep(1);

    /* Send log messages - first two go through, due to starting with record_burst of 2 */
    p = "[0, {\"log\":\"04\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    p = "[0, {\"log\":\"05\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    /* This should be dropped */
    p = "[0, {\"log\":\"06\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    /* Sleep for 1 second - fill up 1 token */
    sleep(1);
    p = "[0, {\"log\":\"07\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    /* These should be dropped */
    p = "[0, {\"log\":\"08\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    p = "[0, {\"log\":\"09\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    /* Sleep for 3 seconds - fill up 2 more tokens */
    sleep(3);
    p = "[0, {\"log\":\"10\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    p = "[0, {\"log\":\"11\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    /* This should be dropped */
    p = "[0, {\"log\":\"12\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    /* Check output */
    sleep(1); /* waiting flush */
    output = get_output(); /* 1sec passed, data should be flushed */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        TEST_CHECK_(output->count == 8, "Expected 8 messages but got %d - should have been rate limited",
                    output->count);
        if (output->count == 8) {
            TEST_CHECK_(strstr(output->val[0], "01") != NULL, "Expected log 01, got '%s'", output);
            TEST_CHECK_(strstr(output->val[1], "02") != NULL, "Expected log 02, got '%s'", output);
            TEST_CHECK_(strstr(output->val[2], "03") != NULL, "Expected log 03, got '%s'", output);
            TEST_CHECK_(strstr(output->val[3], "04") != NULL, "Expected log 04, got '%s'", output);
            TEST_CHECK_(strstr(output->val[4], "05") != NULL, "Expected log 05, got '%s'", output);
            /* 6 is dropped */
            TEST_CHECK_(strstr(output->val[5], "07") != NULL, "Expected log 07, got '%s'", output);
            /* 8 is dropped */
            /* 9 is dropped */
            TEST_CHECK_(strstr(output->val[6], "10") != NULL, "Expected log 10, got '%s'", output);
            TEST_CHECK_(strstr(output->val[7], "11") != NULL, "Expected log 11, got '%s'", output);
            /* 12 is dropped */
        }
    }

    free_output();
    flb_stop(ctx);
    flb_destroy(ctx);
}
