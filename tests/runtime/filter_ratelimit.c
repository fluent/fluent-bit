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
                         "Initial_Records_Burst", "1",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start flb */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Send log messages */
    p = "[0, {\"log\":\"1\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    /* These should be dropped */
    p = "[0, {\"log\":\"2\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    p = "[0, {\"log\":\"3\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    /* Sleep for 3 seconds - fill up 2 tokens */
    sleep(3);
    p = "[0, {\"log\":\"4\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    p = "[0, {\"log\":\"5\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));
    /* These should be dropped */
    p = "[0, {\"log\":\"6\", \"filename\":\"app-log1.txt\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));


    /* Check output */
    sleep(1); /* waiting flush */
    output = get_output(); /* 1sec passed, data should be flushed */
    TEST_CHECK_(output != NULL, "Expected output to not be NULL");
    if (output != NULL) {
        TEST_CHECK_(output->count == 3, "Expected 3 messages but got %d - should have been rate limited",
                    output->count);
        if (output->count == 3) {
            TEST_CHECK_(strstr(output->val[0], "1") != NULL, "Expected log 1, got '%s'", output);
            TEST_CHECK_(strstr(output->val[1], "4") != NULL, "Expected log 4, got '%s'", output);
            TEST_CHECK_(strstr(output->val[2], "5") != NULL, "Expected log 5, got '%s'", output);
        }
    }

    free_output();
    flb_stop(ctx);
    flb_destroy(ctx);
}
