/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;

/* Test data */

/* Test functions */
void flb_test_filter_nest_single(void);

/* Test list */
TEST_LIST = {
    {"single", flb_test_filter_nest_single },
    {NULL, NULL}
};


void set_output(char *val)
{
    pthread_mutex_lock(&result_mutex);
    output = val;
    pthread_mutex_unlock(&result_mutex);
}

char *get_output(void)
{
    char *val;

    pthread_mutex_lock(&result_mutex);
    val = output;
    pthread_mutex_unlock(&result_mutex);

    return val;
}

int callback_test(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        flb_debug("[test_filter_nest] received message: %s", data);
        set_output(data); /* success */
    }
    return 0;
}

void flb_test_filter_nest_single(void)
{
    int ret;
    int bytes;
    char *p, *output, *expected;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb_data;

    ctx = flb_create();
    flb_service_set(ctx,
                    "Flush", "1",
                    "Grace", "1",
                    "Log_Level", "debug",
                    NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "nest", NULL);
    TEST_CHECK(filter_ffd >= 0);

    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "Operation", "nest",
                         "Wildcard", "to_nest",
                         "Nest_under", "nested_key",
                         NULL);

    TEST_CHECK(ret == 0);


    /* Output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *) &cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    p = "[1448403340, {\"to_nest\":\"This is the data to nest\", \"extra\":\"Some more data\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    sleep(1); /* waiting flush */
    output = get_output();

    TEST_CHECK_(output != NULL, "Expected output to not be NULL");

    if (output != NULL) {
        expected = "\"nested_key\":{\"to_nest\":\"This is the data to nest\"}}]";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }
    flb_stop(ctx);
    flb_destroy(ctx);
}
