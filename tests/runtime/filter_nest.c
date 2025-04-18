/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;
int  num_output = 0;

/* Test data */

/* Test functions */
void flb_test_filter_nest_single(void);
void flb_test_filter_nest_multi_nest(void);
void flb_test_filter_nest_multi_lift(void);
void flb_test_filter_nest_add_prefix(void);
void flb_test_filter_nest_include_all(void);
void flb_test_filter_nest_exclude_static(void);
void flb_test_filter_nest_exclude_wildcard(void);
/* Test list */
TEST_LIST = {
    {"single", flb_test_filter_nest_single },
    {"multiple events are not dropped(nest)", flb_test_filter_nest_multi_nest},
    {"multiple events are not dropped(lift)", flb_test_filter_nest_multi_lift},
    {"add_prefix", flb_test_filter_nest_add_prefix},
    {"include_all", flb_test_filter_nest_include_all},
    {"exclude_static", flb_test_filter_nest_exclude_static},
    {"exclude_wildcard", flb_test_filter_nest_exclude_wildcard},
    {NULL, NULL}
};


void add_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output++;
    pthread_mutex_unlock(&result_mutex);
}

void clear_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output = 0;
    pthread_mutex_unlock(&result_mutex);
}

int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

int callback_count(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        flb_debug("[test_filter_nest] received message: %s", (char*)data);
        add_output_num(); /* success */
        flb_free(data);
    }
    return 0;
}

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
        flb_debug("[test_filter_nest] received message: %s", (char*)data);
        set_output(data); /* success */
    }
    return 0;
}

void flb_test_filter_nest_multi_nest(void)
{
    int ret;
    int bytes;
    char *p;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb_data;

    int count = 0; // should be number of events.
    int expected = 2;

    clear_output_num();
    
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
    cb_data.cb = callback_count;
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

    p = "[1448403341, {\"not_nest\":\"dummy data\", \"extra\":\"dummy more data\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    count = get_output_num();

    TEST_CHECK_(count == expected, "Expected number of events %d, got %d", expected, count );

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_nest_multi_lift(void)
{
    int ret;
    int bytes;
    char *p;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb_data;

    int count = 0; // should be number of events.
    int expected = 2;

    clear_output_num();
    
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
    cb_data.cb = callback_count;
    cb_data.data = NULL;

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "nest", NULL);
    TEST_CHECK(filter_ffd >= 0);

    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "Operation", "lift",
                         "Nested_under", "nested",
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

    p = "[1448403340, {\"nested\": {\"child\":\"nested data\"}, \"not_nestd\":\"not nested data\" }]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    p = "[1448403341, {\"not_nest\":\"dummy data\", \"extra\":\"dummy more data\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    count = get_output_num();

    TEST_CHECK_(count == expected, "Expected number of events %d, got %d", expected, count );

    flb_stop(ctx);
    flb_destroy(ctx);
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

    flb_time_msleep(1500); /* waiting flush */
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

void flb_test_filter_nest_add_prefix(void)
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
                         "Operation", "lift",
                         "Nest_under", "nested_key",
                         "Add_prefix", "_nested_key.",
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

    p = "[1448403340, {\"nested_key\":{\"key\":\"value\"}}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    output = get_output();

    TEST_CHECK_(output != NULL, "Expected output to not be NULL");

    if (output != NULL) {
        expected = "\"_nested_key.key\":\"value\"}]";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_nest_include_all(void)
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
                         "Nest_under", "nested_key",
                         "Wildcard", "*",
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

    p = "[1448403340, {\"to_nest\":\"This is some data to nest\", \"extra\":\"Some more data to nest\", \"EXCLUDED_extra_1\":\"Some more data to be excluded\", \"EXCLUDED_extra_2\":\"Some more data to be excluded\", \"EXCLUDED_extra_3\":\"Some more data to be excluded\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    output = get_output();

    TEST_CHECK_(output != NULL, "Expected output to not be NULL");

    if (output != NULL) {
        expected = "{\"nested_key\":{\"to_nest\":\"This is some data to nest\",\"extra\":\"Some more data to nest\",\"EXCLUDED_extra_1\":\"Some more data to be excluded\",\"EXCLUDED_extra_2\":\"Some more data to be excluded\",\"EXCLUDED_extra_3\":\"Some more data to be excluded\"}}]";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_nest_exclude_static(void)
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
                         "Nest_under", "nested_key",
                         "Wildcard", "*",
                         "Wildcard_exclude", "EXCLUDED_extra_1",
                         "Wildcard_exclude", "EXCLUDED_extra_2",
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

    p = "[1448403340, {\"to_nest\":\"This is some data to nest\", \"extra\":\"Some more data to nest\", \"EXCLUDED_extra_1\":\"Some more data to be excluded\", \"EXCLUDED_extra_2\":\"Some more data to be excluded\", \"EXCLUDED_NOT\":\"Some more data to be excluded\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    output = get_output();

    TEST_CHECK_(output != NULL, "Expected output to not be NULL");

    if (output != NULL) {
        expected = "\"nested_key\":{\"to_nest\":\"This is some data to nest\",\"extra\":\"Some more data to nest\",\"EXCLUDED_NOT\":\"Some more data to be excluded\"}}";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_filter_nest_exclude_wildcard(void)
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
                         "Nest_under", "nested_key",
                         "Wildcard", "*",
                         "Wildcard_exclude", "EXCLUDED_*",
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

    p = "[1448403340, {\"to_nest\":\"This is some data to nest\", \"extra\":\"Some more data to nest\", \"EXCLUDED_extra_1\":\"Some more data to be excluded\", \"EXCLUDED_extra_2\":\"Some more data to be excluded\", \"EXCLUDED_extra_3\":\"Some more data to be excluded\"}]";
    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    output = get_output();

    TEST_CHECK_(output != NULL, "Expected output to not be NULL");

    if (output != NULL) {
        expected = "\"nested_key\":{\"to_nest\":\"This is some data to nest\",\"extra\":\"Some more data to nest\"}}]";
        TEST_CHECK_(strstr(output, expected) != NULL, "Expected output to contain '%s', got '%s'", expected, output);
        free(output);
    }
    flb_stop(ctx);
    flb_destroy(ctx);
}