/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

#define WAIT_FOR_FLUSH sleep(0.1);

struct filter_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
};

/* Utility functions */
char *push_data_to_engine_and_take_output(flb_ctx_t * ctx, int in_ffd,
                                          char *message);
void check_if_message_pass_through_engine(flb_ctx_t * ctx, int in_ffd,
                                          char *message);
void check_if_message_doesnt_pass_through_engine(flb_ctx_t * ctx, int in_ffd,
                                                 char *message);
pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;
int num_output;

static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void set_output_num(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_output = num;
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_num()
{
    set_output_num(0);
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
    output = NULL;
    pthread_mutex_unlock(&result_mutex);

    return val;
}

int callback_test(void *data, size_t size, void *cb_data)
{
    if (size > 0) {
        flb_debug("[test_filter_throttle_size] received message: %s\n", data);
        set_output(data);
    }
    set_output_num(get_output_num() + 1);

    return 0;
}

static void filter_test_destroy(flb_ctx_t *ctx)
{
    flb_stop(ctx);
    flb_destroy(ctx);
    //flb_free(ctx);
}

/* Test functions */
void flb_test_log_1(void);
void flb_test_log_2(void);
void flb_test_log_3(void);
void flb_test_log_4(void);



/* Test list */
TEST_LIST = {
    {"test_log_1", flb_test_log_1},
    {"test_log_2", flb_test_log_2},
    {"test_log_3", flb_test_log_3},
    {"test_log_4", flb_test_log_4},
    {NULL, NULL}
};

void flb_test_log_1(void)
{
    /* 6 from 15 msg should pass the filter, because
       window * rate = 6
    */
    int i;
    int ret;
    char p[1000];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *tmp;
    int expected = 6;

    struct flb_lib_out_cb cb;
    cb.cb = callback_test;
    cb.data = NULL;

    ctx = flb_create();
    clear_output_num();
    /* Configure service */
    flb_service_set(ctx, "Flush", "1", "Grace" "1", "Log_Level", "debug",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Output */
    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "Match", "*", "format", "json", NULL);

    filter_ffd = flb_filter(ctx, (char *) "throttle_tag", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "rate", "2", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "window", "3", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "global_rate", "2", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "startup_wait", "0", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "interval", "10s", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "print_status", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Send log messages all should go through */
    for (i = 0; i < 15; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p),
                 "[1.000000,{\"val\":\"%d\",\"END_KEY\":\"JSON_END\"}]", i);
        tmp = push_data_to_engine_and_take_output(ctx, in_ffd, p);
        flb_debug("pushed msg: %s", tmp);
    }

    sleep(1);
    flb_info("passed msg: %d, expected: %d", get_output_num(), expected);
    TEST_CHECK(expected == num_output);

    sleep(8);
    flb_stop(ctx);
    filter_test_destroy(ctx);
}

void flb_test_log_2(void)
{
    /* 15 from 15 msg should pass the filter, because
       window * rate = 15
    */
    int i;
    int ret;
    char p[1000];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *tmp;
    int expected = 15;

    struct flb_lib_out_cb cb;
    cb.cb = callback_test;
    cb.data = NULL;

    ctx = flb_create();
    clear_output_num();
    flb_service_set(ctx,
                    "Flush",
                    "0.2",
                    "Grace" "1",
                    "Log_Level", "debug",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Output */
    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "Match", "*", "format", "json", NULL);

    filter_ffd = flb_filter(ctx, (char *) "throttle_tag", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "rate", "5", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "window", "3", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "global_rate", "2", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "startup_wait", "0", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "interval", "10s", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "print_status", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Send log messages all should go through */
    for (i = 0; i < 15; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p),
                 "[1.000000,{\"val\":\"%d\",\"END_KEY\":\"JSON_END\"}]", i);
        tmp = push_data_to_engine_and_take_output(ctx, in_ffd, p);
        flb_debug("pushed msg: %s", tmp);
    }

    sleep(1);
    flb_info("passed msg: %d, expected: %d", get_output_num(), expected);
    TEST_CHECK(expected == num_output);

    flb_stop(ctx);
    filter_test_destroy(ctx);
}

void flb_test_log_3(void)
{
    /* 15 from 15 msg should pass the filter, because
       global_rate * window > 15 */
    int i;
    int ret;
    char p[1000];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *tmp;
    int expected = 15;

    struct flb_lib_out_cb cb;
    cb.cb = callback_test;
    cb.data = NULL;

    ctx = flb_create();
    clear_output_num();
    /* Configure service */
    flb_service_set(ctx, "Flush", "1", "Grace" "1", "Log_Level", "debug",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Output */
    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "Match", "*", "format", "json", NULL);

    filter_ffd = flb_filter(ctx, (char *) "throttle_tag", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "rate", "2", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "window", "3", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "global_rate", "10", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "startup_wait", "0", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "interval", "10s", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "print_status", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Send log messages all should go through */
    for (i = 0; i < 15; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p),
                 "[1.000000,{\"val\":\"%d\",\"END_KEY\":\"JSON_END\"}]", i);
        tmp = push_data_to_engine_and_take_output(ctx, in_ffd, p);
        flb_debug("pushed msg: %s", tmp);
    }

    sleep(1);
    flb_info("passed msg: %d, expected: %d", get_output_num(), expected);
    TEST_CHECK(expected == num_output);

    flb_stop(ctx);
    filter_test_destroy(ctx);
}

void flb_test_log_4(void)
{
    /* 15 from 15 msg should pass the filter, because
       window * rate = 6 is ignored, due to startup_wait = 5
    */
    int i;
    int ret;
    char p[1000];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *tmp;
    int expected = 15;

    struct flb_lib_out_cb cb;
    cb.cb = callback_test;
    cb.data = NULL;

    ctx = flb_create();
    clear_output_num();
    /* Configure service */
    flb_service_set(ctx, "Flush", "1", "Grace" "1", "Log_Level", "debug",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Output */
    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "Match", "*", "format", "json", NULL);

    filter_ffd = flb_filter(ctx, (char *) "throttle_tag", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "rate", "2", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "window", "3", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "global_rate", "2", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "startup_wait", "5", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "interval", "10s", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "print_status", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Send log messages all should go through */
    for (i = 0; i < 15; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p),
                 "[1.000000,{\"val\":\"%d\",\"END_KEY\":\"JSON_END\"}]", i);
        tmp = push_data_to_engine_and_take_output(ctx, in_ffd, p);
        flb_debug("pushed msg: %s", tmp);
    }

    sleep(1);
    flb_info("passed msg: %d, expected: %d", get_output_num(), expected);
    TEST_CHECK(expected == num_output);

    flb_stop(ctx);
    filter_test_destroy(ctx);
}

char *push_data_to_engine_and_take_output(flb_ctx_t * ctx, int in_ffd,
                                          char *message)
{
    char *result = NULL;
    int bytes;
    /*Push the message into the engine */
    bytes = flb_lib_push(ctx, in_ffd, (void *) message, strlen(message));
    WAIT_FOR_FLUSH              /* wait the output data to be flushed */
    flb_debug("bytes pushed: %d", bytes);
    result = get_output();
    return result;
}

void check_if_message_pass_through_engine(flb_ctx_t * ctx, int in_ffd,
                                          char *message)
{
    char *result;
    result = push_data_to_engine_and_take_output(ctx, in_ffd, message);
    /*Check that the message go through engine without modification */
    flb_info("result: <%s>, messages: <%s>", result, message);
    TEST_CHECK(strncmp(result, message, strlen(result)) == 0);
}

void check_if_message_doesnt_pass_through_engine(flb_ctx_t * ctx, int in_ffd,
                                                 char *message)
{
    char *result;
    result = push_data_to_engine_and_take_output(ctx, in_ffd, message);
    /*Check that the message didn't throught engine */
    TEST_CHECK(result == NULL);
}