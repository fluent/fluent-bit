/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"
#include <stdio.h>

#define FLUSH_DURATION 1
#define WAIT_FOR_FLUSH sleep(FLUSH_DURATION);

/* Test data */
static const char *simple_log =
    "[1519233660.000000, {\"log\":\"%s\", \"stream\":\"%s\", \"time\":\"2018-02-21T17:26:53.360920913Z\", \"value\":\"%d\"}]";
static const char *simple_log_with_missing_log_key =
    "[1519233660.000000, {\"msg\":\"%s\", \"stream\":\"%s\", \"time\":\"2018-02-21T17:26:53.360920913Z\", \"value\":\"%d\"}]";
static const char *simple_log_with_missing_stream_key =
    "[1519233660.000000, {\"log\":\"%s\", \"source\":\"%s\", \"time\":\"2018-02-21T17:26:53.360920913Z\", \"value\":\"%d\"}]";
static const char *nested_log =
    "[1519234013.360921, {\"logwrapper\":{\"log\":\"%s\", \"extra\":\"field\"}, \"stream\":\"stdout\", \"time\":\"2018-02-21T17:26:53.360920913Z\", \"kubernetes\":{\"pod_name\":\"%s\", \"namespace_name\":\"default\", \"pod_id\":\"64f7da23-172c-11e8-bfad-080027749cbc\", \"labels\":{\"run\":\"apache-logs\"}, \"host\":\"minikube\", \"container_name\":\"apache-logs\", \"container_id\":\"ac6095b6c715d823d732dcc9067f75b1299de5cc69a012b08d616a6058bdc0ad\"}, \"va\":\"%d\"}]";
static const char *swap_log_field =
    "[1519234013.360921, {\"log\":{\"logwrapper\":\"%s\", \"extra\":\"field\"}, \"stream\":\"stdout\", \"time\":\"2018-02-21T17:26:53.360920913Z\", \"kubernetes\":{\"pod_name\":\"%s\", \"namespace_name\":\"default\", \"pod_id\":\"64f7da23-172c-11e8-bfad-080027749cbc\", \"labels\":{\"run\":\"apache-logs\"}, \"host\":\"minikube\", \"container_name\":\"apache-logs\", \"container_id\":\"ac6095b6c715d823d732dcc9067f75b1299de5cc69a012b08d616a6058bdc0ad\"}, \"va\":\"%d\"}]";
static const char *swap_name_field =
    "[1519234013.360921, {\"logwrapper\":{\"log\":\"%s\", \"extra\":\"field\"}, \"stream\":\"stdout\", \"time\":\"2018-02-21T17:26:53.360920913Z\", \"pod_name\":{\"kubernetes\":\"%s\", \"namespace_name\":\"default\", \"pod_id\":\"64f7da23-172c-11e8-bfad-080027749cbc\", \"labels\":{\"run\":\"apache-logs\"}, \"host\":\"minikube\", \"container_name\":\"apache-logs\", \"container_id\":\"ac6095b6c715d823d732dcc9067f75b1299de5cc69a012b08d616a6058bdc0ad\"}, \"va\":\"%d\"}]";
static const char *nested_log_with_missing_log_field =
    "[1519234013.360921, {\"logwrapper\":{\"msg\":\"%s\", \"extra\":\"field\"}, \"stream\":\"stdout\", \"time\":\"2018-02-21T17:26:53.360920913Z\", \"kubernetes\":{\"pod_name\":\"%s\", \"namespace_name\":\"default\", \"pod_id\":\"64f7da23-172c-11e8-bfad-080027749cbc\", \"labels\":{\"run\":\"apache-logs\"}, \"host\":\"minikube\", \"container_name\":\"apache-logs\", \"container_id\":\"ac6095b6c715d823d732dcc9067f75b1299de5cc69a012b08d616a6058bdc0ad\"}, \"va\":\"%d\"}]";
static const char *nested_log_with_missing_name_field =
    "[1519234013.360921, {\"logwrapper\":{\"log\":\"%s\", \"extra\":\"field\"}, \"stream\":\"stdout\", \"time\":\"2018-02-21T17:26:53.360920913Z\", \"kubernetes\":{\"pod_alias\":\"%s\", \"namespace_name\":\"default\", \"pod_id\":\"64f7da23-172c-11e8-bfad-080027749cbc\", \"labels\":{\"run\":\"apache-logs\"}, \"host\":\"minikube\", \"container_name\":\"apache-logs\", \"container_id\":\"ac6095b6c715d823d732dcc9067f75b1299de5cc69a012b08d616a6058bdc0ad\"}, \"va\":\"%d\"}]";
static const char *_32_bytes_msg = "This meeesage is 32 symbols long";
static const char *_11_bytes_msg = "I will pass";
static const char *_6_bytes_msg = "I pass";
static const char *_180_bytes_msg =
    "This message is 180 bytes long, so it will be used where we are sure that this message will pass every time or not at all. So used it carefully and at the proper place. Understand?";
static const char *stdout_str = "stdout";
static const char *stderr_str = "stderr";
static const char *apiserver = "kube-apiserver";
static const char *alertmanager = "alertmanager";

/* Utility functions */
char *push_data_to_engine_and_take_output(flb_ctx_t * ctx, int in_ffd,
                                          char *message);
void check_if_message_pass_through_engine(flb_ctx_t * ctx, int in_ffd,
                                          char *message);
void check_if_message_doesnt_pass_through_engine(flb_ctx_t * ctx, int in_ffd,
                                                 char *message);
pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;



/* Test functions */

void flb_test_simple_log(void);
void test_nestest_name_fields(void);
void test_default_name_field(void);
void test_default_log_field(void);


/* Test list */
TEST_LIST = {
    {
    "throttle_size", flb_test_simple_log}, {
    "throttle_size2", test_nestest_name_fields}, {
    "throttle_size3", test_default_name_field}, {
    "throttle_size4", test_default_log_field}, {
    NULL, NULL}
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
    output = NULL;
    pthread_mutex_unlock(&result_mutex);

    return val;
}

int callback_test(void *data, size_t size, void *cb_data)
{
    if (size > 0) {
        flb_debug("[test_filter_throttle_size] received message: %s", data);
        set_output(data);       /* success */
    }
    return 0;
}

void flb_test_simple_log(void)
{
    int i;
    int ret;
    char p[1000];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;


    struct flb_lib_out_cb cb;
    cb.cb = callback_test;
    cb.data = NULL;

    ctx = flb_create();

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

    filter_ffd = flb_filter(ctx, (char *) "throttle_size", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "rate", "10", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "window", "30", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "interval", "3s", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "print_status", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "log_field", "log", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "name_field", "stream", NULL);
    TEST_CHECK(ret == 0);
    ret =
        flb_filter_set(ctx, filter_ffd, "window_time_duration", "10s", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /*  Verify that the size throttle plugin differentiates logs by a non nested name_field.
       We put 9 logs 32 bytes long which is 288 bytes of total or rate of 9.6.
       If all logs passed this means that the the plugin sees them as two seperates tipes or
       does now work at all.Or each logs is seen as different group of logs. */
    for (i = 0; i < 9; i++) {
        /*Make message with sream: stdout */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), simple_log, _32_bytes_msg, stdout_str, i);
        check_if_message_pass_through_engine(ctx, in_ffd, p);

        /*Make message with sream: stderr */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), simple_log, _32_bytes_msg, stderr_str, i);
        check_if_message_pass_through_engine(ctx, in_ffd, p);
    }

    /*  Verify that the plugin cut logs wen rate exceeds 10.
       By add next message which is 32 bytes log the total must become 320 which
       makes the rate 10.66. If the messege is dropped this means that the plugin
       works properly. */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), simple_log, _32_bytes_msg, stdout_str, 9);
    check_if_message_doesnt_pass_through_engine(ctx, in_ffd, p);


    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), simple_log, _32_bytes_msg, stderr_str, 9);
    check_if_message_doesnt_pass_through_engine(ctx, in_ffd, p);

    /*Now we will pass two messages with 11 bytes of lenght an they will make the
       rate 9.96 which is less than 10 and they must pass */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), simple_log, _11_bytes_msg, stdout_str, 10);
    check_if_message_pass_through_engine(ctx, in_ffd, p);

    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), simple_log, _11_bytes_msg, stderr_str, 10);
    check_if_message_pass_through_engine(ctx, in_ffd, p);

    /*check that if log field is missing then the messages will pass throughout the engine */
    for (i = 0; i < 2; i++) {
        /*Make message with sream: stdout */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), simple_log_with_missing_log_key,
                 _180_bytes_msg, stdout_str, i + 11);
        check_if_message_pass_through_engine(ctx, in_ffd, p);

        /*Make message with sream: stderr */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), simple_log_with_missing_log_key,
                 _180_bytes_msg, stderr_str, i + 11);
        check_if_message_pass_through_engine(ctx, in_ffd, p);
    }

    /*check that if stream field is missing then the messages will pass throughout the engine */
    for (i = 0; i < 2; i++) {
        /*Make message with sream: stdout */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), simple_log_with_missing_stream_key,
                 _180_bytes_msg, stdout_str, i + 13);
        check_if_message_pass_through_engine(ctx, in_ffd, p);

        /*Make message with sream: stderr */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), simple_log_with_missing_stream_key,
                 _180_bytes_msg, stderr_str, i + 13);
        check_if_message_pass_through_engine(ctx, in_ffd, p);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void test_nestest_name_fields(void)
{
    int i;
    int ret;
    char p[1000];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;


    struct flb_lib_out_cb cb;
    cb.cb = callback_test;
    cb.data = NULL;

    ctx = flb_create();

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

    filter_ffd = flb_filter(ctx, (char *) "throttle_size", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "rate", "10", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "window", "30", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "interval", "3s", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "print_status", "false", NULL);
    TEST_CHECK(ret == 0);
    ret =
        flb_filter_set(ctx, filter_ffd, "log_field", "logwrapper|log", NULL);
    TEST_CHECK(ret == 0);
    ret =
        flb_filter_set(ctx, filter_ffd, "name_field", "kubernetes|pod_name",
                       NULL);
    TEST_CHECK(ret == 0);
    ret =
        flb_filter_set(ctx, filter_ffd, "window_time_duration", "10s", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /*  Verify that the size throttle plugin differentiates logs by a nested name_field and nested log_field.
       We put 9 logs 32 bytes long which is 288 bytes of total or rate of 9.6.
       If all logs passed this means that the the plugin sees them as two seperates tipes or
       does now work at all.Or each logs is seen as different group of logs. */
    for (i = 0; i < 9; i++) {
        /*Make message with sream: stdout */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), nested_log, _32_bytes_msg, apiserver, i);
        check_if_message_pass_through_engine(ctx, in_ffd, p);

        /*Make message with kubernetes.pod_name: alermanager */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), nested_log, _32_bytes_msg, alertmanager, i);
        check_if_message_pass_through_engine(ctx, in_ffd, p);
    }

    /*  Verify that the plugin cut logs when rate exceeds 10.
       By add next message which is 32 bytes log the total must become 320 which
       makes the rate 10.66. If the messege is dropped this means that the plugin
       works properly. */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), nested_log, _32_bytes_msg, apiserver, 9);
    check_if_message_doesnt_pass_through_engine(ctx, in_ffd, p);


    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), nested_log, _32_bytes_msg, alertmanager, 9);
    check_if_message_doesnt_pass_through_engine(ctx, in_ffd, p);

    /*Now we will pass two messages with 11 bytes of lenght an they will make the
       rate 9.96 which is less than 10 and they must pass */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), nested_log, _11_bytes_msg, apiserver, 10);
    check_if_message_pass_through_engine(ctx, in_ffd, p);

    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), nested_log, _11_bytes_msg, alertmanager, 10);
    check_if_message_pass_through_engine(ctx, in_ffd, p);

    /*check that if log field is missing then the messages will pass throughout the engine */
    for (i = 0; i < 2; i++) {
        /*Make message with kubernetes.pod_name: kube-apiserver */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), nested_log_with_missing_log_field,
                 _180_bytes_msg, apiserver, i + 11);
        check_if_message_pass_through_engine(ctx, in_ffd, p);

        /*Make message with kubernetes.pod_name: alertmanager */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), nested_log_with_missing_log_field,
                 _180_bytes_msg, alertmanager, i + 11);
        check_if_message_pass_through_engine(ctx, in_ffd, p);
    }

    /*check that if pod_name field is missing then the messages will pass throughout the engine */
    for (i = 0; i < 2; i++) {
        /*Make message with kubernetes.pod_name: kube-apiserver */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), nested_log_with_missing_name_field,
                 _180_bytes_msg, apiserver, i + 13);
        check_if_message_pass_through_engine(ctx, in_ffd, p);

        /*Make message with kubernetes.pod_name: alermanager */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), nested_log_with_missing_name_field,
                 _180_bytes_msg, alertmanager, i + 13);
        check_if_message_pass_through_engine(ctx, in_ffd, p);
    }

    /*check that if pod_name is not in the right order then the messages will pass throughout the engine */
    for (i = 0; i < 2; i++) {
        /*Make message with kubernetes.pod_name: kube-apiserver */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), swap_name_field, _180_bytes_msg, apiserver,
                 i + 15);
        check_if_message_pass_through_engine(ctx, in_ffd, p);

        /*Make message with kubernets.pod_name: alertmanager */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), swap_name_field, _180_bytes_msg, alertmanager,
                 i + 15);
        check_if_message_pass_through_engine(ctx, in_ffd, p);
    }

    /*check that if log field is wrong order then the messages will pass throughout the engine */
    for (i = 0; i < 2; i++) {
        /*Make message with kubernetes.pod_name: kube-apiserver */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), swap_log_field, _180_bytes_msg, apiserver,
                 i + 17);
        check_if_message_pass_through_engine(ctx, in_ffd, p);

        /*Make message with kubernetes: alertmanager */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), swap_log_field, _180_bytes_msg, alertmanager,
                 i + 17);
        check_if_message_pass_through_engine(ctx, in_ffd, p);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void test_default_name_field(void)
{
    int i;
    int ret;
    char p[200];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    struct flb_lib_out_cb cb;
    cb.cb = callback_test;
    cb.data = NULL;

    ctx = flb_create();

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

    filter_ffd = flb_filter(ctx, (char *) "throttle_size", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "rate", "10", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "window", "30", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "interval", "3s", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "print_status", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "log_field", "log", NULL);
    TEST_CHECK(ret == 0);
    ret =
        flb_filter_set(ctx, filter_ffd, "window_time_duration", "10s", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /*  Verify that the size throttle plugin do not differentiates logs by name_field.
       We put 8 logs 32 bytes long which is 256 bytes of total or rate of 8.53.
       If all logs passed this means that the the plugin sees them as one or
       does now work at all.Or each logs is seen as different group of logs. */
    for (i = 0; i < 4; i++) {
        /*Make message with sream: stdout */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), simple_log, _32_bytes_msg, stdout_str, i);
        check_if_message_pass_through_engine(ctx, in_ffd, p);

        /*Make message with sream: stderr */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), simple_log, _32_bytes_msg, stderr_str, i);
        check_if_message_pass_through_engine(ctx, in_ffd, p);
    }

    /*Add one exra message with lenght of 32 bytes to make the total 288 or rate of 9.6 */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), simple_log, _32_bytes_msg, stdout_str, 9);
    check_if_message_pass_through_engine(ctx, in_ffd, p);

    /*  Verify that the plugin cut logs when rate exceeds 10.
       By add next message which is 32 bytes log the total must become 320 which
       makes the rate 10.66. If the messege is dropped this means that the plugin
       works properly. */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), simple_log, _32_bytes_msg, stdout_str, 9);
    check_if_message_doesnt_pass_through_engine(ctx, in_ffd, p);
    /*  Verify that the plugin cut logs when rate exceeds 10.
       By add next message which is 32 bytes log the total must become 320 which
       makes the rate 10.66. If the messege is dropped this means that the plugin
       works properly. */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), simple_log, _32_bytes_msg, stderr_str, 9);
    check_if_message_doesnt_pass_through_engine(ctx, in_ffd, p);


    /*Now we will pass two messages with 6 bytes of lenght an they will make the
       rate 10 whch is the limit and the message must pass. */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), simple_log, _6_bytes_msg, stdout_str, 10);
    check_if_message_pass_through_engine(ctx, in_ffd, p);

    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), simple_log, _6_bytes_msg, stderr_str, 10);
    check_if_message_pass_through_engine(ctx, in_ffd, p);


    flb_stop(ctx);
    flb_destroy(ctx);
}


void test_default_log_field(void)
{
    int i;
    int ret;
    char p[1000];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;


    struct flb_lib_out_cb cb;
    cb.cb = callback_test;
    cb.data = NULL;

    ctx = flb_create();

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

    filter_ffd = flb_filter(ctx, (char *) "throttle_size", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "rate", "43", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "window", "30", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "interval", "3s", NULL);
    TEST_CHECK(ret == 0);
    ret =
        flb_filter_set(ctx, filter_ffd, "name_field", "kubernetes|pod_name",
                       NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "print_status", "false", NULL);
    TEST_CHECK(ret == 0);
    ret =
        flb_filter_set(ctx, filter_ffd, "window_time_duration", "10s", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /*  Verify that fluent-bit take in account all of the message payload when log_field is missing.
       We shall put two messages with differen kubernetes.podname which will pass.
       One message is about 463 bytes long and two makes the rate about 30.87 */
    for (i = 0; i < 2; i++) {
        /*Make message with kubernetes.pod_name:kube-apiserver */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), nested_log, _180_bytes_msg, apiserver, 1);
        check_if_message_pass_through_engine(ctx, in_ffd, p);

        /*Make message with kubernetes.pod_name:alermanager */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), nested_log, _180_bytes_msg, alertmanager, 1);
        check_if_message_pass_through_engine(ctx, in_ffd, p);
    }

    /*  Verify that the plugin cut logs when rate exceeds 37.
       We shall add again two messages with size 463 and they will
       fail passing. */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), nested_log, _180_bytes_msg, apiserver, 1);
    check_if_message_doesnt_pass_through_engine(ctx, in_ffd, p);

    /*Make message with kubernetes.pod_name:alermanager */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), nested_log, _180_bytes_msg, alertmanager, 1);
    check_if_message_doesnt_pass_through_engine(ctx, in_ffd, p);

    /*The next two must pass */
    /*Make message with kubernetes.pod_name:kube-apiserver */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), nested_log, _32_bytes_msg, apiserver, 1);
    check_if_message_pass_through_engine(ctx, in_ffd, p);

    /*Make message with kubernetes.pod_name:alermanager */
    memset(p, '\0', sizeof(p));
    snprintf(p, sizeof(p), nested_log, _32_bytes_msg, alertmanager, 1);
    check_if_message_pass_through_engine(ctx, in_ffd, p);


    flb_stop(ctx);
    flb_destroy(ctx);
}

char *push_data_to_engine_and_take_output(flb_ctx_t * ctx, int in_ffd,
                                          char *message)
{
    char *result = NULL;
    int bytes;
    /*Push the message into the engine */
    bytes = flb_lib_push(ctx, in_ffd, (void *) message, strlen(message));
    WAIT_FOR_FLUSH              /*wait the output data to be flushed */
        result = get_output();  /*get the output message */
    TEST_CHECK(bytes == strlen(message));       /*Chech if all of the message was proceesed */
    return result;
}

void check_if_message_pass_through_engine(flb_ctx_t * ctx, int in_ffd,
                                          char *message)
{
    char *result;
    result = push_data_to_engine_and_take_output(ctx, in_ffd, message);
    /*Check that the message go throught engine without modification */
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
