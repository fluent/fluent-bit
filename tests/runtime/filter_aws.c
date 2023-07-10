/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdlib.h>
#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_runtime.h"
#include "../../plugins/filter_aws/aws.h"

#include "../include/aws_client_mock.h"
#include "../include/aws_client_mock.c"

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;

void set_output(char *val)
{
    pthread_mutex_lock(&result_mutex);
    if (output) {
        free(output);
    }
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
        flb_debug("[test_filter_aws] received message: %s", (char*)data);
        set_output(data); /* success */
    }
    return 0;
}

void flb_test_aws_ec2_tags_present() {
    int ret;
    int bytes;
    char *p = "[0, {\"log\": \"hello, from my ec2 instance\"}]";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb_data;
    struct flb_aws_client_generator *client_generator;
    struct flb_filter_aws_init_options *ops;
    struct flb_aws_client_mock_request_chain *request_chain;
    char *output = NULL;
    char *result;

    request_chain = FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/latest/meta-data/tags/instance"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "Name\nCUSTOMER_ID\nthis-would-be-my-very-long-tag-name-does-it-work"),
            set(PAYLOAD_SIZE, 65)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance/Name"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "my_ec2_instance"),
            set(PAYLOAD_SIZE, 15)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance/CUSTOMER_ID"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "70ec5c04-3a6e-11ed-a261-0242ac120002"),
            set(PAYLOAD_SIZE, 36)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance/this-would-be-my-very-long-tag-name-does-it-work"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "yes-it-does"),
            set(PAYLOAD_SIZE, 11)
        )
    );
    flb_aws_client_mock_configure_generator(request_chain);

    client_generator = flb_aws_client_get_mock_generator();
    ops = flb_calloc(1, sizeof(struct flb_filter_aws_init_options));
    if (ops == NULL) {
        TEST_MSG("calloc for aws plugin options failed\n");
        TEST_CHECK(false);
        return;
    }
    ops->client_generator = client_generator;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);


    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    filter_ffd = flb_filter(ctx, (char *) "aws", ops);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "ec2_instance_id", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "az", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "tags_enabled", "true", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    if (!TEST_CHECK(bytes > 0)) {
        TEST_MSG("zero bytes were pushed\n");
    }

    flb_time_msleep(1500); /* waiting flush */

    output = get_output();
    if (output) {
        result = strstr(output, "\"Name\":\"my_ec2_instance\"");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
        result = strstr(output, "\"CUSTOMER_ID\":\"70ec5c04-3a6e-11ed-a261-0242ac120002\"");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
        result = strstr(output, "\"this-would-be-my-very-long-tag-name-does-it-work\":\"yes-it-does\"");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
        result = strstr(output, "hello, from my ec2 instance");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
    }
    else {
        TEST_CHECK(false);
        TEST_MSG("output is empty\n");
    }

    flb_stop(ctx);
    flb_aws_client_mock_destroy_generator();
    flb_destroy(ctx);
    flb_free(ops);

    set_output(NULL);
}

void flb_test_aws_ec2_tags_404() {
    int ret;
    int bytes;
    char *p = "[0, {\"log\": \"hello, from my ec2 instance\"}]";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb_data;
    struct flb_aws_client_generator *client_generator;
    struct flb_filter_aws_init_options *ops;
    struct flb_aws_client_mock_request_chain *request_chain;
    char *output = NULL;
    char *result;

    request_chain = FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/latest/meta-data/tags/instance"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 404)
        )
    );
    flb_aws_client_mock_configure_generator(request_chain);

    client_generator = flb_aws_client_get_mock_generator();
    ops = flb_calloc(1, sizeof(struct flb_filter_aws_init_options));
    if (ops == NULL) {
        TEST_MSG("calloc for aws plugin options failed\n");
        TEST_CHECK(false);
        return;
    }
    ops->client_generator = client_generator;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);


    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    filter_ffd = flb_filter(ctx, (char *) "aws", ops);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "ec2_instance_id", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "az", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "tags_enabled", "true", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    if (!TEST_CHECK(bytes > 0)) {
        TEST_MSG("zero bytes were pushed\n");
    }

    flb_time_msleep(1500); /* waiting flush */

    output = get_output();
    if (output) {
        result = strstr(output, "\"Name\":\"my_ec2_instance\"");
        if (!TEST_CHECK(result == NULL)) {
            TEST_MSG("output:%s\n", output);
        }
        result = strstr(output, "\"CUSTOMER_ID\":\"70ec5c04-3a6e-11ed-a261-0242ac120002\"");
        if (!TEST_CHECK(result == NULL)) {
            TEST_MSG("output:%s\n", output);
        }
        result = strstr(output, "hello, from my ec2 instance");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
    }
    else {
        TEST_CHECK(false);
        TEST_MSG("output is empty");
    }

    flb_stop(ctx);
    flb_aws_client_mock_destroy_generator();
    flb_destroy(ctx);
    flb_free(ops);

    set_output(NULL);
}

void flb_test_aws_ec2_tags_list_500() {
    int ret;
    int bytes;
    char *p = "[0, {\"log\": \"hello, from my ec2 instance\"}]";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb_data;
    struct flb_aws_client_generator *client_generator;
    struct flb_filter_aws_init_options *ops;
    struct flb_aws_client_mock_request_chain *request_chain;
    char *output = NULL;
    char *result;

    request_chain = FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/latest/meta-data/tags/instance"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 500)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 500)
        )
    );
    flb_aws_client_mock_configure_generator(request_chain);

    client_generator = flb_aws_client_get_mock_generator();
    ops = flb_calloc(1, sizeof(struct flb_filter_aws_init_options));
    if (ops == NULL) {
        TEST_MSG("calloc for aws plugin options failed\n");
        TEST_CHECK(false);
        return;
    }
    ops->client_generator = client_generator;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);


    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    filter_ffd = flb_filter(ctx, (char *) "aws", ops);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "ec2_instance_id", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "az", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "tags_enabled", "true", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    if (!TEST_CHECK(bytes > 0)) {
        TEST_MSG("zero bytes were pushed\n");
    }

    flb_time_msleep(1500); /* waiting flush */

    output = get_output();
    if (output) {
        result = strstr(output, "hello, from my ec2 instance");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
    }
    else {
        TEST_CHECK(false);
        TEST_MSG("output is empty");
    }

    flb_stop(ctx);
    flb_aws_client_mock_destroy_generator();
    flb_destroy(ctx);
    flb_free(ops);

    set_output(NULL);
}

void flb_test_aws_ec2_tags_value_404() {
     int ret;
    int bytes;
    char *p = "[0, {\"log\": \"hello, from my ec2 instance\"}]";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb_data;
    struct flb_aws_client_generator *client_generator;
    struct flb_filter_aws_init_options *ops;
    struct flb_aws_client_mock_request_chain *request_chain;
    char *output = NULL;
    char *result;

    request_chain = FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/latest/meta-data/tags/instance"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "Name"),
            set(PAYLOAD_SIZE, 4)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance/Name"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 404)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "Name"),
            set(PAYLOAD_SIZE, 4)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance/Name"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 404)
        )
    );
    flb_aws_client_mock_configure_generator(request_chain);

    client_generator = flb_aws_client_get_mock_generator();
    ops = flb_calloc(1, sizeof(struct flb_filter_aws_init_options));
    if (ops == NULL) {
        TEST_MSG("calloc for aws plugin options failed\n");
        TEST_CHECK(false);
        return;
    }
    ops->client_generator = client_generator;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);


    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    filter_ffd = flb_filter(ctx, (char *) "aws", ops);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "ec2_instance_id", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "az", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "tags_enabled", "true", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    if (!TEST_CHECK(bytes > 0)) {
        TEST_MSG("zero bytes were pushed\n");
    }

    flb_time_msleep(1500); /* waiting flush */

    output = get_output();
    if (output) {
        result = strstr(output, "hello, from my ec2 instance");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
    }
    else {
        TEST_CHECK(false);
        TEST_MSG("output is empty");
    }

    flb_stop(ctx);
    flb_aws_client_mock_destroy_generator();
    flb_destroy(ctx);
    flb_free(ops);

    set_output(NULL);
}

void flb_test_aws_ec2_tags_value_500() {
     int ret;
    int bytes;
    char *p = "[0, {\"log\": \"hello, from my ec2 instance\"}]";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb_data;
    struct flb_aws_client_generator *client_generator;
    struct flb_filter_aws_init_options *ops;
    struct flb_aws_client_mock_request_chain *request_chain;
    char *output = NULL;
    char *result;

    request_chain = FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/latest/meta-data/tags/instance"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "Name"),
            set(PAYLOAD_SIZE, 4)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance/Name"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 500)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "Name"),
            set(PAYLOAD_SIZE, 4)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance/Name"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 500)
        )
    );
    flb_aws_client_mock_configure_generator(request_chain);

    client_generator = flb_aws_client_get_mock_generator();
    ops = flb_calloc(1, sizeof(struct flb_filter_aws_init_options));
    if (ops == NULL) {
        TEST_MSG("calloc for aws plugin options failed\n");
        TEST_CHECK(false);
        return;
    }
    ops->client_generator = client_generator;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);


    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    filter_ffd = flb_filter(ctx, (char *) "aws", ops);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "ec2_instance_id", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "az", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "tags_enabled", "true", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    if (!TEST_CHECK(bytes > 0)) {
        TEST_MSG("zero bytes were pushed\n");
    }

    flb_time_msleep(1500); /* waiting flush */

    output = get_output();
    if (output) {
        result = strstr(output, "hello, from my ec2 instance");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
    }
    else {
        TEST_CHECK(false);
        TEST_MSG("output is empty");
    }

    flb_stop(ctx);
    flb_aws_client_mock_destroy_generator();
    flb_destroy(ctx);
    flb_free(ops);

    set_output(NULL);
}

void flb_test_aws_ec2_tags_include() {
    int ret;
    int bytes;
    char *p = "[0, {\"log\": \"hello, from my ec2 instance\"}]";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb_data;
    struct flb_aws_client_generator *client_generator;
    struct flb_filter_aws_init_options *ops;
    struct flb_aws_client_mock_request_chain *request_chain;
    char *output = NULL;
    char *result;

    request_chain = FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/latest/meta-data/tags/instance"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "Name\nCUSTOMER_ID"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance/Name"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "my_ec2_instance"),
            set(PAYLOAD_SIZE, 15)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance/CUSTOMER_ID"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "70ec5c04-3a6e-11ed-a261-0242ac120002"),
            set(PAYLOAD_SIZE, 36)
        )
    );
    flb_aws_client_mock_configure_generator(request_chain);

    client_generator = flb_aws_client_get_mock_generator();
    ops = flb_calloc(1, sizeof(struct flb_filter_aws_init_options));
    if (ops == NULL) {
        TEST_MSG("calloc for aws plugin options failed\n");
        TEST_CHECK(false);
        return;
    }
    ops->client_generator = client_generator;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);


    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    filter_ffd = flb_filter(ctx, (char *) "aws", ops);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "ec2_instance_id", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "az", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "tags_enabled", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "tags_include", "Namee,MyTag,Name", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    if (!TEST_CHECK(bytes > 0)) {
        TEST_MSG("zero bytes were pushed\n");
    }

    flb_time_msleep(1500); /* waiting flush */

    output = get_output();
    if (output) {
        result = strstr(output, "\"Name\":\"my_ec2_instance\"");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
        result = strstr(output, "hello, from my ec2 instance");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
        /* CUSTOMER_ID is not included, so we don't expect it in the log */
        result = strstr(output, "\"CUSTOMER_ID\":\"70ec5c04-3a6e-11ed-a261-0242ac120002\"");
        if (!TEST_CHECK(result == NULL)) {
            TEST_MSG("output:%s\n", output);
        }
    }
    else {
        TEST_CHECK(false);
        TEST_MSG("output is empty\n");
    }

    flb_stop(ctx);
    flb_aws_client_mock_destroy_generator();
    flb_destroy(ctx);
    flb_free(ops);

    set_output(NULL);
}

void flb_test_aws_ec2_tags_exclude() {
    int ret;
    int bytes;
    char *p = "[0, {\"log\": \"hello, from my ec2 instance\"}]";
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    struct flb_lib_out_cb cb_data;
    struct flb_aws_client_generator *client_generator;
    struct flb_filter_aws_init_options *ops;
    struct flb_aws_client_mock_request_chain *request_chain;
    char *output = NULL;
    char *result;

    request_chain = FLB_AWS_CLIENT_MOCK(
        response(
            expect(URI, "/latest/meta-data/tags/instance"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "Name\nCUSTOMER_ID"),
            set(PAYLOAD_SIZE, 16)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance/Name"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "my_ec2_instance"),
            set(PAYLOAD_SIZE, 15)
        ),
        response(
            expect(URI, "/latest/meta-data/tags/instance/CUSTOMER_ID"),
            expect(METHOD, FLB_HTTP_GET),
            set(STATUS, 200),
            set(PAYLOAD, "70ec5c04-3a6e-11ed-a261-0242ac120002"),
            set(PAYLOAD_SIZE, 36)
        )
    );
    flb_aws_client_mock_configure_generator(request_chain);

    client_generator = flb_aws_client_get_mock_generator();
    ops = flb_calloc(1, sizeof(struct flb_filter_aws_init_options));
    if (ops == NULL) {
        TEST_MSG("calloc for aws plugin options failed\n");
        TEST_CHECK(false);
        return;
    }
    ops->client_generator = client_generator;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);


    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "format", "json",
                   NULL);

    filter_ffd = flb_filter(ctx, (char *) "aws", ops);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd, "match", "*", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "ec2_instance_id", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "az", "false", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "tags_enabled", "true", NULL);
    TEST_CHECK(ret == 0);
    ret = flb_filter_set(ctx, filter_ffd, "tags_exclude", "Name,Name2", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx, in_ffd, p, strlen(p));
    if (!TEST_CHECK(bytes > 0)) {
        TEST_MSG("zero bytes were pushed\n");
    }

    flb_time_msleep(1500); /* waiting flush */

    output = get_output();
    if (output) {
        /* Name is excluded, so we don't expect it in the log */
        result = strstr(output, "\"Name\":\"my_ec2_instance\"");
        if (!TEST_CHECK(result == NULL)) {
            TEST_MSG("output:%s\n", output);
        }
        result = strstr(output, "hello, from my ec2 instance");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
        result = strstr(output, "\"CUSTOMER_ID\":\"70ec5c04-3a6e-11ed-a261-0242ac120002\"");
        if (!TEST_CHECK(result != NULL)) {
            TEST_MSG("output:%s\n", output);
        }
    }
    else {
        TEST_CHECK(false);
        TEST_MSG("output is empty\n");
    }

    flb_stop(ctx);
    flb_aws_client_mock_destroy_generator();
    flb_destroy(ctx);
    flb_free(ops);

    set_output(NULL);
}


TEST_LIST = {
    {"aws_ec2_tags_present", flb_test_aws_ec2_tags_present},
    {"aws_ec2_tags_404", flb_test_aws_ec2_tags_404},
    {"aws_ec2_tags_list_500", flb_test_aws_ec2_tags_list_500},
    {"aws_ec2_tags_value_404", flb_test_aws_ec2_tags_value_404},
    {"aws_ec2_tags_value_500", flb_test_aws_ec2_tags_value_500},
    {"aws_ec2_tags_include", flb_test_aws_ec2_tags_include},
    {"aws_ec2_tags_exclude", flb_test_aws_ec2_tags_exclude},
    {NULL, NULL}
};
