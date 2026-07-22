/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_thread_storage.h>
#include "flb_tests_runtime.h"

#include <stdlib.h>

#define DPATH_LOKI FLB_TESTS_DATA_PATH "/data/loki"
#define LOKI_TENANT_POLICY_HOST "127.0.0.1"
#define LOKI_TENANT_SPLIT_PORT "18083"
#define LOKI_TENANT_POLICY_SUCCESS_PORT "18084"
#define LOKI_TENANT_POLICY_ERROR_PORT "18085"

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_output = 0;
static flb_sds_t tenant_headers[4];
static flb_sds_t tenant_payloads[4];
static int tenant_request_count = 0;
static int tenant_policy_request_count = 0;
static int tenant_policy_a_count = 0;
static int tenant_policy_b_count = 0;
static int tenant_policy_fail_tenant_a = FLB_FALSE;

struct tenant_policy_server {
    struct flb_http_server server;
    struct flb_net_setup net_setup;
    struct flb_config *config;
    struct mk_event_loop *event_loop;
    pthread_t thread;
    int server_initialized;
    int server_started;
    int thread_started;
    int stop;
};

static int tenant_policy_server_should_stop(struct tenant_policy_server *mock)
{
    int stop;

    pthread_mutex_lock(&result_mutex);
    stop = mock->stop;
    pthread_mutex_unlock(&result_mutex);

    return stop;
}

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

static void clear_tenant_requests()
{
    int i;

    pthread_mutex_lock(&result_mutex);
    for (i = 0; i < 4; i++) {
        if (tenant_headers[i]) {
            flb_sds_destroy(tenant_headers[i]);
            tenant_headers[i] = NULL;
        }
        if (tenant_payloads[i]) {
            flb_sds_destroy(tenant_payloads[i]);
            tenant_payloads[i] = NULL;
        }
    }
    tenant_request_count = 0;
    pthread_mutex_unlock(&result_mutex);
}

static int get_tenant_request_count()
{
    int ret;

    pthread_mutex_lock(&result_mutex);
    ret = tenant_request_count;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void clear_tenant_policy_requests()
{
    pthread_mutex_lock(&result_mutex);
    tenant_policy_request_count = 0;
    tenant_policy_a_count = 0;
    tenant_policy_b_count = 0;
    tenant_policy_fail_tenant_a = FLB_FALSE;
    pthread_mutex_unlock(&result_mutex);
}

static int get_tenant_policy_request_count()
{
    int ret;

    pthread_mutex_lock(&result_mutex);
    ret = tenant_policy_request_count;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static int get_tenant_policy_a_count()
{
    int ret;

    pthread_mutex_lock(&result_mutex);
    ret = tenant_policy_a_count;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static int get_tenant_policy_b_count()
{
    int ret;

    pthread_mutex_lock(&result_mutex);
    ret = tenant_policy_b_count;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void set_tenant_policy_fail_tenant_a(int fail)
{
    pthread_mutex_lock(&result_mutex);
    tenant_policy_fail_tenant_a = fail;
    pthread_mutex_unlock(&result_mutex);
}

static int cb_loki_tenant_policy_server(struct flb_http_request *request,
                                        struct flb_http_response *response)
{
    int status = 200;
    int slot;
    int fail_tenant_a;
    char *tenant;

    tenant = flb_http_request_get_header(request, "x-scope-orgid");

    pthread_mutex_lock(&result_mutex);
    slot = tenant_request_count;
    if (slot < 4) {
        if (tenant != NULL) {
            tenant_headers[slot] = flb_sds_create("X-Scope-OrgID: ");
            if (tenant_headers[slot] != NULL) {
                tenant_headers[slot] = flb_sds_cat(tenant_headers[slot],
                                                   tenant, strlen(tenant));
            }
        }

        if (request->body != NULL) {
            tenant_payloads[slot] = flb_sds_create_len(request->body,
                                                       cfl_sds_len(request->body));
        }
        tenant_request_count++;
    }

    tenant_policy_request_count++;
    fail_tenant_a = tenant_policy_fail_tenant_a;
    if (tenant != NULL && strcmp(tenant, "tenant-a") == 0) {
        tenant_policy_a_count++;
        if (fail_tenant_a == FLB_TRUE) {
            status = 400;
        }
    }
    else if (tenant != NULL && strcmp(tenant, "tenant-b") == 0) {
        tenant_policy_b_count++;
    }
    pthread_mutex_unlock(&result_mutex);

    if (status == 400) {
        return flb_hs_response_send_string(response, status,
                                           FLB_HS_CONTENT_TYPE_OTHER,
                                           "bad tenant");
    }

    return flb_hs_response_send_string(response, status,
                                       FLB_HS_CONTENT_TYPE_OTHER,
                                       "ok");
}

static void *tenant_policy_server_loop(void *data)
{
    struct mk_event *event;
    struct tenant_policy_server *mock = data;

    flb_engine_evl_set(mock->event_loop);

    while (tenant_policy_server_should_stop(mock) == FLB_FALSE) {
        mk_event_wait_2(mock->event_loop, 100);

        mk_event_foreach(event, mock->event_loop) {
            if (event->type == FLB_ENGINE_EV_CUSTOM) {
                event->handler(event);
            }
        }

        if (mock->server.downstream != NULL) {
            flb_downstream_conn_pending_destroy(mock->server.downstream);
        }
    }

    return NULL;
}

static void stop_tenant_policy_server(struct tenant_policy_server *mock)
{
    if (mock->thread_started == FLB_TRUE) {
        pthread_mutex_lock(&result_mutex);
        mock->stop = FLB_TRUE;
        pthread_mutex_unlock(&result_mutex);

        pthread_join(mock->thread, NULL);
        mock->thread_started = FLB_FALSE;
    }

    if (mock->server_started == FLB_TRUE) {
        flb_http_server_stop(&mock->server);
        mock->server_started = FLB_FALSE;
    }

    if (mock->server_initialized == FLB_TRUE) {
        flb_http_server_destroy(&mock->server);
        mock->server_initialized = FLB_FALSE;
    }

    if (mock->event_loop != NULL) {
        mk_event_loop_destroy(mock->event_loop);
        mock->event_loop = NULL;
    }

    if (mock->config != NULL) {
        flb_config_exit(mock->config);
        mock->config = NULL;
    }
}

static int start_tenant_policy_server(struct tenant_policy_server *mock,
                                      const char *port)
{
    int ret;
    struct flb_http_server_options options;

    memset(mock, 0, sizeof(struct tenant_policy_server));

    flb_http_server_options_init(&options);
    flb_net_setup_init(&mock->net_setup);

    mock->config = flb_config_init();
    if (mock->config == NULL) {
        return -1;
    }

    mock->event_loop = mk_event_loop_create(256);
    if (mock->event_loop == NULL) {
        stop_tenant_policy_server(mock);
        return -1;
    }

    options.protocol_version = HTTP_PROTOCOL_VERSION_11;
    options.request_callback = cb_loki_tenant_policy_server;
    options.address = (char *) LOKI_TENANT_POLICY_HOST;
    options.port = (unsigned short) atoi(port);
    options.networking_flags = 0;
    options.networking_setup = &mock->net_setup;
    options.event_loop = mock->event_loop;
    options.system_context = mock->config;
    options.use_caller_event_loop = FLB_TRUE;

    ret = flb_http_server_init_with_options(&mock->server, &options);
    if (ret != 0) {
        stop_tenant_policy_server(mock);
        return -1;
    }
    mock->server_initialized = FLB_TRUE;

    ret = flb_http_server_start(&mock->server);
    if (ret != 0) {
        stop_tenant_policy_server(mock);
        return -1;
    }
    mock->server_started = FLB_TRUE;

    mock->stop = FLB_FALSE;
    ret = pthread_create(&mock->thread, NULL, tenant_policy_server_loop, mock);
    if (ret != 0) {
        stop_tenant_policy_server(mock);
        return -1;
    }
    mock->thread_started = FLB_TRUE;

    flb_time_msleep(500);

    return 0;
}

#define JSON_BASIC "[12345678, {\"key\":\"value\"}]"
static void cb_check_basic(void *ctx, int ffd,
                           int res_ret, void *res_data, size_t res_size,
                           void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "{\\\"key\\\":\\\"value\\\"}";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_basic()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_basic,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_labels(void *ctx, int ffd,
                            int res_ret, void *res_data, size_t res_size,
                            void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "\"stream\":{\"a\":\"b\"}";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_labels()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "labels", "a=b", /* "stream":{"a":"b"} */
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_labels,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_label_keys(void *ctx, int ffd,
                                int res_ret, void *res_data, size_t res_size,
                                void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "{\"stream\":{\"data_l_key\":\"test\"}";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

#define JSON_LABEL_KEYS "[12345678, {\"key\":\"value\",\"foo\":\"bar\", \"data\":{\"l_key\":\"test\"}}]"
void flb_test_label_keys()
{
    int ret;
    int size = sizeof(JSON_LABEL_KEYS) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "label_keys", "$data['l_key']", /* {"stream":{"data_l_key":"test"} */
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_label_keys,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_LABEL_KEYS, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_line_format(void *ctx, int ffd,
                                 int res_ret, void *res_data, size_t res_size,
                                 void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "key=\\\"value\\\"";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_line_format()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "line_format", "key_value",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_line_format,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_drop_single_key_off(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "{\\\"key\\\":\\\"value\\\"}";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_drop_single_key_off()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "drop_single_key", "off",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_drop_single_key_off,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_drop_single_key_on(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "\\\"value\\\"";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_drop_single_key_on()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "drop_single_key", "on",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_drop_single_key_on,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_drop_single_key_raw(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "\"value\"";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_drop_single_key_raw()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "drop_single_key", "raw",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_drop_single_key_raw,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_line_format_remove_keys(void *ctx, int ffd,
                                             int res_ret, void *res_data,
                                             size_t res_size, void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "value_nested";

    /* p == NULL is expected since it should be removed.*/
    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p == NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}
#define JSON_BASIC_NEST "[12345678, {\"key\": {\"nest\":\"value_nested\"}} ]"
/* https://github.com/fluent/fluent-bit/issues/3875 */
void flb_test_remove_map()
{
    int ret;
    int size = sizeof(JSON_BASIC_NEST) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "remove_keys", "key",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_line_format_remove_keys,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC_NEST, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_labels_ra(void *ctx, int ffd,
                               int res_ret, void *res_data, size_t res_size,
                               void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "\\\"data\\\":{\\\"l_key\\\":\\\"test\\\"}";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

/* https://github.com/fluent/fluent-bit/issues/3867 */
void flb_test_labels_ra()
{
    int ret;
    int size = sizeof(JSON_LABEL_KEYS) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "labels", "$data['l_key']",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_labels_ra,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_LABEL_KEYS, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_remove_keys(void *ctx, int ffd,
                                int res_ret, void *res_data, size_t res_size,
                                void *data)
{
    char *p;
    flb_sds_t out_js = res_data;

    p = strstr(out_js, "foo");
    if (!TEST_CHECK(p == NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    p = strstr(out_js, "l_key");
    if (!TEST_CHECK(p == NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

void flb_test_remove_keys()
{
    int ret;
    int size = sizeof(JSON_LABEL_KEYS) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "remove_keys", "foo, $data['l_key']",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_remove_keys,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_LABEL_KEYS, size);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_remove_keys_workers()
{
    int ret;
    int i;
    int size = sizeof(JSON_LABEL_KEYS) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output with multiple workers */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "remove_keys", "foo, $data['l_key']",
                   "workers", "2",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_remove_keys,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest multiple data samples */
    for (i = 0; i < 10; i++) {
        flb_lib_push(ctx, in_ffd, (char *) JSON_LABEL_KEYS, size);
    }

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static int check_tenant_request(char *tenant, char *present, char *absent)
{
    int i;

    for (i = 0; i < tenant_request_count; i++) {
        if (tenant_headers[i] == NULL || tenant_payloads[i] == NULL) {
            continue;
        }

        if (strstr(tenant_headers[i], tenant) == NULL) {
            continue;
        }

        if (!TEST_CHECK(strstr(tenant_payloads[i], present) != NULL)) {
            TEST_MSG("payload for %s did not contain %s: %s",
                     tenant, present, tenant_payloads[i]);
            return -1;
        }

        if (!TEST_CHECK(strstr(tenant_payloads[i], absent) == NULL)) {
            TEST_MSG("payload for %s contained %s: %s",
                     tenant, absent, tenant_payloads[i]);
            return -1;
        }

        return 0;
    }

    TEST_CHECK(0);
    TEST_MSG("no request found for tenant %s", tenant);

    return -1;
}

void flb_test_tenant_id_key_splits_requests()
{
    int ret;
    int tries;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct tenant_policy_server mock_server;
    char *tenant_a = "[12345678, {\"tenant_id\":\"tenant-a\",\"msg\":\"msg-a\"}]";
    char *tenant_b = "[12345679, {\"tenant_id\":\"tenant-b\",\"msg\":\"msg-b\"}]";

    clear_tenant_requests();
    clear_tenant_policy_requests();

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match", "test",
                         "host", LOKI_TENANT_POLICY_HOST,
                         "port", LOKI_TENANT_SPLIT_PORT,
                         "tenant_id_key", "tenant_id",
                         "remove_keys", "tenant_id",
                         "net.keepalive", "off",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = start_tenant_policy_server(&mock_server, LOKI_TENANT_SPLIT_PORT);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, tenant_a, strlen(tenant_a));
    TEST_CHECK(ret >= 0);
    ret = flb_lib_push(ctx, in_ffd, tenant_b, strlen(tenant_b));
    TEST_CHECK(ret >= 0);

    for (tries = 0; tries < 20 && get_tenant_request_count() < 2; tries++) {
        flb_time_msleep(500);
    }

    if (!TEST_CHECK(get_tenant_request_count() == 2)) {
        TEST_MSG("expected 2 requests, got %d", get_tenant_request_count());
    }

    pthread_mutex_lock(&result_mutex);
    check_tenant_request("X-Scope-OrgID: tenant-a", "msg-a", "msg-b");
    check_tenant_request("X-Scope-OrgID: tenant-b", "msg-b", "msg-a");
    pthread_mutex_unlock(&result_mutex);

    flb_stop(ctx);
    stop_tenant_policy_server(&mock_server);
    flb_destroy(ctx);
    clear_tenant_requests();
    clear_tenant_policy_requests();
}

static void run_tenant_id_key_partial_handling(char *mode,
                                               char *port,
                                               int expect_retry)
{
    int ret;
    int tries;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct tenant_policy_server mock_server;
    char *tenant_a = "[12345678, {\"tenant_id\":\"tenant-a\",\"msg\":\"msg-a\"}]";
    char *tenant_b = "[12345679, {\"tenant_id\":\"tenant-b\",\"msg\":\"msg-b\"}]";

    clear_tenant_requests();
    clear_tenant_policy_requests();
    set_tenant_policy_fail_tenant_a(FLB_TRUE);

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    "scheduler.base", "1",
                    "scheduler.cap", "1",
                    NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    TEST_CHECK(out_ffd >= 0);
    ret = flb_output_set(ctx, out_ffd,
                         "match", "test",
                         "host", LOKI_TENANT_POLICY_HOST,
                         "port", port,
                         "tenant_id_key", "tenant_id",
                         "tenant_id_key_error_handling", mode,
                         "remove_keys", "tenant_id",
                         "Retry_Limit", "1",
                         "net.keepalive", "off",  /* Prevent mock server 10s timeout races */
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = start_tenant_policy_server(&mock_server, port);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx, in_ffd, tenant_a, strlen(tenant_a));
    TEST_CHECK(ret >= 0);
    ret = flb_lib_push(ctx, in_ffd, tenant_b, strlen(tenant_b));
    TEST_CHECK(ret >= 0);

    for (tries = 0; tries < 40 && get_tenant_policy_request_count() < 2; tries++) {
        flb_time_msleep(500);
    }

    if (!TEST_CHECK(get_tenant_policy_request_count() >= 2)) {
        TEST_MSG("expected at least 2 requests, got %d",
                 get_tenant_policy_request_count());
    }

    if (!TEST_CHECK(get_tenant_policy_a_count() >= 1)) {
        TEST_MSG("expected tenant-a request, got %d",
                 get_tenant_policy_a_count());
    }

    if (!TEST_CHECK(get_tenant_policy_b_count() >= 1)) {
        TEST_MSG("expected tenant-b request after tenant-a failure, got %d",
                 get_tenant_policy_b_count());
    }

    if (expect_retry == FLB_TRUE) {
        for (tries = 0;
             tries < 40 && get_tenant_policy_request_count() < 4;
             tries++) {
            flb_time_msleep(500);
        }

        if (!TEST_CHECK(get_tenant_policy_request_count() >= 4)) {
            TEST_MSG("expected retry requests, got %d",
                     get_tenant_policy_request_count());
        }

        if (!TEST_CHECK(get_tenant_policy_a_count() >= 2)) {
            TEST_MSG("expected tenant-a retry, got %d",
                     get_tenant_policy_a_count());
        }

        if (!TEST_CHECK(get_tenant_policy_b_count() >= 2)) {
            TEST_MSG("expected tenant-b duplicate on retry, got %d",
                     get_tenant_policy_b_count());
        }
    }
    else {
        flb_time_msleep(2500);  /* > one retry window with scheduler.base/cap = 1 */

        if (!TEST_CHECK(get_tenant_policy_request_count() == 2)) {
            TEST_MSG("expected no retry requests, got %d",
                     get_tenant_policy_request_count());
        }
    }

    flb_stop(ctx);
    stop_tenant_policy_server(&mock_server);
    flb_destroy(ctx);
    clear_tenant_requests();
    clear_tenant_policy_requests();
}

void flb_test_tenant_id_key_partial_success()
{
    run_tenant_id_key_partial_handling("partial_success",
                                       LOKI_TENANT_POLICY_SUCCESS_PORT,
                                       FLB_FALSE);
}

void flb_test_tenant_id_key_partial_error()
{
    run_tenant_id_key_partial_handling("partial_error",
                                       LOKI_TENANT_POLICY_ERROR_PORT,
                                       FLB_TRUE);
}

static void cb_check_label_map_path(void *ctx, int ffd,
                                    int res_ret, void *res_data, size_t res_size,
                                    void *data)
{
    char *p;
    flb_sds_t out_log = res_data;
    char *expected[] = {
        "\"container\":\"promtail\"",
        "\"pod\":\"promtail-xxx\"",
        "\"namespace\":\"prod\"",
        "\"team\":\"lalala\"",
        NULL};
    int i = 0;

    set_output_num(1);

    while(expected[i] != NULL) {
        p = strstr(out_log, expected[i]);
        if (!TEST_CHECK(p != NULL)) {
            TEST_MSG("Given:%s Expect:%s", out_log, expected[i]);
        }
        i++;
    }

    flb_sds_destroy(out_log);
}

void flb_test_label_map_path()
{
    int ret;
    char *str = "[12345678, {\"kubernetes\":{\"container_name\":\"promtail\",\"pod_name\":\"promtail-xxx\",\"namespace_name\":\"prod\",\"labels\":{\"team\": \"lalala\"}},\"log\":\"log\"}]";
    int size = strlen(str);
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_output_num();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "label_map_path", DPATH_LOKI "/labelmap.json",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_label_map_path,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, str, size);
    TEST_CHECK(ret == size);

    sleep(2);

    ret = get_output_num();
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("no output");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_float_value(void *ctx, int ffd,
                                 int res_ret, void *res_data, size_t res_size,
                                 void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    char *index_line = "\"float=1.3\"";

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out_js);
    }

    flb_sds_destroy(out_js);
}

#define JSON_FLOAT "[12345678, {\"float\":1.3}]"
void flb_test_float_value()
{
    int ret;
    size_t size = sizeof(JSON_FLOAT) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "line_format", "key_value",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_float_value,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_FLOAT, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

static void cb_check_structured_metadata_value(void *ctx, int ffd,
                                 int res_ret, void *res_data, size_t res_size,
                                 void *data)
{
    char *p;
    flb_sds_t out_js = res_data;
    if (!TEST_CHECK(out_js != NULL)) {
        TEST_MSG("out_js is NULL");
        return;
    }

    char *index_line = (char *) data;

    p = strstr(out_js, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Expecting %s but Given:%s", index_line, out_js);
    }

    flb_sds_destroy(out_js);
}

#define JSON_MAP "[12345678, {\"log\": \"This is an interesting log message!\", " \
    "\"map1\": {\"key1\": \"value1\", \"key2\": \"value2\", \"key_nested_object_1\": " \
    "{\"sub_key1\": \"sub_value1\", \"sub_key2\": false}}, \"map2\": {\"key4\": " \
    "\"value1\", \"key5\": false}, \"map3\": {\"key1\": \"map3_value1\", \"key2\": " \
    "\"map3_value2\"}}]"
void flb_test_structured_metadata_map_params(char *remove_keys,
                                             char *structured_metadata,
                                             char *structured_metadata_map_keys,
                                             char *input_log_json,
                                             char *expected_sub_str)
{
    int ret;
    size_t size = strlen(input_log_json);
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Loki output */
    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "line_format", "key_value",
                   "remove_keys", remove_keys,
                   "drop_single_key", "on",
                   "labels", "service_name=my_service_name",
                   "structured_metadata", structured_metadata,
                   "structured_metadata_map_keys", structured_metadata_map_keys,
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_structured_metadata_value,
                              expected_sub_str, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) input_log_json, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_structured_metadata_map_single_map() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "",
        "$map1",
        JSON_MAP,
        "{\"key1\":\"value1\",\"key2\":\"value2\","
        "\"key_nested_object_1\":\"{\\\"sub_key1\\\":\\\"sub_value1\\\","
        "\\\"sub_key2\\\":false}\"}");
}

void flb_test_structured_metadata_map_two_maps() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "",
        "$map1,$map2",
        JSON_MAP,
        "{\"key1\":\"value1\",\"key2\":\"value2\","
        "\"key_nested_object_1\":\"{\\\"sub_key1\\\":\\\"sub_value1\\\","
        "\\\"sub_key2\\\":false}\",\"key4\":\"value1\",\"key5\":\"false\"}");
}

void flb_test_structured_metadata_map_sub_map() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "",
        "$map1['key_nested_object_1']",
        JSON_MAP,
        "\"This is an interesting log message!\",{\"sub_key1\":\"sub_value1\","
        "\"sub_key2\":\"false\"}");
}

void flb_test_structured_metadata_map_both_with_non_map_value() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "$map2",
        "$map1,$map2",
        JSON_MAP,
        "{\"key1\":\"value1\",\"key2\":\"value2\","
        "\"key_nested_object_1\":\"{\\\"sub_key1\\\":\\\"sub_value1\\\","
        "\\\"sub_key2\\\":false}\",\"key4\":\"value1\",\"key5\":\"false\","
        "\"map2\":\"{\\\"key4\\\":\\\"value1\\\",\\\"key5\\\":false}\"}");
}

/* key1 is overridden by the explicit value given to structured_metadata */
void flb_test_structured_metadata_map_value_explicit_override_map_key() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "key1=value_explicit",
        "$map1,$map2",
        JSON_MAP,
        "{\"key2\":\"value2\","
        "\"key_nested_object_1\":\"{\\\"sub_key1\\\":\\\"sub_value1\\\","
        "\\\"sub_key2\\\":false}\",\"key4\":\"value1\",\"key5\":\"false\","
        "\"key1\":\"value_explicit\"}");
}

void flb_test_structured_metadata_explicit_only_no_map() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "key1=value_explicit",
        "",
        JSON_MAP,
        "[\"12345678000000000\","
        "\"This is an interesting log message!\",{\"key1\":\"value_explicit\"}]");
}

void flb_test_structured_metadata_explicit_only_map() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "$map2",
        "",
        JSON_MAP,
        "{\"map2\":\"{\\\"key4\\\":\\\"value1\\\",\\\"key5\\\":false}\"}");
}

void flb_test_structured_metadata_map_and_explicit() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "key_explicit=value_explicit",
        "$map1",
        JSON_MAP,
        "[\"12345678000000000\",\"This is an interesting log message!\","
        "{\"key1\":\"value1\",\"key2\":\"value2\","
        "\"key_nested_object_1\":\"{\\\"sub_key1\\\":\\\"sub_value1\\\","
        "\\\"sub_key2\\\":false}\",\"key_explicit\":\"value_explicit\"}]");
}

void flb_test_structured_metadata_map_single_missing_map() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "",
        "$missing_map",
        JSON_MAP,
        "[\"12345678000000000\",\"This is an interesting log message!\",{}]");
}

void flb_test_structured_metadata_map_invalid_ra_key() {
    flb_test_structured_metadata_map_params(
        "map1, map2, map3",
        "",
        "$",
        JSON_MAP,
        "[\"12345678000000000\",\"This is an interesting log message!\",{}]");
}

/* Test list */
TEST_LIST = {
    {"remove_keys_remove_map" , flb_test_remove_map},
    {"labels_ra"              , flb_test_labels_ra },
    {"remove_keys"            , flb_test_remove_keys },
    {"remove_keys_workers"    , flb_test_remove_keys_workers },
    {"tenant_id_key_splits_requests", flb_test_tenant_id_key_splits_requests },
    {"tenant_id_key_partial_success", flb_test_tenant_id_key_partial_success },
    {"tenant_id_key_partial_error", flb_test_tenant_id_key_partial_error },
    {"basic"                  , flb_test_basic },
    {"labels"                 , flb_test_labels },
    {"label_keys"             , flb_test_label_keys },
    {"line_format"            , flb_test_line_format },
    {"drop_single_key_off"    , flb_test_drop_single_key_off },
    {"drop_single_key_on"     , flb_test_drop_single_key_on },
    {"drop_single_key_raw"    , flb_test_drop_single_key_raw },
    {"label_map_path"         , flb_test_label_map_path},
    {"float_value"            , flb_test_float_value},
    {"structured_metadata_map_single_map",
        flb_test_structured_metadata_map_single_map},
    {"structured_metadata_map_two_maps",
        flb_test_structured_metadata_map_two_maps},
    {"structured_metadata_map_sub_map",
        flb_test_structured_metadata_map_sub_map},
    {"structured_metadata_map_both_with_non_map_value",
        flb_test_structured_metadata_map_both_with_non_map_value},
    {"structured_metadata_map_value_explicit_override_map_key",
        flb_test_structured_metadata_map_value_explicit_override_map_key},
    {"structured_metadata_explicit_only_no_map",
        flb_test_structured_metadata_explicit_only_no_map},
    {"structured_metadata_explicit_only_map",
        flb_test_structured_metadata_explicit_only_map},
    {"structured_metadata_map_and_explicit",
        flb_test_structured_metadata_map_and_explicit},
    {"structured_metadata_map_single_missing_map",
        flb_test_structured_metadata_map_single_missing_map},
    {"structured_metadata_map_invalid_ra_key",
        flb_test_structured_metadata_map_invalid_ra_key},
    {NULL, NULL}
};
