/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
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

#include <stdlib.h>
#include <fluent-bit.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_downstream.h>
#include <monkey/mk_core.h>
#include <monkey/mk_lib.h>

#include "flb_tests_runtime.h"

#define JSON_CONTENT_TYPE "application/json"

#define KUBE_API_HOST "127.0.0.1"
#define KUBE_API_PORT 8449

#define V1_EVENTS   "/v1/api/events"
#define IN_KUBERNETES_EVENTS_DATA_PATH FLB_TESTS_DATA_PATH "/data/in_kubernetes_events"
#define KUBE_TOKEN_FILE FLB_TESTS_DATA_PATH "/data/in_kubernetes_events/token"

struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd (unused) */
    int o_ffd;         /* Output fd */

};

struct test_k8s_server_ctx {
    mk_ctx_t *ctx;             /* Monkey HTTP Context */
    int vid;                   /* Virtual Host ID     */
    int mq_id;                 /* Message Queue ID    */
    struct mk_event_loop  *evl;
    char json_input_file[1024];
};


pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_output = 0;
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

static flb_sds_t read_file(const char *filename)
{
    int fd = -1;
    struct stat sb;
    int ret;
    flb_sds_t payload = NULL;

    fd = open(filename, O_RDONLY, 0);
    if (fd != -1) {
        if (fstat(fd, &sb) == 0) {
            payload = flb_sds_create_size(sb.st_size+1);
            if (!payload) {
                flb_errno();
            }
            else {
                ret = read(fd, payload, sb.st_size);
                if (ret != sb.st_size) {
                    flb_error("Problem reading file: %s", filename);
                }
                payload[sb.st_size] = '\0';
            }
        }
        close(fd);
    } else {
        flb_error("Unable to open test file: %s", filename);
    }

    return payload;
}

/* Callback to check expected results */
static int cb_check_result_json(void *record, size_t size, void *data)
{
    char *p;
    flb_sds_t expected;
    char *result;
    int num = get_output_num();
    const char *filename;
    char full_filename[1024];

    set_output_num(num+1);

    filename = (const char *) data;
    result = (char *) record;

    sprintf(full_filename, "%s/%s.out", IN_KUBERNETES_EVENTS_DATA_PATH, filename);
    expected = read_file(full_filename);

    p = strstr(result, expected);
    TEST_CHECK(p != NULL);

    if (p == NULL) {
        flb_error("Expected to find: '%s' in result '%s'",
                  expected, result);
    }

    flb_free(record);
    if (expected) {
        flb_sds_destroy(expected);
    }
    return 0;
}

static void cb_root(mk_request_t *request, void *data)
{
    flb_sds_t payload;
    struct test_k8s_server_ctx *server = data;
    payload = read_file(server->json_input_file);

    if (request->query_string.data && strstr(request->query_string.data, "watch=1") != NULL) {
        // NOTE/TODO: stream via watch not currently supported, this should become 200 status
        // and chunked response when we do support it
        mk_http_status(request, 500);
        mk_http_done(request);
    }
    else {
        mk_http_status(request, 200);
        mk_http_header(request, "Content-Type", 12, JSON_CONTENT_TYPE, 16);
        mk_http_send(request, payload, strlen(payload), NULL);
        mk_http_done(request);
    }

    if (payload) {
        flb_sds_destroy(payload);
    }
}

struct test_k8s_server_ctx *initialize_mock_k8s_api(const char* filename) 
{
    int vid;
    char tmp[32];
    struct test_k8s_server_ctx *server;

    server = flb_calloc(1, sizeof(struct test_k8s_server_ctx));
    if (!server) {
        flb_errno();
        return NULL;
    }

    sprintf(server->json_input_file, "%s/%s.json",
                   IN_KUBERNETES_EVENTS_DATA_PATH, filename);

    /* Create HTTP server context */
    server->ctx = mk_create();
    if (!server->ctx) {
        flb_error("[http_server] could not create context");
        flb_free(server);
        return NULL;
    }

    /* Compose listen address */
    snprintf(tmp, sizeof(tmp) -1, "%s:%d", KUBE_API_HOST, KUBE_API_PORT);
    mk_config_set(server->ctx, "Listen", tmp, NULL);
    vid = mk_vhost_create(server->ctx, NULL);
    server->vid = vid;

    /* Setup virtual host */
    mk_vhost_set(server->ctx, vid, "Name", "kubernetes-api", NULL);

    /* Root */
    mk_vhost_handler(server->ctx, vid, "/", cb_root, server);

    mk_start(server->ctx);

    return server;
}

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int o_ffd;
    struct test_ctx *ctx = NULL;
    char kube_url[512] = {0};


    ctx = flb_calloc(1, sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("flb_calloc failed");
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "3",
                    "Log_Level", "debug",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "kubernetes_events", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;

    sprintf(kube_url, "http://%s:%d", KUBE_API_HOST, KUBE_API_PORT);
    TEST_CHECK(flb_input_set(ctx->flb, i_ffd, 
              "kube_url", kube_url,
              "kube_token_file", KUBE_TOKEN_FILE,
              "kube_retention_time", "365000d",
              "tls", "off",
              "interval_sec", "1",
              "interval_nsec", "0",
              NULL) == 0);

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;

    flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    TEST_CHECK(ctx != NULL);

    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);

}

static void mock_k8s_api_destroy(struct test_k8s_server_ctx* server)
{
    TEST_CHECK(server != NULL);
    mk_stop(server->ctx);
    mk_destroy(server->ctx);
    flb_free(server);
}

void flb_test_events_v1_with_lastTimestamp()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    const char *filename = "eventlist_v1_with_lastTimestamp";

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = (void *)filename;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    struct test_k8s_server_ctx* k8s_server = initialize_mock_k8s_api(
        filename
    );

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    // waiting to flush 
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }
    mock_k8s_api_destroy(k8s_server);
    test_ctx_destroy(ctx);
}

void flb_test_events_v1_with_creationTimestamp()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    const char *filename = "eventlist_v1_with_creationTimestamp";

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = (void *)filename;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    struct test_k8s_server_ctx* k8s_server = initialize_mock_k8s_api(
        filename
    );

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    // waiting to flush 
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }
    mock_k8s_api_destroy(k8s_server);
    test_ctx_destroy(ctx);
}

TEST_LIST = {
    {"events_v1_with_lastTimestamp", flb_test_events_v1_with_lastTimestamp},
    {"events_v1_with_creationTimestamp", flb_test_events_v1_with_creationTimestamp},
    {NULL, NULL}
};

