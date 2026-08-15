/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <inttypes.h>
#include <pthread.h>
#include <string.h>

#include "flb_tests_runtime.h"

/*
 * Long enough that the periodic flush timer cannot plausibly fire during
 * the test window, so a record only arrives if an on-demand flush actually
 * dispatched it.
 */
#define TEST_FLUSH_INTERVAL_SEC "60"
#define TEST_WAIT_TIMEOUT_MS    3000
#define TEST_HTTP_HOST          "127.0.0.1"
#define TEST_HTTP_PORT          2020
#define TEST_HTTP_PORT_STR      "2020"
#define TEST_HTTP_READY_TRIES   30
#define TEST_CONCURRENT_CLIENTS 5

/* Must exceed the endpoint's 2000ms acknowledgement timeout */
#define TEST_SLOW_OUTPUT_MS     3000
#define TEST_RECOVERY_TRIES     60

static pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
static int result_count = 0;

static int get_result_count(void)
{
    int ret;

    pthread_mutex_lock(&result_mutex);
    ret = result_count;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void reset_result_count(void)
{
    pthread_mutex_lock(&result_mutex);
    result_count = 0;
    pthread_mutex_unlock(&result_mutex);
}

static void inc_result_count(void)
{
    pthread_mutex_lock(&result_mutex);
    result_count++;
    pthread_mutex_unlock(&result_mutex);
}

static int cb_count_record(void *record, size_t size, void *data)
{
    (void) size;
    (void) data;

    inc_result_count();
    flb_free(record);
    return 0;
}

/*
 * The lib output declares no workers, so it runs as a coroutine on the engine
 * thread: stalling here stalls the whole engine, which is what lets this
 * exercise a slow output and the acknowledgement timeout.
 */
static int slow_output_armed = FLB_FALSE;

static int cb_slow_record(void *record, size_t size, void *data)
{
    (void) size;
    (void) data;

    if (slow_output_armed == FLB_TRUE) {
        slow_output_armed = FLB_FALSE;
        flb_time_msleep(TEST_SLOW_OUTPUT_MS);
    }

    inc_result_count();
    flb_free(record);
    return 0;
}

static void wait_for_result(uint32_t timeout_ms, int expected, int *count)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_ms;

    flb_time_get(&start_time);

    while (true) {
        *count = get_result_count();
        if (*count >= expected) {
            return;
        }

        flb_time_msleep(20);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_ms = flb_time_to_nanosec(&diff_time) / 1000000;

        if (elapsed_ms > timeout_ms) {
            return;
        }
    }
}

struct http_client_ctx {
    struct flb_upstream *u;
    struct flb_connection *u_conn;
    struct flb_config *config;
    struct mk_event_loop *evl;
};

static struct http_client_ctx *http_client_ctx_create(void)
{
    struct http_client_ctx *ret_ctx;
    struct mk_event_loop *evl;

    ret_ctx = flb_calloc(1, sizeof(struct http_client_ctx));
    if (ret_ctx == NULL) {
        return NULL;
    }

    evl = mk_event_loop_create(16);
    if (evl == NULL) {
        flb_free(ret_ctx);
        return NULL;
    }
    ret_ctx->evl = evl;
    flb_engine_evl_init();
    flb_engine_evl_set(evl);

    ret_ctx->config = flb_config_init();
    if (ret_ctx->config == NULL) {
        mk_event_loop_destroy(evl);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u = flb_upstream_create(ret_ctx->config, TEST_HTTP_HOST,
                                     TEST_HTTP_PORT, 0, NULL);
    if (ret_ctx->u == NULL) {
        flb_config_exit(ret_ctx->config);
        mk_event_loop_destroy(evl);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u_conn = flb_upstream_conn_get(ret_ctx->u);
    if (ret_ctx->u_conn == NULL) {
        flb_upstream_destroy(ret_ctx->u);
        flb_config_exit(ret_ctx->config);
        mk_event_loop_destroy(evl);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u_conn->upstream = ret_ctx->u;

    return ret_ctx;
}

static void http_client_ctx_destroy(struct http_client_ctx *http_ctx)
{
    flb_upstream_conn_release(http_ctx->u_conn);
    flb_upstream_destroy(http_ctx->u);
    mk_event_loop_destroy(http_ctx->evl);
    flb_config_exit(http_ctx->config);
    flb_free(http_ctx);
}

static int http_request(struct http_client_ctx *http_ctx, int method,
                        const char *uri, int *status, flb_sds_t *payload)
{
    struct flb_http_client *http_client;
    size_t b_sent;

    if (payload != NULL) {
        *payload = NULL;
    }

    http_client = flb_http_client(http_ctx->u_conn, method, uri, "", 0,
                                  TEST_HTTP_HOST, TEST_HTTP_PORT, NULL, 0);
    if (http_client == NULL) {
        return -1;
    }

    if (flb_http_do(http_client, &b_sent) != 0) {
        flb_http_client_destroy(http_client);
        return -1;
    }

    *status = http_client->resp.status;

    if (payload != NULL && http_client->resp.payload != NULL &&
        http_client->resp.payload_size > 0) {
        *payload = flb_sds_create_len(http_client->resp.payload,
                                      http_client->resp.payload_size);
    }

    flb_http_client_destroy(http_client);
    return 0;
}

static int parse_counter(const char *payload, const char *key, uint64_t *out)
{
    const char *p;

    p = strstr(payload, key);
    if (p == NULL) {
        return -1;
    }

    p = strchr(p, ':');
    if (p == NULL) {
        return -1;
    }

    if (sscanf(p + 1, "%" SCNu64, out) != 1) {
        return -1;
    }

    return 0;
}

static int read_counters(struct http_client_ctx *http_ctx, uint64_t *count,
                         uint64_t *acked)
{
    flb_sds_t payload = NULL;
    int status = 0;
    int ret = -1;

    if (http_request(http_ctx, FLB_HTTP_GET, "/api/v2/flush",
                     &status, &payload) != 0 || status != 200) {
        if (payload != NULL) {
            flb_sds_destroy(payload);
        }
        return -1;
    }

    if (payload != NULL) {
        if (parse_counter(payload, "flush_now_count", count) == 0 &&
            parse_counter(payload, "flush_now_acked", acked) == 0) {
            ret = 0;
        }
        flb_sds_destroy(payload);
    }

    return ret;
}

static flb_ctx_t *flush_test_start(int *in_ffd, struct flb_lib_out_cb *cb_data)
{
    flb_ctx_t *ctx;
    int out_ffd;

    reset_result_count();

    ctx = flb_create();
    if (ctx == NULL) {
        return NULL;
    }

    if (flb_service_set(ctx,
                        "Flush",       TEST_FLUSH_INTERVAL_SEC,
                        "Grace",       "1",
                        "Log_Level",   "error",
                        "HTTP_Server", "On",
                        "HTTP_Listen", TEST_HTTP_HOST,
                        "HTTP_Port",   TEST_HTTP_PORT_STR,
                        NULL) != 0) {
        flb_destroy(ctx);
        return NULL;
    }

    *in_ffd = flb_input(ctx, (char *) "lib", NULL);
    if (*in_ffd < 0) {
        flb_destroy(ctx);
        return NULL;
    }

    cb_data->cb = cb_count_record;
    cb_data->data = NULL;

    out_ffd = flb_output(ctx, (char *) "lib", (void *) cb_data);
    if (out_ffd < 0) {
        flb_destroy(ctx);
        return NULL;
    }

    if (flb_output_set(ctx, out_ffd, "match", "*", NULL) != 0) {
        flb_destroy(ctx);
        return NULL;
    }

    if (flb_start(ctx) != 0) {
        flb_destroy(ctx);
        return NULL;
    }

    return ctx;
}

static struct http_client_ctx *wait_for_http_server(void)
{
    struct http_client_ctx *http_ctx;
    flb_sds_t payload;
    int status;
    int i;

    for (i = 0; i < TEST_HTTP_READY_TRIES; i++) {
        http_ctx = http_client_ctx_create();
        if (http_ctx != NULL) {
            if (http_request(http_ctx, FLB_HTTP_GET, "/api/v2/flush",
                             &status, &payload) == 0 && status == 200) {
                if (payload != NULL) {
                    flb_sds_destroy(payload);
                }
                return http_ctx;
            }
            if (payload != NULL) {
                flb_sds_destroy(payload);
            }
            http_client_ctx_destroy(http_ctx);
        }
        flb_time_msleep(100);
    }

    return NULL;
}

/*
 * flb_engine_flush_request() must dispatch a buffered record immediately,
 * without waiting for the (deliberately very long) periodic flush timer.
 */
void flb_test_flush_now_dispatches_immediately(void)
{
    flb_ctx_t *ctx;
    struct flb_lib_out_cb cb_data;
    int in_ffd;
    int out_ffd;
    int ret;
    int count = 0;
    char *input_json = "[1, {\"msg\": \"flush now test\"}]";

    reset_result_count();

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    TEST_CHECK(flb_service_set(ctx,
                               "Flush",     TEST_FLUSH_INTERVAL_SEC,
                               "Grace",     "1",
                               "Log_Level", "error",
                               NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    cb_data.cb = cb_count_record;
    cb_data.data = NULL;

    out_ffd = flb_output(ctx, (char *) "lib", (void *) &cb_data);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd, "match", "*", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    ret = flb_lib_push(ctx, in_ffd, input_json, strlen(input_json));
    TEST_CHECK_(ret >= 0, "pushing record");

    TEST_CHECK(flb_engine_flush_request(ctx->config, FLB_FALSE) >= 0);

    wait_for_result(TEST_WAIT_TIMEOUT_MS, 1, &count);
    TEST_CHECK_(count > 0,
               "expected the record to arrive within %dms via on-demand "
               "flush (flush interval is %ss); got count=%d",
               TEST_WAIT_TIMEOUT_MS, TEST_FLUSH_INTERVAL_SEC, count);

    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * POST /api/v2/flush must dispatch every buffered chunk and report the
 * request as dispatched.
 */
void flb_test_flush_now_http_dispatches(void)
{
    flb_ctx_t *ctx;
    struct flb_lib_out_cb cb_data;
    struct http_client_ctx *http_ctx;
    flb_sds_t payload = NULL;
    int in_ffd = -1;
    int status = 0;
    int count = 0;
    int i;
    uint64_t acked = 0;
    uint64_t ticket = 0;
    char input_json[64];

    ctx = flush_test_start(&in_ffd, &cb_data);
    TEST_CHECK_(ctx != NULL, "starting engine with HTTP server");
    if (ctx == NULL) {
        return;
    }

    http_ctx = wait_for_http_server();
    TEST_CHECK_(http_ctx != NULL, "HTTP server did not become ready");
    if (http_ctx == NULL) {
        flb_stop(ctx);
        flb_destroy(ctx);
        return;
    }

    for (i = 0; i < 4; i++) {
        snprintf(input_json, sizeof(input_json) - 1,
                 "[1, {\"msg\": \"chunk %d\"}]", i);
        TEST_CHECK(flb_lib_push(ctx, in_ffd, input_json,
                                strlen(input_json)) >= 0);
    }

    TEST_CHECK(http_request(http_ctx, FLB_HTTP_POST, "/api/v2/flush",
                            &status, &payload) == 0);
    TEST_CHECK_(status == 200, "expected 200, got %d", status);
    TEST_CHECK(payload != NULL);

    if (payload != NULL) {
        TEST_CHECK_(strstr(payload, "dispatched") != NULL,
                    "expected a dispatched response, got: %s", payload);
        TEST_CHECK(parse_counter(payload, "flush_now_ticket", &ticket) == 0);
        TEST_CHECK_(ticket == 1, "expected ticket 1, got %" PRIu64, ticket);
        TEST_CHECK(parse_counter(payload, "flush_now_acked", &acked) == 0);
        TEST_CHECK_(acked >= ticket,
                    "acked (%" PRIu64 ") must cover the ticket (%" PRIu64 ")",
                    acked, ticket);
        flb_sds_destroy(payload);
    }

    wait_for_result(TEST_WAIT_TIMEOUT_MS, 4, &count);
    TEST_CHECK_(count >= 4,
                "expected 4 records dispatched via HTTP flush, got %d", count);

    http_client_ctx_destroy(http_ctx);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* GET must report the counters without triggering a flush. */
void flb_test_flush_now_http_get_status(void)
{
    flb_ctx_t *ctx;
    struct flb_lib_out_cb cb_data;
    struct http_client_ctx *http_ctx;
    flb_sds_t payload = NULL;
    int in_ffd = -1;
    int status = 0;
    int count = 0;
    uint64_t requested = 0;
    char *input_json = "[1, {\"msg\": \"not flushed\"}]";

    ctx = flush_test_start(&in_ffd, &cb_data);
    TEST_CHECK_(ctx != NULL, "starting engine with HTTP server");
    if (ctx == NULL) {
        return;
    }

    http_ctx = wait_for_http_server();
    TEST_CHECK_(http_ctx != NULL, "HTTP server did not become ready");
    if (http_ctx == NULL) {
        flb_stop(ctx);
        flb_destroy(ctx);
        return;
    }

    TEST_CHECK(flb_lib_push(ctx, in_ffd, input_json,
                            strlen(input_json)) >= 0);

    TEST_CHECK(http_request(http_ctx, FLB_HTTP_GET, "/api/v2/flush",
                            &status, &payload) == 0);
    TEST_CHECK_(status == 200, "expected 200, got %d", status);
    TEST_CHECK(payload != NULL);

    if (payload != NULL) {
        TEST_CHECK(parse_counter(payload, "flush_now_count", &requested) == 0);
        TEST_CHECK_(requested == 0,
                    "GET must not request a flush, got flush_now_count=%"
                    PRIu64, requested);
        TEST_CHECK(strstr(payload, "flush_now_acked") != NULL);
        flb_sds_destroy(payload);
    }

    flb_time_msleep(300);
    count = get_result_count();
    TEST_CHECK_(count == 0,
                "GET must not dispatch records, got %d", count);

    http_client_ctx_destroy(http_ctx);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Unsupported methods must be rejected. */
void flb_test_flush_now_http_method_not_allowed(void)
{
    flb_ctx_t *ctx;
    struct flb_lib_out_cb cb_data;
    struct http_client_ctx *http_ctx;
    int in_ffd = -1;
    int status = 0;

    ctx = flush_test_start(&in_ffd, &cb_data);
    TEST_CHECK_(ctx != NULL, "starting engine with HTTP server");
    if (ctx == NULL) {
        return;
    }

    http_ctx = wait_for_http_server();
    TEST_CHECK_(http_ctx != NULL, "HTTP server did not become ready");
    if (http_ctx == NULL) {
        flb_stop(ctx);
        flb_destroy(ctx);
        return;
    }

    TEST_CHECK(http_request(http_ctx, FLB_HTTP_DELETE, "/api/v2/flush",
                            &status, NULL) == 0);
    TEST_CHECK_(status == 405, "expected 405, got %d", status);

    http_client_ctx_destroy(http_ctx);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* The retry rescheduling opt-in must be accepted. */
void flb_test_flush_now_http_reschedule_retries(void)
{
    flb_ctx_t *ctx;
    struct flb_lib_out_cb cb_data;
    struct http_client_ctx *http_ctx;
    flb_sds_t payload = NULL;
    int in_ffd = -1;
    int status = 0;
    int count = 0;
    char *input_json = "[1, {\"msg\": \"retry opt-in\"}]";

    ctx = flush_test_start(&in_ffd, &cb_data);
    TEST_CHECK_(ctx != NULL, "starting engine with HTTP server");
    if (ctx == NULL) {
        return;
    }

    http_ctx = wait_for_http_server();
    TEST_CHECK_(http_ctx != NULL, "HTTP server did not become ready");
    if (http_ctx == NULL) {
        flb_stop(ctx);
        flb_destroy(ctx);
        return;
    }

    TEST_CHECK(flb_lib_push(ctx, in_ffd, input_json,
                            strlen(input_json)) >= 0);

    TEST_CHECK(http_request(http_ctx, FLB_HTTP_POST,
                            "/api/v2/flush?reschedule_retries=true",
                            &status, &payload) == 0);
    TEST_CHECK_(status == 200, "expected 200, got %d", status);

    if (payload != NULL) {
        TEST_CHECK(strstr(payload, "dispatched") != NULL);
        flb_sds_destroy(payload);
    }

    wait_for_result(TEST_WAIT_TIMEOUT_MS, 1, &count);
    TEST_CHECK_(count >= 1, "expected the record to be dispatched, got %d",
                count);

    http_client_ctx_destroy(http_ctx);
    flb_stop(ctx);
    flb_destroy(ctx);
}

struct concurrent_worker {
    pthread_t thread;
    struct http_client_ctx *http_ctx;
    int status;
    int dispatched;
    uint64_t ticket;
    uint64_t acked;
};

static void *concurrent_flush_worker(void *arg)
{
    struct concurrent_worker *worker = (struct concurrent_worker *) arg;
    flb_sds_t payload = NULL;

    flb_engine_evl_init();
    flb_engine_evl_set(worker->http_ctx->evl);

    if (http_request(worker->http_ctx, FLB_HTTP_POST, "/api/v2/flush",
                     &worker->status, &payload) == 0) {
        if (worker->status == 200 && payload != NULL &&
            strstr(payload, "dispatched") != NULL) {
            worker->dispatched = FLB_TRUE;
            parse_counter(payload, "flush_now_ticket", &worker->ticket);
            parse_counter(payload, "flush_now_acked", &worker->acked);
        }
    }

    if (payload != NULL) {
        flb_sds_destroy(payload);
    }

    return NULL;
}

/*
 * Concurrent requests must each be acknowledged by a flush that started
 * after they were issued, never by one another.
 */
void flb_test_flush_now_http_concurrent(void)
{
    flb_ctx_t *ctx;
    struct flb_lib_out_cb cb_data;
    struct http_client_ctx *status_ctx;
    struct concurrent_worker workers[TEST_CONCURRENT_CLIENTS];
    flb_sds_t payload = NULL;
    int in_ffd = -1;
    int status = 0;
    int started = 0;
    int i;
    int j;
    uint64_t requested = 0;
    uint64_t acked = 0;
    char *input_json = "[1, {\"msg\": \"concurrent\"}]";

    ctx = flush_test_start(&in_ffd, &cb_data);
    TEST_CHECK_(ctx != NULL, "starting engine with HTTP server");
    if (ctx == NULL) {
        return;
    }

    status_ctx = wait_for_http_server();
    TEST_CHECK_(status_ctx != NULL, "HTTP server did not become ready");
    if (status_ctx == NULL) {
        flb_stop(ctx);
        flb_destroy(ctx);
        return;
    }

    TEST_CHECK(flb_lib_push(ctx, in_ffd, input_json,
                            strlen(input_json)) >= 0);

    for (i = 0; i < TEST_CONCURRENT_CLIENTS; i++) {
        workers[i].status = 0;
        workers[i].dispatched = FLB_FALSE;
        workers[i].ticket = 0;
        workers[i].acked = 0;
        workers[i].http_ctx = http_client_ctx_create();
        TEST_CHECK(workers[i].http_ctx != NULL);
        if (workers[i].http_ctx == NULL) {
            break;
        }
        if (pthread_create(&workers[i].thread, NULL,
                           concurrent_flush_worker, &workers[i]) != 0) {
            http_client_ctx_destroy(workers[i].http_ctx);
            workers[i].http_ctx = NULL;
            break;
        }
        started++;
    }

    TEST_CHECK_(started == TEST_CONCURRENT_CLIENTS,
                "expected %d workers, started %d", TEST_CONCURRENT_CLIENTS,
                started);

    for (i = 0; i < started; i++) {
        pthread_join(workers[i].thread, NULL);
    }

    for (i = 0; i < started; i++) {
        TEST_CHECK_(workers[i].status == 200,
                    "worker %d expected 200, got %d", i, workers[i].status);
        TEST_CHECK_(workers[i].dispatched == FLB_TRUE,
                    "worker %d was not acknowledged as dispatched", i);
        TEST_CHECK_(workers[i].ticket >= 1 &&
                    workers[i].ticket <= (uint64_t) started,
                    "worker %d got out of range ticket %" PRIu64,
                    i, workers[i].ticket);
        TEST_CHECK_(workers[i].acked >= workers[i].ticket,
                    "worker %d acked (%" PRIu64 ") must cover its own ticket "
                    "(%" PRIu64 ")", i, workers[i].acked, workers[i].ticket);

        for (j = 0; j < i; j++) {
            TEST_CHECK_(workers[i].ticket != workers[j].ticket,
                        "workers %d and %d share ticket %" PRIu64,
                        i, j, workers[i].ticket);
        }
    }

    for (i = 0; i < started; i++) {
        http_client_ctx_destroy(workers[i].http_ctx);
    }

    flb_engine_evl_init();
    flb_engine_evl_set(status_ctx->evl);

    TEST_CHECK(http_request(status_ctx, FLB_HTTP_GET, "/api/v2/flush",
                            &status, &payload) == 0);
    TEST_CHECK_(status == 200, "expected 200, got %d", status);

    if (payload != NULL) {
        TEST_CHECK(parse_counter(payload, "flush_now_count", &requested) == 0);
        TEST_CHECK(parse_counter(payload, "flush_now_acked", &acked) == 0);

        TEST_CHECK_(requested == (uint64_t) started,
                    "expected %d requests recorded, got %" PRIu64,
                    started, requested);
        TEST_CHECK_(acked >= (uint64_t) started,
                    "every acknowledged request must be covered by a flush: "
                    "acked=%" PRIu64 " started=%d", acked, started);
        flb_sds_destroy(payload);
    }

    http_client_ctx_destroy(status_ctx);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/*
 * A slow output stalls the engine past the acknowledgement timeout, so the
 * request must report a timeout rather than block forever. The flush still
 * completes afterwards, and the caller can discover that by polling until
 * flush_now_acked catches up with the ticket it was given.
 */
void flb_test_flush_now_http_slow_output_timeout(void)
{
    flb_ctx_t *ctx;
    struct flb_lib_out_cb cb_data;
    struct http_client_ctx *http_ctx;
    flb_sds_t payload = NULL;
    int in_ffd;
    int out_ffd;
    int status = 0;
    int count = 0;
    int i;
    uint64_t ticket = 0;
    uint64_t acked = 0;
    uint64_t requested = 0;
    char *input_json = "[1, {\"msg\": \"slow output\"}]";

    reset_result_count();
    slow_output_armed = FLB_TRUE;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }

    TEST_CHECK(flb_service_set(ctx,
                               "Flush",       TEST_FLUSH_INTERVAL_SEC,
                               "Grace",       "1",
                               "Log_Level",   "error",
                               "HTTP_Server", "On",
                               "HTTP_Listen", TEST_HTTP_HOST,
                               "HTTP_Port",   TEST_HTTP_PORT_STR,
                               NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);

    cb_data.cb = cb_slow_record;
    cb_data.data = NULL;

    out_ffd = flb_output(ctx, (char *) "lib", (void *) &cb_data);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd, "match", "*", NULL) == 0);

    TEST_CHECK(flb_start(ctx) == 0);

    http_ctx = wait_for_http_server();
    TEST_CHECK_(http_ctx != NULL, "HTTP server did not become ready");
    if (http_ctx == NULL) {
        slow_output_armed = FLB_FALSE;
        flb_stop(ctx);
        flb_destroy(ctx);
        return;
    }

    TEST_CHECK(flb_lib_push(ctx, in_ffd, input_json,
                            strlen(input_json)) >= 0);

    /*
     * The first flush only dispatches: it returns before the output
     * coroutine runs, which is the dispatch/delivery distinction.
     */
    TEST_CHECK(http_request(http_ctx, FLB_HTTP_POST, "/api/v2/flush",
                            &status, &payload) == 0);
    TEST_CHECK_(status == 200, "dispatch must not wait on the output, got %d",
                status);
    if (payload != NULL) {
        flb_sds_destroy(payload);
        payload = NULL;
    }

    /*
     * The output is now stalling the engine thread, so this request cannot
     * be acknowledged in time and must report a timeout.
     */
    TEST_CHECK(http_request(http_ctx, FLB_HTTP_POST, "/api/v2/flush",
                            &status, &payload) == 0);

    TEST_CHECK_(status == 503,
                "a stalled engine must report a timeout, got %d", status);

    if (payload != NULL) {
        TEST_CHECK_(strstr(payload, "timeout") != NULL,
                    "expected a timeout response, got: %s", payload);
        TEST_CHECK(parse_counter(payload, "flush_now_ticket", &ticket) == 0);
        TEST_CHECK_(ticket >= 1, "a timed out request still owns a ticket");
        flb_sds_destroy(payload);
        payload = NULL;
    }

    /*
     * The request was not cancelled: once the engine is free the flush
     * completes and the caller can observe it through its ticket.
     */
    for (i = 0; i < TEST_RECOVERY_TRIES; i++) {
        if (read_counters(http_ctx, &requested, &acked) == 0 &&
            acked >= ticket) {
            break;
        }
        flb_time_msleep(100);
    }

    TEST_CHECK_(acked >= ticket,
                "the timed out flush must still complete: acked=%" PRIu64
                " ticket=%" PRIu64, acked, ticket);

    wait_for_result(TEST_SLOW_OUTPUT_MS + TEST_WAIT_TIMEOUT_MS, 1, &count);
    TEST_CHECK_(count >= 1,
                "the record must survive a slow output, got %d", count);

    /* The engine recovered, so a new request succeeds normally */
    TEST_CHECK(http_request(http_ctx, FLB_HTTP_POST, "/api/v2/flush",
                            &status, &payload) == 0);
    TEST_CHECK_(status == 200, "engine must recover, got %d", status);

    if (payload != NULL) {
        TEST_CHECK(strstr(payload, "dispatched") != NULL);
        flb_sds_destroy(payload);
    }

    slow_output_armed = FLB_FALSE;
    http_client_ctx_destroy(http_ctx);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"flush_now_dispatches_immediately", flb_test_flush_now_dispatches_immediately},
    {"flush_now_http_dispatches", flb_test_flush_now_http_dispatches},
    {"flush_now_http_get_status", flb_test_flush_now_http_get_status},
    {"flush_now_http_method_not_allowed", flb_test_flush_now_http_method_not_allowed},
    {"flush_now_http_reschedule_retries", flb_test_flush_now_http_reschedule_retries},
    {"flush_now_http_concurrent", flb_test_flush_now_http_concurrent},
    {"flush_now_http_slow_output_timeout", flb_test_flush_now_http_slow_output_timeout},
    {NULL, NULL}
};
