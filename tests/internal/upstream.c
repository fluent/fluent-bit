/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_upstream.h>

#include <time.h>
#include "flb_tests_internal.h"

#define TEST_TIMEOUT               5

#define TLS_CERTIFICATE_FILENAME   FLB_TESTS_DATA_PATH "/data/tls/certificate.pem"
#define TLS_PRIVATE_KEY_FILENAME   FLB_TESTS_DATA_PATH "/data/tls/private_key.pem"

#define IPV4_PLAINTEXT_HTTP_VHOST  "google.com"
#define IPV4_PLAINTEXT_HTTP_HOST   "142.250.200.78"
#define IPV4_PLAINTEXT_HTTP_PORT   80

#define IPV4_TLS_HTTP_VHOST        "google.com"
#define IPV4_TLS_HTTP_HOST         "142.250.200.78"
#define IPV4_TLS_HTTP_PORT         443

struct test_case_context {
    char                        client_buffer[256];
    struct flb_connection      *client_connection;
    struct flb_coro            *client_coroutine;
    int                         loop_exit_flag;
    struct mk_event            *current_event;
    int                         success_flag;
    time_t                      current_time;
    time_t                      timeout_time;
    struct flb_sched_timer     *dummy_timer;
    size_t                      stack_size;
    struct flb_upstream        *upstream;
    struct flb_net_dns          dns_ctx;
    struct flb_sched           *sched;
    size_t                      loops;
    int                         flags;
    size_t                      sent;
    struct flb_tls             *tls;
    struct mk_event_loop       *evl;
    struct flb_config          *cfg;
};

struct test_case_context context;

static void dummy_timer_callback(struct flb_config *ctx, void *data)
{
    /* This is just here to periodically interrupt the event loop wait */
}

void client_coroutine_entry_point()
{
    int ret;

    context.client_connection = flb_upstream_conn_get(context.upstream);

    TEST_CHECK(context.client_connection != NULL);
    assert(context.client_connection != NULL);

    MK_EVENT_ZERO(&context.client_connection->event);

    mk_event_add(context.evl,
                 context.client_connection->fd,
                 MK_EVENT_CUSTOM,
                 MK_EVENT_READ,
                 &context.client_connection->event);

    memset(context.client_buffer, 0, sizeof(context.client_buffer));

    strncpy(context.client_buffer, "FAIL\r\n", 7);

    ret = flb_io_net_write(context.client_connection,
                           (void *) context.client_buffer,
                            strlen(context.client_buffer),
                            &context.sent);

    if (context.tls != NULL) {
        TEST_CHECK(ret == 0);
        assert(ret == 0);
    }
    else {
        TEST_CHECK(ret > 0);
        assert(ret > 0);
    }

    ret = flb_io_net_read(context.client_connection,
                          (void *) context.client_buffer,
                           sizeof(context.client_buffer));

    if (ret <= 0) {
        mk_event_del(context.evl, &context.client_connection->event);

        context.loop_exit_flag = FLB_TRUE;

        flb_coro_yield(flb_coro_get(), FLB_TRUE);
    }

    TEST_CHECK(ret > 0);

    if (strncasecmp(context.client_buffer, "HTTP", 4) == 0) {
        context.loop_exit_flag = FLB_TRUE;
        context.success_flag = FLB_TRUE;
    }

    flb_coro_yield(flb_coro_get(), FLB_TRUE);
}

static void perform_basic_async_http_test(char *host,
                                          char *vhost,
                                          unsigned short int port,
                                          int tls_flag)
{
    int ret;

    memset(&context, 0, sizeof(struct test_case_context));

    context.flags = FLB_IO_TCP;
    context.tls = NULL;

    context.cfg = flb_config_init();
    TEST_CHECK(context.cfg != NULL);
    assert(context.cfg != NULL);

    context.evl = mk_event_loop_create(8);
    TEST_CHECK(context.evl != NULL);
    assert(context.evl != NULL);
    context.cfg->evl = context.evl;

    context.sched = flb_sched_create(context.cfg, context.cfg->evl);
    TEST_CHECK(context.sched != NULL);
    assert(context.sched != NULL);

    context.cfg->sched = context.sched;

    flb_engine_evl_set(context.evl);

    flb_sched_ctx_init();
    flb_sched_ctx_set(context.sched);

    ret = flb_tls_init();
    TEST_CHECK(ret == 0);

    flb_net_lib_init();

    flb_net_ctx_init(&context.dns_ctx);
    flb_net_dns_ctx_init();
    flb_net_dns_ctx_set(&context.dns_ctx);

    if (tls_flag) {
        context.tls = flb_tls_create(FLB_FALSE,
                                     FLB_TRUE,
                                     FLB_TLS_CLIENT_MODE,
                                     vhost,
                                     NULL,
                                     NULL,
                                     TLS_CERTIFICATE_FILENAME,
                                     TLS_PRIVATE_KEY_FILENAME,
                                     NULL);

        TEST_CHECK(context.tls != NULL);
        assert(context.tls != NULL);

        context.flags |= FLB_IO_TLS;
    }

    context.upstream = flb_upstream_create(context.cfg,
                                           host,
                                           port,
                                           context.flags,
                                           context.tls);

    TEST_CHECK(context.upstream != NULL);
    assert(context.upstream != NULL);

    flb_coro_init();

    context.client_coroutine = flb_coro_create(&context);

    assert(context.client_coroutine != NULL);

    context.stack_size = 1024 * 100;

    context.client_coroutine->caller = co_active();
    context.client_coroutine->callee = co_create(context.stack_size,
                                                 client_coroutine_entry_point,
                                                &context.stack_size);

    assert(context.client_coroutine->callee != NULL);

    flb_sched_timer_cb_create(context.sched,
                              FLB_SCHED_TIMER_CB_PERM,
                              1000,
                              dummy_timer_callback,
                              NULL,
                              &context.dummy_timer);

    context.loop_exit_flag = FLB_FALSE;
    context.success_flag = FLB_FALSE;

    context.current_time = time(NULL);
    context.timeout_time = context.current_time + TEST_TIMEOUT;

    flb_coro_resume(context.client_coroutine);

    while (!context.loop_exit_flag &&
           context.timeout_time > context.current_time) {
           context.current_time = time(NULL);

        mk_event_wait(context.evl);
        mk_event_foreach(context.current_event, context.evl) {
            if (context.current_event->type & FLB_ENGINE_EV_SCHED) {
                flb_sched_event_handler(context.cfg, context.current_event);
            }
            else if (context.current_event->type == FLB_ENGINE_EV_CUSTOM) {
                context.current_event->handler(context.current_event);
            }
            else if (context.current_event->type == FLB_ENGINE_EV_THREAD) {
                struct flb_base_conn *connection;

                connection = (struct flb_base_conn *) context.current_event;

                if (connection->coroutine) {
                    flb_coro_resume(connection->coroutine);
                }
            }
            else if (context.current_event == &context.client_connection->event) {
                flb_coro_resume(context.client_coroutine);
            }
        }
    }

    TEST_CHECK(context.success_flag == FLB_TRUE);

    flb_upstream_destroy(context.upstream);

    mk_event_loop_destroy(context.evl);
}

static void perform_basic_sync_http_test(char *host,
                                         char *vhost,
                                         unsigned short int port,
                                         int tls_flag)
{
    int ret;

    memset(&context, 0, sizeof(struct test_case_context));

    context.flags = FLB_IO_TCP;

    context.cfg = flb_config_init();
    TEST_CHECK(context.cfg != NULL);
    assert(context.cfg != NULL);

    context.evl = mk_event_loop_create(8);
    TEST_CHECK(context.evl != NULL);
    assert(context.evl != NULL);
    context.cfg->evl = context.evl;

    context.sched = flb_sched_create(context.cfg, context.cfg->evl);
    TEST_CHECK(context.sched != NULL);
    assert(context.sched != NULL);

    context.cfg->sched = context.sched;

    flb_engine_evl_set(context.evl);

    flb_sched_ctx_init();
    flb_sched_ctx_set(context.sched);

    ret = flb_tls_init();
    TEST_CHECK(ret == 0);

    if (tls_flag) {
        context.tls = flb_tls_create(FLB_FALSE,
                                     FLB_TRUE,
                                     FLB_TLS_CLIENT_MODE,
                                     vhost,
                                     NULL,
                                     NULL,
                                     TLS_CERTIFICATE_FILENAME,
                                     TLS_PRIVATE_KEY_FILENAME,
                                     NULL);

        TEST_CHECK(context.tls != NULL);
        assert(context.tls != NULL);

        context.flags |= FLB_IO_TLS;
    }

    context.upstream = flb_upstream_create(context.cfg,
                                           host,
                                           port,
                                           context.flags,
                                           context.tls);

    TEST_CHECK(context.upstream != NULL);
    assert(context.upstream != NULL);

    context.upstream->flags &= ~FLB_IO_ASYNC;

    context.upstream->net.io_timeout = TEST_TIMEOUT;

    context.client_connection = flb_upstream_conn_get(context.upstream);

    TEST_CHECK(context.client_connection != NULL);
    assert(context.client_connection != NULL);

    MK_EVENT_ZERO(&context.client_connection->event);

    mk_event_add(context.evl,
                 context.client_connection->fd,
                 MK_EVENT_CUSTOM,
                 MK_EVENT_READ,
                 &context.client_connection->event);

    memset(context.client_buffer, 0, sizeof(context.client_buffer));

    strncpy(context.client_buffer, "FAIL\r\n", 7);

    ret = flb_io_net_write(context.client_connection,
                           (void *) context.client_buffer,
                            strlen(context.client_buffer),
                            &context.sent);

    if (context.tls != NULL) {
        TEST_CHECK(ret == 0);
        assert(ret == 0);
    }
    else {
        TEST_CHECK(ret > 0);
        assert(ret > 0);
    }

    context.loop_exit_flag = FLB_FALSE;
    context.success_flag = FLB_FALSE;

    context.current_time = time(NULL);
    context.timeout_time = context.current_time + TEST_TIMEOUT;

    flb_sched_timer_cb_create(context.sched,
                              FLB_SCHED_TIMER_CB_PERM,
                              1000,
                              dummy_timer_callback,
                              NULL,
                              &context.dummy_timer);

    while (!context.loop_exit_flag &&
           context.timeout_time > context.current_time) {
        context.current_time = time(NULL);

        mk_event_wait(context.evl);
        mk_event_foreach(context.current_event, context.evl) {
            if (context.current_event->type & FLB_ENGINE_EV_SCHED) {
                flb_sched_event_handler(context.cfg, context.current_event);
            }
            else if (context.current_event == &context.client_connection->event) {
                ret = flb_io_net_read(context.client_connection,
                                      (void *) context.client_buffer,
                                       sizeof(context.client_buffer));

                if (ret <= 0) {
                    mk_event_del(context.evl, &context.client_connection->event);

                    context.loop_exit_flag = FLB_TRUE;

                    break;
                }

                TEST_CHECK(ret > 0);

                if (strncasecmp(context.client_buffer, "HTTP", 4) == 0) {
                    context.loop_exit_flag = FLB_TRUE;
                    context.success_flag = FLB_TRUE;
                }
            }
        }
    }

    TEST_CHECK(context.success_flag == FLB_TRUE);

    flb_upstream_destroy(context.upstream);

    mk_event_loop_destroy(context.evl);
}

void test_ipv4_tcp_async_plaintext()
{
    perform_basic_async_http_test(IPV4_PLAINTEXT_HTTP_HOST,
                                  IPV4_PLAINTEXT_HTTP_VHOST,
                                  IPV4_PLAINTEXT_HTTP_PORT,
                                  FLB_FALSE);
}

void test_ipv4_tcp_async_tls()
{
    perform_basic_async_http_test(IPV4_TLS_HTTP_HOST,
                                  IPV4_TLS_HTTP_VHOST,
                                  IPV4_TLS_HTTP_PORT,
                                  FLB_TRUE);
}

void test_ipv4_tcp_sync_plaintext()
{
    perform_basic_sync_http_test(IPV4_PLAINTEXT_HTTP_HOST,
                                 IPV4_PLAINTEXT_HTTP_VHOST,
                                 IPV4_PLAINTEXT_HTTP_PORT,
                                 FLB_FALSE);
}

void test_ipv4_tcp_sync_tls()
{
    perform_basic_sync_http_test(IPV4_TLS_HTTP_HOST,
                                 IPV4_TLS_HTTP_VHOST,
                                 IPV4_TLS_HTTP_PORT,
                                 FLB_TRUE);
}

TEST_LIST = {
    { "ipv4_tcp_async_plaintext", test_ipv4_tcp_async_plaintext},
    { "ipv4_tcp_async_plaintext", test_ipv4_tcp_async_tls},
    { "ipv4_tcp_sync_plaintext",  test_ipv4_tcp_sync_plaintext},
    { "ipv4_tcp_sync_tls",        test_ipv4_tcp_sync_tls},
    { 0 }
};
