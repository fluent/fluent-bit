/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_thread_pool.h>

#include <time.h>
#include "flb_tests_internal.h"

#define TLS_CERTIFICATE_HOSTNAME "leo.vcap.me"
#define TLS_CERTIFICATE_FILENAME FLB_TESTS_DATA_PATH "/data/tls/certificate.pem"
#define TLS_PRIVATE_KEY_FILENAME FLB_TESTS_DATA_PATH "/data/tls/private_key.pem"

#define TEST_TIMEOUT             5
#define TEST_VHOST               TLS_CERTIFICATE_HOSTNAME
#define TEST_HOSTv4              "127.0.0.1"
#define TEST_HOSTv6              "::1"
#define TEST_PORT                "41322"

#define TEST_EV_CLIENT           MK_EVENT_NOTIFICATION
#define TEST_EV_SERVER           MK_EVENT_CUSTOM

struct test_case_context {
    struct flb_connection      *cs_client_connection;
    struct flb_connection      *ss_client_connection;
    int                         client_finished_flag;
    int                         client_success_flag;
    int                         server_success_flag;
    char                        server_buffer[256];
    char                        client_buffer[256];
    int                         client_start_flag;
    struct flb_coro            *client_coroutine;
    int                         loop_exit_flag;
    struct mk_event            *current_event;
    struct flb_tp_thread       *client_thread;
    time_t                      current_time;
    time_t                      timeout_time;
    struct flb_sched_timer     *dummy_timer;
    struct flb_tp              *thread_pool;
    size_t                      stack_size;
    struct flb_downstream      *downstream;
    int                         tls_flag;
    struct flb_upstream        *upstream;
    struct flb_net_dns          dns_ctx;
    struct flb_sched           *sched;
    size_t                      loops;
    int                         flags;
    char                       *vhost;
    char                       *host;
    char                       *port;
    size_t                      sent;
    // struct flb_tls             *tls;
    struct mk_event_loop       *evl;
    struct flb_config          *cfg;
};

struct test_case_context context;

static void dummy_timer_callback(struct flb_config *ctx, void *data)
{
    /* This is just here to periodically interrupt the event loop wait */
}

static int flb_log_start(struct flb_config *config)
{
    int type;
    int level;

    /* Log Level */
    if (config->verbose != FLB_LOG_INFO) {
        level = config->verbose;
    }
    else {
        level = FLB_LOG_INFO;
    }

    /* Destination based on type */
    if (config->log_file) {
        type = FLB_LOG_FILE;
    }
    else {
        type = FLB_LOG_STDERR;
    }

    if (flb_log_create(config, type, level, config->log_file) == NULL) {
        return -1;
    }

    return 0;
}

void client_thread_entry_point(void *arg) {
    unsigned short int port;
    struct flb_tls    *tls;
    int                ret;

    context.client_finished_flag = FLB_FALSE;

    while (!context.client_start_flag) {
        flb_time_msleep(500);
    }

    if (context.tls_flag) {
        tls = flb_tls_create(FLB_FALSE,
                             FLB_TRUE,
                             FLB_TLS_CLIENT_MODE,
                             context.vhost,
                             NULL,
                             NULL,
                             NULL,
                             NULL,
                             NULL);

        TEST_CHECK(tls != NULL);
        assert(tls != NULL);
    }
    else {
        tls = NULL;
    }

    port = (unsigned short int) strtoul(context.port, NULL, 10);

    context.upstream = flb_upstream_create(context.cfg,
                                           context.host,
                                           port,
                                           context.flags,
                                           tls);

    TEST_CHECK(context.upstream != NULL);
    assert(context.upstream != NULL);

    context.upstream->flags &= ~FLB_IO_ASYNC;

    context.upstream->net.io_timeout = TEST_TIMEOUT;

    context.cs_client_connection = flb_upstream_conn_get(context.upstream);

    TEST_CHECK(context.cs_client_connection != NULL);
    assert(context.cs_client_connection != NULL);

    MK_EVENT_ZERO(&context.cs_client_connection->event);

    memset(context.client_buffer, 0, sizeof(context.client_buffer));

    strncpy(context.client_buffer, "HELLO", 6);

    ret = flb_io_net_write(context.cs_client_connection,
                           (void *) context.client_buffer,
                            strlen(context.client_buffer),
                            &context.sent);

    if (tls != NULL) {
        TEST_CHECK(ret == 0);
    }
    else {
        TEST_CHECK(ret > 0);
    }

    ret = flb_io_net_read(context.cs_client_connection,
                          (void *) context.client_buffer,
                           sizeof(context.client_buffer));

    TEST_CHECK(ret > 0);

    if (ret > 0) {
        if (strncasecmp(context.client_buffer, "GOODBYE", 7) == 0) {
            context.client_success_flag = FLB_TRUE;
        }
    }

    context.loop_exit_flag = FLB_TRUE;
    context.client_finished_flag = FLB_TRUE;
}

static void perform_basic_sync_test(char *host,
                                    char *vhost,
                                    char *port,
                                    int tls_flag)
{
    struct flb_tls *tls;
    int             ret;

    memset(&context, 0, sizeof(struct test_case_context));

    context.client_start_flag = FLB_FALSE;
    context.tls_flag = tls_flag;

    context.vhost = vhost;
    context.host  = host;
    context.port  = port;

    context.flags = FLB_IO_TCP;

    context.cfg = flb_config_init();
    TEST_CHECK(context.cfg != NULL);
    assert(context.cfg != NULL);

    context.evl = mk_event_loop_create(8);
    TEST_CHECK(context.evl != NULL);
    assert(context.evl != NULL);
    context.cfg->evl = context.evl;

    ret = flb_log_start(context.cfg);
    TEST_CHECK(ret == 0);
    assert(ret == 0);

    context.sched = flb_sched_create(context.cfg, context.cfg->evl);
    TEST_CHECK(context.sched != NULL);
    assert(context.sched != NULL);

    context.cfg->sched = context.sched;

    flb_engine_evl_set(context.evl);

    flb_sched_ctx_init();
    flb_sched_ctx_set(context.sched);

    context.thread_pool = flb_tp_create(context.cfg);
    TEST_CHECK(context.thread_pool != NULL);
    assert(context.thread_pool != NULL);

    ret = flb_tls_init();
    TEST_CHECK(ret == 0);

    if (context.tls_flag) {
        tls = flb_tls_create(FLB_FALSE,
                             FLB_TRUE,
                             FLB_TLS_SERVER_MODE,
                             context.vhost,
                             NULL,
                             NULL,
                             TLS_CERTIFICATE_FILENAME,
                             TLS_PRIVATE_KEY_FILENAME,
                             NULL);

        TEST_CHECK(tls != NULL);
        assert(tls != NULL);

        context.flags |= FLB_IO_TLS;
    }

    context.client_thread = flb_tp_thread_create(context.thread_pool,
                                                 client_thread_entry_point,
                                                 NULL,
                                                 context.cfg);

    TEST_CHECK(context.client_thread != NULL);
    assert(context.client_thread != NULL);

    flb_tp_thread_start(context.thread_pool, context.client_thread);

    context.downstream = flb_downstream_create(context.cfg,
                                               context.host,
                                               context.port,
                                               context.flags,
                                               tls);
    TEST_CHECK(context.downstream != NULL);
    assert(context.downstream != NULL);

    MK_EVENT_ZERO(&context.downstream->event);

    ret = mk_event_add(context.evl,
                       context.downstream->server_fd,
                       MK_EVENT_CUSTOM,
                       MK_EVENT_READ,
                       &context.downstream->event);

    flb_sched_timer_cb_create(context.sched,
                              FLB_SCHED_TIMER_CB_PERM,
                              1000,
                              dummy_timer_callback,
                              NULL,
                              &context.dummy_timer);

    context.client_success_flag = FLB_FALSE;
    context.server_success_flag = FLB_FALSE;
    context.loop_exit_flag = FLB_FALSE;

    context.current_time = time(NULL);
    context.timeout_time = context.current_time + TEST_TIMEOUT;

    context.client_start_flag = FLB_TRUE;

    while (!context.loop_exit_flag &&
           context.timeout_time > context.current_time) {
        context.current_time = time(NULL);

        mk_event_wait(context.evl);
        mk_event_foreach(context.current_event, context.evl) {
            if (context.current_event->type & FLB_ENGINE_EV_SCHED) {
                flb_sched_event_handler(context.cfg, context.current_event);
            }
            else if (context.current_event == &context.downstream->event) {
                context.ss_client_connection = flb_downstream_conn_get(context.downstream);
                TEST_CHECK(context.ss_client_connection != NULL);

                if (ret == 0) {
                    MK_EVENT_NEW(&context.ss_client_connection->event);

                    ret = mk_event_add(context.evl,
                                       context.ss_client_connection->fd,
                                       MK_EVENT_CUSTOM,
                                       MK_EVENT_READ,
                                       &context.ss_client_connection->event);
                }
            }
            else if (context.current_event == &context.ss_client_connection->event) {
                ret = flb_io_net_read(context.ss_client_connection,
                                      (void *) context.client_buffer,
                                      sizeof(context.client_buffer));

                if (ret <= 0) {
                    mk_event_del(context.evl, &context.ss_client_connection->event);

                    context.ss_client_connection = NULL;

                    break;
                }

                TEST_CHECK(ret > 0);

                if (ret > 0) {
                    if (strncasecmp(context.client_buffer, "HELLO", 5) == 0) {
                        // context.loop_exit_flag = FLB_TRUE;
                        context.server_success_flag = FLB_TRUE;

                        memset(context.server_buffer, 0, sizeof(context.server_buffer));

                        strncpy(context.server_buffer, "GOODBYE", 8);

                        ret = flb_io_net_write(context.ss_client_connection,
                                               (void *) context.server_buffer,
                                               strlen(context.server_buffer),
                                               &context.sent);

                        if (tls != NULL) {
                            TEST_CHECK(ret == 0);
                        }
                        else {
                            TEST_CHECK(ret > 0);
                        }

                    }
                }
            }
        }
    }

    flb_tp_thread_stop_all(context.thread_pool);

    flb_tp_destroy(context.thread_pool);

    flb_downstream_destroy(context.downstream);

    flb_tls_destroy(tls);

    mk_event_loop_destroy(context.evl);

    context.current_time = time(NULL);
    context.timeout_time = context.current_time + TEST_TIMEOUT;

    while (!context.client_finished_flag &&
           context.timeout_time > context.current_time) {
        flb_time_msleep(500);
    }

    TEST_CHECK(context.server_success_flag &&
               context.client_success_flag);
}

void test_ipv4_tls_server()
{
    perform_basic_sync_test(TEST_HOSTv4,
                            TEST_VHOST,
                            TEST_PORT,
                            FLB_TRUE);
}

void test_ipv6_tls_server()
{
    // test_tls_server(FLB_TRUE);
}

TEST_LIST = {
    { "ipv4_tls_server", test_ipv4_tls_server},
    // { "ipv6_tls_server", test_ipv6_tls_server},
    { 0 }
};
