/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_conn.h>
#include <fluent-bit/flb_connection.h>
#include <fluent-bit/flb_engine_macros.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/tls/flb_tls.h>

#include "flb_tests_internal.h"

#ifdef FLB_HAVE_TLS

#ifdef FLB_SYSTEM_WINDOWS
#include <fluent-bit/flb_compat.h>
#endif

struct test_backend_ctx {
    int invalidate_calls;
    int destroy_calls;
};

static int test_event_handler(void *data)
{
    (void) data;

    return 0;
}

static int test_net_read_want_write(struct flb_tls_session *session,
                                    void *buffer, size_t length)
{
    (void) session;
    (void) buffer;
    (void) length;

    return FLB_TLS_WANT_WRITE;
}

static void test_session_invalidate(void *session)
{
    struct test_backend_ctx *ctx = session;

    if (ctx != NULL) {
        ctx->invalidate_calls++;
    }
}

static int test_session_destroy(void *session)
{
    struct test_backend_ctx *ctx = session;

    if (ctx != NULL) {
        ctx->destroy_calls++;
    }

    return 0;
}

static int setup_conn(struct flb_connection *conn,
                      struct flb_upstream *upstream,
                      struct flb_config *config,
                      flb_pipefd_t *socket_pair)
{
    if (flb_pipe_create(socket_pair) != 0) {
        return -1;
    }

    config->is_shutting_down    = FLB_FALSE;
    upstream->base.config       = config;
    upstream->base.net.keepalive = FLB_FALSE;
    upstream->tcp_host          = "example";
    upstream->tcp_port          = 443;
    flb_upstream_queue_init(&upstream->queue);

    conn->fd          = socket_pair[0];
    conn->event.fd    = conn->fd;
    conn->event.status = 0;
    conn->stream      = (struct flb_stream *) upstream;
    conn->net         = &upstream->base.net;
    conn->net_error   = 0;

    mk_list_init(&conn->_head);
    mk_list_add(&conn->_head, &upstream->queue.busy_queue);

    return 0;
}

void test_prepare_destroy_conn_marks_tls_session_stale(void)
{
    struct test_backend_ctx backend_session = {0};
    struct flb_tls_backend backend_api = {0};
    struct flb_tls tls_context = {0};
    struct flb_tls_session tls_session = {0};
    struct flb_connection conn = {0};
    struct flb_upstream upstream = {0};
    struct flb_config config = {0};
    flb_pipefd_t socket_pair[2];

#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    TEST_CHECK(setup_conn(&conn, &upstream, &config, socket_pair) == 0);

    backend_api.session_invalidate = test_session_invalidate;
    tls_context.api = &backend_api;
    tls_session.ptr = &backend_session;
    tls_session.tls = &tls_context;
    tls_session.connection = &conn;
    conn.tls_session = &tls_session;

    TEST_CHECK(flb_upstream_conn_release(&conn) == 0);

    TEST_CHECK(backend_session.invalidate_calls == 1);
    TEST_CHECK(conn.fd == -1);
    TEST_CHECK(conn.event.fd == -1);
    TEST_CHECK(mk_list_size(&upstream.queue.destroy_queue) == 1);
    TEST_CHECK(conn.shutdown_flag == FLB_TRUE);

    flb_pipe_close(socket_pair[1]);

#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

void test_tls_session_destroy_no_double_free(void)
{
    struct test_backend_ctx backend_session = {0};
    struct flb_tls_backend backend_api = {0};
    struct flb_tls tls_context = {0};
    struct flb_tls_session *tls_session;
    struct flb_connection *conn;
    struct flb_upstream upstream = {0};
    struct flb_config config = {0};
    flb_pipefd_t socket_pair[2];

#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    /* heap-allocate conn to match production; pending_destroy calls flb_free on it */
    conn = flb_calloc(1, sizeof(struct flb_connection));
    TEST_CHECK(conn != NULL);
    conn->dynamically_allocated = FLB_TRUE;
    TEST_CHECK(setup_conn(conn, &upstream, &config, socket_pair) == 0);

    backend_api.session_invalidate = test_session_invalidate;
    backend_api.session_destroy    = test_session_destroy;
    tls_context.api = &backend_api;

    /* heap-allocated to match production; flb_tls_session_destroy calls flb_free */
    tls_session = flb_calloc(1, sizeof(struct flb_tls_session));
    TEST_CHECK(tls_session != NULL);
    tls_session->ptr        = &backend_session;
    tls_session->tls        = &tls_context;
    tls_session->connection = conn;
    conn->tls_session       = tls_session;

    /* explicit destroy before release — the fix */
    TEST_CHECK(flb_tls_session_destroy(tls_session) == 0);
    TEST_CHECK(conn->tls_session == NULL);

    TEST_CHECK(flb_upstream_conn_release(conn) == 0);

    /* pending_destroy must not double-free the already-destroyed session */
    TEST_CHECK(flb_upstream_conn_pending_destroy(&upstream) == 0);
    TEST_CHECK(backend_session.destroy_calls == 1);

    flb_pipe_close(socket_pair[1]);

#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

void test_tls_read_retry_preserves_custom_event(void)
{
    int ret;
    char buffer[1];
    flb_pipefd_t socket_pair[2];
    struct mk_event_loop *event_loop;
    struct flb_tls_backend backend_api = {0};
    struct flb_tls tls_context = {0};
    struct flb_tls_session tls_session = {0};
    struct flb_connection connection = {0};
    struct flb_net_setup net_setup = {0};

#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    TEST_CHECK(flb_pipe_create(socket_pair) == 0);

    event_loop = mk_event_loop_create(8);
    TEST_CHECK(event_loop != NULL);

    MK_EVENT_NEW(&connection.event);
    connection.fd = socket_pair[0];
    connection.evl = event_loop;
    connection.type = FLB_DOWNSTREAM_CONNECTION;
    connection.net = &net_setup;
    connection.event.handler = test_event_handler;

    ret = mk_event_add(event_loop,
                       connection.fd,
                       FLB_ENGINE_EV_CUSTOM,
                       MK_EVENT_READ,
                       &connection.event);
    TEST_CHECK(ret == 0);

    backend_api.net_read = test_net_read_want_write;
    tls_context.api = &backend_api;
    tls_session.tls = &tls_context;
    tls_session.connection = &connection;

    ret = flb_tls_net_read(&tls_session, buffer, sizeof(buffer));
    TEST_CHECK(ret == FLB_TLS_WANT_WRITE);
    TEST_CHECK(connection.event.type == FLB_ENGINE_EV_CUSTOM);
    TEST_CHECK(connection.event.handler == test_event_handler);
    TEST_CHECK(connection.event.mask == (MK_EVENT_READ | MK_EVENT_WRITE));

    TEST_CHECK(mk_event_del(event_loop, &connection.event) == 0);
    mk_event_loop_destroy(event_loop);
    flb_pipe_close(socket_pair[0]);
    flb_pipe_close(socket_pair[1]);

#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

#endif

TEST_LIST = {
#ifdef FLB_HAVE_TLS
    {"prepare_destroy_conn_marks_tls_session_stale", test_prepare_destroy_conn_marks_tls_session_stale},
    {"tls_session_destroy_no_double_free", test_tls_session_destroy_no_double_free},
    {"tls_read_retry_preserves_custom_event", test_tls_read_retry_preserves_custom_event},
#endif
    {0}
};
