/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_http_common.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/http_server/flb_http_server.h>
#include <fluent-bit/http_server/flb_http_server_config_map.h>

#include <string.h>

#include "flb_tests_internal.h"

#define TEST_HTTP_SERVER_HOST "127.0.0.1"

struct test_http_server_context {
    pthread_mutex_t lock;
    int init_calls;
    int exit_calls;
    int request_calls;
};


static void test_http_server_context_init(struct test_http_server_context *context)
{
    memset(context, 0, sizeof(struct test_http_server_context));
    pthread_mutex_init(&context->lock, NULL);
}

static void test_http_server_context_destroy(struct test_http_server_context *context)
{
    pthread_mutex_destroy(&context->lock);
}

static int test_http_server_worker_init(struct flb_http_server *server, void *data)
{
    struct test_http_server_context *context;

    (void) server;

    context = data;

    pthread_mutex_lock(&context->lock);
    context->init_calls++;
    pthread_mutex_unlock(&context->lock);

    return 0;
}

static int test_http_server_worker_exit(struct flb_http_server *server, void *data)
{
    struct test_http_server_context *context;

    (void) server;

    context = data;

    pthread_mutex_lock(&context->lock);
    context->exit_calls++;
    pthread_mutex_unlock(&context->lock);

    return 0;
}

static int test_http_server_request_handler(struct flb_http_request *request,
                                            struct flb_http_response *response)
{
    struct test_http_server_context *context;
    struct flb_http_server_session *session;

    session = (struct flb_http_server_session *) request->stream->parent;
    context = session->parent->user_data;

    pthread_mutex_lock(&context->lock);
    context->request_calls++;
    pthread_mutex_unlock(&context->lock);

    flb_http_response_set_status(response, 200);
    flb_http_response_set_body(response,
                               (unsigned char *) "ok",
                               2);

    return flb_http_response_commit(response);
}

static int test_http_server_network_init(void)
{
#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;
    int ret;

    ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    TEST_CHECK(ret == 0);
    return ret;
#else
    return 0;
#endif
}

static void test_http_server_network_cleanup(void)
{
#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

void test_http_server_options_defaults()
{
    struct flb_http_server_options options;
    struct flb_http_server_config config;

    flb_http_server_options_init(&options);
    flb_http_server_config_init(&config);

    TEST_CHECK(options.workers == 1);
    TEST_CHECK(options.use_caller_event_loop == FLB_TRUE);
    TEST_CHECK(options.reuse_port == FLB_FALSE);
    TEST_CHECK(options.idle_timeout == HTTP_SERVER_DEFAULT_IDLE_TIMEOUT);
    TEST_CHECK(options.buffer_max_size == HTTP_SERVER_MAXIMUM_BUFFER_SIZE);
    TEST_CHECK(options.max_connections == 0);
    TEST_CHECK(config.http2 == FLB_TRUE);
    TEST_CHECK(config.idle_timeout == HTTP_SERVER_DEFAULT_IDLE_TIMEOUT);
    TEST_CHECK(config.buffer_max_size == HTTP_SERVER_MAXIMUM_BUFFER_SIZE);
    TEST_CHECK(config.max_connections == 0);
    TEST_CHECK(flb_http_server_property_is_allowed("http_server.idle_timeout") == FLB_TRUE);
    TEST_CHECK(flb_http_server_property_is_allowed("idle_timeout") == FLB_FALSE);
}

void test_http_server_options_multi_worker_magic()
{
    struct flb_config *config;
    struct flb_net_setup net_setup;
    struct flb_http_server server;
    struct flb_http_server_options options;
    int ret;

    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        return;
    }

    flb_net_setup_init(&net_setup);
    flb_http_server_options_init(&options);

    options.protocol_version = HTTP_PROTOCOL_VERSION_AUTODETECT;
    options.request_callback = test_http_server_request_handler;
    options.address = (char *) TEST_HTTP_SERVER_HOST;
    options.port = 10001;
    options.networking_flags = FLB_IO_TCP;
    options.networking_setup = &net_setup;
    options.system_context = config;
    options.workers = 2;
    options.max_connections = 7;

    ret = flb_http_server_init_with_options(&server, &options);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_config_exit(config);
        return;
    }
    TEST_CHECK(server.workers == 2);
    TEST_CHECK(server.reuse_port == FLB_TRUE);
    TEST_CHECK(server.use_caller_event_loop == FLB_FALSE);
    TEST_CHECK(server.idle_timeout == HTTP_SERVER_DEFAULT_IDLE_TIMEOUT);
    TEST_CHECK(net_setup.share_port == FLB_TRUE);
    TEST_CHECK(server.max_connections == 7);

    flb_http_server_destroy(&server);
    flb_config_exit(config);
}

void test_http_server_managed_worker_contract()
{
    struct flb_config *config;
    struct flb_net_setup net_setup;
    struct flb_http_server server;
    struct flb_http_server_options options;
    struct test_http_server_context context;
    int ret;
    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        return;
    }

    test_http_server_context_init(&context);

    flb_net_setup_init(&net_setup);
    flb_http_server_options_init(&options);

    options.protocol_version = HTTP_PROTOCOL_VERSION_AUTODETECT;
    options.request_callback = test_http_server_request_handler;
    options.user_data = &context;
    options.address = (char *) TEST_HTTP_SERVER_HOST;
    options.port = 10002;
    options.networking_flags = FLB_IO_TCP;
    options.networking_setup = &net_setup;
    options.system_context = config;
    options.workers = 2;
    options.max_connections = 3;
    options.cb_worker_init = test_http_server_worker_init;
    options.cb_worker_exit = test_http_server_worker_exit;

    ret = flb_http_server_init_with_options(&server, &options);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        test_http_server_context_destroy(&context);
        flb_config_exit(config);
        return;
    }
    TEST_CHECK(server.workers == 2);
    TEST_CHECK(server.use_caller_event_loop == FLB_FALSE);
    TEST_CHECK(server.reuse_port == FLB_TRUE);
    TEST_CHECK(server.idle_timeout == HTTP_SERVER_DEFAULT_IDLE_TIMEOUT);
    TEST_CHECK(server.max_connections == 3);
    TEST_CHECK(server.cb_worker_init == test_http_server_worker_init);
    TEST_CHECK(server.cb_worker_exit == test_http_server_worker_exit);
    TEST_CHECK(context.request_calls == 0);
    TEST_CHECK(context.init_calls == 0);
    TEST_CHECK(context.exit_calls == 0);

    flb_http_server_destroy(&server);
    test_http_server_context_destroy(&context);
    flb_config_exit(config);
}

void test_http_server_idle_timeout_applies_to_networking_setup()
{
    struct flb_config *config;
    struct flb_net_setup net_setup;
    struct flb_http_server server;
    struct flb_http_server_options options;
    int ret;

    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        return;
    }

    flb_net_setup_init(&net_setup);
    flb_http_server_options_init(&options);

    options.protocol_version = HTTP_PROTOCOL_VERSION_AUTODETECT;
    options.request_callback = test_http_server_request_handler;
    options.address = (char *) TEST_HTTP_SERVER_HOST;
    options.port = 10003;
    options.networking_flags = FLB_IO_TCP;
    options.networking_setup = &net_setup;
    options.system_context = config;
    options.idle_timeout = 17;

    ret = flb_http_server_init_with_options(&server, &options);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_config_exit(config);
        return;
    }

    TEST_CHECK(net_setup.io_timeout == 17);
    TEST_CHECK(server.idle_timeout == 17);

    flb_http_server_destroy(&server);
    flb_config_exit(config);
}

void test_http_server_explicit_network_timeout_is_preserved()
{
    struct flb_config *config;
    struct flb_net_setup net_setup;
    struct flb_http_server server;
    struct flb_http_server_options options;
    int ret;

    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        return;
    }

    flb_net_setup_init(&net_setup);
    flb_http_server_options_init(&options);

    net_setup.io_timeout = 23;

    options.protocol_version = HTTP_PROTOCOL_VERSION_AUTODETECT;
    options.request_callback = test_http_server_request_handler;
    options.address = (char *) TEST_HTTP_SERVER_HOST;
    options.port = 10004;
    options.networking_flags = FLB_IO_TCP;
    options.networking_setup = &net_setup;
    options.system_context = config;
    options.idle_timeout = 17;

    ret = flb_http_server_init_with_options(&server, &options);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_config_exit(config);
        return;
    }

    TEST_CHECK(net_setup.io_timeout == 23);
    TEST_CHECK(server.idle_timeout == 17);

    flb_http_server_destroy(&server);
    flb_config_exit(config);
}

void test_http_server_multi_worker_disabled_idle_timeout_is_preserved()
{
    struct flb_config *config;
    struct flb_net_setup net_setup;
    struct flb_http_server server;
    struct flb_http_server_options options;
    const struct flb_net_setup *worker0_net_setup;
    const struct flb_net_setup *worker1_net_setup;
    const struct flb_net_setup *worker2_net_setup;
    int ret;

    ret = test_http_server_network_init();
    if (ret != 0) {
        return;
    }

    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        test_http_server_network_cleanup();
        return;
    }

    flb_net_setup_init(&net_setup);
    flb_http_server_options_init(&options);

    options.protocol_version = HTTP_PROTOCOL_VERSION_AUTODETECT;
    options.request_callback = test_http_server_request_handler;
    options.address = (char *) TEST_HTTP_SERVER_HOST;
    options.port = 0;
    options.networking_flags = FLB_IO_TCP;
    options.networking_setup = &net_setup;
    options.system_context = config;
    options.workers = 2;
    options.idle_timeout = 0;

    ret = flb_http_server_init_with_options(&server, &options);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_config_exit(config);
        test_http_server_network_cleanup();
        return;
    }

    TEST_CHECK(server.idle_timeout == 0);
    TEST_CHECK(net_setup.io_timeout == 0);

    ret = flb_http_server_start(&server);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_http_server_destroy(&server);
        flb_config_exit(config);
        test_http_server_network_cleanup();
        return;
    }

    worker0_net_setup = flb_http_server_runtime_worker_net_setup_get(&server, 0);
    worker1_net_setup = flb_http_server_runtime_worker_net_setup_get(&server, 1);
    worker2_net_setup = flb_http_server_runtime_worker_net_setup_get(&server, 2);

    if (TEST_CHECK(worker0_net_setup != NULL) &&
        TEST_CHECK(worker1_net_setup != NULL) &&
        TEST_CHECK(worker2_net_setup == NULL)) {
        TEST_CHECK(worker0_net_setup->io_timeout == 0);
        TEST_CHECK(worker1_net_setup->io_timeout == 0);
    }

    flb_http_server_destroy(&server);
    flb_config_exit(config);
    test_http_server_network_cleanup();
}

void test_http_server_session_destroy_with_closed_connection()
{
    struct flb_connection connection;
    struct flb_http_server_session *session;

    memset(&connection, 0, sizeof(struct flb_connection));
    connection.fd = FLB_INVALID_SOCKET;

    session = flb_http_server_session_create(HTTP_PROTOCOL_VERSION_11);
    if (!TEST_CHECK(session != NULL)) {
        return;
    }

    session->connection = &connection;
    connection.user_data = session;
    connection.event.data = session;

    flb_http_server_session_destroy(session);

    TEST_CHECK(connection.user_data == NULL);
    TEST_CHECK(connection.event.data == NULL);
}

void test_http_server_session_destroy_clears_drop_pending()
{
    struct flb_connection connection;
    struct flb_http_server_session *session;

    memset(&connection, 0, sizeof(struct flb_connection));
    connection.fd = FLB_INVALID_SOCKET;

    session = flb_http_server_session_create(HTTP_PROTOCOL_VERSION_11);
    if (!TEST_CHECK(session != NULL)) {
        return;
    }

    session->connection = &connection;
    session->drop_pending = FLB_TRUE;
    session->releasable = FLB_FALSE;
    connection.user_data = session;
    connection.event.data = session;

    flb_http_server_session_destroy(session);

    TEST_CHECK(connection.user_data == NULL);
    TEST_CHECK(connection.event.data == NULL);
    TEST_CHECK(session->drop_pending == FLB_FALSE);

    flb_free(session);
}

TEST_LIST = {
    { "http_server_options_defaults", test_http_server_options_defaults },
    { "http_server_options_multi_worker_magic", test_http_server_options_multi_worker_magic },
    { "http_server_managed_worker_contract", test_http_server_managed_worker_contract },
    { "http_server_idle_timeout_applies_to_networking_setup",
      test_http_server_idle_timeout_applies_to_networking_setup },
    { "http_server_explicit_network_timeout_is_preserved",
      test_http_server_explicit_network_timeout_is_preserved },
    { "http_server_multi_worker_disabled_idle_timeout_is_preserved",
      test_http_server_multi_worker_disabled_idle_timeout_is_preserved },
    { "http_server_session_destroy_with_closed_connection",
      test_http_server_session_destroy_with_closed_connection },
    { "http_server_session_destroy_clears_drop_pending",
      test_http_server_session_destroy_clears_drop_pending },
    { 0 }
};
