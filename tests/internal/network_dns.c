/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_conn.h>
#include <fluent-bit/flb_socket.h>
#ifdef ares_init_options
#undef ares_init_options
#endif
#include <ares.h>

#include "flb_tests_internal.h"

static unsigned short dns_server_port;

/* Only this test target redirects c-ares to a loopback DNS server. */
int flb_test_ares_init_options(ares_channel *channel, struct ares_options *options,
                              int optmask)
{
    int ret;
    char server[64];

    ret = ares_init_options(channel, options, optmask);
    if (ret != ARES_SUCCESS) {
        return ret;
    }

    snprintf(server, sizeof(server), "127.0.0.1:%u", dns_server_port);
    ret = ares_set_servers_ports_csv(*channel, server);
    if (ret != ARES_SUCCESS) {
        ares_destroy(*channel);
        *channel = NULL;
    }
    return ret;
}

struct dns_server {
    flb_sockfd_t listener;
    flb_sockfd_t client;
    unsigned char packet[1024];
    size_t received;
    size_t sent;
};

static void dns_server_start(struct dns_server *server)
{
    struct sockaddr_in address;
    socklen_t address_size;

    memset(server, 0, sizeof(*server));
    server->client = FLB_INVALID_SOCKET;
    server->listener = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(server->listener != FLB_INVALID_SOCKET);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    TEST_ASSERT(bind(server->listener, (struct sockaddr *) &address, sizeof(address)) == 0);
    TEST_ASSERT(listen(server->listener, 1) == 0);
    address_size = sizeof(address);
    TEST_ASSERT(getsockname(server->listener, (struct sockaddr *) &address, &address_size) == 0);
    dns_server_port = ntohs(address.sin_port);
    TEST_ASSERT(flb_net_socket_nonblocking(server->listener) == 0);
}

static void dns_server_respond(struct dns_server *server)
{
    int ret;
    size_t packet_size;

    if (server->client == FLB_INVALID_SOCKET) {
        server->client = accept(server->listener, NULL, NULL);
        if (server->client == FLB_INVALID_SOCKET) {
            return;
        }
        TEST_ASSERT(flb_net_socket_nonblocking(server->client) == 0);
    }

    if (server->sent == 0) {
        ret = recv(server->client, (char *) server->packet + server->received,
                   sizeof(server->packet) - server->received, 0);
        if (ret <= 0) {
            return;
        }
        server->received += ret;
    }
    if (server->received < 2) {
        return;
    }
    packet_size = 2 + ((size_t) server->packet[0] << 8) + server->packet[1];
    TEST_ASSERT(packet_size >= 14 && packet_size <= sizeof(server->packet));
    if (server->received < packet_size) {
        return;
    }

    /* Echo the framed question and EDNS data with an NXDOMAIN response. */
    server->packet[4] = 0x81;
    server->packet[5] = 0x83;
    ret = send(server->client, (char *) server->packet + server->sent,
               packet_size - server->sent, 0);
    if (ret > 0) {
        server->sent += ret;
    }
}

struct dns_timeout_context {
    char *mode;
    int result;
    int timeout;
    int done;
    int resumptions;
    struct flb_upstream *upstream;
};

static void dns_timeout_coro(void)
{
    struct flb_coro *coro;
    struct dns_timeout_context *context;
    struct addrinfo hints;
    struct addrinfo *result;

    coro = flb_coro_get();
    context = coro->data;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    result = NULL;

    if (context->upstream != NULL) {
        TEST_CHECK(flb_upstream_conn_get(context->upstream) == NULL);
    }
    else {
        context->result = flb_net_getaddrinfo("fluent-bit-timeout-test.invalid.", "9200",
                                            &hints, &result, context->mode, context->timeout);
    }
    context->done = FLB_TRUE;
    TEST_CHECK(result == NULL);

    while (FLB_TRUE) {
        context->resumptions++;
        flb_coro_yield(coro, FLB_FALSE);
    }
}

static void test_dns_timeout(char *mode, int upstream_first, int timeout)
{
    size_t stack_size;
    time_t limit;
    void (*timeout_callback)(struct flb_config *, void *);
    void *timeout_data;
    struct flb_connection *connection;
    struct mk_event *event;
    struct dns_timeout_context context = {0};
    struct flb_net_dns dns;
    struct flb_coro *coro;
    struct flb_sched *sched;
    struct flb_sched_timer *timer;
    struct flb_sched_timer *deadline = NULL;
    struct mk_list *head;
    struct mk_event_loop *evl;
    struct dns_server server;
#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;

    TEST_ASSERT(WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0);
#endif

    dns_server_start(&server);
    flb_coro_init();
    flb_coro_thread_init();
    flb_engine_evl_init();
    flb_sched_ctx_init();
    flb_net_dns_ctx_init();
    flb_net_lib_init();
    flb_net_ctx_init(&dns);
    flb_net_dns_ctx_set(&dns);

    evl = mk_event_loop_create(32);
    TEST_ASSERT(evl != NULL);
    flb_engine_evl_set(evl);
    sched = flb_sched_create(test_env_config, evl);
    TEST_ASSERT(sched != NULL);
    flb_sched_ctx_set(sched);

    context.mode = mode;
    context.timeout = timeout;
    if (upstream_first) {
        context.upstream = flb_upstream_create(test_env_config,
                                              "fluent-bit-timeout-test.invalid.",
                                              9200, FLB_IO_TCP, NULL);
        TEST_ASSERT(context.upstream != NULL);
        context.upstream->base.net.connect_timeout = 1;
        context.upstream->base.net.dns_mode = mode;
    }
    coro = flb_coro_create(&context);
    TEST_ASSERT(coro != NULL);
    coro->caller = co_active();
    coro->callee = co_create(test_env_config->coro_stack_size, dns_timeout_coro, &stack_size);
    TEST_ASSERT(coro->callee != NULL);
#ifdef FLB_HAVE_VALGRIND
    coro->valgrind_stack_id = VALGRIND_STACK_REGISTER(
                                  coro->callee, ((char *) coro->callee) + stack_size);
#endif
    flb_coro_resume(coro);
    TEST_ASSERT(context.done == FLB_FALSE);

    /* Do not dispatch DNS socket events: simulate a server that never answers.
     * The lookup must install its own deadline for either transport. Only the
     * scheduler frame timer exists before the lookup starts.
     */
    mk_list_foreach(head, &sched->timers) {
        timer = mk_list_entry(head, struct flb_sched_timer, _head);
        if (timer->type == FLB_SCHED_TIMER_CB_ONESHOT) {
            deadline = timer;
        }
    }
    timeout_callback = NULL;
    timeout_data = NULL;
    if (timeout > 0) {
        TEST_ASSERT(deadline != NULL);
        timeout_callback = deadline->cb;
        timeout_data = deadline->data;
    }
    else {
        TEST_CHECK(deadline == NULL);
    }

    if (upstream_first) {
        connection = mk_list_entry_first(&context.upstream->queue.busy_queue,
                                         struct flb_connection, _head);
        TEST_ASSERT(connection != NULL);
        TEST_CHECK(connection->fd == FLB_INVALID_SOCKET);
        connection->ts_connect_timeout = time(NULL) - 1;
        flb_upstream_conn_timeouts(&test_env_config->upstreams);
        flb_upstream_conn_pending_destroy(context.upstream);
        TEST_CHECK(context.done == FLB_FALSE);
        TEST_CHECK(mk_list_size(&context.upstream->queue.destroy_queue) == 1);
    }

    /* With a deadline, withhold DNS events to simulate an unresponsive server.
     * Without one, answer locally so completion never depends on runner DNS.
     */
    limit = time(NULL) + 5;
    while (!context.done && time(NULL) < limit) {
        if (timeout <= 0) {
            dns_server_respond(&server);
        }
        mk_event_wait_2(evl, 100);
        mk_event_foreach(event, evl) {
            if (timeout <= 0 && event->type == FLB_ENGINE_EV_CUSTOM) {
                event->handler(event);
            }
            else if (event->type & FLB_ENGINE_EV_SCHED) {
                flb_sched_event_handler(test_env_config, event);
            }
        }
        if (timeout_callback != NULL && mk_list_is_empty(&dns.lookups_drop) != 0) {
            /* A late cancellation must be harmless before deferred cleanup. */
            timeout_callback(test_env_config, timeout_data);
        }
        flb_net_dns_lookup_context_cleanup(&dns);
        flb_time_msleep(10);
    }
    TEST_ASSERT(context.done == FLB_TRUE);
    if (!upstream_first) {
        if (timeout > 0) {
            TEST_CHECK(context.result == ARES_ETIMEOUT);
        }
        else {
            TEST_CHECK(context.result == ARES_ENOTFOUND);
        }
    }
    else {
        flb_upstream_conn_pending_destroy(context.upstream);
        TEST_CHECK(mk_list_is_empty(&context.upstream->queue.destroy_queue) == 0);
        flb_upstream_destroy(context.upstream);
    }
    TEST_CHECK(mk_list_is_empty(&dns.lookups) == 0);
    TEST_CHECK(mk_list_is_empty(&dns.lookups_drop) == 0);

    /* A second cleanup must not resume the coroutine or free the lookup again. */
    flb_net_dns_lookup_context_cleanup(&dns);
    TEST_CHECK(context.resumptions == 1);
    flb_coro_destroy(coro);
    flb_sched_destroy(sched);
    flb_sched_ctx_set(NULL);
    flb_engine_evl_set(NULL);
    flb_net_dns_ctx_set(NULL);
    mk_event_loop_destroy(evl);
    ares_library_cleanup();
    if (server.client != FLB_INVALID_SOCKET) {
        flb_socket_close(server.client);
    }
    flb_socket_close(server.listener);
#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

static void test_tcp_dns_timeout(void)
{
    test_dns_timeout("TCP", FLB_FALSE, 1);
}

static void test_udp_dns_timeout(void)
{
    test_dns_timeout("UDP", FLB_FALSE, 1);
}

static void test_upstream_timeout_before_dns(void)
{
    test_dns_timeout("TCP", FLB_TRUE, 1);
}

static void test_tcp_dns_timeout_disabled(void)
{
    test_dns_timeout("TCP", FLB_FALSE, 0);
}

TEST_LIST = {
    { "tcp_dns_timeout_disabled", test_tcp_dns_timeout_disabled},
    { "upstream_timeout_before_dns", test_upstream_timeout_before_dns},
    { "tcp_dns_timeout", test_tcp_dns_timeout},
    { "udp_dns_timeout", test_udp_dns_timeout},
    { 0 }
};
