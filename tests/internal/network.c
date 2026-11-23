/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_downstream.h>

#include <time.h>
#ifndef FLB_SYSTEM_WINDOWS
#include <pthread.h>
#endif
#include "flb_tests_internal.h"

#define TEST_HOSTv4           "127.0.0.1"
#define TEST_HOSTv6           "::1"
#define TEST_HOSTv6_BRACKETED "[::1]"
#define TEST_PORT             "41322"

#define TEST_EV_CLIENT        MK_EVENT_NOTIFICATION
#define TEST_EV_SERVER        MK_EVENT_CUSTOM

struct parent_callback_context {
    struct flb_connection connection;
    struct flb_coro *parent_coro;
    int callback_on_parent;
    int callback_result;
    int coroutine_done;
};

static int parent_callback(void *data)
{
    struct parent_callback_context *context;

    context = data;
    context->callback_on_parent = flb_coro_get() == context->parent_coro;

    return 73;
}

static void parent_callback_coro(void)
{
    struct flb_coro *coro;
    struct parent_callback_context *context;

    coro = flb_coro_get();
    context = coro->data;

    context->callback_result = flb_downstream_conn_event_call_parent(
                                   &context->connection,
                                   parent_callback,
                                   context);
    context->coroutine_done = FLB_TRUE;

    while (FLB_TRUE) {
        flb_coro_yield(coro, FLB_FALSE);
    }
}

static int socket_check_ok(flb_sockfd_t fd)
{
    int ret;
    int error = 0;
    socklen_t len = sizeof(error);

    ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
    if (ret == -1) {
        return -1;
    }

    if (error != 0) {
        return -1;
    }

    return 0;
}

static void test_client_server(int is_ipv6)
{
    int ret;
    int loops = 0;
    int client_OK = FLB_FALSE;
    int server_OK = FLB_FALSE;
    int family;
    char *host;
    flb_sockfd_t fd_client;
    flb_sockfd_t fd_server;
    flb_sockfd_t fd_remote = -1;
    struct mk_event e_client = {0};
    struct mk_event e_server = {0};
    struct mk_event *e_item;
    struct mk_event_loop *evl;

    if (is_ipv6 == FLB_TRUE) {
        family = AF_INET6;
        host = TEST_HOSTv6;
    }
    else {
        family = AF_INET;
        host = TEST_HOSTv4;
    }

    /* Create client and server sockets */
    fd_client = flb_net_socket_create(family, FLB_TRUE);
    if (errno == EAFNOSUPPORT) {
        TEST_MSG("This protocol is not supported in this platform");
        return;
    }
    TEST_CHECK(fd_client != -1);

    fd_server = flb_net_server(TEST_PORT, host,
                               FLB_NETWORK_DEFAULT_BACKLOG_SIZE,
                               FLB_FALSE);
    TEST_CHECK(fd_server != -1);

    /* Create Event loop */
    evl = mk_event_loop_create(8);
    TEST_CHECK(evl != NULL);

    /* Register client/server sockets into the event loop */
    MK_EVENT_NEW(&e_client);
    ret = mk_event_add(evl, fd_client, TEST_EV_CLIENT, MK_EVENT_WRITE, &e_client);
    TEST_CHECK(ret != -1);

    MK_EVENT_NEW(&e_server);
    ret = mk_event_add(evl, fd_server, TEST_EV_SERVER, MK_EVENT_READ, &e_server);
    TEST_CHECK(ret != -1);

    /* Test an async connection, we expect -1 */
    ret = flb_net_tcp_fd_connect(fd_client, host, atol(TEST_PORT));
    TEST_CHECK(ret == -1);
    TEST_CHECK(errno == EINPROGRESS);

#ifdef FLB_SYSTEM_MACOS
    /* On macOS, its internal timer's is inacccurate without waiting code.
     * We need to proceed its timer tick for processing events. */
    flb_time_msleep(50);
#endif

    /* Event loop */
    while (1) {
        /* Break immediately for invalid status */
        if (fd_client == -1 || fd_server == -1) {
            break;
        }
        mk_event_wait(evl);
        mk_event_foreach(e_item, evl) {
            if (e_item->type == TEST_EV_CLIENT) {
                /* Validate event mask */
                TEST_CHECK(e_item->mask & MK_EVENT_WRITE);

                /*
                 * Client socket get a notification, we expect to get a
                 * successful connection.
                 */
                ret = socket_check_ok(fd_client);
                TEST_CHECK(ret == 0);
                client_OK = FLB_TRUE;
            }
            else if (e_item->type == TEST_EV_SERVER) {
                /* Validate event mask */
                TEST_CHECK(e_item->mask & MK_EVENT_READ);

                /* Accept the incoming connection */
                fd_remote = flb_net_accept(fd_server);
                TEST_CHECK(fd_remote > 0);

                server_OK = FLB_TRUE;
            }
            loops++;
        }

        if (client_OK == FLB_TRUE && server_OK == FLB_TRUE) {
            break;
        }

        TEST_CHECK(loops < 2);
        if (loops >= 2) {
            break;
        }
    }

    mk_event_loop_destroy(evl);
    flb_socket_close(fd_client);
    flb_socket_close(fd_server);
    if (fd_remote > 0) {
        flb_socket_close(fd_remote);
    }
}

void test_ipv4_client_server()
{
    test_client_server(FLB_FALSE);
}

void test_ipv6_client_server()
{
    test_client_server(FLB_TRUE);
}

void test_ipv6_bracketed_listen()
{
    flb_sockfd_t fd_server;

    errno = 0;
    fd_server = flb_net_server(TEST_PORT, TEST_HOSTv6_BRACKETED,
                               FLB_NETWORK_DEFAULT_BACKLOG_SIZE,
                               FLB_FALSE);

    if (fd_server == -1 && errno == EAFNOSUPPORT) {
        TEST_MSG("This protocol is not supported in this platform");
        return;
    }

    TEST_CHECK(fd_server != -1);

    if (fd_server != -1) {
        flb_socket_close(fd_server);
    }
}

void test_accept_empty_nonblocking_listener()
{
    flb_sockfd_t fd_remote;
    flb_sockfd_t fd_server;

    fd_server = flb_net_server("0", TEST_HOSTv4,
                               FLB_NETWORK_DEFAULT_BACKLOG_SIZE,
                               FLB_FALSE);
    if (!TEST_CHECK(fd_server != FLB_INVALID_SOCKET)) {
        return;
    }

    fd_remote = flb_net_accept(fd_server);

    TEST_CHECK(fd_remote == FLB_INVALID_SOCKET);
    TEST_CHECK(FLB_WOULDBLOCK());

    flb_socket_close(fd_server);
}

void test_downstream_event_callback_runs_on_parent_stack()
{
    size_t stack_size;
    struct flb_coro *coro;
    struct parent_callback_context context;

    memset(&context, 0, sizeof(context));

    flb_coro_init();
    flb_coro_thread_init();

    coro = flb_coro_create(&context);
    if (!TEST_CHECK(coro != NULL)) {
        return;
    }

    coro->caller = co_active();
    coro->callee = co_create(test_env_config->coro_stack_size,
                             parent_callback_coro,
                             &stack_size);
    if (!TEST_CHECK(coro->callee != NULL)) {
        flb_coro_destroy(coro);
        return;
    }

#ifdef FLB_HAVE_VALGRIND
    coro->valgrind_stack_id = VALGRIND_STACK_REGISTER(
                                  coro->callee,
                                  ((char *) coro->callee) + stack_size);
#endif

    context.parent_coro = flb_coro_get();
    context.connection.event_coroutine = coro;

    flb_downstream_conn_event_resume(&context.connection);

    TEST_CHECK(context.callback_on_parent == FLB_TRUE);
    TEST_CHECK(context.callback_result == 73);
    TEST_CHECK(context.coroutine_done == FLB_TRUE);

    context.connection.event_coroutine = NULL;
    flb_coro_destroy(coro);
}

/* Verify that a blocking send to a stalled peer is bounded by its timeout. */
#ifndef FLB_SYSTEM_WINDOWS
static void test_blocking_send_timeout(void)
{
    int ret;
    int pair[2];
    int buffer_size = 4096;
    size_t written = 99;
    char data[4096] = {0};
    struct flb_time start;
    struct flb_time end;
    double elapsed;

    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
    if (!TEST_CHECK(ret == 0)) {
        return;
    }

    ret = setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
    TEST_CHECK(ret == 0);
    TEST_CHECK(flb_net_socket_nonblocking(pair[0]) == 0);
    do {
        ret = send(pair[0], data, sizeof(data), 0);
    } while (ret > 0);
    TEST_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);

    TEST_CHECK(flb_net_socket_blocking(pair[0]) == 0);
    TEST_CHECK(flb_net_socket_set_sndtimeout(pair[0], 1) == 0);
    flb_time_get(&start);
    ret = flb_io_fd_write(pair[0], data, sizeof(data), &written);
    flb_time_get(&end);
    TEST_CHECK(ret == -1);
    TEST_CHECK(written == 0);
    TEST_CHECK(errno == ETIMEDOUT);
    elapsed = flb_time_to_double(&end) - flb_time_to_double(&start);
    TEST_CHECK(elapsed >= 0.5 && elapsed < 5.0);
    TEST_MSG("blocked send returned after %.3f seconds", elapsed);

    flb_socket_close(pair[0]);
    flb_socket_close(pair[1]);
}

/* A timed-out write must report bytes sent before the peer stopped reading. */
static void test_blocking_send_timeout_partial(void)
{
    int ret;
    int pair[2];
    int buffer_size = 4096;
    char data[65536] = {0};
    size_t written = 0;
    struct flb_time start;
    struct flb_time end;
    double elapsed;
    struct flb_stream stream = {0};
    struct flb_connection connection = {0};

    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
    if (!TEST_CHECK(ret == 0)) {
        return;
    }

    TEST_CHECK(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF,
                         &buffer_size, sizeof(buffer_size)) == 0);
    TEST_CHECK(flb_net_socket_set_sndtimeout(pair[0], 1) == 0);
    connection.fd = pair[0];
    connection.stream = &stream;
    connection.net_error = -1;
    flb_time_get(&start);
    ret = flb_io_net_write(&connection, data, sizeof(data), &written);
    flb_time_get(&end);
    TEST_CHECK(ret == -1);
    TEST_CHECK(connection.net_error == ETIMEDOUT);
    TEST_CHECK(written > 0 && written < sizeof(data));
    elapsed = flb_time_to_double(&end) - flb_time_to_double(&start);
    TEST_CHECK(elapsed >= 0.5 && elapsed < 5.0);
    TEST_MSG("partial write of %zu bytes returned after %.3f seconds", written, elapsed);

    flb_socket_close(pair[0]);
    flb_socket_close(pair[1]);
}

/* Drain the initial backlog after the writer encounters nonblocking EAGAIN. */
static void *drain_nonblocking_peer(void *data)
{
    int fd = *(int *) data;
    char buffer[4096];

    flb_time_msleep(100);
    while (recv(fd, buffer, sizeof(buffer), 0) > 0) {
    }

    return NULL;
}

/* Transient nonblocking backpressure must still retry and deliver the payload. */
static void test_nonblocking_send_retry(void)
{
    int ret;
    int pair[2];
    int buffer_size = 4096;
    char filler[4096] = {0};
    char payload[] = "retry";
    char received[sizeof(payload)] = {0};
    size_t written = 0;
    pthread_t reader;

    ret = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
    if (!TEST_CHECK(ret == 0)) {
        return;
    }

    TEST_CHECK(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF,
                         &buffer_size, sizeof(buffer_size)) == 0);
    TEST_CHECK(flb_net_socket_nonblocking(pair[0]) == 0);
    TEST_CHECK(flb_net_socket_nonblocking(pair[1]) == 0);
    TEST_CHECK(flb_net_socket_set_sndtimeout(pair[0], 1) == 0);
    do {
        ret = send(pair[0], filler, sizeof(filler), 0);
    } while (ret > 0);
    TEST_CHECK(ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));

    ret = pthread_create(&reader, NULL, drain_nonblocking_peer, &pair[1]);
    if (TEST_CHECK(ret == 0)) {
        ret = flb_io_fd_write(pair[0], payload, sizeof(payload), &written);
        TEST_CHECK(ret == sizeof(payload));
        TEST_CHECK(written == sizeof(payload));
        pthread_join(reader, NULL);
        ret = recv(pair[1], received, sizeof(received), 0);
        TEST_CHECK(ret == sizeof(payload));
        TEST_CHECK(memcmp(received, payload, sizeof(payload)) == 0);
    }

    flb_socket_close(pair[0]);
    flb_socket_close(pair[1]);
}

#endif

TEST_LIST = {
#ifndef FLB_SYSTEM_WINDOWS
    { "blocking_send_timeout", test_blocking_send_timeout },
    { "blocking_send_timeout_partial", test_blocking_send_timeout_partial },
    { "nonblocking_send_retry", test_nonblocking_send_retry },
#endif
    { "ipv4_client_server", test_ipv4_client_server},
    { "ipv6_client_server", test_ipv6_client_server},
    { "ipv6_bracketed_listen", test_ipv6_bracketed_listen},
    { "accept_empty_nonblocking_listener", test_accept_empty_nonblocking_listener},
    { "downstream_event_callback_runs_on_parent_stack",
      test_downstream_event_callback_runs_on_parent_stack },
    { 0 }
};
