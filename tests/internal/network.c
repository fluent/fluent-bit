/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_time.h>

#include <time.h>

#ifndef FLB_SYSTEM_WINDOWS
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "flb_tests_internal.h"

#define TEST_HOSTv4           "127.0.0.1"
#define TEST_HOSTv6           "::1"
#define TEST_HOSTv6_BRACKETED "[::1]"
#define TEST_PORT             "41322"

#define TEST_EV_CLIENT        MK_EVENT_NOTIFICATION
#define TEST_EV_SERVER        MK_EVENT_CUSTOM

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

#ifndef FLB_SYSTEM_WINDOWS

#define TEST_WRITE_SIZE (16 * 1024)
#define TEST_WRITE_MAX_ELAPSED_MILLISECONDS 900

struct socket_reader_context {
    int fd;
    int close_peer;
    size_t bytes_read;
};

static void *socket_reader(void *data)
{
    char buffer[4096];
    ssize_t bytes_read;
    struct socket_reader_context *context;

    context = data;

    /*
     * Give the writer time to fill the small send buffer and enter the
     * writability wait before draining the peer.
     */
    flb_time_msleep(20);

    if (context->close_peer == FLB_TRUE) {
        flb_socket_close(context->fd);
        return NULL;
    }

    while (context->bytes_read < TEST_WRITE_SIZE) {
        bytes_read = recv(context->fd, buffer, sizeof(buffer), 0);

        if (bytes_read > 0) {
            context->bytes_read += bytes_read;
        }
        else if (bytes_read < 0 && errno == EINTR) {
            continue;
        }
        else {
            break;
        }
    }

    return NULL;
}

static long elapsed_milliseconds(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000 +
           (end->tv_nsec - start->tv_nsec) / 1000000;
}

void test_nonblocking_socket_write_waits_for_writability()
{
    char *buffer;
    int result;
    int send_buffer_size;
    int sockets[2];
    long elapsed;
    size_t bytes_written;
    pthread_t reader_thread;
    struct timespec start;
    struct timespec end;
    struct socket_reader_context reader_context;

    result = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    if (!TEST_CHECK(result == 0)) {
        return;
    }

    send_buffer_size = 4096;
    result = setsockopt(sockets[0],
                        SOL_SOCKET,
                        SO_SNDBUF,
                        &send_buffer_size,
                        sizeof(send_buffer_size));
    if (!TEST_CHECK(result == 0)) {
        flb_socket_close(sockets[0]);
        flb_socket_close(sockets[1]);
        return;
    }

    result = flb_net_socket_nonblocking(sockets[0]);
    if (!TEST_CHECK(result == 0)) {
        flb_socket_close(sockets[0]);
        flb_socket_close(sockets[1]);
        return;
    }

    buffer = flb_malloc(TEST_WRITE_SIZE);
    if (!TEST_CHECK(buffer != NULL)) {
        flb_socket_close(sockets[0]);
        flb_socket_close(sockets[1]);
        return;
    }
    memset(buffer, 'x', TEST_WRITE_SIZE);

    reader_context.fd = sockets[1];
    reader_context.close_peer = FLB_FALSE;
    reader_context.bytes_read = 0;

    result = pthread_create(&reader_thread, NULL, socket_reader, &reader_context);
    if (!TEST_CHECK(result == 0)) {
        flb_free(buffer);
        flb_socket_close(sockets[0]);
        flb_socket_close(sockets[1]);
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    result = flb_io_fd_write(sockets[0],
                             buffer,
                             TEST_WRITE_SIZE,
                             &bytes_written);
    clock_gettime(CLOCK_MONOTONIC, &end);

    shutdown(sockets[0], SHUT_WR);
    pthread_join(reader_thread, NULL);

    elapsed = elapsed_milliseconds(&start, &end);

    TEST_CHECK(result == TEST_WRITE_SIZE);
    TEST_CHECK(bytes_written == TEST_WRITE_SIZE);
    TEST_CHECK(reader_context.bytes_read == TEST_WRITE_SIZE);
    TEST_CHECK(elapsed < TEST_WRITE_MAX_ELAPSED_MILLISECONDS);

    flb_free(buffer);
    flb_socket_close(sockets[0]);
    flb_socket_close(sockets[1]);
}

void test_nonblocking_socket_write_propagates_peer_close()
{
    char *buffer;
    int result;
    int send_buffer_size;
    int socket_error;
    int sockets[2];
    int write_result;
    size_t bytes_written;
    pthread_t reader_thread;
    struct sigaction ignore_action;
    struct sigaction previous_action;
    struct socket_reader_context reader_context;

    result = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
    if (!TEST_CHECK(result == 0)) {
        return;
    }

    send_buffer_size = 4096;
    result = setsockopt(sockets[0],
                        SOL_SOCKET,
                        SO_SNDBUF,
                        &send_buffer_size,
                        sizeof(send_buffer_size));
    if (!TEST_CHECK(result == 0)) {
        flb_socket_close(sockets[0]);
        flb_socket_close(sockets[1]);
        return;
    }

    result = flb_net_socket_nonblocking(sockets[0]);
    if (!TEST_CHECK(result == 0)) {
        flb_socket_close(sockets[0]);
        flb_socket_close(sockets[1]);
        return;
    }

    buffer = flb_malloc(TEST_WRITE_SIZE);
    if (!TEST_CHECK(buffer != NULL)) {
        flb_socket_close(sockets[0]);
        flb_socket_close(sockets[1]);
        return;
    }
    memset(buffer, 'x', TEST_WRITE_SIZE);

    reader_context.fd = sockets[1];
    reader_context.close_peer = FLB_TRUE;
    reader_context.bytes_read = 0;

    result = pthread_create(&reader_thread, NULL, socket_reader, &reader_context);
    if (!TEST_CHECK(result == 0)) {
        flb_free(buffer);
        flb_socket_close(sockets[0]);
        flb_socket_close(sockets[1]);
        return;
    }

    memset(&ignore_action, 0, sizeof(ignore_action));
    ignore_action.sa_handler = SIG_IGN;
    sigemptyset(&ignore_action.sa_mask);
    result = sigaction(SIGPIPE, &ignore_action, &previous_action);
    if (!TEST_CHECK(result == 0)) {
        pthread_join(reader_thread, NULL);
        flb_free(buffer);
        flb_socket_close(sockets[0]);
        return;
    }

    errno = 0;
    write_result = flb_io_fd_write(sockets[0],
                                   buffer,
                                   TEST_WRITE_SIZE,
                                   &bytes_written);
    socket_error = errno;

    result = sigaction(SIGPIPE, &previous_action, NULL);
    pthread_join(reader_thread, NULL);

    TEST_CHECK(result == 0);
    TEST_CHECK(write_result == -1);
    TEST_CHECK(socket_error == EPIPE ||
               socket_error == ECONNRESET ||
               socket_error == ENOTCONN);

    flb_free(buffer);
    flb_socket_close(sockets[0]);
}

#endif

TEST_LIST = {
    { "ipv4_client_server", test_ipv4_client_server},
    { "ipv6_client_server", test_ipv6_client_server},
    { "ipv6_bracketed_listen", test_ipv6_bracketed_listen},
#ifndef FLB_SYSTEM_WINDOWS
    { "nonblocking_socket_write_waits_for_writability",
      test_nonblocking_socket_write_waits_for_writability},
    { "nonblocking_socket_write_propagates_peer_close",
      test_nonblocking_socket_write_propagates_peer_close},
#endif
    { 0 }
};
