/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_time.h>

#include <time.h>
#include "flb_tests_internal.h"

#define TEST_HOSTv4           "127.0.0.1"
#define TEST_HOSTv6           "::1"
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

TEST_LIST = {
    { "ipv4_client_server", test_ipv4_client_server},
    { "ipv6_client_server", test_ipv6_client_server},
    { 0 }
};
