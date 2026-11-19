/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pipe.h>
#include <monkey/mk_core.h>
#ifdef FLB_SYSTEM_WINDOWS
#include <fluent-bit/flb_compat.h>
#endif

#include <inttypes.h>
#include "flb_tests_internal.h"

struct data {
    int x;
    char str[32];
};

static void test_pipe_usage()
{
    int i;
    int ret;
    char *b;
    ssize_t bytes;
    flb_pipefd_t p[2];
    struct data data;
    struct data rec;
#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;
#endif

#ifdef FLB_SYSTEM_WINDOWS
    WSAStartup(0x0201, &wsa_data);
#endif
    /* Create pipe */
    ret = flb_pipe_create(p);
    TEST_CHECK(ret == 0);

    /* Prepare test */
    memset(&data, '\0', sizeof(struct data));
    data.x = 2017;
    memcpy(data.str, "this is a test\n", 15);
    data.str[15] = '\0';

    /* Simple write/read */
    bytes = flb_pipe_w(p[1], &data, sizeof(struct data));
    TEST_CHECK(bytes > 0);

    bytes = flb_pipe_r(p[0], &rec, sizeof(struct data));
    TEST_CHECK(bytes > 0);
    TEST_CHECK(rec.x == 2017);
    TEST_CHECK(strlen(rec.str) == 15);

    /* Iterate write, all_read */
    b = (char *) &data;
    for (i = 0; i < sizeof(struct data); i++, b++) {
        bytes = flb_pipe_w(p[1], b, 1);
        TEST_CHECK(bytes == 1);
    }

    b = (char *) &rec;
    memset(&rec, '\0', sizeof(struct data));
    for (i = 0; i < sizeof(struct data); i++, b++) {
        bytes = flb_pipe_read_all(p[0], b, 1);
        TEST_CHECK(bytes == 1);
    }
    TEST_CHECK(rec.x == 2017);
    TEST_CHECK(strlen(rec.str) == 15);

    /* All write, all read */
    bytes = flb_pipe_write_all(p[1], &data, sizeof(struct data));
    TEST_CHECK(bytes == sizeof(struct data));

    memset(&rec, '\0', sizeof(struct data));
    bytes = flb_pipe_read_all(p[0], &rec, sizeof(struct data));
    TEST_CHECK(bytes == sizeof(struct data));
    TEST_CHECK(rec.x == 2017);
    TEST_CHECK(strlen(rec.str) == 15);

    /* Close pipe channels */
    flb_pipe_close(p[0]);
    flb_pipe_close(p[1]);
#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

static void test_event_channel_descriptor_width(void)
{
    struct mk_event_loop *loop;
    struct mk_event event = {0};
    flb_pipefd_t channels[2] = {-1, -1};
    uint64_t sent = 42;
    uint64_t received = 0;
    int ret;
#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;

    TEST_ASSERT(WSAStartup(0x0201, &wsa_data) == 0);
#endif

    loop = mk_event_loop_create(8);
    TEST_ASSERT(loop != NULL);
    MK_EVENT_ZERO(&event);

    ret = flb_pipe_event_channel_create(loop, &channels[0], &channels[1], &event);
    TEST_ASSERT(ret == 0);
    /* Replacing -1 must clear every byte of native-width descriptor storage. */
    TEST_ASSERT(channels[0] >= 0);
    TEST_ASSERT(channels[1] >= 0);
    TEST_CHECK(channels[0] == event.fd);
    TEST_ASSERT(flb_pipe_w(channels[1], &sent, sizeof(sent)) == sizeof(sent));
    TEST_ASSERT(mk_event_wait_2(loop, 1000) == 1);
    TEST_CHECK(flb_pipe_r(channels[0], &received, sizeof(received)) == sizeof(received));
    TEST_CHECK(received == sent);

    mk_event_del(loop, &event);
    flb_pipe_destroy(channels);
    mk_event_loop_destroy(loop);
#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

TEST_LIST = {
    { "pipe_usage", test_pipe_usage},
    { "event_channel_descriptor_width", test_event_channel_descriptor_width},
    { 0 }
};
