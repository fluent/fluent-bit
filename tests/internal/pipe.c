/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pipe.h>
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

TEST_LIST = {
    { "pipe_usage", test_pipe_usage},
    { 0 }
};
