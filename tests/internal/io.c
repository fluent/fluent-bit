/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef FLB_SYSTEM_WINDOWS
#include <sys/socket.h>
#endif

#include <fluent-bit/flb_connection.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_stream.h>
#include <fluent-bit/flb_pthread.h>

#include "flb_tests_internal.h"

#define LARGE_IOV_COUNT 2048

struct reader_context {
    flb_pipefd_t fd;
    char *buffer;
    size_t length;
    ssize_t result;
};

static void *read_payload(void *data)
{
    struct reader_context *context;

    context = data;
    context->result = flb_pipe_read_all(context->fd,
                                        context->buffer,
                                        context->length);

    return NULL;
}

static int create_socket_pair(flb_pipefd_t pair[2])
{
#ifdef FLB_SYSTEM_WINDOWS
    return flb_pipe_create(pair);
#else
    return socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
#endif
}

static void setup_connection(struct flb_connection *connection,
                             struct flb_stream *stream,
                             flb_pipefd_t fd)
{
    memset(connection, 0, sizeof(struct flb_connection));
    memset(stream, 0, sizeof(struct flb_stream));

    flb_net_setup_init(&stream->net);
    stream->transport = FLB_TRANSPORT_UNIX_STREAM;
    connection->fd = fd;
    connection->type = FLB_UPSTREAM_CONNECTION;
    connection->stream = stream;
    connection->net = &stream->net;
    connection->net_error = -1;
}

static void assert_vector_payload(const struct flb_iovec *iov,
                                  int iovcnt,
                                  const char *expected,
                                  size_t expected_length)
{
    int result;
    size_t out_length;
    pthread_t reader;
    flb_pipefd_t pair[2];
    struct flb_stream stream;
    struct flb_connection connection;
    struct reader_context reader_context;

    result = create_socket_pair(pair);
    TEST_CHECK(result == 0);
    if (result != 0) {
        return;
    }

    reader_context.fd = pair[1];
    reader_context.buffer = calloc(1, expected_length + 1);
    reader_context.length = expected_length;
    reader_context.result = -1;
    TEST_CHECK(reader_context.buffer != NULL);
    if (reader_context.buffer == NULL) {
        flb_socket_close(pair[0]);
        flb_socket_close(pair[1]);
        return;
    }

    setup_connection(&connection, &stream, pair[0]);

    result = pthread_create(&reader, NULL, read_payload, &reader_context);
    TEST_CHECK(result == 0);
    if (result != 0) {
        free(reader_context.buffer);
        flb_socket_close(pair[0]);
        flb_socket_close(pair[1]);
        return;
    }

    out_length = SIZE_MAX;
    result = flb_io_net_writev(&connection, iov, iovcnt, &out_length);
    TEST_CHECK(result > 0);
    TEST_CHECK(out_length == expected_length);

    pthread_join(reader, NULL);
    TEST_CHECK(reader_context.result == (ssize_t) expected_length);
    TEST_CHECK(memcmp(reader_context.buffer, expected, expected_length) == 0);

    free(reader_context.buffer);
    flb_socket_close(pair[0]);
    flb_socket_close(pair[1]);
}

static void test_writev_preconditions(void)
{
    int result;
    char byte;
    size_t out_length;
    struct flb_connection connection;
    struct flb_iovec valid_vector[1];
    struct flb_iovec overflow_vector[2];
    struct flb_iovec null_base_vector[1];

    byte = 'x';
    memset(&connection, 0, sizeof(struct flb_connection));
    valid_vector[0].iov_base = &byte;
    valid_vector[0].iov_len = 1;

    out_length = SIZE_MAX;
    errno = 0;
    result = flb_io_net_writev(NULL, valid_vector, 1, &out_length);
    TEST_CHECK(result == -1);
    TEST_CHECK(errno == EINVAL);
    TEST_CHECK(out_length == 0);

    out_length = SIZE_MAX;
    errno = 0;
    result = flb_io_net_writev(&connection, NULL, 1, &out_length);
    TEST_CHECK(result == -1);
    TEST_CHECK(errno == EINVAL);
    TEST_CHECK(out_length == 0);

    out_length = SIZE_MAX;
    errno = 0;
    result = flb_io_net_writev(&connection, valid_vector, 0, &out_length);
    TEST_CHECK(result == -1);
    TEST_CHECK(errno == EINVAL);
    TEST_CHECK(out_length == 0);

    errno = 0;
    result = flb_io_net_writev(&connection, valid_vector, 1, NULL);
    TEST_CHECK(result == -1);
    TEST_CHECK(errno == EINVAL);

    overflow_vector[0].iov_base = &byte;
    overflow_vector[0].iov_len = SIZE_MAX;
    overflow_vector[1].iov_base = &byte;
    overflow_vector[1].iov_len = 1;
    out_length = SIZE_MAX;
    errno = 0;
    result = flb_io_net_writev(&connection, overflow_vector, 2, &out_length);
    TEST_CHECK(result == -1);
    TEST_CHECK(errno == EOVERFLOW);
    TEST_CHECK(out_length == 0);

    null_base_vector[0].iov_base = NULL;
    null_base_vector[0].iov_len = 1;
    out_length = SIZE_MAX;
    errno = 0;
    result = flb_io_net_writev(&connection, null_base_vector, 1, &out_length);
    TEST_CHECK(result == -1);
    TEST_CHECK(errno == EINVAL);
    TEST_CHECK(out_length == 0);
}

static void test_writev_empty_vectors(void)
{
    int result;
    size_t out_length;
    struct flb_connection connection;
    struct flb_iovec vector[3];

    memset(&connection, 0, sizeof(struct flb_connection));
    memset(vector, 0, sizeof(vector));

    out_length = SIZE_MAX;
    result = flb_io_net_writev(&connection, vector, 3, &out_length);
    TEST_CHECK(result == 0);
    TEST_CHECK(out_length == 0);
}

static void test_writev_transport_error(void)
{
    int result;
    char byte;
    size_t out_length;
    struct flb_stream stream;
    struct flb_connection connection;
    struct flb_iovec vector[1];

    byte = 'x';
    vector[0].iov_base = &byte;
    vector[0].iov_len = 1;
    setup_connection(&connection, &stream, INT_MAX);

    out_length = SIZE_MAX;
    errno = 0;
    result = flb_io_net_writev(&connection, vector, 1, &out_length);
    TEST_CHECK(result == -1);
#ifndef FLB_SYSTEM_WINDOWS
    TEST_CHECK(errno == EBADF);
#else
    TEST_CHECK(errno != 0);
#endif
    TEST_CHECK(out_length == 0);
}

static void test_writev_vector_shapes(void)
{
    int index;
    char one[] = "one";
    char two[] = "two";
    char expected[] = "onetwo";
    char *large_expected;
    struct flb_iovec one_vector[1];
    struct flb_iovec two_vectors[3];
    struct flb_iovec *large_vector;

    one_vector[0].iov_base = expected;
    one_vector[0].iov_len = sizeof(expected) - 1;
    assert_vector_payload(one_vector, 1, expected, sizeof(expected) - 1);

    two_vectors[0].iov_base = one;
    two_vectors[0].iov_len = sizeof(one) - 1;
    two_vectors[1].iov_base = NULL;
    two_vectors[1].iov_len = 0;
    two_vectors[2].iov_base = two;
    two_vectors[2].iov_len = sizeof(two) - 1;
    assert_vector_payload(two_vectors, 3, expected, sizeof(expected) - 1);

    large_vector = calloc(LARGE_IOV_COUNT, sizeof(struct flb_iovec));
    large_expected = malloc(LARGE_IOV_COUNT);
    TEST_CHECK(large_vector != NULL);
    TEST_CHECK(large_expected != NULL);
    if (large_vector == NULL || large_expected == NULL) {
        free(large_vector);
        free(large_expected);
        return;
    }

    for (index = 0; index < LARGE_IOV_COUNT; index++) {
        large_expected[index] = (char) ('a' + (index % 26));
        large_vector[index].iov_base = &large_expected[index];
        large_vector[index].iov_len = 1;
    }

    assert_vector_payload(large_vector, LARGE_IOV_COUNT,
                          large_expected, LARGE_IOV_COUNT);
    free(large_vector);
    free(large_expected);
}

static void test_writev_coalesce_boundary(void)
{
    char *payload;
    size_t payload_length;
    struct flb_iovec vector[2];

    payload_length = FLB_IO_WRITEV_COALESCE_MAX + 1;
    payload = malloc(payload_length);
    TEST_CHECK(payload != NULL);
    if (payload == NULL) {
        return;
    }

    memset(payload, 'z', payload_length);
    vector[0].iov_base = payload;
    vector[0].iov_len = FLB_IO_WRITEV_COALESCE_MAX / 2;
    vector[1].iov_base = payload + vector[0].iov_len;
    vector[1].iov_len = FLB_IO_WRITEV_COALESCE_MAX - vector[0].iov_len;
    assert_vector_payload(vector, 2, payload, FLB_IO_WRITEV_COALESCE_MAX);

    vector[1].iov_len++;
    assert_vector_payload(vector, 2, payload, payload_length);
    free(payload);
}

TEST_LIST = {
    { "writev_preconditions", test_writev_preconditions },
    { "writev_empty_vectors", test_writev_empty_vectors },
    { "writev_transport_error", test_writev_transport_error },
    { "writev_vector_shapes", test_writev_vector_shapes },
    { "writev_coalesce_boundary", test_writev_coalesce_boundary },
    { 0 }
};
