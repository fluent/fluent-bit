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
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/tls/flb_tls.h>

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

    /* Unblock the reader even if a regression caused a short write. */
    shutdown(pair[0], SHUT_WR);
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

struct async_writer_context {
    struct flb_connection *connection;
    struct flb_iovec *iov;
    int count;
    int result;
    int done;
    size_t written;
};

static void write_vectors_async(void)
{
    struct flb_coro *coro;
    struct async_writer_context *context;

    coro = flb_coro_get();
    context = coro->data;
    context->result = flb_io_net_writev(context->connection, context->iov,
                                       context->count, &context->written);
    context->done = FLB_TRUE;
    flb_coro_yield(coro, FLB_TRUE);
}

static void check_writev_async(int cancel)
{
    int result;
    int buffer_size;
    int iterations;
    ssize_t bytes;
    size_t length;
    size_t received;
    size_t stack_size;
    size_t index;
    char *payload;
    char *output;
    flb_pipefd_t pair[2];
    struct flb_stream stream;
    struct flb_connection connection;
    struct flb_iovec iov[4];
    struct flb_coro *coro;
    struct flb_coro *parent;
    struct async_writer_context context;

    length = 1024 * 1024 + 31;
    payload = malloc(length);
    output = malloc(length);
    if (!TEST_CHECK(payload != NULL && output != NULL)) {
        free(payload);
        free(output);
        return;
    }
    for (index = 0; index < length; index++) {
        payload[index] = (char) (index % 251);
    }

    result = create_socket_pair(pair);
    if (!TEST_CHECK(result == 0)) {
        free(payload);
        free(output);
        return;
    }
    TEST_CHECK(flb_net_socket_nonblocking(pair[0]) == 0);
    TEST_CHECK(flb_net_socket_nonblocking(pair[1]) == 0);
    buffer_size = 4096;
    TEST_CHECK(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF,
                         (const char *) &buffer_size, sizeof(buffer_size)) == 0);
    setup_connection(&connection, &stream, pair[0]);
    stream.flags = FLB_IO_ASYNC;
    connection.evl = mk_event_loop_create(8);
    if (!TEST_CHECK(connection.evl != NULL)) {
        goto cleanup_sockets;
    }
    MK_EVENT_NEW(&connection.event);
    TEST_CHECK(mk_event_add(connection.evl, pair[0], MK_EVENT_CUSTOM,
                            MK_EVENT_READ, &connection.event) == 0);

    iov[0].iov_base = payload;
    iov[0].iov_len = 13;
    iov[1].iov_base = NULL;
    iov[1].iov_len = 0;
    iov[2].iov_base = payload + 13;
    iov[2].iov_len = 700001;
    iov[3].iov_base = payload + 700014;
    iov[3].iov_len = length - 700014;
    memset(&context, 0, sizeof(context));
    context.connection = &connection;
    context.iov = iov;
    context.count = 4;

    flb_coro_init();
    flb_coro_thread_init();
    parent = flb_coro_get();
    coro = flb_coro_create(&context);
    if (!TEST_CHECK(coro != NULL)) {
        goto cleanup_events;
    }
    coro->callee = co_create(test_env_config->coro_stack_size, write_vectors_async, &stack_size);
    if (!TEST_CHECK(coro->callee != NULL)) {
        flb_coro_destroy(coro);
        goto cleanup_events;
    }
#ifdef FLB_HAVE_VALGRIND
    coro->valgrind_stack_id = VALGRIND_STACK_REGISTER(
                                 coro->callee, ((char *) coro->callee) + stack_size);
#endif
    flb_coro_resume(coro);
    TEST_CHECK(context.done == FLB_FALSE);
    TEST_CHECK(connection.coroutine == coro);

    /* Resume without draining: exercise EAGAIN after a positive short write. */
    if (!context.done) {
        flb_coro_resume(coro);
        TEST_CHECK(context.done == FLB_FALSE);
    }

    received = 0;
    iterations = 0;
    while (iterations++ < 1000) {
        while (received < length) {
            bytes = recv(pair[1], output + received, length - received, 0);
            if (bytes <= 0) {
                TEST_CHECK(bytes == -1 && FLB_WOULDBLOCK());
                break;
            }
            received += bytes;
        }
        if (context.done) {
            break;
        }
        if (cancel) {
            connection.net_error = ETIMEDOUT;
        }
        else {
            TEST_CHECK(mk_event_wait_2(connection.evl, 1000) > 0);
        }
        flb_coro_resume(coro);
    }
    TEST_CHECK(context.done == FLB_TRUE);
    TEST_CHECK(connection.coroutine == NULL);
    TEST_CHECK(MK_EVENT_IS_REGISTERED((&connection.event)));
    TEST_CHECK(connection.event.mask == MK_EVENT_READ);
    TEST_CHECK(connection.event.type == MK_EVENT_CUSTOM);
    TEST_CHECK(context.written == received);
    TEST_CHECK(memcmp(payload, output, received) == 0);
    if (cancel) {
        TEST_CHECK(context.result == -1);
        TEST_CHECK(received > 0 && received < length);
    }
    else {
        TEST_CHECK(context.result > 0);
        TEST_CHECK(received == length);
    }
    flb_coro_set(parent);
    flb_coro_destroy(coro);

cleanup_events:
    mk_event_del(connection.evl, &connection.event);
    mk_event_loop_destroy(connection.evl);
cleanup_sockets:
    flb_socket_close(pair[0]);
    flb_socket_close(pair[1]);
    free(payload);
    free(output);
}

static void test_writev_async_partial(void)
{
    check_writev_async(FLB_FALSE);
}

static void test_writev_async_error(void)
{
    check_writev_async(FLB_TRUE);
}

#ifdef FLB_HAVE_TLS
struct tls_writer_context {
    const char *expected;
    const void *retry_data;
    size_t retry_length;
    size_t written;
    size_t fail_after;
    int calls;
};

static int tls_write_vectors(struct flb_tls_session *session, const void *data, size_t length)
{
    struct tls_writer_context *context;

    context = session->ptr;
    context->calls++;
    TEST_CHECK(length <= FLB_IO_WRITEV_COALESCE_MAX);
    TEST_CHECK(memcmp(data, context->expected + context->written, length) == 0);

    if (context->calls == 1) {
        context->retry_data = data;
        context->retry_length = length;
        return FLB_TLS_WANT_WRITE;
    }
    if (context->calls <= 3) {
        TEST_CHECK(data == context->retry_data);
        TEST_CHECK(length == context->retry_length);
        if (context->calls == 2) {
            return FLB_TLS_WANT_READ;
        }
    }
    if (context->fail_after > 0) {
        if (context->written == context->fail_after) {
            errno = ECONNRESET;
            return -1;
        }
        if (length > context->fail_after - context->written) {
            length = context->fail_after - context->written;
        }
    }
    context->written += length;
    return length;
}

static void test_writev_tls_batching(void)
{
    int result;
    int fail;
    int proxy;
    size_t index;
    size_t length;
    size_t written;
    char *payload;
    struct flb_stream stream;
    struct flb_connection connection;
    struct flb_iovec iov[4];
    struct flb_tls tls;
    struct flb_tls_session session;
    struct flb_tls_backend backend;
    struct tls_writer_context context;

    length = 2 * FLB_IO_WRITEV_COALESCE_MAX + 7;
    payload = malloc(length);
    if (!TEST_CHECK(payload != NULL)) {
        return;
    }
    for (index = 0; index < length; index++) {
        payload[index] = (char) (index % 251);
    }
    memset(&backend, 0, sizeof(backend));
    memset(&tls, 0, sizeof(tls));
    backend.net_write = tls_write_vectors;
    tls.api = &backend;
    setup_connection(&connection, &stream, INT_MAX);
    connection.tls_session = &session;
    session.tls = &tls;
    session.connection = &connection;
    session.ptr = &context;
    iov[0].iov_base = payload;
    iov[0].iov_len = 13;
    iov[1].iov_base = NULL;
    iov[1].iov_len = 0;
    iov[2].iov_base = payload + 13;
    iov[2].iov_len = FLB_IO_WRITEV_COALESCE_MAX;
    iov[3].iov_base = payload + 13 + FLB_IO_WRITEV_COALESCE_MAX;
    iov[3].iov_len = length - 13 - FLB_IO_WRITEV_COALESCE_MAX;

    for (proxy = 0; proxy <= 1; proxy++) {
        stream.flags = proxy ? 0 : FLB_IO_TLS;
        connection.flags = proxy ? FLB_IO_PROXY_TLS : 0;
        for (fail = 0; fail <= 1; fail++) {
            memset(&context, 0, sizeof(context));
            context.expected = payload;
            context.fail_after = fail ? FLB_IO_WRITEV_COALESCE_MAX + 17 : 0;
            result = flb_io_net_writev(&connection, iov, 4, &written);
            TEST_CHECK(written == context.written);
            if (fail) {
                TEST_CHECK(result == -1);
                TEST_CHECK(errno == ECONNRESET);
                TEST_CHECK(written == context.fail_after);
            }
            else {
                TEST_CHECK(result > 0);
                TEST_CHECK(written == length);
                TEST_CHECK(context.calls == 5);
            }
        }
    }
    free(payload);
}
#endif

TEST_LIST = {
    { "writev_preconditions", test_writev_preconditions },
    { "writev_empty_vectors", test_writev_empty_vectors },
    { "writev_transport_error", test_writev_transport_error },
    { "writev_vector_shapes", test_writev_vector_shapes },
    { "writev_coalesce_boundary", test_writev_coalesce_boundary },
    { "writev_async_partial", test_writev_async_partial },
    { "writev_async_error", test_writev_async_error },
#ifdef FLB_HAVE_TLS
    { "writev_tls_batching", test_writev_tls_batching },
#endif
    { 0 }
};
