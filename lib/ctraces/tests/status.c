/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* Copyright 2026 The CTraces Authors. Licensed under the Apache License, Version 2.0. */

#include <limits.h>
#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>
#include <fluent-otel-proto/fluent-otel.h>
#include "ctr_tests.h"

static const int status_codes[] = {0, 1, 2, 3, 12345, -1, -12345, INT32_MIN, INT32_MAX};

static struct ctrace_span *first_span(struct ctrace *ctx)
{
    TEST_ASSERT(ctx != NULL);
    TEST_ASSERT(!cfl_list_is_empty(&ctx->span_list));
    return cfl_list_entry(ctx->span_list.next, struct ctrace_span, _head_global);
}

static struct ctrace *make_trace(struct ctrace_span **span)
{
    struct ctrace *ctx;
    struct ctrace_resource_span *rs;
    struct ctrace_scope_span *ss;

    ctx = ctr_create(NULL);
    TEST_ASSERT(ctx != NULL);
    rs = ctr_resource_span_create(ctx);
    TEST_ASSERT(rs != NULL);
    ss = ctr_scope_span_create(rs);
    TEST_ASSERT(ss != NULL);
    *span = ctr_span_create(ctx, ss, "status", NULL);
    TEST_ASSERT(*span != NULL);
    return ctx;
}

static void check_status(struct ctrace *ctx, int code, const char *message)
{
    struct ctrace_span *span = first_span(ctx);

    TEST_CHECK(span->status.code == code);
    if (message == NULL) {
        TEST_CHECK(span->status.message == NULL);
    }
    else {
        TEST_ASSERT(span->status.message != NULL);
        TEST_CHECK(strcmp(span->status.message, message) == 0);
    }
}

/* Forward in both directions across the formats to exercise received telemetry. */
static void check_roundtrip(struct ctrace *ctx, int code, const char *message)
{
    char *msgpack;
    cfl_sds_t protobuf;
    size_t size;
    size_t offset;
    struct ctrace *decoded;
    struct ctrace *forwarded;

    protobuf = ctr_encode_opentelemetry_create(ctx);
    TEST_ASSERT(protobuf != NULL);
    offset = 0;
    TEST_ASSERT(ctr_decode_opentelemetry_create(&decoded, protobuf,
                cfl_sds_len(protobuf), &offset) == 0);
    /* Proto3 strings map an absent message to the empty string. */
    check_status(decoded, code, message == NULL ? "" : message);
    ctr_encode_opentelemetry_destroy(protobuf);

    TEST_ASSERT(ctr_encode_msgpack_create(decoded, &msgpack, &size) == 0);
    offset = 0;
    TEST_ASSERT(ctr_decode_msgpack_create(&forwarded, msgpack, size, &offset) == 0);
    check_status(forwarded, code, message == NULL ? "" : message);
    ctr_encode_msgpack_destroy(msgpack);
    ctr_destroy(decoded);
    ctr_destroy(forwarded);

    TEST_ASSERT(ctr_encode_msgpack_create(ctx, &msgpack, &size) == 0);
    offset = 0;
    TEST_ASSERT(ctr_decode_msgpack_create(&decoded, msgpack, size, &offset) == 0);
    check_status(decoded, code, message);
    ctr_encode_msgpack_destroy(msgpack);

    protobuf = ctr_encode_opentelemetry_create(decoded);
    TEST_ASSERT(protobuf != NULL);
    offset = 0;
    TEST_ASSERT(ctr_decode_opentelemetry_create(&forwarded, protobuf,
                cfl_sds_len(protobuf), &offset) == 0);
    check_status(forwarded, code, message == NULL ? "" : message);
    ctr_encode_opentelemetry_destroy(protobuf);
    ctr_destroy(decoded);
    ctr_destroy(forwarded);
}

static void test_status_updates(void)
{
    struct ctrace *ctx;
    struct ctrace_span *span;
    char message[2048];
    char expected[64];
    cfl_sds_t text;
    size_t index;

    TEST_CHECK(ctr_span_set_status(NULL, 3, "message") == -1);
    TEST_CHECK(ctr_span_set_status(NULL, -1, NULL) == -1);
    ctx = make_trace(&span);
    memset(message, 'm', sizeof(message) - 1);
    message[sizeof(message) - 1] = '\0';

    for (index = 0; index < sizeof(status_codes) / sizeof(status_codes[0]); index++) {
        TEST_ASSERT(ctr_span_set_status(span, status_codes[index], message) == 0);
        check_status(ctx, status_codes[index], message);
        check_roundtrip(ctx, status_codes[index], message);
        /* A self-update must copy before destroying the previous message. */
        TEST_ASSERT(ctr_span_set_status(span, status_codes[index], span->status.message) == 0);
        check_status(ctx, status_codes[index], message);
        text = ctr_encode_text_create(ctx);
        TEST_ASSERT(text != NULL);
        snprintf(expected, sizeof(expected), "- code    : %i\n", status_codes[index]);
        TEST_CHECK(strstr(text, expected) != NULL);
        TEST_CHECK(strstr(text, message) != NULL);
        ctr_encode_text_destroy(text);

        TEST_ASSERT(ctr_span_set_status(span, status_codes[index], "") == 0);
        check_roundtrip(ctx, status_codes[index], "");
        TEST_ASSERT(ctr_span_set_status(span, status_codes[index], NULL) == 0);
        check_roundtrip(ctx, status_codes[index], NULL);
    }
    ctr_destroy(ctx);
}

/* Minimal decoder input with the message first, so rejection also tests cleanup. */
static char *status_payload(int64_t code, int invalid_type, size_t *size)
{
    mpack_writer_t writer;
    char *buffer;

    mpack_writer_init_growable(&writer, &buffer, size);
    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "resourceSpans");
    mpack_start_array(&writer, 1);
    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "scope_spans");
    mpack_start_array(&writer, 1);
    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "spans");
    mpack_start_array(&writer, 1);
    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "status");
    mpack_start_map(&writer, 2);
    mpack_write_cstr(&writer, "message");
    mpack_write_cstr(&writer, "preserve received message");
    mpack_write_cstr(&writer, "code");
    if (invalid_type == 1) {
        mpack_write_cstr(&writer, "3");
    }
    else if (invalid_type == 2) {
        mpack_write_u64(&writer, UINT64_MAX);
    }
    else {
        mpack_write_i64(&writer, code);
    }
    mpack_finish_map(&writer);
    mpack_finish_map(&writer);
    mpack_finish_array(&writer);
    mpack_finish_map(&writer);
    mpack_finish_array(&writer);
    mpack_finish_map(&writer);
    mpack_finish_array(&writer);
    mpack_finish_map(&writer);
    TEST_ASSERT(mpack_writer_destroy(&writer) == mpack_ok);
    return buffer;
}

static void test_status_rejected_input(void)
{
    const int64_t codes[] = {(int64_t) INT32_MIN - 1, (int64_t) INT32_MAX + 1, INT64_MIN, INT64_MAX, 3, 3};
    char *buffer;
    size_t size;
    size_t offset;
    size_t index;
    struct ctrace *decoded;

    for (index = 0; index < sizeof(codes) / sizeof(codes[0]); index++) {
        buffer = status_payload(codes[index], index >= 4 ? (int) index - 3 : 0, &size);
        offset = 0;
        decoded = NULL;
        TEST_CHECK(ctr_decode_msgpack_create(&decoded, buffer, size, &offset) != 0);
        TEST_CHECK(decoded == NULL);
        free(buffer);
        /* Recovery with the same output argument after each rejected payload. */
        buffer = status_payload(-1, 0, &size);
        offset = 0;
        TEST_ASSERT(ctr_decode_msgpack_create(&decoded, buffer, size, &offset) == 0);
        check_status(decoded, -1, "preserve received message");
        check_roundtrip(decoded, -1, "preserve received message");
        ctr_destroy(decoded);
        free(buffer);
    }
}

#ifdef CTR_TEST_ALLOC_WRAP
static size_t fail_malloc_size;
static size_t fail_calloc_size;
static int failures;
void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);

void *__wrap_malloc(size_t size)
{
    if (fail_malloc_size != 0 && size == fail_malloc_size) {
        fail_malloc_size = 0;
        failures++;
        return NULL;
    }
    return __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size)
{
    if (fail_calloc_size != 0 && count == 1 && size == fail_calloc_size) {
        fail_calloc_size = 0;
        failures++;
        return NULL;
    }
    return __real_calloc(count, size);
}

static void test_status_allocation_failure(void)
{
    struct ctrace *ctx;
    struct ctrace *decoded;
    struct ctrace_span *span;
    cfl_sds_t old_message;
    cfl_sds_t protobuf;
    char *buffer;
    char message[2048];
    size_t size;
    size_t offset;
    int ret;

    ctx = make_trace(&span);
    TEST_ASSERT(ctr_span_set_status(span, -1, "previous") == 0);
    old_message = span->status.message;
    memset(message, 'f', sizeof(message) - 1);
    message[sizeof(message) - 1] = '\0';
    failures = 0;
    fail_malloc_size = CFL_SDS_HEADER_SIZE + sizeof(message);
    ret = ctr_span_set_status(span, INT32_MAX, message);
    fail_malloc_size = 0;
    TEST_CHECK(ret == -1);
    TEST_CHECK(failures == 1);
    TEST_CHECK(span->status.message == old_message);
    check_status(ctx, -1, "previous");
    check_roundtrip(ctx, -1, "previous");
    TEST_ASSERT(ctr_span_set_status(span, INT32_MIN, message) == 0);

    failures = 0;
    fail_calloc_size = sizeof(Opentelemetry__Proto__Trace__V1__Status);
    protobuf = ctr_encode_opentelemetry_create(ctx);
    fail_calloc_size = 0;
    TEST_CHECK(protobuf == NULL);
    TEST_CHECK(failures == 1);
    check_status(ctx, INT32_MIN, message);

    protobuf = ctr_encode_opentelemetry_create(ctx);
    TEST_ASSERT(protobuf != NULL);
    failures = 0;
    fail_malloc_size = CFL_SDS_HEADER_SIZE + sizeof(message);
    offset = 0;
    ret = ctr_decode_opentelemetry_create(&decoded, protobuf, cfl_sds_len(protobuf), &offset);
    fail_malloc_size = 0;
    TEST_CHECK(ret != 0);
    TEST_CHECK(failures == 1);
    TEST_CHECK(decoded == NULL);
    offset = 0;
    TEST_ASSERT(ctr_decode_opentelemetry_create(&decoded, protobuf, cfl_sds_len(protobuf), &offset) == 0);
    check_status(decoded, INT32_MIN, message);
    ctr_destroy(decoded);
    ctr_encode_opentelemetry_destroy(protobuf);

    TEST_ASSERT(ctr_encode_msgpack_create(ctx, &buffer, &size) == 0);
    failures = 0;
    /* MessagePack reserves one additional byte when allocating a string SDS. */
    fail_malloc_size = CFL_SDS_HEADER_SIZE + sizeof(message) + 1;
    offset = 0;
    ret = ctr_decode_msgpack_create(&decoded, buffer, size, &offset);
    fail_malloc_size = 0;
    TEST_CHECK(ret != 0);
    TEST_CHECK(failures == 1);
    TEST_CHECK(decoded == NULL);
    offset = 0;
    TEST_ASSERT(ctr_decode_msgpack_create(&decoded, buffer, size, &offset) == 0);
    check_status(decoded, INT32_MIN, message);
    ctr_destroy(decoded);
    ctr_encode_msgpack_destroy(buffer);
    check_roundtrip(ctx, INT32_MIN, message);
    ctr_destroy(ctx);
}
#endif

TEST_LIST = {
    {"status_updates", test_status_updates},
    {"status_rejected_input", test_status_rejected_input},
#ifdef CTR_TEST_ALLOC_WRAP
    {"status_allocation_failure", test_status_allocation_failure},
#endif
    {0}
};
