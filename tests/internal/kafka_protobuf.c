/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <string.h>
#include "flb_tests_internal.h"
#include "kafka_protobuf.h"

static struct flb_kafka_protobuf *make_schema(const char *schema, const char *message)
{
    int ret;
    char error[512] = {0};
    struct flb_kafka_protobuf *ctx;

    ctx = flb_kafka_protobuf_create();
    TEST_ASSERT(ctx != NULL);
    ret = flb_kafka_protobuf_add(ctx, FLB_KAFKA_PROTOBUF_ROOT, schema, strlen(schema));
    TEST_ASSERT(ret == 0);
    ret = flb_kafka_protobuf_compile(ctx, message, error, sizeof(error));
    TEST_CHECK(ret == 0);
    TEST_MSG("%s", error);
    return ctx;
}

static void test_frame_and_payload(void)
{
    int ret;
    size_t size;
    char *payload;
    char error[512];
    const char json[] = "{\"value\":\"hi\"}";
    const unsigned char expected[] = {0, 0, 0, 0, 42, 0, 10, 2, 'h', 'i'};
    struct flb_kafka_protobuf *ctx;

    ctx = make_schema("syntax = \"proto3\"; message Event { string value = 1; }", NULL);
    ret = flb_kafka_protobuf_encode(ctx, 42, json, strlen(json),
                                    &payload, &size, error, sizeof(error));
    TEST_CHECK(ret == 0);
    TEST_CHECK(size == sizeof(expected));
    if (payload != NULL && size == sizeof(expected)) {
        TEST_CHECK(memcmp(payload, expected, size) == 0);
    }
    flb_kafka_protobuf_free(payload);
    flb_kafka_protobuf_destroy(ctx);
}

static void test_nested_indexes(void)
{
    int ret;
    size_t size;
    char *payload;
    char error[512];
    const unsigned char expected[] = {0, 1, 2, 3, 4, 4, 2, 2, 8, 7};
    struct flb_kafka_protobuf *ctx;

    ctx = make_schema("syntax = \"proto3\"; package logs; message First {} "
                      "message Outer { map<string, string> labels = 1; "
                      "message FirstChild {} message Event { int32 value = 1; } }",
                      "logs.Outer.Event");
    ret = flb_kafka_protobuf_encode(ctx, 0x01020304, "{\"value\":7}", 11,
                                    &payload, &size, error, sizeof(error));
    TEST_CHECK(ret == 0);
    TEST_CHECK(size == sizeof(expected));
    if (payload != NULL && size == sizeof(expected)) {
        TEST_CHECK(memcmp(payload, expected, size) == 0);
    }
    flb_kafka_protobuf_free(payload);
    flb_kafka_protobuf_destroy(ctx);
}

static void test_reference_and_validation(void)
{
    int ret;
    size_t i;
    size_t size;
    char *payload;
    char error[512];
    struct flb_kafka_protobuf *ctx;
    const char root[] = "syntax = \"proto3\"; import \"child.proto\"; "
                        "message Event { Child child = 1; oneof choice { int32 a = 2; string b = 3; } }";
    const char child[] = "syntax = \"proto3\"; message Child { int32 count = 1; }";
    const char *invalid[] = {"{\"unknown\":7}", "{\"child\":{\"count\":2147483648}}",
                             "{\"a\":1,\"b\":\"two\"}", "{\"a\":1.5}"};
    const unsigned char expected[] = {0, 0, 0, 0, 42, 0, 10, 2, 8, 7};

    ctx = flb_kafka_protobuf_create();
    TEST_ASSERT(ctx != NULL);
    TEST_CHECK(flb_kafka_protobuf_add(ctx, FLB_KAFKA_PROTOBUF_ROOT, root, strlen(root)) == 0);
    TEST_CHECK(flb_kafka_protobuf_add(ctx, "child.proto", child, strlen(child)) == 0);
    TEST_CHECK(flb_kafka_protobuf_add(ctx, "child.proto", "conflict", 8) == -1);
    ret = flb_kafka_protobuf_compile(ctx, NULL, error, sizeof(error));
    TEST_CHECK(ret == 0);
    TEST_MSG("%s", error);
    ret = flb_kafka_protobuf_encode(ctx, 42, "{\"child\":{\"count\":7}}", 21,
                                    &payload, &size, error, sizeof(error));
    TEST_CHECK(ret == 0);
    TEST_MSG("%s", error);
    TEST_CHECK(size == sizeof(expected));
    if (payload != NULL && size == sizeof(expected)) {
        TEST_CHECK(memcmp(payload, expected, size) == 0);
    }
    flb_kafka_protobuf_free(payload);
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        ret = flb_kafka_protobuf_encode(ctx, 42, invalid[i], strlen(invalid[i]),
                                       &payload, &size, error, sizeof(error));
        TEST_CHECK(ret == -1);
        TEST_CHECK(payload == NULL);
        TEST_CHECK(size == 0);
    }
    flb_kafka_protobuf_destroy(ctx);
}

static void test_invalid_schemas(void)
{
    size_t i;
    char error[512];
    struct flb_kafka_protobuf *ctx;
    const char *schemas[] = {"not a schema", "message A {} message B {}",
        "syntax=\"proto3\"; import \"missing.proto\"; message A { Missing value = 1; }"};

    for (i = 0; i < sizeof(schemas) / sizeof(schemas[0]); i++) {
        ctx = flb_kafka_protobuf_create();
        TEST_ASSERT(ctx != NULL);
        TEST_CHECK(flb_kafka_protobuf_add(ctx, FLB_KAFKA_PROTOBUF_ROOT,
                                         schemas[i], strlen(schemas[i])) == 0);
        TEST_CHECK(flb_kafka_protobuf_compile(ctx, NULL, error, sizeof(error)) == -1);
        flb_kafka_protobuf_destroy(ctx);
    }
}

static void test_well_known_type_and_required_field(void)
{
    int ret;
    size_t size;
    char *payload;
    char error[512];
    struct flb_kafka_protobuf *ctx;
    const char json[] = "{\"time\":\"1970-01-01T00:00:00.000000001Z\"}";
    const unsigned char expected[] = {0, 0, 0, 0, 42, 0, 10, 2, 16, 1};

    ctx = make_schema("syntax = \"proto3\"; import \"google/protobuf/timestamp.proto\"; "
                      "message Event { google.protobuf.Timestamp time = 1; }", NULL);
    ret = flb_kafka_protobuf_encode(ctx, 42, json, strlen(json),
                                    &payload, &size, error, sizeof(error));
    TEST_CHECK(ret == 0);
    TEST_MSG("%s", error);
    TEST_CHECK(size == sizeof(expected));
    if (payload != NULL && size == sizeof(expected)) {
        TEST_CHECK(memcmp(payload, expected, size) == 0);
    }
    flb_kafka_protobuf_free(payload);
    flb_kafka_protobuf_destroy(ctx);

    ctx = make_schema("syntax = \"proto2\"; message Event { required string value = 1; }", NULL);
    ret = flb_kafka_protobuf_encode(ctx, 42, "{}", 2, &payload, &size, error, sizeof(error));
    TEST_CHECK(ret == -1);
    TEST_CHECK(payload == NULL);
    flb_kafka_protobuf_destroy(ctx);
}

TEST_LIST = {
    {"frame_and_payload", test_frame_and_payload},
    {"nested_indexes", test_nested_indexes},
    {"reference_and_validation", test_reference_and_validation},
    {"invalid_schemas", test_invalid_schemas},
    {"well_known_type_and_required_field", test_well_known_type_and_required_field},
    {NULL, NULL}
};
