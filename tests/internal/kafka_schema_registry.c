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

#include <fluent-bit/flb_sds.h>

#include "flb_tests_internal.h"
#include "kafka_config.h"

static const char expected_schema[] =
    "{\"type\":\"record\",\"name\":\"registry_test\","
    "\"fields\":[{\"name\":\"message\",\"type\":\"string\"}]}";

static void test_parse_subject_version_response()
{
    int ret;
    struct flb_out_kafka ctx = {0};
    const char response[] =
        "{\"subject\":\"topic-value\",\"id\":42,\"version\":3,"
        "\"schema\":\"{\\\"type\\\":\\\"record\\\","
        "\\\"name\\\":\\\"registry_test\\\","
        "\\\"fields\\\":[{\\\"name\\\":\\\"message\\\","
        "\\\"type\\\":\\\"string\\\"}]}\"}";

    ret = flb_kafka_schema_registry_parse_response(&ctx,
                                                   response,
                                                   sizeof(response) - 1);

    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx.schema_id == 42);
    TEST_CHECK(ctx.schema_str != NULL);
    TEST_CHECK(strcmp(ctx.schema_str, expected_schema) == 0);

    flb_sds_destroy(ctx.schema_str);
}

static void test_parse_schema_id_response()
{
    int ret;
    struct flb_out_kafka ctx = {0};
    const char response[] =
        "{\"schema\":\"{\\\"type\\\":\\\"record\\\","
        "\\\"name\\\":\\\"registry_test\\\","
        "\\\"fields\\\":[{\\\"name\\\":\\\"message\\\","
        "\\\"type\\\":\\\"string\\\"}]}\"}";

    ctx.schema_id = 7;

    ret = flb_kafka_schema_registry_parse_response(&ctx,
                                                   response,
                                                   sizeof(response) - 1);

    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx.schema_id == 7);
    TEST_CHECK(ctx.schema_str != NULL);
    TEST_CHECK(strcmp(ctx.schema_str, expected_schema) == 0);

    flb_sds_destroy(ctx.schema_str);
}

static void test_reject_invalid_response()
{
    size_t i;
    int ret;
    struct flb_output_instance ins = {0};
    struct flb_out_kafka ctx = {0};
    const char *responses[] = {
        "{\"id\":4294967297,\"schema\":\"x\"}",
        "{\"id\":2147483648,\"schema\":\"x\"}",
        "{\"id\":0,\"schema\":\"x\"}",
        "{\"id\":-1,\"schema\":\"x\"}",
        "{\"id\":\"42\",\"schema\":\"x\"}",
        "{\"id\":null,\"schema\":\"x\"}",
        "{\"id\":42.5,\"schema\":\"x\"}",
        "{\"id\":42,\"schema\":\"\"}",
        "{\"id\":42,\"schema\":null}",
        "{\"id\":42}",
        "{\"id\":42,\"schema\":\"x\",\"schemaType\":null}",
        "{\"id\":42,\"schema\":\"x\",\"schemaType\":\"PROTOBUF\"}",
        "{\"id\":42,\"id\":43,\"schema\":\"x\"}",
        "[]",
        "{"
    };

    ctx.ins = &ins;
    ctx.schema_id = 7;
    ctx.schema_str = flb_sds_create(expected_schema);

    for (i = 0; i < sizeof(responses) / sizeof(responses[0]); i++) {
        ret = flb_kafka_schema_registry_parse_response(&ctx, responses[i], strlen(responses[i]));
        TEST_CHECK(ret == -1);
        TEST_MSG("response: %s", responses[i]);
        TEST_CHECK(ctx.schema_id == 7);
        TEST_CHECK(strcmp(ctx.schema_str, expected_schema) == 0);
    }

    flb_sds_destroy(ctx.schema_str);
}

#ifdef FLB_HAVE_PROTOBUF_ENCODER
static void test_reject_invalid_protobuf_document(void)
{
    size_t i;
    int ret;
    struct flb_output_instance ins = {0};
    struct flb_out_kafka ctx = {0};
    const char *responses[] = {
        "{\"schemaType\":\"PROTOBUF\",\"schema\":\"syntax = \\\"proto3\\\"; message Event {}\"}",
        "{\"id\":42,\"schema\":\"syntax = \\\"proto3\\\"; message Event {}\"}",
        "{\"id\":42,\"schemaType\":\"PROTOBUF\"}",
        "{\"id\":42,\"schemaType\":null,\"schema\":\"syntax = \\\"proto3\\\"; message Event {}\"}",
        "{\"id\":42,\"schemaType\":\"AVRO\",\"schema\":\"syntax = \\\"proto3\\\"; message Event {}\"}",
        "{\"id\":42,\"schemaType\":\"PROTOBUF\",\"schema\":3}",
        "{\"id\":42,\"schemaType\":\"PROTOBUF\",\"schema\":\"\"}",
        "{\"id\":-1,\"schemaType\":\"PROTOBUF\",\"schema\":\"syntax = \\\"proto3\\\"; message Event {}\"}",
        "{\"id\":2147483648,\"schemaType\":\"PROTOBUF\",\"schema\":\"syntax = \\\"pro"
        "to3\\\"; message Event {}\"}",
        "{\"id\":42,\"schemaType\":\"PROTOBUF\",\"schema\":\"syntax = \\\"proto3\\\"; m"
        "essage Event {}\",\"references\":{}}",
        "{\"id\":42,\"schemaType\":\"PROTOBUF\",\"schema\":\"syntax = \\\"proto3\\\"; m"
        "essage Event {}\",\"references\":[null]}",
        "{\"id\":42,\"schemaType\":\"PROTOBUF\",\"schema\":\"syntax = \\\"proto3\\\"; m"
        "essage Event {}\",\"references\":[{\"name\":\"\",\"subject\":\"child\",\"vers"
        "ion\":2}]}",
        "{\"id\":42,\"schemaType\":\"PROTOBUF\",\"schema\":\"syntax = \\\"proto3\\\"; m"
        "essage Event {}\",\"references\":[{\"name\":\"__fluent_bit_root.proto\","
        "\"subject\":\"child\",\"version\":2}]}",
        "{\"id\":42,\"schemaType\":\"PROTOBUF\",\"schema\":\"syntax = \\\"proto3\\\"; m"
        "essage Event {}\",\"references\":[{\"name\":\"child.proto\",\"subject\":\"\""
        ",\"version\":2}]}",
        "{\"id\":42,\"schemaType\":\"PROTOBUF\",\"schema\":\"syntax = \\\"proto3\\\"; m"
        "essage Event {}\",\"references\":[{\"name\":\"child.proto\",\"subject\":\"c"
        "hild\",\"version\":0}]}",
        "{\"id\":42,\"schemaType\":\"PROTOBUF\",\"schema\":\"syntax = \\\"proto3\\\"; m"
        "essage Event {}\",\"references\":[{\"name\":\"child.proto\",\"subject\":\"c"
        "hild\",\"version\":2147483648}]}",
        "{\"id\":42,\"schemaType\":\"PROTOBUF\",\"schema\":\"syntax = \\\"proto3\\\"; m"
        "essage Event {}\",\"references\":[{\"name\":\"child.proto\",\"subject\":\"c"
        "hild\",\"version\":\"2\"}]}"
    };

    ctx.ins = &ins;
    ctx.format = FLB_KAFKA_FMT_PROTOBUF;
    ctx.schema_str = flb_sds_create("unchanged");
    for (i = 0; i < sizeof(responses) / sizeof(responses[0]); i++) {
        ret = flb_kafka_schema_registry_parse_response(&ctx, responses[i], strlen(responses[i]));
        TEST_CHECK(ret == -1);
        TEST_MSG("response: %s", responses[i]);
        TEST_CHECK(ctx.schema_id == 0);
        TEST_CHECK(strcmp(ctx.schema_str, "unchanged") == 0);
    }
    flb_sds_destroy(ctx.schema_str);
}
#endif

TEST_LIST = {
    {"parse_subject_version_response", test_parse_subject_version_response},
    {"parse_schema_id_response", test_parse_schema_id_response},
    {"reject_invalid_response", test_reject_invalid_response},
#ifdef FLB_HAVE_PROTOBUF_ENCODER
    {"reject_invalid_protobuf_document", test_reject_invalid_protobuf_document},
#endif
    {NULL, NULL}
};
