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
    TEST_CHECK(ctx.avro_fields.schema_id == 42);
    TEST_CHECK(ctx.avro_fields.schema_str != NULL);
    TEST_CHECK(strcmp(ctx.avro_fields.schema_str, expected_schema) == 0);

    flb_sds_destroy(ctx.avro_fields.schema_str);
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

    ctx.avro_fields.schema_id = 7;

    ret = flb_kafka_schema_registry_parse_response(&ctx,
                                                   response,
                                                   sizeof(response) - 1);

    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx.avro_fields.schema_id == 7);
    TEST_CHECK(ctx.avro_fields.schema_str != NULL);
    TEST_CHECK(strcmp(ctx.avro_fields.schema_str, expected_schema) == 0);

    flb_sds_destroy(ctx.avro_fields.schema_str);
}

TEST_LIST = {
    {"parse_subject_version_response", test_parse_subject_version_response},
    {"parse_schema_id_response", test_parse_schema_id_response},
    {NULL, NULL}
};
