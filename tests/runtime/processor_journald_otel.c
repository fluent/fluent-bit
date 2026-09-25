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

#include <fluent-bit.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_conditionals.h>
#include "flb_tests_runtime.h"

struct result {
    void *buffer;
    size_t size;
    struct flb_log_event_decoder decoder;
};

static struct result process(char *json, int lowercase, int strip, int repeat)
{
    int ret;
    int root_type;
    int i;
    char *input = NULL;
    size_t size;
    struct flb_config *config;
    struct flb_processor *processor;
    struct flb_processor_unit *unit;
    struct result result = {0};

    flb_init_env();
    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    processor = flb_processor_create(config, "journald_test", NULL, 0);
    TEST_ASSERT(processor != NULL);
    if (repeat < 0) {
        unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS,
                                         "opentelemetry_envelope");
        TEST_ASSERT(unit != NULL);
        repeat = 1;
    }
    for (i = 0; i < repeat; i++) {
        unit = flb_processor_unit_create(processor, FLB_PROCESSOR_LOGS, "journald_otel");
        TEST_ASSERT(unit != NULL);
        TEST_CHECK(flb_processor_unit_set_property_str(unit, "lowercase",
                                                       lowercase ? "true" : "false") == 0);
        TEST_CHECK(flb_processor_unit_set_property_str(unit, "strip_underscores",
                                                       strip ? "true" : "false") == 0);
        if (lowercase == 2) {
            unit->condition = flb_condition_create(FLB_COND_OP_AND);
            TEST_ASSERT(unit->condition != NULL);
            TEST_ASSERT(flb_condition_add_rule(unit->condition, "$message", FLB_RULE_OP_EQ,
                                               "map", 0, RECORD_CONTEXT_BODY) == FLB_TRUE);
        }
    }
    TEST_ASSERT(flb_processor_init(processor) == 0);
    TEST_ASSERT(flb_pack_json(json, strlen(json), &input, &size, &root_type, NULL) == 0);
    ret = flb_processor_run(processor, 0, FLB_PROCESSOR_LOGS, "test", 4,
                            input, size, &result.buffer, &result.size);
    TEST_ASSERT(ret == 0);
    if (input != result.buffer) {
        flb_free(input);
    }
    flb_processor_destroy(processor);
    flb_config_exit(config);
    TEST_ASSERT(flb_log_event_decoder_init(&result.decoder, result.buffer, result.size) == 0);
    return result;
}

static void destroy_result(struct result *result)
{
    flb_log_event_decoder_destroy(&result->decoder);
    flb_free(result->buffer);
}

static msgpack_object *get(msgpack_object *map, char *key)
{
    size_t i;
    msgpack_object_kv *pair;

    TEST_ASSERT(map != NULL);
    TEST_ASSERT(map->type == MSGPACK_OBJECT_MAP);
    for (i = 0; i < map->via.map.size; i++) {
        pair = &map->via.map.ptr[i];
        if (pair->key.type == MSGPACK_OBJECT_STR && pair->key.via.str.size == strlen(key) &&
            memcmp(pair->key.via.str.ptr, key, strlen(key)) == 0) {
            return &pair->val;
        }
    }
    return NULL;
}

static void string_equals(msgpack_object *value, char *expected)
{
    TEST_ASSERT(value != NULL);
    TEST_ASSERT(value->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(value->via.str.size == strlen(expected));
    TEST_CHECK(value->via.str.size == strlen(expected) &&
               memcmp(value->via.str.ptr, expected, strlen(expected)) == 0);
}

static void number_equals(msgpack_object *value, uint64_t expected)
{
    TEST_ASSERT(value != NULL);
    TEST_ASSERT(value->type == MSGPACK_OBJECT_POSITIVE_INTEGER);
    TEST_CHECK(value->via.u64 == expected);
}

static msgpack_object *attributes(struct flb_log_event *event)
{
    return get(get(event->metadata, "otlp"), "attributes");
}

static msgpack_object *resource(struct flb_log_event *event)
{
    return get(get(event->group_attributes, "resource"), "attributes");
}

static void mapping(void)
{
    struct result result;
    struct flb_log_event event;
    msgpack_object *attrs;
    msgpack_object *res;
    msgpack_object *otlp;

    result = process("[123,{\"MESSAGE\":\"hello\",\"PRIORITY\":\"3\","
                     "\"_HOSTNAME\":\"host-a\",\"_PID\":\"42\",\"_COMM\":\"app\","
                     "\"_EXE\":\"/bin/app\",\"_CMDLINE\":\"app -v\","
                     "\"CODE_FILE\":\"app.c\",\"CODE_FUNC\":\"main\",\"CODE_LINE\":\"10\","
                     "\"SYSLOG_FACILITY\":\"3\",\"SYSLOG_IDENTIFIER\":\"client\","
                     "\"SYSLOG_PID\":\"99\",\"SYSLOG_TIMESTAMP\":\"Sep 8 10:00:00\","
                     "\"_SYSTEMD_UNIT\":\"app.service\",\"EXTRA\":[\"a\",\"b\"]}]", 0, 0, 1);
    TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
    string_equals(get(event.body, "message"), "hello");
    TEST_CHECK(event.body->via.map.size == 1);
    otlp = get(event.metadata, "otlp");
    number_equals(get(otlp, "severity_number"), 17);
    string_equals(get(otlp, "severity_text"), "err");
    number_equals(get(otlp, "timestamp"), 123000000000ULL);
    TEST_CHECK(event.timestamp.tm.tv_sec == 123);
    attrs = attributes(&event);
    res = resource(&event);
    string_equals(get(res, "host.name"), "host-a");
    number_equals(get(res, "process.pid"), 42);
    string_equals(get(res, "process.executable.name"), "app");
    string_equals(get(res, "process.executable.path"), "/bin/app");
    string_equals(get(res, "process.command_line"), "app -v");
    TEST_CHECK(get(res, "service.name") == NULL);
    string_equals(get(attrs, "code.file.path"), "app.c");
    string_equals(get(attrs, "code.function.name"), "main");
    number_equals(get(attrs, "code.line.number"), 10);
    number_equals(get(attrs, "syslog.facility.code"), 3);
    number_equals(get(attrs, "syslog.pid"), 99);
    string_equals(get(attrs, "syslog.identifier"), "client");
    string_equals(get(attrs, "syslog.timestamp"), "Sep 8 10:00:00");
    string_equals(get(attrs, "journald._SYSTEMD_UNIT"), "app.service");
    TEST_ASSERT(get(attrs, "journald.EXTRA") != NULL);
    TEST_CHECK(get(attrs, "journald.EXTRA")->type == MSGPACK_OBJECT_ARRAY);
    TEST_CHECK(flb_log_event_decoder_next(&result.decoder, &event) != 0);
    destroy_result(&result);
}

static void severity(void)
{
    int i;
    int numeric;
    int expected[] = {21, 19, 18, 17, 13, 10, 9, 5};
    char json[128];
    struct result result;
    struct flb_log_event event;

    for (numeric = 0; numeric < 2; numeric++) {
        for (i = 0; i < 8; i++) {
            snprintf(json, sizeof(json), numeric ? "[1,{\"PRIORITY\":%d}]" :
                     "[1,{\"PRIORITY\":\"%d\"}]", i);
            result = process(json, 0, 0, 1);
            TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
            number_equals(get(get(event.metadata, "otlp"), "severity_number"), expected[i]);
            TEST_CHECK(event.body->via.map.size == 0);
            destroy_result(&result);
        }
    }
}

static void malformed_numbers(void)
{
    size_t i;
    char json[512];
    char *values[] = {"\"\"", "\"-1\"", "\" 3\"", "\"+3\"", "\"3x\"",
                      "\"3\\u0000x\"", "\"18446744073709551616\"", "null", "[]", "{}", "1.5"};
    struct result result;
    struct flb_log_event event;
    msgpack_object *attrs;

    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        snprintf(json, sizeof(json), "[1,{\"PRIORITY\":%s,\"_PID\":%s,"
                 "\"CODE_LINE\":%s,\"__REALTIME_TIMESTAMP\":%s}]",
                 values[i], values[i], values[i], values[i]);
        result = process(json, 0, 0, 1);
        TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
        attrs = attributes(&event);
        TEST_CHECK(get(attrs, "journald.PRIORITY") != NULL);
        TEST_CHECK(get(attrs, "journald._PID") != NULL);
        TEST_CHECK(get(attrs, "journald.CODE_LINE") != NULL);
        TEST_CHECK(get(attrs, "journald.__REALTIME_TIMESTAMP") != NULL);
        TEST_CHECK(get(resource(&event), "process.pid") == NULL);
        TEST_CHECK(get(get(event.metadata, "otlp"), "severity_number") == NULL);
        number_equals(get(get(event.metadata, "otlp"), "timestamp"), 1000000000);
        destroy_result(&result);
    }
}

static void resource_isolation_and_repeat(void)
{
    int i;
    struct result result;
    struct flb_log_event event;

    result = process("[1,{\"MESSAGE\":\"first\",\"_PID\":\"42\"}]"
                     "[2,{\"MESSAGE\":\"second\",\"_PID\":\"43\"}]"
                     "[3,{\"MESSAGE\":\"third\"}]", 0, 0, 2);
    for (i = 0; i < 3; i++) {
        TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
        TEST_CHECK(event.timestamp.tm.tv_sec == i + 1);
        if (i < 2) {
            number_equals(get(resource(&event), "process.pid"), 42 + i);
        }
        else {
            TEST_CHECK(get(resource(&event), "process.pid") == NULL);
        }
        TEST_CHECK(attributes(&event) == NULL);
    }
    TEST_CHECK(flb_log_event_decoder_next(&result.decoder, &event) != 0);
    destroy_result(&result);
}

static void field_options(void)
{
    int lower;
    int strip;
    char json[256];
    struct result result;
    struct flb_log_event event;

    for (lower = 0; lower < 2; lower++) {
        for (strip = 0; strip < 2; strip++) {
            snprintf(json, sizeof(json), "[1,{\"%s\":\"hello\",\"%s%s\":\"host\","
                     "\"%s%s\":\"0\"}]", lower ? "message" : "MESSAGE",
                     strip ? "" : "_", lower ? "hostname" : "HOSTNAME",
                     strip ? "" : "_", lower ? "pid" : "PID");
            result = process(json, lower, strip, 1);
            TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
            string_equals(get(event.body, "message"), "hello");
            string_equals(get(resource(&event), "host.name"), "host");
            number_equals(get(resource(&event), "process.pid"), 0);
            destroy_result(&result);
        }
    }
}

static void timestamp_and_limits(void)
{
    struct result result;
    struct flb_log_event event;

    result = process("[1,{\"__REALTIME_TIMESTAMP\":\"1700000000123456\","
                     "\"_PID\":\"9223372036854775807\",\"SYSLOG_PID\":\"9223372036854775808\","
                     "\"PRIORITY\":8}]", 0, 0, 1);
    TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
    TEST_CHECK(event.timestamp.tm.tv_sec == 1700000000);
    TEST_CHECK(event.timestamp.tm.tv_nsec == 123456000);
    number_equals(get(get(event.metadata, "otlp"), "timestamp"), 1700000000123456000ULL);
    number_equals(get(resource(&event), "process.pid"), INT64_MAX);
    string_equals(get(attributes(&event), "journald.SYSLOG_PID"), "9223372036854775808");
    number_equals(get(attributes(&event), "journald.PRIORITY"), 8);
    destroy_result(&result);
}

static void existing_metadata(void)
{
    struct result result;
    struct flb_log_event event;

    result = process("[[1,{\"custom\":\"keep\"}],{\"MESSAGE\":\"hello\"}]"
                     "[[2,{\"otlp\":{\"severity_number\":9}}],{\"message\":\"mapped\"}]", 0, 0, 1);
    TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
    string_equals(get(event.metadata, "custom"), "keep");
    TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
    string_equals(get(event.body, "message"), "mapped");
    number_equals(get(get(event.metadata, "otlp"), "severity_number"), 9);
    destroy_result(&result);
}

static void conditional_mapping(void)
{
    struct result result;
    struct flb_log_event event;

    result = process("[1,{\"message\":\"skip\"}]"
                     "[2,{\"message\":\"map\",\"_pid\":\"42\"}]"
                     "[3,{\"message\":\"skip\"}]", 2, 0, 1);
    TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
    TEST_CHECK(get(event.metadata, "otlp") == NULL);
    TEST_CHECK(event.group_attributes == NULL);
    TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
    number_equals(get(resource(&event), "process.pid"), 42);
    TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
    TEST_CHECK(get(event.metadata, "otlp") == NULL);
    TEST_CHECK(event.group_attributes == NULL);
    destroy_result(&result);
}

#ifdef JOURNALD_TEST_ENVELOPE
static void existing_envelope(void)
{
    int i;
    struct result result;
    struct flb_log_event event;

    /* A preceding processor's new group may have no per-record group pointers. */
    for (i = 0; i < 2; i++) {
        result = process("[1,{\"message\":\"map\",\"_pid\":\"42\"}]",
                         i == 0 ? 1 : 2, 0, -1);
        TEST_ASSERT(flb_log_event_decoder_next(&result.decoder, &event) == 0);
        string_equals(get(event.body, "_pid"), "42");
        TEST_CHECK(get(event.metadata, "otlp") == NULL);
        TEST_ASSERT(event.group_attributes != NULL);
        TEST_CHECK(flb_log_event_decoder_next(&result.decoder, &event) != 0);
        destroy_result(&result);
    }
}
#endif

TEST_LIST = {
    {"mapping", mapping},
    {"severity", severity},
    {"malformed_numbers", malformed_numbers},
    {"resource_isolation_and_repeat", resource_isolation_and_repeat},
    {"field_options", field_options},
    {"timestamp_and_limits", timestamp_and_limits},
    {"existing_metadata", existing_metadata},
    {"conditional_mapping", conditional_mapping},
#ifdef JOURNALD_TEST_ENVELOPE
    {"existing_envelope", existing_envelope},
#endif
    {NULL, NULL}
};
