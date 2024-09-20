/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_input_plugin.h>

#include "../../plugins/in_ebpf/in_ebpf.h"
#include "flb_tests_runtime.h"

/* Mock initialization for input instance */
struct flb_input_instance *init_mock_instance(struct flb_in_ebpf_config *ctx)
{
    struct flb_input_instance *mock_instance;

    mock_instance = flb_calloc(1, sizeof(struct flb_input_instance));
    if (!mock_instance) {
        printf("Failed to allocate memory for mock_instance\n");
        return NULL;
    }

    mock_instance->context = ctx;

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!ctx->log_encoder) {
        printf("Failed to create log event encoder\n");
        flb_free(mock_instance);
        return NULL;
    }

    return mock_instance;
}

/* Cleanup function for the mock input instance */
void cleanup_mock_instance(struct flb_input_instance *mock_instance)
{
    struct flb_in_ebpf_config *ctx;

    if (mock_instance) {
        ctx = mock_instance->context;
        if (ctx && ctx->log_encoder) {
            flb_log_event_encoder_destroy(ctx->log_encoder);
        }
        flb_free(mock_instance);
    }
}

/* Test 1: Normal encoding with valid data */
void test_encode_log_event_valid()
{
    int ret;
    struct flb_in_ebpf_config ctx;
    struct flb_input_instance *mock_instance = init_mock_instance(&ctx);
    const char *event_type = "test_event";
    __u32 pid = 1234;
    const char *data = "valid_data";
    size_t data_len = strlen(data);

    if (!mock_instance) {
        return; /* Exit if initialization failed */
    }

    ret = encode_log_event(mock_instance, ctx.log_encoder, event_type, pid, data, data_len);
    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx.log_encoder->output_length > 0);
    printf("test_encode_log_event_valid passed\n");

    cleanup_mock_instance(mock_instance);
}

/* Test 2: Encoding with NULL event type */
void test_encode_log_event_null_event_type()
{
    int ret;
    struct flb_in_ebpf_config ctx;
    struct flb_input_instance *mock_instance = init_mock_instance(&ctx);
    __u32 pid = 1234;
    const char *data = "valid_data";
    size_t data_len = strlen(data);

    if (!mock_instance) {
        return; /* Exit if initialization failed */
    }

    ret = encode_log_event(mock_instance, ctx.log_encoder, NULL, pid, data, data_len);
    TEST_CHECK(ret == 0);
    printf("test_encode_log_event_null_event_type passed\n");

    cleanup_mock_instance(mock_instance);
}

/* Test 3: Encoding with zero-length data */
void test_encode_log_event_zero_length_data()
{
    int ret;
    struct flb_in_ebpf_config ctx;
    struct flb_input_instance *mock_instance = init_mock_instance(&ctx);
    const char *event_type = "test_event";
    __u32 pid = 1234;
    const char *data = "";
    size_t data_len = 0;

    if (!mock_instance) {
        return; /* Exit if initialization failed */
    }

    ret = encode_log_event(mock_instance, ctx.log_encoder, event_type, pid, data, data_len);
    TEST_CHECK(ret == 0);
    printf("test_encode_log_event_zero_length_data passed\n");

    cleanup_mock_instance(mock_instance);
}

/* Test 4: Extract event data with structured input */
void test_extract_event_data_structured()
{
    int ret;
    struct flb_in_ebpf_event event;
    strncpy(event.data, "structured_event_data", sizeof(event.data) - 1);
    event.event_type = FLB_IN_EBPF_EVENT_PROCESS;
    event.pid = 5678;

    const char *event_type_str;
    __u32 pid;
    char *event_data;
    size_t event_data_len;

    ret = extract_event_data(&event, sizeof(event), &event_type_str, &pid, &event_data, &event_data_len);
    TEST_CHECK(ret == 0);
    TEST_CHECK(strcmp(event_type_str, FLB_IN_EBPF_EVENT_TYPE_PROCESS) == 0);
    TEST_CHECK(pid == 5678);
    TEST_CHECK(strcmp(event_data, "structured_event_data") == 0);
    printf("test_extract_event_data_structured passed\n");
}

/* Test 5: Extract event data with raw string input */
void test_extract_event_data_raw()
{
    int ret;
    const char *raw_data = "raw_event_data";
    size_t data_sz = strlen(raw_data) + 1;

    const char *event_type_str;
    __u32 pid;
    char *event_data;
    size_t event_data_len;

    ret = extract_event_data((void *)raw_data, data_sz, &event_type_str, &pid, &event_data, &event_data_len);
    TEST_CHECK(ret == 0);
    TEST_CHECK(strcmp(event_type_str, FLB_IN_EBPF_EVENT_TYPE_UNKNOWN) == 0);
    TEST_CHECK(pid == 0);
    TEST_CHECK(strcmp(event_data, "raw_event_data") == 0);
    printf("test_extract_event_data_raw passed\n");
}

/* Test 8: Extract event data with invalid size */
void test_extract_event_data_invalid_size()
{
    int ret;
    struct flb_in_ebpf_event event;
    strncpy(event.data, "invalid_size_event", sizeof(event.data) - 1);
    event.event_type = FLB_IN_EBPF_EVENT_PROCESS;
    event.pid = 1234;

    const char *event_type_str;
    __u32 pid;
    char *event_data;
    size_t event_data_len;

    ret = extract_event_data(&event, sizeof(event) - 1, &event_type_str, &pid, &event_data, &event_data_len);
    TEST_CHECK(ret != 0); /* Expect failure */
    printf("test_extract_event_data_invalid_size passed\n");
}

/* Test 9: Encoding with NULL data */
void test_encode_log_event_null_data()
{
    int ret;
    struct flb_in_ebpf_config ctx;
    struct flb_input_instance *mock_instance = init_mock_instance(&ctx);
    const char *event_type = "test_event";
    __u32 pid = 1234;
    const char *data = NULL;
    size_t data_len = 0;

    if (!mock_instance) {
        return; /* Exit if initialization failed */
    }

    ret = encode_log_event(mock_instance, ctx.log_encoder, event_type, pid, data, data_len);
    TEST_CHECK(ret == 0);
    printf("test_encode_log_event_null_data passed\n");

    cleanup_mock_instance(mock_instance);
}

/* Test 10: Encoding with extremely large data */
void test_encode_log_event_large_data()
{
    int ret;
    struct flb_in_ebpf_config ctx;
    struct flb_input_instance *mock_instance = init_mock_instance(&ctx);
    const char *event_type = "large_event";
    __u32 pid = 4321;
    char large_data[10000];
    memset(large_data, 'A', sizeof(large_data));
    size_t data_len = sizeof(large_data);

    if (!mock_instance) {
        return; /* Exit if initialization failed */
    }

    ret = encode_log_event(mock_instance, ctx.log_encoder, event_type, pid, large_data, data_len);
    TEST_CHECK(ret == 0);
    printf("test_encode_log_event_large_data passed\n");

    cleanup_mock_instance(mock_instance);
}

TEST_LIST = {
    {"encode_log_event_valid", test_encode_log_event_valid},
    {"encode_log_event_null_event_type", test_encode_log_event_null_event_type},
    {"encode_log_event_zero_length_data", test_encode_log_event_zero_length_data},
    {"extract_event_data_structured", test_extract_event_data_structured},
    {"extract_event_data_raw", test_extract_event_data_raw},
    {"extract_event_data_invalid_size", test_extract_event_data_invalid_size},
    {"encode_log_event_null_data", test_encode_log_event_null_data},
    {"encode_log_event_large_data", test_encode_log_event_large_data},
    {NULL, NULL}
};