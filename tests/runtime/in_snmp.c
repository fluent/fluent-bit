/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <sys/types.h>
#include "flb_tests_runtime.h"

struct callback_record {
    void *data;
    size_t size;
};

struct callback_records {
    int num_records;
    struct callback_record *records;
};

int callback_add_record(void* data, size_t size, void* cb_data)
{
    struct callback_records *ctx = (struct callback_records *)cb_data;

    if (size > 0) {
        flb_info("[test] flush record");
        if (ctx->records == NULL) {
            ctx->records = (struct callback_record *)
                           flb_calloc(1, sizeof(struct callback_record));
        }
        else {
            ctx->records = (struct callback_record *)
                           flb_realloc(ctx->records,
                                       (ctx->num_records + 1) *
                                       sizeof(struct callback_record));
        }

        if (ctx->records == NULL) {
            return -1;
        }

        ctx->records[ctx->num_records].size = size;
        ctx->records[ctx->num_records].data = data;
        ctx->num_records++;
    }
    return 0;
}

void flb_test_snmp_records_message_get(struct callback_records *records)
{
    int i;
    msgpack_unpacked result;
    msgpack_object *obj;
    size_t off = 0;
    struct flb_time ftm;

    TEST_CHECK(records->num_records > 0);

    for (i = 0; i < records->num_records; i++) {
        off = 0;
        msgpack_unpacked_init(&result);
        while (msgpack_unpack_next(&result, records->records[i].data,
                                    records->records[i].size,
                                    &off) == MSGPACK_UNPACK_SUCCESS) {
            flb_time_pop_from_msgpack(&ftm, &result, &obj);
            TEST_CHECK(obj->type == MSGPACK_OBJECT_MAP);
            TEST_CHECK(obj->via.map.size >= 1);
            TEST_CHECK(strncmp("iso.3.6.1.2.1.1.3.0",
                               obj->via.map.ptr[0].key.via.str.ptr,
                               obj->via.map.ptr[0].key.via.str.size) == 0);
            TEST_CHECK(strncmp("123",
                               obj->via.map.ptr[0].val.via.str.ptr,
                               obj->via.map.ptr[0].val.via.str.size) == 0);
        }
        msgpack_unpacked_destroy(&result);
    }
}

void flb_test_snmp_records_message_walk(struct callback_records *records)
{
    int i, j;
    msgpack_unpacked result;
    msgpack_object *obj;
    size_t off = 0;
    struct flb_time ftm;
    msgpack_object key;
    msgpack_object val;
    char expected_keys[2][26] = {
        "iso.3.6.1.2.1.31.1.1.1.1.1",
        "iso.3.6.1.2.1.31.1.1.1.1.2"
    };
    char expected_vals[2][7] = {
        "\"Fa0/0\"",
        "\"Fa0/1\""
    };

    TEST_CHECK(records->num_records > 0);

    for (i = 0; i < records->num_records; i++) {
        off = 0;
        msgpack_unpacked_init(&result);
        while (msgpack_unpack_next(&result, records->records[i].data,
                                    records->records[i].size,
                                    &off) == MSGPACK_UNPACK_SUCCESS) {
            flb_time_pop_from_msgpack(&ftm, &result, &obj);
            TEST_CHECK(obj->type == MSGPACK_OBJECT_MAP);
            {
                size_t count = obj->via.map.size;
                size_t limit;

                TEST_CHECK(count >= 2);
                limit = count < 2 ? count : 2;
                for (j = 0; j < limit; j++) {
                    key = obj->via.map.ptr[j].key;
                    val = obj->via.map.ptr[j].val;
                    TEST_CHECK(strncmp(expected_keys[j], key.via.str.ptr,
                                       26) == 0);
                    TEST_CHECK(strncmp(expected_vals[j], val.via.str.ptr,
                                       7) == 0);
                }
            }
        }
        msgpack_unpacked_destroy(&result);
    }
}

void do_test_records(char *response,
                     void (*records_cb)(struct callback_records *), ...)
{
    flb_ctx_t *ctx = NULL;
    int in_ffd;
    int out_ffd;
    va_list va;
    char *key;
    char *value;
    int i;
    struct flb_lib_out_cb cb;
    struct callback_records *records;

    /* mocks calls- signals that we are in test mode */
    setenv("FLB_SNMP_PLUGIN_UNDER_TEST", "true", 1);
    setenv("TEST_SNMP_RESPONSE", response, 1);

    records = flb_calloc(1, sizeof(struct callback_records));
    if (!records) {
        flb_error("[test] Failed to allocate callback_records");
        return;
    }
    records->num_records = 0;
    records->records = NULL;

    cb.cb = callback_add_record;
    cb.data = (void *)records;

    /* initialize */
    ctx = flb_create();

    in_ffd = flb_input(ctx, "snmp", NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    va_start(va, records_cb);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        TEST_CHECK(value != NULL);
        TEST_CHECK(flb_input_set(ctx, in_ffd, key, value, NULL) == 0);
    }
    va_end(va);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd, "match", "test", NULL) == 0);

    /* Start test */
    TEST_CHECK(flb_start(ctx) == 0);

    /* 5 sec passed. It must have flushed */
    sleep(5);

    records_cb(records);

    flb_stop(ctx);

    for (i = 0; i < records->num_records; i++) {
        flb_lib_free(records->records[i].data);
    }

    flb_free(records->records);
    flb_free(records);
    flb_destroy(ctx);
}

void flb_test_snmp()
{
    do_test_records("snmp_get", flb_test_snmp_records_message_get, NULL);
    do_test_records("snmp_walk", flb_test_snmp_records_message_walk, NULL);
}

/* Test list */
TEST_LIST = {
    {"snmp", flb_test_snmp},
    {NULL, NULL}
};
