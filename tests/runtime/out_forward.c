/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_record_accessor.h>

#include "flb_tests_runtime.h"

/* Include plugin header to get the flush_ctx structure definition */
#include "../../plugins/out_forward/forward.h"

static void cb_check_message_mode(void *ctx, int ffd,
                                  int res_ret, void *res_data, size_t res_size,
                                  void *data)
{
    int ret;
    size_t off = 0;
    msgpack_object tag;
    msgpack_object ts;
    msgpack_object record;
    msgpack_object root;
    msgpack_unpacked result;
    struct flb_time time = {0};

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    root = result.data;

    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(root.type == MSGPACK_OBJECT_ARRAY);
    TEST_CHECK(root.via.array.size == 4);

    /* Tag */
    tag = root.via.array.ptr[0];
    TEST_CHECK(tag.type == MSGPACK_OBJECT_STR);
    ret = strncmp(tag.via.str.ptr, "new.tag.fluent", tag.via.str.size);
    TEST_CHECK(ret == 0);

    /* Timestamp */
    ts = root.via.array.ptr[1];
    TEST_CHECK(ts.type == MSGPACK_OBJECT_EXT);

    ret = flb_time_msgpack_to_time(&time, &ts);
    TEST_CHECK(ret == 0);
    TEST_CHECK(time.tm.tv_nsec != 0);

    /* Record */
    record = root.via.array.ptr[2];
    TEST_CHECK(record.type == MSGPACK_OBJECT_MAP);
    TEST_CHECK(record.via.map.size == 2);

    msgpack_unpacked_destroy(&result);
    flb_free(res_data);
}

static void cb_check_message_compat_mode(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    int ret;
    size_t off = 0;
    msgpack_object tag;
    msgpack_object ts;
    msgpack_object record;
    msgpack_object root;
    msgpack_unpacked result;
    struct flb_time time = {0};

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    root = result.data;

    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(root.type == MSGPACK_OBJECT_ARRAY);
    TEST_CHECK(root.via.array.size == 4);

    /* Tag */
    tag = root.via.array.ptr[0];
    TEST_CHECK(tag.type == MSGPACK_OBJECT_STR);
    ret = strncmp(tag.via.str.ptr, "new.tag.fluent", tag.via.str.size);
    TEST_CHECK(ret == 0);

    /* Timestamp */
    ts = root.via.array.ptr[1];
    TEST_CHECK(ts.type == MSGPACK_OBJECT_POSITIVE_INTEGER);

    ret = flb_time_msgpack_to_time(&time, &ts);
    TEST_CHECK(ret == 0);
    TEST_CHECK(time.tm.tv_nsec == 0);

    /* Record */
    record = root.via.array.ptr[2];
    TEST_CHECK(record.type == MSGPACK_OBJECT_MAP);
    TEST_CHECK(record.via.map.size == 2);

    msgpack_unpacked_destroy(&result);
    flb_free(res_data);
}

static void cb_check_forward_mode(void *ctx, int ffd,
                                  int res_ret, void *res_data, size_t res_size,
                                  void *data)
{
    int ret;
    size_t off = 0;
    msgpack_object key;
    msgpack_object val;
    msgpack_object root;
    msgpack_unpacked result;

    /*
     * the check for forward mode is a bit special, since no data is formatted, instead the formatter callback
     * will return the "options" map that will be send after the records chunk. The options are set because the
     * caller specified 'send_options true'.
     */
    TEST_CHECK(res_ret == MODE_FORWARD);

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    root = result.data;

    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);

    /* fluent_signal and size */
    TEST_CHECK(root.via.map.size == 2);

    /* Record */
    key = root.via.map.ptr[1].key;
    val = root.via.map.ptr[1].val;

    ret = strncmp(key.via.str.ptr, "fluent_signal", 13);
    TEST_CHECK(ret == 0);
    TEST_CHECK(val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
    TEST_CHECK(val.via.u64 == 0);

    msgpack_unpacked_destroy(&result);
    flb_free(res_data);
}

static void cb_check_forward_compat_mode(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    int ret;
    size_t off = 0;
    msgpack_object root;
    msgpack_object records;
    msgpack_object entry;
    msgpack_unpacked result;

    TEST_CHECK(res_ret == MODE_FORWARD_COMPAT);

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    root = result.data;
    records = root.via.array.ptr[1];

    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(root.type == MSGPACK_OBJECT_ARRAY);

    /* Record */
    entry = records.via.array.ptr[0];
    TEST_CHECK(entry.type == MSGPACK_OBJECT_ARRAY);
    TEST_CHECK(entry.via.array.ptr[0].type == MSGPACK_OBJECT_POSITIVE_INTEGER);

    msgpack_unpacked_destroy(&result);
    flb_free(res_data);
}

void flb_test_message_mode()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "2", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd,
                  "tag", "test",
                  "samples", "1",
                  "dummy", "{\"key1\": 123, \"key2\": {\"s1\": \"fluent\"}}",
                  NULL);


    /* Forward output */
    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag.$key2['s1']",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_message_mode,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_message_compat_mode()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "2", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd,
                  "tag", "test",
                  "samples", "1",
                  "dummy", "{\"key1\": 123, \"key2\": {\"s1\": \"fluent\"}}",
                  NULL);


    /* Forward output with timestamp in integer mode (compat) */
    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "time_as_integer", "true",
                   "tag", "new.tag.$key2['s1']",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_message_compat_mode,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_forward_mode()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "2", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd,
                  "tag", "test",
                  "samples", "1",
                  "dummy", "{\"key1\": 123, \"key2\": {\"s1\": \"fluent\"}}",
                  NULL);


    /* Forward output: without a tag key access, forward mode is used */
    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag",
                   "send_options", "true",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_forward_mode,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_forward_compat_mode()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "3", "grace", "1", NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd,
                  "tag", "test",
                  "samples", "2",
                  "dummy", "{\"key1\": 123, \"key2\": {\"s1\": \"fluent\"}}",
                  NULL);


    /* Forward output: without a tag key access, forward mode is used */
    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag",
                   "time_as_integer", "true",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_forward_compat_mode,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
#ifdef FLB_HAVE_RECORD_ACCESSOR
    {"message_mode"       , flb_test_message_mode },
    {"message_compat_mode", flb_test_message_compat_mode },
#endif
    {"forward_mode"       , flb_test_forward_mode },
    {"forward_compat_mode", flb_test_forward_compat_mode },
    {NULL, NULL}
};
