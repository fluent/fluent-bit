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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_output.h>

#include "flb_tests_runtime.h"

/* Include plugin header to get the flush_ctx structure definition */
#include "../../plugins/out_forward/forward.h"

static struct flb_input_instance *get_input_instance_by_name(flb_ctx_t *ctx,
                                                              const char *name)
{
    struct mk_list *head;
    struct flb_input_instance *ins;

    mk_list_foreach(head, &ctx->config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        if (ins->p && strcmp(ins->p->name, name) == 0) {
            return ins;
        }
    }

    return NULL;
}

static struct flb_output_instance *get_output_instance_by_name(flb_ctx_t *ctx,
                                                                const char *name)
{
    struct mk_list *head;
    struct flb_output_instance *ins;

    mk_list_foreach(head, &ctx->config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);
        if (ins->p && strcmp(ins->p->name, name) == 0) {
            return ins;
        }
    }

    return NULL;
}

static int run_forward_formatter_non_log(flb_ctx_t *ctx,
                                         int event_type,
                                         const char *tag,
                                         const void *data,
                                         size_t size,
                                         void **out_buf,
                                         size_t *out_size)
{
    int ret;
    struct flb_input_instance *i_ins;
    struct flb_output_instance *o_ins;

    i_ins = get_input_instance_by_name(ctx, "lib");
    if (i_ins == NULL) {
        return -1;
    }

    o_ins = get_output_instance_by_name(ctx, "forward");
    if (o_ins == NULL ||
        o_ins->p == NULL ||
        o_ins->p->test_formatter.callback == NULL ||
        o_ins->context == NULL) {
        return -1;
    }

    ret = o_ins->p->test_formatter.callback(ctx->config,
                                            i_ins,
                                            o_ins->context,
                                            NULL,
                                            event_type,
                                            tag,
                                            strlen(tag),
                                            data,
                                            size,
                                            out_buf,
                                            out_size);

    return ret;
}

static void verify_non_log_options_map(void *res_data,
                                       size_t res_size,
                                       int expected_signal)
{
    int i;
    int ret;
    int have_size;
    int have_signal;
    size_t off;
    msgpack_object key;
    msgpack_object val;
    msgpack_object root;
    msgpack_unpacked result;

    have_size = FLB_FALSE;
    have_signal = FLB_FALSE;
    off = 0;

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        return;
    }

    root = result.data;
    TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        val = root.via.map.ptr[i].val;

        if (key.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (key.via.str.size == 4 &&
            strncmp(key.via.str.ptr, "size", 4) == 0) {
            have_size = FLB_TRUE;
        }
        else if (key.via.str.size == 13 &&
                 strncmp(key.via.str.ptr, "fluent_signal", 13) == 0) {
            TEST_CHECK(val.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
                       val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER);
            if (val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                TEST_CHECK((int) val.via.u64 == expected_signal);
            }
            else if (val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                TEST_CHECK((int) val.via.i64 == expected_signal);
            }
            have_signal = FLB_TRUE;
        }
    }

    TEST_CHECK(have_size == FLB_FALSE);
    TEST_CHECK(have_signal == FLB_TRUE);

    msgpack_unpacked_destroy(&result);
}

static int inject_raw_non_log_chunk(flb_ctx_t *ctx, int input_type, const char *tag)
{
    int ret;
    struct flb_input_instance *ins;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    ins = get_input_instance_by_name(ctx, "lib");
    if (ins == NULL) {
        return -1;
    }

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 1);
    msgpack_pack_str_body(&mp_pck, "k", 1);
    msgpack_pack_str(&mp_pck, 1);
    msgpack_pack_str_body(&mp_pck, "v", 1);

    ret = flb_input_chunk_append_raw(ins,
                                     input_type,
                                     1,
                                     tag,
                                     strlen(tag),
                                     mp_sbuf.data,
                                     mp_sbuf.size);

    msgpack_sbuffer_destroy(&mp_sbuf);

    return ret;
}

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

static void cb_check_forward_mode_ack_options(void *ctx, int ffd,
                                              int res_ret, void *res_data, size_t res_size,
                                              void *data)
{
    int i;
    int ret;
    int have_chunk;
    int have_size;
    int have_signal;
    size_t off;
    msgpack_object key;
    msgpack_object val;
    msgpack_object root;
    msgpack_unpacked result;

    (void) ctx;
    (void) ffd;
    (void) data;

    TEST_CHECK(res_ret == MODE_FORWARD);

    have_chunk = FLB_FALSE;
    have_size = FLB_FALSE;
    have_signal = FLB_FALSE;
    off = 0;

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        flb_free(res_data);
        return;
    }

    root = result.data;
    TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        val = root.via.map.ptr[i].val;

        if (key.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (key.via.str.size == 5 &&
            strncmp(key.via.str.ptr, "chunk", 5) == 0) {
            TEST_CHECK(val.type == MSGPACK_OBJECT_STR);
            if (val.type == MSGPACK_OBJECT_STR) {
                TEST_CHECK(val.via.str.size == 32);
            }
            have_chunk = FLB_TRUE;
        }
        else if (key.via.str.size == 4 &&
                 strncmp(key.via.str.ptr, "size", 4) == 0) {
            TEST_CHECK(val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            if (val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                TEST_CHECK(val.via.u64 == 1);
            }
            have_size = FLB_TRUE;
        }
        else if (key.via.str.size == 13 &&
                 strncmp(key.via.str.ptr, "fluent_signal", 13) == 0) {
            TEST_CHECK(val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            if (val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                TEST_CHECK(val.via.u64 == 0);
            }
            have_signal = FLB_TRUE;
        }
    }

    TEST_CHECK(have_chunk == FLB_TRUE);
    TEST_CHECK(have_size == FLB_TRUE);
    TEST_CHECK(have_signal == FLB_TRUE);

    msgpack_unpacked_destroy(&result);
    flb_free(res_data);
}

#ifdef FLB_HAVE_METRICS
static void cb_check_forward_mode_metrics_options(void *ctx, int ffd,
                                                  int res_ret, void *res_data, size_t res_size,
                                                  void *data)
{
    int i;
    int ret;
    int have_signal;
    size_t off;
    msgpack_object key;
    msgpack_object val;
    msgpack_object root;
    msgpack_unpacked result;

    (void) ctx;
    (void) ffd;
    (void) data;

    TEST_CHECK(res_ret == MODE_FORWARD);

    have_signal = FLB_FALSE;
    off = 0;

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        flb_free(res_data);
        return;
    }

    root = result.data;
    TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        val = root.via.map.ptr[i].val;

        if (key.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (key.via.str.size == 4 &&
            strncmp(key.via.str.ptr, "size", 4) == 0) {
            TEST_CHECK(val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            if (val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                TEST_CHECK(val.via.u64 >= 0);
            }
        }
        else if (key.via.str.size == 13 &&
                 strncmp(key.via.str.ptr, "fluent_signal", 13) == 0) {
            TEST_CHECK(val.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
                       val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER);
            if (val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                TEST_CHECK(val.via.u64 == FLB_EVENT_TYPE_METRICS);
            }
            else if (val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                TEST_CHECK(val.via.i64 == FLB_EVENT_TYPE_METRICS);
            }
            have_signal = FLB_TRUE;
        }
    }

    TEST_CHECK(have_signal == FLB_TRUE);

    msgpack_unpacked_destroy(&result);
    flb_free(res_data);
}
#endif

static void cb_check_forward_mode_traces_options(void *ctx, int ffd,
                                                 int res_ret, void *res_data, size_t res_size,
                                                 void *data)
{
    int i;
    int ret;
    int have_size;
    int have_signal;
    size_t off;
    msgpack_object key;
    msgpack_object val;
    msgpack_object root;
    msgpack_unpacked result;

    (void) ctx;
    (void) ffd;
    (void) data;

    TEST_CHECK(res_ret == MODE_FORWARD);

    have_size = FLB_FALSE;
    have_signal = FLB_FALSE;
    off = 0;

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        flb_free(res_data);
        return;
    }

    root = result.data;
    TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);

    for (i = 0; i < root.via.map.size; i++) {
        key = root.via.map.ptr[i].key;
        val = root.via.map.ptr[i].val;

        if (key.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (key.via.str.size == 4 &&
            strncmp(key.via.str.ptr, "size", 4) == 0) {
            have_size = FLB_TRUE;
        }
        else if (key.via.str.size == 13 &&
                 strncmp(key.via.str.ptr, "fluent_signal", 13) == 0) {
            TEST_CHECK(val.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
                       val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER);
            if (val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                TEST_CHECK(val.via.u64 == FLB_EVENT_TYPE_TRACES);
            }
            else if (val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                TEST_CHECK(val.via.i64 == FLB_EVENT_TYPE_TRACES);
            }
            have_signal = FLB_TRUE;
        }
    }

    TEST_CHECK(have_size == FLB_FALSE);
    TEST_CHECK(have_signal == FLB_TRUE);

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

void flb_test_forward_mode_ack_options()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "2", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd,
                  "tag", "test",
                  "samples", "1",
                  "dummy", "{\"key1\": 123, \"key2\": {\"s1\": \"fluent\"}}",
                  NULL);

    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag",
                   "require_ack_response", "true",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_forward_mode_ack_options,
                              NULL, NULL);

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

void flb_test_forward_mode_traces_options()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "0.2", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag.traces",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_forward_mode_traces_options,
                              NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    ret = inject_raw_non_log_chunk(ctx, FLB_INPUT_TRACES, "test");
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_forward_mode_profiles_no_crash()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    void *res_data;
    size_t res_size;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "tag", "new.tag",
                   "time_as_integer", "true",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 1);
    msgpack_pack_str_body(&mp_pck, "k", 1);
    msgpack_pack_str(&mp_pck, 1);
    msgpack_pack_str_body(&mp_pck, "v", 1);

    res_data = NULL;
    res_size = 0;
    ret = run_forward_formatter_non_log(ctx,
                                        FLB_EVENT_TYPE_PROFILES,
                                        "test",
                                        mp_sbuf.data,
                                        mp_sbuf.size,
                                        &res_data,
                                        &res_size);

    TEST_CHECK(ret == MODE_FORWARD);
    TEST_CHECK(res_data != NULL);
    TEST_CHECK(res_size > 0);

    if (ret == MODE_FORWARD && res_data != NULL && res_size > 0) {
        verify_non_log_options_map(res_data, res_size, FLB_EVENT_TYPE_PROFILES);
    }

    if (res_data != NULL) {
        flb_free(res_data);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_forward_mode_blobs_no_crash()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    void *res_data;
    size_t res_size;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "tag", "new.tag",
                   "time_as_integer", "true",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 1);
    msgpack_pack_str_body(&mp_pck, "k", 1);
    msgpack_pack_str(&mp_pck, 1);
    msgpack_pack_str_body(&mp_pck, "v", 1);

    res_data = NULL;
    res_size = 0;
    ret = run_forward_formatter_non_log(ctx,
                                        FLB_EVENT_TYPE_BLOBS,
                                        "test",
                                        mp_sbuf.data,
                                        mp_sbuf.size,
                                        &res_data,
                                        &res_size);

    TEST_CHECK(ret == MODE_FORWARD);
    TEST_CHECK(res_data != NULL);
    TEST_CHECK(res_size > 0);

    if (ret == MODE_FORWARD && res_data != NULL && res_size > 0) {
        verify_non_log_options_map(res_data, res_size, FLB_EVENT_TYPE_BLOBS);
    }

    if (res_data != NULL) {
        flb_free(res_data);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);

    flb_stop(ctx);
    flb_destroy(ctx);
}

#ifdef FLB_HAVE_METRICS
void flb_test_forward_mode_metrics_options()
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1", NULL);

    in_ffd = flb_input(ctx, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "scrape_interval", "1", NULL);

    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   "tag", "new.tag.metrics",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_forward_mode_metrics_options,
                              NULL, NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}
#endif

/* Test list */
TEST_LIST = {
#ifdef FLB_HAVE_RECORD_ACCESSOR
    {"message_mode"       , flb_test_message_mode },
    {"message_compat_mode", flb_test_message_compat_mode },
#endif
    {"forward_mode"       , flb_test_forward_mode },
    {"forward_mode_ack_options", flb_test_forward_mode_ack_options },
    {"forward_compat_mode", flb_test_forward_compat_mode },
    {"forward_mode_traces_options", flb_test_forward_mode_traces_options },
    {"forward_mode_profiles_no_crash", flb_test_forward_mode_profiles_no_crash },
    {"forward_mode_blobs_no_crash", flb_test_forward_mode_blobs_no_crash },
#ifdef FLB_HAVE_METRICS
    {"forward_mode_metrics_options", flb_test_forward_mode_metrics_options },
#endif
    {NULL, NULL}
};
