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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>

#include "flb_tests_runtime.h"
#include "../../plugins/out_forward/forward.h"

#include <msgpack.h>
#include <pthread.h>
#include <string.h>

#define SERVICE_CREDENTIALS \
    FLB_TESTS_DATA_PATH "/data/stackdriver/stackdriver-credentials.json"

static pthread_mutex_t g_result_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_forward_size = -1;
static int g_loki_values = -1;
static int g_stackdriver_entries = -1;

static void reset_results()
{
    pthread_mutex_lock(&g_result_mutex);
    g_forward_size = -1;
    g_loki_values = -1;
    g_stackdriver_entries = -1;
    pthread_mutex_unlock(&g_result_mutex);
}

static void set_forward_size(int value)
{
    pthread_mutex_lock(&g_result_mutex);
    g_forward_size = value;
    pthread_mutex_unlock(&g_result_mutex);
}

static void set_loki_values(int value)
{
    pthread_mutex_lock(&g_result_mutex);
    g_loki_values = value;
    pthread_mutex_unlock(&g_result_mutex);
}

static void set_stackdriver_entries(int value)
{
    pthread_mutex_lock(&g_result_mutex);
    g_stackdriver_entries = value;
    pthread_mutex_unlock(&g_result_mutex);
}

static int get_forward_size()
{
    int value;

    pthread_mutex_lock(&g_result_mutex);
    value = g_forward_size;
    pthread_mutex_unlock(&g_result_mutex);

    return value;
}

static int get_loki_values()
{
    int value;

    pthread_mutex_lock(&g_result_mutex);
    value = g_loki_values;
    pthread_mutex_unlock(&g_result_mutex);

    return value;
}

static int get_stackdriver_entries()
{
    int value;

    pthread_mutex_lock(&g_result_mutex);
    value = g_stackdriver_entries;
    pthread_mutex_unlock(&g_result_mutex);

    return value;
}

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

static int build_grouped_log_payload(char **out_buf, size_t *out_size)
{
    int ret;
    struct flb_time ts;
    char *copied_buffer;
    struct flb_log_event_encoder *encoder;

    *out_buf = NULL;
    *out_size = 0;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (encoder == NULL) {
        return -1;
    }

    ret = flb_log_event_encoder_group_init(encoder);
    if (ret != 0) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_metadata_values(
            encoder,
            FLB_LOG_EVENT_STRING_VALUE("group", 5),
            FLB_LOG_EVENT_CSTRING_VALUE("g1"));
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_STRING_VALUE("resource", 8),
            FLB_LOG_EVENT_CSTRING_VALUE("test"));
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_group_header_end(encoder);
    if (ret != 0) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_begin_record(encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    flb_time_set(&ts, 1700000000, 0);
    ret = flb_log_event_encoder_set_timestamp(encoder, &ts);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_STRING_VALUE("message", 7),
            FLB_LOG_EVENT_CSTRING_VALUE("hello"));
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_commit_record(encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_group_end(encoder);
    if (ret != 0) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    copied_buffer = flb_malloc(encoder->output_length);
    if (copied_buffer == NULL) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    memcpy(copied_buffer, encoder->output_buffer, encoder->output_length);

    *out_buf = copied_buffer;
    *out_size = encoder->output_length;

    flb_log_event_encoder_destroy(encoder);

    return 0;
}

static int append_log_record(struct flb_log_event_encoder *encoder,
                             int64_t seconds,
                             const char *message)
{
    int ret;
    struct flb_time ts;

    ret = flb_log_event_encoder_begin_record(encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    flb_time_set(&ts, seconds, 0);
    ret = flb_log_event_encoder_set_timestamp(encoder, &ts);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_STRING_VALUE("message", 7),
            FLB_LOG_EVENT_CSTRING_VALUE(message));
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_commit_record(encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    return 0;
}

static int build_mixed_with_empty_group_payload(char **out_buf, size_t *out_size)
{
    int ret;
    char *copied_buffer;
    struct flb_log_event_encoder *encoder;

    *out_buf = NULL;
    *out_size = 0;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (encoder == NULL) {
        return -1;
    }

    ret = append_log_record(encoder, 1700000000, "r1");
    if (ret != 0) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = append_log_record(encoder, 1700000001, "r2");
    if (ret != 0) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_group_init(encoder);
    if (ret != 0) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_metadata_values(
            encoder,
            FLB_LOG_EVENT_STRING_VALUE("group", 5),
            FLB_LOG_EVENT_CSTRING_VALUE("empty"));
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_group_header_end(encoder);
    if (ret != 0) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = flb_log_event_encoder_group_end(encoder);
    if (ret != 0) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = append_log_record(encoder, 1700000002, "r3");
    if (ret != 0) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    ret = append_log_record(encoder, 1700000003, "r4");
    if (ret != 0) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    copied_buffer = flb_malloc(encoder->output_length);
    if (copied_buffer == NULL) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    memcpy(copied_buffer, encoder->output_buffer, encoder->output_length);
    *out_buf = copied_buffer;
    *out_size = encoder->output_length;

    flb_log_event_encoder_destroy(encoder);

    return 0;
}

static int inject_grouped_log_chunk(flb_ctx_t *ctx, const char *tag)
{
    int ret;
    char *payload;
    size_t payload_size;
    struct flb_input_instance *ins;

    ins = get_input_instance_by_name(ctx, "lib");
    if (ins == NULL) {
        return -1;
    }

    payload = NULL;
    payload_size = 0;

    ret = build_grouped_log_payload(&payload, &payload_size);
    if (ret != 0) {
        return -1;
    }

    ret = flb_input_chunk_append_raw(ins,
                                     FLB_INPUT_LOGS,
                                     0,
                                     tag,
                                     strlen(tag),
                                     payload,
                                     payload_size);

    flb_free(payload);
    return ret;
}

static int inject_mixed_with_empty_group_chunk(flb_ctx_t *ctx, const char *tag)
{
    int ret;
    char *payload;
    size_t payload_size;
    struct flb_input_instance *ins;

    ins = get_input_instance_by_name(ctx, "lib");
    if (ins == NULL) {
        return -1;
    }

    payload = NULL;
    payload_size = 0;

    ret = build_mixed_with_empty_group_payload(&payload, &payload_size);
    if (ret != 0) {
        return -1;
    }

    ret = flb_input_chunk_append_raw(ins,
                                     FLB_INPUT_LOGS,
                                     0,
                                     tag,
                                     strlen(tag),
                                     payload,
                                     payload_size);

    flb_free(payload);
    return ret;
}

static int map_find_key(msgpack_object map, const char *key, msgpack_object **out)
{
    size_t i;
    size_t key_len;
    msgpack_object k;

    if (map.type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    key_len = strlen(key);

    for (i = 0; i < map.via.map.size; i++) {
        k = map.via.map.ptr[i].key;

        if (k.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (k.via.str.size != key_len) {
            continue;
        }

        if (strncmp(k.via.str.ptr, key, key_len) == 0) {
            *out = &map.via.map.ptr[i].val;
            return 0;
        }
    }

    return -1;
}

static void cb_forward_size_check(void *ctx, int ffd,
                                  int res_ret, void *res_data, size_t res_size,
                                  void *data)
{
    int ret;
    size_t off;
    msgpack_object *size_obj;
    msgpack_object root;
    msgpack_unpacked result;

    (void) ctx;
    (void) ffd;
    (void) res_size;
    (void) data;

    TEST_CHECK(res_ret == MODE_FORWARD);

    off = 0;
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, res_data, res_size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    if (ret == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        if (map_find_key(root, "size", &size_obj) == 0 &&
            size_obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            set_forward_size((int) size_obj->via.u64);
        }
    }

    msgpack_unpacked_destroy(&result);
    flb_free(res_data);
}

static int extract_json_array_size(char *json_data, size_t json_len,
                                   const char *array_key, int *size_out)
{
    int ret;
    int type;
    size_t off;
    char *mp_buf;
    size_t mp_size;
    msgpack_object *array_obj;
    msgpack_object root;
    msgpack_unpacked result;

    *size_out = -1;
    mp_buf = NULL;
    mp_size = 0;

    ret = flb_pack_json((const char *) json_data,
                        json_len,
                        &mp_buf,
                        &mp_size,
                        &type,
                        NULL);
    if (ret != 0) {
        return -1;
    }

    off = 0;
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, mp_buf, mp_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        flb_free(mp_buf);
        return -1;
    }

    root = result.data;
    if (map_find_key(root, array_key, &array_obj) == 0 &&
        array_obj->type == MSGPACK_OBJECT_ARRAY) {
        *size_out = (int) array_obj->via.array.size;
    }

    msgpack_unpacked_destroy(&result);
    flb_free(mp_buf);

    if (*size_out < 0) {
        return -1;
    }

    return 0;
}

static void cb_loki_values_check(void *ctx, int ffd,
                                 int res_ret, void *res_data, size_t res_size,
                                 void *data)
{
    int ret;
    int streams_size;
    int values_size;
    size_t i;
    msgpack_object *streams_obj;
    msgpack_object stream_obj;
    msgpack_object *values_obj;
    msgpack_object root;
    msgpack_unpacked result;
    size_t off;
    int type;
    char *mp_buf;
    size_t mp_size;

    (void) ctx;
    (void) ffd;
    (void) res_ret;
    (void) data;

    streams_size = -1;
    values_size = -1;
    mp_buf = NULL;
    mp_size = 0;

    ret = flb_pack_json((const char *) res_data,
                        res_size,
                        &mp_buf,
                        &mp_size,
                        &type,
                        NULL);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_sds_destroy((flb_sds_t) res_data);
        return;
    }

    off = 0;
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, mp_buf, mp_size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    if (ret == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        if (map_find_key(root, "streams", &streams_obj) == 0 &&
            streams_obj->type == MSGPACK_OBJECT_ARRAY) {
            streams_size = (int) streams_obj->via.array.size;
            for (i = 0; i < streams_obj->via.array.size; i++) {
                stream_obj = streams_obj->via.array.ptr[i];
                if (stream_obj.type != MSGPACK_OBJECT_MAP) {
                    continue;
                }

                if (map_find_key(stream_obj, "values", &values_obj) == 0 &&
                    values_obj->type == MSGPACK_OBJECT_ARRAY) {
                    values_size = (int) values_obj->via.array.size;
                    break;
                }
            }
        }
    }

    msgpack_unpacked_destroy(&result);
    flb_free(mp_buf);
    flb_sds_destroy((flb_sds_t) res_data);

    TEST_CHECK(streams_size > 0);
    TEST_CHECK(values_size >= 0);
    if (values_size >= 0) {
        set_loki_values(values_size);
    }
}

static void cb_stackdriver_entries_check(void *ctx, int ffd,
                                         int res_ret, void *res_data, size_t res_size,
                                         void *data)
{
    int entries_size;
    int ret;

    (void) ctx;
    (void) ffd;
    (void) res_ret;
    (void) data;

    entries_size = -1;

    ret = extract_json_array_size((char *) res_data,
                                  res_size,
                                  "entries",
                                  &entries_size);

    TEST_CHECK(ret == 0);
    if (ret == 0) {
        set_stackdriver_entries(entries_size);
    }

    flb_sds_destroy((flb_sds_t) res_data);
}

static void run_group_count_test(flb_ctx_t *ctx)
{
    int ret;

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }

    ret = inject_grouped_log_chunk(ctx, "test");
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);
    flb_stop(ctx);
}

static void flb_test_forward_group_size_default()
{
    int out_ffd;
    int in_ffd;
    int ret;
    flb_ctx_t *ctx;

    reset_results();

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.2", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag",
                   "send_options", "true",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_forward_size_check,
                              NULL, NULL);
    TEST_CHECK(ret == 0);

    run_group_count_test(ctx);
    TEST_CHECK(get_forward_size() == 3);

    flb_destroy(ctx);
}

static void flb_test_forward_group_size_opt_out_metadata()
{
    int out_ffd;
    int in_ffd;
    int ret;
    flb_ctx_t *ctx;

    reset_results();

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.2", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag",
                   "send_options", "true",
                   "retain_metadata_in_forward_mode", "false",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_forward_size_check,
                              NULL, NULL);
    TEST_CHECK(ret == 0);

    run_group_count_test(ctx);
    TEST_CHECK(get_forward_size() == 1);

    flb_destroy(ctx);
}

static void flb_test_forward_group_size_retain_metadata()
{
    int out_ffd;
    int in_ffd;
    int ret;
    flb_ctx_t *ctx;

    reset_results();

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.2", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag",
                   "send_options", "true",
                   "retain_metadata_in_forward_mode", "true",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_forward_size_check,
                              NULL, NULL);
    TEST_CHECK(ret == 0);

    run_group_count_test(ctx);
    TEST_CHECK(get_forward_size() == 3);

    flb_destroy(ctx);
}

static void flb_test_forward_group_size_retain_metadata_upstream_node()
{
    int ret;
    int out_ffd;
    int in_ffd;
    flb_ctx_t *ctx;

    reset_results();

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.2", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag",
                   "upstream",
                   FLB_TESTS_DATA_PATH "/data/forward/upstream_retain_metadata.conf",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_forward_size_check,
                              NULL, NULL);
    TEST_CHECK(ret == 0);

    run_group_count_test(ctx);
    TEST_CHECK(get_forward_size() == 3);

    flb_destroy(ctx);
}

static void flb_test_loki_group_values_count()
{
    int out_ffd;
    int in_ffd;
    int ret;
    flb_ctx_t *ctx;

    reset_results();

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.2", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "loki", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_loki_values_check,
                              NULL, NULL);
    TEST_CHECK(ret == 0);

    run_group_count_test(ctx);
    TEST_CHECK(get_loki_values() == 1);

    flb_destroy(ctx);
}

static void flb_test_stackdriver_group_entries_count()
{
    int out_ffd;
    int in_ffd;
    int ret;
    flb_ctx_t *ctx;

    reset_results();

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.2", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stackdriver", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "google_service_credentials", SERVICE_CREDENTIALS,
                   "resource", "global",
                   NULL);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_stackdriver_entries_check,
                              NULL, NULL);
    TEST_CHECK(ret == 0);

    run_group_count_test(ctx);
    TEST_CHECK(get_stackdriver_entries() == 1);

    flb_destroy(ctx);
}

static void flb_test_forward_output_processor_mixed_payload_smoke()
{
    int ret;
    int out_ffd;
    int in_ffd;
    flb_ctx_t *ctx;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;

    reset_results();

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "0.2", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "forward", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "tag", "new.tag",
                   "send_options", "true",
                   "retain_metadata_in_forward_mode", "true",
                   NULL);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);
    if (proc == NULL) {
        flb_destroy(ctx);
        return;
    }

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "grep");
    TEST_CHECK(pu != NULL);
    if (pu == NULL) {
        flb_destroy(ctx);
        return;
    }

    ret = flb_processor_unit_set_property_str(pu, "regex", "message ^r[1-4]$");
    TEST_CHECK(ret == 0);

    ret = flb_output_set_processor(ctx, out_ffd, proc);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_forward_size_check,
                              NULL, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        return;
    }

    ret = inject_mixed_with_empty_group_chunk(ctx, "test");
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);
    flb_stop(ctx);

    TEST_CHECK(get_forward_size() > 0);

    flb_destroy(ctx);
}

TEST_LIST = {
    {"forward_group_size_default", flb_test_forward_group_size_default},
    {"forward_group_size_opt_out_metadata", flb_test_forward_group_size_opt_out_metadata},
    {"forward_group_size_retain_metadata", flb_test_forward_group_size_retain_metadata},
    {"forward_group_size_retain_metadata_upstream_node",
     flb_test_forward_group_size_retain_metadata_upstream_node},
    {"loki_group_values_count", flb_test_loki_group_values_count},
    {"stackdriver_group_entries_count", flb_test_stackdriver_group_entries_count},
    {"forward_output_processor_mixed_payload_smoke",
     flb_test_forward_output_processor_mixed_payload_smoke},
    {NULL, NULL}
};
