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
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_time.h>
#include <cmetrics/cmt_counter.h>

#include "flb_tests_runtime.h"

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

static struct flb_filter_instance *get_filter_instance_by_name(flb_ctx_t *ctx,
                                                                const char *name)
{
    struct mk_list *head;
    struct flb_filter_instance *ins;

    mk_list_foreach(head, &ctx->config->filters) {
        ins = mk_list_entry(head, struct flb_filter_instance, _head);
        if (ins->p && strcmp(ins->p->name, name) == 0) {
            return ins;
        }
    }

    return NULL;
}

static int get_counter_value_1(struct cmt_counter *counter,
                               char *label_value_0,
                               double *value)
{
    char *labels[1];

    labels[0] = label_value_0;

    return cmt_counter_get_val(counter, 1, labels, value);
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

static void flb_test_grouped_log_filter_counters(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    int f_ffd;
    double records;
    double dropped;
    double added;
    flb_ctx_t *ctx;
    struct flb_filter_instance *f_ins;

    records = 0;
    dropped = 0;
    added = 0;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return;
    }

    ret = flb_service_set(ctx, "Flush", "0.2", "Grace", "1", "Log_Level", "error", NULL);
    TEST_CHECK(ret == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    f_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx, f_ffd,
                   "match", "test",
                   "regex", "message ^doesnotmatch$",
                   NULL);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        return;
    }

    ret = inject_grouped_log_chunk(ctx, "test");
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);

    f_ins = get_filter_instance_by_name(ctx, "grep");
    TEST_CHECK(f_ins != NULL);
    if (f_ins != NULL) {
        ret = get_counter_value_1(f_ins->cmt_records, (char *) f_ins->name, &records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_1(f_ins->cmt_drop_records, (char *) f_ins->name, &dropped);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_1(f_ins->cmt_add_records, (char *) f_ins->name, &added);
        TEST_CHECK(ret == 0);

        TEST_CHECK(records == 1.0);
        TEST_CHECK(dropped == 1.0);
        TEST_CHECK(added == 0.0);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

TEST_LIST = {
    {"grouped_log_filter_counters", flb_test_grouped_log_filter_counters},
    {NULL, NULL}
};

