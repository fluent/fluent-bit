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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_router.h>
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

static int get_counter_value_1_or_zero(struct cmt_counter *counter,
                                       char *label_value_0,
                                       double *value)
{
    int ret;

    ret = get_counter_value_1(counter, label_value_0, value);
    if (ret != 0) {
        *value = 0.0;
        return 0;
    }

    return ret;
}

static int get_counter_value_2(struct cmt_counter *counter,
                               char *label_value_0,
                               char *label_value_1,
                               double *value)
{
    char *labels[2];

    labels[0] = label_value_0;
    labels[1] = label_value_1;

    return cmt_counter_get_val(counter, 2, labels, value);
}

static int get_counter_value_2_or_zero(struct cmt_counter *counter,
                                       char *label_value_0,
                                       char *label_value_1,
                                       double *value)
{
    int ret;

    ret = get_counter_value_2(counter, label_value_0, label_value_1, value);
    if (ret != 0) {
        *value = 0.0;
        return 0;
    }

    return ret;
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

    payload = NULL;
    payload_size = 0;

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

static void flb_test_mixed_input_processor_filter_parity(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    int f_ffd;
    double output_proc_records;
    double router_records;
    double router_drop_records;
    double filter_records;
    double filter_drop_records;
    flb_ctx_t *ctx;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_filter_instance *f_ins;
    struct flb_input_instance *i_ins;
    struct flb_output_instance *o_ins;

    output_proc_records = 0.0;
    router_records = 0.0;
    router_drop_records = 0.0;
    filter_records = 0.0;
    filter_drop_records = 0.0;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return;
    }

    ret = flb_service_set(ctx, "Flush", "0.2", "Grace", "1", "Log_Level", "error", NULL);
    TEST_CHECK(ret == 0);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);
    if (!proc) {
        flb_destroy(ctx);
        return;
    }

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "grep");
    TEST_CHECK(pu != NULL);
    if (!pu) {
        flb_destroy(ctx);
        return;
    }

    ret = flb_processor_unit_set_property_str(pu, "regex", "message ^hello$");
    TEST_CHECK(ret == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    ret = flb_input_set_processor(ctx, in_ffd, proc);
    TEST_CHECK(ret == 0);

    f_ffd = flb_filter(ctx, (char *) "grep", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx, f_ffd,
                   "match", "test",
                   "regex", "message ^hello$",
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

    i_ins = get_input_instance_by_name(ctx, "lib");
    o_ins = get_output_instance_by_name(ctx, "null");
    f_ins = get_filter_instance_by_name(ctx, "grep");

    TEST_CHECK(i_ins != NULL);
    TEST_CHECK(o_ins != NULL);
    TEST_CHECK(f_ins != NULL);

    if (i_ins && o_ins && f_ins) {
        ret = get_counter_value_1(o_ins->cmt_proc_records,
                                  (char *) flb_output_name(o_ins),
                                  &output_proc_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_2(ctx->config->router->logs_records_total,
                                  (char *) flb_input_name(i_ins),
                                  (char *) flb_output_name(o_ins),
                                  &router_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_2_or_zero(ctx->config->router->logs_drop_records_total,
                                          (char *) flb_input_name(i_ins),
                                          (char *) flb_output_name(o_ins),
                                          &router_drop_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_1(f_ins->cmt_records, (char *) f_ins->name,
                                  &filter_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_1(f_ins->cmt_drop_records, (char *) f_ins->name,
                                  &filter_drop_records);
        TEST_CHECK(ret == 0);

        TEST_CHECK(output_proc_records == 1.0);
        TEST_CHECK(router_records == 1.0);
        TEST_CHECK(router_drop_records == 0.0);
        TEST_CHECK(filter_records == 1.0);
        TEST_CHECK(filter_drop_records == 0.0);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

static void flb_test_output_processor_drop_parity(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    double output_proc_records;
    double router_records;
    double router_drop_records;
    flb_ctx_t *ctx;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_input_instance *i_ins;
    struct flb_output_instance *o_ins;

    output_proc_records = 0.0;
    router_records = 0.0;
    router_drop_records = 0.0;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return;
    }

    ret = flb_service_set(ctx, "Flush", "0.2", "Grace", "1", "Log_Level", "error", NULL);
    TEST_CHECK(ret == 0);

    proc = flb_processor_create(ctx->config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);
    if (!proc) {
        flb_destroy(ctx);
        return;
    }

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "grep");
    TEST_CHECK(pu != NULL);
    if (!pu) {
        flb_destroy(ctx);
        return;
    }

    ret = flb_processor_unit_set_property_str(pu, "regex", "message ^doesnotmatch$");
    TEST_CHECK(ret == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    ret = flb_output_set_processor(ctx, out_ffd, proc);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        return;
    }

    ret = inject_grouped_log_chunk(ctx, "test");
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500);

    i_ins = get_input_instance_by_name(ctx, "lib");
    o_ins = get_output_instance_by_name(ctx, "null");

    TEST_CHECK(i_ins != NULL);
    TEST_CHECK(o_ins != NULL);

    if (i_ins && o_ins) {
        ret = get_counter_value_1(o_ins->cmt_proc_records,
                                  (char *) flb_output_name(o_ins),
                                  &output_proc_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_2_or_zero(ctx->config->router->logs_records_total,
                                          (char *) flb_input_name(i_ins),
                                          (char *) flb_output_name(o_ins),
                                          &router_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_2_or_zero(ctx->config->router->logs_drop_records_total,
                                          (char *) flb_input_name(i_ins),
                                          (char *) flb_output_name(o_ins),
                                          &router_drop_records);
        TEST_CHECK(ret == 0);

        TEST_CHECK(output_proc_records == 0.0);
        TEST_CHECK(router_records == 0.0);
        TEST_CHECK(router_drop_records == 0.0);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

static void flb_test_retry_drop_route_parity_grouped(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    double output_proc_records;
    double output_retries;
    double output_retried_records;
    double output_dropped_records;
    double output_retries_failed;
    double router_records;
    double router_drop_records;
    flb_ctx_t *ctx;
    struct flb_input_instance *i_ins;
    struct flb_output_instance *o_ins;

    output_proc_records = 0.0;
    output_retries = 0.0;
    output_retried_records = 0.0;
    output_dropped_records = 0.0;
    output_retries_failed = 0.0;
    router_records = 0.0;
    router_drop_records = 0.0;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return;
    }

    ret = flb_service_set(ctx, "Flush", "0.2", "Grace", "2", "Log_Level", "error", NULL);
    TEST_CHECK(ret == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "http", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "host", "127.0.0.1",
                   "port", "1",
                   "uri", "/",
                   "retry_limit", "no_retries",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        return;
    }

    ret = inject_grouped_log_chunk(ctx, "test");
    TEST_CHECK(ret == 0);

    i_ins = get_input_instance_by_name(ctx, "lib");
    o_ins = get_output_instance_by_name(ctx, "http");

    TEST_CHECK(i_ins != NULL);
    TEST_CHECK(o_ins != NULL);

    if (i_ins && o_ins) {
        flb_time_msleep(2000);

        ret = get_counter_value_1(o_ins->cmt_proc_records,
                                  (char *) flb_output_name(o_ins),
                                  &output_proc_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_1_or_zero(o_ins->cmt_retries,
                                          (char *) flb_output_name(o_ins),
                                          &output_retries);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_1_or_zero(o_ins->cmt_retried_records,
                                          (char *) flb_output_name(o_ins),
                                          &output_retried_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_1_or_zero(o_ins->cmt_dropped_records,
                                          (char *) flb_output_name(o_ins),
                                          &output_dropped_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_1_or_zero(o_ins->cmt_retries_failed,
                                          (char *) flb_output_name(o_ins),
                                          &output_retries_failed);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_2_or_zero(ctx->config->router->logs_records_total,
                                          (char *) flb_input_name(i_ins),
                                          (char *) flb_output_name(o_ins),
                                          &router_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_2_or_zero(ctx->config->router->logs_drop_records_total,
                                          (char *) flb_input_name(i_ins),
                                          (char *) flb_output_name(o_ins),
                                          &router_drop_records);
        TEST_CHECK(ret == 0);

        TEST_CHECK(output_proc_records == 0.0);
        TEST_CHECK(output_retries == 0.0);
        TEST_CHECK(output_retried_records == 0.0);
        TEST_CHECK(output_dropped_records == 1.0);
        TEST_CHECK(output_retries_failed == 0.0);
        TEST_CHECK(router_records == 0.0);
        TEST_CHECK(router_drop_records == 1.0);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

static void flb_test_retry_scheduled_route_parity_grouped(void)
{
    int ret;
    int in_ffd;
    int out_ffd;
    double output_proc_records;
    double output_retries;
    double output_retried_records;
    double router_records;
    flb_ctx_t *ctx;
    struct flb_input_instance *i_ins;
    struct flb_output_instance *o_ins;

    output_proc_records = 0.0;
    output_retries = 0.0;
    output_retried_records = 0.0;
    router_records = 0.0;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return;
    }

    ret = flb_service_set(ctx, "Flush", "0.2", "Grace", "2", "Log_Level", "error", NULL);
    TEST_CHECK(ret == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "http", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "host", "127.0.0.1",
                   "port", "1",
                   "uri", "/",
                   "retry_limit", "2",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_destroy(ctx);
        return;
    }

    ret = inject_grouped_log_chunk(ctx, "test");
    TEST_CHECK(ret == 0);

    flb_time_msleep(1200);

    i_ins = get_input_instance_by_name(ctx, "lib");
    o_ins = get_output_instance_by_name(ctx, "http");

    TEST_CHECK(i_ins != NULL);
    TEST_CHECK(o_ins != NULL);

    if (i_ins && o_ins) {
        ret = get_counter_value_1(o_ins->cmt_proc_records,
                                  (char *) flb_output_name(o_ins),
                                  &output_proc_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_1_or_zero(o_ins->cmt_retries,
                                          (char *) flb_output_name(o_ins),
                                          &output_retries);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_1_or_zero(o_ins->cmt_retried_records,
                                          (char *) flb_output_name(o_ins),
                                          &output_retried_records);
        TEST_CHECK(ret == 0);

        ret = get_counter_value_2_or_zero(ctx->config->router->logs_records_total,
                                          (char *) flb_input_name(i_ins),
                                          (char *) flb_output_name(o_ins),
                                          &router_records);
        TEST_CHECK(ret == 0);

        TEST_CHECK(output_proc_records == 0.0);
        TEST_CHECK(output_retries >= 1.0);
        TEST_CHECK(output_retried_records >= 1.0);
        TEST_CHECK(router_records == 0.0);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

TEST_LIST = {
    {"mixed_input_processor_filter_parity", flb_test_mixed_input_processor_filter_parity},
    {"output_processor_drop_parity", flb_test_output_processor_drop_parity},
    {"retry_drop_route_parity_grouped", flb_test_retry_drop_route_parity_grouped},
    {"retry_scheduled_route_parity_grouped", flb_test_retry_scheduled_route_parity_grouped},
    {NULL, NULL}
};
