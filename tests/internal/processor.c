/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_event_loop.h>
#include <fluent-bit/flb_bucket_queue.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_plugin.h>
#include <cmetrics/cmt_counter.h>

#include "flb_tests_internal.h"

#define APACHE_10K    FLB_TESTS_DATA_PATH "/data/mp/apache_10k.mp"

static int create_msgpack_records(char **out_buf, size_t *out_size)
{
    int ret;
    int root_type;
    char *json = "{\"key1\": 12345, \"key2\": \"fluent bit\"}";
    char *mp_tmp;
    size_t mp_size;

    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);

    ret = flb_pack_json(json, strlen(json), &mp_tmp, &mp_size, &root_type, NULL);
    TEST_CHECK(ret == 0);

    msgpack_sbuffer_write(&mp_sbuf, mp_tmp, mp_size);
    flb_free(mp_tmp);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

static int create_grouped_msgpack_records(char **out_buf, size_t *out_size)
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

static int get_counter_value_5(struct cmt_counter *counter,
                               char *label_value_0,
                               char *label_value_1,
                               char *label_value_2,
                               char *label_value_3,
                               char *label_value_4,
                               double *value)
{
    char *labels[5];

    labels[0] = label_value_0;
    labels[1] = label_value_1;
    labels[2] = label_value_2;
    labels[3] = label_value_3;
    labels[4] = label_value_4;

    return cmt_counter_get_val(counter, 5, labels, value);
}

static int get_counter_value_5_or_zero(struct cmt_counter *counter,
                                       char *label_value_0,
                                       char *label_value_1,
                                       char *label_value_2,
                                       char *label_value_3,
                                       char *label_value_4,
                                       double *value)
{
    int ret;

    ret = get_counter_value_5(counter,
                              label_value_0,
                              label_value_1,
                              label_value_2,
                              label_value_3,
                              label_value_4,
                              value);
    if (ret != 0) {
        *value = 0.0;
        return 0;
    }

    return ret;
}

static void processor()
{
    int ret;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_config *config;
    char *mp_buf;
    size_t mp_size;
    void *out_buf = NULL;
    size_t out_size;
    flb_sds_t hostname_prop_key;
    struct cfl_variant var = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = NULL,
    };

    printf("\n\n");

    flb_init_env();

    hostname_prop_key = flb_sds_create("hostname monox");
    TEST_CHECK(hostname_prop_key != NULL);
    var.data.as_string = hostname_prop_key;

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    proc = flb_processor_create(config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "stdout");
    TEST_CHECK(pu != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "modify");
    TEST_CHECK(pu != NULL);

    ret = flb_processor_unit_set_property(pu, "add", &var);
    TEST_CHECK(ret == 0);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "stdout");
    TEST_CHECK(pu != NULL);

    ret = flb_processor_init(proc);
    TEST_CHECK(ret == 0);

    /* generate records (simulate an input plugin */
    ret = create_msgpack_records(&mp_buf, &mp_size);
    TEST_CHECK(ret == 0);

    ret = flb_processor_run(proc, 0, FLB_PROCESSOR_LOGS, "TEST", 4, mp_buf, mp_size, &out_buf, &out_size);

    if (out_buf != mp_buf) {
        flb_free(out_buf);
    }
    flb_free(mp_buf);

    flb_processor_destroy(proc);
    flb_config_exit(config);

    flb_sds_destroy(hostname_prop_key);
}

static void processor_grouped_filter_counters()
{
    int ret;
    int vret;
    double records;
    double dropped;
    double added;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_config *config;
    struct flb_filter_instance *f_ins;
    char *mp_buf;
    size_t mp_size;
    void *out_buf;
    size_t out_size;
    int init_ok;
    flb_sds_t regex_prop_key;
    struct cfl_variant var = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = NULL,
    };
    char *labels[1];

    records = 0;
    dropped = 0;
    added = 0;
    init_ok = FLB_FALSE;
    mp_buf = NULL;
    out_buf = NULL;
    out_size = 0;

    flb_init_env();

    regex_prop_key = flb_sds_create("message ^doesnotmatch$");
    TEST_CHECK(regex_prop_key != NULL);
    var.data.as_string = regex_prop_key;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        flb_sds_destroy(regex_prop_key);
        return;
    }

    proc = flb_processor_create(config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);
    if (proc == NULL) {
        flb_config_exit(config);
        flb_sds_destroy(regex_prop_key);
        return;
    }

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "grep");
    TEST_CHECK(pu != NULL);
    if (pu == NULL) {
        flb_processor_destroy(proc);
        flb_config_exit(config);
        flb_sds_destroy(regex_prop_key);
        return;
    }

    ret = flb_processor_unit_set_property(pu, "regex", &var);
    TEST_CHECK(ret == 0);

    ret = flb_processor_init(proc);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        init_ok = FLB_TRUE;
    }

    ret = create_grouped_msgpack_records(&mp_buf, &mp_size);
    TEST_CHECK(ret == 0);
    if (ret == 0 && init_ok == FLB_TRUE) {
        ret = flb_processor_run(proc, 0, FLB_PROCESSOR_LOGS,
                                "TEST", 4, mp_buf, mp_size,
                                &out_buf, &out_size);
        TEST_CHECK(ret == 0);
        TEST_CHECK(out_size == 0);
    }

    if (out_buf != NULL && out_buf != mp_buf) {
        flb_free(out_buf);
        out_buf = NULL;
    }

    if (mp_buf != NULL) {
        flb_free(mp_buf);
        mp_buf = NULL;
    }

    if (ret == 0 && init_ok == FLB_TRUE) {
        f_ins = pu->ctx;
        labels[0] = f_ins->name;

        vret = cmt_counter_get_val(f_ins->cmt_records, 1, labels, &records);
        TEST_CHECK(vret == 0);
        vret = cmt_counter_get_val(f_ins->cmt_drop_records, 1, labels, &dropped);
        TEST_CHECK(vret == 0);
        vret = cmt_counter_get_val(f_ins->cmt_add_records, 1, labels, &added);
        TEST_CHECK(vret == 0);

        TEST_CHECK(records == 1.0);
        TEST_CHECK(dropped == 1.0);
        TEST_CHECK(added == 0.0);
    }

    flb_processor_destroy(proc);
    flb_config_exit(config);
    flb_sds_destroy(regex_prop_key);
}

static void processor_private_inputs_use_main_loop()
{
    int ret;
    int collector_count;
    void *context;
    struct flb_config *config;
    struct flb_input_instance *ins;
    struct mk_event_loop *thread_evl;
    struct flb_sched *thread_sched;
    struct mk_list *head;
    struct flb_input_collector *coll;

    flb_init_env();

#ifdef _WIN32
    WSADATA wsa;
    int wret = WSAStartup(MAKEWORD(2,2), &wsa);
    TEST_CHECK(wret == 0);
#endif

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    config->evl = mk_event_loop_create(256);
    TEST_CHECK(config->evl != NULL);

    config->evl_bktq = flb_bucket_queue_create(FLB_ENGINE_PRIORITY_COUNT);
    TEST_CHECK(config->evl_bktq != NULL);

    config->sched = flb_sched_create(config, config->evl);
    TEST_CHECK(config->sched != NULL);

    ret = flb_storage_create(config);
    TEST_CHECK(ret == 0);

    thread_evl = mk_event_loop_create(64);
    TEST_CHECK(thread_evl != NULL);

    thread_sched = flb_sched_create(config, thread_evl);
    TEST_CHECK(thread_sched != NULL);

    /* Simulate the environment of an input thread */
    flb_engine_evl_set(thread_evl);
    flb_sched_ctx_set(thread_sched);

    ins = flb_input_new(config, "emitter", NULL, FLB_FALSE);
    TEST_CHECK(ins != NULL);

    ret = flb_input_instance_init(ins, config);
    TEST_CHECK(ret == 0);

    /* Initializing a private input again must not replace its owned state. */
    context = ins->context;
    collector_count = mk_list_size(&ins->collectors);
    ret = flb_input_instance_init(ins, config);
    TEST_CHECK(ret == 0);
    TEST_CHECK(ins->context == context);
    TEST_CHECK(mk_list_size(&ins->collectors) == collector_count);

    mk_list_foreach(head, &ins->collectors) {
        coll = mk_list_entry(head, struct flb_input_collector, _head);
        TEST_CHECK(coll->evl == config->evl);
    }

    flb_input_instance_exit(ins, config);
    flb_input_instance_destroy(ins);

    flb_sched_ctx_set(config->sched);
    flb_engine_evl_set(NULL);

    flb_sched_destroy(thread_sched);
    mk_event_loop_destroy(thread_evl);

    flb_storage_destroy(config);
    flb_config_exit(config);

#ifdef _WIN32
    WSACleanup();
#endif
}

static void processor_metrics_counters()
{
    int ret;
    int vret;
    double invocations;
    double errors;
    double items_in;
    double items_out;
    double items_drop;
    double items_add;
    char stage_label[32];
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_config *config;
    struct flb_input_instance owner_input;
    char *mp_buf;
    size_t mp_size;
    void *out_buf;
    size_t out_size;
    flb_sds_t regex_prop_key;
    struct cfl_variant var = {
        .type = CFL_VARIANT_STRING,
        .data.as_string = NULL,
    };

    invocations = 0.0;
    errors = 0.0;
    items_in = 0.0;
    items_out = 0.0;
    items_drop = 0.0;
    items_add = 0.0;
    out_buf = NULL;
    out_size = 0;

    flb_init_env();

    regex_prop_key = flb_sds_create("message ^doesnotmatch$");
    TEST_CHECK(regex_prop_key != NULL);
    var.data.as_string = regex_prop_key;

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
        flb_sds_destroy(regex_prop_key);
        return;
    }

    proc = flb_processor_create(config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);
    if (proc == NULL) {
        flb_config_exit(config);
        flb_sds_destroy(regex_prop_key);
        return;
    }

    memset(&owner_input, 0, sizeof(owner_input));
    snprintf(owner_input.name, sizeof(owner_input.name) - 1, "%s",
             "unit_input.0");
    owner_input.name[sizeof(owner_input.name) - 1] = '\0';
    owner_input.cmt = cmt_create();
    TEST_CHECK(owner_input.cmt != NULL);
    if (owner_input.cmt == NULL) {
        flb_processor_destroy(proc);
        flb_config_exit(config);
        flb_sds_destroy(regex_prop_key);
        return;
    }

    proc->data = &owner_input;
    proc->source_plugin_type = FLB_PLUGIN_INPUT;

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "grep");
    TEST_CHECK(pu != NULL);
    if (pu == NULL) {
        cmt_destroy(owner_input.cmt);
        flb_processor_destroy(proc);
        flb_config_exit(config);
        flb_sds_destroy(regex_prop_key);
        return;
    }

    ret = flb_processor_unit_set_property(pu, "regex", &var);
    TEST_CHECK(ret == 0);

    ret = flb_processor_init(proc);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cmt_destroy(owner_input.cmt);
        flb_processor_destroy(proc);
        flb_config_exit(config);
        flb_sds_destroy(regex_prop_key);
        return;
    }

    ret = create_grouped_msgpack_records(&mp_buf, &mp_size);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cmt_destroy(owner_input.cmt);
        flb_processor_destroy(proc);
        flb_config_exit(config);
        flb_sds_destroy(regex_prop_key);
        return;
    }

    ret = flb_processor_run(proc, 0, FLB_PROCESSOR_LOGS,
                            "TEST", 4, mp_buf, mp_size,
                            &out_buf, &out_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out_size == 0);
    if (out_buf != NULL && out_buf != mp_buf) {
        flb_free(out_buf);
        out_buf = NULL;
    }
    flb_free(mp_buf);

    snprintf(stage_label, sizeof(stage_label) - 1, "%zu", pu->stage);
    stage_label[sizeof(stage_label) - 1] = '\0';

    vret = get_counter_value_5(proc->cmt_invocations,
                               "input",
                               (char *) flb_input_name(&owner_input),
                               (char *) pu->name,
                               stage_label,
                               "logs",
                               &invocations);
    TEST_CHECK(vret == 0);

    vret = get_counter_value_5_or_zero(proc->cmt_errors,
                                       "input",
                                       (char *) flb_input_name(&owner_input),
                                       (char *) pu->name,
                                       stage_label,
                                       "logs",
                                       &errors);
    TEST_CHECK(vret == 0);

    vret = get_counter_value_5(proc->cmt_items_in,
                               "input",
                               (char *) flb_input_name(&owner_input),
                               (char *) pu->name,
                               stage_label,
                               "logs",
                               &items_in);
    TEST_CHECK(vret == 0);

    vret = get_counter_value_5(proc->cmt_items_out,
                               "input",
                               (char *) flb_input_name(&owner_input),
                               (char *) pu->name,
                               stage_label,
                               "logs",
                               &items_out);
    TEST_CHECK(vret == 0);

    vret = get_counter_value_5(proc->cmt_items_drop,
                               "input",
                               (char *) flb_input_name(&owner_input),
                               (char *) pu->name,
                               stage_label,
                               "logs",
                               &items_drop);
    TEST_CHECK(vret == 0);

    vret = get_counter_value_5_or_zero(proc->cmt_items_add,
                                       "input",
                                       (char *) flb_input_name(&owner_input),
                                       (char *) pu->name,
                                       stage_label,
                                       "logs",
                                       &items_add);
    TEST_CHECK(vret == 0);

    TEST_CHECK(invocations == 1.0);
    TEST_CHECK(errors == 0.0);
    TEST_CHECK(items_in == 1.0);
    TEST_CHECK(items_out == 0.0);
    TEST_CHECK(items_drop == 1.0);
    TEST_CHECK(items_add == 0.0);

    cmt_destroy(owner_input.cmt);
    flb_processor_destroy(proc);
    flb_config_exit(config);
    flb_sds_destroy(regex_prop_key);
}

static int create_intermediate_metrics(struct flb_processor_instance *ins,
                                       struct cmt *input, struct cmt **output,
                                       const char *tag, int tag_len)
{
    *output = cmt_create();
    return *output == NULL ? -1 : FLB_PROCESSOR_SUCCESS;
}

static int fail_metrics_processing(struct flb_processor_instance *ins,
                                   struct cmt *input, struct cmt **output,
                                   const char *tag, int tag_len)
{
    *output = NULL;
    return -1;
}

static void processor_metrics_failure_clears_output(void)
{
    struct flb_config *config;
    struct flb_processor *proc;
    struct cmt *input;
    void *output;
    size_t output_size = 123;
    struct flb_processor_plugin first = {
        .name = "test_metrics_copy",
        .description = "create intermediate metrics",
        .cb_process_metrics = create_intermediate_metrics
    };
    struct flb_processor_plugin second = {
        .name = "test_metrics_failure",
        .description = "fail metrics processing",
        .cb_process_metrics = fail_metrics_processing
    };

    flb_init_env();
    config = flb_config_init();
    TEST_ASSERT(config != NULL);
    mk_list_add(&first._head, &config->processor_plugins);
    mk_list_add(&second._head, &config->processor_plugins);
    proc = flb_processor_create(config, "failure", NULL, 0);
    TEST_ASSERT(proc != NULL);
    TEST_ASSERT(flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, first.name) != NULL);
    TEST_ASSERT(flb_processor_unit_create(proc, FLB_PROCESSOR_METRICS, second.name) != NULL);
    TEST_ASSERT(flb_processor_init(proc) == 0);
    input = cmt_create();
    TEST_ASSERT(input != NULL);
    output = input;
    TEST_CHECK(flb_processor_run(proc, 0, FLB_PROCESSOR_METRICS, "test", 4,
                                input, 0, &output, &output_size) == -1);
    TEST_CHECK(output == NULL);
    TEST_CHECK(output_size == 0);
    /* The caller still owns the original input after a failed pipeline. */
    cmt_destroy(input);
    flb_processor_destroy(proc);
    mk_list_del(&first._head);
    mk_list_del(&second._head);
    flb_config_exit(config);
}

/* records per group and around the groups of the windowed buffer */
#define WINDOW_GROUPS          3
#define WINDOW_GROUP_RECORDS   1500
#define WINDOW_PLAIN_RECORDS   2000
#define WINDOW_TOTAL_RECORDS   (WINDOW_GROUPS * WINDOW_GROUP_RECORDS + \
                                2 * WINDOW_PLAIN_RECORDS)

static int window_calls;
static int window_max_records;

static int append_window_record(struct flb_log_event_encoder *encoder, int seq)
{
    int ret;
    struct flb_time ts;

    ret = flb_log_event_encoder_begin_record(encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    flb_time_set(&ts, 1700000000 + seq, 0);
    ret = flb_log_event_encoder_set_timestamp(encoder, &ts);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("seq"),
            FLB_LOG_EVENT_INT64_VALUE(seq),
            FLB_LOG_EVENT_CSTRING_VALUE("message"),
            FLB_LOG_EVENT_CSTRING_VALUE("windowed processing test record"));
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(encoder);
    }

    return ret == FLB_EVENT_ENCODER_SUCCESS ? 0 : -1;
}

/* plain records, groups larger than the window record limit, plain records */
static int create_window_records(char **out_buf, size_t *out_size)
{
    int i;
    int g;
    int seq = 0;
    int ret = 0;
    char name[8];
    struct flb_log_event_encoder *encoder;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (encoder == NULL) {
        return -1;
    }

    for (i = 0; ret == 0 && i < WINDOW_PLAIN_RECORDS; i++) {
        ret = append_window_record(encoder, seq++);
    }

    for (g = 0; ret == 0 && g < WINDOW_GROUPS; g++) {
        snprintf(name, sizeof(name), "g%d", g);
        if (flb_log_event_encoder_group_init(encoder) != 0) {
            ret = -1;
            break;
        }

        ret = flb_log_event_encoder_append_metadata_values(
                encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("group"),
                FLB_LOG_EVENT_CSTRING_VALUE(name));
        if (ret != FLB_EVENT_ENCODER_SUCCESS ||
            flb_log_event_encoder_group_header_end(encoder) != 0) {
            ret = -1;
            break;
        }

        for (i = 0; ret == 0 && i < WINDOW_GROUP_RECORDS; i++) {
            ret = append_window_record(encoder, seq++);
        }

        if (ret == 0 && flb_log_event_encoder_group_end(encoder) != 0) {
            ret = -1;
        }
    }

    for (i = 0; ret == 0 && i < WINDOW_PLAIN_RECORDS; i++) {
        ret = append_window_record(encoder, seq++);
    }

    if (ret != 0) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }

    *out_buf = flb_malloc(encoder->output_length);
    if (*out_buf == NULL) {
        flb_log_event_encoder_destroy(encoder);
        return -1;
    }
    memcpy(*out_buf, encoder->output_buffer, encoder->output_length);
    *out_size = encoder->output_length;
    flb_log_event_encoder_destroy(encoder);

    return 0;
}

static int mark_window_records(struct flb_processor_instance *ins, void *data,
                               const char *tag, int tag_len)
{
    int type;
    int records = 0;
    struct flb_mp_chunk_cobj *chunk = data;
    struct flb_mp_chunk_record *record;

    while (flb_mp_chunk_cobj_record_next(chunk, &record) == FLB_MP_CHUNK_RECORD_OK) {
        if (flb_log_event_decoder_get_record_type(&record->event, &type) != 0 ||
            type != FLB_LOG_EVENT_NORMAL) {
            continue;
        }
        records++;
        if (cfl_kvlist_insert_int64(record->cobj_record->variant->data.as_kvlist,
                                    "x", 1) != 0) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    window_calls++;
    if (records > window_max_records) {
        window_max_records = records;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int drop_window_records(struct flb_processor_instance *ins, void *data,
                               const char *tag, int tag_len)
{
    int type;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct flb_mp_chunk_cobj *chunk = data;
    struct flb_mp_chunk_record *record;

    while (flb_mp_chunk_cobj_record_next(chunk, &record) == FLB_MP_CHUNK_RECORD_OK) {
    }
    chunk->record_pos = NULL;

    cfl_list_foreach_safe(head, tmp, &chunk->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        if (flb_log_event_decoder_get_record_type(&record->event, &type) == 0 &&
            type == FLB_LOG_EVENT_NORMAL) {
            flb_mp_chunk_cobj_record_destroy(chunk, record);
        }
    }

    window_calls++;
    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_processor_plugin window_mark_plugin = {
    .name = "test_window_mark",
    .description = "windowed record marker",
    .cb_process_logs = mark_window_records,
    .flags = FLB_PROCESSOR_FLAG_LOG_WINDOWS
};

static struct flb_processor_plugin single_mark_plugin = {
    .name = "test_single_mark",
    .description = "single chunk record marker",
    .cb_process_logs = mark_window_records,
    .flags = 0
};

static struct flb_processor_plugin window_drop_plugin = {
    .name = "test_window_drop",
    .description = "windowed record dropper",
    .cb_process_logs = drop_window_records,
    .flags = FLB_PROCESSOR_FLAG_LOG_WINDOWS
};

static struct flb_config *window_config_create(void)
{
    struct flb_config *config;

    flb_init_env();
    config = flb_config_init();
    if (config == NULL) {
        return NULL;
    }
    mk_list_add(&window_mark_plugin._head, &config->processor_plugins);
    mk_list_add(&single_mark_plugin._head, &config->processor_plugins);
    mk_list_add(&window_drop_plugin._head, &config->processor_plugins);

    return config;
}

static void window_config_destroy(struct flb_config *config)
{
    mk_list_del(&window_mark_plugin._head);
    mk_list_del(&single_mark_plugin._head);
    mk_list_del(&window_drop_plugin._head);
    flb_config_exit(config);
}

static struct flb_processor *window_processor_create(struct flb_config *config,
                                                     struct flb_input_instance *owner,
                                                     char *first, char *second)
{
    struct flb_processor *proc;

    proc = flb_processor_create(config, "window_test", NULL, 0);
    if (proc == NULL) {
        return NULL;
    }
    proc->data = owner;
    proc->source_plugin_type = FLB_PLUGIN_INPUT;

    if (flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, first) == NULL ||
        (second && flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, second) == NULL) ||
        flb_processor_init(proc) != 0) {
        flb_processor_destroy(proc);
        return NULL;
    }

    return proc;
}

/* checks order, the processor mark and that every group stayed whole */
static void check_window_output(char *buf, size_t size)
{
    int ret;
    int type;
    int seq = 0;
    int groups = 0;
    int in_group = FLB_FALSE;
    int group_records = 0;
    char name[8];
    msgpack_object *value;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;

    ret = flb_log_event_decoder_init(&decoder, buf, size);
    TEST_ASSERT(ret == FLB_EVENT_DECODER_SUCCESS);
    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);

    while (flb_log_event_decoder_next(&decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {
        TEST_ASSERT(flb_log_event_decoder_get_record_type(&event, &type) == 0);

        if (type == FLB_LOG_EVENT_GROUP_START) {
            TEST_CHECK(in_group == FLB_FALSE);
            snprintf(name, sizeof(name), "g%d", groups);
            value = &event.metadata->via.map.ptr[0].val;
            TEST_CHECK(event.metadata->via.map.size == 1);
            TEST_CHECK(value->type == MSGPACK_OBJECT_STR &&
                       value->via.str.size == strlen(name) &&
                       memcmp(value->via.str.ptr, name, strlen(name)) == 0);
            in_group = FLB_TRUE;
            group_records = 0;
            continue;
        }
        else if (type == FLB_LOG_EVENT_GROUP_END) {
            TEST_CHECK(in_group == FLB_TRUE);
            TEST_CHECK(group_records == WINDOW_GROUP_RECORDS);
            in_group = FLB_FALSE;
            groups++;
            continue;
        }

        if (in_group) {
            group_records++;
        }
        TEST_CHECK(event.body->type == MSGPACK_OBJECT_MAP &&
                   event.body->via.map.size == 3);
        TEST_CHECK(event.body->via.map.ptr[0].val.via.i64 == seq);
        TEST_CHECK(event.body->via.map.ptr[2].val.via.i64 == 1);
        seq++;
    }

    TEST_CHECK(seq == WINDOW_TOTAL_RECORDS);
    TEST_CHECK(groups == WINDOW_GROUPS);
    TEST_CHECK(in_group == FLB_FALSE);
    flb_log_event_decoder_destroy(&decoder);
}

static void processor_log_windows_match_single_chunk(void)
{
    int ret;
    int records;
    int single_calls;
    char *input;
    size_t input_size;
    void *windowed;
    size_t windowed_size;
    void *single;
    size_t single_size;
    double items_in;
    double items_out;
    double invocations;
    char stage_label[32];
    struct flb_config *config;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_input_instance owner;

    config = window_config_create();
    TEST_ASSERT(config != NULL);
    memset(&owner, 0, sizeof(owner));
    snprintf(owner.name, sizeof(owner.name), "%s", "window_input.0");
    owner.cmt = cmt_create();
    TEST_ASSERT(owner.cmt != NULL);
    TEST_ASSERT(create_window_records(&input, &input_size) == 0);
    TEST_CHECK(input_size > 4 * 65536);

    /* the single chunk reference */
    proc = window_processor_create(config, &owner, "test_single_mark", NULL);
    TEST_ASSERT(proc != NULL);
    window_calls = 0;
    window_max_records = 0;
    ret = flb_processor_run(proc, 0, FLB_PROCESSOR_LOGS, "test", 4,
                            input, input_size, &single, &single_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(window_calls == 1);
    TEST_CHECK(window_max_records == WINDOW_TOTAL_RECORDS);
    single_calls = window_calls;
    flb_processor_destroy(proc);

    /* the windowed run must produce the same bytes */
    proc = window_processor_create(config, &owner, "test_window_mark", NULL);
    TEST_ASSERT(proc != NULL);
    window_calls = 0;
    window_max_records = 0;
    records = -1;
    ret = flb_processor_run_with_count(proc, 0, FLB_PROCESSOR_LOGS, "test", 4,
                                       input, input_size, &windowed, &windowed_size,
                                       -1, &records);
    TEST_CHECK(ret == 0);
    TEST_CHECK(window_calls > single_calls);
    /* windows hold at most the record limit plus one whole group */
    TEST_CHECK(window_max_records <= 1024 + WINDOW_GROUP_RECORDS);
    TEST_CHECK(records == WINDOW_TOTAL_RECORDS);
    TEST_CHECK(windowed != NULL && windowed != input);
    TEST_CHECK(windowed_size == single_size);
    TEST_CHECK(windowed_size == single_size &&
               memcmp(windowed, single, single_size) == 0);
    check_window_output(windowed, windowed_size);

    /* one invocation per buffer, with logical record counts */
    pu = mk_list_entry(proc->logs.next, struct flb_processor_unit, _head);
    snprintf(stage_label, sizeof(stage_label), "%zu", pu->stage);
    TEST_CHECK(get_counter_value_5(proc->cmt_invocations, "input", "window_input.0",
                                   (char *) pu->name, stage_label, "logs",
                                   &invocations) == 0);
    TEST_CHECK(get_counter_value_5(proc->cmt_items_in, "input", "window_input.0",
                                   (char *) pu->name, stage_label, "logs",
                                   &items_in) == 0);
    TEST_CHECK(get_counter_value_5(proc->cmt_items_out, "input", "window_input.0",
                                   (char *) pu->name, stage_label, "logs",
                                   &items_out) == 0);
    TEST_CHECK(invocations == 1.0);
    TEST_CHECK(items_in == WINDOW_TOTAL_RECORDS);
    TEST_CHECK(items_out == WINDOW_TOTAL_RECORDS);
    flb_processor_destroy(proc);

    flb_free(windowed);
    flb_free(single);
    flb_free(input);
    cmt_destroy(owner.cmt);
    window_config_destroy(config);
}

static void processor_log_windows_drop_all(void)
{
    int ret;
    int records;
    char *input;
    size_t input_size;
    void *output;
    size_t output_size;
    double items_drop;
    char stage_label[32];
    struct flb_config *config;
    struct flb_processor *proc;
    struct flb_processor_unit *pu;
    struct flb_input_instance owner;

    config = window_config_create();
    TEST_ASSERT(config != NULL);
    memset(&owner, 0, sizeof(owner));
    snprintf(owner.name, sizeof(owner.name), "%s", "window_input.0");
    owner.cmt = cmt_create();
    TEST_ASSERT(owner.cmt != NULL);
    TEST_ASSERT(create_window_records(&input, &input_size) == 0);

    proc = window_processor_create(config, &owner, "test_window_drop", NULL);
    TEST_ASSERT(proc != NULL);
    window_calls = 0;
    records = -1;
    output = input;
    output_size = input_size;
    ret = flb_processor_run_with_count(proc, 0, FLB_PROCESSOR_LOGS, "test", 4,
                                       input, input_size, &output, &output_size,
                                       -1, &records);
    TEST_CHECK(ret == 0);
    TEST_CHECK(window_calls > 1);
    TEST_CHECK(output == NULL);
    TEST_CHECK(output_size == 0);
    TEST_CHECK(records == 0);

    pu = mk_list_entry(proc->logs.next, struct flb_processor_unit, _head);
    snprintf(stage_label, sizeof(stage_label), "%zu", pu->stage);
    TEST_CHECK(get_counter_value_5(proc->cmt_items_drop, "input", "window_input.0",
                                   (char *) pu->name, stage_label, "logs",
                                   &items_drop) == 0);
    TEST_CHECK(items_drop == WINDOW_TOTAL_RECORDS);

    flb_processor_destroy(proc);
    flb_free(input);
    cmt_destroy(owner.cmt);
    window_config_destroy(config);
}

static void processor_log_windows_need_every_unit(void)
{
    int i;
    int ret;
    char *input;
    size_t input_size;
    void *output;
    size_t output_size;
    struct flb_config *config;
    struct flb_processor *proc;
    struct flb_input_instance owner;
    struct flb_log_event_encoder *encoder;

    config = window_config_create();
    TEST_ASSERT(config != NULL);
    memset(&owner, 0, sizeof(owner));
    snprintf(owner.name, sizeof(owner.name), "%s", "window_input.0");
    owner.cmt = cmt_create();
    TEST_ASSERT(owner.cmt != NULL);
    TEST_ASSERT(create_window_records(&input, &input_size) == 0);

    /* a unit without the capability keeps the whole run on one chunk */
    proc = window_processor_create(config, &owner, "test_window_mark",
                                   "test_single_mark");
    TEST_ASSERT(proc != NULL);
    window_calls = 0;
    window_max_records = 0;
    ret = flb_processor_run(proc, 0, FLB_PROCESSOR_LOGS, "test", 4,
                            input, input_size, &output, &output_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(window_calls == 2);
    TEST_CHECK(window_max_records == WINDOW_TOTAL_RECORDS);
    flb_free(output);
    flb_processor_destroy(proc);

    flb_free(input);

    /* a buffer within one window keeps the single chunk path */
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    for (i = 0; i < 300; i++) {
        TEST_ASSERT(append_window_record(encoder, i) == 0);
    }
    proc = window_processor_create(config, &owner, "test_window_mark", NULL);
    TEST_ASSERT(proc != NULL);
    window_calls = 0;
    window_max_records = 0;
    ret = flb_processor_run(proc, 0, FLB_PROCESSOR_LOGS, "test", 4,
                            encoder->output_buffer, encoder->output_length,
                            &output, &output_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(window_calls == 1);
    TEST_CHECK(window_max_records == 300);
    flb_free(output);
    flb_processor_destroy(proc);
    flb_log_event_encoder_destroy(encoder);

    cmt_destroy(owner.cmt);
    window_config_destroy(config);
}

/*
 * The decoded chunk outlives the first unit's lock, so it must decode and
 * encode with its own codec: another worker thread can reset the first
 * unit's decoder while later units still read records from the chunk.
 */
static int codec_shared;

static int probe_codec_and_stop(struct flb_processor_instance *ins, void *data,
                                const char *tag, int tag_len)
{
    struct flb_mp_chunk_cobj *chunk = data;
    struct flb_mp_chunk_record *record;

    /* callbacks run under the unit lock, so the counter needs no atomics */
    if (chunk->log_decoder == ins->log_decoder || chunk->log_encoder == ins->log_encoder) {
        codec_shared++;
    }

    /* leave the remaining records for the next unit to decode */
    flb_mp_chunk_cobj_record_next(chunk, &record);
    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_processor_plugin codec_probe_plugin = {
    .name = "test_codec_probe",
    .description = "checks the chunk codec and stops early",
    .cb_process_logs = probe_codec_and_stop,
    .flags = 0
};

static struct flb_processor_plugin codec_window_probe_plugin = {
    .name = "test_codec_window_probe",
    .description = "checks the chunk codec and stops early, windowed",
    .cb_process_logs = probe_codec_and_stop,
    .flags = FLB_PROCESSOR_FLAG_LOG_WINDOWS
};

struct codec_worker {
    struct flb_processor *proc;
    char *input;
    size_t input_size;
    int expected;
    int failures;
};

static void *codec_worker_run(void *data)
{
    int i;
    int ret;
    int records;
    void *output;
    size_t output_size;
    struct codec_worker *worker = data;

    for (i = 0; i < 50; i++) {
        records = -1;
        output = NULL;
        ret = flb_processor_run_with_count(worker->proc, 0, FLB_PROCESSOR_LOGS, "test", 4,
                                           worker->input, worker->input_size,
                                           &output, &output_size, -1, &records);
        if (ret != 0 || records != worker->expected || output == NULL) {
            worker->failures++;
        }
        if (output != NULL && output != worker->input) {
            flb_free(output);
        }
    }

    return NULL;
}

static void run_codec_workers(struct flb_config *config, char *first, char *second,
                              char *input, size_t input_size, int expected)
{
    int i;
    struct flb_processor *proc;
    struct flb_input_instance owner;
    struct codec_worker workers[4];
    pthread_t threads[4];

    memset(&owner, 0, sizeof(owner));
    snprintf(owner.name, sizeof(owner.name), "%s", "window_input.0");
    owner.cmt = cmt_create();
    TEST_ASSERT(owner.cmt != NULL);
    proc = window_processor_create(config, &owner, first, second);
    TEST_ASSERT(proc != NULL);

    for (i = 0; i < 4; i++) {
        workers[i].proc = proc;
        workers[i].input = input;
        workers[i].input_size = input_size;
        workers[i].expected = expected;
        workers[i].failures = 0;
        TEST_ASSERT(pthread_create(&threads[i], NULL, codec_worker_run, &workers[i]) == 0);
    }
    for (i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
        TEST_CHECK(workers[i].failures == 0);
    }

    flb_processor_destroy(proc);
    cmt_destroy(owner.cmt);
}

static void processor_chunk_codec_is_per_run(void)
{
    int i;
    char *input;
    size_t input_size;
    struct flb_config *config;
    struct flb_log_event_encoder *encoder;

    config = window_config_create();
    TEST_ASSERT(config != NULL);
    mk_list_add(&codec_probe_plugin._head, &config->processor_plugins);
    mk_list_add(&codec_window_probe_plugin._head, &config->processor_plugins);
    codec_shared = 0;

    /* single chunk path: the second unit decodes what the first one left */
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    for (i = 0; i < 300; i++) {
        TEST_ASSERT(append_window_record(encoder, i) == 0);
    }
    run_codec_workers(config, "test_codec_probe", "test_single_mark",
                      encoder->output_buffer, encoder->output_length, 300);
    flb_log_event_encoder_destroy(encoder);

    /* windowed path */
    TEST_ASSERT(create_window_records(&input, &input_size) == 0);
    run_codec_workers(config, "test_codec_window_probe", "test_window_mark",
                      input, input_size, WINDOW_TOTAL_RECORDS);
    flb_free(input);

    TEST_CHECK(codec_shared == 0);

    mk_list_del(&codec_probe_plugin._head);
    mk_list_del(&codec_window_probe_plugin._head);
    window_config_destroy(config);
}

/* removes group end markers, as a filtering processor can do */
static int drop_group_ends(struct flb_processor_instance *ins, void *data,
                           const char *tag, int tag_len)
{
    int type;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct flb_mp_chunk_cobj *chunk = data;
    struct flb_mp_chunk_record *record;

    while (flb_mp_chunk_cobj_record_next(chunk, &record) == FLB_MP_CHUNK_RECORD_OK) {
    }
    chunk->record_pos = NULL;

    cfl_list_foreach_safe(head, tmp, &chunk->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        if (flb_log_event_decoder_get_record_type(&record->event, &type) == 0 &&
            type == FLB_LOG_EVENT_GROUP_END) {
            flb_mp_chunk_cobj_record_destroy(chunk, record);
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_processor_plugin drop_group_end_plugin = {
    .name = "test_drop_group_end",
    .description = "removes group end markers",
    .cb_process_logs = drop_group_ends,
    .flags = 0
};

/* layout tokens: r<n> record, S group start, E group end */
static void run_group_layout(struct flb_config *config, char *unit,
                             const char *layout, const char *expected)
{
    int ret;
    int type;
    int length;
    char token[16];
    char result[128];
    const char *cursor;
    void *output = NULL;
    size_t output_size = 0;
    msgpack_object *seq;
    struct flb_processor *proc;
    struct flb_input_instance owner;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;
    struct flb_log_event_encoder *encoder;

    memset(&owner, 0, sizeof(owner));
    snprintf(owner.name, sizeof(owner.name), "%s", "window_input.0");
    owner.cmt = cmt_create();
    TEST_ASSERT(owner.cmt != NULL);
    proc = window_processor_create(config, &owner, unit, NULL);
    TEST_ASSERT(proc != NULL);

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    for (cursor = layout; sscanf(cursor, "%15s%n", token, &length) == 1; cursor += length) {
        if (token[0] == 'r') {
            TEST_ASSERT(append_window_record(encoder, atoi(token + 1)) == 0);
        }
        else if (token[0] == 'S') {
            TEST_ASSERT(flb_log_event_encoder_group_init(encoder) == 0);
            TEST_ASSERT(flb_log_event_encoder_group_header_end(encoder) == 0);
        }
        else {
            TEST_ASSERT(flb_log_event_encoder_group_end(encoder) == 0);
        }
    }

    ret = flb_processor_run(proc, 0, FLB_PROCESSOR_LOGS, "test", 4,
                            encoder->output_buffer, encoder->output_length,
                            &output, &output_size);
    TEST_CHECK(ret == 0);

    result[0] = '\0';
    if (output != NULL && output_size > 0) {
        TEST_ASSERT(flb_log_event_decoder_init(&decoder, output, output_size) == 0);
        flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);
        while (flb_log_event_decoder_next(&decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {
            TEST_ASSERT(flb_log_event_decoder_get_record_type(&event, &type) == 0);
            if (type == FLB_LOG_EVENT_GROUP_START) {
                snprintf(token, sizeof(token), "S ");
            }
            else if (type == FLB_LOG_EVENT_GROUP_END) {
                snprintf(token, sizeof(token), "E ");
            }
            else {
                seq = &event.body->via.map.ptr[0].val;
                snprintf(token, sizeof(token), "r%d ", (int) seq->via.i64);
            }
            strncat(result, token, sizeof(result) - strlen(result) - 1);
        }
        flb_log_event_decoder_destroy(&decoder);
    }
    if (strlen(result) > 0) {
        result[strlen(result) - 1] = '\0';
    }
    TEST_CHECK(strcmp(result, expected) == 0);
    TEST_MSG("%s: '%s' produced '%s', expected '%s'", unit, layout, result, expected);

    if (output != NULL && output != encoder->output_buffer) {
        flb_free(output);
    }
    flb_log_event_encoder_destroy(encoder);
    flb_processor_destroy(proc);
    cmt_destroy(owner.cmt);
}

static void processor_group_boundaries_follow_the_input(void)
{
    struct flb_config *config;

    config = window_config_create();
    TEST_ASSERT(config != NULL);
    mk_list_add(&drop_group_end_plugin._head, &config->processor_plugins);

    /* a processor removing an end never leaves an orphan start behind */
    run_group_layout(config, "test_drop_group_end", "S r0 r1 E r2", "r0 r1 r2");
    /* groups split across appends keep their boundary markers */
    run_group_layout(config, "test_single_mark", "S r0 r1", "S r0 r1");
    run_group_layout(config, "test_single_mark", "r0 E S r1 E", "r0 E S r1 E");
    /* stray and empty markers of a balanced input are removed as before */
    run_group_layout(config, "test_single_mark", "S r0 E E r1", "S r0 E r1");

    mk_list_del(&drop_group_end_plugin._head);
    window_config_destroy(config);
}

static int native_drop_second_record(struct flb_processor_instance *ins,
                                      void *data, const char *tag, int tag_len)
{
    int ret;
    int type;
    int count;
    struct flb_mp_chunk_cobj *chunk;
    struct flb_mp_chunk_record *record;

    chunk = data;
    count = 0;
    while ((ret = flb_mp_chunk_cobj_record_next(chunk, &record)) == FLB_MP_CHUNK_RECORD_OK) {
        TEST_CHECK(flb_log_event_decoder_get_record_type(&record->event, &type) == 0);
        if (type == FLB_LOG_EVENT_NORMAL && ++count == 2) {
            TEST_CHECK(flb_mp_chunk_cobj_record_destroy(chunk, record) == 0);
        }
    }
    return ret == FLB_MP_CHUNK_RECORD_EOF ? FLB_PROCESSOR_SUCCESS : FLB_PROCESSOR_FAILURE;
}

static void processor_native_chain_counters(void)
{
    int grouped;
    int root_type;
    char *data;
    char *resized;
    size_t bytes;
    size_t out_size;
    void *out;
    double value;
    struct flb_config *config;
    struct flb_processor *proc;
    struct flb_processor_unit *first;
    struct flb_processor_unit *second;
    struct flb_processor_instance *ins;
    struct flb_processor_plugin *original;
    struct flb_processor_plugin drop;
    struct flb_input_instance owner;
    const char *json = "[[1700000000,{}],{\"message\":\"first\"}]"
                       "[[1700000001,{}],{\"message\":\"second\"}]";

    flb_init_env();
    for (grouped = 0; grouped <= 1; grouped++) {
        config = flb_config_init();
        TEST_CHECK(config != NULL);
        memset(&owner, 0, sizeof(owner));
        snprintf(owner.name, sizeof(owner.name), "unit_input.0");
        owner.cmt = cmt_create();
        TEST_CHECK(owner.cmt != NULL);
        proc = flb_processor_create(config, "native_counters", &owner, FLB_PLUGIN_INPUT);
        TEST_CHECK(proc != NULL);
        first = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "content_modifier");
        second = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "content_modifier");
        TEST_CHECK(first != NULL && second != NULL);
        TEST_CHECK(flb_processor_unit_set_property_str(first, "action", "insert") == 0);
        TEST_CHECK(flb_processor_unit_set_property_str(first, "key", "unused") == 0);
        TEST_CHECK(flb_processor_unit_set_property_str(first, "value", "unused") == 0);
        TEST_CHECK(flb_processor_unit_set_property_str(second, "action", "insert") == 0);
        TEST_CHECK(flb_processor_unit_set_property_str(second, "key", "after_drop") == 0);
        TEST_CHECK(flb_processor_unit_set_property_str(second, "value", "yes") == 0);
        TEST_CHECK(flb_processor_init(proc) == 0);
        ins = first->ctx;
        original = ins->p;
        drop = *original;
        drop.cb_process_logs_raw = NULL;
        drop.cb_process_logs = native_drop_second_record;
        ins->p = &drop;
        if (grouped) {
            TEST_CHECK(create_grouped_msgpack_records(&data, &bytes) == 0);
            resized = flb_realloc(data, bytes * 2);
            TEST_CHECK(resized != NULL);
            data = resized;
            memcpy(data + bytes, data, bytes);
            bytes *= 2;
        }
        else {
            TEST_CHECK(flb_pack_json(json, strlen(json), &data, &bytes, &root_type, NULL) == 0);
        }
        TEST_CHECK(flb_mp_count_log_records(data, bytes) == 2);
        out = NULL;
        TEST_CHECK(flb_processor_run(proc, 0, FLB_PROCESSOR_LOGS, "test", 4,
                                    data, bytes, &out, &out_size) == 0);
        TEST_CHECK(flb_mp_count_log_records(out, out_size) == 1);
        TEST_CHECK(get_counter_value_5(proc->cmt_items_in, "input", "unit_input.0",
                                       "content_modifier", "0", "logs", &value) == 0);
        TEST_CHECK(value == 2.0);
        TEST_CHECK(get_counter_value_5(proc->cmt_items_out, "input", "unit_input.0",
                                       "content_modifier", "0", "logs", &value) == 0);
        TEST_CHECK(value == 1.0);
        TEST_CHECK(get_counter_value_5(proc->cmt_items_in, "input", "unit_input.0",
                                       "content_modifier", "1", "logs", &value) == 0);
        TEST_CHECK(value == 1.0);
        TEST_CHECK(get_counter_value_5(proc->cmt_items_out, "input", "unit_input.0",
                                       "content_modifier", "1", "logs", &value) == 0);
        TEST_CHECK(value == 1.0);
        TEST_CHECK(get_counter_value_5(proc->cmt_items_drop, "input", "unit_input.0",
                                       "content_modifier", "0", "logs", &value) == 0);
        TEST_CHECK(value == 1.0);
        TEST_CHECK(get_counter_value_5_or_zero(proc->cmt_items_drop, "input", "unit_input.0",
                                               "content_modifier", "1", "logs", &value) == 0);
        TEST_CHECK(value == 0.0);
        ins->p = original;
        if (out != data) {
            flb_free(out);
        }
        flb_free(data);
        flb_processor_destroy(proc);
        cmt_destroy(owner.cmt);
        flb_config_exit(config);
    }
}

TEST_LIST = {
    { "processor_native_chain_counters", processor_native_chain_counters },
    {"processor_metrics_failure_clears_output", processor_metrics_failure_clears_output},
    { "processor_private_inputs_use_main_loop", processor_private_inputs_use_main_loop },
    { "processor", processor },
    { "processor_grouped_filter_counters", processor_grouped_filter_counters },
    { "processor_metrics_counters", processor_metrics_counters },
    { "processor_log_windows_match_single_chunk", processor_log_windows_match_single_chunk },
    { "processor_log_windows_drop_all", processor_log_windows_drop_all },
    { "processor_log_windows_need_every_unit", processor_log_windows_need_every_unit },
    { "processor_chunk_codec_is_per_run", processor_chunk_codec_is_per_run },
    { "processor_group_boundaries_follow_the_input", processor_group_boundaries_follow_the_input },
    { 0 }
};
