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
        if (out_buf != NULL) {
            flb_free(out_buf);
            out_buf = NULL;
        }
        flb_free(mp_buf);
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

TEST_LIST = {
    { "processor_private_inputs_use_main_loop", processor_private_inputs_use_main_loop },
    { "processor", processor },
    { "processor_grouped_filter_counters", processor_grouped_filter_counters },
    { 0 }
};
