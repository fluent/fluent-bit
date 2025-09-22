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
}

TEST_LIST = {
    { "processor_private_inputs_use_main_loop", processor_private_inputs_use_main_loop },
    { "processor", processor },
    { 0 }
};
