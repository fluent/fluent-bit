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
//#include <msgpack.h>

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

    printf("\n\n");

    flb_init_env();

    config = flb_config_init();
    TEST_CHECK(config != NULL);

    proc = flb_processor_create(config, "unit_test", NULL, 0);
    TEST_CHECK(proc != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "stdout");
    TEST_CHECK(pu != NULL);

    pu = flb_processor_unit_create(proc, FLB_PROCESSOR_LOGS, "modify");
    TEST_CHECK(pu != NULL);

    ret = flb_processor_unit_set_property(pu, "add", "hostname monox");
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

}

TEST_LIST = {
    { "processor", processor },
    { 0 }
};
