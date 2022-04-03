/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <mpack/mpack.h>
#include "flb_tests_internal.h"


void test_to_nanosec()
{
    uint64_t expect = 123000000456;
    uint64_t ret;
    struct flb_time tm;

    flb_time_set(&tm, 123, 456);

    ret = flb_time_to_nanosec(&tm);
    if (!TEST_CHECK(ret == expect)) {
      TEST_MSG("given  =%" PRIu64, ret);
      TEST_MSG("expect =%" PRIu64, expect);
    }
}

/* https://github.com/fluent/fluent-bit/issues/5215 */
void test_append_to_mpack_v1() {
    mpack_writer_t writer;
    char *data;
    size_t size;
    struct flb_time tm;
    int ret;

    msgpack_zone mempool;
    msgpack_object ret_obj;
    size_t off = 0;

    flb_time_set(&tm, 123, 456);
    mpack_writer_init_growable(&writer, &data, &size);

    ret = flb_time_append_to_mpack(&writer, &tm, FLB_TIME_ETFMT_V1_FIXEXT);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_time_append_to_mpack failed");
        mpack_writer_destroy(&writer);
        flb_free(data);
        exit(EXIT_FAILURE);
    }
    mpack_writer_destroy(&writer);

    msgpack_zone_init(&mempool, 1024);
    ret = msgpack_unpack(data, size, &off, &mempool, &ret_obj);
    if (!TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS)) {
        TEST_MSG("unpack failed ret = %d", ret);
        msgpack_zone_destroy(&mempool);
        flb_free(data);
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(ret_obj.type == MSGPACK_OBJECT_EXT)) {
        TEST_MSG("data type is not ext. type=%d", ret_obj.type);
        msgpack_zone_destroy(&mempool);
        flb_free(data);
        exit(EXIT_FAILURE);
    }
    if (!TEST_CHECK(ret_obj.via.ext.type == 0)) {
        TEST_MSG("ext type is not 0. ext type=%d", ret_obj.via.ext.type);
        msgpack_zone_destroy(&mempool);
        flb_free(data);
        exit(EXIT_FAILURE);
    }
    msgpack_zone_destroy(&mempool);
    flb_free(data);
}

TEST_LIST = {
    { "flb_time_to_nanosec"           , test_to_nanosec},
    { "flb_time_append_to_mpack_v1"   , test_append_to_mpack_v1},
    { NULL, NULL }
};
