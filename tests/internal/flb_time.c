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
#include <fluent-bit/flb_pack.h>
#include <mpack/mpack.h>
#include <msgpack.h>
#include <msgpack/timestamp.h>
#include <string.h>
#include "flb_tests_internal.h"

#define SEC_32BIT  1647061992 /* 0x622c2be8 */
#define NSEC_32BIT 123000000  /* 123ms 0x0754d4c0 */
#define D_SEC 1647061992.123;
const char eventtime[8] = {0x62, 0x2c, 0x2b, 0xe8, 0x07, 0x54, 0xd4, 0xc0 };

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

void test_msgpack_to_time_int()
{
    struct flb_time tm;
    int64_t expect = SEC_32BIT;
    int ret;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;

    msgpack_object tm_obj;

    /* create int object*/
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_int(&mp_pck, expect);

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, NULL);

    tm_obj = result.data;
    ret = flb_time_msgpack_to_time(&tm, &tm_obj);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_time_msgpack_to_time failed");
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(tm.tm.tv_sec == expect && tm.tm.tv_nsec == 0)) {
        TEST_MSG("got %ld.%ld, expect %ld.%d", tm.tm.tv_sec, tm.tm.tv_nsec, expect, 0);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_unpacked_destroy(&result);
}

void test_msgpack_to_time_double()
{
    struct flb_time tm;
    double d_time = D_SEC;
    int64_t expect_sec = SEC_32BIT;
    int64_t expect_nsec = NSEC_32BIT;

    int ret;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;

    msgpack_object tm_obj;

    /* create int object*/
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_double(&mp_pck, d_time);

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, NULL);

    tm_obj = result.data;
    ret = flb_time_msgpack_to_time(&tm, &tm_obj);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_time_msgpack_to_time failed");
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(tm.tm.tv_sec == expect_sec &&
                    llabs(tm.tm.tv_nsec - expect_nsec ) < 10000 /* 10us*/)) {
        TEST_MSG("got %ld.%ld, expect %ld.%ld", tm.tm.tv_sec, tm.tm.tv_nsec, expect_sec, expect_nsec);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_unpacked_destroy(&result);
}

void test_msgpack_to_time_eventtime()
{
    struct flb_time tm;
    int64_t expect_sec = SEC_32BIT;
    int64_t expect_nsec = NSEC_32BIT;
    char ext_data[8] = {0};
    int ret;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;

    msgpack_object tm_obj;

    memcpy(&ext_data[0], &eventtime[0], 8);

    /* create int object*/
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v1#eventtime-ext-format */
    msgpack_pack_ext(&mp_pck, 8/*fixext8*/, 0);
    msgpack_pack_ext_body(&mp_pck, ext_data, sizeof(ext_data));

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, NULL);

    tm_obj = result.data;
    ret = flb_time_msgpack_to_time(&tm, &tm_obj);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_time_msgpack_to_time failed");
        exit(EXIT_FAILURE);
    }

    if (!TEST_CHECK(tm.tm.tv_sec == expect_sec &&
                    llabs(tm.tm.tv_nsec - expect_nsec ) < 10000 /* 10us*/)) {
        TEST_MSG("got %ld.%ld, expect %ld.%ld", tm.tm.tv_sec, tm.tm.tv_nsec, expect_sec, expect_nsec);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_unpacked_destroy(&result);
}

void test_eventtime_boundaries()
{
    struct flb_time tm;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    msgpack_object tm_obj;
    uint32_t value[2];
    int ret;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    value[0] = htonl(UINT32_MAX - 2);
    value[1] = htonl(999999999);
    msgpack_pack_ext(&mp_pck, 8, 0);
    msgpack_pack_ext_body(&mp_pck, value, sizeof(value));

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, NULL);
    tm_obj = result.data;
    ret = flb_time_msgpack_to_time(&tm, &tm_obj);
    TEST_CHECK(ret == 0);
    TEST_CHECK(tm.tm.tv_sec == (time_t) (UINT32_MAX - 2));
    TEST_CHECK(tm.tm.tv_nsec == 999999999);
    msgpack_unpacked_destroy(&result);

    msgpack_sbuffer_clear(&mp_sbuf);
    value[0] = htonl(2209072510U);
    value[1] = htonl(808241446);
    msgpack_pack_ext(&mp_pck, 8, 0);
    msgpack_pack_ext_body(&mp_pck, value, sizeof(value));
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, NULL);
    tm_obj = result.data;
    ret = flb_time_msgpack_to_time(&tm, &tm_obj);
    TEST_CHECK(ret == 0);
    TEST_CHECK(tm.tm.tv_sec == (time_t) 2209072510U);
    TEST_CHECK(tm.tm.tv_nsec == 808241446);
    msgpack_unpacked_destroy(&result);

    msgpack_sbuffer_clear(&mp_sbuf);
    value[0] = htonl(2209072510U);
    value[1] = htonl(1000000000U);
    msgpack_pack_ext(&mp_pck, 8, 0);
    msgpack_pack_ext_body(&mp_pck, value, sizeof(value));
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, NULL);
    tm_obj = result.data;
    ret = flb_time_msgpack_to_time(&tm, &tm_obj);
    TEST_CHECK(ret != 0);
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&mp_sbuf);
}

void test_from_uint64_post_2038()
{
    struct flb_time tm;
    int ret;

    ret = flb_time_from_uint64(&tm, UINT64_C(2209072510808241446));
    TEST_CHECK(ret == 0);
    TEST_CHECK(tm.tm.tv_sec == (time_t) 2209072510U);
    TEST_CHECK(tm.tm.tv_nsec == 808241446);
}

void test_msgpack_to_time_invalid()
{
    struct flb_time tm;
    char ext_data[8] = {0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    int ret;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;


    msgpack_object tm_obj;

    /* create int object*/
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_ext(&mp_pck, 5 /* invalid size */, 0);
    msgpack_pack_ext_body(&mp_pck, ext_data, 5);

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, NULL);

    tm_obj = result.data;

    /* Check if ext */
    TEST_CHECK(tm_obj.type == MSGPACK_OBJECT_EXT);
    TEST_CHECK(tm_obj.via.ext.type == 0);
    TEST_CHECK(tm_obj.via.ext.size == 5);

    ret = flb_time_msgpack_to_time(&tm, &tm_obj);
    if(!TEST_CHECK(ret != 0)) {
        TEST_MSG("flb_time_msgpack_to_time should fail");
        exit(EXIT_FAILURE);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_unpacked_destroy(&result);


    /* create int object*/
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_ext(&mp_pck, 8, 10 /* invalid type */);
    msgpack_pack_ext_body(&mp_pck, ext_data, 8);

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, NULL);

    tm_obj = result.data;

    /* Check if ext */
    TEST_CHECK(tm_obj.type == MSGPACK_OBJECT_EXT);
    TEST_CHECK(tm_obj.via.ext.type == 10);
    TEST_CHECK(tm_obj.via.ext.size == 8);

    ret = flb_time_msgpack_to_time(&tm, &tm_obj);
    if(!TEST_CHECK(ret != 0)) {
        TEST_MSG("flb_time_msgpack_to_time should fail");
        exit(EXIT_FAILURE);
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_unpacked_destroy(&result);
}

void test_append_to_msgpack_eventtime()
{
    struct flb_time tm;
    int ret;
    char expect_data[8] = {0};

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;

    msgpack_object tm_obj;

    memcpy(&expect_data[0], &eventtime[0], 8);

    tm.tm.tv_sec  = SEC_32BIT;
    tm.tm.tv_nsec = NSEC_32BIT;

    /* create int object*/
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    ret = flb_time_append_to_msgpack(&tm, &mp_pck, FLB_TIME_ETFMT_V1_FIXEXT);
    if(!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_time_append_to_msgpack failed");
        exit(EXIT_FAILURE);
    }
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, NULL);

    tm_obj = result.data;

    /* Check if Eventtime */
    TEST_CHECK(tm_obj.type == MSGPACK_OBJECT_EXT);
    TEST_CHECK(tm_obj.via.ext.type == 0);
    TEST_CHECK(tm_obj.via.ext.size == 8);

    if (!TEST_CHECK(memcmp(&expect_data[0], tm_obj.via.ext.ptr, 8) == 0) ) {
        TEST_MSG("got 0x%x, expect 0x%x", *(uint32_t*)tm_obj.via.ext.ptr, *((uint32_t*)&expect_data[0]));
    }

    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_unpacked_destroy(&result);
}

void test_windows_zone_to_iana()
{
    const char *iana;

    iana = flb_time_windows_zone_to_iana("Pacific Standard Time");
    if (!TEST_CHECK(iana != NULL && strcmp(iana, "America/Los_Angeles") == 0)) {
        TEST_MSG("got %s, expect America/Los_Angeles", iana);
    }

    iana = flb_time_windows_zone_to_iana("arabian standard time");
    if (!TEST_CHECK(iana != NULL && strcmp(iana, "Asia/Dubai") == 0)) {
        TEST_MSG("got %s, expect Asia/Dubai", iana);
    }

    iana = flb_time_windows_zone_to_iana("Middle East Standard Time");
    if (!TEST_CHECK(iana != NULL && strcmp(iana, "Asia/Beirut") == 0)) {
        TEST_MSG("got %s, expect Asia/Beirut", iana);
    }

    iana = flb_time_windows_zone_to_iana("India Standard Time");
    if (!TEST_CHECK(iana != NULL && strcmp(iana, "Asia/Kolkata") == 0)) {
        TEST_MSG("got %s, expect Asia/Kolkata", iana);
    }

    iana = flb_time_windows_zone_to_iana("Nepal Standard Time");
    if (!TEST_CHECK(iana != NULL && strcmp(iana, "Asia/Kathmandu") == 0)) {
        TEST_MSG("got %s, expect Asia/Kathmandu", iana);
    }

    iana = flb_time_windows_zone_to_iana("Unknown Standard Time");
    if (!TEST_CHECK(iana == NULL)) {
        TEST_MSG("got %s, expect NULL", iana);
    }

    iana = flb_time_windows_zone_to_iana(NULL);
    if (!TEST_CHECK(iana == NULL)) {
        TEST_MSG("got %s, expect NULL", iana);
    }
}

void test_iana_zone_to_windows()
{
    const char *windows;

    windows = flb_time_iana_zone_to_windows("America/Vancouver");
    if (!TEST_CHECK(windows != NULL && strcmp(windows, "Pacific Standard Time") == 0)) {
        TEST_MSG("got %s, expect Pacific Standard Time", windows);
    }

    windows = flb_time_iana_zone_to_windows("Etc/GMT-4");
    if (!TEST_CHECK(windows != NULL && strcmp(windows, "Arabian Standard Time") == 0)) {
        TEST_MSG("got %s, expect Arabian Standard Time", windows);
    }

    windows = flb_time_iana_zone_to_windows("Asia/Kathmandu");
    if (!TEST_CHECK(windows != NULL && strcmp(windows, "Nepal Standard Time") == 0)) {
        TEST_MSG("got %s, expect Nepal Standard Time", windows);
    }

    windows = flb_time_iana_zone_to_windows("Etc/Unknown");
    if (!TEST_CHECK(windows == NULL)) {
        TEST_MSG("got %s, expect NULL", windows);
    }

    windows = flb_time_iana_zone_to_windows(NULL);
    if (!TEST_CHECK(windows == NULL)) {
        TEST_MSG("got %s, expect NULL", windows);
    }
}

void test_windows_zone_to_utc_offset()
{
    int ret;
    long offset;

    ret = flb_time_windows_zone_to_utc_offset("SE Asia Standard Time", &offset);
    if (!TEST_CHECK(ret == 0 && offset == 25200)) {
        TEST_MSG("got ret=%d offset=%ld, expect ret=0 offset=25200", ret, offset);
    }

    ret = flb_time_windows_zone_to_utc_offset("Nepal Standard Time", &offset);
    if (!TEST_CHECK(ret == 0 && offset == 20700)) {
        TEST_MSG("got ret=%d offset=%ld, expect ret=0 offset=20700", ret, offset);
    }

    ret = flb_time_windows_zone_to_utc_offset("Newfoundland Standard Time", &offset);
    if (!TEST_CHECK(ret == 0 && offset == -12600)) {
        TEST_MSG("got ret=%d offset=%ld, expect ret=0 offset=-12600", ret, offset);
    }

    ret = flb_time_windows_zone_to_utc_offset("Unknown Standard Time", &offset);
    if (!TEST_CHECK(ret == -1)) {
        TEST_MSG("got ret=%d, expect ret=-1", ret);
    }

    ret = flb_time_windows_zone_to_utc_offset(NULL, &offset);
    if (!TEST_CHECK(ret == -1)) {
        TEST_MSG("got ret=%d, expect ret=-1", ret);
    }

    ret = flb_time_windows_zone_to_utc_offset("UTC", NULL);
    if (!TEST_CHECK(ret == -1)) {
        TEST_MSG("got ret=%d, expect ret=-1", ret);
    }
}

void test_iana_zone_to_utc_offset()
{
    int ret;
    long offset;

    ret = flb_time_iana_zone_to_utc_offset("Asia/Bangkok", &offset);
    if (!TEST_CHECK(ret == 0 && offset == 25200)) {
        TEST_MSG("got ret=%d offset=%ld, expect ret=0 offset=25200", ret, offset);
    }

    ret = flb_time_iana_zone_to_utc_offset("Australia/Eucla", &offset);
    if (!TEST_CHECK(ret == 0 && offset == 31500)) {
        TEST_MSG("got ret=%d offset=%ld, expect ret=0 offset=31500", ret, offset);
    }

    ret = flb_time_iana_zone_to_utc_offset("Etc/GMT+12", &offset);
    if (!TEST_CHECK(ret == 0 && offset == -43200)) {
        TEST_MSG("got ret=%d offset=%ld, expect ret=0 offset=-43200", ret, offset);
    }

    ret = flb_time_iana_zone_to_utc_offset("Etc/Unknown", &offset);
    if (!TEST_CHECK(ret == -1)) {
        TEST_MSG("got ret=%d, expect ret=-1", ret);
    }

    ret = flb_time_iana_zone_to_utc_offset(NULL, &offset);
    if (!TEST_CHECK(ret == -1)) {
        TEST_MSG("got ret=%d, expect ret=-1", ret);
    }

    ret = flb_time_iana_zone_to_utc_offset("Etc/UTC", NULL);
    if (!TEST_CHECK(ret == -1)) {
        TEST_MSG("got ret=%d, expect ret=-1", ret);
    }
}

/* flb_time_pop_from_msgpack must reject record arrays shorter than 2
 * elements instead of reading via.array.ptr[0]/ptr[1] out of bounds. */
static void pop_from_array(const char *data, size_t size, int expect)
{
    struct flb_time tm;
    msgpack_object *map;
    msgpack_unpacked result;
    int ret;

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, data, size, NULL);

    ret = flb_time_pop_from_msgpack(&tm, &result, &map);
    if (!TEST_CHECK(ret == expect)) {
        TEST_MSG("got %d, expect %d", ret, expect);
    }

    msgpack_unpacked_destroy(&result);
}

void test_pop_from_msgpack_short_array()
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* empty array: [] */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&mp_pck, 0);
    pop_from_array(mp_sbuf.data, mp_sbuf.size, -1);
    msgpack_sbuffer_destroy(&mp_sbuf);

    /* single element: [ timestamp ] */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&mp_pck, 1);
    msgpack_pack_int(&mp_pck, SEC_32BIT);
    pop_from_array(mp_sbuf.data, mp_sbuf.size, -1);
    msgpack_sbuffer_destroy(&mp_sbuf);

    /* valid record: [ timestamp, map ] */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&mp_pck, 2);
    msgpack_pack_int(&mp_pck, SEC_32BIT);
    msgpack_pack_map(&mp_pck, 0);
    pop_from_array(mp_sbuf.data, mp_sbuf.size, 0);
    msgpack_sbuffer_destroy(&mp_sbuf);
}

TEST_LIST = {
    { "flb_time_to_nanosec"           , test_to_nanosec},
    { "pop_from_msgpack_short_array"  , test_pop_from_msgpack_short_array},
    { "flb_time_append_to_mpack_v1"   , test_append_to_mpack_v1},
    { "msgpack_to_time_int"           , test_msgpack_to_time_int},
    { "msgpack_to_time_double"        , test_msgpack_to_time_double},
    { "msgpack_to_time_eventtime"     , test_msgpack_to_time_eventtime},
    { "eventtime_boundaries"          , test_eventtime_boundaries},
    { "from_uint64_post_2038"         , test_from_uint64_post_2038},
    { "msgpack_to_time_invalid"       , test_msgpack_to_time_invalid},
    { "append_to_msgpack_eventtime"   , test_append_to_msgpack_eventtime},
    { "windows_zone_to_iana"          , test_windows_zone_to_iana},
    { "iana_zone_to_windows"          , test_iana_zone_to_windows},
    { "windows_zone_to_utc_offset"    , test_windows_zone_to_utc_offset},
    { "iana_zone_to_utc_offset"       , test_iana_zone_to_utc_offset},
    { NULL, NULL }
};
