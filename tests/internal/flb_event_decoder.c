/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2023 The Fluent Bit Authors
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

#include <fluent-bit/flb_event_decoder.h>
#include <fluent-bit/flb_time.h>
#include "flb_tests_internal.h"
#include <string.h>
#include <msgpack.h>

static int create_test_msgpack(struct flb_time *tm, msgpack_packer *mp_pck, msgpack_sbuffer *mp_sbuf, int val1, int val2)
{
    tm->tm.tv_sec  = 123456;
    tm->tm.tv_nsec = 987654;

    msgpack_pack_array(mp_pck, 2);
    flb_time_append_to_msgpack(tm, mp_pck, FLB_TIME_ETFMT_V1_FIXEXT);
    msgpack_pack_map(mp_pck, 2);

    msgpack_pack_str(mp_pck, 4);
    msgpack_pack_str_body(mp_pck, "key1", 4);
    msgpack_pack_int64(mp_pck, val1);

    msgpack_pack_str(mp_pck, 4);
    msgpack_pack_str_body(mp_pck, "key2", 4);
    msgpack_pack_int64(mp_pck, val2);

    return 0;
}

static int compare_char_key_int_val(msgpack_object_kv kv, char *key, size_t key_size,int val)
{

    if (!TEST_CHECK(kv.key.type == MSGPACK_OBJECT_STR)) {
        TEST_MSG("type error. type=%d", kv.key.type);
        return -1;
    }
    if(!TEST_CHECK(strncmp(kv.key.via.str.ptr, key, key_size) == 0)) {
        TEST_MSG("str error got=%.*s expect=%s", 
                 kv.key.via.str.size, kv.key.via.str.ptr, key);
        return -1;
    }
    if (!TEST_CHECK(kv.val.type == MSGPACK_OBJECT_POSITIVE_INTEGER)) {
        TEST_MSG("type error. type=%d", kv.val.type);
        return -1;
    }
    if(!TEST_CHECK(kv.val.via.i64 == val)) {
        TEST_MSG("str error got=%"PRId64 " expect=%d", 
                 kv.val.via.i64, val);
        return -1;
    }

    return 0;
}

void event_decoder_msgpack()
{
    int ret;
    struct flb_time tm;
    struct flb_event event;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_event_decoder *dec = NULL;

    msgpack_object *obj = NULL;

    /* encode msgpack */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    create_test_msgpack(&tm, &mp_pck, &mp_sbuf, 123, 456);

    /* unpack */
    dec = flb_event_decoder_create(mp_sbuf.data, mp_sbuf.size,0);
    if (!TEST_CHECK(dec != NULL)) {
        TEST_MSG("flb_event_decoder_create failed");
        goto event_decode_msgpack_end;
    }

    ret = flb_event_decoder_next(dec, &event);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_event_decoder_next failed");
        goto event_decode_msgpack_end;
    }

    if (!TEST_CHECK(event.timestamp.tm.tv_sec == tm.tm.tv_sec && event.timestamp.tm.tv_nsec == tm.tm.tv_nsec)) {
        TEST_MSG("timestamp error. got=%ld.%ld expect=%ld.%ld",
                 event.timestamp.tm.tv_sec,
                 event.timestamp.tm.tv_nsec , tm.tm.tv_sec, tm.tm.tv_nsec);
        goto event_decode_msgpack_end;
    }

    /* check record */
    obj = event.record.reader.msgpack;
    ret = compare_char_key_int_val(obj->via.map.ptr[0], "key1", 4, 123);
    if (ret < 0) {
        TEST_MSG("key1 error");
        goto event_decode_msgpack_end;
    }
    ret = compare_char_key_int_val(obj->via.map.ptr[1], "key2", 4, 456);
    if (ret < 0) {
        TEST_MSG("key2 error");
        goto event_decode_msgpack_end;
    }

 event_decode_msgpack_end:
    if (dec != NULL) {
        flb_event_decoder_destroy(dec);
    }
    msgpack_sbuffer_destroy(&mp_sbuf);
}

void event_decoder_next_msgpack()
{
    int ret;
    struct flb_time tm;
    struct flb_event event;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_event_decoder *dec = NULL;
    int val1 = 123;
    int val2 = 456;
    int val3 = 234;
    int val4 = 567;

    msgpack_object *obj = NULL;

    /* encode msgpack */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    create_test_msgpack(&tm, &mp_pck, &mp_sbuf, val1, val2);
    create_test_msgpack(&tm, &mp_pck, &mp_sbuf, val3, val4);

    /* unpack */
    dec = flb_event_decoder_create(mp_sbuf.data, mp_sbuf.size,0);
    if (!TEST_CHECK(dec != NULL)) {
        TEST_MSG("flb_event_decoder_create failed");
        goto event_decode_next_msgpack_end;
    }

    ret = flb_event_decoder_next(dec, &event);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_event_decoder_next failed");
        goto event_decode_next_msgpack_end;
    }

    if (!TEST_CHECK(event.timestamp.tm.tv_sec == tm.tm.tv_sec && event.timestamp.tm.tv_nsec == tm.tm.tv_nsec)) {
        TEST_MSG("timestamp error. got=%ld.%ld expect=%ld.%ld",
                 event.timestamp.tm.tv_sec,
                 event.timestamp.tm.tv_nsec , tm.tm.tv_sec, tm.tm.tv_nsec);
        goto event_decode_next_msgpack_end;
    }

    /* check record */
    obj = event.record.reader.msgpack;
    ret = compare_char_key_int_val(obj->via.map.ptr[0], "key1", 4, val1);
    if (ret < 0) {
        TEST_MSG("1. key1 error");
        goto event_decode_next_msgpack_end;
    }
    ret = compare_char_key_int_val(obj->via.map.ptr[1], "key2", 4, val2);
    if (ret < 0) {
        TEST_MSG("1. key2 error");
        goto event_decode_next_msgpack_end;
    }

    ret = flb_event_decoder_next(dec, &event);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_event_decoder_next failed");
        goto event_decode_next_msgpack_end;
    }

    if (!TEST_CHECK(event.timestamp.tm.tv_sec == tm.tm.tv_sec && event.timestamp.tm.tv_nsec == tm.tm.tv_nsec)) {
        TEST_MSG("timestamp error. got=%ld.%ld expect=%ld.%ld",
                 event.timestamp.tm.tv_sec,
                 event.timestamp.tm.tv_nsec , tm.tm.tv_sec, tm.tm.tv_nsec);
        goto event_decode_next_msgpack_end;
    }

    /* check record */
    obj = event.record.reader.msgpack;
    ret = compare_char_key_int_val(obj->via.map.ptr[0], "key1", 4, val3);
    if (ret < 0) {
        TEST_MSG("2. key1 error");
        goto event_decode_next_msgpack_end;
    }
    ret = compare_char_key_int_val(obj->via.map.ptr[1], "key2", 4, val4);
    if (ret < 0) {
        TEST_MSG("2. key2 error");
        goto event_decode_next_msgpack_end;
    }

 event_decode_next_msgpack_end:
    if (dec != NULL) {
        flb_event_decoder_destroy(dec);
    }
    msgpack_sbuffer_destroy(&mp_sbuf);
}

void event_decoder_mpack()
{
    int ret;
    struct flb_time tm;
    struct flb_event event;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_event_decoder *dec = NULL;

    mpack_reader_t *reader;
    mpack_tag_t tag;

    /* encode msgpack */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    create_test_msgpack(&tm, &mp_pck, &mp_sbuf, 123, 456);

    /* unpack */
    dec = flb_event_decoder_create(mp_sbuf.data, mp_sbuf.size, FLB_EVENT_DECODER_OPT_USE_MPACK);
    if (!TEST_CHECK(dec != NULL)) {
        TEST_MSG("flb_event_decoder_create failed");
        goto event_decode_mpack_end;
    }

    ret = flb_event_decoder_next(dec, &event);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_event_decoder_next failed. ret=%d", ret);
        goto event_decode_mpack_end;
    }

    if (!TEST_CHECK(event.timestamp.tm.tv_sec == tm.tm.tv_sec && event.timestamp.tm.tv_nsec == tm.tm.tv_nsec)) {
        TEST_MSG("timestamp error. got=%ld.%ld expect=%ld.%ld",
                 event.timestamp.tm.tv_sec,
                 event.timestamp.tm.tv_nsec , tm.tm.tv_sec, tm.tm.tv_nsec);
        goto event_decode_mpack_end;
    }

    reader = event.record.reader.mpack;
    if (!TEST_CHECK(reader != NULL)) {
        TEST_MSG("reader is NULL");
        goto event_decode_mpack_end;
    }

    tag = mpack_read_tag(reader);
    if (!TEST_CHECK(mpack_tag_type(&tag) == mpack_type_map)) {
        TEST_MSG("type error. It should be map. type=%d", mpack_tag_type(&tag));
        goto event_decode_mpack_end;
    }

    /* TODO: check kv */

 event_decode_mpack_end:
    if (dec != NULL) {
        flb_event_decoder_destroy(dec);
    }
    msgpack_sbuffer_destroy(&mp_sbuf);
}

void reuse_decoder_msgpack()
{
    int ret;
    int i;
    int val1;
    int val2;
    struct flb_time tm;
    struct flb_event event;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_event_decoder *dec = NULL;

    msgpack_object *obj = NULL;

    /* encode msgpack */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    create_test_msgpack(&tm, &mp_pck, &mp_sbuf, 123, 456);

    /* unpack */
    dec = flb_event_decoder_create(mp_sbuf.data, mp_sbuf.size,0);
    if (!TEST_CHECK(dec != NULL)) {
        TEST_MSG("flb_event_decoder_create failed");
        goto reuse_decoder_msgpack_end;
    }

    for (i=0; i<10; i++) {
        /* encode msgpack */
        msgpack_sbuffer_destroy(&mp_sbuf);
        val1 = 123 + 10 * i;
        val2 = 456 + 10 * i;

        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
        create_test_msgpack(&tm, &mp_pck, &mp_sbuf, val1, val2);

        ret = flb_event_decoder_reuse(dec, mp_sbuf.data, mp_sbuf.size);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("flb_event_decoder_reuse failed");
            goto reuse_decoder_msgpack_end;
        }

        ret = flb_event_decoder_next(dec, &event);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("flb_event_decoder_next failed");
            goto reuse_decoder_msgpack_end;
        }

        if (!TEST_CHECK(event.timestamp.tm.tv_sec == tm.tm.tv_sec && event.timestamp.tm.tv_nsec == tm.tm.tv_nsec)) {
            TEST_MSG("timestamp error. got=%ld.%ld expect=%ld.%ld",
                     event.timestamp.tm.tv_sec,
                     event.timestamp.tm.tv_nsec , tm.tm.tv_sec, tm.tm.tv_nsec);
            goto reuse_decoder_msgpack_end;
        }

        /* check record */
        obj = event.record.reader.msgpack;
        ret = compare_char_key_int_val(obj->via.map.ptr[0], "key1", 4, val1);
        if (ret < 0) {
            TEST_MSG("key1 error");
            goto reuse_decoder_msgpack_end;
        }
        ret = compare_char_key_int_val(obj->via.map.ptr[1], "key2", 4, val2);
        if (ret < 0) {
            TEST_MSG("key2 error");
            goto reuse_decoder_msgpack_end;
        }

    }
 reuse_decoder_msgpack_end:
    if (dec != NULL) {
        flb_event_decoder_destroy(dec);
    }
    msgpack_sbuffer_destroy(&mp_sbuf);
}

TEST_LIST = {
    {"event_decoder_msgpack", event_decoder_msgpack},
    {"event_decoder_next_msgpack", event_decoder_next_msgpack},
    {"event_decoder_mpack", event_decoder_mpack},
    {"reuse_decoder_msgpack", reuse_decoder_msgpack},
    {NULL, NULL}
};
