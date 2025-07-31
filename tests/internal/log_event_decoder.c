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
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>
#include <string.h>

#include "flb_tests_internal.h"

static int pack_event_time(msgpack_packer *pck, struct flb_time *tm)
{
    char ext_data[8] = {0};
    uint32_t tmp;

    /* event time */
    tmp = htonl((uint32_t)tm->tm.tv_sec); /* second from epoch */
    memcpy(&ext_data, &tmp, 4);
    tmp = htonl((uint32_t)tm->tm.tv_nsec);/* nanosecond */
    memcpy(&ext_data[4], &tmp, 4);

    msgpack_pack_ext(pck, 8, 0);
    msgpack_pack_ext_body(pck, ext_data, sizeof(ext_data));

    return 0;
}

void create_destroy()
{
    struct flb_log_event_decoder *dec = NULL;
    char buf[256] = {0};

    dec = flb_log_event_decoder_create(&buf[0], sizeof(buf));
    if (!TEST_CHECK(dec != NULL)) {
        TEST_MSG("flb_log_event_decoder_create failed");
        return;
    }

    flb_log_event_decoder_destroy(dec);
}

void init_destroy()
{
    struct flb_log_event_decoder dec;
    char buf[256] = {0};
    int ret;

    ret = flb_log_event_decoder_init(&dec, &buf[0], sizeof(buf));
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        TEST_MSG("flb_log_event_decoder_init failed. ret=%s",
                 flb_log_event_decoder_get_error_description(ret));
        return;
    }

    flb_log_event_decoder_destroy(&dec);
}

void decode_timestamp()
{
    struct flb_time tm;
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked result;
    size_t offset = 0;

    int ret;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_int64(&pck, 123456);

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, sbuf.data, sbuf.size, &offset);

    ret = flb_log_event_decoder_decode_timestamp(&result.data, &tm);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        TEST_MSG("flb_log_event_decoder_timestamp failed. ret=%s",
                 flb_log_event_decoder_get_error_description(ret));
        return;
    }
    if (!TEST_CHECK(tm.tm.tv_sec == 123456 && tm.tm.tv_nsec == 0)) {
        TEST_MSG("timestamp error. tv_sec=%ld tv_nsec=%lu", tm.tm.tv_sec, tm.tm.tv_nsec);
        return;
    }

    msgpack_unpacked_init(&result);
    msgpack_sbuffer_clear(&sbuf);

    /* event time */
    flb_time_set(&tm, 123456, 123456);
    pack_event_time(&pck, &tm);

    offset = 0;
    msgpack_unpack_next(&result, sbuf.data, sbuf.size, &offset);

    flb_time_zero(&tm);
    ret = flb_log_event_decoder_decode_timestamp(&result.data, &tm);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        TEST_MSG("flb_log_event_decoder_timestamp failed. ret=%s",
                 flb_log_event_decoder_get_error_description(ret));
        return;
    }
    if (!TEST_CHECK(tm.tm.tv_sec == 123456 && tm.tm.tv_nsec == 123456)) {
        TEST_MSG("timestamp error. tv_sec=%ld tv_nsec=%lu", tm.tm.tv_sec, tm.tm.tv_nsec);
        return;
    }

    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&sbuf);
}

void decode_object()
{
    struct flb_log_event_decoder dec;
    struct flb_log_event event;
    int ret;
    struct flb_time tm;
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked result;
    size_t offset = 0;
    char *json = NULL;

    flb_time_set(&tm, 123456, 123456);

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    /* [[123456.123456, {}], {"key1":"val1", "key2":"val2"}] */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    pack_event_time(&pck, &tm);
    msgpack_pack_map(&pck, 0);
    msgpack_pack_map(&pck, 2);

    msgpack_pack_str(&pck, 4);
    msgpack_pack_str_body(&pck, "key1", 4);
    msgpack_pack_str(&pck, 4);
    msgpack_pack_str_body(&pck, "val1", 4);

    msgpack_pack_str(&pck, 4);
    msgpack_pack_str_body(&pck, "key2", 4);
    msgpack_pack_str(&pck, 4);
    msgpack_pack_str_body(&pck, "val2", 4);

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, sbuf.data, sbuf.size, &offset);
    if (!TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS)) {
        TEST_MSG("msgpack_unpack_next failed");
        return;
    }

    ret = flb_event_decoder_decode_object(&dec, &event, &result.data);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        TEST_MSG("flb_log_event_decoder_decode_object failed. ret=%s",
                 flb_log_event_decoder_get_error_description(ret));
        return;
    }

    if (!TEST_CHECK(flb_time_equal(&tm, &event.timestamp))) {
        TEST_MSG("timestamp mismatch");
        return;
    }

    json = flb_msgpack_to_json_str(4096, event.body, FLB_TRUE);
    if (!TEST_CHECK(json != NULL)) {
        TEST_MSG("flb_msgpack_to_json_str error");
        return;
    }
    if (!TEST_CHECK(strstr(json, "\"key1\":\"val1\"") != NULL)) {
        TEST_MSG("\"key1\":\"val1\" is missing. json=%s", json);
        return;
    }
    if (!TEST_CHECK(strstr(json, "\"key2\":\"val2\"") != NULL)) {
        TEST_MSG("\"key2\":\"val2\" is missing. json=%s", json);
        return;
    }

    flb_free(json);
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&sbuf);
}

void decoder_next()
{
    struct flb_log_event_decoder dec;
    struct flb_log_event event;
    int ret;
    struct flb_time tm;
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    char *json = NULL;

    flb_time_set(&tm, 123456, 123456);

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    /* [[123456.123456, {}], {"key1":"val1", "key2":"val2"}] */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    pack_event_time(&pck, &tm);
    msgpack_pack_map(&pck, 0);
    msgpack_pack_map(&pck, 2);

    msgpack_pack_str(&pck, 4);
    msgpack_pack_str_body(&pck, "key1", 4);
    msgpack_pack_str(&pck, 4);
    msgpack_pack_str_body(&pck, "val1", 4);

    msgpack_pack_str(&pck, 4);
    msgpack_pack_str_body(&pck, "key2", 4);
    msgpack_pack_str(&pck, 4);
    msgpack_pack_str_body(&pck, "val2", 4);


    ret = flb_log_event_decoder_init(&dec, (char *)sbuf.data, sbuf.size);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        TEST_MSG("flb_log_event_decoder_init failed. ret=%s",
                 flb_log_event_decoder_get_error_description(ret));
        return;
    }

    ret = flb_log_event_decoder_next(&dec, &event);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        TEST_MSG("flb_log_event_decoder_next failed. ret=%s",
                 flb_log_event_decoder_get_error_description(ret));
        return;
    }
    if (!TEST_CHECK(flb_time_equal(&tm, &event.timestamp))) {
        TEST_MSG("timestamp mismatch");
        return;
    }

    json = flb_msgpack_to_json_str(4096, event.body, FLB_TRUE);
    if (!TEST_CHECK(json != NULL)) {
        TEST_MSG("flb_msgpack_to_json_str error");
        return;
    }
    if (!TEST_CHECK(strstr(json, "\"key1\":\"val1\"") != NULL)) {
        TEST_MSG("\"key1\":\"val1\" is missing. json=%s", json);
        return;
    }
    if (!TEST_CHECK(strstr(json, "\"key2\":\"val2\"") != NULL)) {
        TEST_MSG("\"key2\":\"val2\" is missing. json=%s", json);
        return;
    }

    flb_free(json);
    flb_log_event_decoder_destroy(&dec);
    msgpack_sbuffer_destroy(&sbuf);
}



TEST_LIST = {
    { "create_destroy", create_destroy },
    { "init_destroy", init_destroy },
    { "decode_timestamp", decode_timestamp },
    { "decode_object", decode_object },
    { "decoder_next", decoder_next },
    { 0 }
};
