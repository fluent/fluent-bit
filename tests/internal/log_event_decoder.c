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
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event.h>
#include <msgpack.h>
#include <string.h>
#include <stdio.h>

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

static void pack_group_marker(msgpack_packer *pck, int32_t marker_type)
{
    struct flb_time tm;

    /* Set negative timestamp to indicate group marker */
    flb_time_set(&tm, marker_type, 0);

    msgpack_pack_array(pck, 2);  /* Root array: [header, body] */
    msgpack_pack_array(pck, 2);  /* Header array: [timestamp, metadata] */
    pack_event_time(pck, &tm);   /* Group marker timestamp */
    msgpack_pack_map(pck, 1);     /* Metadata: group info */
    msgpack_pack_str(pck, 5);
    msgpack_pack_str_body(pck, "group", 5);
    msgpack_pack_str(pck, 6);
    msgpack_pack_str_body(pck, "marker", 6);
    msgpack_pack_map(pck, 1);     /* Body: group attributes */
    msgpack_pack_str(pck, 3);
    msgpack_pack_str_body(pck, "tag", 3);
    msgpack_pack_str(pck, 4);
    msgpack_pack_str_body(pck, "test", 4);
}

void decoder_skip_groups()
{
    struct flb_log_event_decoder dec;
    struct flb_log_event event;
    int ret;
    struct flb_time tm1, tm2, tm3;
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    char *json = NULL;
    int record_count = 0;
    int32_t decoded_record_type;

    /* Create timestamps for normal log records */
    flb_time_set(&tm1, 1000, 100);
    flb_time_set(&tm2, 2000, 200);
    flb_time_set(&tm3, 3000, 300);

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    /* Pack: GROUP_START, normal log1, normal log2, GROUP_END, normal log3 */

    /* GROUP_START marker */
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_START);

    /* Normal log 1 */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    pack_event_time(&pck, &tm1);
    msgpack_pack_map(&pck, 0);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "log", 3);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "1", 1);

    /* Normal log 2 */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    pack_event_time(&pck, &tm2);
    msgpack_pack_map(&pck, 0);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "log", 3);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "2", 1);

    /* GROUP_END marker */
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_END);

    /* Normal log 3 */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    pack_event_time(&pck, &tm3);
    msgpack_pack_map(&pck, 0);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "log", 3);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "3", 1);

    /* Initialize decoder with read_groups = false */
    ret = flb_log_event_decoder_init(&dec, (char *)sbuf.data, sbuf.size);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        TEST_MSG("flb_log_event_decoder_init failed. ret=%s",
                 flb_log_event_decoder_get_error_description(ret));
        msgpack_sbuffer_destroy(&sbuf);
        return;
    }

    ret = flb_log_event_decoder_read_groups(&dec, FLB_FALSE);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_log_event_decoder_read_groups failed");
        flb_log_event_decoder_destroy(&dec);
        msgpack_sbuffer_destroy(&sbuf);
        return;
    }

    /* Decode records and verify group markers are skipped */
    while ((ret = flb_log_event_decoder_next(&dec, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        /* Verify we never get a zeroed event (both sec and nsec should not be 0) */
        if (!TEST_CHECK(!(event.timestamp.tm.tv_sec == 0 && event.timestamp.tm.tv_nsec == 0))) {
            TEST_MSG("Received zeroed event - group marker was not skipped properly");
            flb_log_event_decoder_destroy(&dec);
            msgpack_sbuffer_destroy(&sbuf);
            return;
        }

        /* Get record type */
        ret = flb_log_event_decoder_get_record_type(&event, &decoded_record_type);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("flb_log_event_decoder_get_record_type failed");
            flb_log_event_decoder_destroy(&dec);
            msgpack_sbuffer_destroy(&sbuf);
            return;
        }

        /* Verify we never receive group markers when read_groups is false */
        if (!TEST_CHECK(decoded_record_type == FLB_LOG_EVENT_NORMAL)) {
            TEST_MSG("Received group marker (type=%d) when read_groups=false",
                     decoded_record_type);
            flb_log_event_decoder_destroy(&dec);
            msgpack_sbuffer_destroy(&sbuf);
            return;
        }

        record_count++;

        /* Verify expected timestamps are returned in order */
        if (record_count == 1) {
            if (!TEST_CHECK(flb_time_equal(&tm1, &event.timestamp))) {
                TEST_MSG("First record timestamp mismatch");
                flb_log_event_decoder_destroy(&dec);
                msgpack_sbuffer_destroy(&sbuf);
                return;
            }
        }
        else if (record_count == 2) {
            if (!TEST_CHECK(flb_time_equal(&tm2, &event.timestamp))) {
                TEST_MSG("Second record timestamp mismatch");
                flb_log_event_decoder_destroy(&dec);
                msgpack_sbuffer_destroy(&sbuf);
                return;
            }
        }
        else if (record_count == 3) {
            if (!TEST_CHECK(flb_time_equal(&tm3, &event.timestamp))) {
                TEST_MSG("Third record timestamp mismatch");
                flb_log_event_decoder_destroy(&dec);
                msgpack_sbuffer_destroy(&sbuf);
                return;
            }
        }

        /* Verify body is valid */
        json = flb_msgpack_to_json_str(4096, event.body, FLB_TRUE);
        if (TEST_CHECK(json != NULL)) {
            char expected_log[16];
            snprintf(expected_log, sizeof(expected_log), "\"log\":\"%d\"", record_count);
            if (!TEST_CHECK(strstr(json, expected_log) != NULL)) {
                TEST_MSG("Expected %s in body, got json=%s", expected_log, json);
            }
            flb_free(json);
            json = NULL;
        }
    }

    /* Verify we got exactly 3 normal records (group markers should be skipped) */
    if (!TEST_CHECK(record_count == 3)) {
        TEST_MSG("Expected 3 normal records, got %d. Group markers were not skipped properly.",
                 record_count);
    }

    /* Verify we reached end of data, not an error */
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA ||
                    ret == FLB_EVENT_DECODER_SUCCESS)) {
        TEST_MSG("Unexpected decoder result: %s",
                 flb_log_event_decoder_get_error_description(ret));
    }

    flb_log_event_decoder_destroy(&dec);
    msgpack_sbuffer_destroy(&sbuf);
}

void decoder_skip_groups_corrupted()
{
    struct flb_log_event_decoder dec;
    struct flb_log_event event;
    int ret;
    struct flb_time tm1, tm2;
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    int record_count = 0;
    int32_t decoded_record_type;

    flb_time_set(&tm1, 1000, 100);
    flb_time_set(&tm2, 2000, 200);

    /* Test Case 1: Unmatched GROUP_START (no GROUP_END) */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_START);

    /* Normal log */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    pack_event_time(&pck, &tm1);
    msgpack_pack_map(&pck, 0);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "log", 3);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "1", 1);

    /* Another GROUP_START without END */
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_START);

    /* Another normal log */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    pack_event_time(&pck, &tm2);
    msgpack_pack_map(&pck, 0);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "log", 3);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "2", 1);

    ret = flb_log_event_decoder_init(&dec, (char *)sbuf.data, sbuf.size);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    ret = flb_log_event_decoder_read_groups(&dec, FLB_FALSE);
    TEST_CHECK(ret == 0);

    record_count = 0;
    while ((ret = flb_log_event_decoder_next(&dec, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_decoder_get_record_type(&event, &decoded_record_type);
        TEST_CHECK(ret == 0);
        TEST_CHECK(decoded_record_type == FLB_LOG_EVENT_NORMAL);
        record_count++;
    }

    /* Should get 2 normal records, skipping unmatched GROUP_START markers */
    TEST_CHECK(record_count == 2);

    flb_log_event_decoder_destroy(&dec);
    msgpack_sbuffer_destroy(&sbuf);

    /* Test Case 2: Unmatched GROUP_END (no GROUP_START) */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_END);

    /* Normal log */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    pack_event_time(&pck, &tm1);
    msgpack_pack_map(&pck, 0);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "log", 3);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "1", 1);

    ret = flb_log_event_decoder_init(&dec, (char *)sbuf.data, sbuf.size);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    ret = flb_log_event_decoder_read_groups(&dec, FLB_FALSE);
    TEST_CHECK(ret == 0);

    record_count = 0;
    while ((ret = flb_log_event_decoder_next(&dec, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_decoder_get_record_type(&event, &decoded_record_type);
        TEST_CHECK(ret == 0);
        TEST_CHECK(decoded_record_type == FLB_LOG_EVENT_NORMAL);
        record_count++;
    }

    /* Should get 1 normal record, skipping unmatched GROUP_END */
    TEST_CHECK(record_count == 1);

    flb_log_event_decoder_destroy(&dec);
    msgpack_sbuffer_destroy(&sbuf);

    /* Test Case 3: Multiple consecutive GROUP_START */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_START);
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_START);
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_START);

    /* Normal log */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    pack_event_time(&pck, &tm1);
    msgpack_pack_map(&pck, 0);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "log", 3);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "1", 1);

    ret = flb_log_event_decoder_init(&dec, (char *)sbuf.data, sbuf.size);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    ret = flb_log_event_decoder_read_groups(&dec, FLB_FALSE);
    TEST_CHECK(ret == 0);

    record_count = 0;
    while ((ret = flb_log_event_decoder_next(&dec, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_decoder_get_record_type(&event, &decoded_record_type);
        TEST_CHECK(ret == 0);
        TEST_CHECK(decoded_record_type == FLB_LOG_EVENT_NORMAL);
        record_count++;
    }

    /* Should get 1 normal record, skipping all GROUP_START markers */
    TEST_CHECK(record_count == 1);

    flb_log_event_decoder_destroy(&dec);
    msgpack_sbuffer_destroy(&sbuf);

    /* Test Case 4: Multiple consecutive GROUP_END */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    /* Normal log */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    pack_event_time(&pck, &tm1);
    msgpack_pack_map(&pck, 0);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "log", 3);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "1", 1);

    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_END);
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_END);
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_END);

    ret = flb_log_event_decoder_init(&dec, (char *)sbuf.data, sbuf.size);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    ret = flb_log_event_decoder_read_groups(&dec, FLB_FALSE);
    TEST_CHECK(ret == 0);

    record_count = 0;
    while ((ret = flb_log_event_decoder_next(&dec, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_decoder_get_record_type(&event, &decoded_record_type);
        TEST_CHECK(ret == 0);
        TEST_CHECK(decoded_record_type == FLB_LOG_EVENT_NORMAL);
        record_count++;
    }

    /* Should get 1 normal record, skipping all GROUP_END markers */
    TEST_CHECK(record_count == 1);

    flb_log_event_decoder_destroy(&dec);
    msgpack_sbuffer_destroy(&sbuf);

    /* Test Case 5: Mixed invalid states - GROUP_END, GROUP_START, GROUP_END, normal log */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_END);
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_START);
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_END);

    /* Normal log */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_array(&pck, 2);
    pack_event_time(&pck, &tm1);
    msgpack_pack_map(&pck, 0);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "log", 3);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "1", 1);

    ret = flb_log_event_decoder_init(&dec, (char *)sbuf.data, sbuf.size);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    ret = flb_log_event_decoder_read_groups(&dec, FLB_FALSE);
    TEST_CHECK(ret == 0);

    record_count = 0;
    while ((ret = flb_log_event_decoder_next(&dec, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        /* Verify we never get a zeroed event */
        TEST_CHECK(!(event.timestamp.tm.tv_sec == 0 && event.timestamp.tm.tv_nsec == 0));

        ret = flb_log_event_decoder_get_record_type(&event, &decoded_record_type);
        TEST_CHECK(ret == 0);
        TEST_CHECK(decoded_record_type == FLB_LOG_EVENT_NORMAL);
        record_count++;
    }

    /* Should get 1 normal record, skipping all invalid group markers */
    TEST_CHECK(record_count == 1);

    flb_log_event_decoder_destroy(&dec);
    msgpack_sbuffer_destroy(&sbuf);

    /* Test Case 6: Only group markers, no normal logs */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_START);
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_END);
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_START);
    pack_group_marker(&pck, FLB_LOG_EVENT_GROUP_END);

    ret = flb_log_event_decoder_init(&dec, (char *)sbuf.data, sbuf.size);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    ret = flb_log_event_decoder_read_groups(&dec, FLB_FALSE);
    TEST_CHECK(ret == 0);

    record_count = 0;
    ret = flb_log_event_decoder_next(&dec, &event);

    /* Should get INSUFFICIENT_DATA since all records are group markers */
    TEST_CHECK(ret == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA);
    TEST_CHECK(record_count == 0);

    flb_log_event_decoder_destroy(&dec);
    msgpack_sbuffer_destroy(&sbuf);
}



TEST_LIST = {
    { "create_destroy", create_destroy },
    { "init_destroy", init_destroy },
    { "decode_timestamp", decode_timestamp },
    { "decode_object", decode_object },
    { "decoder_next", decoder_next },
    { "decoder_skip_groups", decoder_skip_groups },
    { "decoder_skip_groups_corrupted", decoder_skip_groups_corrupted },
    { 0 }
};
