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

#include <string.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include "../../plugins/in_collectd/netprot.h"
#include "../../plugins/in_collectd/typesdb.h"
#include "flb_tests_internal.h"

/* Mixed byte orders and odd-length parts are intentional wire fixtures. */
static const unsigned char packet[] = {
    0x00, 0x00, 0x00, 0x07, 'h', 'i', 0,
    0x00, 0x01, 0x00, 0x0c, 0, 0, 0, 0, 0x65, 0x53, 0xf1, 0x00,
    0x00, 0x07, 0x00, 0x0c, 0, 0, 0, 0, 0, 0, 0, 10,
    0xff, 0xff, 0x00, 0x05, 0,
    0x00, 0x04, 0x00, 0x0a, 'm', 'i', 'x', 'e', 'd', 0,
    0x00, 0x06, 0x00, 0x2a, 0, 4, 0, 1, 2, 3,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0, 0, 0, 0, 0, 0x20, 0x45, 0x40,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xd6,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

static msgpack_object *find_field(msgpack_object *body, const char *name)
{
    size_t i;
    msgpack_object_kv *entry;

    for (i = 0; i < body->via.map.size; i++) {
        entry = &body->via.map.ptr[i];
        if (entry->key.type == MSGPACK_OBJECT_STR &&
            entry->key.via.str.size == strlen(name) &&
            memcmp(entry->key.via.str.ptr, name, strlen(name)) == 0) {
            return &entry->val;
        }
    }
    TEST_CHECK(0);
    TEST_MSG("missing field %s", name);
    return NULL;
}

static void check_double(msgpack_object *body, const char *name, double expected)
{
    msgpack_object *value;

    value = find_field(body, name);
    if (TEST_CHECK(value != NULL)) {
        TEST_CHECK(value->type == MSGPACK_OBJECT_FLOAT64);
        TEST_CHECK(value->via.f64 == expected);
    }
}

static void test_unaligned_values(void)
{
    int offset;
    int high_resolution;
    int ret;
    char buffer[sizeof(packet) + 8];
    char *fields[] = {"counter", "gauge", "derive", "absolute"};
    struct mk_list tdb;
    struct typesdb_node node = {0};
    struct flb_log_event_encoder encoder;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    msgpack_object *value;

    mk_list_init(&tdb);
    node.type = "mixed";
    node.count = 4;
    node.fields = fields;
    mk_list_add(&node._head, &tdb);
    ret = flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(ret == FLB_EVENT_ENCODER_SUCCESS);

    for (high_resolution = 0; high_resolution < 2; high_resolution++) {
        for (offset = 0; offset < 8; offset++) {
            memcpy(buffer + offset, packet, sizeof(packet));
            if (high_resolution) {
                buffer[offset + 8] = 8;
                buffer[offset + 20] = 9;
            }
            flb_log_event_encoder_reset(&encoder);
            ret = netprot_to_msgpack(buffer + offset, sizeof(packet), &tdb, &encoder);
            TEST_ASSERT(ret == 0);
            ret = flb_log_event_decoder_init(&decoder, encoder.output_buffer,
                                            encoder.output_length);
            TEST_ASSERT(ret == FLB_EVENT_DECODER_SUCCESS);
            ret = flb_log_event_decoder_next(&decoder, &event);
            TEST_ASSERT(ret == FLB_EVENT_DECODER_SUCCESS);
            TEST_ASSERT(event.body->type == MSGPACK_OBJECT_MAP);
            check_double(event.body, "time", high_resolution ?
                         1700000000.0 / 1073741824.0 : 1700000000.0);
            check_double(event.body, "interval", high_resolution ?
                         10.0 / 1073741824.0 : 10.0);
            check_double(event.body, "gauge", 42.25);
            value = find_field(event.body, "counter");
            TEST_ASSERT(value != NULL);
            TEST_CHECK(value->type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            TEST_CHECK(value->via.u64 == UINT64_C(0x0102030405060708));
            value = find_field(event.body, "derive");
            TEST_ASSERT(value != NULL);
            TEST_CHECK(value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER);
            TEST_CHECK(value->via.i64 == -42);
            value = find_field(event.body, "absolute");
            TEST_ASSERT(value != NULL);
            TEST_CHECK(value->type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            TEST_CHECK(value->via.u64 == UINT64_C(0xfedcba9876543210));
            TEST_CHECK(flb_log_event_decoder_next(&decoder, &event) !=
                       FLB_EVENT_DECODER_SUCCESS);
            flb_log_event_decoder_destroy(&decoder);
        }
    }
    flb_log_event_encoder_destroy(&encoder);
}

static void test_truncated_parts(void)
{
    int length;
    int ret;
    char buffer[sizeof(packet)];
    struct mk_list tdb;
    struct flb_log_event_encoder encoder;

    mk_list_init(&tdb);
    ret = flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(ret == FLB_EVENT_ENCODER_SUCCESS);
    memcpy(buffer, packet, sizeof(packet));
    /* The odd-length host is followed by an incomplete timestamp. */
    for (length = 11; length < 19; length++) {
        flb_log_event_encoder_reset(&encoder);
        TEST_CHECK(netprot_to_msgpack(buffer, length, &tdb, &encoder) == -1);
        TEST_CHECK(encoder.output_length == 0);
    }
    /* A part that fits in the datagram but has too few timestamp bytes. */
    buffer[10] = 11;
    TEST_CHECK(netprot_to_msgpack(buffer, 18, &tdb, &encoder) == -1);
    buffer[10] = 3;
    TEST_CHECK(netprot_to_msgpack(buffer, 18, &tdb, &encoder) == -1);
    flb_log_event_encoder_destroy(&encoder);
}

TEST_LIST = {
    {"unaligned_values", test_unaligned_values},
    {"truncated_parts", test_truncated_parts},
    {NULL, NULL}
};
