/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include "flb_tests_internal.h"
#include <string.h>

#define EXPECTED_OUT \
    "{\"version\":\"1.1\", \"short_message\":\"true, 2019, str\", \"_t2\":\"false\", \"timestamp\":337647600.1234}"

void test_gelf_pack()
{
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct flb_time ts;
    struct flb_gelf_fields fields = {0};
    flb_sds_t out;

    /* Pack sample msgpack */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);


    ts.tm.tv_sec = 337647600;
    ts.tm.tv_nsec = 1234111111;

    msgpack_pack_map(&mp_pck, 2);
    msgpack_pack_str(&mp_pck, 2);
    msgpack_pack_str_body(&mp_pck, "t1", 2);
    msgpack_pack_array(&mp_pck, 3);
    msgpack_pack_true(&mp_pck);
    msgpack_pack_uint64(&mp_pck, 2019);
    msgpack_pack_str(&mp_pck, 3);
    msgpack_pack_str_body(&mp_pck, "str", 3);
    msgpack_pack_str(&mp_pck, 2);
    msgpack_pack_str_body(&mp_pck, "t2", 2);
    msgpack_pack_false(&mp_pck);

    fields.short_message_key = flb_sds_create("t1");
    out = flb_msgpack_raw_to_gelf(mp_sbuf.data, mp_sbuf.size, &ts, &fields);
    TEST_CHECK(out != NULL);

    TEST_CHECK(strcmp(out, EXPECTED_OUT) == 0);
    flb_sds_destroy(out);
    flb_sds_destroy(fields.short_message_key);
    msgpack_sbuffer_destroy(&mp_sbuf);
}

#define EXPECTED_OUT_MSEC \
    "{\"version\":\"1.1\", \"short_message\":\"true, 2019, str\", \"_t2\":\"false\", \"timestamp\":337647600.012}"

/* https://github.com/fluent/fluent-bit/issues/3727 */
void test_gelf_pack_msec()
{
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct flb_time ts;
    struct flb_gelf_fields fields = {0};
    flb_sds_t out;

    /* Pack sample msgpack */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);


    ts.tm.tv_sec =  337647600;
    ts.tm.tv_nsec =  12341111; /* 12.34msec */

    msgpack_pack_map(&mp_pck, 2);
    msgpack_pack_str(&mp_pck, 2);
    msgpack_pack_str_body(&mp_pck, "t1", 2);
    msgpack_pack_array(&mp_pck, 3);
    msgpack_pack_true(&mp_pck);
    msgpack_pack_uint64(&mp_pck, 2019);
    msgpack_pack_str(&mp_pck, 3);
    msgpack_pack_str_body(&mp_pck, "str", 3);
    msgpack_pack_str(&mp_pck, 2);
    msgpack_pack_str_body(&mp_pck, "t2", 2);
    msgpack_pack_false(&mp_pck);

    fields.short_message_key = flb_sds_create("t1");
    out = flb_msgpack_raw_to_gelf(mp_sbuf.data, mp_sbuf.size, &ts, &fields);
    TEST_CHECK(out != NULL);

    if(!TEST_CHECK(strcmp(out, EXPECTED_OUT_MSEC) == 0)) {
        TEST_MSG("out=%s", out);
    }
    flb_sds_destroy(out);
    flb_sds_destroy(fields.short_message_key);
    msgpack_sbuffer_destroy(&mp_sbuf);
}

TEST_LIST = {
    {"gelf_pack",      test_gelf_pack},
    {"gelf_pack_msec", test_gelf_pack_msec},
    { 0 }
};
