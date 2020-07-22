/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_mp.h>
#include <msgpack.h>

#include "flb_tests_internal.h"


#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define APACHE_10K    FLB_TESTS_DATA_PATH "/data/mp/apache_10k.mp"

void test_count()
{
    int ret;
    int count;
    char *data;
    size_t len;
    struct stat st;

    ret = stat(APACHE_10K, &st);
    if (ret == -1) {
        exit(1);
    }
    len = st.st_size;

    data = mk_file_to_buffer(APACHE_10K);
    TEST_CHECK(data != NULL);

    count = flb_mp_count(data, len);
    TEST_CHECK(count == 10000);
    flb_free(data);
}

void test_map_header()
{
    int i;
    int ret;
    size_t off = 0;
    msgpack_packer mp_pck;
    msgpack_object root;
    msgpack_sbuffer mp_sbuf;
    msgpack_unpacked result;
    struct flb_mp_map_header mh;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Init map header */
    flb_mp_map_header_init(&mh, &mp_pck);

    /* Append 1000 items */
    for (i = 0; i < 100; i++) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(&mp_pck, 3);
        msgpack_pack_str_body(&mp_pck, "key", 3);
        msgpack_pack_uint64(&mp_pck, i);
    }
    flb_mp_map_header_end(&mh);

    /* Unpack and check */
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, mp_sbuf.data, mp_sbuf.size, &off);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

    root = result.data;
    TEST_CHECK(root.type == MSGPACK_OBJECT_MAP);
    TEST_CHECK(root.via.array.size == 100);

    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&mp_sbuf);
}

TEST_LIST = {
    {"count"         , test_count},
    {"map_header"    , test_map_header},
    { 0 }
};
