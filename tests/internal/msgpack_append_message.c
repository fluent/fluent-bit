/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_msgpack_append_message.h>
#include <monkey/mk_core.h>

#include <sys/types.h>
#include <sys/stat.h>

/* JSON tests data */
#define JSON_MAP1 FLB_TESTS_DATA_PATH "/data/msgpack_append_message/map1.json"

#include "flb_tests_internal.h"

struct msgpack_append_message_test {
    char *msgpack;
    char *json;
};

static inline int process_pack(char *pack, size_t size)
{
    int ret;
    msgpack_unpacked result;
    char   *appended_buffer = NULL;
    size_t  appended_size;
    char *inject_message = "injected";
    char *inject_key_name = "expanding";
    flb_sds_t inject_key;
    size_t off = 0;
    size_t prev_off = 0;
    flb_sds_t out_buf;
    char *p = NULL;

    inject_key = flb_sds_create_len(inject_key_name, strlen(inject_key_name));
    if (!inject_key) {
        flb_errno();
        return -1;
    }
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            ret = flb_msgpack_append_message_to_record(&appended_buffer,
                                                       &appended_size,
                                                       inject_key,
                                                       pack + prev_off,
                                                       size,
                                                       inject_message,
                                                       8,
                                                       MSGPACK_OBJECT_STR);
            TEST_CHECK(ret == 0);

            out_buf = flb_msgpack_raw_to_json_sds(appended_buffer, appended_size, FLB_TRUE);
            TEST_CHECK(out_buf != NULL);
            p = strstr(out_buf, "\"expanding\":\"injected\"");
            if (!TEST_CHECK(p != NULL)) {
                TEST_MSG("\"expanding\":\"injected\" should be appended. out_buf=%s", out_buf);
            }
            if (out_buf) {
                flb_sds_destroy(out_buf);
            }
        }
        prev_off = off;
    }

    msgpack_unpacked_destroy(&result);

    flb_sds_destroy(inject_key);
    flb_free(appended_buffer);

    return ret;
}

/* Append a single key-value pair into msgpack map */
void test_append_basic()
{
    int ret;
    size_t len;
    char *data;
    char *pack;
    int   out_size;
    struct flb_pack_state state;

    data = mk_file_to_buffer(JSON_MAP1);
    TEST_CHECK(data != NULL);

    len = strlen(data);

    ret = flb_pack_state_init(&state);
    TEST_CHECK(ret == 0);

    ret = flb_pack_json_state(data, len, &pack, &out_size, &state);
    TEST_CHECK(ret == 0);

    ret = process_pack(pack, out_size);
    TEST_CHECK(ret == 0);

    flb_pack_state_reset(&state);
    flb_free(data);
    flb_free(pack);
}

TEST_LIST = {
    { "basic", test_append_basic },
    { 0 }
};
