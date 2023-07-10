/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mp.h>
#include <msgpack.h>

#include "flb_tests_internal.h"


#include <sys/types.h>
#include <sys/stat.h>

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

void test_accessor_keys_remove()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *buf;
    size_t size;
    char *out_buf;
    size_t out_size;
    char *json;
    msgpack_unpacked result;
    msgpack_object map;
    struct flb_mp_accessor *mpa;
    struct mk_list patterns;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\","
        "                       \"extra\": false\""
        "}}]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &buf, &size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Unpack the content */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, buf, size, &off);
    map = result.data;

    /* Create list of patterns */
    flb_slist_create(&patterns);
    flb_slist_add(&patterns, "$kubernetes[2]['annotations']['fluentbit.io/tag']");
    flb_slist_add(&patterns, "$key1");

    /* Create mp accessor */
    mpa = flb_mp_accessor_create(&patterns);
    TEST_CHECK(mpa != NULL);

    /* Remove the entry that matches the pattern(s) */
    ret = flb_mp_accessor_keys_remove(mpa, &map, (void *) &out_buf, &out_size);
    TEST_CHECK(ret == FLB_TRUE);

    printf("\n=== ORIGINAL  ===\n");
    flb_pack_print(buf, size);
    flb_free(buf);

    printf("=== FINAL MAP ===\n");
    if (ret == FLB_TRUE) {
        flb_pack_print(out_buf, out_size);
        flb_free(out_buf);
    }

    flb_mp_accessor_destroy(mpa);
    flb_slist_destroy(&patterns);
    msgpack_unpacked_destroy(&result);
}

/* https://github.com/fluent/fluent-bit/issues/5546 */
void test_keys_remove_subkey_key()
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *buf;
    size_t size;
    char *out_buf;
    size_t out_size;
    char *json;
    char final_json[2048] = {0};
    msgpack_unpacked result;
    msgpack_unpacked result_final;
    msgpack_object map;
    struct flb_mp_accessor *mpa;
    struct mk_list patterns;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\","
        "                       \"extra\": false\""
        "}}]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &buf, &size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Unpack the content */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, buf, size, &off);
    map = result.data;

    /* Create list of patterns */
    flb_slist_create(&patterns);

    /* sub key -> key */
    flb_slist_add(&patterns, "$kubernetes[2]['annotations']['fluentbit.io/tag']");
    flb_slist_add(&patterns, "$kubernetes");


    /* Create mp accessor */
    mpa = flb_mp_accessor_create(&patterns);
    TEST_CHECK(mpa != NULL);

    /* Remove the entry that matches the pattern(s) */
    ret = flb_mp_accessor_keys_remove(mpa, &map, (void *) &out_buf, &out_size);
    TEST_CHECK(ret == FLB_TRUE);

    printf("\n=== ORIGINAL  ===\n");
    flb_pack_print(buf, size);
    flb_free(buf);

    printf("=== FINAL MAP ===\n");
    if (ret == FLB_TRUE) {
        flb_pack_print(out_buf, out_size);
    }
    msgpack_unpacked_destroy(&result);

    off = 0;
    msgpack_unpacked_init(&result_final);
    msgpack_unpack_next(&result_final, out_buf, out_size, &off);
    flb_msgpack_to_json(&final_json[0], sizeof(final_json), &result_final.data);

    if (!TEST_CHECK(strstr(&final_json[0] ,"kubernetes") == NULL)) {
        TEST_MSG("kubernetes field should be removed");
    }

    msgpack_unpacked_destroy(&result_final);

    flb_free(out_buf);
    flb_mp_accessor_destroy(mpa);
    flb_slist_destroy(&patterns);

}

void remove_subkey_keys(char *list[], int list_size, int index_start)
{
    int len;
    int ret;
    int type;
    size_t off = 0;
    char *buf;
    size_t size;
    char *out_buf;
    size_t out_size;
    char *json;
    char final_json[2048] = {0};
    msgpack_unpacked result;
    msgpack_unpacked result_final;
    msgpack_object map;
    struct flb_mp_accessor *mpa;
    struct mk_list patterns;
    int i;
    int count = 0;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\","
        "                       \"extra\": false\""
        "}}]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &buf, &size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Unpack the content */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, buf, size, &off);
    map = result.data;

    /* Create list of patterns */
    flb_slist_create(&patterns);

    /* sub keys */
    for (i=index_start; count<list_size; i++) {
        if (i>=list_size) {
            i = 0;
        }
        flb_slist_add(&patterns, list[i]);
        count++;
    }

    /* Create mp accessor */
    mpa = flb_mp_accessor_create(&patterns);
    TEST_CHECK(mpa != NULL);

    /* Remove the entry that matches the pattern(s) */
    ret = flb_mp_accessor_keys_remove(mpa, &map, (void *) &out_buf, &out_size);
    TEST_CHECK(ret == FLB_TRUE);

    printf("\n=== ORIGINAL  ===\n");
    flb_pack_print(buf, size);
    flb_free(buf);

    printf("=== FINAL MAP ===\n");
    if (ret == FLB_TRUE) {
        flb_pack_print(out_buf, out_size);
    }
    msgpack_unpacked_destroy(&result);

    off = 0;
    msgpack_unpacked_init(&result_final);
    msgpack_unpack_next(&result_final, out_buf, out_size, &off);
    flb_msgpack_to_json(&final_json[0], sizeof(final_json), &result_final.data);

    if (!TEST_CHECK(strstr(&final_json[0] ,"kubernetes") == NULL)) {
        TEST_MSG("kubernetes field should be removed");
    }

    msgpack_unpacked_destroy(&result_final);

    flb_free(out_buf);
    flb_mp_accessor_destroy(mpa);
    flb_slist_destroy(&patterns);
}

void test_keys_remove_subkey_keys()
{
    char *list[] = {"$kubernetes[2]['annotations']['fluentbit.io/tag']",
                    "$kubernetes[2]['a']", 
                    "$kubernetes"};
    char *list2[] = {"$kubernetes[2]['annotations']['fluentbit.io/tag']",
                     "$kubernetes",
                     "$kubernetes[2]['a']"};

    int size = sizeof(list)/sizeof(char*);
    int i;
    
    for (i=0; i<size; i++) {
        remove_subkey_keys(list, size, i);
    }
    for (i=0; i<size; i++) {
        remove_subkey_keys(list2, size, i);
    }
}

TEST_LIST = {
    {"count"                , test_count},
    {"map_header"           , test_map_header},
    {"accessor_keys_remove" , test_accessor_keys_remove},
    {"accessor_keys_remove_subkey_key" , test_keys_remove_subkey_key},
    {"accessor_keys_remove_subkey_keys" , test_keys_remove_subkey_keys},
    { 0 }
};
