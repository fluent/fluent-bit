/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_mp_preflight.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>
#include <mpack/mpack.h>
#include <ctraces/ctraces.h>

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
        "                       \"extra\": false"
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
        "                       \"extra\": false"
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
    flb_msgpack_to_json(&final_json[0], sizeof(final_json), &result_final.data, FLB_TRUE);

    if (!TEST_CHECK(strstr(&final_json[0] ,"kubernetes") == NULL)) {
        TEST_MSG("kubernetes field should be removed");
    }

    msgpack_unpacked_destroy(&result_final);

    flb_free(out_buf);
    flb_mp_accessor_destroy(mpa);
    flb_slist_destroy(&patterns);

}

void test_remove_sibling_subkeys()
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
        "{"
        "\"kubernetes\": {"
            "\"pod_id\": \"id\","
            "\"pod_name\": \"name\","
            "\"host\": \"localhost\","
            "\"labels\": {"
                "\"app\": \"myapp\","
                "\"tier\": \"backend\""
            "}"
        "},"
        "\"msg\": \"kernel panic\""
        "}";

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
    flb_slist_add(&patterns, "$kubernetes['pod_name']");
    flb_slist_add(&patterns, "$kubernetes['foo']");
    flb_slist_add(&patterns, "$kubernetes['pod_id']");
    flb_slist_add(&patterns, "$kubernetes['labels']['tier']");
    flb_slist_add(&patterns, "$time");


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
    flb_msgpack_to_json(&final_json[0], sizeof(final_json), &result_final.data, FLB_TRUE);

    if (!TEST_CHECK(strstr(&final_json[0] ,"pod_id") == NULL)) {
        TEST_MSG("pod_id field should be removed");
    }
    if (!TEST_CHECK(strstr(&final_json[0] ,"pod_name") == NULL)) {
        TEST_MSG("pod_name field should be removed");
    }
    if (!TEST_CHECK(strstr(&final_json[0] ,"tier") == NULL)) {
        TEST_MSG("tier field should be removed");
    }
    if (!TEST_CHECK(strstr(&final_json[0] ,"app") != NULL)) {
        TEST_MSG("app field should not be removed");
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
        "                       \"extra\": false"
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
    flb_msgpack_to_json(&final_json[0], sizeof(final_json), &result_final.data, FLB_TRUE);

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

void test_object_to_cfl_to_msgpack()
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
    struct cfl_object *obj;
    struct mk_list patterns;
    flb_sds_t buf1;
    flb_sds_t buf2;

    /* Sample JSON message */
    json =
        "{\"key1\": \"something\", "
        "\"kubernetes\": "
        "   [true, "
        "    false, "
        "    null, "
        "    -10,"
        "    123456,"
        "    789.123,"
        "    {\"a\": false, "
        "     \"annotations\": { "
        "                       \"fluentbit.io/tag\": \"thetag\","
        "                       \"extra\": false"
        "}}]}";

    /* Convert to msgpack */
    len = strlen(json);
    ret = flb_pack_json(json, len, &buf, &size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    printf("\n");
    printf("\n>> original JSON in msgpack:\n");
    flb_pack_print(buf, size);

    /* Unpack msgpack to get a msgpack object, and convert it to CFL */
    /* Unpack the content */
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, buf, size, &off);
    map = result.data;

    obj = flb_mp_object_to_cfl(&map);
    TEST_CHECK(obj != NULL);

    /* Print the CFL object*/
    printf("\n>> CFL print:\n");
    cfl_object_print(stdout, obj);

    /* Convert back the CFL Object to a msgpack buffer. */
    ret = flb_mp_cfl_to_msgpack(obj, &out_buf, &out_size);
    TEST_CHECK(ret == 0);

    /* Print msgpack */

    printf("\n>> CFL to msgpack content:\n");
    flb_pack_print(out_buf, out_size);

    /*
     * Convert buf (msgpack 1 buffer) to JSON, and compare the strings
     * generated by out_buf (msgpack 2 buffer). They must match.
     */
    buf1 = flb_msgpack_raw_to_json_sds(buf, size, FLB_TRUE);
    buf2 = flb_msgpack_raw_to_json_sds(out_buf, out_size, FLB_TRUE);

    ret = strcmp(buf1, buf2);
    printf("\n>> Compare JSON buf1 v/s JSON buf2 (ret=%i):\n", ret);
    TEST_CHECK(ret == 0);
    printf("[buf1]: %s\n", buf1);
    printf("[buf2]: %s\n\n", buf2);

    flb_sds_destroy(buf1);
    flb_sds_destroy(buf2);

    msgpack_unpacked_destroy(&result);
    flb_free(buf);
    flb_free(out_buf);

    cfl_object_destroy(obj);
}

void test_validate_trace_chunk()
{
    int codes[] = {0, 1, 2, -2147483647 - 1, -1, 3, 2147483647};
    int ret;
    int count;
    size_t index;
    size_t size;
    size_t processed;
    char *packed;
    char invalid = '\xc1';
    msgpack_sbuffer buffer;
    struct ctrace *trace;
    struct ctrace_resource_span *resource;
    struct ctrace_scope_span *scope;
    struct ctrace_span *span;

    msgpack_sbuffer_init(&buffer);
    for (index = 0; index < sizeof(codes) / sizeof(codes[0]); index++) {
        trace = ctr_create(NULL);
        TEST_ASSERT(trace != NULL);
        resource = ctr_resource_span_create(trace);
        TEST_ASSERT(resource != NULL);
        scope = ctr_scope_span_create(resource);
        TEST_ASSERT(scope != NULL);
        span = ctr_span_create(trace, scope, "trace", NULL);
        TEST_ASSERT(span != NULL);
        TEST_ASSERT(ctr_span_set_status(span, codes[index], "message") == 0);
        TEST_ASSERT(ctr_encode_msgpack_create(trace, &packed, &size) == 0);
        TEST_ASSERT(msgpack_sbuffer_write(&buffer, packed, size) == 0);
        ctr_encode_msgpack_destroy(packed);
        ctr_destroy(trace);
    }

    ret = flb_mp_validate_trace_chunk(buffer.data, buffer.size, &count, &processed);
    TEST_CHECK(ret == 0);
    TEST_CHECK(count == 7);
    TEST_CHECK(processed == buffer.size);

    ret = flb_mp_validate_trace_chunk(buffer.data, buffer.size - 1, &count, &processed);
    TEST_CHECK(ret == -1);
    TEST_CHECK(count == 6);
    TEST_CHECK(processed < buffer.size - 1);

    TEST_ASSERT(msgpack_sbuffer_write(&buffer, &invalid, 1) == 0);
    ret = flb_mp_validate_trace_chunk(buffer.data, buffer.size, &count, &processed);
    TEST_CHECK(ret == -1);
    TEST_CHECK(count == 7);
    TEST_CHECK(processed == buffer.size - 1);

    ret = flb_mp_validate_trace_chunk(&invalid, 1, &count, &processed);
    TEST_CHECK(ret == -1);
    TEST_CHECK(count == 0);
    TEST_CHECK(processed == 0);

    ret = flb_mp_validate_trace_chunk(NULL, 0, &count, &processed);
    TEST_CHECK(ret == 0);
    TEST_CHECK(count == 0);
    TEST_CHECK(processed == 0);
    msgpack_sbuffer_destroy(&buffer);
}

/* Budget checks must run before msgpack-c sees attacker-controlled counts. */
static void test_preflight(void)
{
    struct flb_mp_preflight *scan;
    size_t consumed;
    size_t cost;
    size_t required;
    size_t i;
    int ret;
    char deep[MSGPACK_EMBED_STACK_SIZE + 1];
    char large_string[16387];
    const char array[] = "\xdd\xff\xff\xff\xff";
    const char map[] = "\xdf\xff\xff\xff\xff";
    const char valid[] = "\x92\x01\x81\xa1k\x02";
    const char nested[] = "\x92\xdd\x00\x00\x00\x64";
    const char invalid[] = "\xc1";
    const char sequence[] = "\x91\x01\x91\x02";
    const char long_string[] = "\xdb\xff\xff\xff\xff";

    scan = flb_mp_preflight_create(6144000, 6144000);
    TEST_ASSERT(scan != NULL);
    ret = flb_mp_preflight_scan(scan, array, 5, &consumed, &cost);
    TEST_CHECK(ret == -1);
    flb_mp_preflight_reset(scan, 6144000, 6144000);
    TEST_CHECK(flb_mp_preflight_scan(scan, map, 5, &consumed, &cost) == -1);

    flb_mp_preflight_reset(scan, 6144000, 6144000);
    TEST_CHECK(flb_mp_preflight_scan(scan, array, 2, &consumed, &cost) == 0);
    TEST_CHECK(flb_mp_preflight_scan(scan, array, 5, &consumed, &cost) == -1);

    flb_mp_preflight_reset(scan, 6144000, 6144000);
    for (i = 1; i < sizeof(valid); i++) {
        ret = flb_mp_preflight_scan(scan, valid, i, &consumed, &cost);
        TEST_CHECK(ret == (i == sizeof(valid) - 1 ? 1 : 0));
    }
    required = cost;
    TEST_CHECK(consumed == sizeof(valid) - 1);
    TEST_CHECK(required >= MSGPACK_ZONE_CHUNK_SIZE);
    flb_mp_preflight_reset(scan, required, 6144000);
    TEST_CHECK(flb_mp_preflight_scan(scan, valid, sizeof(valid) - 1, &consumed, &cost) == 1);
    flb_mp_preflight_reset(scan, required - 1, 6144000);
    TEST_CHECK(flb_mp_preflight_scan(scan, valid, sizeof(valid) - 1, &consumed, &cost) == -1);

    flb_mp_preflight_reset(scan, 128, 6144000);
    TEST_CHECK(flb_mp_preflight_scan(scan, nested, sizeof(nested) - 1, &consumed, &cost) == -1);
    flb_mp_preflight_reset(scan, 6144000, 6144000);
    memset(deep, 0x91, sizeof(deep));
    TEST_CHECK(flb_mp_preflight_scan(scan, deep, sizeof(deep), &consumed, &cost) == -1);
    flb_mp_preflight_reset(scan, 6144000, 6144000);
    TEST_CHECK(flb_mp_preflight_scan(scan, invalid, 1, &consumed, &cost) == -1);
    TEST_CHECK(flb_mp_preflight_sequence(valid, sizeof(valid) - 1, required) == 0);
    TEST_CHECK(flb_mp_preflight_sequence(valid, sizeof(valid) - 2, required) == -1);
    TEST_CHECK(flb_mp_preflight_sequence(array, 5, 6144000) == -1);
    TEST_CHECK(flb_mp_preflight_sequence(sequence, sizeof(sequence) - 1, required) == -1);
    TEST_CHECK(flb_mp_preflight_sequence(sequence, sizeof(sequence) - 1, 2 * required) == 0);
    TEST_CHECK(flb_mp_preflight_sequence_limited(sequence, sizeof(sequence) - 1,
                                                  2 * required, 3) == -1);
    TEST_CHECK(flb_mp_preflight_sequence_limited(sequence, sizeof(sequence) - 1,
                                                  2 * required, 4) == 0);
    flb_mp_preflight_reset(scan, 6144000, 6144000);
    TEST_CHECK(flb_mp_preflight_scan(scan, long_string, 5, &consumed, &cost) == -1);
    memset(large_string, 'a', sizeof(large_string));
    large_string[0] = (char) 0xda;
    large_string[1] = 0x40;
    large_string[2] = 0;
    flb_mp_preflight_reset(scan, required, sizeof(large_string));
    TEST_CHECK(flb_mp_preflight_scan(scan, large_string, sizeof(large_string),
                                     &consumed, &cost) == 1);
    flb_mp_preflight_reset(scan, required, sizeof(large_string) - 1);
    TEST_CHECK(flb_mp_preflight_scan(scan, large_string, sizeof(large_string),
                                     &consumed, &cost) == -1);
    flb_mp_preflight_destroy(scan);
}

static void test_preflight_formats(void)
{
    struct flb_mp_preflight *scan;
    msgpack_sbuffer buffer;
    msgpack_packer packer;
    msgpack_unpacked result;
    size_t consumed;
    size_t cost;
    size_t offset;
    size_t i;
    size_t limit;
    int ret;
    char bytes[300];

    memset(bytes, 'a', sizeof(bytes));
    scan = flb_mp_preflight_create(6144000, 6144000);
    TEST_ASSERT(scan != NULL);
    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);
    msgpack_pack_array(&packer, 20);
    msgpack_pack_nil(&packer);
    msgpack_pack_true(&packer);
    msgpack_pack_false(&packer);
    msgpack_pack_uint8(&packer, 200);
    msgpack_pack_uint16(&packer, 1000);
    msgpack_pack_uint32(&packer, 100000);
    msgpack_pack_uint64(&packer, UINT64_MAX);
    msgpack_pack_int8(&packer, -100);
    msgpack_pack_int16(&packer, -1000);
    msgpack_pack_int32(&packer, -100000);
    msgpack_pack_int64(&packer, INT64_MIN);
    msgpack_pack_float(&packer, 1.5);
    msgpack_pack_double(&packer, 2.5);
    msgpack_pack_str(&packer, sizeof(bytes));
    msgpack_pack_str_body(&packer, bytes, sizeof(bytes));
    msgpack_pack_bin(&packer, sizeof(bytes));
    msgpack_pack_bin_body(&packer, bytes, sizeof(bytes));
    msgpack_pack_ext(&packer, sizeof(bytes), 1);
    msgpack_pack_ext_body(&packer, bytes, sizeof(bytes));
    msgpack_pack_ext(&packer, 0, 1);
    msgpack_pack_ext(&packer, 8, 0);
    msgpack_pack_ext_body(&packer, bytes, 8);
    msgpack_pack_map(&packer, 0);
    msgpack_pack_array(&packer, 2000);
    for (i = 0; i < 2000; i++) {
        msgpack_pack_map(&packer, 1);
        msgpack_pack_str(&packer, 1);
        msgpack_pack_str_body(&packer, "k", 1);
        msgpack_pack_nil(&packer);
    }
    for (i = 1; i <= buffer.size; i++) {
        ret = flb_mp_preflight_scan(scan, buffer.data, i, &consumed, &cost);
        TEST_CHECK(ret == (i == buffer.size ? 1 : 0));
    }
    TEST_CHECK(consumed == buffer.size);
    limit = cost;
    TEST_CHECK(limit > MSGPACK_ZONE_CHUNK_SIZE);
    flb_mp_preflight_reset(scan, limit, 6144000);
    TEST_CHECK(flb_mp_preflight_scan(scan, buffer.data, buffer.size, &consumed, &cost) == 1);
    flb_mp_preflight_reset(scan, limit - 1, 6144000);
    TEST_CHECK(flb_mp_preflight_scan(scan, buffer.data, buffer.size, &consumed, &cost) == -1);
    msgpack_unpacked_init(&result);
    offset = 0;
    TEST_CHECK(msgpack_unpack_next(&result, buffer.data, buffer.size, &offset) ==
               MSGPACK_UNPACK_SUCCESS);
    TEST_CHECK(offset == buffer.size);
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_destroy(&buffer);
    flb_mp_preflight_destroy(scan);
}

/* Compare optimized counts with the authoritative decoder, including every
 * truncated prefix and byte corruption of grouped and ordinary records. */
static int reference_log_count(const char *data, size_t size)
{
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    int count = 0;

    if (flb_log_event_decoder_init(&decoder, (char *) data, size) != 0) {
        return 0;
    }
    while (flb_log_event_decoder_next(&decoder, &event) == 0) {
        count++;
    }
    flb_log_event_decoder_destroy(&decoder);
    return count;
}

/* pack one object of every MessagePack family, nested 'depth' levels */
static void raw_pack_sample(msgpack_packer *pck, int depth)
{
    int i;
    char blob[300];

    memset(blob, 'x', sizeof(blob));

    msgpack_pack_map(pck, 12);
    msgpack_pack_str_with_body(pck, "fixstr", 6);
    msgpack_pack_str_with_body(pck, blob, 31);
    msgpack_pack_str_with_body(pck, "str8", 4);
    msgpack_pack_str_with_body(pck, blob, 200);
    msgpack_pack_str_with_body(pck, "str16", 5);
    msgpack_pack_str_with_body(pck, blob, 300);
    msgpack_pack_str_with_body(pck, "bin", 3);
    msgpack_pack_bin_with_body(pck, blob, 40);
    msgpack_pack_str_with_body(pck, "ext", 3);
    msgpack_pack_ext_with_body(pck, blob, 8, 0);
    msgpack_pack_str_with_body(pck, "ext8", 4);
    msgpack_pack_ext_with_body(pck, blob, 23, 5);
    msgpack_pack_str_with_body(pck, "ints", 4);
    msgpack_pack_array(pck, 9);
    msgpack_pack_uint64(pck, 1);
    msgpack_pack_uint64(pck, 200);
    msgpack_pack_uint64(pck, 70000);
    msgpack_pack_uint64(pck, 5000000000ULL);
    msgpack_pack_int64(pck, -1);
    msgpack_pack_int64(pck, -100);
    msgpack_pack_int64(pck, -40000);
    msgpack_pack_int64(pck, -3000000000LL);
    msgpack_pack_uint64(pck, 60000);
    msgpack_pack_str_with_body(pck, "floats", 6);
    msgpack_pack_array(pck, 2);
    msgpack_pack_float(pck, 1.5);
    msgpack_pack_double(pck, 2.5);
    msgpack_pack_str_with_body(pck, "others", 6);
    msgpack_pack_array(pck, 3);
    msgpack_pack_nil(pck);
    msgpack_pack_true(pck);
    msgpack_pack_false(pck);
    msgpack_pack_str_with_body(pck, "array16", 7);
    msgpack_pack_array(pck, 20);

    for (i = 0; i < 20; i++) {
        msgpack_pack_int(pck, i);
    }

    msgpack_pack_str_with_body(pck, "map16", 5);
    msgpack_pack_map(pck, 17);

    for (i = 0; i < 17; i++) {
        msgpack_pack_int(pck, i);
        msgpack_pack_nil(pck);
    }

    msgpack_pack_str_with_body(pck, "nested", 6);

    for (i = 0; i < depth; i++) {
        msgpack_pack_array(pck, 1);
    }

    msgpack_pack_nil(pck);
}

/* the raw walker must find the same object boundaries as the unpacker */
static void test_raw_skip(void)
{
    int i;
    int ret;
    size_t off;
    size_t length;
    uint32_t count;
    uint32_t str_len;
    const unsigned char *p;
    const unsigned char *q;
    const unsigned char *end;
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    msgpack_unpacked result;
    unsigned char c1 = 0xc1;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    for (i = 0; i < 3; i++) {
        raw_pack_sample(&pck, 5 + i);
    }

    /* walk the three objects */
    off = 0;
    p = (const unsigned char *) sbuf.data;
    end = p + sbuf.size;
    msgpack_unpacked_init(&result);

    for (i = 0; i < 3; i++) {
        ret = msgpack_unpack_next(&result, sbuf.data, sbuf.size, &off);
        TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
        TEST_CHECK(flb_mp_raw_skip(&p, end, FLB_MP_RAW_MAX_DEPTH) == 0);
        TEST_CHECK((size_t) (p - (const unsigned char *) sbuf.data) == off);
    }

    msgpack_unpacked_destroy(&result);
    TEST_CHECK(p == end);

    /* a truncated buffer never succeeds and never moves the cursor */
    length = flb_mp_raw_object_size(sbuf.data, sbuf.size, FLB_MP_RAW_MAX_DEPTH);
    TEST_CHECK(length > 0 && length < sbuf.size);

    for (off = 0; off < length; off++) {
        p = (const unsigned char *) sbuf.data;
        ret = flb_mp_raw_skip(&p, p + off, FLB_MP_RAW_MAX_DEPTH);
        TEST_CHECK(ret == -1);
        TEST_CHECK(p == (const unsigned char *) sbuf.data);
    }

    TEST_CHECK(flb_mp_raw_object_size(sbuf.data, 0, FLB_MP_RAW_MAX_DEPTH) == 0);
    TEST_CHECK(flb_mp_raw_object_size(NULL, 10, FLB_MP_RAW_MAX_DEPTH) == 0);

    /* 0xc1 is not a valid type */
    p = &c1;
    TEST_CHECK(flb_mp_raw_skip(&p, p + 1, FLB_MP_RAW_MAX_DEPTH) == -1);

    /* map and string headers */
    p = (const unsigned char *) sbuf.data;
    TEST_CHECK(flb_mp_raw_map_header(&p, end, &count) == 0 && count == 12);
    TEST_CHECK(flb_mp_raw_map_header(&p, end, &count) == -1);
    TEST_CHECK(flb_mp_raw_str_header(&p, end, &str_len) == 0 && str_len == 6);
    TEST_CHECK(memcmp(p, "fixstr", 6) == 0);
    p += str_len;
    TEST_CHECK(flb_mp_raw_str_header(&p, p + 10, &str_len) == -1);
    TEST_CHECK(flb_mp_raw_str_header(&p, end, &str_len) == 0 && str_len == 31);
    msgpack_sbuffer_destroy(&sbuf);

    /* a string header is minimal only in the shortest format */
    p = (const unsigned char *) "\xa3" "abc";
    TEST_CHECK(flb_mp_raw_str_header_minimal(&p, p + 4, &str_len) == 0 &&
               str_len == 3);
    p = (const unsigned char *) "\xd9\x03" "abc";
    q = p;
    TEST_CHECK(flb_mp_raw_str_header_minimal(&p, p + 5, &str_len) == -1);
    TEST_CHECK(p == q);
    TEST_CHECK(flb_mp_raw_str_header(&p, p + 5, &str_len) == 0 && str_len == 3);
    p = (const unsigned char *) "\xda\x00\x03" "abc";
    TEST_CHECK(flb_mp_raw_str_header_minimal(&p, p + 6, &str_len) == -1);
    p = (const unsigned char *) "\xdb\x00\x00\x00\x03" "abc";
    TEST_CHECK(flb_mp_raw_str_header_minimal(&p, p + 8, &str_len) == -1);
    p = (const unsigned char *) "\xc4\x03" "abc";
    TEST_CHECK(flb_mp_raw_str_header_minimal(&p, p + 5, &str_len) == -1);

    /*
     * Nesting limit: the sample has the map, the 'nested' arrays and the
     * final value, so 'depth' arrays need depth + 2 levels.
     */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    raw_pack_sample(&pck, 10);
    TEST_CHECK(flb_mp_raw_object_size(sbuf.data, sbuf.size, 12) == sbuf.size);
    TEST_CHECK(flb_mp_raw_object_size(sbuf.data, sbuf.size, 11) == 0);
    TEST_CHECK(flb_mp_raw_object_size(sbuf.data, sbuf.size, 1) == 0);
    msgpack_sbuffer_destroy(&sbuf);

    /* a depth above the supported one is capped, not trusted */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    raw_pack_sample(&pck, FLB_MP_RAW_MAX_DEPTH + 10);
    TEST_CHECK(flb_mp_raw_object_size(sbuf.data, sbuf.size, 1000) == 0);
    msgpack_sbuffer_destroy(&sbuf);
}

/* Results of the two reference implementations for one buffer */
struct raw_reference {
    int msgpack_ok;
    size_t msgpack_size;
    int mpack_ok;
    size_t mpack_size;
    int repack_equal;
};

/*
 * Decode the first object of a buffer with msgpack-c and with mpack. The
 * object is packed again with msgpack-c to know if the same bytes come back.
 */
static void raw_reference_run(const unsigned char *buf, size_t size,
                              int use_msgpack, struct raw_reference *ref)
{
    int ret;
    size_t off = 0;
    mpack_reader_t reader;
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    msgpack_unpacked result;

    memset(ref, 0, sizeof(struct raw_reference));

    if (size > 0) {
        mpack_reader_init_data(&reader, (const char *) buf, size);
        mpack_discard(&reader);

        if (mpack_reader_error(&reader) == mpack_ok) {
            ref->mpack_ok = FLB_TRUE;
            ref->mpack_size = size - mpack_reader_remaining(&reader, NULL);
        }

        mpack_reader_destroy(&reader);
    }

    if (use_msgpack == FLB_FALSE || size == 0) {
        return;
    }

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, (const char *) buf, size, &off);

    if (ret == MSGPACK_UNPACK_SUCCESS) {
        ref->msgpack_ok = FLB_TRUE;
        ref->msgpack_size = off;

        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
        ret = msgpack_pack_object(&pck, result.data);

        if (ret == 0 && sbuf.size == off && memcmp(sbuf.data, buf, off) == 0) {
            ref->repack_equal = FLB_TRUE;
        }

        msgpack_sbuffer_destroy(&sbuf);
    }

    msgpack_unpacked_destroy(&result);
}

/*
 * Check one valid object of a known size: the walker, msgpack-c and mpack
 * must agree on it, and no truncated version of it can be accepted. Returns
 * FLB_TRUE if the object is accepted by the minimal walker.
 */
static int raw_check_valid(const unsigned char *buf, size_t size)
{
    int ret;
    int minimal;
    size_t cut;
    size_t step;
    const unsigned char *p;
    struct raw_reference ref;

    raw_reference_run(buf, size, FLB_TRUE, &ref);
    TEST_CHECK(ref.msgpack_ok == FLB_TRUE && ref.msgpack_size == size);
    TEST_CHECK(ref.mpack_ok == FLB_TRUE && ref.mpack_size == size);

    p = buf;
    ret = flb_mp_raw_skip(&p, buf + size, 0);
    TEST_CHECK(ret == 0 && p == buf + size);

    p = buf;
    ret = flb_mp_raw_skip(&p, buf + size, FLB_MP_RAW_MAX_DEPTH);
    TEST_CHECK(ret == 0 && p == buf + size);

    TEST_CHECK(flb_mp_raw_object_size((const char *) buf, size, 0) == size);

    /* trailing data is not part of the object */
    p = buf;
    ret = flb_mp_raw_skip(&p, buf + size + 1, 0);
    TEST_CHECK(ret == 0 && p == buf + size);

    /* minimal: accepted only if packing the object gives the same bytes */
    p = buf;
    minimal = flb_mp_raw_skip_minimal(&p, buf + size, 0) == 0;
    TEST_CHECK(minimal == ref.repack_equal);
    TEST_MSG("first byte 0x%02x size %zu minimal %d repack %d",
             buf[0], size, minimal, ref.repack_equal);

    if (minimal) {
        TEST_CHECK(p == buf + size);
    }
    else {
        TEST_CHECK(p == buf);
    }

    /* every truncation fails and leaves the cursor in place */
    step = size > 4096 ? size / 61 : 1;

    for (cut = 0; cut < size; cut += step) {
        p = buf;
        ret = flb_mp_raw_skip(&p, buf + cut, 0);
        TEST_CHECK(ret == -1 && p == buf);

        p = buf;
        ret = flb_mp_raw_skip_minimal(&p, buf + cut, 0);
        TEST_CHECK(ret == -1 && p == buf);
    }

    p = buf;
    ret = flb_mp_raw_skip(&p, buf + size - 1, 0);
    TEST_CHECK(ret == -1 && p == buf);

    return minimal;
}

static size_t raw_put_be(unsigned char *buf, uint64_t value, int bytes)
{
    int i;

    for (i = 0; i < bytes; i++) {
        buf[i] = (unsigned char) (value >> (8 * (bytes - 1 - i)));
    }

    return bytes;
}

/*
 * Build the object that starts with the given byte. Lengths and counts that
 * are not part of the first byte are set to 'count'. Returns the size that
 * the specification gives to the object, zero if the byte is not a format.
 */
static size_t raw_build_format(unsigned char c, uint32_t count,
                               unsigned char *buf)
{
    size_t len = 0;
    size_t body = 0;
    size_t fill = 0xc0;

    buf[len++] = c;

    if (c <= 0x7f || c >= 0xe0) {
        return len;
    }
    else if (c <= 0x8f) {
        body = (size_t) (c & 0x0f) * 2;
    }
    else if (c <= 0x9f) {
        body = c & 0x0f;
    }
    else if (c <= 0xbf) {
        body = c & 0x1f;
        fill = 'a';
    }
    else {
        switch (c) {
        case 0xc0:
        case 0xc2:
        case 0xc3:
            return len;
        case 0xc1:
            return 0;
        case 0xc4:
        case 0xd9:
            len += raw_put_be(buf + len, count, 1);
            body = count;
            fill = 'b';
            break;
        case 0xc5:
        case 0xda:
            len += raw_put_be(buf + len, count, 2);
            body = count;
            fill = 'b';
            break;
        case 0xc6:
        case 0xdb:
            len += raw_put_be(buf + len, count, 4);
            body = count;
            fill = 'b';
            break;
        case 0xc7:
            len += raw_put_be(buf + len, count, 1);
            buf[len++] = 0x05;
            body = count;
            fill = 'e';
            break;
        case 0xc8:
            len += raw_put_be(buf + len, count, 2);
            buf[len++] = 0x05;
            body = count;
            fill = 'e';
            break;
        case 0xc9:
            len += raw_put_be(buf + len, count, 4);
            buf[len++] = 0x05;
            body = count;
            fill = 'e';
            break;
        case 0xca:
        case 0xce:
        case 0xd2:
            /* 1.5 as float, 0x3fc00000 as uint, a negative int 32 */
            len += raw_put_be(buf + len, c == 0xd2 ? 0x80000001 : 0x3fc00000, 4);
            return len;
        case 0xcb:
        case 0xcf:
        case 0xd3:
            len += raw_put_be(buf + len,
                              c == 0xd3 ? 0x8000000000000001ULL :
                              0x3ff8000000000000ULL, 8);
            return len;
        case 0xcc:
        case 0xd0:
            len += raw_put_be(buf + len, 0x90, 1);
            return len;
        case 0xcd:
        case 0xd1:
            len += raw_put_be(buf + len, 0x9000, 2);
            return len;
        case 0xd4:
            body = 2;
            fill = 0x05;
            break;
        case 0xd5:
            body = 3;
            fill = 0x05;
            break;
        case 0xd6:
            body = 5;
            fill = 0x05;
            break;
        case 0xd7:
            body = 9;
            fill = 0x05;
            break;
        case 0xd8:
            body = 17;
            fill = 0x05;
            break;
        case 0xdc:
            len += raw_put_be(buf + len, count, 2);
            body = count;
            break;
        case 0xdd:
            len += raw_put_be(buf + len, count, 4);
            body = count;
            break;
        case 0xde:
            len += raw_put_be(buf + len, count, 2);
            body = (size_t) count * 2;
            break;
        case 0xdf:
            len += raw_put_be(buf + len, count, 4);
            body = (size_t) count * 2;
            break;
        }
    }

    memset(buf + len, (int) fill, body);

    return len + body;
}

/* every one of the 256 first bytes: sizes defined by the specification */
static void test_raw_skip_formats(void)
{
    int c;
    int ret;
    int minimal;
    size_t size;
    unsigned char *buf;
    const unsigned char *p;
    struct raw_reference ref;

    buf = flb_malloc(256);
    TEST_CHECK(buf != NULL);

    if (buf == NULL) {
        return;
    }

    for (c = 0; c <= 0xff; c++) {
        /* 40 does not fit in a shorter format for any type */
        size = raw_build_format((unsigned char) c, 40, buf);

        if (c == 0xc1) {
            TEST_CHECK(size == 0);
            buf[1] = 0xc0;
            p = buf;
            ret = flb_mp_raw_skip(&p, buf + 2, 0);
            TEST_CHECK(ret == -1 && p == buf);
            ret = flb_mp_raw_skip_minimal(&p, buf + 2, 0);
            TEST_CHECK(ret == -1 && p == buf);
            TEST_CHECK(flb_mp_raw_object_size((char *) buf, 2, 0) == 0);

            raw_reference_run(buf, 2, FLB_TRUE, &ref);
            TEST_CHECK(ref.msgpack_ok == FLB_FALSE);
            TEST_CHECK(ref.mpack_ok == FLB_FALSE);
            continue;
        }

        TEST_CHECK(size > 0);
        minimal = raw_check_valid(buf, size);

        /* a length or count of 40 fits in a shorter header for these */
        if (c == 0xc5 || c == 0xc6 || c == 0xc8 || c == 0xc9 ||
            c == 0xda || c == 0xdb || c == 0xdd || c == 0xdf) {
            TEST_CHECK(minimal == FLB_FALSE);
        }
        else {
            TEST_CHECK(minimal == FLB_TRUE);
        }

        TEST_MSG("first byte 0x%02x", c);
    }

    flb_free(buf);
}

/* lengths and counts around the limit of every header size */
static void test_raw_skip_lengths(void)
{
    int i;
    int j;
    int minimal;
    int expected;
    size_t size;
    uint32_t count;
    unsigned char *buf;
    uint32_t counts[] = {0, 1, 2, 4, 8, 15, 16, 17, 31, 32, 33, 255, 256,
                         257, 65535, 65536, 65537, 70000};
    /* format, bytes of the length, first length that needs this format */
    struct {
        unsigned char format;
        uint32_t max;
        uint32_t min;
    } formats[] = {
        {0xc4, 0xff, 0},         {0xc5, 0xffff, 256},
        {0xc6, 0xffffffff, 65536},
        {0xc7, 0xff, 0},         {0xc8, 0xffff, 256},
        {0xc9, 0xffffffff, 65536},
        {0xd9, 0xff, 32},        {0xda, 0xffff, 256},
        {0xdb, 0xffffffff, 65536},
        {0xdc, 0xffff, 16},      {0xdd, 0xffffffff, 65536},
        {0xde, 0xffff, 16},      {0xdf, 0xffffffff, 65536}
    };

    buf = flb_malloc(70000 * 2 + 16);
    TEST_CHECK(buf != NULL);

    if (buf == NULL) {
        return;
    }

    for (i = 0; i < sizeof(formats) / sizeof(formats[0]); i++) {
        for (j = 0; j < sizeof(counts) / sizeof(counts[0]); j++) {
            count = counts[j];

            if (count > formats[i].max) {
                continue;
            }

            size = raw_build_format(formats[i].format, count, buf);
            minimal = raw_check_valid(buf, size);
            expected = count >= formats[i].min;

            /* ext 8: these lengths are a fixext */
            if (formats[i].format == 0xc7 &&
                (count == 1 || count == 2 || count == 4 || count == 8 ||
                 count == 16)) {
                expected = FLB_FALSE;
            }

            TEST_CHECK(minimal == expected);
            TEST_MSG("format 0x%02x count %u", formats[i].format, count);
        }
    }

    flb_free(buf);
}

/* integers and floats: shortest format rules of the packer */
static void test_raw_skip_numbers(void)
{
    int i;
    int j;
    int bytes;
    int minimal;
    int64_t value;
    uint64_t mask;
    size_t size;
    const unsigned char *p;
    unsigned char buf[16];
    unsigned char formats[] = {0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3};
    int64_t values[] = {0, 1, 127, 128, 255, 256, 32767, 32768, 65535, 65536,
                        2147483647LL, 2147483648LL, 4294967295LL, 4294967296LL,
                        INT64_MAX, -1, -32, -33, -128, -129, -32768, -32769,
                        -2147483648LL, -2147483649LL, INT64_MIN};
    /* float 32 and float 64 bit patterns */
    uint32_t floats[] = {0x00000000, 0x80000000, 0x3fc00000, 0x00000001,
                         0x7f800000, 0xff800000, 0x7f7fffff};
    uint32_t float_nans[] = {0x7fc00000, 0x7f800001, 0xffc00000, 0x7fa00000,
                             0x7fffffff};
    uint64_t doubles[] = {0x0000000000000000ULL, 0x8000000000000000ULL,
                          0x3ff8000000000000ULL, 0x0000000000000001ULL,
                          0x7ff0000000000000ULL, 0xfff0000000000000ULL};
    uint64_t double_nans[] = {0x7ff8000000000000ULL, 0x7ff0000000000001ULL,
                              0xfff8000000000000ULL, 0x7ff4000000000000ULL,
                              0x7ff0000100000000ULL};

    for (i = 0; i < sizeof(formats); i++) {
        bytes = 1 << (i % 4);
        mask = bytes == 8 ? UINT64_MAX : (1ULL << (bytes * 8)) - 1;

        for (j = 0; j < sizeof(values) / sizeof(values[0]); j++) {
            value = values[j];
            buf[0] = formats[i];
            raw_put_be(buf + 1, (uint64_t) value & mask, bytes);
            size = 1 + bytes;

            /* the reference tells if this is what the packer writes */
            raw_check_valid(buf, size);
        }
    }

    for (i = 0; i < sizeof(floats) / sizeof(floats[0]); i++) {
        buf[0] = 0xca;
        raw_put_be(buf + 1, floats[i], 4);
        minimal = raw_check_valid(buf, 5);
        TEST_CHECK(minimal == FLB_TRUE);
    }

    for (i = 0; i < sizeof(doubles) / sizeof(doubles[0]); i++) {
        buf[0] = 0xcb;
        raw_put_be(buf + 1, doubles[i], 8);
        minimal = raw_check_valid(buf, 9);
        TEST_CHECK(minimal == FLB_TRUE);
    }

    /* a NaN is valid, but it is never reported as minimal */
    for (i = 0; i < sizeof(float_nans) / sizeof(float_nans[0]); i++) {
        buf[0] = 0xca;
        raw_put_be(buf + 1, float_nans[i], 4);
        p = buf;
        TEST_CHECK(flb_mp_raw_skip(&p, buf + 5, 0) == 0 && p == buf + 5);
        p = buf;
        TEST_CHECK(flb_mp_raw_skip_minimal(&p, buf + 5, 0) == -1 && p == buf);
    }

    for (i = 0; i < sizeof(double_nans) / sizeof(double_nans[0]); i++) {
        buf[0] = 0xcb;
        raw_put_be(buf + 1, double_nans[i], 8);
        p = buf;
        TEST_CHECK(flb_mp_raw_skip(&p, buf + 9, 0) == 0 && p == buf + 9);
        p = buf;
        TEST_CHECK(flb_mp_raw_skip_minimal(&p, buf + 9, 0) == -1 && p == buf);
    }
}

/* nesting: exact limits, no limit, and counts larger than the buffer */
static void test_raw_skip_depth(void)
{
    int i;
    int depth;
    int limit;
    int ret;
    size_t len;
    size_t size;
    unsigned char *buf;
    const unsigned char *p;
    struct raw_reference ref;

    buf = flb_malloc(8192);
    TEST_CHECK(buf != NULL);

    if (buf == NULL) {
        return;
    }

    /* 'depth' containers and a final value need depth + 1 levels */
    for (depth = 0; depth <= 300; depth++) {
        len = 0;

        for (i = 0; i < depth; i++) {
            if (i % 3 == 0) {
                /* map of one pair: the nested value is the key */
                buf[len++] = 0x81;
            }
            else if (i % 3 == 1) {
                buf[len++] = 0x91;
            }
            else {
                /* array 16 of two items */
                buf[len++] = 0xdc;
                buf[len++] = 0x00;
                buf[len++] = 0x02;
            }
        }

        buf[len++] = 0x2a;

        /* close the containers from the inside out */
        for (i = depth - 1; i >= 0; i--) {
            if (i % 3 == 0) {
                buf[len++] = 0xc0;
            }
            else if (i % 3 == 2) {
                buf[len++] = 0xc3;
            }
        }

        size = len;

        /* no limit: any depth is valid MessagePack */
        p = buf;
        ret = flb_mp_raw_skip(&p, buf + size, 0);
        TEST_CHECK(ret == 0 && p == buf + size);
        TEST_MSG("depth %d", depth);

        /* mpack has no depth limit, msgpack-c stops at 32 levels */
        raw_reference_run(buf, size, depth < 30, &ref);
        TEST_CHECK(ref.mpack_ok == FLB_TRUE && ref.mpack_size == size);

        if (depth < 30) {
            TEST_CHECK(ref.msgpack_ok == FLB_TRUE && ref.msgpack_size == size);
        }

        for (limit = 1; limit <= FLB_MP_RAW_MAX_DEPTH + 3; limit++) {
            p = buf;
            ret = flb_mp_raw_skip(&p, buf + size, limit);

            if (depth + 1 <= limit && depth + 1 <= FLB_MP_RAW_MAX_DEPTH) {
                TEST_CHECK(ret == 0 && p == buf + size);
            }
            else {
                TEST_CHECK(ret == -1 && p == buf);
            }

            TEST_MSG("depth %d limit %d ret %d", depth, limit, ret);
        }

        /* truncated deep objects */
        if (size > 1) {
            p = buf;
            ret = flb_mp_raw_skip(&p, buf + size - 1, 0);
            TEST_CHECK(ret == -1 && p == buf);
        }
    }

    /* empty containers do not need a level of their own */
    buf[0] = 0x80;
    p = buf;
    TEST_CHECK(flb_mp_raw_skip(&p, buf + 1, 1) == 0 && p == buf + 1);
    buf[0] = 0x90;
    p = buf;
    TEST_CHECK(flb_mp_raw_skip(&p, buf + 1, 1) == 0 && p == buf + 1);
    buf[0] = 0x91;
    buf[1] = 0x90;
    p = buf;
    TEST_CHECK(flb_mp_raw_skip(&p, buf + 2, 1) == -1 && p == buf);
    TEST_CHECK(flb_mp_raw_skip(&p, buf + 2, 2) == 0 && p == buf + 2);

    /* huge counts with no data, at any depth, are an error and not a loop */
    len = 0;

    for (i = 0; i < 200; i++) {
        buf[len++] = (i % 2) ? 0xdd : 0xdf;
        buf[len++] = 0xff;
        buf[len++] = 0xff;
        buf[len++] = 0xff;
        buf[len++] = 0xff;

        p = buf;
        ret = flb_mp_raw_skip(&p, buf + len, 0);
        TEST_CHECK(ret == -1 && p == buf);

        p = buf;
        ret = flb_mp_raw_skip(&p, buf + len, FLB_MP_RAW_MAX_DEPTH);
        TEST_CHECK(ret == -1 && p == buf);
    }

    /* invalid arguments */
    TEST_CHECK(flb_mp_raw_object_size((char *) buf, 0, 0) == 0);
    TEST_CHECK(flb_mp_raw_object_size(NULL, 10, 0) == 0);
    p = buf;
    TEST_CHECK(flb_mp_raw_skip(&p, buf, 0) == -1 && p == buf);

    flb_free(buf);
}

/* random documents */
struct raw_gen {
    uint64_t state;
    unsigned char *buf;
    size_t len;
    size_t cap;
    int nodes;
    /* the first value of these levels is a container: a deep document */
    int spine;
    int spine_reached;
};

static uint64_t raw_gen_rand(struct raw_gen *gen)
{
    /* xorshift64* */
    gen->state ^= gen->state >> 12;
    gen->state ^= gen->state << 25;
    gen->state ^= gen->state >> 27;

    return gen->state * 2685821657736338717ULL;
}

static uint32_t raw_gen_pick(struct raw_gen *gen, uint32_t n)
{
    return (uint32_t) ((raw_gen_rand(gen) >> 32) % n);
}

/* length or count header in any format that is wide enough */
static void raw_gen_header(struct raw_gen *gen, int type, uint32_t count)
{
    int i;
    int options = 0;
    unsigned char format[4];
    int bytes[4];
    /* fix, 8, 16 and 32 bit formats: str, bin, ext, array, map */
    unsigned char table[5][4] = {
        {0xa0, 0xd9, 0xda, 0xdb}, {0x00, 0xc4, 0xc5, 0xc6},
        {0x00, 0xc7, 0xc8, 0xc9}, {0x90, 0x00, 0xdc, 0xdd},
        {0x80, 0x00, 0xde, 0xdf}
    };
    uint32_t fix_max[5] = {31, 0, 0, 15, 15};

    if (table[type][0] != 0 && count <= fix_max[type]) {
        format[options] = (unsigned char) (table[type][0] | count);
        bytes[options++] = 0;
    }

    if (type == 2 && (count == 1 || count == 2 || count == 4 || count == 8 ||
                      count == 16)) {
        format[options] = (unsigned char) (0xd4 + (count == 1 ? 0 :
                                                   count == 2 ? 1 :
                                                   count == 4 ? 2 :
                                                   count == 8 ? 3 : 4));
        bytes[options++] = 0;
    }

    if (table[type][1] != 0 && count <= 0xff) {
        format[options] = table[type][1];
        bytes[options++] = 1;
    }

    if (count <= 0xffff) {
        format[options] = table[type][2];
        bytes[options++] = 2;
    }

    format[options] = table[type][3];
    bytes[options++] = 4;

    /* half of the time use the shortest one */
    i = raw_gen_pick(gen, 2) ? 0 : (int) raw_gen_pick(gen, options);
    gen->buf[gen->len++] = format[i];
    gen->len += raw_put_be(gen->buf + gen->len, count, bytes[i]);

    if (type == 2) {
        gen->buf[gen->len++] = (unsigned char) raw_gen_rand(gen);
    }
}

static void raw_gen_integer(struct raw_gen *gen)
{
    int i;
    int options = 0;
    int shift;
    int64_t value;
    unsigned char format[9];
    int bytes[9];

    /* random magnitude, so every format is used */
    shift = 1 + raw_gen_pick(gen, 63);
    value = (int64_t) (raw_gen_rand(gen) >> shift);

    if (raw_gen_pick(gen, 2)) {
        value = -value - 1;
    }

    if (raw_gen_pick(gen, 8) == 0) {
        value = (int64_t) raw_gen_pick(gen, 300) - 150;
    }

    if (value >= 0) {
        if (value <= 0x7f) {
            format[options] = (unsigned char) value;
            bytes[options++] = 0;
        }

        if (value <= 0xff) {
            format[options] = 0xcc;
            bytes[options++] = 1;
        }

        if (value <= 0xffff) {
            format[options] = 0xcd;
            bytes[options++] = 2;
        }

        if (value <= 0xffffffffLL) {
            format[options] = 0xce;
            bytes[options++] = 4;
        }

        format[options] = 0xcf;
        bytes[options++] = 8;
    }
    else if (value >= -32) {
        format[options] = (unsigned char) value;
        bytes[options++] = 0;
    }

    if (value >= INT8_MIN && value <= INT8_MAX) {
        format[options] = 0xd0;
        bytes[options++] = 1;
    }

    if (value >= INT16_MIN && value <= INT16_MAX) {
        format[options] = 0xd1;
        bytes[options++] = 2;
    }

    if (value >= INT32_MIN && value <= INT32_MAX) {
        format[options] = 0xd2;
        bytes[options++] = 4;
    }

    format[options] = 0xd3;
    bytes[options++] = 8;

    i = raw_gen_pick(gen, 2) ? 0 : (int) raw_gen_pick(gen, options);
    gen->buf[gen->len++] = format[i];
    gen->len += raw_put_be(gen->buf + gen->len, (uint64_t) value, bytes[i]);
}

static void raw_gen_value(struct raw_gen *gen, int depth, int max_depth)
{
    int type;
    int spine = FLB_FALSE;
    uint32_t i;
    uint32_t count;
    uint64_t bits;

    gen->nodes++;
    type = raw_gen_pick(gen, 100);

    /* keep the document inside the buffer */
    if (gen->nodes > 400 || gen->cap - gen->len < 80000) {
        type = 99;
    }

    if (depth < gen->spine && depth == gen->spine_reached) {
        gen->spine_reached++;
        spine = FLB_TRUE;
        type = 65 + raw_gen_pick(gen, 25);
    }

    if (type < 25) {
        raw_gen_integer(gen);
    }
    else if (type < 30) {
        /* float 32, no NaN */
        bits = raw_gen_rand(gen) & 0xffffffff;

        if ((bits & 0x7f800000) == 0x7f800000) {
            bits &= 0xff800000;
        }

        gen->buf[gen->len++] = 0xca;
        gen->len += raw_put_be(gen->buf + gen->len, bits, 4);
    }
    else if (type < 35) {
        /* float 64, no NaN */
        bits = raw_gen_rand(gen);

        if ((bits & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL) {
            bits &= 0xfff0000000000000ULL;
        }

        gen->buf[gen->len++] = 0xcb;
        gen->len += raw_put_be(gen->buf + gen->len, bits, 8);
    }
    else if (type < 65) {
        /* str, bin and ext */
        count = raw_gen_pick(gen, 40);

        if (raw_gen_pick(gen, 10) == 0) {
            count = 250 + raw_gen_pick(gen, 12);
        }
        else if (raw_gen_pick(gen, 400) == 0) {
            count = 65530 + raw_gen_pick(gen, 12);
        }

        raw_gen_header(gen, (type - 35) / 10, count);

        for (i = 0; i < count; i++) {
            gen->buf[gen->len++] = (unsigned char) raw_gen_rand(gen);
        }
    }
    else if (type < 90 && depth < max_depth) {
        /* array and map */
        count = raw_gen_pick(gen, 5);

        if (raw_gen_pick(gen, 30) == 0) {
            count = 14 + raw_gen_pick(gen, 5);
        }

        if (count == 0 && spine) {
            count = 1;
        }

        raw_gen_header(gen, type < 77 ? 3 : 4, count);

        if (type >= 77) {
            count *= 2;
        }

        for (i = 0; i < count; i++) {
            raw_gen_value(gen, depth + 1, max_depth);
        }
    }
    else {
        count = raw_gen_pick(gen, 3);
        gen->buf[gen->len++] = count == 0 ? 0xc0 : count == 1 ? 0xc2 : 0xc3;
    }
}

#ifndef FLB_TEST_MP_RAW_ROUNDS
#define FLB_TEST_MP_RAW_ROUNDS 20000
#endif

/*
 * Random documents in every format, minimal or not, and random damage to
 * them: the walker must give the answer of the reference implementations.
 */
static void test_raw_skip_random(void)
{
    int i;
    int j;
    int ret;
    int ok;
    int max_depth;
    int deep;
    int minimal;
    int accepted = 0;
    int rejected = 0;
    int minimal_count = 0;
    size_t size;
    size_t pos;
    unsigned char saved;
    const unsigned char *p;
    struct raw_gen gen;
    struct raw_reference ref;

    gen.state = 0x9e3779b97f4a7c15ULL;
    gen.cap = 4 * 1024 * 1024;
    gen.buf = flb_malloc(gen.cap);
    TEST_CHECK(gen.buf != NULL);

    if (gen.buf == NULL) {
        return;
    }

    for (i = 0; i < FLB_TEST_MP_RAW_ROUNDS; i++) {
        gen.len = 0;
        gen.nodes = 0;
        max_depth = 1 + raw_gen_pick(&gen, 12);
        gen.spine = 0;
        gen.spine_reached = 0;

        /*
         * Some documents are deeper than the levels tracked by the walker
         * and than the limit of msgpack-c: mpack is the only reference.
         */
        deep = raw_gen_pick(&gen, 40) == 0;

        if (deep) {
            gen.spine = 40 + raw_gen_pick(&gen, 100);
            max_depth = gen.spine + raw_gen_pick(&gen, 4);
        }

        raw_gen_value(&gen, 0, max_depth);
        size = gen.len;

        /* valid document: same size everywhere */
        raw_reference_run(gen.buf, size, !deep, &ref);
        ok = ref.mpack_ok == FLB_TRUE && ref.mpack_size == size;
        TEST_CHECK(ok);

        if (!deep) {
            ok = ref.msgpack_ok == FLB_TRUE && ref.msgpack_size == size;
            TEST_CHECK(ok);
        }

        p = gen.buf;
        ret = flb_mp_raw_skip(&p, gen.buf + size, 0);
        ok = ret == 0 && p == gen.buf + size;
        TEST_CHECK(ok);

        if (!ok) {
            TEST_MSG("round %d size %zu ret %d", i, size, ret);
            break;
        }

        /* the depth limit is exact up to the levels that are tracked */
        p = gen.buf;
        ret = flb_mp_raw_skip(&p, gen.buf + size, max_depth + 1);

        if (max_depth + 1 <= FLB_MP_RAW_MAX_DEPTH) {
            TEST_CHECK(ret == 0 && p == gen.buf + size);
        }
        else if (gen.spine + 1 > FLB_MP_RAW_MAX_DEPTH) {
            TEST_CHECK(ret == -1 && p == gen.buf);
        }

        if (deep) {
            p = gen.buf;
            ret = flb_mp_raw_skip(&p, gen.buf + size, gen.spine);
            TEST_CHECK(ret == -1 && p == gen.buf);
        }

        /* minimal: the answer is 'packing it again gives the same bytes' */
        p = gen.buf;
        minimal = flb_mp_raw_skip_minimal(&p, gen.buf + size, 0) == 0;
        ok = deep || minimal == ref.repack_equal;
        TEST_CHECK(ok);

        if (!ok) {
            TEST_MSG("round %d size %zu minimal %d repack %d",
                     i, size, minimal, ref.repack_equal);
            break;
        }

        minimal_count += minimal;

        /* damage: one byte changed, or the end removed */
        for (j = 0; j < 8; j++) {
            pos = raw_gen_pick(&gen, (uint32_t) size);
            saved = gen.buf[pos];

            if (j < 6) {
                gen.buf[pos] = (unsigned char) raw_gen_rand(&gen);
                raw_reference_run(gen.buf, size, FLB_FALSE, &ref);
                p = gen.buf;
                ret = flb_mp_raw_skip(&p, gen.buf + size, 0);
            }
            else {
                raw_reference_run(gen.buf, pos, FLB_FALSE, &ref);
                p = gen.buf;
                ret = flb_mp_raw_skip(&p, gen.buf + pos, 0);
            }

            if (ret == 0) {
                accepted++;
                ok = ref.mpack_ok == FLB_TRUE &&
                     (size_t) (p - gen.buf) == ref.mpack_size;
            }
            else {
                rejected++;
                ok = ref.mpack_ok == FLB_FALSE && p == gen.buf;
            }

            TEST_CHECK(ok);

            if (!ok) {
                TEST_MSG("round %d damage %d pos %zu ret %d mpack %d",
                         i, j, pos, ret, ref.mpack_ok);
            }

            /* what the walker accepts, msgpack-c decodes to the same size */
            if (ret == 0 && !deep) {
                size = (size_t) (p - gen.buf);
                raw_reference_run(gen.buf, size, FLB_TRUE, &ref);
                ok = ref.msgpack_ok == FLB_TRUE && ref.msgpack_size == size;
                TEST_CHECK(ok);

                p = gen.buf;
                minimal = flb_mp_raw_skip_minimal(&p, gen.buf + size, 0) == 0;

                if (minimal) {
                    TEST_CHECK(ref.repack_equal == FLB_TRUE);
                }

                size = gen.len;
            }

            gen.buf[pos] = saved;
        }
    }

    /* the three outcomes must be exercised */
    TEST_CHECK(accepted > 0 && rejected > 0);
    TEST_CHECK(minimal_count > 0 && minimal_count < FLB_TEST_MP_RAW_ROUNDS);
    TEST_MSG("accepted %d rejected %d minimal %d",
             accepted, rejected, minimal_count);

    flb_free(gen.buf);
}

/* the scan reports records and group markers for both event layouts */
static void test_log_scan_events_group_markers(void)
{
    struct flb_log_event_encoder *encoder;
    struct flb_time timestamp;
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    int ret;
    int count;
    int markers;
    int record;

    count = -1;
    markers = -1;
    TEST_CHECK(flb_mp_scan_log_events(NULL, 0, &count, &markers) == 0);
    TEST_CHECK(count == 0 && markers == 0);

    /* layout generated by the encoder: plain records, then two groups */
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);

    for (record = 0; record < 6; record++) {
        if (record == 2 || record == 4) {
            TEST_CHECK(flb_mp_scan_log_events(encoder->output_buffer,
                                              encoder->output_length,
                                              &count, &markers) == 0);
            TEST_CHECK(count == record && markers == (record - 2));

            TEST_ASSERT(flb_log_event_encoder_group_init(encoder) == 0);
            TEST_ASSERT(flb_log_event_encoder_group_header_end(encoder) == 0);
        }

        TEST_ASSERT(flb_log_event_encoder_begin_record(encoder) == 0);
        flb_time_set(&timestamp, 1700000000 + record, record);
        TEST_ASSERT(flb_log_event_encoder_set_timestamp(encoder, &timestamp) == 0);
        ret = flb_log_event_encoder_append_body_values(encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("key"), FLB_LOG_EVENT_CSTRING_VALUE("value"));
        TEST_ASSERT(ret == 0);
        TEST_ASSERT(flb_log_event_encoder_commit_record(encoder) == 0);

        if (record == 3 || record == 5) {
            TEST_ASSERT(flb_log_event_encoder_group_end(encoder) == 0);
        }
    }

    TEST_CHECK(flb_mp_scan_log_events(encoder->output_buffer, encoder->output_length,
                                      &count, &markers) == 0);
    TEST_CHECK(count == 6 && markers == 4);
    TEST_CHECK(flb_mp_scan_log_events(encoder->output_buffer, encoder->output_length,
                                      &count, NULL) == 0);
    TEST_CHECK(count == 6);
    TEST_CHECK(flb_mp_count_log_records(encoder->output_buffer,
                                        encoder->output_length) == 6);
    flb_log_event_encoder_destroy(encoder);

    /* legacy [timestamp, body] events are left to the generic scan */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    for (record = 0; record < 3; record++) {
        msgpack_pack_array(&pck, 2);
        msgpack_pack_uint64(&pck, 1700000000 + record);
        msgpack_pack_map(&pck, 1);
        msgpack_pack_str_with_body(&pck, "key", 3);
        msgpack_pack_str_with_body(&pck, "value", 5);
    }

    count = -1;
    markers = -1;
    TEST_CHECK(flb_mp_scan_log_events(sbuf.data, sbuf.size, &count, &markers) == 0);
    TEST_CHECK(count == 3 && markers == 0);

    /* an event that is not a log record is rejected by both scans */
    msgpack_pack_array(&pck, 3);
    msgpack_pack_nil(&pck);
    msgpack_pack_nil(&pck);
    msgpack_pack_nil(&pck);
    TEST_CHECK(flb_mp_scan_log_events(sbuf.data, sbuf.size, &count, &markers) == -1);
    msgpack_sbuffer_destroy(&sbuf);
}

/* a processor that drops every record leaves an empty, NULL buffer */
static void test_log_helpers_accept_empty_buffers(void)
{
    int count;
    int records;
    char *out_buf;
    size_t out_size;
    size_t window_end;

    count = -1;
    TEST_CHECK(flb_mp_scan_log_records(NULL, 0, &count) == 0 && count == 0);
    TEST_CHECK(flb_mp_scan_log_records(NULL, 1, &count) == -1);
    TEST_CHECK(flb_mp_count_log_records(NULL, 0) == 0);
    TEST_CHECK(flb_mp_log_group_boundaries(NULL, 0) == 0);
    TEST_CHECK(flb_mp_log_group_starts(NULL, 0) == 0);
    TEST_CHECK(flb_mp_log_window_next(NULL, 0, 0, 65536, 1024,
                                      &window_end, &records) == -1);

    out_buf = (char *) 1;
    out_size = 1;
    TEST_CHECK(flb_mp_normalize_log_buffer_groups_msgpack_ex(NULL, 0, &out_buf, &out_size,
                                                             FLB_MP_GROUPS_KEEP_LEADING_END |
                                                             FLB_MP_GROUPS_KEEP_TRAILING_OPEN) == 0);
    TEST_CHECK(out_buf == NULL && out_size == 0);
}

static void test_log_scan_matches_decoder(void)
{
    struct flb_log_event_encoder *encoder;
    struct flb_time timestamp;
    size_t length;
    size_t index;
    int ret;
    int count;
    int record;
    char saved;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    for (record = 0; record < 4; record++) {
        if (record == 1) {
            TEST_ASSERT(flb_log_event_encoder_group_init(encoder) == 0);
            TEST_ASSERT(flb_log_event_encoder_group_header_end(encoder) == 0);
        }
        TEST_ASSERT(flb_log_event_encoder_begin_record(encoder) == 0);
        flb_time_set(&timestamp, 1700000000 + record, record);
        TEST_ASSERT(flb_log_event_encoder_set_timestamp(encoder, &timestamp) == 0);
        ret = flb_log_event_encoder_append_body_values(encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("key"), FLB_LOG_EVENT_CSTRING_VALUE("value"));
        TEST_ASSERT(ret == 0);
        TEST_ASSERT(flb_log_event_encoder_commit_record(encoder) == 0);
        if (record == 2) {
            TEST_ASSERT(flb_log_event_encoder_group_end(encoder) == 0);
        }
    }
    TEST_CHECK(flb_mp_scan_log_records(encoder->output_buffer, encoder->output_length,
                                      &count) == 0);
    TEST_CHECK(count == 4);
    for (length = 0; length <= encoder->output_length; length++) {
        TEST_CHECK(flb_mp_count_log_records(encoder->output_buffer, length) ==
                   reference_log_count(encoder->output_buffer, length));
    }
    for (index = 0; index < encoder->output_length; index++) {
        saved = encoder->output_buffer[index];
        encoder->output_buffer[index] = (char) 0xc1;
        TEST_CHECK(flb_mp_count_log_records(encoder->output_buffer, encoder->output_length) ==
                   reference_log_count(encoder->output_buffer, encoder->output_length));
        encoder->output_buffer[index] = saved;

        /*
         * Leave the counts of 16 and 32 bit array and map headers intact: a
         * corrupted count makes the msgpack-c fallback request gigabytes.
         */
        if ((unsigned char) saved == 0xdc || (unsigned char) saved == 0xde) {
            index += 2;
        }
        else if ((unsigned char) saved == 0xdd || (unsigned char) saved == 0xdf) {
            index += 4;
        }
    }
    flb_log_event_encoder_destroy(encoder);
}

static void append_window_test_record(struct flb_log_event_encoder *encoder, int seq)
{
    int ret;
    struct flb_time timestamp;

    TEST_ASSERT(flb_log_event_encoder_begin_record(encoder) == 0);
    flb_time_set(&timestamp, 1700000000 + seq, 0);
    TEST_ASSERT(flb_log_event_encoder_set_timestamp(encoder, &timestamp) == 0);
    ret = flb_log_event_encoder_append_body_values(encoder,
        FLB_LOG_EVENT_CSTRING_VALUE("seq"), FLB_LOG_EVENT_INT64_VALUE(seq));
    TEST_ASSERT(ret == 0);
    TEST_ASSERT(flb_log_event_encoder_commit_record(encoder) == 0);
}

static void test_log_window_next(void)
{
    struct flb_log_event_encoder *encoder;
    size_t offset;
    size_t end;
    size_t group_start;
    size_t group_end;
    int records;
    int total;
    int windows;
    int seq;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);

    /* 10 plain records, a group of 6 records, 4 plain records */
    for (seq = 0; seq < 10; seq++) {
        append_window_test_record(encoder, seq);
    }
    group_start = encoder->output_length;
    TEST_ASSERT(flb_log_event_encoder_group_init(encoder) == 0);
    TEST_ASSERT(flb_log_event_encoder_group_header_end(encoder) == 0);
    for (; seq < 16; seq++) {
        append_window_test_record(encoder, seq);
    }
    TEST_ASSERT(flb_log_event_encoder_group_end(encoder) == 0);
    group_end = encoder->output_length;
    for (; seq < 20; seq++) {
        append_window_test_record(encoder, seq);
    }

    /* record limited windows cover the buffer without splitting the group */
    offset = 0;
    total = 0;
    windows = 0;
    while (offset < encoder->output_length) {
        TEST_ASSERT(flb_mp_log_window_next(encoder->output_buffer,
                                           encoder->output_length, offset,
                                           SIZE_MAX, 4, &end, &records) == 0);
        TEST_CHECK(end > offset && end <= encoder->output_length);
        TEST_CHECK(!(offset < group_start && end > group_start && end < group_end));
        TEST_CHECK(!(offset > group_start && offset < group_end));
        TEST_CHECK(flb_mp_count_log_records(encoder->output_buffer + offset,
                                            end - offset) == records);
        if (end <= group_start || offset >= group_end) {
            TEST_CHECK(records <= 4);
        }
        total += records;
        windows++;
        offset = end;
    }
    TEST_CHECK(offset == encoder->output_length);
    TEST_CHECK(total == 20);
    /* 4 + 4 + (2 plain and the whole group of 6) + 4 */
    TEST_CHECK(windows == 4);

    /* a byte limit of one closes after every event outside the group */
    TEST_ASSERT(flb_mp_log_window_next(encoder->output_buffer, encoder->output_length,
                                       0, 1, INT_MAX, &end, &records) == 0);
    TEST_CHECK(records == 1);
    TEST_ASSERT(flb_mp_log_window_next(encoder->output_buffer, encoder->output_length,
                                       group_start, 1, INT_MAX, &end, &records) == 0);
    TEST_CHECK(end == group_end && records == 6);
    TEST_CHECK(flb_mp_log_group_starts(encoder->output_buffer + group_start,
                                       group_end - group_start) == 1);

    /* a single window for the whole buffer */
    TEST_ASSERT(flb_mp_log_window_next(encoder->output_buffer, encoder->output_length,
                                       0, SIZE_MAX, INT_MAX, &end, &records) == 0);
    TEST_CHECK(end == encoder->output_length && records == 20);

    /* invalid input and offsets */
    TEST_CHECK(flb_mp_log_window_next(encoder->output_buffer, encoder->output_length,
                                      encoder->output_length, 1, 1, &end, &records) == -1);
    TEST_CHECK(flb_mp_log_window_next(NULL, 10, 0, 1, 1, &end, &records) == -1);
    TEST_CHECK(flb_mp_log_window_next(encoder->output_buffer, encoder->output_length - 1,
                                      0, SIZE_MAX, INT_MAX, &end, &records) == -1);
    TEST_CHECK(flb_mp_log_window_next("\x92\x01", 2, 0, 1, 1, &end, &records) == -1);

    flb_log_event_encoder_destroy(encoder);

    /* a full window keeps a following end marker instead of starting with it */
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    for (seq = 0; seq < 4; seq++) {
        append_window_test_record(encoder, seq);
    }
    TEST_ASSERT(flb_log_event_encoder_group_end(encoder) == 0);
    group_end = encoder->output_length;
    TEST_ASSERT(flb_log_event_encoder_group_init(encoder) == 0);
    TEST_ASSERT(flb_log_event_encoder_group_header_end(encoder) == 0);
    append_window_test_record(encoder, seq);
    TEST_ASSERT(flb_log_event_encoder_group_end(encoder) == 0);

    TEST_ASSERT(flb_mp_log_window_next(encoder->output_buffer, encoder->output_length,
                                       0, SIZE_MAX, 4, &end, &records) == 0);
    TEST_CHECK(end == group_end && records == 4);
    TEST_ASSERT(flb_mp_log_window_next(encoder->output_buffer, encoder->output_length,
                                       end, SIZE_MAX, 4, &end, &records) == 0);
    TEST_CHECK(end == encoder->output_length && records == 1);

    flb_log_event_encoder_destroy(encoder);
}

/* layout tokens: r<n> record, S group start, E group end */
static void encode_group_layout(struct flb_log_event_encoder *encoder, const char *layout)
{
    int length;
    char token[16];
    const char *cursor;

    for (cursor = layout; sscanf(cursor, "%15s%n", token, &length) == 1; cursor += length) {
        if (token[0] == 'r') {
            append_window_test_record(encoder, atoi(token + 1));
        }
        else if (token[0] == 'S') {
            TEST_CHECK(flb_log_event_encoder_group_init(encoder) == 0);
            TEST_CHECK(flb_log_event_encoder_group_header_end(encoder) == 0);
        }
        else {
            TEST_CHECK(flb_log_event_encoder_group_end(encoder) == 0);
        }
    }
}

static void describe_group_layout(char *buf, size_t size, char *out, size_t out_size)
{
    int type;
    char token[16];
    msgpack_object *seq;
    struct flb_log_event event;
    struct flb_log_event_decoder decoder;

    out[0] = '\0';
    if (buf == NULL || size == 0) {
        return;
    }

    TEST_ASSERT(flb_log_event_decoder_init(&decoder, buf, size) == 0);
    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);
    while (flb_log_event_decoder_next(&decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {
        TEST_ASSERT(flb_log_event_decoder_get_record_type(&event, &type) == 0);
        if (type == FLB_LOG_EVENT_GROUP_START) {
            snprintf(token, sizeof(token), "S ");
        }
        else if (type == FLB_LOG_EVENT_GROUP_END) {
            snprintf(token, sizeof(token), "E ");
        }
        else {
            seq = &event.body->via.map.ptr[0].val;
            snprintf(token, sizeof(token), "r%d ", (int) seq->via.i64);
        }
        strncat(out, token, out_size - strlen(out) - 1);
    }
    flb_log_event_decoder_destroy(&decoder);
    if (strlen(out) > 0) {
        out[strlen(out) - 1] = '\0';
    }
}

static void check_normalized_layout(char *output, size_t output_size,
                                    const char *layout, const char *expected,
                                    const char *mode)
{
    char result[128];

    describe_group_layout(output, output ? output_size : 0, result, sizeof(result));
    TEST_CHECK(strcmp(result, expected) == 0);
    TEST_MSG("%s: '%s' produced '%s', expected '%s'", mode, layout, result, expected);
}

/*
 * 'strict' is the default normalization. 'kept' keeps the boundary markers
 * the input already had, as processor chains do for groups split across
 * appends.
 */
static void check_group_normalization(const char *layout, const char *strict,
                                      const char *kept)
{
    struct flb_log_event_encoder *encoder;
    struct flb_log_event_encoder *copy;
    struct flb_mp_chunk_cobj *chunk;
    struct flb_log_event_decoder *decoder;
    struct flb_mp_chunk_record *record;
    char *output;
    size_t output_size;
    int flags;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    encode_group_layout(encoder, layout);
    flags = flb_mp_log_group_boundaries(encoder->output_buffer, encoder->output_length);

    output = NULL;
    TEST_CHECK(flb_mp_normalize_log_buffer_groups_msgpack(encoder->output_buffer,
                                                          encoder->output_length,
                                                          &output, &output_size) == 0);
    check_normalized_layout(output, output_size, layout, strict, "msgpack strict");
    flb_free(output);

    output = NULL;
    TEST_CHECK(flb_mp_normalize_log_buffer_groups(encoder->output_buffer,
                                                  encoder->output_length,
                                                  &output, &output_size) == 0);
    check_normalized_layout(output, output_size, layout, strict, "chunk strict");
    flb_free(output);

    output = NULL;
    TEST_CHECK(flb_mp_normalize_log_buffer_groups_msgpack_ex(encoder->output_buffer,
                                                             encoder->output_length,
                                                             &output, &output_size,
                                                             flags) == 0);
    check_normalized_layout(output, output_size, layout, kept, "msgpack kept");
    flb_free(output);

    /* the chunk normalizer with the same flags */
    decoder = flb_log_event_decoder_create(encoder->output_buffer, encoder->output_length);
    TEST_ASSERT(decoder != NULL);
    flb_log_event_decoder_read_groups(decoder, FLB_TRUE);
    copy = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(copy != NULL);
    chunk = flb_mp_chunk_cobj_create(copy, decoder);
    TEST_ASSERT(chunk != NULL);
    while (flb_mp_chunk_cobj_record_next(chunk, &record) == FLB_MP_CHUNK_RECORD_OK) {
    }
    TEST_CHECK(flb_mp_chunk_cobj_normalize_groups_ex(chunk, flags) == 0);
    output = NULL;
    output_size = 0;
    if (cfl_list_size(&chunk->records) > 0) {
        TEST_CHECK(flb_mp_chunk_cobj_encode(chunk, &output, &output_size) == 0);
    }
    check_normalized_layout(output, output_size, layout, kept, "chunk kept");
    flb_free(output);
    flb_mp_chunk_cobj_destroy(chunk);
    flb_log_event_encoder_destroy(copy);
    flb_log_event_decoder_destroy(decoder);

    flb_log_event_encoder_destroy(encoder);
}

static void test_group_normalization_keeps_append_boundaries(void)
{
    /* a group continued in the next append keeps its start when kept */
    check_group_normalization("S r0 r1", "r0 r1", "S r0 r1");
    check_group_normalization("S", "", "S");
    /* records closing a group opened by a previous append keep their end */
    check_group_normalization("r0 r1 E", "r0 r1", "r0 r1 E");
    check_group_normalization("r0 E S r1 E S r2", "r0 S r1 E r2", "r0 E S r1 E S r2");
    /* other stray ends, empty groups and nested open groups are always removed */
    check_group_normalization("r0 E E S r1 E E r2", "r0 S r1 E r2", "r0 E S r1 E r2");
    check_group_normalization("S E r0", "r0", "r0");
    check_group_normalization("S S r0", "r0", "r0");
    check_group_normalization("S r0 E S E r1", "S r0 E r1", "S r0 E r1");
    check_group_normalization("S r0 E r1", "S r0 E r1", "S r0 E r1");
}

static void test_group_boundaries_follow_the_input(void)
{
    struct flb_log_event_encoder *encoder;
    int flags;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    encode_group_layout(encoder, "r0 E S r1 E S r2");
    flags = flb_mp_log_group_boundaries(encoder->output_buffer, encoder->output_length);
    TEST_CHECK(flags == (FLB_MP_GROUPS_KEEP_LEADING_END | FLB_MP_GROUPS_KEEP_TRAILING_OPEN));
    flb_log_event_encoder_destroy(encoder);

    /* a balanced input keeps nothing, whatever a processor removes later */
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    encode_group_layout(encoder, "S r0 E r1");
    TEST_CHECK(flb_mp_log_group_boundaries(encoder->output_buffer, encoder->output_length) == 0);
    flb_log_event_encoder_destroy(encoder);

    /* nested open groups are not a single continued group */
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    encode_group_layout(encoder, "S S r0");
    TEST_CHECK(flb_mp_log_group_boundaries(encoder->output_buffer, encoder->output_length) == 0);
    flb_log_event_encoder_destroy(encoder);

    TEST_CHECK(flb_mp_log_group_boundaries(NULL, 0) == 0);
    TEST_CHECK(flb_mp_log_group_boundaries("\x92\x01", 2) == 0);
}

TEST_LIST = {
    {"log_helpers_accept_empty_buffers", test_log_helpers_accept_empty_buffers},
    {"log_scan_matches_decoder", test_log_scan_matches_decoder},
    {"log_scan_events_group_markers", test_log_scan_events_group_markers},
    {"raw_skip", test_raw_skip},
    {"raw_skip_formats", test_raw_skip_formats},
    {"raw_skip_lengths", test_raw_skip_lengths},
    {"raw_skip_numbers", test_raw_skip_numbers},
    {"raw_skip_depth", test_raw_skip_depth},
    {"raw_skip_random", test_raw_skip_random},
    {"log_window_next", test_log_window_next},
    {"group_normalization_append_boundaries", test_group_normalization_keeps_append_boundaries},
    {"group_boundaries_follow_the_input", test_group_boundaries_follow_the_input},
    {"preflight", test_preflight},
    {"preflight_formats", test_preflight_formats},
    {"validate_trace_chunk" , test_validate_trace_chunk},
    {"count"                , test_count},
    {"map_header"           , test_map_header},
    {"accessor_keys_remove" , test_accessor_keys_remove},
    {"accessor_keys_remove_subkey_key" , test_keys_remove_subkey_key},
    {"accessor_keys_remove_subkey_keys" , test_keys_remove_subkey_keys},
    {"object_to_cfl_to_msgpack" , test_object_to_cfl_to_msgpack},
    {"test_remove_sibling_subkeys" , test_remove_sibling_subkeys},
    { 0 }
};
