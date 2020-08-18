/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_avro.h>

#include "flb_tests_internal.h"

/* AVRO iteration tests */
#define AVRO_SINGLE_MAP1 FLB_TESTS_DATA_PATH "/data/pack/json_single_map_001.json"

const char  JSON_SINGLE_MAP_001_SCHEMA[] =
"{\"type\":\"record\",\
  \"name\":\"Map001\",\
  \"fields\":[\
     {\"name\": \"key001\", \"type\": \"int\"},\
     {\"name\": \"key002\", \"type\": \"float\"},\
     {\"name\": \"key003\", \"type\": \"string\"},\
     {\"name\": \"key004\", \"type\":\
        {\"type\": \"array\", \"items\":\
             {\"type\": \"map\",\"values\": \"int\"}}}]}";

/* Unpack msgpack per avro schema */
void test_unpack_to_avro()
{
    // int root_type;
    // size_t len;
    // char *data;
    // char *out_buf;
    // size_t out_size;

    // avro_value_t  aobject;

    // AVRO_POOL *ppp = avro_pool_create(1024 * 1024);

    // avro_set_allocator(flb_avro_allocatorqqq, (void *)ppp);
    // avro_value_iface_t  *aclass = NULL;
    // avro_schema_t aschema;

    // aclass = flb_avro_init(&aobject, (char *)JSON_SINGLE_MAP_001_SCHEMA, strlen(JSON_SINGLE_MAP_001_SCHEMA), &aschema);

    // data = mk_file_to_buffer(AVRO_SINGLE_MAP1);
    // TEST_CHECK(data != NULL);

    // len = strlen(data);

    // TEST_CHECK(flb_pack_json(data, len, &out_buf, &out_size, &root_type) == 0);

    // msgpack_unpacked msg;
    // msgpack_unpacked_init(&msg);
    // TEST_CHECK(msgpack_unpack_next(&msg, out_buf, out_size, NULL) == MSGPACK_UNPACK_SUCCESS);

    // msgpack_object_print(stderr, msg.data);
    // flb_msgpack_to_avro(&aobject, &msg.data);

    // avro_value_t test_value;
    // TEST_CHECK(avro_value_get_by_name(&aobject, "key001", &test_value, NULL) == 0);

    // int val001 = 0;
    // avro_value_get_int(&test_value, &val001);
    // TEST_CHECK(val001 == 123456789);

    // TEST_CHECK(avro_value_get_by_name(&aobject, "key002", &test_value, NULL) == 0);

    // float val002 = 0.0f;
    // // for some reason its rounding to this value
    // float val002_actual = 0.999888f;
    // avro_value_get_float(&test_value, &val002);
    // char str1[80];
    // char str2[80];
    // sprintf(str1, "%f", val002);
    // sprintf(str2, "%f", val002_actual);
    // fprintf(stderr, "val002:%s:\n", str1);
    // fprintf(stderr, "val002_actual:%s:\n", str2);
    // TEST_CHECK((strcmp(str1, str2) == 0));

    // TEST_CHECK(avro_value_get_by_name(&aobject, "key003", &test_value, NULL) == 0);
    // char *val003 = NULL;
    // size_t val003_size = 0;
    // avro_value_get_string(&test_value, &val003, &val003_size);
    // fprintf(stderr, "val003_size:%zu:\n", val003_size);

    // TEST_CHECK((strcmp(val003, "abcdefghijk") == 0));
    // TEST_CHECK(val003_size == 12);

    // TEST_CHECK(avro_value_get_by_name(&aobject, "key004", &test_value, NULL) == 0);

    // size_t asize = 0;
    // avro_value_get_size(&test_value, &asize);
    // fprintf(stderr, "asize:%zu:\n", asize);

    // TEST_CHECK(asize == 2);

    // // check the first map
    // avro_value_t mapX;
    // TEST_CHECK(avro_value_get_by_index(&test_value, 0, &mapX, NULL) == 0);

    // size_t msize = 0;
    // avro_value_get_size(&mapX, &msize);
    // fprintf(stderr, "msize:%zu:\n", msize);

    // TEST_CHECK(msize == 2);

    // avro_value_t obj_test;
    // const char  *actual_key = NULL;
    // int  actual = 0;

    // // check the first item in the map
    // TEST_CHECK(avro_value_get_by_index(&mapX, 0, &obj_test, &actual_key) == 0);
    // TEST_CHECK(strcmp(actual_key, "a") == 0);
    // TEST_CHECK(avro_value_get_int(&obj_test, &actual) == 0);
    // TEST_CHECK(actual == 1);

    // // check the second item in the map
    // TEST_CHECK(avro_value_get_by_index(&mapX, 1, &obj_test, &actual_key) == 0);
    // TEST_CHECK(strcmp(actual_key, "b") == 0);
    // TEST_CHECK(avro_value_get_int(&obj_test, &actual) == 0);
    // TEST_CHECK(actual == 2);

    // // check the second map
    // TEST_CHECK(avro_value_get_by_index(&test_value, 1, &mapX, NULL) == 0);

    // avro_value_get_size(&mapX, &msize);
    // fprintf(stderr, "msize:%zu:\n", msize);

    // TEST_CHECK(msize == 2);

    // avro_pool_destroy(ppp);
    // msgpack_unpacked_destroy(&msg);
    // // flb_free(aclass);
    // flb_free(data);
    // flb_free(out_buf);
}

TEST_LIST = {
    /* Avro */
    { "msgpack_to_avro", test_unpack_to_avro},
    { 0 }
};
