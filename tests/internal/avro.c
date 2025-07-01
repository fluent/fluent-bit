/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <errno.h>
#include <string.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_avro.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include "flb_tests_internal.h"

/* AVRO iteration tests */
#define AVRO_SINGLE_MAP1 FLB_TESTS_DATA_PATH "/data/avro/json_single_map_001.json"
#define AVRO_MULTILINE_JSON FLB_TESTS_DATA_PATH "/data/avro/live-sample.json"

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

msgpack_unpacked test_init(avro_value_t *aobject, avro_schema_t *aschema, const char *json_schema, const char *json_data) {
    char *out_buf;
    size_t out_size;
    int root_type;

    avro_value_iface_t  *aclass = flb_avro_init(aobject, (char *)json_schema, strlen(json_schema), aschema);
    TEST_CHECK(aclass != NULL);

    char *data = mk_file_to_buffer(json_data);
    TEST_CHECK(data != NULL);

    size_t len = strlen(data);

    TEST_CHECK(flb_pack_json(data, len, &out_buf, &out_size, &root_type, NULL) == 0);

    msgpack_unpacked msg;
    msgpack_unpacked_init(&msg);
    TEST_CHECK(msgpack_unpack_next(&msg, out_buf, out_size, NULL) == MSGPACK_UNPACK_SUCCESS);

    avro_value_iface_decref(aclass);
    flb_free(data);
    flb_free(out_buf);

    return msg;
}
/* Unpack msgpack per avro schema */
void test_unpack_to_avro()
{
    avro_value_t  aobject;
    avro_schema_t aschema;

    msgpack_unpacked mp = test_init(&aobject, &aschema, JSON_SINGLE_MAP_001_SCHEMA, AVRO_SINGLE_MAP1);

    msgpack_object_print(stderr, mp.data);
    flb_msgpack_to_avro(&aobject, &mp.data);

    avro_value_t test_value;
    TEST_CHECK(avro_value_get_by_name(&aobject, "key001", &test_value, NULL) == 0);

    int val001 = 0;
    avro_value_get_int(&test_value, &val001);
    TEST_CHECK(val001 == 123456789);

    TEST_CHECK(avro_value_get_by_name(&aobject, "key002", &test_value, NULL) == 0);

    float val002 = 0.0f;
    // for some reason its rounding to this value
    float val002_actual = 0.999888f;
    avro_value_get_float(&test_value, &val002);
    char str1[80];
    char str2[80];
    sprintf(str1, "%f", val002);
    sprintf(str2, "%f", val002_actual);
    flb_info("val002:%s:\n", str1);
    flb_info("val002_actual:%s:\n", str2);
    TEST_CHECK((strcmp(str1, str2) == 0));

    TEST_CHECK(avro_value_get_by_name(&aobject, "key003", &test_value, NULL) == 0);
    const char *val003 = NULL;
    size_t val003_size = 0;
    avro_value_get_string(&test_value, &val003, &val003_size);
    flb_info("val003_size:%zu:\n", val003_size);
    TEST_CHECK(val003[val003_size] == '\0');

    TEST_CHECK((strcmp(val003, "abcdefghijk") == 0));
    // avro_value_get_by_name returns ths string length plus the NUL
    TEST_CHECK(val003_size == 12);

    TEST_CHECK(avro_value_get_by_name(&aobject, "key004", &test_value, NULL) == 0);

    size_t asize = 0;
    avro_value_get_size(&test_value, &asize);
    flb_info("asize:%zu:\n", asize);

    TEST_CHECK(asize == 2);

    // check the first map
    avro_value_t k8sRecord;
    TEST_CHECK(avro_value_get_by_index(&test_value, 0, &k8sRecord, NULL) == 0);

    size_t msize = 0;
    avro_value_get_size(&k8sRecord, &msize);
    flb_info("msize:%zu:\n", msize);

    TEST_CHECK(msize == 2);

    avro_value_t obj_test;
    const char  *actual_key = NULL;
    int  actual = 0;

    // check the first item in the map
    TEST_CHECK(avro_value_get_by_index(&k8sRecord, 0, &obj_test, &actual_key) == 0);
    flb_info("actual_key:%s:\n", actual_key);

    TEST_CHECK(strcmp(actual_key, "a") == 0);
    TEST_CHECK(avro_value_get_int(&obj_test, &actual) == 0);
    TEST_CHECK(actual == 1);

    // check the second item in the map
    TEST_CHECK(avro_value_get_by_index(&k8sRecord, 1, &obj_test, &actual_key) == 0);
    flb_info("actual_key:%s:\n", actual_key);

    TEST_CHECK(strcmp(actual_key, "b") == 0);
    TEST_CHECK(avro_value_get_int(&obj_test, &actual) == 0);
    TEST_CHECK(actual == 2);

    // check the second map
    TEST_CHECK(avro_value_get_by_index(&test_value, 1, &k8sRecord, NULL) == 0);

    avro_value_get_size(&k8sRecord, &msize);
    flb_info("msize:%zu:\n", msize);

    TEST_CHECK(msize == 2);

    avro_value_decref(&aobject);
    avro_schema_decref(aschema);
    msgpack_unpacked_destroy(&mp);
}

void test_parse_reordered_schema()
{
    // test same schema but different order of fields
    const char *ts1 = "{\"name\":\"qavrov2_record\",\"type\":\"record\",\"fields\":[{\"name\":\"log\",\"type\":\"string\"},{\"name\":\"capture\",\"type\":\"string\"},{\"name\":\"kubernetes\",\"type\":{\"name\":\"krec\",\"type\":\"record\",\"fields\":[{\"name\":\"pod_name\",\"type\":\"string\"},{\"name\":\"namespace_name\",\"type\":\"string\"},{\"name\":\"pod_id\",\"type\":\"string\"},{\"name\":\"labels\",\"type\":{\"type\":\"map\",\"values\":\"string\"}},{\"name\":\"annotations\",\"type\":{\"type\":\"map\",\"values\":\"string\"}},{\"name\":\"host\",\"type\":\"string\"},{\"name\":\"container_name\",\"type\":\"string\"},{\"name\":\"container_id\",\"type\":\"string\"},{\"name\":\"container_hash\",\"type\":\"string\"},{\"name\":\"container_image\",\"type\":\"string\"}]}}]}";
    const char *ts2 = "{\"name\":\"qavrov2_record\",\"type\":\"record\",\"fields\":[{\"name\":\"capture\",\"type\":\"string\"},{\"name\":\"log\",\"type\":\"string\"},{\"name\":\"kubernetes\",\"type\":{\"name\":\"krec\",\"type\":\"record\",\"fields\":[{\"name\":\"namespace_name\",\"type\":\"string\"},{\"name\":\"pod_name\",\"type\":\"string\"},{\"name\":\"pod_id\",\"type\":\"string\"},{\"name\":\"annotations\",\"type\":{\"type\":\"map\",\"values\":\"string\"}},{\"name\":\"labels\",\"type\":{\"type\":\"map\",\"values\":\"string\"}},{\"name\":\"host\",\"type\":\"string\"},{\"name\":\"container_name\",\"type\":\"string\"},{\"name\":\"container_id\",\"type\":\"string\"},{\"name\":\"container_hash\",\"type\":\"string\"},{\"name\":\"container_image\",\"type\":\"string\"}]}}]}";
    const char *ts3 = "{\"name\":\"qavrov2_record\",\"type\":\"record\",\"fields\":[{\"name\":\"newnovalue\",\"type\":\"string\"},{\"name\":\"capture\",\"type\":\"string\"},{\"name\":\"log\",\"type\":\"string\"},{\"name\":\"kubernetes\",\"type\":{\"name\":\"krec\",\"type\":\"record\",\"fields\":[{\"name\":\"namespace_name\",\"type\":\"string\"},{\"name\":\"pod_name\",\"type\":\"string\"},{\"name\":\"pod_id\",\"type\":\"string\"},{\"name\":\"annotations\",\"type\":{\"type\":\"map\",\"values\":\"string\"}},{\"name\":\"labels\",\"type\":{\"type\":\"map\",\"values\":\"string\"}},{\"name\":\"host\",\"type\":\"string\"},{\"name\":\"container_name\",\"type\":\"string\"},{\"name\":\"container_id\",\"type\":\"string\"},{\"name\":\"container_hash\",\"type\":\"string\"},{\"name\":\"container_image\",\"type\":\"string\"}]}}]}";

    const char *schemas[] = {ts1, ts2, ts3, ts2, ts1, NULL};

    int i=0;
    for (i=0; schemas[i] != NULL ; i++) {

        avro_value_t  aobject = {0};
        avro_schema_t aschema = {0};

        msgpack_unpacked msg = test_init(&aobject, &aschema, schemas[i], AVRO_MULTILINE_JSON);

        msgpack_object_print(stderr, msg.data);

        flb_msgpack_to_avro(&aobject, &msg.data);

        avro_value_t log0;
        TEST_CHECK(avro_value_get_by_name(&aobject, "log", &log0, NULL) == 0);

        size_t size1 = 0;
        const char  *log_line = NULL;
        TEST_CHECK(avro_value_get_string(&log0, &log_line, &size1) == 0);
        char *pre = "2020-08-21T15:49:48.154291375Z";
        TEST_CHECK((strncmp(pre, log_line, strlen(pre)) == 0));
        flb_info("log_line len:%zu:\n", strlen(log_line));

        avro_value_t kubernetes0;
        TEST_CHECK(avro_value_get_by_name(&aobject, "kubernetes", &kubernetes0, NULL) == 0);

        avro_value_get_size(&kubernetes0, &size1);
        flb_info("asize:%zu:\n", size1);
        TEST_CHECK(size1 == 10);

        avro_value_t pn;
        TEST_CHECK(avro_value_get_by_name(&kubernetes0, "pod_name", &pn, NULL) == 0);

        const char *pod_name = NULL;
        size_t pod_name_size = 0;
        TEST_CHECK(avro_value_get_string(&pn, &pod_name, &pod_name_size) == 0);
        TEST_CHECK(strcmp(pod_name, "rrrr-bert-completion-tb1-6786c9c8-wj25m") == 0);
        TEST_CHECK(pod_name[pod_name_size] == '\0');
        TEST_CHECK(strlen(pod_name) == (pod_name_size-1));

        avro_value_t nn;
        TEST_CHECK(avro_value_get_by_name(&kubernetes0, "namespace_name", &nn, NULL) == 0);

        const char *namespace_name = NULL;
        size_t namespace_name_size = 0;
        TEST_CHECK(avro_value_get_string(&nn, &namespace_name, &namespace_name_size) == 0);
        TEST_CHECK(strcmp(namespace_name, "k8s-fgg") == 0);

        avro_value_t mapX;
        TEST_CHECK(avro_value_get_by_name(&kubernetes0, "annotations", &mapX, NULL) == 0);

        avro_value_get_size(&mapX, &size1);
        flb_info("asize:%zu:\n", size1);

        TEST_CHECK(size1 == 5);

        // check the first item in the map
        avro_value_t doas;
        TEST_CHECK(avro_value_get_by_name(&mapX, "doAs", &doas, NULL) == 0);
        const char *doaser = NULL;
        size_t doaser_size;
        TEST_CHECK(avro_value_get_string(&doas, &doaser, &doaser_size) == 0);
        TEST_CHECK((strcmp(doaser, "weeb") == 0));

        // check the second item in the map
        avro_value_t iddecorator;
        TEST_CHECK(avro_value_get_by_name(&mapX, "iddecorator.dkdk.username", &iddecorator, NULL) == 0);
        const char *idder = NULL;
        size_t idder_size;
        TEST_CHECK(avro_value_get_string(&iddecorator, &idder, &idder_size) == 0);
        TEST_CHECK((strcmp(idder, "rrrr") == 0));

        avro_schema_decref(aschema);
        msgpack_unpacked_destroy(&msg);
        avro_value_decref(&aobject);
    }

}

// int msgpack2avro(avro_value_t *val, msgpack_object *o)
// get a schema for a type like this:
// http://avro.apache.org/docs/current/api/c/index.html#_examples
// ../lib/msgpack-3.2.0/include/msgpack/pack.h
// static int msgpack_pack_nil(msgpack_packer* pk);
void test_msgpack2avro()
{
    avro_value_t  aobject;
    avro_schema_t schema = avro_schema_null();
    avro_value_iface_t  *aclass = avro_generic_class_from_schema(schema);
    avro_generic_value_new(aclass, &aobject);

    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    msgpack_zone mempool;
    msgpack_object deserialized;

    /* msgpack::sbuffer is a simple buffer implementation. */
    msgpack_sbuffer_init(&sbuf);

    /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_nil(&pk);

    /* deserialize the buffer into msgpack_object instance. */
    /* deserialized object is valid during the msgpack_zone instance alive. */
    msgpack_zone_init(&mempool, 2048);
    msgpack_unpack(sbuf.data, sbuf.size, NULL, &mempool, &deserialized);

    TEST_CHECK((msgpack2avro(&aobject, &deserialized) == FLB_TRUE));

    msgpack_zone_destroy(&mempool);
    msgpack_sbuffer_destroy(&sbuf);
}
const char  JSON_SINGLE_MAP_001_SCHEMA_WITH_UNION[] =
"{\"type\":\"record\",\
  \"name\":\"Map001\",\
  \"fields\":[\
     {\"name\": \"key001\", \"type\": \"int\"},\
     {\"name\": \"key002\", \"type\": \"float\"},\
     {\"name\": \"key003\", \"type\": \"string\"},\
              { \
                \"name\": \"status\", \
                \"default\": null, \
                \"type\": [\"null\", \"string\"] \
              }, \
     {\"name\": \"key004\", \"type\":\
        {\"type\": \"array\", \"items\":\
             {\"type\": \"map\",\"values\": \"int\"}}}]}";
void test_union_type_sanity()
{
    avro_value_t  aobject;
    avro_schema_t aschema;

    msgpack_unpacked msg = test_init(&aobject, &aschema, JSON_SINGLE_MAP_001_SCHEMA_WITH_UNION, AVRO_SINGLE_MAP1);

    msgpack_object_print(stderr, msg.data);
    flb_msgpack_to_avro(&aobject, &msg.data);

    size_t totalSize = 0;
    avro_value_get_size(&aobject, &totalSize);
    flb_info("totalSize:%zu:\n", totalSize);
    // this is key001,2,3,4 and the status field which is the union type
    TEST_CHECK(totalSize == 5);

    avro_value_t test_value;
    TEST_CHECK(avro_value_get_by_name(&aobject, "key001", &test_value, NULL) == 0);

    int val001 = 0;
    avro_value_get_int(&test_value, &val001);
    TEST_CHECK(val001 == 123456789);

    TEST_CHECK(avro_value_get_by_name(&aobject, "key002", &test_value, NULL) == 0);

    float val002 = 0.0f;
    // for some reason its rounding to this value
    float val002_actual = 0.999888f;
    avro_value_get_float(&test_value, &val002);
    char str1[80];
    char str2[80];
    sprintf(str1, "%f", val002);
    sprintf(str2, "%f", val002_actual);
    flb_info("val002:%s:\n", str1);
    flb_info("val002_actual:%s:\n", str2);
    TEST_CHECK((strcmp(str1, str2) == 0));

    TEST_CHECK(avro_value_get_by_name(&aobject, "key003", &test_value, NULL) == 0);
    const char *val003 = NULL;
    size_t val003_size = 0;
    TEST_CHECK(avro_value_get_string(&test_value, &val003, &val003_size) == 0);
    flb_info("val003_size:%zu:\n", val003_size);
    TEST_CHECK(val003[val003_size] == '\0');

    TEST_CHECK((strcmp(val003, "abcdefghijk") == 0));
    // avro_value_get_by_name returns ths string length plus the NUL
    TEST_CHECK(val003_size == 12);

    TEST_CHECK(avro_value_get_by_name(&aobject, "key004", &test_value, NULL) == 0);

    size_t asize = 0;
    avro_value_get_size(&test_value, &asize);
    flb_info("asize:%zu:\n", asize);

    TEST_CHECK(asize == 2);

    TEST_CHECK(avro_value_get_by_name(&aobject, "status", &test_value, NULL) == 0);

    avro_value_decref(&aobject);
    avro_schema_decref(aschema);
    msgpack_unpacked_destroy(&msg);
}

void test_union_type_branches()
{
    avro_value_t  aobject;
    avro_schema_t aschema;
    
    msgpack_unpacked mp = test_init(&aobject, &aschema, JSON_SINGLE_MAP_001_SCHEMA_WITH_UNION, AVRO_SINGLE_MAP1);

    flb_msgpack_to_avro(&aobject, &mp.data);

    avro_value_t test_value;
    TEST_CHECK(avro_value_get_by_name(&aobject, "status", &test_value, NULL) == 0);
    TEST_CHECK(avro_value_get_type(&test_value) == AVRO_UNION);

    int discriminant = 0;
    TEST_CHECK(avro_value_get_discriminant(&test_value, &discriminant) == 0);
    TEST_CHECK(discriminant == -1);

    avro_value_t  branch;
    TEST_CHECK(avro_value_get_current_branch(&test_value, &branch) != 0);

    TEST_CHECK(avro_value_set_branch(&test_value, 0, &branch) == 0);
    TEST_CHECK(avro_value_set_null(&branch) == 0);

    TEST_CHECK(avro_value_get_null(&branch) == 0);

    avro_value_decref(&aobject);
    avro_schema_decref(aschema);
    msgpack_unpacked_destroy(&mp);
}
TEST_LIST = {
    /* Avro */
    { "msgpack_to_avro_basic", test_unpack_to_avro},
    { "test_parse_reordered_schema", test_parse_reordered_schema},
    { "test_union_type_sanity", test_union_type_sanity},
    { "test_union_type_branches", test_union_type_branches},
    { 0 }
};
