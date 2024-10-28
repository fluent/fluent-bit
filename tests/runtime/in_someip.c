/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include <someip_api.h>
#include "flb_tests_runtime.h"

struct test_ctx
{
    flb_ctx_t *flb;             /* Fluent Bit library context */
    int i_ffd;                  /* Input fd */
    int f_ffd;                  /* Filter fd  (not used) */
    int o_ffd;                  /* Output fd */
};

/* Holds one record output from the input SOME/IP plugin */
struct callback_record
{
    void *data;                 /* Raw record buffer */
    size_t size;                /* Raw record size */
};

/* Holds all records output from the input SOME/IP plugin */
struct callback_records
{
    int num_records;            /* Number of records */
    struct callback_record *records;    /* Record structs */
};

/* Protects access to the records */
pthread_mutex_t record_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Called by FB thread when record is SOME/IP record is flushed out
 * 
 * @param data Pointer to the record data
 * @param size Size of the record data
 * @param Pointer to the callback_records struct
 */
static int callback_add_record(void *data, size_t size, void *cb_data)
{
    struct callback_records *ctx = (struct callback_records *) cb_data;
    struct callback_record *new_record = NULL;
    int ret = 0;

    if (!TEST_CHECK(data != NULL)) {
        flb_error("Data pointer is NULL");
        return -1;
    }

    if (!TEST_CHECK(ctx != NULL)) {
        flb_error("Test records pointer is NULL");
        flb_free(data);
        return -1;
    }
    flb_debug("add_record: data size = %ld, callback_records = %d", size,
              ctx->num_records);

    if (size > 0) {
        /* Add the record to the record list */
        pthread_mutex_lock(&record_mutex);

        /* Grow the array of records by one */
        if (ctx->records == NULL) {
            /* First one. Allocate the record */
            ctx->records = (struct callback_record *)
                flb_calloc(1, sizeof(struct callback_record));
        }
        else {
            /* Grow the record buffer enough for another record to be appended */
            ctx->records = (struct callback_record *)
                flb_realloc(ctx->records,
                            (ctx->num_records +
                             1) * sizeof(struct callback_record));
        }
        if (ctx->records == NULL) {
            ret = -1;
        }
        else {
            new_record = &(ctx->records[ctx->num_records++]);
            new_record->size = size;
            new_record->data = flb_malloc(size);
            if (new_record->data != NULL) {
                memcpy(new_record->data, data, size);
            }
        }
        pthread_mutex_unlock(&record_mutex);
    }
    flb_free(data);
    return ret;
}

/*
 * Cleans up any memory allocated for the data records
 *
 * @param record_holder Pointer to the records
 */
static void destroy_records(struct callback_records *record_holder)
{
    int i;
    struct callback_record *record;

    for (i = 0; i < record_holder->num_records; ++i) {
        record = &(record_holder->records[i]);
        if (record->data != NULL) {
            flb_free(record->data);
            record->data = NULL;
            record->size = 0;
        }
    }
    flb_free(record_holder->records);
    record_holder->records = NULL;
    record_holder->num_records = 0;
}

/*
 * Creates the text context
 * 
 * @param data Pointer to the output callback structure
 */
static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int o_ffd;
    struct test_ctx *ctx = NULL;

    ctx = flb_malloc(sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("malloc failed");
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1", "Log_Level", "trace", NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "someip", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;

    return ctx;
}

/*
 * Client up the test context
 */
static void test_ctx_destroy(struct test_ctx *ctx)
{
    TEST_CHECK(ctx != NULL);

    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

/*
 * Method to check a single record
 * 
 * @param records Collected records structure
 * @param rec_num Which record number to check
 * @param expected Expected fields in the record
 * @param expected_size Number of expected fields
 */
static void check_record(struct callback_records *records, int rec_num,
                         struct msgpack_object_kv *expected,
                         size_t expected_size)
{
    int i;
    msgpack_unpacked result;
    msgpack_object *obj;
    size_t off = 0;
    struct flb_time ftm;
    struct callback_record *record;

    TEST_CHECK(records->num_records >= rec_num);

    record = &(records->records[rec_num]);

    // Unpack the record
    msgpack_unpacked_init(&result);
    TEST_CHECK(msgpack_unpack_next(&result, record->data, record->size, &off)
               == MSGPACK_UNPACK_SUCCESS);

    flb_debug("Unpack successful");
    flb_time_pop_from_msgpack(&ftm, &result, &obj);
    TEST_CHECK(obj->type == MSGPACK_OBJECT_MAP);
    if (TEST_CHECK(obj->via.map.size >= expected_size)) {
        for (i = 0; i < expected_size; ++i) {
            TEST_CHECK(msgpack_object_equal
                       (obj->via.map.ptr[i].key, expected[i].key));
            TEST_CHECK(msgpack_object_equal
                       (obj->via.map.ptr[i].val, expected[i].val));
        }
    }
    msgpack_unpacked_destroy(&result);
}

/*
 * Helper method to populate an expected record field with a string value
 * 
 * @param field Pointer to the record field to populate
 * @param key Key portion (always a string) of the record field
 * @param val (string) Value portion of the record field
 */
static void populate_expected_field_string(msgpack_object_kv * field,
                                           const char *key, const char *val)
{
    field->key.type = MSGPACK_OBJECT_STR;
    field->key.via.str.ptr = key;
    field->key.via.str.size = strlen(key);

    field->val.type = MSGPACK_OBJECT_STR;
    field->val.via.str.ptr = val;
    field->val.via.str.size = strlen(val);
}

/*
 * Helper method to populate an expected record field with a unsigned value
 * 
 * @param field Pointer to the record field to populate
 * @param key Key portion (always a string) of the record field
 * @param val (unsigned int) Value portion of the record field
 */
static void populate_expected_field_uint(msgpack_object_kv * field,
                                         const char *key, unsigned value)
{
    field->key.type = MSGPACK_OBJECT_STR;
    field->key.via.str.ptr = key;
    field->key.via.str.size = strlen(key);

    field->val.type = MSGPACK_OBJECT_POSITIVE_INTEGER;
    field->val.via.u64 = value;
}

struct some_ip_request received_request;

/* Protects access to the received request */
pthread_mutex_t request_mutex = PTHREAD_MUTEX_INITIALIZER;

void request_call_back(void*, struct some_ip_request *request_details)
{
    pthread_mutex_lock(&request_mutex);
    received_request.request_id = request_details->request_id;
    received_request.method_id = request_details->method_id;
    received_request.payload = NULL;
    received_request.payload_len = 0;
    if (request_details->payload != NULL && request_details->payload_len > 0) {
        received_request.payload = flb_malloc(request_details->payload_len);
        if (received_request.payload != NULL) {
            memcpy(received_request.payload, request_details->payload,
                   request_details->payload_len);
            received_request.payload_len = request_details->payload_len;
        }
    }
    pthread_mutex_unlock(&request_mutex);
}

void destroy_request()
{
    pthread_mutex_lock(&request_mutex);
    if (received_request.payload != NULL) {
        flb_free(received_request.payload);
    }
    memset(&received_request, 0, sizeof(received_request));
    pthread_mutex_unlock(&request_mutex);
}

/* Basic test for injecting an event */
void flb_test_someip_event()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    uint16_t someip_client_id;
    char *event_text = "Test SOME/IP event 1";
    char *event_base64 = "VGVzdCBTT01FL0lQIGV2ZW50IDE=";
    struct callback_records records;
    msgpack_object_kv expected_fields[5];
    uint16_t event_group = 1;

    populate_expected_field_string(&(expected_fields[0]), "record type",
                                   "event");
    populate_expected_field_uint(&(expected_fields[1]), "service", 4);
    populate_expected_field_uint(&(expected_fields[2]), "instance", 1);
    populate_expected_field_uint(&(expected_fields[3]), "event", 32768);
    populate_expected_field_string(&(expected_fields[4]), "payload",
                                   event_base64);

    records.records = NULL;
    records.num_records = 0;

    cb_data.cb = callback_add_record;
    cb_data.data = (void *) &records;

    /* Create the test context */
    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    /* Provide input configuration */
    ret = flb_input_set(ctx->flb, ctx->i_ffd, "Event", "4,1,32768,1",   /*Service,Instance,Event,EventGroup */
                        NULL);

    TEST_CHECK(ret == 0);

    /* Set up to get msgpack upstream data */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*", "format", "msgpack", NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Initialize the test application to inject an event */
    ret = someip_initialize("SomeipTestService", &someip_client_id);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Offer the event */
    ret = someip_offer_event(someip_client_id, 4, 1, 32768, &event_group, 1);   /* Should match the configuration above */
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Offer the service */
    ret = someip_offer_service(someip_client_id, 4, 1);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* wait for plugin to connect to the service */
    flb_time_msleep(1000);

    /* Publish the event */
    ret =
        someip_send_event(someip_client_id, 4, 1, 32768, event_text,
                          strlen(event_text));
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* waiting to flush */
    flb_time_msleep(1500);

    /* Check for the upstream record */
    pthread_mutex_lock(&record_mutex);
    TEST_CHECK(records.num_records == 1);
    check_record(&records, 0, expected_fields,
                 sizeof(expected_fields) / sizeof(msgpack_object_kv));
    destroy_records(&records);

    pthread_mutex_unlock(&record_mutex);

    (void) someip_shutdown(someip_client_id);
    test_ctx_destroy(ctx);
}

/* Service publishes an event with no payload */
void flb_test_someip_event_empty_payload()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    uint16_t someip_client_id;
    struct callback_records records;
    msgpack_object_kv expected_fields[5];
    uint16_t event_group = 1;

    populate_expected_field_string(&(expected_fields[0]), "record type",
                                   "event");
    populate_expected_field_uint(&(expected_fields[1]), "service", 4);
    populate_expected_field_uint(&(expected_fields[2]), "instance", 1);
    populate_expected_field_uint(&(expected_fields[3]), "event", 32768);
    populate_expected_field_string(&(expected_fields[4]), "payload", "");

    records.records = NULL;
    records.num_records = 0;

    cb_data.cb = callback_add_record;
    cb_data.data = (void *) &records;

    /* Create the test context */
    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    /* Provide input configuration */
    ret = flb_input_set(ctx->flb, ctx->i_ffd, "Event", "4,1,32768,1",   /*Service,Instance,Event,Event Group */
                        NULL);

    TEST_CHECK(ret == 0);

    /* Set up to get msgpack upstream data */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*", "format", "msgpack", NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Initialize the test application to inject an event */
    ret = someip_initialize("SomeipTestService", &someip_client_id);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Offer the event */
    ret = someip_offer_event(someip_client_id, 4, 1, 32768, &event_group, 1);   /* Should match the configuration above */
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Offer the service */
    ret = someip_offer_service(someip_client_id, 4, 1);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* wait for plugin to connect to the service */
    flb_time_msleep(1000);

    /* Publish the event */
    ret = someip_send_event(someip_client_id, 4, 1, 32768, NULL, 0);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* waiting to flush */
    flb_time_msleep(1500);

    /* Check for the upstream record */
    pthread_mutex_lock(&record_mutex);
    TEST_CHECK(records.num_records == 1);
    check_record(&records, 0, expected_fields,
                 sizeof(expected_fields) / sizeof(msgpack_object_kv));
    destroy_records(&records);

    pthread_mutex_unlock(&record_mutex);

    (void) someip_shutdown(someip_client_id);
    test_ctx_destroy(ctx);
}

/* Multiple subscribed events. One event for each subscription */
void flb_test_multiple_events()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    uint16_t someip_client_id;
    char *event_config = "4,1,32768,1"; /*Service,Instance,Event,Event Groups */
    char *event_text = "Test SOME/IP event 1";
    char *event_base64 = "VGVzdCBTT01FL0lQIGV2ZW50IDE=";
    char *second_event_config = "4,1,32769,2";  /*Service,Instance,Event,Event Group(s) */
    char *second_event_text = "Test SOME/IP event 2";
    char *second_event_base64 = "VGVzdCBTT01FL0lQIGV2ZW50IDI=";
    struct callback_records records;
    uint16_t event_one_group = 1;
    uint16_t event_two_group = 2;
    msgpack_object_kv first_event_fields[5];
    msgpack_object_kv second_event_fields[5];

    populate_expected_field_string(&(first_event_fields[0]), "record type",
                                   "event");
    populate_expected_field_uint(&(first_event_fields[1]), "service", 4);
    populate_expected_field_uint(&(first_event_fields[2]), "instance", 1);
    populate_expected_field_uint(&(first_event_fields[3]), "event", 32768);
    populate_expected_field_string(&(first_event_fields[4]), "payload",
                                   event_base64);

    populate_expected_field_string(&(second_event_fields[0]), "record type",
                                   "event");
    populate_expected_field_uint(&(second_event_fields[1]), "service", 4);
    populate_expected_field_uint(&(second_event_fields[2]), "instance", 1);
    populate_expected_field_uint(&(second_event_fields[3]), "event", 32769);
    populate_expected_field_string(&(second_event_fields[4]), "payload",
                                   second_event_base64);

    records.records = NULL;
    records.num_records = 0;

    cb_data.cb = callback_add_record;
    cb_data.data = (void *) &records;

    /* Create the test context */
    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    /* Provide input configuration */
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "Event", event_config,
                        "Event", second_event_config, NULL);

    TEST_CHECK(ret == 0);

    /* Set up to get msgpack upstream data */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*", "format", "msgpack", NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Initialize the test application to inject an events */
    ret = someip_initialize("SomeipTestService", &someip_client_id);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Offer the events */

    ret = someip_offer_event(someip_client_id, 4, 1, 32768, &event_one_group, 1);       /* Should match the configuration above */
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);
    ret = someip_offer_event(someip_client_id, 4, 1, 32769, &event_two_group, 1);       /* Should match the configuration above */
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Offer the service */
    ret = someip_offer_service(someip_client_id, 4, 1);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* wait for plugin to connect to the service */
    flb_time_msleep(1000);

    /* Publish event 1 */
    ret =
        someip_send_event(someip_client_id, 4, 1, 32768, event_text,
                          strlen(event_text));
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Publish event 2 */
    ret =
        someip_send_event(someip_client_id, 4, 1, 32769, second_event_text,
                          strlen(second_event_text));
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* waiting to flush */
    flb_time_msleep(1500);

    /* Check for the upstream record */
    pthread_mutex_lock(&record_mutex);
    TEST_CHECK(records.num_records == 2);
    check_record(&records, 0, first_event_fields,
                 sizeof(first_event_fields) / sizeof(msgpack_object_kv));
    check_record(&records, 1, second_event_fields,
                 sizeof(second_event_fields) / sizeof(msgpack_object_kv));
    destroy_records(&records);

    pthread_mutex_unlock(&record_mutex);

    (void) someip_shutdown(someip_client_id);
    test_ctx_destroy(ctx);
}

/* Single event that belongs to multiple event groups */
void flb_test_multiple_event_groups()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    uint16_t someip_client_id;
    char *event_config = "4,1,32768,1,2";       /*Service,Instance,Event,Event Groups */
    char *event_text = "Test SOME/IP event 1";
    char *event_base64 = "VGVzdCBTT01FL0lQIGV2ZW50IDE=";
    struct callback_records records;
    uint16_t event_one_groups[2] = { 1, 2 };
    msgpack_object_kv first_event_fields[5];

    populate_expected_field_string(&(first_event_fields[0]), "record type",
                                   "event");
    populate_expected_field_uint(&(first_event_fields[1]), "service", 4);
    populate_expected_field_uint(&(first_event_fields[2]), "instance", 1);
    populate_expected_field_uint(&(first_event_fields[3]), "event", 32768);
    populate_expected_field_string(&(first_event_fields[4]), "payload",
                                   event_base64);

    records.records = NULL;
    records.num_records = 0;

    cb_data.cb = callback_add_record;
    cb_data.data = (void *) &records;

    /* Create the test context */
    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    /* Provide input configuration */
    ret = flb_input_set(ctx->flb, ctx->i_ffd, "Event", event_config, NULL);

    TEST_CHECK(ret == 0);

    /* Set up to get msgpack upstream data */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*", "format", "msgpack", NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Initialize the test application to inject an events */
    ret = someip_initialize("SomeipTestService", &someip_client_id);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Offer the event */

    ret = someip_offer_event(someip_client_id, 4, 1, 32768, event_one_groups, sizeof(event_one_groups) / sizeof(uint16_t));     /* Should match the configuration above */
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Offer the service */
    ret = someip_offer_service(someip_client_id, 4, 1);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* wait for plugin to connect to the service */
    flb_time_msleep(1000);

    /* Publish event 1 */
    ret =
        someip_send_event(someip_client_id, 4, 1, 32768, event_text,
                          strlen(event_text));
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* waiting to flush */
    flb_time_msleep(1500);

    /* Check for the upstream record */
    pthread_mutex_lock(&record_mutex);
    TEST_CHECK(records.num_records == 1);
    check_record(&records, 0, first_event_fields,
                 sizeof(first_event_fields) / sizeof(msgpack_object_kv));
    destroy_records(&records);

    pthread_mutex_unlock(&record_mutex);

    (void) someip_shutdown(someip_client_id);
    test_ctx_destroy(ctx);
}

/* Basic test for injecting an RPC and processing response */
void flb_test_someip_rpc_payload()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    uint16_t someip_client_id;
    char *rpc_request_text = "Test SOME/IP request";
    char *rpc_response_text = "Test SOME/IP response";
    char *rpc_response_base64 = "VGVzdCBTT01FL0lQIHJlc3BvbnNl";
    struct callback_records records;
    msgpack_object_kv expected_fields[5];
    uint32_t request_id;

    populate_expected_field_string(&(expected_fields[0]), "record type",
                                   "response");
    populate_expected_field_uint(&(expected_fields[1]), "service", 4);
    populate_expected_field_uint(&(expected_fields[2]), "instance", 1);
    populate_expected_field_uint(&(expected_fields[3]), "method", 1);
    populate_expected_field_string(&(expected_fields[4]), "payload",
                                   rpc_response_base64);

    records.records = NULL;
    records.num_records = 0;

    cb_data.cb = callback_add_record;
    cb_data.data = (void *) &records;

    /* Create the test context */
    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    /* Provide input configuration */

    /* Last parameter is the base64 of the request payload */
    ret = flb_input_set(ctx->flb, ctx->i_ffd, "RPC", "4,1,1,VGVzdCBTT01FL0lQIHJlcXVlc3Q=",      /*Service,Instance,Method,Payload */
                        NULL);

    TEST_CHECK(ret == 0);

    /* Set up to get msgpack upstream data */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*", "format", "msrequest_call_backgpack",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Initialize the test application register a RPC handler */
    ret = someip_initialize("SomeipTestService", &someip_client_id);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    ret =
        someip_register_request_handler(someip_client_id, 4, 1, 1, NULL,
                                        request_call_back);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Offer the service */
    ret = someip_offer_service(someip_client_id, 4, 1);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* wait for plugin to connect to the service */
    flb_time_msleep(1000);

    /* Should have gotten the request */
    pthread_mutex_lock(&request_mutex);
    TEST_CHECK(received_request.request_id.service_id == 4);
    TEST_CHECK(received_request.request_id.instance_id == 1);
    TEST_CHECK(received_request.method_id == 1);
    TEST_CHECK(received_request.payload != NULL);
    TEST_CHECK(received_request.payload_len >= strlen(rpc_request_text));
    TEST_CHECK(strncmp
               (rpc_request_text, (const char *) received_request.payload,
                strlen(rpc_request_text)) == 0);
    request_id = received_request.request_id.client_request_id;
    pthread_mutex_unlock(&request_mutex);
    destroy_request();

    /* Send back the response */
    ret =
        someip_send_response(someip_client_id, request_id, rpc_response_text,
                             strlen(rpc_response_text));
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* waiting to flush */
    flb_time_msleep(1500);

    /* Check for the upstream record */
    pthread_mutex_lock(&record_mutex);
    if (TEST_CHECK(records.num_records == 1)) {
        check_record(&records, 0, expected_fields,
                     sizeof(expected_fields) / sizeof(msgpack_object_kv));

    }
    destroy_records(&records);

    pthread_mutex_unlock(&record_mutex);

    (void) someip_shutdown(someip_client_id);
    test_ctx_destroy(ctx);
}

/* Basic test for injecting an RPC and processing response with empty payload */
void flb_test_someip_rpc_empty_payload()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    uint16_t someip_client_id;
    char *rpc_request_text = "Test SOME/IP request";
    struct callback_records records;
    msgpack_object_kv expected_fields[5];
    uint32_t request_id;

    populate_expected_field_string(&(expected_fields[0]), "record type",
                                   "response");
    populate_expected_field_uint(&(expected_fields[1]), "service", 4);
    populate_expected_field_uint(&(expected_fields[2]), "instance", 1);
    populate_expected_field_uint(&(expected_fields[3]), "method", 1);
    populate_expected_field_string(&(expected_fields[4]), "payload", "");

    records.records = NULL;
    records.num_records = 0;

    cb_data.cb = callback_add_record;
    cb_data.data = (void *) &records;

    /* Create the test context */
    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    /* Provide input configuration */

    /* Last parameter is the base64 of the request payload */
    ret = flb_input_set(ctx->flb, ctx->i_ffd, "RPC", "4,1,1,VGVzdCBTT01FL0lQIHJlcXVlc3Q=",      /*Service,Instance,Method,Payload */
                        NULL);

    TEST_CHECK(ret == 0);

    /* Set up to get msgpack upstream data */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*", "format", "msrequest_call_backgpack",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Initialize the test application register a RPC handler */
    ret = someip_initialize("SomeipTestService", &someip_client_id);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    ret =
        someip_register_request_handler(someip_client_id, 4, 1, 1,
                                        NULL, request_call_back);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Offer the service */
    ret = someip_offer_service(someip_client_id, 4, 1);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* wait for plugin to connect to the service */
    flb_time_msleep(1000);

    /* Should have gotten the request */
    pthread_mutex_lock(&request_mutex);
    TEST_CHECK(received_request.request_id.service_id == 4);
    TEST_CHECK(received_request.request_id.instance_id == 1);
    TEST_CHECK(received_request.method_id == 1);
    TEST_CHECK(received_request.payload != NULL);
    TEST_CHECK(received_request.payload_len >= strlen(rpc_request_text));
    TEST_CHECK(strncmp
               (rpc_request_text, (const char *) received_request.payload,
                strlen(rpc_request_text)) == 0);
    request_id = received_request.request_id.client_request_id;
    pthread_mutex_unlock(&request_mutex);
    destroy_request();

    /* Send back the response */
    ret =
        someip_send_response(someip_client_id, request_id, NULL, 0);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* waiting to flush */
    flb_time_msleep(1500);

    /* Check for the upstream record */
    pthread_mutex_lock(&record_mutex);
    if (TEST_CHECK(records.num_records == 1)) {
        check_record(&records, 0, expected_fields,
                     sizeof(expected_fields) / sizeof(msgpack_object_kv));

    }
    destroy_records(&records);

    pthread_mutex_unlock(&record_mutex);

    (void) someip_shutdown(someip_client_id);
    test_ctx_destroy(ctx);
}

/* Test with empty request payload */
void flb_test_someip_rpc_empty_request()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    uint16_t someip_client_id;
    char *rpc_response_text = "Test SOME/IP response";
    char *rpc_response_base64 = "VGVzdCBTT01FL0lQIHJlc3BvbnNl";
    struct callback_records records;
    msgpack_object_kv expected_fields[5];
    uint32_t request_id;

    populate_expected_field_string(&(expected_fields[0]), "record type",
                                   "response");
    populate_expected_field_uint(&(expected_fields[1]), "service", 4);
    populate_expected_field_uint(&(expected_fields[2]), "instance", 1);
    populate_expected_field_uint(&(expected_fields[3]), "method", 1);
    populate_expected_field_string(&(expected_fields[4]), "payload",
                                   rpc_response_base64);

    records.records = NULL;
    records.num_records = 0;

    cb_data.cb = callback_add_record;
    cb_data.data = (void *) &records;

    /* Create the test context */
    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    /* Provide input configuration */

    /* Last parameter is the base64 of the request payload */
    ret = flb_input_set(ctx->flb, ctx->i_ffd, "RPC", "4,1,1,",      /*Service,Instance,Method,Payload */
                        NULL);

    TEST_CHECK(ret == 0);

    /* Set up to get msgpack upstream data */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*", "format", "msrequest_call_backgpack",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Initialize the test application register a RPC handler */
    ret = someip_initialize("SomeipTestService", &someip_client_id);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    ret =
        someip_register_request_handler(someip_client_id, 4, 1, 1,
                                        NULL, request_call_back);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* Offer the service */
    ret = someip_offer_service(someip_client_id, 4, 1);
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* wait for plugin to connect to the service */
    flb_time_msleep(1000);

    /* Should have gotten the request */
    pthread_mutex_lock(&request_mutex);
    TEST_CHECK(received_request.request_id.service_id == 4);
    TEST_CHECK(received_request.request_id.instance_id == 1);
    TEST_CHECK(received_request.method_id == 1);
    TEST_CHECK(received_request.payload == NULL);
    TEST_CHECK(received_request.payload_len == 0);
    request_id = received_request.request_id.client_request_id;
    pthread_mutex_unlock(&request_mutex);
    destroy_request();

    /* Send back the response */
    ret =
        someip_send_response(someip_client_id, request_id, rpc_response_text,
                             strlen(rpc_response_text));
    TEST_CHECK(ret == SOMEIP_RET_SUCCESS);

    /* waiting to flush */
    flb_time_msleep(1500);

    /* Check for the upstream record */
    pthread_mutex_lock(&record_mutex);
    if (TEST_CHECK(records.num_records == 1)) {
        check_record(&records, 0, expected_fields,
                     sizeof(expected_fields) / sizeof(msgpack_object_kv));

    }
    destroy_records(&records);

    pthread_mutex_unlock(&record_mutex);

    (void) someip_shutdown(someip_client_id);
    test_ctx_destroy(ctx);
}

TEST_LIST = {
    {"single event", flb_test_someip_event},
    {"event no payload", flb_test_someip_event_empty_payload},
    {"multiple events", flb_test_multiple_events},
    {"multiple event_groups", flb_test_multiple_event_groups},
    {"rpc response with payload", flb_test_someip_rpc_payload},
    {"rpc response empty payload", flb_test_someip_rpc_empty_payload},
    {"rpc request empty payload", flb_test_someip_rpc_empty_request},
    {NULL, NULL}
};
