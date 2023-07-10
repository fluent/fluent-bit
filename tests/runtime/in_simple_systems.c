/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include "flb_tests_runtime.h"


int64_t result_time;
static inline int64_t set_result(int64_t v)
{
    int64_t old = __sync_lock_test_and_set(&result_time, v);
    return old;
}

static inline int64_t get_result(void)
{
    int64_t old = __sync_fetch_and_add(&result_time, 0);

    return old;
}

static inline int64_t time_in_ms()
{
    int ms;
    struct timespec s;
    TEST_CHECK(clock_gettime(CLOCK_MONOTONIC, &s) == 0);
    ms = s.tv_nsec / 1.0e6;
    if (ms >= 1000) {
        ms = 0;
    }
    return 1000 * s.tv_sec + ms;
}

int callback_test(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        flb_info("[test] flush triggered");
        flb_lib_free(data);
        set_result(time_in_ms()); /* success */
    }
    return 0;
}

struct callback_record {
    void *data;
    size_t size;
};

struct callback_records {
    int num_records;
    struct callback_record *records;
};

int callback_add_record(void* data, size_t size, void* cb_data)
{
    struct callback_records *ctx = (struct callback_records *)cb_data;

    if (size > 0) {
        flb_info("[test] flush record");
        if (ctx->records == NULL) {
            ctx->records = (struct callback_record *)
                           flb_calloc(1, sizeof(struct callback_record));
        } else {
            ctx->records = (struct callback_record *)
                           flb_realloc(ctx->records,
                                       (ctx->num_records+1)*sizeof(struct callback_record));
        }
        if (ctx->records ==  NULL) {
            return -1;
        }
        ctx->records[ctx->num_records].size = size;
        ctx->records[ctx->num_records].data = data;
        ctx->num_records++;
    }
    return 0;
}

void do_test(char *system, ...)
{
    int64_t ret;
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;
    va_list va;
    char *key;
    char *value;
    struct flb_lib_out_cb cb;

    cb.cb   = callback_test;
    cb.data = NULL;

    /* initialize */
    set_result(0);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) system, NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    va_start(va, system);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        TEST_CHECK(value != NULL);
        TEST_CHECK(flb_input_set(ctx, in_ffd, key, value, NULL) == 0);
    }
    va_end(va);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd, "match", "test", NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    NULL) == 0);

    /* The following test tries to check if an input plugin generates
     * data in a timely manner.
     *
     *    0     1     2     3     4   (sec)
     *    |--F--F--F--C--F--F--F--C--|
     *
     *    F ... Flush (0.5 sec interval)
     *    C ... Condition checks
     *
     * Since CI servers can be sometimes very slow, we wait slightly a
     * little more before checking the condition.
     */

    /* Start test */
    TEST_CHECK(flb_start(ctx) == 0);

    /* 2 sec passed. It must have flushed */
    sleep(2);
    flb_info("[test] check status 1");
    ret = get_result();
    TEST_CHECK(ret > 0);

    /* 4 sec passed. It must have flushed */
    sleep(2);
    flb_info("[test] check status 2");
    ret = get_result();
    TEST_CHECK(ret > 0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void do_test_records(char *system, void (*records_cb)(struct callback_records *), ...)
{
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;
    va_list va;
    char *key;
    char *value;
    int i;
    struct flb_lib_out_cb cb;
    struct callback_records *records;

    records = flb_calloc(1, sizeof(struct callback_records));
    records->num_records = 0;
    records->records = NULL;
    cb.cb   = callback_add_record;
    cb.data = (void *)records;

    /* initialize */
    set_result(0);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) system, NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    va_start(va, records_cb);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        TEST_CHECK(value != NULL);
        TEST_CHECK(flb_input_set(ctx, in_ffd, key, value, NULL) == 0);
    }
    va_end(va);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd, "match", "test", NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "1",
                                    "Grace", "1",
                                    NULL) == 0);

    /* Start test */
    TEST_CHECK(flb_start(ctx) == 0);

    /* 4 sec passed. It must have flushed */
    sleep(5);

    records_cb(records);

    flb_stop(ctx);

    for (i = 0; i < records->num_records; i++) {
        flb_lib_free(records->records[i].data);
    }
    flb_free(records->records);
    flb_free(records);

    flb_destroy(ctx);
}

void do_test_records_single(char *system, void (*records_cb)(struct callback_records *), ...)
{
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;
    int exit_ffd;
    va_list va;
    char *key;
    char *value;
    int i;
    struct flb_lib_out_cb cb;
    struct callback_records *records;

    records = flb_calloc(1, sizeof(struct callback_records));
    records->num_records = 0;
    records->records = NULL;
    cb.cb   = callback_add_record;
    cb.data = (void *)records;

    /* initialize */
    set_result(0);

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) system, NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    va_start(va, records_cb);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        TEST_CHECK(value != NULL);
        TEST_CHECK(flb_input_set(ctx, in_ffd, key, value, NULL) == 0);
    }
    va_end(va);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd, "match", "test", NULL) == 0);

    exit_ffd = flb_output(ctx, (char *)"exit", &cb);
    TEST_CHECK(flb_output_set(ctx, exit_ffd, "match", "test", NULL) == 0);

    TEST_CHECK(flb_service_set(ctx, "Flush", "1",
                                    "Grace", "1",
                                    NULL) == 0);

    /* Start test */
    TEST_CHECK(flb_start(ctx) == 0);

    /* 4 sec passed. It must have flushed */
    sleep(5);

    records_cb(records);

    flb_stop(ctx);

    for (i = 0; i < records->num_records; i++) {
        flb_lib_free(records->records[i].data);
    }
    flb_free(records->records);
    flb_free(records);

    flb_destroy(ctx);
}

void flb_test_in_disk_flush()
{
    do_test("disk",
            "interval_sec", "0",
            "interval_nsec", "500000000",
            NULL);
}
void flb_test_in_proc_flush()
{
    do_test("proc",
            "interval_sec", "0",
            "interval_nsec", "500000000",
            "proc_name", "flb_test_in_proc",
            "alert", "true",
            "mem", "on",
            "fd", "on",
            NULL);
}
void flb_test_in_head_flush()
{
    do_test("head",
            "interval_sec", "0",
            "interval_nsec", "500000000",
            "File", "/dev/urandom",
            NULL);
}
void flb_test_in_cpu_flush()
{
    do_test("cpu", NULL);
}
void flb_test_in_random_flush()
{
    do_test("random", NULL);
}

void flb_test_dummy_records_1234(struct callback_records *records)
{
    int i;
    msgpack_unpacked result;
    msgpack_object *obj;
    size_t off = 0;
    struct flb_time ftm;

    TEST_CHECK(records->num_records > 0);
    for (i = 0; i < records->num_records; i++) {
        msgpack_unpacked_init(&result);

        while (msgpack_unpack_next(&result, records->records[i].data,
                                   records->records[i].size, &off) == MSGPACK_UNPACK_SUCCESS) {
            flb_time_pop_from_msgpack(&ftm, &result, &obj);

            TEST_CHECK(ftm.tm.tv_sec == 1234);
            TEST_CHECK(ftm.tm.tv_nsec == 1234);
        }
        msgpack_unpacked_destroy(&result);
    }
}

void flb_test_dummy_records_1999(struct callback_records *records)
{
    int i;
    msgpack_unpacked result;
    msgpack_object *obj;
    size_t off = 0;
    struct flb_time ftm;

    TEST_CHECK(records->num_records > 0);
    for (i = 0; i < records->num_records; i++) {
        msgpack_unpacked_init(&result);

        while (msgpack_unpack_next(&result, records->records[i].data,
                                   records->records[i].size, &off) == MSGPACK_UNPACK_SUCCESS) {
            flb_time_pop_from_msgpack(&ftm, &result, &obj);
            TEST_CHECK(ftm.tm.tv_sec == 1999);
            TEST_CHECK(ftm.tm.tv_nsec == 1999);
        }
        msgpack_unpacked_destroy(&result);
    }
}

void flb_test_dummy_records_today(struct callback_records *records)
{
    int i;
    msgpack_unpacked result;
    msgpack_object *obj;
    size_t off = 0;
    struct flb_time ftm;
    struct flb_time now;

    flb_time_get(&now);
    /* set 5 minutes in the past since this is invoked after the test began */
    now.tm.tv_sec -= (5 * 60);

    TEST_CHECK(records->num_records > 0);
    for (i = 0; i < records->num_records; i++) {
        msgpack_unpacked_init(&result);

        while (msgpack_unpack_next(&result, records->records[i].data,
                                   records->records[i].size, &off) == MSGPACK_UNPACK_SUCCESS) {
            flb_time_pop_from_msgpack(&ftm, &result, &obj);
            TEST_CHECK(ftm.tm.tv_sec >= now.tm.tv_sec);
        }
        msgpack_unpacked_destroy(&result);
    }
}

void flb_test_dummy_records_message(struct callback_records *records)
{
    int i;
    msgpack_unpacked result;
    msgpack_object *obj;
    size_t off = 0;
    struct flb_time ftm;

    TEST_CHECK(records->num_records > 0);
    for (i = 0; i < records->num_records; i++) {
        msgpack_unpacked_init(&result);

        while (msgpack_unpack_next(&result, records->records[i].data,
                                   records->records[i].size, &off) == MSGPACK_UNPACK_SUCCESS) {
            flb_time_pop_from_msgpack(&ftm, &result, &obj);
            TEST_CHECK(obj->type == MSGPACK_OBJECT_MAP);
            TEST_CHECK(strncmp("new_key",
                               obj->via.map.ptr[0].key.via.str.ptr,
                               obj->via.map.ptr[0].key.via.str.size) == 0);
            TEST_CHECK(strncmp("new_value",
                               obj->via.map.ptr[0].val.via.str.ptr,
                               obj->via.map.ptr[0].val.via.str.size) == 0);
        }
        msgpack_unpacked_destroy(&result);
    }
}

void flb_test_dummy_records_message_default(struct callback_records *records)
{
    int i;
    msgpack_unpacked result;
    msgpack_object *obj;
    size_t off = 0;
    struct flb_time ftm;

    TEST_CHECK(records->num_records > 0);
    for (i = 0; i < records->num_records; i++) {
        msgpack_unpacked_init(&result);

        while (msgpack_unpack_next(&result, records->records[i].data,
                                   records->records[i].size, &off) == MSGPACK_UNPACK_SUCCESS) {
            flb_time_pop_from_msgpack(&ftm, &result, &obj);
            TEST_CHECK(obj->type == MSGPACK_OBJECT_MAP);
            TEST_CHECK(strncmp("message",
                               obj->via.map.ptr[0].key.via.str.ptr,
                               obj->via.map.ptr[0].key.via.str.size) == 0);
            TEST_CHECK(strncmp("dummy",
                               obj->via.map.ptr[0].val.via.str.ptr,
                               obj->via.map.ptr[0].val.via.str.size) == 0);
        }
        msgpack_unpacked_destroy(&result);
    }
}

// We check for a minimum of messages because of the non-deterministic
// nature of flushes as well as chunking.
void flb_test_dummy_records_message_copies_1(struct callback_records *records)
{
    TEST_CHECK(records->num_records >= 1);
}

void flb_test_dummy_records_message_copies_5(struct callback_records *records)
{
    TEST_CHECK(records->num_records >= 5);
}

void flb_test_dummy_records_message_copies_100(struct callback_records *records)
{
    TEST_CHECK(records->num_records >= 100);
}

void flb_test_in_dummy_flush()
{
    do_test("dummy", NULL);
    do_test_records("dummy", flb_test_dummy_records_message_default, NULL);
    do_test_records("dummy", flb_test_dummy_records_today, NULL);
    do_test_records("dummy", flb_test_dummy_records_message,
                    "dummy", "{\"new_key\": \"new_value\"}",
                    NULL);
    do_test_records("dummy", flb_test_dummy_records_message_default,
                    "dummy", "{\"bad_json}",
                    NULL);
    do_test_records("dummy", flb_test_dummy_records_1234,
                    "start_time_sec", "1234",
                    "start_time_nsec", "1234",
                    "fixed_timestamp", "on",
                    NULL);
    do_test_records("dummy", flb_test_dummy_records_1999,
                    "start_time_sec", "1999",
                    "start_time_nsec", "1999",
                    "fixed_timestamp", "on",
                    NULL);
    do_test_records_single("dummy", flb_test_dummy_records_message_copies_1,
	                   "copies", "1",
	                   NULL);
    do_test_records_single("dummy", flb_test_dummy_records_message_copies_5,
	                   "copies", "5",
	                   NULL);
    do_test_records_single("dummy", flb_test_dummy_records_message_copies_100,
	                   "copies", "100",
	                   NULL);
}

void flb_test_in_dummy_thread_flush()
{
    do_test("dummy_thread", NULL);
}

void flb_test_in_mem_flush()
{
    do_test("mem", NULL);
}

#ifdef in_proc
void flb_test_in_proc_absent_process(void)
{
    int ret;
    flb_ctx_t    *ctx    = NULL;
    int in_ffd;
    int out_ffd;

    struct flb_lib_out_cb cb;
    cb.cb   = callback_test;
    cb.data = NULL;

    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "proc", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test",
                  "interval_sec", "1", "proc_name", "-",
                  "alert", "true", "mem", "on", "fd", "on", NULL);

    out_ffd = flb_output(ctx, (char *) "lib", &cb);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    flb_service_set(ctx, "Flush", "2", "Grace", "1", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0); // error occurs but return value is true

    flb_stop(ctx);
    flb_destroy(ctx);
}
#endif

/* Test list */
TEST_LIST = {
#ifdef in_disk
    {"disk_flush",    flb_test_in_disk_flush},
#endif
#ifdef in_proc
    {"proc_flush",    flb_test_in_proc_flush},
    {"proc_absent_process",     flb_test_in_proc_absent_process},
#endif
#ifdef in_head
    {"head_flush",    flb_test_in_head_flush},
#endif
#ifdef in_cpu
    {"cpu_flush",     flb_test_in_cpu_flush},
#endif
#ifdef in_random
    {"random_flush",  flb_test_in_random_flush},
#endif
#ifdef in_dummy
    {"dummy_flush",   flb_test_in_dummy_flush},
#endif
#ifdef in_mem
    {"mem_flush",     flb_test_in_mem_flush},
#endif
    {NULL, NULL}
};

