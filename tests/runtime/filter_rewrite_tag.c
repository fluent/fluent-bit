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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>
#include "flb_tests_runtime.h"

struct filter_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
    int o_ffd;         /* Output fd */
};

struct expect_str {
    char *str;
    int  found;
};

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int  num_output = 0;

static int cb_count_msgpack(void *record, size_t size, void *data)
{
    msgpack_unpacked result;
    size_t off = 0;

    if (!TEST_CHECK(data != NULL)) {
        flb_error("data is NULL");
    }

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        pthread_mutex_lock(&result_mutex);
        num_output++;
        pthread_mutex_unlock(&result_mutex);
    }
    msgpack_unpacked_destroy(&result);

    flb_free(record);
    return 0;
}

static void clear_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output = 0;
    pthread_mutex_unlock(&result_mutex);
}

static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void wait_for_output_num(uint32_t timeout_ms, int expected_num, int *output_num)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_ms = 0;

    flb_time_get(&start_time);

    while (elapsed_time_ms < timeout_ms) {
        *output_num = get_output_num();

        if (*output_num >= expected_num) {
            return;
        }

        flb_time_msleep(100);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_time_ms = flb_time_to_nanosec(&diff_time) / 1000000;
    }

    *output_num = get_output_num();
}

static struct filter_test *filter_test_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int f_ffd;
    int o_ffd;
    struct filter_test *ctx;

    ctx = flb_malloc(sizeof(struct filter_test));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(i_ffd >= 0);
    flb_input_set(ctx->flb, i_ffd, "tag", "rewrite", NULL);
    ctx->i_ffd = i_ffd;

    /* Filter configuration */
    f_ffd = flb_filter(ctx->flb, (char *) "rewrite_tag", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "rewrite", NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;

    return ctx;
}

static void filter_test_destroy(struct filter_test *ctx)
{
    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}


/* 
 * Original  tag: rewrite
 * Rewritten tag: updated
 */
static void flb_test_matched()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    int got;
    char *p = "[0, {\"key\":\"rewrite\"}]";

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$key ^(rewrite)$ updated false",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "updated",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* ingest record */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got != 0)) {
        TEST_MSG("expect: %d got: %d", 1, got);
    }

    filter_test_destroy(ctx);
}

/* 
 * Original  tag: rewrite
 * Rewritten tag: updated
 */
static void flb_test_not_matched()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    int got;
    char *p = "[0, {\"key\":\"not_match\"}]";

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$key ^(rewrite)$ updated false",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "rewrite",
                         NULL);
    TEST_CHECK(ret == 0);


    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* ingest record */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got != 0)) {
        TEST_MSG("expect: %d got: %d", 1, got);
    }

    filter_test_destroy(ctx);
}

/* 
 * Original  tag: rewrite
 * Rewritten tag: updated
 */
static void flb_test_keep_true()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    int got;
    char *p = "[0, {\"key\":\"rewrite\"}]";

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$key ^(rewrite)$ updated true",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output to count up all record */
    ret = flb_output_set(ctx->flb, ctx->o_ffd, "Match", "*", NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* ingest record */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    /* original record(keep) + rewritten record */
    if (!TEST_CHECK(got == 2)) {
        TEST_MSG("expect: %d got: %d", 2, got);
    }

    filter_test_destroy(ctx);
}

/* https://github.com/fluent/fluent-bit/issues/4049
 * Emitter should pause if tons of input come.
 */
static void flb_test_heavy_input_pause_emitter()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    int heavy_loop = 100000;
    int got;
    char p[256];
    int i;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$key ^(rewrite)$ updated false",
                         "Emitter_Mem_Buf_Limit", "1kb",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "updated",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Suppress emitter log. error registering chunk with tag: updated */
    ret = flb_service_set(ctx->flb, "Log_Level", "Off", NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    for (i = 0; i < heavy_loop; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"key\": \"rewrite\"}]", i, i);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got != 0)) {
        TEST_MSG("callback is not invoked");
    }

    /*
     * Input should be paused since Mem_Buf_Limit is small size. Retagged
     * records accepted within the emitter budget should drain, but the
     * emitter must stop accepting before the full unbounded stream is queued.
     */
    if(!TEST_CHECK(heavy_loop > got)) {
        TEST_MSG("expect: %d got: %d", heavy_loop, got);
    }

    filter_test_destroy(ctx);
}

static void flb_test_busy_emitter_keeps_original()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    int heavy_loop = 100000;
    int got;
    char p[256];
    int i;

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$key ^(rewrite)$ updated false",
                         "Emitter_Mem_Buf_Limit", "1kb",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "*",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_service_set(ctx->flb, "Log_Level", "Off", NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    for (i = 0; i < heavy_loop; i++) {
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"key\": \"rewrite\"}]", i, i);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    wait_for_output_num(30000, heavy_loop, &got);

    if (!TEST_CHECK(got == heavy_loop)) {
        TEST_MSG("expect: %d got: %d", heavy_loop, got);
    }

    filter_test_destroy(ctx);
}

static void flb_test_issue_4793()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int loop_max = 4;
    int bytes;
    int got;
    char p[256];
    int i;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$destination ^(server)$ updated false",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd, "Match", "*", NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);


    /* emit (loop_max * 2) records */
    for (i = 0; i < loop_max; i++) {
        /* "destination": "server" */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"destination\": \"server\"}]", i, i);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));

        /* "destination": "other" */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"val\": \"%d\",\"destination\": \"other\"}]", i+1, i+1);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got != 0)) {
        TEST_MSG("callback is not invoked");
    }

    if(!TEST_CHECK(2*loop_max ==  got)) {
        TEST_MSG("expect: %d got: %d", 2 * loop_max, got);
    }

    filter_test_destroy(ctx);
}

static void flb_test_issue_4518()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int loop_max = 2;
    int bytes;
    int got;
    char p[256];
    int i;
    int f_ffd;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "*",
                         NULL);

    /* create 2nd filter  */
    f_ffd = flb_filter(ctx->flb, (char *) "rewrite_tag", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "rewrite", NULL);
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, f_ffd,
                         "Rule", "$test3 ^(true)$ updated true",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure 1st filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$test2 ^(true)$ updated true",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    for (i = 0; i < loop_max; i++) {
        memset(p, '\0', sizeof(p));
        /* 1st filter duplicates below record. */
        snprintf(p, sizeof(p), "[%d, {\"msg\":\"DEBUG\", \"val\": \"%d\",\"test2\": \"true\"}]", i, i);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));

        /* 2nd filter duplicates below record. */
        memset(p, '\0', sizeof(p));
        snprintf(p, sizeof(p), "[%d, {\"msg\":\"ERROR\", \"val\": \"%d\",\"test3\": \"true\"}]", i, i);
        bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
        TEST_CHECK(bytes == strlen(p));
    }

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got != 0)) {
        TEST_MSG("callback is not invoked");
    }

    /* Output should be 4 * loop_max. 
       1st filter appends 1 record and 2nd filter also appends 1 record.
       Original 2 records + 1 record(1st filter) + 1 record(2nd filter) = 4 records.
     */
    if(!TEST_CHECK(4*loop_max ==  got)) {
        TEST_MSG("expect: %d got: %d", 4 * loop_max, got);
    }

    filter_test_destroy(ctx);
}

/* $TAG as a key of rule causes SIGSEGV */
static void flb_test_issue_5846()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    char *p = "[0, {\"key\":\"rewrite\"}]";

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();
    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$TAG ^(rewrite)$ updated false",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "updated",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* ingest record */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */

    /* It is OK, if there is no SIGSEGV. */

    filter_test_destroy(ctx);
}

/*
 * A rule that rewrites a record to the tag it already has makes the emitter
 * re-inject the record into the same filter. The emitter used to register
 * itself as one of its own senders, so pausing it (hot reload or shutdown)
 * recursed until the stack was exhausted.
 */
static void flb_test_self_cycle_issue_12189()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int ret;
    int not_used = 0;
    int bytes;
    int got;
    char *p = "[0, {\"key\":\"cycle\"}]";

    /* Prepare output callback with expected result */
    cb_data.cb = cb_count_msgpack;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    clear_output_num();

    /* The new tag is the tag the filter is matching, so it emits to itself */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Rule", "$key ^(cycle)$ rewrite false",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Configure output */
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "Match", "rewrite",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* ingest record */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, strlen(p));
    TEST_CHECK(bytes == strlen(p));

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    /*
     * The record emitted once is kept by the filter on the second evaluation,
     * the self-emission is rejected instead of looping.
     */
    if (!TEST_CHECK(got == 1)) {
        TEST_MSG("expect: 1 got: %d", got);
    }

    /* Shutdown pauses the inputs, it must not recurse into the emitter */
    filter_test_destroy(ctx);
}

struct group_output {
    int records[3];
};

static int map_has_string(msgpack_object *map, const char *key, const char *value)
{
    size_t i;
    msgpack_object_kv *entry;

    if (map == NULL || map->type != MSGPACK_OBJECT_MAP) {
        return FLB_FALSE;
    }
    for (i = 0; i < map->via.map.size; i++) {
        entry = &map->via.map.ptr[i];
        if (entry->key.type == MSGPACK_OBJECT_STR &&
            entry->key.via.str.size == strlen(key) &&
            memcmp(entry->key.via.str.ptr, key, strlen(key)) == 0 &&
            entry->val.type == MSGPACK_OBJECT_STR &&
            entry->val.via.str.size == strlen(value) &&
            memcmp(entry->val.via.str.ptr, value, strlen(value)) == 0) {
            return FLB_TRUE;
        }
    }
    return FLB_FALSE;
}

static int cb_check_group(void *record, size_t size, void *data)
{
    int ret;
    int id;
    struct group_output *output = data;
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;

    ret = flb_log_event_decoder_init(&decoder, record, size);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        return 0;
    }
    while ((ret = flb_log_event_decoder_next(&decoder, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        if (map_has_string(event.body, "message", "order accepted")) {
            id = 0;
        }
        else if (map_has_string(event.body, "message", "payment authorization failed")) {
            id = 1;
        }
        else {
            TEST_CHECK(map_has_string(event.body, "message", "ungrouped"));
            id = 2;
        }
        TEST_CHECK(map_has_string(event.body, "level", id == 1 ? "error" : "info"));
        TEST_CHECK(map_has_string(event.metadata, "record_attribute", "preserved"));
        TEST_CHECK(event.timestamp.tm.tv_sec == 1700000000);
        TEST_CHECK(event.timestamp.tm.tv_nsec == 123456789);
        if (id < 2) {
            TEST_CHECK(map_has_string(event.group_metadata, "schema", "test-schema"));
            TEST_CHECK(map_has_string(event.group_attributes, "service.name", "checkout"));
            TEST_CHECK(map_has_string(event.group_attributes,
                                     "deployment.environment.name", "production"));
        }
        else {
            TEST_CHECK(event.group_metadata == NULL);
            TEST_CHECK(event.group_attributes == NULL);
        }
        pthread_mutex_lock(&result_mutex);
        output->records[id]++;
        num_output++;
        pthread_mutex_unlock(&result_mutex);
    }
    TEST_CHECK(ret == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA);
    TEST_CHECK(decoder.offset == size);
    flb_log_event_decoder_destroy(&decoder);

    /* Chunk mode borrows the engine's buffer. */
    return 0;
}

static void append_group_test_record(struct flb_log_event_encoder *encoder, int id)
{
    int ret;
    struct flb_time timestamp;
    const char *messages[] = {"order accepted", "payment authorization failed", "ungrouped"};

    ret = flb_log_event_encoder_begin_record(encoder);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    flb_time_set(&timestamp, 1700000000, 123456789);
    ret = flb_log_event_encoder_set_timestamp(encoder, &timestamp);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    ret = flb_log_event_encoder_append_metadata_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("record_attribute"),
            FLB_LOG_EVENT_CSTRING_VALUE("preserved"));
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    ret = flb_log_event_encoder_append_body_values(
            encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("level"),
            FLB_LOG_EVENT_CSTRING_VALUE((id == 1 ? "error" : "info")),
            FLB_LOG_EVENT_CSTRING_VALUE("message"),
            FLB_LOG_EVENT_CSTRING_VALUE(messages[id]));
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    ret = flb_log_event_encoder_commit_record(encoder);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
}

static void check_group_rewrite(int reverse, int keep, int unmatched, int same_tag)
{
    int ret;
    int i;
    int id;
    int got;
    int output_id;
    int expected[3][3] = {{0}};
    char rule[128];
    const char *tags[] = {"routed.info", "routed.error", "rewrite"};
    struct group_output outputs[3] = {{{0}}};
    struct flb_lib_out_cb callbacks[3];
    struct filter_test *ctx;
    struct flb_input_instance *input;
    struct flb_log_event_encoder encoder;

    for (i = 0; i < 3; i++) {
        callbacks[i].cb = cb_check_group;
        callbacks[i].data = &outputs[i];
    }
    ctx = filter_test_create(&callbacks[0]);
    if (!TEST_CHECK(ctx != NULL)) {
        return;
    }
    snprintf(rule, sizeof(rule), "$level %s %s %s",
             unmatched ? "^info$" : "^(info|error)$",
             same_tag ? "routed.info" : "routed.$level",
             keep ? "true" : "false");
    ret = flb_filter_set(ctx->flb, ctx->f_ffd, "Rule", rule, NULL);
    TEST_CHECK(ret == 0);
    for (i = 0; i < 3; i++) {
        output_id = i == 0 ? ctx->o_ffd : flb_output(ctx->flb, "lib", &callbacks[i]);
        TEST_CHECK(output_id >= 0);
        ret = flb_output_set(ctx->flb, output_id, "Match", tags[i],
                             "data_mode", "chunk", NULL);
        TEST_CHECK(ret == 0);
    }
    clear_output_num();
    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return;
    }
    ret = flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        filter_test_destroy(ctx);
        return;
    }
    ret = flb_log_event_encoder_group_init(&encoder);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    ret = flb_log_event_encoder_append_metadata_values(
            &encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("schema"),
            FLB_LOG_EVENT_CSTRING_VALUE("test-schema"));
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    ret = flb_log_event_encoder_append_body_values(
            &encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("service.name"),
            FLB_LOG_EVENT_CSTRING_VALUE("checkout"),
            FLB_LOG_EVENT_CSTRING_VALUE("deployment.environment.name"),
            FLB_LOG_EVENT_CSTRING_VALUE("production"));
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    ret = flb_log_event_encoder_group_header_end(&encoder);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    append_group_test_record(&encoder, reverse ? 1 : 0);
    append_group_test_record(&encoder, reverse ? 0 : 1);
    ret = flb_log_event_encoder_group_end(&encoder);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);
    append_group_test_record(&encoder, 2);

    input = flb_input_get_instance(ctx->flb->config, ctx->i_ffd);
    if (TEST_CHECK(input != NULL)) {
        ret = flb_input_chunk_append_raw(input, FLB_INPUT_LOGS, 3, "rewrite", 7,
                                         encoder.output_buffer, encoder.output_length);
        TEST_CHECK(ret == 0);
    }
    flb_log_event_encoder_destroy(&encoder);
    wait_for_output_num(5000, keep ? 6 : 3, &got);
    filter_test_destroy(ctx);
    TEST_CHECK(get_output_num() == (keep ? 6 : 3));

    for (id = 0; id < 3; id++) {
        if (unmatched && id == 1) {
            expected[2][id] = 1;
        }
        else {
            expected[same_tag || id != 1 ? 0 : 1][id] = 1;
            if (keep) {
                expected[2][id] = 1;
            }
        }
        for (i = 0; i < 3; i++) {
            TEST_CHECK(outputs[i].records[id] == expected[i][id]);
            TEST_MSG("tag=%s record=%d expected=%d got=%d",
                     tags[i], id, expected[i][id], outputs[i].records[id]);
        }
    }
}

static void flb_test_group_split(void)
{
    check_group_rewrite(FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_FALSE);
}

static void flb_test_group_split_reverse(void)
{
    check_group_rewrite(FLB_TRUE, FLB_FALSE, FLB_FALSE, FLB_FALSE);
}

static void flb_test_group_keep(void)
{
    check_group_rewrite(FLB_FALSE, FLB_TRUE, FLB_FALSE, FLB_FALSE);
}

static void flb_test_group_unmatched(void)
{
    check_group_rewrite(FLB_FALSE, FLB_FALSE, FLB_TRUE, FLB_FALSE);
}

static void flb_test_group_same_tag(void)
{
    check_group_rewrite(FLB_FALSE, FLB_FALSE, FLB_FALSE, FLB_TRUE);
}

TEST_LIST = {
    {"group_split", flb_test_group_split},
    {"group_split_reverse", flb_test_group_split_reverse},
    {"group_keep", flb_test_group_keep},
    {"group_unmatched", flb_test_group_unmatched},
    {"group_same_tag", flb_test_group_same_tag},
    {"matched",          flb_test_matched},
    {"not_matched",      flb_test_not_matched},
    {"keep_true",        flb_test_keep_true},
    {"heavy_input_pause_emitter", flb_test_heavy_input_pause_emitter},
    {"busy_emitter_keeps_original", flb_test_busy_emitter_keeps_original},
    {"issue_4518", flb_test_issue_4518},
    {"issue_4793", flb_test_issue_4793},
    {"sigsegv_issue_5846", flb_test_issue_5846},
    {"self_cycle_issue_12189", flb_test_self_cycle_issue_12189},
    {NULL, NULL}
};
