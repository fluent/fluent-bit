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
#include <fluent-bit/flb_chunk_trace.h>
#include <fluent-bit/flb_router.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include "flb_tests_runtime.h"

#define FLB_TEST_MAX_WAIT 60

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
        /* We should check ctx->num_records has a valid value. */
        if (ctx->num_records < 0) {
            return -1;
        }
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

void do_test_records_trace(void (*records_cb)(struct callback_records *))
{
    flb_ctx_t    *ctx    = NULL;
    struct flb_input_instance *input;
    struct flb_output_instance *output;
    int i;
    struct flb_lib_out_cb cb;
    struct callback_records *records;

    records = flb_calloc(1, sizeof(struct callback_records));
    records->num_records = 0;
    records->records = NULL;
    cb.cb   = callback_add_record;
    cb.data = (void *)records;

    ctx = flb_create();

    input = flb_input_new(ctx->config, "dummy", NULL, FLB_TRUE);
    TEST_CHECK(input != NULL);

    output = flb_output_new(ctx->config, (char *) "stdout", NULL, FLB_TRUE);
    TEST_CHECK(output != NULL);

    TEST_CHECK(flb_service_set(ctx, "Flush", "0.5",
                                    "Grace", "1",
                                    "Enable_Chunk_Trace", "On",
                                    NULL) == 0);


    flb_router_connect_direct(input, output);

    TEST_CHECK(flb_chunk_trace_context_new(input, "lib", "test.", (void *)&cb, NULL) != NULL);
    
    /* Start test */
    TEST_CHECK(flb_start(ctx) == 0);

    /* Wait at most FLB_TEST_MAX_WAIT seconds for the dummy input, and trace callback */
    for(i = 0; records->num_records == 0 && i < FLB_TEST_MAX_WAIT; i++ ) {
        sleep(1);
    }
    flb_info("[test] collected records, waited %d seconds", i);

    records_cb(records);
    
    flb_stop(ctx);
    sleep(5);

    for (i = 0; i < records->num_records; i++) {
        flb_lib_free(records->records[i].data);
    }
    flb_free(records->records);
    flb_free(records);

    flb_destroy(ctx);
}

void flb_test_dummy_records_trace_simple(struct callback_records *records)
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
            //TEST_CHECK(ftm.tm.tv_sec == 1234);
            //TEST_CHECK(ftm.tm.tv_nsec == 1234);
        }
        msgpack_unpacked_destroy(&result);
    }
}

void flb_test_trace()
{
    do_test_records_trace(flb_test_dummy_records_trace_simple);
}

/* Test list */
TEST_LIST = {
#ifdef FLB_HAVE_CHUNK_TRACE
    {"trace",    flb_test_trace},
#endif
    {NULL, NULL}
};
