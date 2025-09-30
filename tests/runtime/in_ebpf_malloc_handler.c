#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include "flb_tests_runtime.h"

#include "../../plugins/in_ebpf/traces/includes/common/event_context.h"
#include "../../plugins/in_ebpf/traces/includes/common/events.h"
#include "../../plugins/in_ebpf/traces/includes/common/encoder.h"
#include "../../plugins/in_ebpf/traces/malloc/handler.h"

/* Test context structure */
struct test_context {
    struct trace_event_context event_ctx;
    struct flb_input_instance *ins;
    struct flb_log_event_decoder *decoder;
};

/* Initialize test context */
static struct test_context *init_test_context() {
    struct test_context *ctx = flb_calloc(1, sizeof(struct test_context));
    if (!ctx) {
        return NULL;
    }

    ctx->ins = flb_calloc(1, sizeof(struct flb_input_instance));
    if (!ctx->ins) {
        flb_free(ctx);
        return NULL;
    }

    ctx->event_ctx.log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!ctx->event_ctx.log_encoder) {
        flb_free(ctx->ins);
        flb_free(ctx);
        return NULL;
    }

    ctx->decoder = flb_log_event_decoder_create(NULL, 0);
    if (!ctx->decoder) {
        flb_log_event_encoder_destroy(ctx->event_ctx.log_encoder);
        flb_free(ctx->ins);
        flb_free(ctx);
        return NULL;
    }

    ctx->ins->context = &ctx->event_ctx;
    ctx->event_ctx.ins = ctx->ins;

    return ctx;
}

/* Cleanup test context */
static void cleanup_test_context(struct test_context *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->decoder) {
        flb_log_event_decoder_destroy(ctx->decoder);
    }

    if (ctx->event_ctx.log_encoder) {
        flb_log_event_encoder_destroy(ctx->event_ctx.log_encoder);
    }

    if (ctx->ins) {
        flb_free(ctx->ins);
    }

    flb_free(ctx);
}

/* Helper function to check if a msgpack object key matches a string */
static int key_matches(msgpack_object key, const char *str) {
    if (key.type != MSGPACK_OBJECT_STR) {
        return 0;
    }
    return (strncmp(key.via.str.ptr, str, key.via.str.size) == 0 &&
            strlen(str) == key.via.str.size);
}

/* Helper function to verify decoded values */
static void verify_decoded_values(struct flb_log_event *event, const struct event *original) {
    msgpack_object_kv *kv;
    int i;

    TEST_CHECK(event != NULL);
    TEST_CHECK(event->body->type == MSGPACK_OBJECT_MAP);

    /* Iterate through map to find and verify values */
    for (i = 0; i < event->body->via.map.size; i++) {
        kv = &event->body->via.map.ptr[i];
        
        if (key_matches(kv->key, "pid")) {
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            TEST_CHECK(kv->val.via.u64 == original->common.pid);
        }
        else if (key_matches(kv->key, "comm")) {
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_STR);
            TEST_CHECK(strncmp(kv->val.via.str.ptr, original->common.comm, 
                             kv->val.via.str.size) == 0);
        }
        else if (key_matches(kv->key, "operation")) {
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
                      kv->val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER);
            TEST_CHECK(kv->val.via.i64 == original->details.mem.operation);
        }
        else if (key_matches(kv->key, "address")) {
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            TEST_CHECK(kv->val.via.u64 == original->details.mem.addr);
        }
        else if (key_matches(kv->key, "size")) {
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            TEST_CHECK(kv->val.via.u64 == original->details.mem.size);
        }
    }
}

/* Test encoding and decoding of malloc events */
void test_malloc_event_encoding() {
    struct test_context *ctx = init_test_context();
    TEST_CHECK(ctx != NULL);

    struct event test_event = {
        .type = EVENT_TYPE_MEM,
        .common = {
            .pid = 12345,
            .comm = "test_process"
        },
        .details.mem = {
            .operation = 1,  // Allocation
            .addr = 0x7fff1234000,
            .size = 4096
        }
    };

    /* Test encoding */
    int ret = encode_malloc_event(ctx->ins, ctx->event_ctx.log_encoder, &test_event);
    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx->event_ctx.log_encoder->output_length > 0);

    /* Initialize decoder with encoded data */
    ret = flb_log_event_decoder_init(ctx->decoder, 
                                   ctx->event_ctx.log_encoder->output_buffer,
                                   ctx->event_ctx.log_encoder->output_length);
    TEST_CHECK(ret == 0);

    /* Decode and verify */
    struct flb_log_event log_event;
    ret = flb_log_event_decoder_next(ctx->decoder, &log_event);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    /* Verify decoded values match original event */
    verify_decoded_values(&log_event, &test_event);

    cleanup_test_context(ctx);
}

/* Define test cases */
TEST_LIST = {
    {"malloc_event_encoding", test_malloc_event_encoding},
    {NULL, NULL}
};