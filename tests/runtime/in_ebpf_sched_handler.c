#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "flb_tests_runtime.h"

#include "../../plugins/in_ebpf/traces/includes/common/event_context.h"
#include "../../plugins/in_ebpf/traces/includes/common/events.h"
#include "../../plugins/in_ebpf/traces/sched/handler.h"

struct test_context {
    struct trace_event_context event_ctx;
    struct flb_input_instance *ins;
    struct flb_log_event_decoder *decoder;
};

static struct test_context *init_test_context()
{
    struct test_context *ctx;

    ctx = flb_calloc(1, sizeof(struct test_context));
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

static void cleanup_test_context(struct test_context *ctx)
{
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

static int key_matches(msgpack_object key, const char *str)
{
    if (key.type != MSGPACK_OBJECT_STR) {
        return 0;
    }

    return strncmp(key.via.str.ptr, str, key.via.str.size) == 0 &&
           strlen(str) == key.via.str.size;
}

static void verify_decoded_values(struct flb_log_event *event,
                                  const struct event *original)
{
    msgpack_object_kv *kv;
    int i;

    TEST_CHECK(event != NULL);
    TEST_CHECK(event->body->type == MSGPACK_OBJECT_MAP);

    for (i = 0; i < event->body->via.map.size; i++) {
        kv = &event->body->via.map.ptr[i];

        if (key_matches(kv->key, "event_type")) {
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_STR);
            TEST_CHECK(strncmp(kv->val.via.str.ptr, "sched", kv->val.via.str.size) == 0);
        }
        else if (key_matches(kv->key, "cpu")) {
            TEST_CHECK(kv->val.via.u64 == original->details.sched.cpu);
        }
        else if (key_matches(kv->key, "prev_pid")) {
            TEST_CHECK(kv->val.via.u64 == original->details.sched.prev_pid);
        }
        else if (key_matches(kv->key, "next_pid")) {
            TEST_CHECK(kv->val.via.u64 == original->details.sched.next_pid);
        }
        else if (key_matches(kv->key, "runq_latency_ns")) {
            TEST_CHECK(kv->val.via.u64 == original->details.sched.runq_latency_ns);
        }
    }
}

void test_sched_event_encoding()
{
    struct test_context *ctx;
    struct flb_log_event log_event;
    struct event test_event;
    int ret;

    ctx = init_test_context();
    TEST_CHECK(ctx != NULL);

    memset(&test_event, 0, sizeof(struct event));
    test_event.type = EVENT_TYPE_SCHED;
    test_event.common.pid = 4321;
    test_event.common.tid = 4321;
    memcpy(test_event.common.comm, "sched_test", strlen("sched_test"));

    test_event.details.sched.prev_pid = 1111;
    test_event.details.sched.prev_prio = 120;
    test_event.details.sched.prev_state = 1;
    test_event.details.sched.next_pid = 4321;
    test_event.details.sched.next_prio = 90;
    test_event.details.sched.cpu = 3;
    test_event.details.sched.runq_latency_ns = 125000;
    test_event.details.sched.wakeup_tracked = 1;

    ret = encode_sched_event(ctx->event_ctx.log_encoder, &test_event);
    TEST_CHECK(ret == 0);
    TEST_CHECK(ctx->event_ctx.log_encoder->output_length > 0);

    ret = flb_log_event_decoder_init(ctx->decoder,
                                     ctx->event_ctx.log_encoder->output_buffer,
                                     ctx->event_ctx.log_encoder->output_length);
    TEST_CHECK(ret == 0);

    ret = flb_log_event_decoder_next(ctx->decoder, &log_event);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    verify_decoded_values(&log_event, &test_event);

    cleanup_test_context(ctx);
}

TEST_LIST = {
    {"sched_event_encoding", test_sched_event_encoding},
    {NULL, NULL}
};
