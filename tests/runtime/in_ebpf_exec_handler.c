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
#include "../../plugins/in_ebpf/traces/exec/handler.h"

struct test_context {
    struct trace_event_context event_ctx;
    struct flb_input_instance *ins;
    struct flb_log_event_decoder *decoder;
};

static struct test_context *init_test_context()
{
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

    return (strncmp(key.via.str.ptr, str, key.via.str.size) == 0 &&
            strlen(str) == key.via.str.size);
}

static void verify_decoded_values(struct flb_log_event *event,
                                  const struct event *original)
{
    int seen_pid = FLB_FALSE;
    int seen_stage = FLB_FALSE;
    int seen_ppid = FLB_FALSE;
    int seen_filename = FLB_FALSE;
    int seen_argv = FLB_FALSE;
    int seen_argv1 = FLB_FALSE;
    int seen_argv2 = FLB_FALSE;
    int seen_argv_last = FLB_FALSE;
    int seen_argc = FLB_FALSE;
    int seen_error_raw = FLB_FALSE;
    msgpack_object_kv *kv;
    int i;

    TEST_CHECK(event != NULL);
    TEST_CHECK(event->body->type == MSGPACK_OBJECT_MAP);

    for (i = 0; i < event->body->via.map.size; i++) {
        kv = &event->body->via.map.ptr[i];

        if (key_matches(kv->key, "pid")) {
            seen_pid = FLB_TRUE;
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            TEST_CHECK(kv->val.via.u64 == original->common.pid);
        }
        else if (key_matches(kv->key, "stage")) {
            seen_stage = FLB_TRUE;
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_STR);
            if (original->details.execve.stage == EXECVE_STAGE_ENTER) {
                TEST_CHECK(strncmp(kv->val.via.str.ptr, "enter", kv->val.via.str.size) == 0);
            }
            else if (original->details.execve.stage == EXECVE_STAGE_EXIT) {
                TEST_CHECK(strncmp(kv->val.via.str.ptr, "exit", kv->val.via.str.size) == 0);
            }
            else {
                TEST_CHECK(strncmp(kv->val.via.str.ptr, "unknown", kv->val.via.str.size) == 0);
            }
        }
        else if (key_matches(kv->key, "ppid")) {
            seen_ppid = FLB_TRUE;
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            TEST_CHECK(kv->val.via.u64 == original->details.execve.ppid);
        }
        else if (key_matches(kv->key, "filename")) {
            seen_filename = FLB_TRUE;
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_STR);
            TEST_CHECK(kv->val.via.str.size ==
                       strlen(original->details.execve.filename));
            TEST_CHECK(strncmp(kv->val.via.str.ptr,
                               original->details.execve.filename,
                               kv->val.via.str.size) == 0);
        }
        else if (key_matches(kv->key, "argv")) {
            seen_argv = FLB_TRUE;
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_STR);
            TEST_CHECK(kv->val.via.str.size ==
                       strlen(original->details.execve.argv));
            TEST_CHECK(strncmp(kv->val.via.str.ptr,
                               original->details.execve.argv[0],
                               kv->val.via.str.size) == 0);
        }
        else if (key_matches(kv->key, "argv1")) {
            seen_argv1 = FLB_TRUE;
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_STR);
            TEST_CHECK(strncmp(kv->val.via.str.ptr,
                               original->details.execve.argv[1],
                               kv->val.via.str.size) == 0);
        }
        else if (key_matches(kv->key, "argv2")) {
            seen_argv2 = FLB_TRUE;
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_STR);
            TEST_CHECK(strncmp(kv->val.via.str.ptr,
                               original->details.execve.argv[2],
                               kv->val.via.str.size) == 0);
        }
        else if (key_matches(kv->key, "argv_last")) {
            seen_argv_last = FLB_TRUE;
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_STR);
            TEST_CHECK(strncmp(kv->val.via.str.ptr,
                               original->details.execve.argv_last,
                               kv->val.via.str.size) == 0);
        }
        else if (key_matches(kv->key, "argc")) {
            seen_argc = FLB_TRUE;
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER);
            TEST_CHECK(kv->val.via.u64 == original->details.execve.argc);
        }
        else if (key_matches(kv->key, "error_raw")) {
            seen_error_raw = FLB_TRUE;
            TEST_CHECK(kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER ||
                       kv->val.type == MSGPACK_OBJECT_NEGATIVE_INTEGER);
            TEST_CHECK(kv->val.via.i64 == original->details.execve.error_raw);
        }
    }

    TEST_CHECK(seen_pid == FLB_TRUE);
    TEST_CHECK(seen_stage == FLB_TRUE);
    TEST_CHECK(seen_ppid == FLB_TRUE);
    TEST_CHECK(seen_filename == FLB_TRUE);
    TEST_CHECK(seen_argv == FLB_TRUE);
    TEST_CHECK(seen_argv1 == FLB_TRUE);
    TEST_CHECK(seen_argv2 == FLB_TRUE);
    TEST_CHECK(seen_argv_last == FLB_TRUE);
    TEST_CHECK(seen_argc == FLB_TRUE);
    TEST_CHECK(seen_error_raw == FLB_TRUE);
}

void test_exec_event_encoding()
{
    struct event test_event = {
        .type = EVENT_TYPE_EXECVE,
        .common = {
            .pid = 100,
            .tid = 101,
            .uid = 1000,
            .gid = 1000,
            .comm = "bash"
        },
        .details.execve = {
            .stage = EXECVE_STAGE_EXIT,
            .ppid = 1,
            .filename = "/usr/bin/bash",
            .argv = {"bash", "-lc", "echo hello"},
            .argv_last = "echo hello",
            .argc = 3,
            .error_raw = 0
        }
    };
    struct flb_log_event log_event;
    struct test_context *ctx;
    int ret;

    ctx = init_test_context();
    TEST_CHECK(ctx != NULL);

    ret = encode_exec_event(ctx->ins, ctx->event_ctx.log_encoder, &test_event);
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

void test_trace_exec_handler_negative_paths()
{
    struct test_context *ctx;
    struct event invalid_type_event;
    struct event valid_event;
    int ret;

    ctx = init_test_context();
    TEST_CHECK(ctx != NULL);

    memset(&invalid_type_event, 0, sizeof(struct event));
    invalid_type_event.type = EVENT_TYPE_SIGNAL;
    ret = trace_exec_handler(&ctx->event_ctx, &invalid_type_event, sizeof(struct event));
    TEST_CHECK(ret == -1);

    memset(&valid_event, 0, sizeof(struct event));
    valid_event.type = EVENT_TYPE_EXECVE;
    ret = trace_exec_handler(&ctx->event_ctx, &valid_event, sizeof(struct event) - 1);
    TEST_CHECK(ret == -1);

    cleanup_test_context(ctx);
}

TEST_LIST = {
    {"exec_event_encoding", test_exec_event_encoding},
    {"trace_exec_handler_negative_paths", test_trace_exec_handler_negative_paths},
    {NULL, NULL}
};
