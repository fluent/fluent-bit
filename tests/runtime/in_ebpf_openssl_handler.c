#include <stdio.h>
#include <string.h>

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_input_plugin.h>

#include "flb_tests_runtime.h"

#include "../../plugins/in_ebpf/traces/includes/common/event_context.h"
#include "../../plugins/in_ebpf/traces/includes/common/events.h"
#include "../../plugins/in_ebpf/traces/openssl/handler.h"

struct test_context {
    struct trace_event_context event_ctx;
    struct flb_input_instance *ins;
};

static struct test_context *init_test_context(void)
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

    ctx->ins->context = &ctx->event_ctx;
    ctx->event_ctx.ins = ctx->ins;

    return ctx;
}

static void cleanup_test_context(struct test_context *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->event_ctx.log_encoder) {
        flb_log_event_encoder_destroy(ctx->event_ctx.log_encoder);
    }

    if (ctx->ins) {
        flb_free(ctx->ins);
    }

    flb_free(ctx);
}

void test_openssl_event_encoding(void)
{
    struct test_context *ctx;
    struct event ev = {0};
    int ret;
    int i;
    int types[] = {
        EVENT_TYPE_TLS_HANDSHAKE,
        EVENT_TYPE_TLS_READ,
        EVENT_TYPE_TLS_WRITE,
        EVENT_TYPE_TLS_SHUTDOWN
    };

    ctx = init_test_context();
    TEST_CHECK(ctx != NULL);

    for (i = 0; i < (int) (sizeof(types) / sizeof(types[0])); i++) {
        memset(&ev, 0, sizeof(ev));
        ev.type = types[i];
        ev.common.pid = 101;
        ev.common.tid = 202;
        strncpy(ev.common.comm, "openssl", sizeof(ev.common.comm));
        ev.details.tls_io.ssl_ptr = 0x1234;
        ev.details.tls_io.latency_ns = 5000;
        ev.details.tls_io.ret = 1;

        ret = encode_openssl_event(ctx->event_ctx.log_encoder, &ev);
        TEST_CHECK(ret == 0);
    }

    cleanup_test_context(ctx);
}

void test_openssl_event_encoding_rejects_unknown_type(void)
{
    struct test_context *ctx;
    struct event ev = {0};
    int ret;

    ctx = init_test_context();
    TEST_CHECK(ctx != NULL);

    ev.type = EVENT_TYPE_SCHED;
    ev.common.pid = 101;
    ev.common.tid = 202;
    strncpy(ev.common.comm, "openssl", sizeof(ev.common.comm));

    ret = encode_openssl_event(ctx->event_ctx.log_encoder, &ev);
    TEST_CHECK(ret == -1);
    TEST_CHECK(ctx->event_ctx.log_encoder->output_length == 0);

    cleanup_test_context(ctx);
}

TEST_LIST = {
    {"openssl_event_encoding", test_openssl_event_encoding},
    {"openssl_event_encoding_rejects_unknown_type",
     test_openssl_event_encoding_rejects_unknown_type},
    {NULL, NULL}
};
