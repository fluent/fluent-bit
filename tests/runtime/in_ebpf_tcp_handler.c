#include <stdio.h>
#include <string.h>

#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_input_plugin.h>

#include "flb_tests_runtime.h"

#include "../../plugins/in_ebpf/traces/includes/common/event_context.h"
#include "../../plugins/in_ebpf/traces/includes/common/events.h"
#include "../../plugins/in_ebpf/traces/tcp/handler.h"

struct test_context {
    struct trace_event_context event_ctx;
    struct flb_input_instance *ins;
    struct flb_log_event_decoder *decoder;
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

void test_tcp_event_encoding(void)
{
    struct test_context *ctx;
    struct event listen_ev = {0};
    struct event accept_ev = {0};
    struct event connect_ev = {0};
    int ret;

    ctx = init_test_context();
    TEST_CHECK(ctx != NULL);

    listen_ev.type = EVENT_TYPE_LISTEN;
    listen_ev.common.pid = 100;
    listen_ev.common.tid = 101;
    strncpy(listen_ev.common.comm, "tcpd", sizeof(listen_ev.common.comm));
    listen_ev.details.listen.fd = 3;
    listen_ev.details.listen.backlog = 128;
    listen_ev.details.listen.error_raw = 0;

    ret = encode_tcp_event(ctx->ins, ctx->event_ctx.log_encoder, &listen_ev);
    TEST_CHECK(ret == 0);

    accept_ev.type = EVENT_TYPE_ACCEPT;
    accept_ev.common.pid = 100;
    accept_ev.common.tid = 101;
    strncpy(accept_ev.common.comm, "tcpd", sizeof(accept_ev.common.comm));
    accept_ev.details.accept.fd = 3;
    accept_ev.details.accept.new_fd = 5;
    accept_ev.details.accept.peer.version = 4;
    accept_ev.details.accept.peer.port = 443;
    accept_ev.details.accept.peer.addr_raw.v4 = 0x0100007f;
    accept_ev.details.accept.error_raw = 0;

    ret = encode_tcp_event(ctx->ins, ctx->event_ctx.log_encoder, &accept_ev);
    TEST_CHECK(ret == 0);

    connect_ev.type = EVENT_TYPE_CONNECT;
    connect_ev.common.pid = 200;
    connect_ev.common.tid = 201;
    strncpy(connect_ev.common.comm, "curl", sizeof(connect_ev.common.comm));
    connect_ev.details.connect.fd = 7;
    connect_ev.details.connect.remote.version = 4;
    connect_ev.details.connect.remote.port = 80;
    connect_ev.details.connect.remote.addr_raw.v4 = 0x0101a8c0;
    connect_ev.details.connect.error_raw = 0;

    ret = encode_tcp_event(ctx->ins, ctx->event_ctx.log_encoder, &connect_ev);
    TEST_CHECK(ret == 0);

    connect_ev.details.connect.remote.version = 6;
    connect_ev.details.connect.remote.port = 8080;
    connect_ev.details.connect.remote.addr_raw.v6[0] = 0x20010db8;
    connect_ev.details.connect.remote.addr_raw.v6[1] = 0;
    connect_ev.details.connect.remote.addr_raw.v6[2] = 0;
    connect_ev.details.connect.remote.addr_raw.v6[3] = 1;

    ret = encode_tcp_event(ctx->ins, ctx->event_ctx.log_encoder, &connect_ev);
    TEST_CHECK(ret == 0);

    cleanup_test_context(ctx);
}

TEST_LIST = {
    {"tcp_event_encoding", test_tcp_event_encoding},
    {NULL, NULL}
};
