/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_input_ingest.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_time.h>

#include <pthread.h>
#include <string.h>

#include "flb_tests_internal.h"

/*
 * Test input: it has no native collection. Stream bytes become one log
 * record per payload and requests are answered with status 201 and the
 * request path as body.
 */
struct ingest_test_state {
    pthread_mutex_t lock;
    int gate_closed;             /* cb_ingest waits while set          */
    int pause_request;           /* served by the plugin timer         */
    int resume_request;
    int paused;
    int ingest_calls;
    size_t ingest_bytes;
    int in_flight;
    int output_records;
    int replies;
    int reply_outcome[8];
    int reply_status[8];
    char reply_body[8][64];
    char last_payload[64];
    char last_header[64];
};

static struct ingest_test_state state;

struct ingest_test_context {
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *encoder;
};

static int state_get(int *field)
{
    int value;

    pthread_mutex_lock(&state.lock);
    value = *field;
    pthread_mutex_unlock(&state.lock);

    return value;
}

static void state_set(int *field, int value)
{
    pthread_mutex_lock(&state.lock);
    *field = value;
    pthread_mutex_unlock(&state.lock);
}

static int state_wait(int *field, int expected)
{
    int i;

    for (i = 0; i < 500; i++) {
        if (state_get(field) == expected) {
            return 0;
        }
        flb_time_msleep(10);
    }

    return -1;
}

static void state_reset(void)
{
    pthread_mutex_lock(&state.lock);
    state.gate_closed = FLB_FALSE;
    state.pause_request = FLB_FALSE;
    state.resume_request = FLB_FALSE;
    state.paused = FLB_FALSE;
    state.ingest_calls = 0;
    state.ingest_bytes = 0;
    state.in_flight = 0;
    state.output_records = 0;
    state.replies = 0;
    memset(state.reply_outcome, 0, sizeof(state.reply_outcome));
    memset(state.reply_status, 0, sizeof(state.reply_status));
    memset(state.reply_body, 0, sizeof(state.reply_body));
    memset(state.last_payload, 0, sizeof(state.last_payload));
    memset(state.last_header, 0, sizeof(state.last_header));
    pthread_mutex_unlock(&state.lock);
}

static int ingest_test_timer(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    (void) config;
    (void) in_context;

    if (state_get(&state.pause_request) == FLB_TRUE) {
        state_set(&state.pause_request, FLB_FALSE);
        flb_input_pause(ins);
        ins->mem_buf_status = FLB_INPUT_PAUSED;
        state_set(&state.paused, FLB_TRUE);
    }
    else if (state_get(&state.resume_request) == FLB_TRUE) {
        state_set(&state.resume_request, FLB_FALSE);
        ins->mem_buf_status = FLB_INPUT_RUNNING;
        flb_input_resume(ins);
        state_set(&state.paused, FLB_FALSE);
    }

    return 0;
}

static int ingest_test_init(struct flb_input_instance *ins,
                            struct flb_config *config, void *data)
{
    int ret;
    struct ingest_test_context *ctx;

    (void) data;

    ctx = flb_calloc(1, sizeof(struct ingest_test_context));
    if (ctx == NULL) {
        return -1;
    }

    ctx->ins = ins;
    ctx->encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ctx->encoder == NULL) {
        flb_free(ctx);
        return -1;
    }

    flb_input_set_context(ins, ctx);

    ret = flb_input_set_collector_time(ins, ingest_test_timer, 0, 20000000, config);
    if (ret < 0) {
        flb_log_event_encoder_destroy(ctx->encoder);
        flb_free(ctx);
        return -1;
    }

    return 0;
}

static int ingest_test_exit(void *data, struct flb_config *config)
{
    struct ingest_test_context *ctx;

    (void) config;

    ctx = data;
    flb_log_event_encoder_destroy(ctx->encoder);
    flb_free(ctx);

    return 0;
}

static void ingest_test_pause(void *data, struct flb_config *config)
{
    (void) data;
    (void) config;
}

static void ingest_test_resume(void *data, struct flb_config *config)
{
    (void) data;
    (void) config;
}

static int ingest_test_ingest(struct flb_input_instance *ins, void *in_context,
                              const struct flb_input_ingest_event *event)
{
    int ret;
    size_t length;
    struct flb_input_ingest_reply reply;
    struct flb_input_ingest_header header;
    struct ingest_test_context *ctx;

    ctx = in_context;

    state_set(&state.in_flight, 1);
    while (state_get(&state.gate_closed) == FLB_TRUE) {
        flb_time_msleep(5);
    }

    pthread_mutex_lock(&state.lock);
    state.ingest_calls++;
    state.ingest_bytes += event->size;
    length = event->size;
    if (length >= sizeof(state.last_payload)) {
        length = sizeof(state.last_payload) - 1;
    }
    memcpy(state.last_payload, event->data, length);
    state.last_payload[length] = '\0';
    pthread_mutex_unlock(&state.lock);

    state_set(&state.in_flight, 0);

    if (event->kind == FLB_INPUT_INGEST_HTTP_REQUEST) {
        if (event->header_count > 0) {
            pthread_mutex_lock(&state.lock);
            snprintf(state.last_header, sizeof(state.last_header), "%s=%s",
                     event->headers[0].name, event->headers[0].value);
            pthread_mutex_unlock(&state.lock);
        }

        if (strcmp(event->path, "/noreply") == 0) {
            return -1;
        }

        header.name = "x-method";
        header.name_len = 8;
        header.value = event->method;
        header.value_len = event->method_len;

        memset(&reply, 0, sizeof(reply));
        reply.status = 201;
        reply.headers = &header;
        reply.header_count = 1;
        reply.body = event->path;
        reply.body_size = event->path_len;

        ret = flb_input_ingest_event_reply(event, &reply);
        TEST_CHECK(ret == 0);

        /* A second reply for the same request is refused */
        ret = flb_input_ingest_event_reply(event, &reply);
        TEST_CHECK(ret == -1);

        return 0;
    }

    if (event->size == 4 && memcmp(event->data, "FAIL", 4) == 0) {
        flb_input_ingest_fail(ins);
        return -1;
    }

    flb_log_event_encoder_reset(ctx->encoder);
    ret = flb_log_event_encoder_begin_record(ctx->encoder);
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(ctx->encoder);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(
                  ctx->encoder,
                  FLB_LOG_EVENT_CSTRING_VALUE("log"),
                  FLB_LOG_EVENT_STRING_VALUE(event->data, event->size));
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->encoder);
    }
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    return flb_input_log_append(ins, NULL, 0,
                                ctx->encoder->output_buffer,
                                ctx->encoder->output_length);
}

static struct flb_input_plugin ingest_test_plugin = {
    .name         = "ingest_test",
    .description  = "host-driven ingestion test input",
    .cb_init      = ingest_test_init,
    .cb_pause     = ingest_test_pause,
    .cb_resume    = ingest_test_resume,
    .cb_exit      = ingest_test_exit,
    .cb_ingest    = ingest_test_ingest,
    .ingest_kinds = FLB_INPUT_INGEST_STREAM_BYTES | FLB_INPUT_INGEST_HTTP_REQUEST
};

static int cb_output(void *record, size_t size, void *data)
{
    (void) data;

    pthread_mutex_lock(&state.lock);
    state.output_records += flb_mp_count(record, size);
    pthread_mutex_unlock(&state.lock);

    flb_free(record);

    return 0;
}

static void cb_reply(int outcome, const struct flb_input_ingest_reply *reply,
                     void *data)
{
    int slot;
    size_t length;

    slot = (int) (size_t) data;

    pthread_mutex_lock(&state.lock);
    state.replies++;
    if (slot >= 0 && slot < 8) {
        /* A second callback for the same request would show up here */
        state.reply_outcome[slot] += outcome + 100;
        if (reply != NULL) {
            state.reply_status[slot] = reply->status;
            length = reply->body_size;
            if (length >= sizeof(state.reply_body[slot])) {
                length = sizeof(state.reply_body[slot]) - 1;
            }
            memcpy(state.reply_body[slot], reply->body, length);
            state.reply_body[slot][length] = '\0';
        }
    }
    pthread_mutex_unlock(&state.lock);
}

struct test_ctx {
    flb_ctx_t *flb;
    struct flb_input_instance *ins;
    struct flb_lib_out_cb callback;
};

static int register_plugin(flb_ctx_t *flb, struct flb_input_plugin *source,
                           const char *name)
{
    struct flb_input_plugin *plugin;

    plugin = flb_malloc(sizeof(struct flb_input_plugin));
    if (plugin == NULL) {
        return -1;
    }

    memcpy(plugin, source, sizeof(struct flb_input_plugin));
    plugin->name = (char *) name;
    mk_list_add(&plugin->_head, &flb->config->in_plugins);

    return 0;
}

static struct flb_input_instance *instance_get(flb_ctx_t *flb, int ffd)
{
    struct mk_list *head;
    struct flb_input_instance *ins;

    mk_list_foreach(head, &flb->config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        if (ins->id == ffd) {
            return ins;
        }
    }

    return NULL;
}

static int test_ctx_create(struct test_ctx *ctx, const char *mode, int start)
{
    int ret;
    int in_ffd;
    int out_ffd;

    pthread_mutex_init(&state.lock, NULL);
    state_reset();

    memset(ctx, 0, sizeof(struct test_ctx));

    ctx->flb = flb_create();
    if (!TEST_CHECK(ctx->flb != NULL)) {
        return -1;
    }

    flb_service_set(ctx->flb, "flush", "0.2", "grace", "1", "log_level", "error", NULL);

    ret = register_plugin(ctx->flb, &ingest_test_plugin, "ingest_test");
    TEST_CHECK(ret == 0);

    in_ffd = flb_input(ctx->flb, "ingest_test", NULL);
    if (!TEST_CHECK(in_ffd >= 0)) {
        return -1;
    }

    if (mode != NULL) {
        ret = flb_input_set(ctx->flb, in_ffd, "source.mode", mode, NULL);
        TEST_CHECK(ret == 0);
    }

    ctx->ins = instance_get(ctx->flb, in_ffd);
    TEST_CHECK(ctx->ins != NULL);

    ctx->callback.cb = cb_output;
    ctx->callback.data = NULL;

    out_ffd = flb_output(ctx->flb, "lib", &ctx->callback);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx->flb, out_ffd, "match", "*", NULL);

    if (start == FLB_TRUE) {
        ret = flb_start(ctx->flb);
        if (!TEST_CHECK(ret == 0)) {
            flb_destroy(ctx->flb);
            return -1;
        }
    }

    return 0;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
}

static int submit_bytes(struct test_ctx *ctx, const char *data, size_t size)
{
    return flb_input_ingest_submit(ctx->ins, FLB_INPUT_INGEST_STREAM_BYTES,
                                   data, size, NULL, NULL, NULL);
}

static void test_submit_and_ownership(void)
{
    int ret;
    char payload[32];
    struct test_ctx ctx;

    if (test_ctx_create(&ctx, "external", FLB_TRUE) != 0) {
        return;
    }

    /* Hold the dispatch so the copy is observed after the caller reuses it */
    state_set(&state.gate_closed, FLB_TRUE);

    strcpy(payload, "first payload");
    ret = submit_bytes(&ctx, payload, strlen(payload));
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    memset(payload, 'x', sizeof(payload));

    state_set(&state.gate_closed, FLB_FALSE);

    TEST_CHECK(state_wait(&state.ingest_calls, 1) == 0);
    TEST_CHECK(strcmp(state.last_payload, "first payload") == 0);
    TEST_CHECK(state_wait(&state.output_records, 1) == 0);

    /* An empty payload is a valid submission */
    ret = submit_bytes(&ctx, NULL, 0);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    TEST_CHECK(state_wait(&state.ingest_calls, 2) == 0);

    test_ctx_destroy(&ctx);
}

static void test_argument_and_mode_results(void)
{
    int ret;
    struct test_ctx ctx;
    struct flb_input_ingest_request request;

    /* Native mode: the plugin collects on its own */
    if (test_ctx_create(&ctx, NULL, FLB_TRUE) != 0) {
        return;
    }
    ret = submit_bytes(&ctx, "data", 4);
    TEST_CHECK(ret == FLB_INPUT_INGEST_NOT_SUPPORTED);
    test_ctx_destroy(&ctx);

    /* External mode, engine not started yet */
    if (test_ctx_create(&ctx, "external", FLB_FALSE) != 0) {
        return;
    }
    ret = submit_bytes(&ctx, "data", 4);
    TEST_CHECK(ret == FLB_INPUT_INGEST_NOT_RUNNING);

    ret = flb_start(ctx.flb);
    TEST_CHECK(ret == 0);

    ret = flb_input_ingest_submit(NULL, FLB_INPUT_INGEST_STREAM_BYTES,
                                  "data", 4, NULL, NULL, NULL);
    TEST_CHECK(ret == FLB_INPUT_INGEST_ERROR);

    ret = flb_input_ingest_submit(ctx.ins, 64, "data", 4, NULL, NULL, NULL);
    TEST_CHECK(ret == FLB_INPUT_INGEST_ERROR);

    ret = flb_input_ingest_submit(ctx.ins, FLB_INPUT_INGEST_STREAM_BYTES,
                                  NULL, 4, NULL, NULL, NULL);
    TEST_CHECK(ret == FLB_INPUT_INGEST_ERROR);

    /* A request needs its context and a stream must not carry one */
    ret = flb_input_ingest_submit(ctx.ins, FLB_INPUT_INGEST_HTTP_REQUEST,
                                  "data", 4, NULL, NULL, NULL);
    TEST_CHECK(ret == FLB_INPUT_INGEST_ERROR);

    memset(&request, 0, sizeof(request));
    ret = flb_input_ingest_submit(ctx.ins, FLB_INPUT_INGEST_STREAM_BYTES,
                                  "data", 4, &request, NULL, NULL);
    TEST_CHECK(ret == FLB_INPUT_INGEST_ERROR);

    TEST_CHECK(state_get(&state.ingest_calls) == 0);

    test_ctx_destroy(&ctx);
}

static void test_unsupported_plugin_configuration(void)
{
    int ret;
    int in_ffd;
    flb_ctx_t *flb;
    struct flb_input_plugin plugin;
    struct flb_input_instance *ins;

    pthread_mutex_init(&state.lock, NULL);
    state_reset();

    /* A plugin without the hook cannot be configured in external mode */
    flb = flb_create();
    TEST_CHECK(flb != NULL);
    flb_service_set(flb, "log_level", "off", NULL);

    memcpy(&plugin, &ingest_test_plugin, sizeof(plugin));
    plugin.cb_ingest = NULL;
    plugin.ingest_kinds = 0;
    ret = register_plugin(flb, &plugin, "ingest_none");
    TEST_CHECK(ret == 0);

    in_ffd = flb_input(flb, "ingest_none", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(flb, in_ffd, "source.mode", "external", NULL);
    flb_output(flb, "null", NULL);

    ret = flb_start(flb);
    TEST_CHECK(ret != 0);
    flb_destroy(flb);

    /* A hook that only understands streams refuses requests */
    flb = flb_create();
    TEST_CHECK(flb != NULL);
    flb_service_set(flb, "log_level", "off", NULL);

    memcpy(&plugin, &ingest_test_plugin, sizeof(plugin));
    plugin.ingest_kinds = FLB_INPUT_INGEST_STREAM_BYTES;
    ret = register_plugin(flb, &plugin, "ingest_stream");
    TEST_CHECK(ret == 0);

    in_ffd = flb_input(flb, "ingest_stream", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(flb, in_ffd, "source.mode", "external", NULL);
    flb_output(flb, "null", NULL);
    ins = instance_get(flb, in_ffd);

    ret = flb_start(flb);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        struct flb_input_ingest_request request;

        memset(&request, 0, sizeof(request));
        request.method = "POST";
        request.method_len = 4;
        request.path = "/";
        request.path_len = 1;

        ret = flb_input_ingest_submit(ins, FLB_INPUT_INGEST_HTTP_REQUEST,
                                      NULL, 0, &request, NULL, NULL);
        TEST_CHECK(ret == FLB_INPUT_INGEST_NOT_SUPPORTED);
        flb_stop(flb);
    }
    flb_destroy(flb);

    /* Options of the native collection are refused */
    flb = flb_create();
    TEST_CHECK(flb != NULL);
    flb_service_set(flb, "log_level", "off", NULL);
    ret = register_plugin(flb, &ingest_test_plugin, "ingest_test");
    TEST_CHECK(ret == 0);
    in_ffd = flb_input(flb, "ingest_test", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(flb, in_ffd, "source.mode", "external", "threaded", "true", NULL);
    flb_output(flb, "null", NULL);
    ret = flb_start(flb);
    TEST_CHECK(ret != 0);
    flb_destroy(flb);

    /* Unknown mode */
    flb = flb_create();
    TEST_CHECK(flb != NULL);
    flb_service_set(flb, "log_level", "off", NULL);
    ret = register_plugin(flb, &ingest_test_plugin, "ingest_test");
    TEST_CHECK(ret == 0);
    in_ffd = flb_input(flb, "ingest_test", NULL);
    TEST_CHECK(in_ffd >= 0);
    ret = flb_input_set(flb, in_ffd, "source.mode", "sideways", NULL);
    TEST_CHECK(ret != 0);
    flb_destroy(flb);
}

static void test_too_large(void)
{
    int i;
    int ret;
    char *buffer;
    struct test_ctx ctx;
    struct flb_input_ingest_request request;
    struct flb_input_ingest_header headers[FLB_INPUT_INGEST_HEADER_MAX + 1];

    if (test_ctx_create(&ctx, "external", FLB_TRUE) != 0) {
        return;
    }

    buffer = flb_malloc(FLB_INPUT_INGEST_EVENT_MAX + 1);
    if (!TEST_CHECK(buffer != NULL)) {
        test_ctx_destroy(&ctx);
        return;
    }
    memset(buffer, 'a', FLB_INPUT_INGEST_EVENT_MAX + 1);

    /* The largest payload is accepted, one more byte never is */
    ret = submit_bytes(&ctx, buffer, FLB_INPUT_INGEST_EVENT_MAX);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);

    ret = submit_bytes(&ctx, buffer, FLB_INPUT_INGEST_EVENT_MAX + 1);
    TEST_CHECK(ret == FLB_INPUT_INGEST_TOO_LARGE);

    /* The limit covers the context: small body, oversized header */
    memset(&request, 0, sizeof(request));
    request.method = "POST";
    request.method_len = 4;
    request.path = "/";
    request.path_len = 1;
    headers[0].name = "x-large";
    headers[0].name_len = 7;
    headers[0].value = buffer;
    headers[0].value_len = FLB_INPUT_INGEST_EVENT_MAX;
    request.headers = headers;
    request.header_count = 1;

    ret = flb_input_ingest_submit(ctx.ins, FLB_INPUT_INGEST_HTTP_REQUEST,
                                  "body", 4, &request, NULL, NULL);
    TEST_CHECK(ret == FLB_INPUT_INGEST_TOO_LARGE);

    /* Header count */
    for (i = 0; i <= FLB_INPUT_INGEST_HEADER_MAX; i++) {
        headers[i].name = "a";
        headers[i].name_len = 1;
        headers[i].value = "b";
        headers[i].value_len = 1;
    }
    request.header_count = FLB_INPUT_INGEST_HEADER_MAX + 1;
    ret = flb_input_ingest_submit(ctx.ins, FLB_INPUT_INGEST_HTTP_REQUEST,
                                  "body", 4, &request, NULL, NULL);
    TEST_CHECK(ret == FLB_INPUT_INGEST_TOO_LARGE);

    request.header_count = FLB_INPUT_INGEST_HEADER_MAX;
    ret = flb_input_ingest_submit(ctx.ins, FLB_INPUT_INGEST_HTTP_REQUEST,
                                  "body", 4, &request, NULL, NULL);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);

    TEST_CHECK(state_wait(&state.ingest_calls, 2) == 0);

    flb_free(buffer);
    test_ctx_destroy(&ctx);
}

static void test_busy_and_resubmit(void)
{
    int i;
    int ret;
    struct test_ctx ctx;

    if (test_ctx_create(&ctx, "external", FLB_TRUE) != 0) {
        return;
    }

    pthread_mutex_lock(&ctx.ins->ingress_queue_lock);
    ctx.ins->ingress_queue_event_limit = 4;
    pthread_mutex_unlock(&ctx.ins->ingress_queue_lock);

    /* The first payload is taken by the dispatch and held there */
    state_set(&state.gate_closed, FLB_TRUE);
    ret = submit_bytes(&ctx, "one", 3);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    TEST_CHECK(state_wait(&state.in_flight, 1) == 0);

    /* The payload being processed still counts against the limit */
    for (i = 0; i < 3; i++) {
        ret = submit_bytes(&ctx, "more", 4);
        TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    }

    ret = submit_bytes(&ctx, "busy", 4);
    TEST_CHECK(ret == FLB_INPUT_INGEST_BUSY);
    ret = submit_bytes(&ctx, "busy", 4);
    TEST_CHECK(ret == FLB_INPUT_INGEST_BUSY);

    state_set(&state.gate_closed, FLB_FALSE);
    TEST_CHECK(state_wait(&state.ingest_calls, 4) == 0);

    /* Nothing was consumed by the busy result: the same data is accepted */
    ret = -1;
    for (i = 0; i < 100 && ret != FLB_INPUT_INGEST_OK; i++) {
        ret = submit_bytes(&ctx, "busy", 4);
        if (ret != FLB_INPUT_INGEST_OK) {
            flb_time_msleep(10);
        }
    }
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    TEST_CHECK(state_wait(&state.ingest_calls, 5) == 0);
    TEST_CHECK(strcmp(state.last_payload, "busy") == 0);
    TEST_CHECK(state_wait(&state.output_records, 5) == 0);

    test_ctx_destroy(&ctx);
}

static void test_dispatch_budget_rearm(void)
{
    int i;
    int ret;
    int total;
    struct test_ctx ctx;

    if (test_ctx_create(&ctx, "external", FLB_TRUE) != 0) {
        return;
    }

    /* Several passes worth of payloads, then silence */
    total = (FLB_INPUT_INGEST_PASS_EVENTS * 3) + 7;

    state_set(&state.gate_closed, FLB_TRUE);
    for (i = 0; i < total; i++) {
        ret = submit_bytes(&ctx, "payload", 7);
        TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    }
    state_set(&state.gate_closed, FLB_FALSE);

    TEST_CHECK(state_wait(&state.ingest_calls, total) == 0);
    TEST_CHECK(state_wait(&state.output_records, total) == 0);

    pthread_mutex_lock(&ctx.ins->ingress_queue_lock);
    TEST_CHECK(ctx.ins->ingress_queue_pending_events == 0);
    TEST_CHECK(ctx.ins->ingress_queue_pending_bytes == 0);
    pthread_mutex_unlock(&ctx.ins->ingress_queue_lock);

    test_ctx_destroy(&ctx);
}

static void test_pause_holds_and_resume_dispatches(void)
{
    int i;
    int ret;
    struct test_ctx ctx;

    if (test_ctx_create(&ctx, "external", FLB_TRUE) != 0) {
        return;
    }

    state_set(&state.pause_request, FLB_TRUE);
    TEST_CHECK(state_wait(&state.paused, FLB_TRUE) == 0);

    for (i = 0; i < 3; i++) {
        ret = submit_bytes(&ctx, "held", 4);
        TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    }

    flb_time_msleep(300);
    TEST_CHECK(state_get(&state.ingest_calls) == 0);

    pthread_mutex_lock(&ctx.ins->ingress_queue_lock);
    TEST_CHECK(ctx.ins->ingress_queue_pending_events == 3);
    pthread_mutex_unlock(&ctx.ins->ingress_queue_lock);

    state_set(&state.resume_request, FLB_TRUE);
    TEST_CHECK(state_wait(&state.ingest_calls, 3) == 0);
    TEST_CHECK(state_wait(&state.output_records, 3) == 0);

    test_ctx_destroy(&ctx);
}

static int submit_request(struct test_ctx *ctx, const char *path, int slot)
{
    struct flb_input_ingest_request request;
    struct flb_input_ingest_header header;

    header.name = "content-type";
    header.name_len = 12;
    header.value = "application/json";
    header.value_len = 16;

    memset(&request, 0, sizeof(request));
    request.method = "POST";
    request.method_len = 4;
    request.path = path;
    request.path_len = strlen(path);
    request.headers = &header;
    request.header_count = 1;

    return flb_input_ingest_submit(ctx->ins, FLB_INPUT_INGEST_HTTP_REQUEST,
                                   "{}", 2, &request,
                                   slot >= 0 ? cb_reply : NULL,
                                   (void *) (size_t) slot);
}

static void test_reply_outcomes(void)
{
    int ret;
    struct test_ctx ctx;

    if (test_ctx_create(&ctx, "external", FLB_TRUE) != 0) {
        return;
    }

    /* Replied */
    ret = submit_request(&ctx, "/v1/logs?a=b", 0);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    TEST_CHECK(state_wait(&state.replies, 1) == 0);
    TEST_CHECK(state.reply_outcome[0] == 100 + FLB_INPUT_INGEST_REPLIED);
    TEST_CHECK(state.reply_status[0] == 201);
    TEST_CHECK(strcmp(state.reply_body[0], "/v1/logs?a=b") == 0);
    TEST_CHECK(strcmp(state.last_header, "content-type=application/json") == 0);
    TEST_CHECK(strcmp(state.last_payload, "{}") == 0);

    /* The plugin returned without a reply */
    ret = submit_request(&ctx, "/noreply", 1);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    TEST_CHECK(state_wait(&state.replies, 2) == 0);
    TEST_CHECK(state.reply_outcome[1] == 100 + FLB_INPUT_INGEST_REPLY_FAILED);

    /* No callback: the request is still processed */
    ret = submit_request(&ctx, "/quiet", -1);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    TEST_CHECK(state_wait(&state.ingest_calls, 3) == 0);
    TEST_CHECK(state_get(&state.replies) == 2);

    /* Queued while paused, then the engine stops */
    state_set(&state.pause_request, FLB_TRUE);
    TEST_CHECK(state_wait(&state.paused, FLB_TRUE) == 0);

    ret = submit_request(&ctx, "/late", 2);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    ret = submit_request(&ctx, "/later", 3);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);

    flb_time_msleep(100);
    TEST_CHECK(state_get(&state.replies) == 2);

    test_ctx_destroy(&ctx);

    TEST_CHECK(state.replies == 4);
    TEST_CHECK(state.reply_outcome[2] == 100 + FLB_INPUT_INGEST_REPLY_CANCELLED);
    TEST_CHECK(state.reply_outcome[3] == 100 + FLB_INPUT_INGEST_REPLY_CANCELLED);
    TEST_CHECK(state.ingest_calls == 3);
}

static void test_stream_failed_state(void)
{
    int i;
    int ret;
    struct test_ctx ctx;

    if (test_ctx_create(&ctx, "external", FLB_TRUE) != 0) {
        return;
    }

    state_set(&state.gate_closed, FLB_TRUE);

    ret = submit_bytes(&ctx, "FAIL", 4);
    TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    TEST_CHECK(state_wait(&state.in_flight, 1) == 0);

    /* Admitted before the failure: discarded with it */
    for (i = 0; i < 5; i++) {
        ret = submit_bytes(&ctx, "lost", 4);
        TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    }

    state_set(&state.gate_closed, FLB_FALSE);
    TEST_CHECK(state_wait(&state.ingest_calls, 1) == 0);

    ret = FLB_INPUT_INGEST_OK;
    for (i = 0; i < 100 && ret != FLB_INPUT_INGEST_FAILED; i++) {
        ret = submit_bytes(&ctx, "after", 5);
        if (ret != FLB_INPUT_INGEST_FAILED) {
            flb_time_msleep(10);
        }
    }
    TEST_CHECK(ret == FLB_INPUT_INGEST_FAILED);

    flb_time_msleep(100);
    TEST_CHECK(state_get(&state.ingest_calls) == 1);

    pthread_mutex_lock(&ctx.ins->ingress_queue_lock);
    TEST_CHECK(ctx.ins->ingress_queue_pending_events == 0);
    TEST_CHECK(ctx.ins->ingress_queue_pending_bytes == 0);
    pthread_mutex_unlock(&ctx.ins->ingress_queue_lock);

    test_ctx_destroy(&ctx);
}

static void test_stop_with_queued_data(void)
{
    int i;
    int ret;
    struct test_ctx ctx;

    if (test_ctx_create(&ctx, "external", FLB_TRUE) != 0) {
        return;
    }

    state_set(&state.pause_request, FLB_TRUE);
    TEST_CHECK(state_wait(&state.paused, FLB_TRUE) == 0);

    for (i = 0; i < 50; i++) {
        ret = submit_bytes(&ctx, "queued at stop", 14);
        TEST_CHECK(ret == FLB_INPUT_INGEST_OK);
    }

    /* Queued payloads are discarded; nothing leaks and nothing is parsed */
    test_ctx_destroy(&ctx);
    TEST_CHECK(state.ingest_calls == 0);
}

TEST_LIST = {
    { "submit_and_ownership", test_submit_and_ownership },
    { "argument_and_mode_results", test_argument_and_mode_results },
    { "unsupported_plugin_configuration", test_unsupported_plugin_configuration },
    { "too_large", test_too_large },
    { "busy_and_resubmit", test_busy_and_resubmit },
    { "dispatch_budget_rearm", test_dispatch_budget_rearm },
    { "pause_holds_and_resume_dispatches", test_pause_holds_and_resume_dispatches },
    { "reply_outcomes", test_reply_outcomes },
    { "stream_failed_state", test_stream_failed_state },
    { "stop_with_queued_data", test_stop_with_queued_data },
    { 0 }
};
