#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "common/events.h"
#include "common/event_context.h"
#include "common/encoder.h"

#include "handler.h"

static int is_openssl_tls_event(enum event_type type)
{
    if (type == EVENT_TYPE_TLS_HANDSHAKE ||
        type == EVENT_TYPE_TLS_READ ||
        type == EVENT_TYPE_TLS_WRITE ||
        type == EVENT_TYPE_TLS_SHUTDOWN) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

int encode_openssl_event(struct flb_log_event_encoder *log_encoder,
                         const struct event *ev)
{
    int ret;
    const char *trace_name;

    if (!is_openssl_tls_event(ev->type)) {
        return -1;
    }

    ret = flb_log_event_encoder_begin_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = encode_common_fields(log_encoder, ev);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "trace");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    if (ev->type == EVENT_TYPE_TLS_READ) {
        trace_name = "openssl_tls_read";
    }
    else if (ev->type == EVENT_TYPE_TLS_WRITE) {
        trace_name = "openssl_tls_write";
    }
    else if (ev->type == EVENT_TYPE_TLS_SHUTDOWN) {
        trace_name = "openssl_tls_shutdown";
    }
    else if (ev->type == EVENT_TYPE_TLS_HANDSHAKE) {
        trace_name = "openssl_tls_handshake";
    }
    else {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, trace_name);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "ssl_ptr");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    if (ev->type == EVENT_TYPE_TLS_HANDSHAKE) {
        ret = flb_log_event_encoder_append_body_uint64(log_encoder,
                                                       ev->details.tls_handshake.ssl_ptr);
    }
    else {
        ret = flb_log_event_encoder_append_body_uint64(log_encoder,
                                                       ev->details.tls_io.ssl_ptr);
    }
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "latency_ns");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    if (ev->type == EVENT_TYPE_TLS_HANDSHAKE) {
        ret = flb_log_event_encoder_append_body_int64(log_encoder,
                                                      ev->details.tls_handshake.latency_ns);
    }
    else {
        ret = flb_log_event_encoder_append_body_int64(log_encoder,
                                                      ev->details.tls_io.latency_ns);
    }
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "ret");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    if (ev->type == EVENT_TYPE_TLS_HANDSHAKE) {
        ret = flb_log_event_encoder_append_body_int32(log_encoder,
                                                      ev->details.tls_handshake.ret);
    }
    else {
        ret = flb_log_event_encoder_append_body_int32(log_encoder,
                                                      ev->details.tls_io.ret);
    }
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_commit_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    return 0;
}

int trace_openssl_handler(void *ctx, void *data, size_t data_sz)
{
    struct trace_event_context *event_ctx;
    struct event *ev;
    struct flb_log_event_encoder *encoder;
    int ret;

    event_ctx = (struct trace_event_context *) ctx;
    ev = (struct event *) data;
    encoder = event_ctx->log_encoder;

    if (data_sz < sizeof(struct event)) {
        return -1;
    }

    if (!is_openssl_tls_event(ev->type)) {
        return -1;
    }

    ret = encode_openssl_event(encoder, ev);
    if (ret != 0) {
        return -1;
    }

    ret = flb_input_log_append(event_ctx->ins, NULL, 0,
                               encoder->output_buffer, encoder->output_length);
    flb_log_event_encoder_reset(encoder);
    if (ret == -1) {
        return -1;
    }

    return 0;
}
