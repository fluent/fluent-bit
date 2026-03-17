#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "common/events.h"
#include "common/event_context.h"
#include "common/encoder.h"

#include "handler.h"

int encode_vfs_event(struct flb_input_instance *ins,
                     struct flb_log_event_encoder *log_encoder,
                     const struct event *ev)
{
    int ret;

    ret = flb_log_event_encoder_begin_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ret = encode_common_fields(log_encoder, ev);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "operation");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.vfs.operation);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "path");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, ev->details.vfs.path);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "flags");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, ev->details.vfs.flags);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "mode");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, ev->details.vfs.mode);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "fd");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.vfs.fd);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "error_raw");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.vfs.error_raw);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_commit_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    return 0;
}

int trace_vfs_handler(void *ctx, void *data, size_t data_sz)
{
    struct trace_event_context *event_ctx = (struct trace_event_context *) ctx;
    struct event *ev = (struct event *) data;
    struct flb_log_event_encoder *encoder = event_ctx->log_encoder;
    int ret;

    if (data_sz < sizeof(struct event) || ev->type != EVENT_TYPE_VFS) {
        return -1;
    }

    ret = encode_vfs_event(event_ctx->ins, encoder, ev);
    if (ret != 0) {
        return -1;
    }

    ret = flb_input_log_append(event_ctx->ins, NULL, 0,
                               encoder->output_buffer, encoder->output_length);
    if (ret == -1) {
        return -1;
    }

    flb_log_event_encoder_reset(encoder);

    return 0;
}
