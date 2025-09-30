#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <stdio.h>

#include "common/events.h"
#include "common/event_context.h"
#include "common/encoder.h"

#include "handler.h"

int encode_bind_event(struct flb_input_instance *ins,
                             struct flb_log_event_encoder *log_encoder,
                             const struct event *ev)
{
    int ret;

    ret = flb_log_event_encoder_begin_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    /* Encode common fields */
    ret = encode_common_fields(log_encoder, ev);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "pid");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, ev->common.pid);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "comm");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_string(log_encoder, ev->common.comm, TASK_COMM_LEN);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    /* Encode bind-specific fields */
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "uid");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, ev->common.uid);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "gid");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, ev->common.gid);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "error_raw");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.bind.error_raw);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "port");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint16(log_encoder, ev->details.bind.addr.port);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "bound_dev_if");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, ev->details.bind.bound_dev_if);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    /* Commit the record */
    ret = flb_log_event_encoder_commit_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    return 0;
}

/* Handler for bind events */
int trace_bind_handler(void *ctx, void *data, size_t data_sz)
{
    struct trace_event_context *event_ctx = (struct trace_event_context *)ctx;  // Use the minimal context
    struct event *ev = (struct event *)data;
    struct flb_log_event_encoder *encoder = event_ctx->log_encoder;
    int ret;

    /* Ensure the size of the data matches the expected size */
    if (data_sz < sizeof(struct event) || ev->type != EVENT_TYPE_BIND) {
        return -1;
    }

    /* Encode and send the bind event */
    ret = encode_bind_event(event_ctx->ins, encoder, ev);
    if (ret != 0) {
        return -1;
    }

    /* Send the encoded log event */
    ret = flb_input_log_append(event_ctx->ins, NULL, 0, encoder->output_buffer, encoder->output_length);
    if (ret == -1) {
        return -1;
    }

    /* Reset the log encoder for the next event */
    flb_log_event_encoder_reset(encoder);

    return 0;
}
