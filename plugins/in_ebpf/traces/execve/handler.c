#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <stdio.h>

#include "common/events.h"
#include "common/event_context.h"

/* Helper function to encode execve events into Fluent Bit log format */
static int encode_execve_event(struct flb_input_instance *ins,
                               struct flb_log_event_encoder *log_encoder,
                               const struct event *ev)
{
    int ret;

    /* Start encoding the log event */
    ret = flb_log_event_encoder_begin_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    /* Encode common fields */
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

    /* Encode execve-specific fields */
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "tpid");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, ev->details.execve.tpid);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "filename");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_string(log_encoder, ev->details.execve.filename, PATH_MAX);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "argc");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, ev->details.execve.argc);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "argv");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_string(log_encoder, ev->details.execve.argv, sizeof(ev->details.execve.argv));
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

/* Handler for execve events */
int trace_execve_handler(void *ctx, void *data, size_t data_sz)
{
    struct trace_event_context *event_ctx = (struct trace_event_context *)ctx;  // Use the minimal context
    struct event *ev = (struct event *)data;
    struct flb_log_event_encoder *encoder = event_ctx->log_encoder;
    int ret;

    /* Ensure the size of the data matches the expected size */
    if (data_sz < sizeof(struct event) || ev->type != EVENT_TYPE_EXECVE) {
        return -1;
    }

    /* Encode and send the execve event */
    ret = encode_execve_event(event_ctx->ins, encoder, ev);
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
