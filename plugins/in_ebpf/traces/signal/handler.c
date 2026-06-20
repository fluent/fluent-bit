#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log.h>
#include <stdio.h>

#include "common/events.h"
#include "common/event_context.h"  // Include the generic event context
#include "common/encoder.h"

#include "handler.h"

int encode_signal_event(struct flb_input_instance *ins,
                               struct flb_log_event_encoder *log_encoder,
                               const struct event *e)
{
    int ret;

    /* Start encoding the log event */
    ret = flb_log_event_encoder_begin_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    /* Encode common fields */
    ret = encode_common_fields(log_encoder, e);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    /* Encode signal-specific fields */
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "signal");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_int32(log_encoder, e->details.signal.sig_raw);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "tpid");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, e->details.signal.tpid);
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

/* Handler for signal events */
int trace_signal_handler(void *ctx, void *data, size_t data_sz)
{
    struct trace_event_context *event_ctx = (struct trace_event_context *)ctx;  // Use the minimal event context
    struct event *e = (struct event *)data;
    struct flb_log_event_encoder *encoder = event_ctx->log_encoder;
    int ret;

    /* Ensure the size of the data matches the expected size */
    if (data_sz < sizeof(struct event) || e->type != EVENT_TYPE_SIGNAL) {
        return -1;
    }

    /* Encode and send the signal event */
    ret = encode_signal_event(event_ctx->ins, encoder, e);
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
