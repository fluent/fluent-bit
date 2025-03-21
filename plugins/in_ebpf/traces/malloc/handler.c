#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <stdio.h>

#include "common/events.h"
#include "common/event_context.h"
#include "common/encoder.h"

#include "handler.h"

int encode_malloc_event(struct flb_input_instance *ins,
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
    ret = encode_common_fields(log_encoder, ev);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    /* Encode malloc-specific fields */
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "operation");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.mem.operation);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "address");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint64(log_encoder, ev->details.mem.addr);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "size");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint64(log_encoder, ev->details.mem.size);
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

/* Handler for malloc events */
int trace_malloc_handler(void *ctx, void *data, size_t data_sz)
{
    struct trace_event_context *event_ctx = (struct trace_event_context *)ctx;  // Use the minimal context
    struct event *ev = (struct event *)data;
    struct flb_log_event_encoder *encoder = event_ctx->log_encoder;
    int ret;

    /* Ensure the size of the data matches the expected size */
    if (data_sz < sizeof(struct event) || ev->type != EVENT_TYPE_MEM) {
        return -1;
    }

    /* Encode and send the malloc event */
    ret = encode_malloc_event(event_ctx->ins, encoder, ev);
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
