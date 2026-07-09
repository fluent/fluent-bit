#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "common/events.h"
#include "common/event_context.h"
#include "common/encoder.h"

#include "handler.h"

int encode_sched_event(struct flb_log_event_encoder *log_encoder,
                       const struct sched_sample *e)
{
    struct event ev;
    int ret;

    ret = flb_log_event_encoder_begin_record(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    ev.type = e->type;
    ev.common = e->common;

    ret = encode_common_fields(log_encoder, &ev);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "cpu");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, e->details.cpu);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "prev_pid");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, e->details.prev_pid);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "prev_prio");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_int32(log_encoder, e->details.prev_prio);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "prev_state");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_int64(log_encoder, e->details.prev_state);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "next_pid");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, e->details.next_pid);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "next_prio");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_int32(log_encoder, e->details.next_prio);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "runq_latency_ns");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint64(log_encoder, e->details.runq_latency_ns);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "wakeup_tracked");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(log_encoder);
        return -1;
    }
    ret = flb_log_event_encoder_append_body_boolean(log_encoder, e->details.wakeup_tracked);
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

int trace_sched_handler(void *ctx, void *data, size_t data_sz)
{
    struct trace_event_context *event_ctx;
    struct flb_log_event_encoder *encoder;
    struct sched_sample *e;
    int ret;

    event_ctx = (struct trace_event_context *) ctx;
    e = (struct sched_sample *) data;

    if (data_sz < sizeof(struct sched_sample) || e->type != EVENT_TYPE_SCHED) {
        return -1;
    }

    encoder = event_ctx->log_encoder;

    ret = encode_sched_event(encoder, e);
    if (ret != 0) {
        flb_log_event_encoder_reset(encoder);
        return -1;
    }

    ret = flb_input_log_append(event_ctx->ins,
                               NULL,
                               0,
                               encoder->output_buffer,
                               encoder->output_length);
    if (ret == -1) {
        flb_log_event_encoder_reset(encoder);
        return -1;
    }

    flb_log_event_encoder_reset(encoder);

    return 0;
}
