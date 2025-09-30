// plugins/in_ebpf/traces/includes/common/encoder_helpers.h
#ifndef ENCODER_HELPERS_H
#define ENCODER_HELPERS_H

#include <fluent-bit/flb_log_event_encoder.h>
#include "events.h"

#define TASK_COMM_LEN 16  // Update this based on your actual TASK_COMM_LEN

static inline char *event_type_to_string(enum event_type type) {
    switch (type) {
        case EVENT_TYPE_EXECVE:
            return "execve";
        case EVENT_TYPE_SIGNAL:
            return "signal";
        case EVENT_TYPE_MEM:
            return "malloc";
        case EVENT_TYPE_BIND:
            return "bind";
        default:
            return "unknown";
    }
}

/* Function to encode common fields for all traces */
static inline int encode_common_fields(struct flb_log_event_encoder *log_encoder, const struct event *e) {
    int ret;
    char *event_type_str;

    /* Set timestamp */
    ret = flb_log_event_encoder_set_current_timestamp(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    /* Get event type string */
    event_type_str = event_type_to_string(e->type);

    /* Encode event type */
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "event_type");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, event_type_str);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    /* Encode process ID */
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "pid");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, e->common.pid);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    /* Encode thread ID */
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "tid");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, e->common.tid);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    /* Encode command name */
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "comm");
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }
    ret = flb_log_event_encoder_append_body_string(log_encoder, (char *)e->common.comm, TASK_COMM_LEN);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    return FLB_EVENT_ENCODER_SUCCESS;
}

#endif // ENCODER_HELPERS_H