#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <stdio.h>

#include "common/events.h"
#include "common/event_context.h"
#include "common/encoder.h"

#include "handler.h"

static int encode_tcp_addr(struct flb_log_event_encoder *log_encoder,
                           const char *key_prefix,
                           struct tcp_addr *addr)
{
    int ret;
    char key[64];

    snprintf(key, sizeof(key), "%s_port", key_prefix);
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, key);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint16(log_encoder, addr->port);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    snprintf(key, sizeof(key), "%s_version", key_prefix);
    ret = flb_log_event_encoder_append_body_cstring(log_encoder, key);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }
    ret = flb_log_event_encoder_append_body_uint32(log_encoder, addr->version);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        return -1;
    }

    if (addr->version == 6) {
        int i;

        for (i = 0; i < 4; i++) {
            snprintf(key, sizeof(key), "%s_addr_v6_%d", key_prefix, i);
            ret = flb_log_event_encoder_append_body_cstring(log_encoder, key);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                return -1;
            }

            ret = flb_log_event_encoder_append_body_uint32(log_encoder,
                                                           addr->addr_raw.v6[i]);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                return -1;
            }
        }
    }
    else {
        snprintf(key, sizeof(key), "%s_addr_v4", key_prefix);
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, key);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            return -1;
        }

        ret = flb_log_event_encoder_append_body_uint32(log_encoder, addr->addr_raw.v4);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            return -1;
        }
    }

    return 0;
}

int encode_tcp_event(struct flb_input_instance *ins,
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

    if (ev->type == EVENT_TYPE_LISTEN) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "fd");
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.listen.fd);
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_cstring(log_encoder, "backlog");
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.listen.backlog);
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_cstring(log_encoder, "error_raw");
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.listen.error_raw);
        }
    }
    else if (ev->type == EVENT_TYPE_ACCEPT) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "fd");
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.accept.fd);
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_cstring(log_encoder, "new_fd");
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.accept.new_fd);
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = encode_tcp_addr(log_encoder, "peer", (struct tcp_addr *) &ev->details.accept.peer);
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_cstring(log_encoder, "error_raw");
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.accept.error_raw);
        }
    }
    else if (ev->type == EVENT_TYPE_CONNECT) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "fd");
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.connect.fd);
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = encode_tcp_addr(log_encoder, "remote", (struct tcp_addr *) &ev->details.connect.remote);
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_cstring(log_encoder, "error_raw");
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.connect.error_raw);
        }
    }
    else {
        ret = -1;
    }

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

int trace_tcp_handler(void *ctx, void *data, size_t data_sz)
{
    struct trace_event_context *event_ctx = (struct trace_event_context *) ctx;
    struct event *ev = (struct event *) data;
    struct flb_log_event_encoder *encoder = event_ctx->log_encoder;
    int ret;

    if (data_sz < sizeof(struct event)) {
        return -1;
    }

    if (ev->type != EVENT_TYPE_LISTEN &&
        ev->type != EVENT_TYPE_ACCEPT &&
        ev->type != EVENT_TYPE_CONNECT) {
        return -1;
    }

    ret = encode_tcp_event(event_ctx->ins, encoder, ev);
    if (ret != 0) {
        return -1;
    }

    ret = flb_input_log_append(event_ctx->ins, NULL, 0,
                               encoder->output_buffer,
                               encoder->output_length);
    if (ret == -1) {
        return -1;
    }

    flb_log_event_encoder_reset(encoder);

    return 0;
}
