#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <stdint.h>
#include <string.h>

#include "common/events.h"
#include "common/event_context.h"
#include "common/encoder.h"

#include "handler.h"

#define DNS_HEADER_SIZE 12

static int decode_dns_query_name(const uint8_t *raw, size_t raw_len, char *out, size_t out_len,
                                 uint16_t *query_type)
{
    size_t cursor;
    size_t out_i;
    size_t label_end;
    uint8_t label_len;

    if (!raw || raw_len < DNS_HEADER_SIZE || !out || out_len == 0) {
        return -1;
    }

    cursor = DNS_HEADER_SIZE;
    out_i = 0;

    while (cursor < raw_len) {
        label_len = raw[cursor++];

        if (label_len == 0) {
            break;
        }

        if ((label_len & 0xc0) != 0 || cursor + label_len > raw_len) {
            return -1;
        }

        if (out_i > 0) {
            if (out_i + 1 >= out_len) {
                return -1;
            }
            out[out_i++] = '.';
        }

        label_end = cursor + label_len;
        while (cursor < label_end) {
            if (out_i + 1 >= out_len) {
                return -1;
            }
            out[out_i++] = (char) raw[cursor++];
        }
    }

    if (out_i == 0) {
        if (out_len < 2) {
            return -1;
        }
        out[out_i++] = '.';
    }

    out[out_i] = '\0';

    if (cursor + 4 > raw_len) {
        return -1;
    }

    if (query_type) {
        *query_type = (uint16_t) ((raw[cursor] << 8) | raw[cursor + 1]);
    }

    return 0;
}

int encode_dns_event(struct flb_input_instance *ins,
                     struct flb_log_event_encoder *log_encoder,
                     const struct event *ev)
{
    char query_name[DNS_NAME_MAX];
    uint16_t query_type;
    int ret;
    (void) ins;

    query_name[0] = '\0';
    query_type = ev->details.dns.query_type;

    if (ev->details.dns.query_raw_len > 0 &&
        ev->details.dns.query_raw_len <= DNS_QUERY_RAW_MAX) {
        if (decode_dns_query_name(ev->details.dns.query_raw,
                                  ev->details.dns.query_raw_len,
                                  query_name,
                                  sizeof(query_name),
                                  &query_type) != 0) {
            if (ev->details.dns.response == 0) {
                return -2;
            }

            memcpy(query_name, "<unknown>", 9);
            query_name[9] = '\0';
        }
    }
    else {
        if (ev->details.dns.response == 0) {
            return -2;
        }

        memcpy(query_name, "<unknown>", 9);
        query_name[9] = '\0';
    }

    if (ev->details.dns.response == 0 && query_type == 0) {
        return -2;
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

    ret = flb_log_event_encoder_append_body_cstring(log_encoder, "query");
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, query_name);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "query_type");
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_uint16(log_encoder, query_type);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "txid");
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_uint16(log_encoder, ev->details.dns.txid);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "response");
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_uint8(log_encoder, ev->details.dns.response);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "rcode");
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_uint8(log_encoder, ev->details.dns.rcode);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "latency_ns");
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_uint64(log_encoder, ev->details.dns.latency_ns);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_cstring(log_encoder, "error_raw");
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_int32(log_encoder, ev->details.dns.error_raw);
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

int trace_dns_handler(void *ctx, void *data, size_t data_sz)
{
    struct trace_event_context *event_ctx;
    struct event *ev;
    struct flb_log_event_encoder *encoder;
    int ret;

    event_ctx = (struct trace_event_context *) ctx;
    ev = (struct event *) data;
    encoder = event_ctx->log_encoder;

    if (data_sz < sizeof(struct event) || ev->type != EVENT_TYPE_DNS) {
        return -1;
    }

    ret = encode_dns_event(event_ctx->ins, encoder, ev);
    if (ret == -2) {
        return 0;
    }
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
