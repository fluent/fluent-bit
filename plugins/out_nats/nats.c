/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <msgpack.h>

#include "nats.h"

#define NATS_ENCODED_SUBJECT_PREFIX "_flb_encoded."

static int cb_nats_init(struct flb_output_instance *ins, struct flb_config *config,
                        void *data)
{
    int io_flags;
    int ret;
    struct flb_upstream *upstream;
    struct flb_out_nats_config *ctx;

    /* Set default network configuration */
    flb_output_net_default("127.0.0.1", 4222, ins);

    /* Allocate plugin context */
    ctx = flb_malloc(sizeof(struct flb_out_nats_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    /* Set default values */
    ret = flb_output_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_plg_error(ins, "flb_output_config_map_set failed");
        flb_free(ctx);
        return -1;
    }

    if (strcmp(ctx->invalid_subject_action, "reject") != 0 &&
        strcmp(ctx->invalid_subject_action, "encode") != 0) {
        flb_plg_error(ins, "invalid value for invalid_subject_action: %s",
                      ctx->invalid_subject_action);
        flb_free(ctx);
        return -1;
    }

    io_flags = FLB_IO_TCP;
    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags,
                                   NULL);
    if (!upstream) {
        flb_free(ctx);
        return -1;
    }
    ctx->u   = upstream;
    ctx->ins = ins;
    flb_output_upstream_set(ctx->u, ins);
    flb_output_set_context(ins, ctx);

    return 0;
}

static int msgpack_to_json(struct flb_out_nats_config *ctx,
                           const void *data, size_t bytes,
                           const char *tag, int tag_len,
                           char **out_json, size_t *out_size,
                           struct flb_config *config)
{
    int i;
    int map_size;
    size_t array_size = 0;
    flb_sds_t out_buf;
    msgpack_object map;
    msgpack_object m_key;
    msgpack_object m_val;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return -1;
    }

    array_size = flb_mp_count_log_records(data, bytes);

    /* Convert MsgPack to JSON */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&mp_pck, array_size);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        map      = *log_event.body;
        map_size = map.via.map.size;

        msgpack_pack_array(&mp_pck, 2);
        msgpack_pack_double(&mp_pck, flb_time_to_double(&log_event.timestamp));

        msgpack_pack_map(&mp_pck, map_size + 1);
        msgpack_pack_str(&mp_pck, 3);
        msgpack_pack_str_body(&mp_pck, "tag", 3);
        msgpack_pack_str(&mp_pck, tag_len);
        msgpack_pack_str_body(&mp_pck, tag, tag_len);

        for (i = 0; i < map_size; i++) {
            m_key = map.via.map.ptr[i].key;
            m_val = map.via.map.ptr[i].val;

            msgpack_pack_object(&mp_pck, m_key);
            msgpack_pack_object(&mp_pck, m_val);
        }
    }

    flb_log_event_decoder_destroy(&log_decoder);

    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, config->json_escape_unicode);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!out_buf) {
        return -1;
    }

    *out_json = out_buf;
    *out_size = flb_sds_len(out_buf);

    return 0;
}

/* A publish subject must contain nonempty tokens and no protocol separators. */
static int valid_publish_subject(const char *tag, size_t length)
{
    size_t i;
    unsigned char c;

    if (length == 0) {
        return FLB_FALSE;
    }

    for (i = 0; i < length; i++) {
        c = (unsigned char) tag[i];
        if (c <= 0x20 || c == 0x7f || c == '*' || c == '>') {
            return FLB_FALSE;
        }
        if (c == '.' && (i == 0 || i + 1 == length || tag[i - 1] == '.')) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

/* Encode reserved-prefix tags too, so encoded and unchanged subjects cannot collide. */
static char *encode_publish_subject(const char *tag, size_t length)
{
    size_t i;
    size_t prefix_length;
    char *subject;
    static const char hex[] = "0123456789ABCDEF";

    prefix_length = sizeof(NATS_ENCODED_SUBJECT_PREFIX) - 1;
    if (length > (SIZE_MAX - prefix_length - 1) / 2) {
        return NULL;
    }

    subject = flb_malloc(prefix_length + length * 2 + 1);
    if (!subject) {
        return NULL;
    }

    memcpy(subject, NATS_ENCODED_SUBJECT_PREFIX, prefix_length);
    for (i = 0; i < length; i++) {
        subject[prefix_length + i * 2] = hex[((unsigned char) tag[i]) >> 4];
        subject[prefix_length + i * 2 + 1] = hex[((unsigned char) tag[i]) & 0x0f];
    }
    subject[prefix_length + length * 2] = '\0';

    return subject;
}

static void cb_nats_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int ret;
    size_t bytes_sent;
    size_t json_len;
    flb_sds_t json_msg;
    char *request;
    int req_len;
    size_t tag_length;
    size_t subject_length;
    const char *subject;
    char *encoded_subject = NULL;
    struct flb_out_nats_config *ctx = out_context;
    struct flb_connection *u_conn;

    tag_length = flb_sds_len(event_chunk->tag);
    subject = event_chunk->tag;
    subject_length = tag_length;

    if (strcmp(ctx->invalid_subject_action, "encode") == 0 &&
        (!valid_publish_subject(subject, subject_length) ||
         strncmp(subject, NATS_ENCODED_SUBJECT_PREFIX,
                 sizeof(NATS_ENCODED_SUBJECT_PREFIX) - 1) == 0)) {
        encoded_subject = encode_publish_subject(event_chunk->tag, tag_length);
        if (!encoded_subject) {
            flb_errno();
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
        subject = encoded_subject;
        subject_length = strlen(subject);
    }
    else if (!valid_publish_subject(subject, subject_length)) {
        flb_plg_error(ctx->ins, "invalid NATS publish subject in tag");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Convert original Fluent Bit MsgPack format to JSON */
    ret = msgpack_to_json(ctx,
                          event_chunk->data, event_chunk->size,
                          event_chunk->tag, flb_sds_len(event_chunk->tag),
                          &json_msg, &json_len, config);
    if (ret == -1) {
        flb_free(encoded_subject);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Bound the complete PUB line to the NATS default max_control_line. */
    req_len = snprintf(NULL, 0, "PUB %s %zu\r\n", subject, json_len);
    if (req_len < 0 || req_len > 4096) {
        flb_plg_error(ctx->ins, "NATS publish control line exceeds 4096 bytes");
        flb_sds_destroy(json_msg);
        flb_free(encoded_subject);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available");
        flb_sds_destroy(json_msg);
        flb_free(encoded_subject);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Before to flush the content check if we need to start the handshake */
    ret = flb_io_net_write(u_conn,
                           NATS_CONNECT,
                           sizeof(NATS_CONNECT) - 1,
                           &bytes_sent);
    if (ret == -1) {
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(json_msg);
        flb_free(encoded_subject);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Compose the NATS Publish request */
    request = flb_malloc(json_len + subject_length + 32);
    if (!request) {
        flb_errno();
        flb_sds_destroy(json_msg);
        flb_upstream_conn_release(u_conn);
        flb_free(encoded_subject);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    req_len = snprintf(request, subject_length + 32,
                       "PUB %s %zu\r\n",
                       subject, json_len);
    flb_free(encoded_subject);

    /* Append JSON message and ending CRLF */
    memcpy(request + req_len, json_msg, json_len);
    req_len += json_len;
    request[req_len++] = '\r';
    request[req_len++] = '\n';
    flb_sds_destroy(json_msg);

    ret = flb_io_net_write(u_conn, request, req_len, &bytes_sent);
    if (ret == -1) {
        flb_errno();
        flb_free(request);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    flb_free(request);
    flb_upstream_conn_release(u_conn);
    FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_nats_exit(void *data, struct flb_config *config)
{
    (void) config;
    struct flb_out_nats_config *ctx = data;

    flb_upstream_destroy(ctx->u);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "invalid_subject_action", "reject",
     0, FLB_TRUE, offsetof(struct flb_out_nats_config, invalid_subject_action),
     "Action for tags that are invalid NATS subjects: reject or encode. Encoding uses "
     "_flb_encoded. followed by uppercase hex, and also encodes tags with that prefix. "
     "Subscribers and publish permissions must use the encoded subject."
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_nats_plugin = {
    .name         = "nats",
    .description  = "NATS Server",
    .cb_init      = cb_nats_init,
    .cb_flush     = cb_nats_flush,
    .cb_exit      = cb_nats_exit,
    .flags        = FLB_OUTPUT_NET,
    .config_map   = config_map
};
