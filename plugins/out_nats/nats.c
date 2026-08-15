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
#include <msgpack.h>

#include "nats.h"

/*
 * Conservative payload limit for a single PUB message. The nats-server
 * default max_payload is 1MB; whole-chunk publishes can exceed it under
 * load and are rejected with -ERR 'Maximum Payload Violation' (the server
 * then closes the connection). Parsing the actual limit from the server
 * INFO line was considered and deliberately left out to keep the plugin
 * simple: the fixed 1MB limit matches the server default.
 */
#define NATS_MAX_PAYLOAD (1024 * 1024)

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

/*
 * Convert a single log event to its JSON array-element form
 * "[ts, {"tag": tag, ...record fields}]", the same shape the plugin has
 * always produced inside the payload array. Returns the JSON sds, or NULL
 * on conversion failure.
 */
static flb_sds_t record_to_json(struct flb_out_nats_config *ctx,
                                struct flb_log_event *log_event,
                                const char *tag, int tag_len,
                                struct flb_config *config)
{
    int i;
    int map_size;
    flb_sds_t out_buf;
    msgpack_object map;
    msgpack_object m_key;
    msgpack_object m_val;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    map      = *log_event->body;
    map_size = map.via.map.size;

    /* Convert MsgPack to JSON */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    msgpack_pack_double(&mp_pck, flb_time_to_double(&log_event->timestamp));

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

    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, config->json_escape_unicode);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return out_buf;
}

/*
 * Frame and send one NATS PUB message:
 *   PUB <subject> <payload_len>\r\n<payload>\r\n
 *
 * Returns 0 on success, -1 on failure (allocation or incomplete write).
 */
static int nats_pub(struct flb_out_nats_config *ctx,
                    struct flb_connection *u_conn,
                    const char *tag, size_t tag_len,
                    flb_sds_t payload)
{
    int ret;
    int req_len;
    size_t bytes_sent;
    size_t json_len;
    size_t buf_size;
    char *request;

    /* Compose the NATS Publish request */
    json_len = flb_sds_len(payload);
    buf_size = tag_len + json_len + 32;

    request = flb_malloc(buf_size);
    if (!request) {
        flb_errno();
        return -1;
    }

    /* Write the PUB header; snprintf size is the full buffer */
    req_len = snprintf(request, buf_size,
                       "PUB %s %zu\r\n",
                       tag, json_len);

    /* snprintf returns the would-be length on truncation; guard against it */
    if (req_len < 0 || (size_t) req_len + json_len + 2 > buf_size) {
        flb_plg_error(ctx->ins, "PUB header too large for buffer");
        flb_free(request);
        return -1;
    }

    /* Append JSON message and ending CRLF */
    memcpy(request + req_len, payload, json_len);
    req_len += json_len;
    request[req_len++] = '\r';
    request[req_len++] = '\n';

    ret = flb_io_net_write(u_conn, request, req_len, &bytes_sent);
    if (ret == -1 || bytes_sent != (size_t) req_len) {
        /* an incomplete PUB leaves the protocol stream misaligned: the
         * server would parse the next frame in the middle of this one */
        flb_plg_error(ctx->ins, "PUB write incomplete (%zu/%d bytes)",
                      ret == -1 ? 0 : bytes_sent, req_len);
        flb_errno();
        flb_free(request);
        return -1;
    }

    flb_free(request);
    return 0;
}

static void cb_nats_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    int ret;
    int batch_count = 0;
    size_t bytes_sent;
    size_t tag_len;
    size_t elem_len;
    flb_sds_t elem;
    flb_sds_t json_msg;
    struct flb_out_nats_config *ctx = out_context;
    struct flb_connection *u_conn;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available");
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /*
     * Send the NATS CONNECT handshake only once per connection instead of
     * on every flush: sending it again on a recycled keepalive connection
     * is redundant, the server only needs it right after the TCP connection
     * is established.
     *
     * The handshake state is tracked in the connection's own user_data
     * field (unused for upstream connections): connections are zeroed on
     * creation, so a fresh connection always runs the handshake, while a
     * recycled one keeps the mark and skips it. A connection that fails an
     * I/O operation is destroyed by the upstream layer rather than
     * recycled, and the keepalive queue destroys connections dropped by
     * the server, so no stale mark can ever skip the handshake on a new
     * connection.
     */
    if (u_conn->user_data == NULL) {
        ret = flb_io_net_write(u_conn,
                               NATS_CONNECT,
                               sizeof(NATS_CONNECT) - 1,
                               &bytes_sent);
        if (ret == -1 || bytes_sent != sizeof(NATS_CONNECT) - 1) {
            /* an incomplete CONNECT leaves the protocol stream misaligned */
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        flb_plg_debug(ctx->ins, "sent NATS CONNECT handshake");
        u_conn->user_data = u_conn;
    }

    ret = flb_log_event_decoder_init(&log_decoder,
                                     (char *) event_chunk->data,
                                     event_chunk->size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    tag_len = flb_sds_len(event_chunk->tag);

    /*
     * Publish the chunk in batches: every PUB message keeps the usual
     * '[[ts, record], ...]' JSON array shape (message semantics are
     * unchanged for downstream consumers), but each payload is kept below
     * NATS_MAX_PAYLOAD so the server does not reject it with
     * -ERR 'Maximum Payload Violation' when a chunk grows past the limit
     * under load.
     *
     * Note on partial failure: if a write fails after some batches were
     * sent, those records are published again when the chunk is retried.
     * This is accepted (outputs are at-least-once) in exchange for a
     * fail-fast flush that does not keep writing to a broken connection.
     */
    json_msg = flb_sds_create_size(4096);
    if (!json_msg) {
        flb_errno();
        flb_log_event_decoder_destroy(&log_decoder);
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    json_msg = flb_sds_cat(json_msg, "[", 1);

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        elem = record_to_json(ctx, &log_event,
                              event_chunk->tag, tag_len, config);
        if (!elem) {
            flb_plg_error(ctx->ins, "failed to convert record to JSON");
            flb_sds_destroy(json_msg);
            flb_log_event_decoder_destroy(&log_decoder);
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        elem_len = flb_sds_len(elem);

        /*
         * A single record larger than the limit would be rejected no
         * matter how it is batched and would retry-loop the chunk
         * forever: drop it and continue with the next records.
         */
        if (elem_len > NATS_MAX_PAYLOAD) {
            flb_plg_error(ctx->ins,
                          "dropping record of %zu bytes: exceeds NATS "
                          "max_payload (%d)", elem_len, NATS_MAX_PAYLOAD);
            flb_sds_destroy(elem);
            continue;
        }

        /* send the current batch if this record would push it over the limit */
        if (batch_count > 0 &&
            flb_sds_len(json_msg) + 1 + elem_len + 1 > NATS_MAX_PAYLOAD) {
            json_msg = flb_sds_cat(json_msg, "]", 1);
            if (nats_pub(ctx, u_conn, event_chunk->tag, tag_len,
                         json_msg) == -1) {
                flb_sds_destroy(elem);
                flb_sds_destroy(json_msg);
                flb_log_event_decoder_destroy(&log_decoder);
                flb_upstream_conn_release(u_conn);
                FLB_OUTPUT_RETURN(FLB_RETRY);
            }
            flb_sds_destroy(json_msg);

            json_msg = flb_sds_create_size(4096);
            if (!json_msg) {
                flb_errno();
                flb_sds_destroy(elem);
                flb_log_event_decoder_destroy(&log_decoder);
                flb_upstream_conn_release(u_conn);
                FLB_OUTPUT_RETURN(FLB_RETRY);
            }
            json_msg = flb_sds_cat(json_msg, "[", 1);
            batch_count = 0;
        }

        if (batch_count > 0) {
            json_msg = flb_sds_cat(json_msg, ",", 1);
        }
        json_msg = flb_sds_cat(json_msg, elem, elem_len);
        flb_sds_destroy(elem);
        batch_count++;
    }

    flb_log_event_decoder_destroy(&log_decoder);

    /* send the final batch */
    if (batch_count > 0) {
        json_msg = flb_sds_cat(json_msg, "]", 1);
        if (nats_pub(ctx, u_conn, event_chunk->tag, tag_len, json_msg) == -1) {
            flb_sds_destroy(json_msg);
            flb_upstream_conn_release(u_conn);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    flb_sds_destroy(json_msg);
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
