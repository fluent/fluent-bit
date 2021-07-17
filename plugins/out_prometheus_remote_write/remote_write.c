/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_snappy.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_prometheus_remote_write.h>

#include "remote_write.h"
#include "remote_write_conf.h"

static int http_post(struct prometheus_remote_write_context *ctx,
                     const void *body, size_t body_len,
                     const char *tag, int tag_len)
{
    int ret;
    int out_ret = FLB_OK;
    size_t b_sent;
    void *payload_buf = NULL;
    size_t payload_size = 0;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available to %s:%i",
                      u->tcp_host, u->tcp_port);
        return FLB_RETRY;
    }

    /* Map payload */
    ret = flb_snappy_compress((void *) body, body_len,
                              &payload_buf, &payload_size);
    if (ret != 0) {
        flb_upstream_conn_release(u_conn);

        flb_plg_error(ctx->ins,
                      "cannot compress payload, aborting");

        return FLB_ERROR;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        payload_buf, payload_size,
                        ctx->host, ctx->port,
                        ctx->proxy, 0);


    if (c->proxy.host) {
        flb_plg_debug(ctx->ins, "[http_client] proxy host: %s port: %i",
                      c->proxy.host, c->proxy.port);
    }

    /* Allow duplicated headers ? */
    flb_http_allow_duplicated_headers(c, FLB_FALSE);

    /*
     * Direct assignment of the callback context to the HTTP client context.
     * This needs to be improved through a more clean API.
     */
    c->cb_ctx = ctx->ins->callback;

    flb_http_add_header(c,
                        FLB_PROMETHEUS_REMOTE_WRITE_CONTENT_TYPE_HEADER_NAME,
                        sizeof(FLB_PROMETHEUS_REMOTE_WRITE_CONTENT_TYPE_HEADER_NAME) - 1,
                        FLB_PROMETHEUS_REMOTE_WRITE_MIME_PROTOBUF_LITERAL,
                        sizeof(FLB_PROMETHEUS_REMOTE_WRITE_MIME_PROTOBUF_LITERAL) - 1);

    flb_http_add_header(c,
                        FLB_PROMETHEUS_REMOTE_WRITE_VERSION_HEADER_NAME,
                        sizeof(FLB_PROMETHEUS_REMOTE_WRITE_VERSION_HEADER_NAME) - 1,
                        FLB_PROMETHEUS_REMOTE_WRITE_VERSION_LITERAL,
                        sizeof(FLB_PROMETHEUS_REMOTE_WRITE_VERSION_LITERAL) - 1);

    /* Basic Auth headers */
    if (ctx->http_user && ctx->http_passwd) {
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    }

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    ret = flb_http_do(c, &b_sent);
    if (ret == 0) {
        /*
         * Only allow the following HTTP status:
         *
         * - 200: OK
         * - 201: Created
         * - 202: Accepted
         * - 203: no authorative resp
         * - 204: No Content
         * - 205: Reset content
         *
         */
        if (c->resp.status < 200 || c->resp.status > 205) {
            if (ctx->log_response_payload &&
                c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                              ctx->host, ctx->port,
                              c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                              ctx->host, ctx->port, c->resp.status);
            }
            out_ret = FLB_RETRY;
        }
        else {
            if (ctx->log_response_payload &&
                c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                             ctx->host, ctx->port,
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i",
                             ctx->host, ctx->port,
                             c->resp.status);
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->host, ctx->port, ret);
        out_ret = FLB_RETRY;
    }

    /*
     * If the payload buffer is different than incoming records in body, means
     * we generated a different payload and must be freed.
     */
    if (payload_buf != body) {
        flb_free(payload_buf);
    }

    /* Destroy HTTP client context */
    flb_http_client_destroy(c);

    /* Release the TCP connection */
    flb_upstream_conn_release(u_conn);

    return out_ret;
}

static int cb_prom_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    struct prometheus_remote_write_context *ctx;

    ctx = flb_prometheus_remote_write_context_create(ins, config);
    if (!ctx) {
        return -1;
    }

    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_prom_flush(const void *data, size_t bytes,
                          const char *tag, int tag_len,
                          struct flb_input_instance *ins, void *out_context,
                          struct flb_config *config)
{
    cmt_sds_t                               encoded_chunk;
    int                                     result;
    size_t                                  off;
    struct cmt                             *cmt;
    struct prometheus_remote_write_context *ctx;

    off = 0;
    ctx = out_context;
    result = FLB_OK;

    while (result == FLB_OK) {
        result = cmt_decode_msgpack_create(&cmt, (char *) data, bytes, &off);

        if (result == CMT_DECODE_MSGPACK_INSUFFICIENT_DATA) {
            result = FLB_OK;

            /* We can't handle this case afterwards because there is an overlap in the
             * constant values for the FLB_* and CMT_DECODE_MSGPACK_* groups.
             */
            break;
        }
        else if (result != CMT_DECODE_MSGPACK_SUCCESS) {
            flb_plg_error(ctx->ins, "Error decoding msgpack encoded context");

            result = FLB_ERROR;
        }
        else {
            encoded_chunk = cmt_encode_prometheus_remote_write_create(cmt);

            if (encoded_chunk == NULL) {
                flb_plg_error(ctx->ins, "Error encoding context as prometheus remote write");

                result = FLB_ERROR;
            }
            else {
                result = http_post(ctx, encoded_chunk, flb_sds_len(encoded_chunk), tag, tag_len);

                cmt_encode_text_destroy(encoded_chunk);
            }

            cmt_destroy(cmt);
        }
    }

    FLB_OUTPUT_RETURN(result);
}

static int cb_prom_exit(void *data, struct flb_config *config)
{
    struct prometheus_remote_write_context *ctx;

    ctx = (struct prometheus_remote_write_context *) data;

    flb_prometheus_remote_write_context_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "proxy", NULL,
     0, FLB_FALSE, 0,
     "Specify an HTTP Proxy. The expected format of this value is http://host:port. "
    },
    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct prometheus_remote_write_context, http_user),
     "Set HTTP auth user"
    },
    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct prometheus_remote_write_context, http_passwd),
     "Set HTTP auth password"
    },
    {
     FLB_CONFIG_MAP_STR, "uri", NULL,
     0, FLB_TRUE, offsetof(struct prometheus_remote_write_context, uri),
     "Specify an optional HTTP URI for the target web server, e.g: /something"
    },
    {
     FLB_CONFIG_MAP_BOOL, "log_response_payload", "true",
     0, FLB_TRUE, offsetof(struct prometheus_remote_write_context, log_response_payload),
     "Specify if the response paylod should be logged or not"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_prometheus_remote_write_plugin = {
    .name        = "prometheus_remote_write",
    .description = "Prometheus remote write",
    .cb_init     = cb_prom_init,
    .cb_flush    = cb_prom_flush,
    .cb_exit     = cb_prom_exit,
    .config_map  = config_map,
    .event_type  = FLB_OUTPUT_METRICS,
    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
