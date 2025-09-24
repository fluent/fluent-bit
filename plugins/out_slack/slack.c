/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_log_event_decoder.h>

#include "slack.h"

#define FLB_HTTP_CONTENT_TYPE   "Content-Type"
#define FLB_HTTP_MIME_JSON      "application/json"

static int cb_slack_init(struct flb_output_instance *ins,
                         struct flb_config *config, void *data)
{
    int ret;
    char *protocol = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;
    struct flb_slack *ctx;
    (void) config;
    (void) data;

    /* Allocate context */
    ctx = flb_calloc(1, sizeof(struct flb_slack));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);

    /* Create config map and validate expected parameters */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Validate if the slack webhook is defined */
    if (!ctx->webhook) {
        flb_plg_error(ctx->ins, "the 'webhook' address has not been defined");
        return -1;
    }

    /* Split the address */
    ret = flb_utils_url_split(ctx->webhook, &protocol, &host, &port, &uri);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not process 'webhook' address");
        return -1;
    }

    if (strcasecmp(protocol, "https") != 0) {
        flb_plg_error(ctx->ins, "invalid protocol '%s', we expected 'https'",
                      protocol);
        goto error;
    }

    if (!host) {
        flb_plg_error(ctx->ins, "invalid slack host");
        goto error;
    }

    if (!uri) {
        flb_plg_error(ctx->ins, "slack webhook uri has not been defined");
        goto error;
    }

    ctx->host = flb_sds_create(host);
    ctx->uri = flb_sds_create(uri);

    if (port) {
        ctx->port = atoi(port);
    }
    else {
        ctx->port = 443;
    }

    /* Create upstream context */
    ctx->u = flb_upstream_create(config,
                                 ctx->host,
                                 ctx->port,
                                 FLB_IO_TLS, ins->tls);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "error creating upstream context");
        goto error;
    }

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    /* Cleanup */
    if (protocol) {
        flb_free(protocol);
    }
    if (host) {
        flb_free(host);
    }
    if (port) {
        flb_free(port);
    }
    if (uri) {
        flb_free(uri);
    }

    return 0;

error:
    if (protocol) {
        flb_free(protocol);
    }
    if (host) {
        flb_free(host);
    }
    if (port) {
        flb_free(port);
    }
    if (uri) {
        flb_free(uri);
    }

    return -1;
}

static void cb_slack_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    int len;
    int ret;
    int out_ret = FLB_OK;
    size_t size;
    size_t printed = 0;
    size_t b_sent;
    flb_sds_t json;
    flb_sds_t out_buf;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct flb_http_client *c;
    struct flb_connection *u_conn;
    struct flb_slack *ctx = out_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    size = event_chunk->size * 4;
    json = flb_sds_create_size(size);
    if (!json) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    memset(json, '\0', size);

    ret = flb_log_event_decoder_init(&log_decoder,
                                     (char *) event_chunk->data,
                                     event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        flb_sds_destroy(json);

        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        ret = snprintf(json + printed, size - printed,
                       "[\"timestamp\": %" PRIu32 ".%09lu, ",
                       (uint32_t) log_event.timestamp.tm.tv_sec,
                       log_event.timestamp.tm.tv_nsec);
        printed += ret;

        ret = msgpack_object_print_buffer(json + printed,
                                          size - printed,
                                          *log_event.body);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "error formatting payload");
            flb_sds_destroy(json);
            flb_log_event_decoder_destroy(&log_decoder);

            FLB_OUTPUT_RETURN(FLB_RETRY);
        }

        /* the previous call returns the remaining available space in the buffer */
        printed += ret;
        json[printed++] = ']';
        json[printed++] = '\n';
    }

    flb_log_event_decoder_destroy(&log_decoder);

    /* Take formatted message and convert it to msgpack */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    len = strlen(json);

    msgpack_pack_map(&mp_pck, 1);
    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "text", 4);
    msgpack_pack_str(&mp_pck, len);
    msgpack_pack_str_body(&mp_pck, json, len);

    /* Release buffer */
    flb_sds_destroy(json);

    /* Re-format mspgack as JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, config->json_escape_unicode);
    if (!out_buf) {
        msgpack_sbuffer_destroy(&mp_sbuf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    msgpack_sbuffer_destroy(&mp_sbuf);

    /* Create upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_sds_destroy(out_buf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        out_buf, flb_sds_len(out_buf),
                        ctx->host, ctx->port,
                        NULL, 0);
    flb_http_add_header(c,
                        FLB_HTTP_CONTENT_TYPE,
                        sizeof(FLB_HTTP_CONTENT_TYPE) - 1,
                        FLB_HTTP_MIME_JSON,
                        sizeof(FLB_HTTP_MIME_JSON) - 1);
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    ret = flb_http_do(c, &b_sent);
    if (ret == 0) {
        if (c->resp.status < 200 || c->resp.status > 205) {
            flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                      ctx->host, ctx->port, c->resp.status);
            out_ret = FLB_RETRY;
        }
        else {
            if (c->resp.payload) {
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

    flb_upstream_conn_release(u_conn);
    flb_http_client_destroy(c);
    flb_sds_destroy(out_buf);
    FLB_OUTPUT_RETURN(out_ret);
}

static int cb_slack_exit(void *data, struct flb_config *config)
{
    struct flb_slack *ctx;

    ctx = (struct flb_slack *) data;
    if (!ctx) {
        return 0;
    }

    if (ctx->host) {
        flb_sds_destroy(ctx->host);
    }
    if (ctx->uri) {
        flb_sds_destroy(ctx->uri);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_free(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "webhook", NULL,
        0, FLB_TRUE, offsetof(struct flb_slack, webhook),
        NULL
    },

    /* EOF */
    {0}
};

struct flb_output_plugin out_slack_plugin = {
    .name         = "slack",
    .description  = "Send events to a Slack channel",
    .cb_init      = cb_slack_init,
    .cb_flush     = cb_slack_flush,
    .cb_exit      = cb_slack_exit,
    .flags        = FLB_OUTPUT_NET | FLB_IO_TLS,
    .config_map   = config_map
};
