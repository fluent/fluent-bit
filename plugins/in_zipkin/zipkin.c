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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_sds.h>

#include "zipkin.h"
#include "zipkin_decoder.h"

#define ZIPKIN_V2_SPANS_PATH "/api/v2/spans"

static int zipkin_send_response(struct flb_http_response *response, int status,
                                const char *message, const char *body)
{
    flb_http_response_set_status(response, status);
    flb_http_response_set_message(response, (char *) message);
    flb_http_response_set_header(response, "Content-Type", 12,
                                 "text/plain; charset=utf-8", 25);

    if (body != NULL) {
        flb_http_response_set_body(response, (unsigned char *) body, strlen(body));
    }

    return flb_http_response_commit(response);
}

static int zipkin_content_type_is_json(const char *content_type)
{
    size_t length;
    size_t expected_length;
    const char *expected;

    if (content_type == NULL) {
        return FLB_FALSE;
    }

    expected = "application/json";
    expected_length = strlen(expected);
    length = strlen(content_type);

    if (length < expected_length ||
        strncasecmp(content_type, expected, expected_length) != 0) {
        return FLB_FALSE;
    }

    if (content_type[expected_length] == '\0' ||
        content_type[expected_length] == ';' ||
        content_type[expected_length] == ' ' ||
        content_type[expected_length] == '\t') {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static int zipkin_ingest(struct flb_zipkin *ctx, struct ctrace *trace,
                         size_t payload_size)
{
    if (zipkin_uses_worker_ingress_queue(ctx)) {
        return flb_input_ingress_queue_traces(ctx->ins, NULL, 0,
                                              trace, payload_size);
    }

    return flb_input_trace_append(ctx->ins, NULL, 0, trace);
}

static int zipkin_request_handler(struct flb_http_request *request,
                                  struct flb_http_response *response)
{
    int ret;
    size_t span_count;
    struct ctrace *trace;
    struct flb_zipkin *ctx;
    char error[ZIPKIN_DECODE_ERROR_SIZE];

    ctx = request->stream->user_data;

    if (request->path == NULL ||
        strcmp(request->path, ZIPKIN_V2_SPANS_PATH) != 0) {
        return zipkin_send_response(response, 404, "Not Found", "not found\n");
    }

    if (request->method != HTTP_METHOD_POST) {
        flb_http_response_set_header(response, "Allow", 5, "POST", 4);
        return zipkin_send_response(response, 405, "Method Not Allowed",
                                    "method not allowed\n");
    }

    if (zipkin_content_type_is_json(request->content_type) == FLB_FALSE) {
        return zipkin_send_response(response, 415, "Unsupported Media Type",
                                    "expected application/json\n");
    }

    if (request->body == NULL || cfl_sds_len(request->body) == 0) {
        return zipkin_send_response(response, 400, "Bad Request", "empty request body\n");
    }

    trace = NULL;
    span_count = 0;
    ret = zipkin_decode_json(request->body, cfl_sds_len(request->body),
                             ctx->parse_string_tags, &trace, &span_count, error);
    if (ret != 0) {
        flb_plg_debug(ctx->ins, "rejected Zipkin payload: %s", error);
        return zipkin_send_response(response, 400, "Bad Request", error);
    }

    if (span_count > 0) {
        ret = zipkin_ingest(ctx, trace, cfl_sds_len(request->body));
        if (ret != 0) {
            if (zipkin_uses_worker_ingress_queue(ctx) == FLB_FALSE) {
                ctr_destroy(trace);
            }

            flb_plg_error(ctx->ins, "could not ingest Zipkin trace payload");
            return zipkin_send_response(response, 503, "Service Unavailable",
                                        "ingestion queue unavailable\n");
        }
    }
    else {
        ctr_destroy(trace);
    }

    return zipkin_send_response(response, 202, "Accepted", NULL);
}

static int in_zipkin_init(struct flb_input_instance *ins,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_zipkin *ctx;
    struct flb_http_server_options options;

    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_zipkin));
    if (ctx == NULL) {
        flb_errno();
        return -1;
    }

    ctx->ins = ins;
    flb_input_net_default_listener("0.0.0.0", 9411, ins);

    ret = flb_input_config_map_set(ins, ctx);
    if (ret != 0) {
        flb_plg_error(ins, "configuration error");
        flb_free(ctx);
        return -1;
    }

    flb_input_set_context(ins, ctx);

    ret = flb_input_http_server_options_init(&options, ins,
                                              FLB_HTTP_SERVER_FLAG_KEEPALIVE |
                                              FLB_HTTP_SERVER_FLAG_AUTO_INFLATE,
                                              zipkin_request_handler, ctx);
    if (ret == 0 && options.workers > 1) {
        ret = flb_input_ingress_enable(ins);
    }
    if (ret == 0) {
        ret = flb_http_server_init_with_options(&ctx->http_server, &options);
    }
    if (ret == 0) {
        ret = flb_http_server_start(&ctx->http_server);
    }
    if (ret == 0 && ctx->http_server.downstream != NULL) {
        ret = flb_input_downstream_set(ctx->http_server.downstream, ins);
    }

    if (ret != 0) {
        flb_plg_error(ins, "could not start Zipkin HTTP server on %s:%u",
                      ins->host.listen, ins->host.port);
        flb_http_server_destroy(&ctx->http_server);
        flb_free(ctx);
        return -1;
    }

    flb_plg_info(ins, "listening for Zipkin v2 spans on %s:%u with %i worker%s",
                 ins->host.listen, ins->host.port, ctx->http_server.workers,
                 ctx->http_server.workers == 1 ? "" : "s");

    return 0;
}

static int in_zipkin_pause(void *data, struct flb_config *config)
{
    struct flb_zipkin *ctx;

    (void) config;
    ctx = data;

    if (flb_http_server_pause(&ctx->http_server) != 0) {
        flb_plg_error(ctx->ins, "could not pause Zipkin HTTP server");
        return -1;
    }

    return 0;
}

static int in_zipkin_resume(void *data, struct flb_config *config)
{
    struct flb_zipkin *ctx;

    (void) config;
    ctx = data;

    if (flb_http_server_resume(&ctx->http_server) != 0) {
        flb_plg_error(ctx->ins, "could not resume Zipkin HTTP server");
        return -1;
    }

    return 0;
}

static int in_zipkin_exit(void *data, struct flb_config *config)
{
    struct flb_zipkin *ctx;

    (void) config;
    ctx = data;

    if (ctx != NULL) {
        flb_http_server_destroy(&ctx->http_server);
        flb_free(ctx);
    }

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "parse_string_tags", "false",
     0, FLB_TRUE, offsetof(struct flb_zipkin, parse_string_tags),
     "Convert Zipkin string tag values to boolean, integer, or double values when possible"
    },
    {0}
};

struct flb_input_plugin in_zipkin_plugin = {
    .name              = "zipkin",
    .description       = "Zipkin v2 trace receiver",
    .cb_init           = in_zipkin_init,
    .cb_pre_run        = NULL,
    .cb_collect        = NULL,
    .cb_flush_buf      = NULL,
    .cb_pause_checked  = in_zipkin_pause,
    .cb_resume_checked = in_zipkin_resume,
    .cb_exit           = in_zipkin_exit,
    .config_map        = config_map,
    .flags             = FLB_INPUT_NET_SERVER | FLB_INPUT_HTTP_SERVER | FLB_IO_OPT_TLS
};
