/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_config.h>

#include "http2.h"
#include "http2_prot.h"
#include "http2_config.h"

int request_processor(struct flb_http_request_ng *request,
                      struct flb_http_response_ng *response)
{
    char *sample;
    int   zz;

    printf("REQUEST PROCESSOR\n");

    if (request->method == MK_METHOD_POST) {
        printf("BODY LENGTH : %zu\n\n", cfl_sds_len(request->body));

        for (zz = 0 ; zz < cfl_sds_len(request->body) ; zz++) {
            printf("%c", request->body[zz]);
        }

        printf("\n\n");
    }

    sample = flb_http_request_get_header(request, "user-agent");

    if (sample != NULL) {
        printf("HEADER VALUE = %s\n", sample);
    }

    flb_http_response_set_header(response, "test", 4, "value", 5);
    flb_http_response_set_header(response, "content-length", 14, "5", 1);
    flb_http_response_set_status(response, 200);
    flb_http_response_set_message(response, "TEST MESSAGE!");
    flb_http_response_set_body(response, (unsigned char *) "TEST!", 5);
    flb_http_response_commit(response);

    return 0;
}

static int in_http2_init(struct flb_input_instance *ins,
                        struct flb_config *config, void *data)
{
    unsigned short int  port;
    int                 ret;
    struct flb_http2    *ctx;

    (void) data;

    /* Create context and basic conf */
    ctx = http2_config_create(ins);
    if (!ctx) {
        return -1;
    }

    ctx->collector_id = -1;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        http2_config_destroy(ctx);
        return -1;
    }

    /* Set the context */
    flb_input_set_context(ins, ctx);

    ret = flb_http_server_start(&ctx->http_server);

    if (ret != 0) {
        flb_plg_error(ctx->ins,
                      "could not initialize downstream on %s:%s. Aborting",
                      ctx->listen, ctx->tcp_port);

        http2_config_destroy(ctx);

        return -1;
    }

    ctx->http_server.request_callback = http2_handle_request;

    flb_input_downstream_set(ctx->http_server.downstream, ctx->ins);

    if (ctx->successful_response_code != 200 &&
        ctx->successful_response_code != 201 &&
        ctx->successful_response_code != 204) {
        flb_plg_error(ctx->ins, "%d is not supported response code. Use default 201",
                      ctx->successful_response_code);
        ctx->successful_response_code = 201;
    }

    return 0;
}

static int in_http2_exit(void *data, struct flb_config *config)
{
    struct flb_http2 *ctx;

    (void) config;

    ctx = data;

    if (ctx != NULL) {
        http2_config_destroy(ctx);
    }

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SIZE, "buffer_max_size", HTTP_BUFFER_MAX_SIZE,
     0, FLB_TRUE, offsetof(struct flb_http2, buffer_max_size),
     ""
    },

    {
     FLB_CONFIG_MAP_SIZE, "buffer_chunk_size", HTTP_BUFFER_CHUNK_SIZE,
     0, FLB_TRUE, offsetof(struct flb_http2, buffer_chunk_size),
     ""
    },

    {
     FLB_CONFIG_MAP_SLIST_1, "success_header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_http2, success_headers),
     "Add an HTTP header key/value pair on success. Multiple headers can be set"
    },

    {
     FLB_CONFIG_MAP_STR, "tag_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_http2, tag_key),
     ""
    },
    {
     FLB_CONFIG_MAP_INT, "successful_response_code", "201",
     0, FLB_TRUE, offsetof(struct flb_http2, successful_response_code),
     "Set successful response code. 200, 201 and 204 are supported."
    },


    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_http2_plugin = {
    .name         = "http2",
    .description  = "HTTP2",
    .cb_init      = in_http2_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = in_http2_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_IO_OPT_TLS
};
