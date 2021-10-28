/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <fluent-bit.h>

#define _OPEN_SYS_ITOA_EXT
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

#define MAX_SOCK_NAME_PATH 108

typedef struct collectx_plugin_api_ctx_t {
    flb_ctx_t *flb_ctx;

    int in_ffd;
    int out_ffd;
} collectx_plugin_api_ctx_t;


typedef struct collectx_plugin_input_data {
    int32_t   fluent_aggr_sock_fd;
    char      collector_sock_name[MAX_SOCK_NAME_PATH];
} collectx_plugin_input_data_t;


void* initialize(uint16_t port, int fluent_aggr_sock_fd, const char* collector_sock_name) {
    collectx_plugin_api_ctx_t* api_ctx = (collectx_plugin_api_ctx_t*) calloc(1, sizeof(collectx_plugin_api_ctx_t));

    /* Initialize library */
    api_ctx->flb_ctx = flb_create();
    if (!api_ctx->flb_ctx) {
        printf("[FLuentBit Collectx plugin API] cannot create fluentbit context\n"); fflush(stdout);
        return NULL;
    }
    flb_service_set(api_ctx->flb_ctx, "Flush", "0.1", NULL);
    flb_service_set(api_ctx->flb_ctx, "Grace", "1", NULL);

    api_ctx->in_ffd = -1;
    api_ctx->in_ffd = flb_input(api_ctx->flb_ctx, "forward", NULL);
    if (api_ctx->in_ffd == -1) {
        printf("[FLuentBit Collectx plugin API] cannot create input 'forward' plugin\n"); fflush(stdout);
        return NULL;
    }
    char port_str[6];
    memset(port_str, 0, 6);
    sprintf(port_str, "%d", port);

    flb_input_set(api_ctx->flb_ctx, api_ctx->in_ffd, "Port", port_str, NULL);

    collectx_plugin_input_data_t* input_data = calloc(1, sizeof(collectx_plugin_input_data_t));
    input_data->fluent_aggr_sock_fd = (uint32_t)fluent_aggr_sock_fd;
    memset(input_data->collector_sock_name, 0, MAX_SOCK_NAME_PATH);
    strncpy(input_data->collector_sock_name, collector_sock_name, MAX_SOCK_NAME_PATH);
    api_ctx->out_ffd = -1;
    api_ctx->out_ffd = flb_output(api_ctx->flb_ctx, "collectx", (void*) input_data);

    if (api_ctx->out_ffd == -1) {
        printf("[FLuentBit Collectx plugin API] cannot create output 'collectx' plugin.\n"); fflush(stdout);
        return NULL;
    }

    flb_output_set(api_ctx->flb_ctx, api_ctx->out_ffd, "match", "*", NULL);

    // Start the background worker
    flb_start(api_ctx->flb_ctx);
    free(input_data);
    return api_ctx;
}


int finalize(void* ctx) {
    collectx_plugin_api_ctx_t* api_ctx = (collectx_plugin_api_ctx_t*) ctx;

    flb_stop(api_ctx->flb_ctx);
    flb_destroy(api_ctx->flb_ctx);
    return 0;
}
