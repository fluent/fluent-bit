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
#include <fluent-bit/flb_http_server.h>
#include <fluent-bit/http_server/flb_hs_utils.h>
#include "prom.h"
#include "prom_http.h"

static int prom_http_request_handler(struct flb_http_request *request,
                                     struct flb_http_response *response)
{
    int ret;
    cfl_sds_t payload;
    cfl_sds_t source_payload;
    struct prom_exporter *ctx;
    struct prom_http *ph;

    ctx = response->stream->user_data;
    if (ctx == NULL || ctx->http == NULL) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    ph = ctx->http;

    if (strcmp(request->path, "/") == 0) {
        return flb_hs_response_send_string(response,
                                           200,
                                           FLB_HS_CONTENT_TYPE_OTHER,
                                           "Fluent Bit Prometheus Exporter\n");
    }

    if (strcmp(request->path, "/metrics") != 0) {
        flb_http_response_set_status(response, 404);
        return flb_http_response_commit(response);
    }

    pthread_mutex_lock(&ph->metrics_mutex);
    source_payload = ph->metrics_payload;
    if (source_payload != NULL) {
        payload = cfl_sds_create_len(source_payload, cfl_sds_len(source_payload));
    }
    else {
        payload = NULL;
    }
    pthread_mutex_unlock(&ph->metrics_mutex);

    if (payload == NULL) {
        if (source_payload == NULL) {
            return flb_hs_response_set_payload(response,
                                               200,
                                               FLB_HS_CONTENT_TYPE_PROMETHEUS,
                                               NULL,
                                               0);
        }

        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }
    ret = flb_hs_response_set_payload(response,
                                      200,
                                      FLB_HS_CONTENT_TYPE_PROMETHEUS,
                                      payload,
                                      cfl_sds_len(payload));

    cfl_sds_destroy(payload);

    return ret;
}

struct prom_http *prom_http_server_create(struct prom_exporter *ctx,
                                          struct flb_config *config)
{
    int ret;
    int protocol_version;
    struct prom_http *ph;
    struct flb_output_instance *ins;
    struct flb_http_server_options options;

    ph = flb_calloc(1, sizeof(struct prom_http));
    if (!ph) {
        flb_errno();
        return NULL;
    }

    ins = ctx->ins;
    ph->config = config;
    pthread_mutex_init(&ph->metrics_mutex, NULL);

    if (ins->http_server_config != NULL &&
        ins->http_server_config->http2 == FLB_FALSE) {
        protocol_version = HTTP_PROTOCOL_VERSION_11;
    }
    else {
        protocol_version = HTTP_PROTOCOL_VERSION_AUTODETECT;
    }

    flb_http_server_options_init(&options);
    options.protocol_version = protocol_version;
    options.flags = 0;
    options.request_callback = prom_http_request_handler;
    options.user_data = ctx;
    options.address = ins->host.name;
    options.port = ins->host.port;
    options.networking_flags = ins->flags;
    options.networking_setup = &ins->net_setup;
    options.event_loop = config->evl;
    options.system_context = config;
    options.use_caller_event_loop = FLB_TRUE;

    if (ins->http_server_config != NULL) {
        options.buffer_max_size = ins->http_server_config->buffer_max_size;
        options.max_connections = ins->http_server_config->max_connections;
    }

    ret = flb_http_server_init_with_options(&ph->server, &options);
    if (ret != 0) {
        pthread_mutex_destroy(&ph->metrics_mutex);
        flb_free(ph);
        return NULL;
    }

    return ph;
}

void prom_http_server_destroy(struct prom_http *ph)
{
    if (ph) {
        flb_http_server_destroy(&ph->server);

        if (ph->metrics_payload != NULL) {
            cfl_sds_destroy(ph->metrics_payload);
        }

        pthread_mutex_destroy(&ph->metrics_mutex);
        flb_free(ph);
    }
}

int prom_http_server_start(struct prom_http *ph)
{
    return flb_http_server_start(&ph->server);
}

int prom_http_server_stop(struct prom_http *ph)
{
    return flb_http_server_stop(&ph->server);
}

int prom_http_server_mq_push_metrics(struct prom_http *ph,
                                     void *data, size_t size)
{
    cfl_sds_t new_payload;

    new_payload = cfl_sds_create_len(data, size);
    if (new_payload == NULL) {
        return -1;
    }

    pthread_mutex_lock(&ph->metrics_mutex);

    if (ph->metrics_payload != NULL) {
        cfl_sds_destroy(ph->metrics_payload);
    }

    ph->metrics_payload = new_payload;

    pthread_mutex_unlock(&ph->metrics_mutex);

    return 0;
}
