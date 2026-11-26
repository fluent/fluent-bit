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
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_zstd.h>
#include <fluent-bit/http_server/flb_hs_utils.h>
#include "prom.h"
#include "prom_http.h"

enum prom_http_encoding {
    PROM_HTTP_IDENTITY,
    PROM_HTTP_GZIP,
    PROM_HTTP_ZSTD,
    PROM_HTTP_SNAPPY,
    PROM_HTTP_WILDCARD,
    PROM_HTTP_ENCODING_COUNT
};

static const char *const prom_http_encoding_name[] = {
    [PROM_HTTP_IDENTITY] = "identity",
    [PROM_HTTP_GZIP] = "gzip",
    [PROM_HTTP_ZSTD] = "zstd",
    [PROM_HTTP_SNAPPY] = "snappy",
    [PROM_HTTP_WILDCARD] = "*"
};

/* Parse an HTTP quality value as an integer in thousandths. */
static int prom_http_encoding_quality(const char *parameter, const char *end)
{
    int quality;
    int factor = 100;

    while (parameter < end && (*parameter == ' ' || *parameter == '\t')) {
        parameter++;
    }
    if (parameter == end) {
        return 1000;
    }
    if (*parameter++ != ';') {
        return 0;
    }
    while (parameter < end && (*parameter == ' ' || *parameter == '\t')) {
        parameter++;
    }
    while (end > parameter && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }
    if (end - parameter < 3 || strncasecmp(parameter, "q=", 2) != 0) {
        return 0;
    }
    parameter += 2;
    if (*parameter != '0' && *parameter != '1') {
        return 0;
    }
    quality = (*parameter++ - '0') * 1000;
    if (parameter < end && *parameter++ != '.') {
        return 0;
    }
    while (parameter < end) {
        if (factor == 0 || *parameter < '0' || *parameter > '9' ||
            (quality == 1000 && *parameter != '0')) {
            return 0;
        }
        quality += (*parameter++ - '0') * factor;
        factor /= 10;
    }
    return quality;
}

static int prom_http_response_encoding(const char *header, int *identity_allowed)
{
    int encoding;
    int selected;
    int quality;
    int selected_quality;
    int qualities[PROM_HTTP_ENCODING_COUNT] = {-1, -1, -1, -1, -1};
    size_t name_length;
    const char *cursor;
    const char *end;
    const char *name;

    cursor = header;
    while (cursor != NULL && *cursor != '\0') {
        cursor += strspn(cursor, " \t,");
        end = cursor + strcspn(cursor, ",");
        name_length = strcspn(cursor, " \t;,");
        for (encoding = 0; encoding < PROM_HTTP_ENCODING_COUNT; encoding++) {
            name = prom_http_encoding_name[encoding];
            if (name_length == strlen(name) && strncasecmp(cursor, name, name_length) == 0) {
                quality = prom_http_encoding_quality(cursor + name_length, end);
                if (qualities[encoding] < 0 || quality < qualities[encoding]) {
                    qualities[encoding] = quality;
                }
                break;
            }
        }
        cursor = *end == ',' ? end + 1 : end;
    }

    quality = qualities[PROM_HTTP_IDENTITY];
    *identity_allowed = quality != 0 && (quality > 0 || qualities[PROM_HTTP_WILDCARD] != 0);
    selected = PROM_HTTP_IDENTITY;
    selected_quality = *identity_allowed ? quality : 0;

    /* Keep gzip first on ties. Only offer raw Snappy to clients that name it. */
    for (encoding = PROM_HTTP_GZIP; encoding < PROM_HTTP_WILDCARD; encoding++) {
        quality = qualities[encoding];
        if (quality < 0 && encoding != PROM_HTTP_SNAPPY) {
            quality = qualities[PROM_HTTP_WILDCARD];
        }
        if (quality > 0 && (quality > selected_quality ||
                            (quality == selected_quality && selected == PROM_HTTP_IDENTITY))) {
            selected = encoding;
            selected_quality = quality;
        }
    }
    return selected;
}

static int prom_http_send_metrics(struct flb_http_request *request,
                                  struct flb_http_response *response,
                                  char *payload, size_t size)
{
    int encoding;
    int identity_allowed;
    int ret;
    void *compressed = NULL;
    char *snappy_payload;
    size_t compressed_size;

    ret = flb_http_response_set_header(response, "Vary", 0, "Accept-Encoding", 0);
    if (ret != 0) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    encoding = prom_http_response_encoding(
        flb_http_request_get_header(request, "accept-encoding"), &identity_allowed);
    if (encoding == PROM_HTTP_IDENTITY && !identity_allowed) {
        flb_http_response_set_status(response, 406);
        return flb_http_response_commit(response);
    }

    ret = 0;
    if (size > 0 || !identity_allowed) {
        switch (encoding) {
        case PROM_HTTP_GZIP:
            ret = flb_gzip_compress(payload, size, &compressed, &compressed_size);
            break;
        case PROM_HTTP_ZSTD:
            ret = flb_zstd_compress(payload, size, &compressed, &compressed_size);
            break;
        case PROM_HTTP_SNAPPY:
            ret = flb_snappy_compress(payload, size, &snappy_payload, &compressed_size);
            if (ret == 0) {
                compressed = snappy_payload;
            }
            break;
        }
    }

    if (ret != 0 && !identity_allowed) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }
    flb_http_response_set_status(response, 200);
    flb_hs_response_set_content_type(response, FLB_HS_CONTENT_TYPE_PROMETHEUS);
    if (compressed != NULL) {
        ret = flb_http_response_set_body(response, compressed, compressed_size);
        flb_free(compressed);
        if (ret == 0) {
            ret = flb_http_response_set_header(response, "Content-Encoding", 0,
                                               (char *) prom_http_encoding_name[encoding], 0);
        }
    }
    else {
        ret = flb_http_response_set_body(response, (unsigned char *) payload, size);
    }
    if (ret != 0) {
        flb_http_response_set_body(response, NULL, 0);
        flb_http_response_set_status(response, 500);
    }
    return flb_http_response_commit(response);
}

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

    if (source_payload != NULL && payload == NULL) {
        flb_http_response_set_status(response, 500);
        return flb_http_response_commit(response);
    }

    ret = prom_http_send_metrics(request, response, payload ? payload : "",
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
        options.idle_timeout = ins->http_server_config->idle_timeout;
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
