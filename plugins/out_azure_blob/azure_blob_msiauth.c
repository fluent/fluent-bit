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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>

#include "azure_blob_msiauth.h"

char *flb_azure_blob_msiauth_token_get(struct flb_oauth2 *ctx)
{
    int ret;
    size_t b_sent;
    time_t now;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    now = time(NULL);
    if (ctx->access_token) {
        /* validate unexpired token */
        if (ctx->expires_at > now && flb_sds_len(ctx->access_token) > 0) {
            return ctx->access_token;
        }
    }

    /* Get Token and store it in the context */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_error("[azure blob msi auth] could not get an upstream connection to %s:%i",
                  ctx->u->tcp_host, ctx->u->tcp_port);
        return NULL;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_GET, ctx->uri,
                        NULL, 0,
                        ctx->host, atoi(ctx->port),
                        NULL, 0);
    if (!c) {
        flb_error("[azure blob msi auth] error creating HTTP client context");
        flb_upstream_conn_release(u_conn);
        return NULL;
    }

    /* Append HTTP Header */
    flb_http_add_header(c, "Metadata", 8, "true", 4);

    /* Issue request */
    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[azure blob msi auth] cannot issue request, http_do=%i", ret);
    }
    else {
        flb_info("[azure blob msi auth] HTTP Status=%i", c->resp.status);
        if (c->resp.payload_size > 0) {
            if (c->resp.status == 200) {
                flb_debug("[azure blob msi auth] payload:\n%s", c->resp.payload);
            }
            else {
                flb_info("[azure blob msi auth] payload:\n%s", c->resp.payload);
            }
        }
    }

    /* Extract token */
    if (c->resp.payload_size > 0 && c->resp.status == 200) {
        ret = flb_oauth2_parse_json_response(c->resp.payload,
                                             c->resp.payload_size, ctx);
        if (ret == 0) {
            flb_info("[azure blob msi auth] access token from '%s:%s' retrieved",
                     ctx->host, ctx->port);
            flb_http_client_destroy(c);
            flb_upstream_conn_release(u_conn);
            ctx->expires_at = time(NULL) + ctx->expires_in;
            return ctx->access_token;
        }
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return NULL;
}

/* Read token from file */
static flb_sds_t read_token_from_file(const char *token_file)
{
    FILE *fp;
    flb_sds_t token = NULL;
    char buf[4096];
    size_t bytes_read;

    if (!token_file) {
        flb_error("[azure blob workload identity] token file path is NULL");
        return NULL;
    }

    fp = fopen(token_file, "r");
    if (!fp) {
        flb_error("[azure blob workload identity] could not open token file: %s",
                  token_file);
        return NULL;
    }

    bytes_read = fread(buf, 1, sizeof(buf) - 1, fp);
    if (bytes_read == sizeof(buf) - 1 && !feof(fp)) {
        fclose(fp);
        flb_error("[azure blob workload identity] token file too large: %s",
                  token_file);
        return NULL;
    }
    fclose(fp);

    if (bytes_read <= 0) {
        flb_error("[azure blob workload identity] could not read token from file: %s",
                  token_file);
        return NULL;
    }

    buf[bytes_read] = '\0';
    token = flb_sds_create(buf);

    return token;
}

int flb_azure_blob_workload_identity_token_get(struct flb_oauth2 *ctx,
                                               const char *token_file,
                                               const char *client_id,
                                               const char *tenant_id)
{
    int ret;
    size_t b_sent;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    flb_sds_t federated_token;
    flb_sds_t body = NULL;

    /* Default token file location if not specified */
    if (!token_file) {
        token_file = "/var/run/secrets/azure/tokens/azure-identity-token";
    }

    /* Read the federated token from file */
    federated_token = read_token_from_file(token_file);
    if (!federated_token) {
        flb_error("[azure blob workload identity] failed to read federated token");
        return -1;
    }

    /* Build the form data for token exchange */
    body = flb_sds_create_size(4096);
    if (!body) {
        flb_error("[azure blob workload identity] failed to allocate request body");
        flb_sds_destroy(federated_token);
        return -1;
    }

    body = flb_sds_cat(body, "client_id=", 10);
    body = flb_sds_cat(body, client_id, strlen(client_id));
    body = flb_sds_cat(body, "&grant_type=client_credentials", 30);
    body = flb_sds_cat(body,
                       "&client_assertion_type="
                       "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", 77);
    body = flb_sds_cat(body, "&client_assertion=", 18);
    body = flb_sds_cat(body, federated_token, flb_sds_len(federated_token));
    body = flb_sds_cat(body,
                       "&scope=https://storage.azure.com/.default", 41);

    if (!body) {
        flb_error("[azure blob workload identity] failed to build request body");
        flb_sds_destroy(federated_token);
        return -1;
    }

    /* Get upstream connection to Azure AD token endpoint */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_error("[azure blob workload identity] could not get upstream connection");
        flb_sds_destroy(federated_token);
        flb_sds_destroy(body);
        return -1;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        body, flb_sds_len(body),
                        ctx->host, atoi(ctx->port), NULL, 0);
    if (!c) {
        flb_error("[azure blob workload identity] error creating HTTP client context");
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(federated_token);
        flb_sds_destroy(body);
        return -1;
    }

    /* Set content type header */
    flb_http_add_header(c, "Content-Type", 12,
                        "application/x-www-form-urlencoded", 33);

    /* Issue request */
    ret = flb_http_do(c, &b_sent);

    flb_sds_destroy(body);
    body = NULL;

    if (ret != 0) {
        flb_warn("[azure blob workload identity] HTTP request error, http_do=%i", ret);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(federated_token);
        return -1;
    }

    flb_debug("[azure blob workload identity] HTTP Status=%i", c->resp.status);
    if (c->resp.payload_size > 0 && c->resp.status != 200) {
        flb_warn("[azure blob workload identity] token exchange failed: %s",
                 c->resp.payload);
        flb_http_client_destroy(c);
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(federated_token);
        return -1;
    }

    /* Parse the response and extract the token */
    if (c->resp.payload_size > 0 && c->resp.status == 200) {
        ret = flb_oauth2_parse_json_response(c->resp.payload,
                                             c->resp.payload_size, ctx);
        if (ret == 0) {
            flb_info("[azure blob workload identity] access token retrieved");
            flb_http_client_destroy(c);
            flb_upstream_conn_release(u_conn);
            flb_sds_destroy(federated_token);
            ctx->expires_at = time(NULL) + ctx->expires_in;
            return 0;
        }
    }

    flb_error("[azure blob workload identity] failed to parse token response");
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    flb_sds_destroy(federated_token);

    return -1;
}
