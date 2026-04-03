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
#include <fluent-bit/flb_azure_auth.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

char *flb_azure_msi_token_get(struct flb_oauth2 *ctx)
{
    int ret;
    size_t b_sent;
    char *token = NULL;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    /* Get Token and store it in the context */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_error("[azure msi auth] could not get an upstream connection to %s:%d",
                  ctx->u->tcp_host, ctx->u->tcp_port);
        return NULL;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_GET, ctx->uri,
                        NULL, 0,
                        ctx->host, atoi(ctx->port),
                        NULL, 0);
    if (!c) {
        flb_error("[azure msi auth] error creating HTTP client context");
        flb_upstream_conn_release(u_conn);
        return NULL;
    }

    /* Append HTTP Header - IMDS requires Metadata:true header */
    flb_http_add_header(c, "Metadata", 8, "true", 4);

    /* Issue request */
    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[azure msi auth] cannot issue request, http_do=%i", ret);
    }
    else {
        flb_debug("[azure msi auth] HTTP Status=%i", c->resp.status);
    }

    /* Extract token */
    if (c->resp.payload_size > 0 && c->resp.status == 200) {
        ret = flb_oauth2_parse_json_response(c->resp.payload,
                                             c->resp.payload_size, ctx);
        if (ret == 0) {
            flb_info("[azure msi auth] access token from '%s:%s' retrieved",
                     ctx->host, ctx->port);
            ctx->expires_at = time(NULL) + ctx->expires_in;
            token = ctx->access_token;
        }
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return token;
}

/** Read token from file */
static flb_sds_t read_token_from_file(const char *token_file)
{
    FILE *fp;
    flb_sds_t token = NULL;
    char buf[4096]; /* Assuming token won't be larger than 4KB */
    size_t bytes_read;

    if (!token_file) {
        flb_error("[azure workload identity] token file path is NULL");
        return NULL;
    }

    fp = fopen(token_file, "r");
    if (!fp) {
        flb_error("[azure workload identity] could not open token file: %s", token_file);
        return NULL;
    }

    bytes_read = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);

    if (bytes_read <= 0) {
        flb_error("[azure workload identity] could not read token from file: %s", token_file);
        return NULL;
    }

    buf[bytes_read] = '\0';
    token = flb_sds_create(buf);

    return token;
}

int flb_azure_workload_identity_token_get(struct flb_oauth2 *ctx,
                                          const char *token_file,
                                          const char *client_id,
                                          const char *tenant_id,
                                          const char *resource)
{
    int ret = -1;
    size_t b_sent;
    struct flb_connection *u_conn = NULL;
    struct flb_http_client *c = NULL;
    flb_sds_t federated_token = NULL;
    flb_sds_t body = NULL;

    /* Default token file location if not specified */
    if (!token_file) {
        token_file = FLB_AZURE_WORKLOAD_IDENTITY_TOKEN_FILE;
    }

    flb_info("[azure workload identity] initiating token exchange");

    /* Read the federated token from file */
    federated_token = read_token_from_file(token_file);
    if (!federated_token) {
        flb_error("[azure workload identity] failed to read federated token");
        return -1;
    }

    flb_debug("[azure workload identity] federated token read from file: %s", token_file);

    /* Build the form data for token exchange */
    body = flb_sds_create_size(4096);
    if (!body) {
        flb_error("[azure workload identity] failed to allocate memory for request body");
        goto cleanup;
    }

    flb_sds_cat_safe(&body, "client_id=", 10);
    flb_sds_cat_safe(&body, client_id, strlen(client_id));
    flb_sds_cat_safe(&body, "&grant_type=client_credentials", 30);
    flb_sds_cat_safe(&body, "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer", 77);
    flb_sds_cat_safe(&body, "&client_assertion=", 18);
    flb_sds_cat_safe(&body, federated_token, flb_sds_len(federated_token));
    flb_sds_cat_safe(&body, "&scope=", 7);
    flb_sds_cat_safe(&body, resource, strlen(resource));

    if (!body) {
        flb_error("[azure workload identity] failed to build request body");
        goto cleanup;
    }

    /* Get upstream connection to Azure AD token endpoint */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_error("[azure workload identity] could not get an upstream connection");
        goto cleanup;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        body, flb_sds_len(body),
                        ctx->host, atoi(ctx->port), NULL, 0);
    if (!c) {
        flb_error("[azure workload identity] error creating HTTP client context");
        flb_upstream_conn_release(u_conn);
        u_conn = NULL;
        goto cleanup;
    }

    /* Prepare token exchange request headers */
    flb_http_add_header(c, "Content-Type", 12, "application/x-www-form-urlencoded", 33);

    flb_debug("[azure workload identity] sending request body (len=%zu)", flb_sds_len(body));

    /* Issue request */
    ret = flb_http_do(c, &b_sent);

    /* Free body now that the request is sent */
    flb_sds_destroy(body);
    body = NULL;

    if (ret != 0) {
        flb_warn("[azure workload identity] error in HTTP request, http_do=%i", ret);
        ret = -1;
        goto cleanup;
    }

    flb_debug("[azure workload identity] HTTP Status=%i", c->resp.status);

    if (c->resp.payload_size > 0 && c->resp.status == 200) {
        ret = flb_oauth2_parse_json_response(c->resp.payload,
                                             c->resp.payload_size, ctx);
        if (ret == 0) {
            flb_info("[azure workload identity] access token retrieved successfully");
            ctx->expires_at = time(NULL) + ctx->expires_in;
        }
        else {
            flb_error("[azure workload identity] failed to parse token response");
            ret = -1;
        }
    }
    else {
        flb_warn("[azure workload identity] token exchange failed with status %i",
                 c->resp.status);
        ret = -1;
    }

cleanup:
    if (c) {
        flb_http_client_destroy(c);
    }
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }
    if (federated_token) {
        flb_sds_destroy(federated_token);
    }
    if (body) {
        flb_sds_destroy(body);
    }

    return ret;
}

flb_sds_t flb_azure_auth_build_oauth_url(flb_azure_auth_type auth_type,
                                          const char *tenant_id,
                                          const char *client_id,
                                          const char *resource)
{
    flb_sds_t url = NULL;
    size_t url_size;

    switch (auth_type) {
        case FLB_AZURE_AUTH_MANAGED_IDENTITY_SYSTEM:
            /* System-assigned managed identity - no client_id parameter, no .default suffix */
            url_size = sizeof(FLB_AZURE_MSI_AUTH_URL_TEMPLATE) + strlen(resource);
            url = flb_sds_create_size(url_size);
            if (!url) {
                flb_errno();
                return NULL;
            }
            flb_sds_snprintf(&url, flb_sds_alloc(url),
                            FLB_AZURE_MSI_AUTH_URL_TEMPLATE,
                            "", "", resource);
            break;

        case FLB_AZURE_AUTH_MANAGED_IDENTITY_USER:
            /* User-assigned managed identity - include client_id parameter, no .default suffix */
            if (!client_id) {
                flb_error("[azure auth] client_id required for user-assigned managed identity");
                return NULL;
            }
            url_size = sizeof(FLB_AZURE_MSI_AUTH_URL_TEMPLATE) +
                       sizeof("&client_id=") + strlen(client_id) + strlen(resource);
            url = flb_sds_create_size(url_size);
            if (!url) {
                flb_errno();
                return NULL;
            }
            flb_sds_snprintf(&url, flb_sds_alloc(url),
                            FLB_AZURE_MSI_AUTH_URL_TEMPLATE,
                            "&client_id=", client_id, resource);
            break;

        case FLB_AZURE_AUTH_SERVICE_PRINCIPAL:
        case FLB_AZURE_AUTH_WORKLOAD_IDENTITY:
            /* Standard OAuth2 endpoint for Azure AD */
            if (!tenant_id) {
                flb_error("[azure auth] tenant_id required for service principal or workload identity");
                return NULL;
            }
            url_size = sizeof(FLB_AZURE_MSAL_AUTH_URL_TEMPLATE) + strlen(tenant_id);
            url = flb_sds_create_size(url_size);
            if (!url) {
                flb_errno();
                return NULL;
            }
            flb_sds_snprintf(&url, flb_sds_alloc(url),
                            FLB_AZURE_MSAL_AUTH_URL_TEMPLATE, tenant_id);
            break;

        default:
            flb_error("[azure auth] unsupported auth type: %d", auth_type);
            return NULL;
    }

    return url;
}
