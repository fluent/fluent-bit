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
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_aws_util.h>

#include "s3.h"
#include "s3_auth.h"

struct url_parts {
    char *scheme;
    char *host;
    char *port;
    char *uri;
};

static void url_parts_destroy(struct url_parts *parts)
{
    if (!parts) {
        return;
    }

    if (parts->scheme) {
        flb_free(parts->scheme);
    }
    if (parts->host) {
        flb_free(parts->host);
    }
    if (parts->port) {
        flb_free(parts->port);
    }
    if (parts->uri) {
        flb_free(parts->uri);
    }
}

static int parse_url(struct flb_s3 *ctx, const char *url, struct url_parts *parts)
{
    int ret;

    memset(parts, 0, sizeof(struct url_parts));

    ret = flb_utils_url_split(url, &parts->scheme, &parts->host,
                              &parts->port, &parts->uri);
    if (ret == -1) {
        url_parts_destroy(parts);
        flb_plg_error(ctx->ins, "Invalid URL: %s", url);
        return -1;
    }

    if (!parts->host || !parts->uri) {
        url_parts_destroy(parts);
        flb_plg_error(ctx->ins, "Invalid URL (missing host or path): %s", url);
        return -1;
    }

    return 0;
}

int s3_auth_init_endpoint(struct flb_s3 *ctx)
{
    struct url_parts parts;
    struct flb_upstream *upstream = NULL;
    struct flb_tls *tls_context = NULL;
    int ret;

    ctx->authorization_endpoint_upstream = NULL;
    ctx->authorization_endpoint_tls_context = NULL;

    ret = parse_url(ctx, ctx->authorization_endpoint_url, &parts);
    if (ret == -1) {
        return -1;
    }

    /* Determine if HTTPS is used */
    int use_https = (parts.scheme && strcasecmp(parts.scheme, "https") == 0);
    int io_flags = use_https ? FLB_IO_TLS : FLB_IO_TCP;

    /* Create TLS context only for HTTPS endpoints */
    if (use_https) {
        tls_context = flb_tls_create(FLB_TLS_CLIENT_MODE, FLB_TRUE, FLB_FALSE,
                                     parts.host, NULL, NULL, NULL, NULL, NULL);
        if (!tls_context) {
            flb_plg_error(ctx->ins, "TLS context creation error");
            url_parts_destroy(&parts);
            return -1;
        }
    }

    upstream = flb_upstream_create_url(ctx->ins->config,
                                       ctx->authorization_endpoint_url,
                                       io_flags, tls_context);
    if (!upstream) {
        flb_plg_error(ctx->ins, "Upstream creation error");
        if (tls_context) {
            flb_tls_destroy(tls_context);
        }
        url_parts_destroy(&parts);
        return -1;
    }

    flb_output_upstream_set(upstream, ctx->ins);

    ctx->authorization_endpoint_upstream = upstream;
    ctx->authorization_endpoint_tls_context = tls_context;

    url_parts_destroy(&parts);
    return 0;
}

static uint16_t get_port_from_url(const char *scheme, const char *port_str)
{
    if (port_str) {
        char *endptr;
        unsigned long port_val;

        errno = 0;
        port_val = strtoul(port_str, &endptr, 10);

        /* Validate conversion: must convert entire string, no overflow, valid port range */
        if (endptr != port_str && *endptr == '\0' &&
            errno != ERANGE && port_val >= 1 && port_val <= 65535) {
            return (uint16_t) port_val;
        }

        /* Conversion failed, fall back to scheme-based default */
    }

    if (scheme && strcasecmp(scheme, "https") == 0) {
        return 443;
    }

    return 80;
}

static int setup_http_client_headers(struct flb_s3 *ctx,
                                      struct flb_http_client *client)
{
    flb_http_add_header(client, "Accept", 6, "text/plain", 10);
    flb_http_add_header(client, "User-Agent", 10, "Fluent-Bit", 10);

    if (ctx->authorization_endpoint_username &&
        ctx->authorization_endpoint_password) {
        flb_http_basic_auth(client, ctx->authorization_endpoint_username,
                           ctx->authorization_endpoint_password);
    }
    else if (ctx->authorization_endpoint_bearer_token) {
        flb_http_bearer_auth(client, ctx->authorization_endpoint_bearer_token);
    }

    return 0;
}

int s3_auth_request_presigned_url(struct flb_s3 *ctx,
                                   flb_sds_t *result_url,
                                   char *url)
{
    struct url_parts parts;
    struct flb_connection *connection = NULL;
    struct flb_http_client *http_client = NULL;
    uint16_t port;
    size_t b_sent;
    flb_sds_t tmp;
    int ret;

    ret = parse_url(ctx, url, &parts);
    if (ret == -1) {
        return -1;
    }

    port = get_port_from_url(parts.scheme, parts.port);

    connection = flb_upstream_conn_get(ctx->authorization_endpoint_upstream);
    if (!connection) {
        flb_plg_error(ctx->ins, "Cannot create connection");
        ret = -1;
        goto cleanup;
    }

    http_client = flb_http_client(connection, FLB_HTTP_GET, parts.uri,
                                  NULL, 0, parts.host, (int) port, NULL, 0);
    if (!http_client) {
        flb_plg_error(ctx->ins, "Cannot create HTTP client");
        ret = -1;
        goto cleanup;
    }

    setup_http_client_headers(ctx, http_client);

    ret = flb_http_do(http_client, &b_sent);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Error sending configuration request");
        goto cleanup;
    }

    if (http_client->resp.status != 200) {
        if (http_client->resp.payload_size > 0) {
            flb_plg_error(ctx->ins,
                         "Pre-signed URL retrieval failed with status %i\n%s",
                         http_client->resp.status, http_client->resp.payload);
        }
        else {
            flb_plg_error(ctx->ins,
                         "Pre-signed URL retrieval failed with status %i",
                         http_client->resp.status);
        }
        ret = -1;
        goto cleanup;
    }

    flb_plg_info(ctx->ins, "Pre-signed URL retrieved successfully");

    if (*result_url) {
        tmp = flb_sds_copy(*result_url, http_client->resp.payload,
                          http_client->resp.payload_size);
    }
    else {
        tmp = flb_sds_create_len(http_client->resp.payload,
                                http_client->resp.payload_size);
    }

    if (!tmp) {
        flb_plg_error(ctx->ins, "Pre-signed URL duplication error");
        ret = -1;
        goto cleanup;
    }

    *result_url = tmp;
    ret = 0;

cleanup:
    if (http_client) {
        flb_http_client_destroy(http_client);
    }
    if (connection) {
        flb_upstream_conn_release(connection);
    }
    url_parts_destroy(&parts);

    return ret;
}

static flb_sds_t build_presigned_url_path(struct flb_s3 *ctx,
                                           int url_type,
                                           const char *s3_key,
                                           const char *upload_id,
                                           int part_number)
{
    flb_sds_t encoded_key = NULL;
    flb_sds_t encoded_id = NULL;
    flb_sds_t path = NULL;
    flb_sds_t tmp;

    encoded_key = flb_aws_uri_encode_path(s3_key, strlen(s3_key));
    if (!encoded_key) {
        flb_plg_error(ctx->ins, "Failed to URL encode S3 key: %s", s3_key);
        return NULL;
    }

    if (upload_id) {
        encoded_id = flb_aws_uri_encode_path(upload_id, strlen(upload_id));
        if (!encoded_id) {
            flb_plg_error(ctx->ins, "Failed to URL encode upload_id");
            flb_sds_destroy(encoded_key);
            return NULL;
        }
    }

    path = flb_sds_create_size(512);
    if (!path) {
        flb_errno();
        goto error;
    }

    /* Strip leading '/' from encoded_key if present */
    const char *key_to_use = encoded_key;
    if (encoded_key[0] == '/') {
        key_to_use = encoded_key + 1;
    }

    switch (url_type) {
    case S3_PRESIGNED_URL_CREATE_MULTIPART:
        tmp = flb_sds_printf(&path, "/multipart_creation_presigned_url/%s/%s",
                            ctx->bucket, key_to_use);
        break;

    case S3_PRESIGNED_URL_UPLOAD_PART:
        if (!encoded_id) {
            goto error;
        }
        tmp = flb_sds_printf(&path, "/multipart_upload_presigned_url/%s/%s/%s/%d",
                            ctx->bucket, key_to_use, encoded_id, part_number);
        break;

    case S3_PRESIGNED_URL_COMPLETE_MULTIPART:
        if (!encoded_id) {
            goto error;
        }
        tmp = flb_sds_printf(&path, "/multipart_complete_presigned_url/%s/%s/%s",
                            ctx->bucket, key_to_use, encoded_id);
        break;

    case S3_PRESIGNED_URL_ABORT_MULTIPART:
        if (!encoded_id) {
            goto error;
        }
        tmp = flb_sds_printf(&path, "/multipart_abort_presigned_url/%s/%s/%s",
                            ctx->bucket, key_to_use, encoded_id);
        break;

    default:
        flb_plg_error(ctx->ins, "Unknown URL type: %d", url_type);
        goto error;
    }

    if (!tmp) {
        goto error;
    }

    flb_sds_destroy(encoded_key);
    if (encoded_id) {
        flb_sds_destroy(encoded_id);
    }

    return tmp;

error:
    if (path) {
        flb_sds_destroy(path);
    }
    if (encoded_key) {
        flb_sds_destroy(encoded_key);
    }
    if (encoded_id) {
        flb_sds_destroy(encoded_id);
    }
    return NULL;
}

int s3_auth_fetch_presigned_url(struct flb_s3 *ctx,
                                 flb_sds_t *result_url,
                                 int url_type,
                                 const char *s3_key,
                                 const char *upload_id,
                                 int part_number)
{
    flb_sds_t url_path = NULL;
    flb_sds_t full_url = NULL;
    flb_sds_t tmp = NULL;
    int ret;

    if (!ctx->authorization_endpoint_url) {
        *result_url = NULL;
        return 0;
    }

    if (!ctx->authorization_endpoint_upstream) {
        flb_plg_error(ctx->ins, "Authorization endpoint upstream not initialized");
        return -1;
    }

    url_path = build_presigned_url_path(ctx, url_type, s3_key, upload_id, part_number);
    if (!url_path) {
        return -1;
    }

    full_url = flb_sds_create_size(
        flb_sds_len(ctx->authorization_endpoint_url) + flb_sds_len(url_path) + 1);
    if (!full_url) {
        flb_sds_destroy(url_path);
        return -1;
    }

    /* Ensure exactly one slash between endpoint and path */
    if (ctx->authorization_endpoint_url[flb_sds_len(ctx->authorization_endpoint_url) - 1] == '/'
        && url_path[0] == '/') {
        /* Skip leading slash in url_path to avoid double slash */
        tmp = flb_sds_printf(&full_url, "%s%s",
                             ctx->authorization_endpoint_url, url_path + 1);
    }
    else if (ctx->authorization_endpoint_url[flb_sds_len(ctx->authorization_endpoint_url) - 1] != '/'
             && url_path[0] != '/') {
        /* Add a slash between endpoint and path */
        tmp = flb_sds_printf(&full_url, "%s/%s",
                             ctx->authorization_endpoint_url, url_path);
    }
    else {
        /* Exactly one slash already present */
        tmp = flb_sds_printf(&full_url, "%s%s",
                             ctx->authorization_endpoint_url, url_path);
    }
    if (!tmp) {
        flb_sds_destroy(full_url);
        flb_sds_destroy(url_path);
        return -1;
    }

    ret = s3_auth_request_presigned_url(ctx, result_url, full_url);

    flb_sds_destroy(url_path);
    flb_sds_destroy(full_url);

    return ret;
}
