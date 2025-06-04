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
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_base64.h>
#include <fluent-bit/flb_crypto.h>
#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_json.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/rsa.h>

#include "gcs.h"

/* JWT creation for service account authentication */
static flb_sds_t gcs_create_jwt(struct flb_gcs *ctx, const char *private_key,
                                const char *client_email)
{
    flb_sds_t jwt = NULL;
    flb_sds_t header = NULL;
    flb_sds_t payload = NULL;
    flb_sds_t signature = NULL;
    flb_sds_t header_b64 = NULL;
    flb_sds_t payload_b64 = NULL;
    flb_sds_t signature_b64 = NULL;
    flb_sds_t unsigned_jwt = NULL;
    char *encoded = NULL;
    size_t encoded_len;
    time_t now;
    time_t exp;
    int ret;

    /* Create JWT header */
    header = flb_sds_create_size(256);
    if (!header) {
        return NULL;
    }
    
    header = flb_sds_printf(&header, 
                           "{\"alg\":\"RS256\",\"typ\":\"JWT\"}");

    /* Create JWT payload */
    now = time(NULL);
    exp = now + 3600; /* 1 hour expiration */
    
    payload = flb_sds_create_size(512);
    if (!payload) {
        goto error;
    }
    
    payload = flb_sds_printf(&payload,
                            "{"
                            "\"iss\":\"%s\","
                            "\"scope\":\"%s\","
                            "\"aud\":\"https://oauth2.googleapis.com/token\","
                            "\"iat\":%ld,"
                            "\"exp\":%ld"
                            "}",
                            client_email,
                            FLB_GCS_SCOPE,
                            now,
                            exp);

    /* Base64 encode header and payload */
    ret = flb_base64_encode((unsigned char *) header, flb_sds_len(header),
                           &encoded, &encoded_len);
    if (ret == -1) {
        goto error;
    }
    header_b64 = flb_sds_create_len(encoded, encoded_len);
    flb_free(encoded);
    encoded = NULL;
    
    if (!header_b64) {
        goto error;
    }

    ret = flb_base64_encode((unsigned char *) payload, flb_sds_len(payload),
                           &encoded, &encoded_len);
    if (ret == -1) {
        goto error;
    }
    payload_b64 = flb_sds_create_len(encoded, encoded_len);
    flb_free(encoded);
    encoded = NULL;
    
    if (!payload_b64) {
        goto error;
    }

    /* Create unsigned JWT */
    unsigned_jwt = flb_sds_create_size(flb_sds_len(header_b64) + 
                                      flb_sds_len(payload_b64) + 2);
    if (!unsigned_jwt) {
        goto error;
    }
    
    unsigned_jwt = flb_sds_printf(&unsigned_jwt, "%s.%s", header_b64, payload_b64);

    /* Sign the JWT using RS256 */
    ret = flb_crypto_sign_simple(FLB_CRYPTO_SIGN_RSA_SHA256,
                                (unsigned char *) unsigned_jwt,
                                flb_sds_len(unsigned_jwt),
                                (unsigned char *) private_key,
                                strlen(private_key),
                                &encoded, &encoded_len);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to sign JWT");
        goto error;
    }

    signature_b64 = flb_sds_create_len(encoded, encoded_len);
    flb_free(encoded);
    
    if (!signature_b64) {
        goto error;
    }

    /* Create final JWT */
    jwt = flb_sds_create_size(flb_sds_len(unsigned_jwt) + 
                             flb_sds_len(signature_b64) + 2);
    if (!jwt) {
        goto error;
    }
    
    jwt = flb_sds_printf(&jwt, "%s.%s", unsigned_jwt, signature_b64);

    goto cleanup;

error:
    if (jwt) {
        flb_sds_destroy(jwt);
        jwt = NULL;
    }

cleanup:
    if (header) flb_sds_destroy(header);
    if (payload) flb_sds_destroy(payload);
    if (header_b64) flb_sds_destroy(header_b64);
    if (payload_b64) flb_sds_destroy(payload_b64);
    if (signature_b64) flb_sds_destroy(signature_b64);
    if (unsigned_jwt) flb_sds_destroy(unsigned_jwt);
    if (encoded) flb_free(encoded);

    return jwt;
}

/* Parse service account JSON file */
static int gcs_parse_credentials_file(struct flb_gcs *ctx,
                                      char **client_email,
                                      char **private_key)
{
    char *data;
    size_t data_size;
    struct flb_parser *parser;
    msgpack_object root;
    msgpack_object_kv *kv;
    int i;
    int ret;

    /* Read credentials file */
    ret = flb_file_read(ctx->credentials_file, &data, &data_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Cannot read credentials file: %s",
                      ctx->credentials_file);
        return -1;
    }

    /* Parse JSON */
    ret = flb_json_tokenise(data, data_size, &root);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Invalid JSON in credentials file");
        flb_free(data);
        return -1;
    }

    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "Credentials file must contain JSON object");
        flb_free(data);
        return -1;
    }

    /* Extract client_email and private_key */
    *client_email = NULL;
    *private_key = NULL;

    for (i = 0; i < root.via.map.size; i++) {
        kv = &root.via.map.ptr[i];
        
        if (kv->key.type != MSGPACK_OBJECT_STR ||
            kv->val.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (strncmp(kv->key.via.str.ptr, "client_email", 
                   kv->key.via.str.size) == 0) {
            *client_email = flb_strndup(kv->val.via.str.ptr, 
                                       kv->val.via.str.size);
        }
        else if (strncmp(kv->key.via.str.ptr, "private_key", 
                        kv->key.via.str.size) == 0) {
            *private_key = flb_strndup(kv->val.via.str.ptr, 
                                      kv->val.via.str.size);
        }
    }

    flb_free(data);

    if (!*client_email || !*private_key) {
        flb_plg_error(ctx->ins, "Missing client_email or private_key in credentials");
        if (*client_email) {
            flb_free(*client_email);
            *client_email = NULL;
        }
        if (*private_key) {
            flb_free(*private_key);
            *private_key = NULL;
        }
        return -1;
    }

    return 0;
}

/* Service account authentication */
static int gcs_service_account_auth(struct flb_gcs *ctx)
{
    char *client_email = NULL;
    char *private_key = NULL;
    flb_sds_t jwt = NULL;
    flb_sds_t payload = NULL;
    struct flb_http_client *c = NULL;
    struct flb_upstream_conn *u_conn = NULL;
    int ret = -1;

    /* Parse credentials file */
    ret = gcs_parse_credentials_file(ctx, &client_email, &private_key);
    if (ret == -1) {
        return -1;
    }

    /* Create JWT */
    jwt = gcs_create_jwt(ctx, private_key, client_email);
    if (!jwt) {
        flb_plg_error(ctx->ins, "Failed to create JWT");
        goto cleanup;
    }

    /* Create OAuth2 token request payload */
    payload = flb_sds_create_size(512 + flb_sds_len(jwt));
    if (!payload) {
        goto cleanup;
    }
    
    payload = flb_sds_printf(&payload,
                            "grant_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Ajwt-bearer"
                            "&assertion=%s",
                            jwt);

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u_oauth);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "Failed to get OAuth upstream connection");
        goto cleanup;
    }

    /* Create HTTP request */
    c = flb_http_client(ctx->u_oauth, FLB_HTTP_POST, "/token",
                        payload, flb_sds_len(payload),
                        NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "Failed to create HTTP client for OAuth");
        goto cleanup;
    }

    /* Add headers */
    flb_http_add_header(c, "Content-Type", 12,
                       "application/x-www-form-urlencoded", 33);
    flb_http_add_header(c, "Host", 4, FLB_GCS_TOKEN_HOST, 
                       strlen(FLB_GCS_TOKEN_HOST));

    /* Send request */
    ret = flb_http_do(c, &u_conn);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to send OAuth request");
        goto cleanup;
    }

    /* Check response */
    if (c->resp.status != 200) {
        flb_plg_error(ctx->ins, "OAuth request failed with status %d: %.*s",
                      c->resp.status, (int)c->resp.payload_size, c->resp.payload);
        ret = -1;
        goto cleanup;
    }

    /* Parse response to extract access token */
    ret = flb_oauth2_parse_response(ctx->oauth2, c->resp.payload, 
                                   c->resp.payload_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to parse OAuth response");
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (client_email) flb_free(client_email);
    if (private_key) flb_free(private_key);
    if (jwt) flb_sds_destroy(jwt);
    if (payload) flb_sds_destroy(payload);
    if (c) flb_http_client_destroy(c);
    if (u_conn) flb_upstream_conn_release(u_conn);

    return ret;
}

/* Metadata server authentication for ADC */
static int gcs_metadata_server_auth(struct flb_gcs *ctx)
{
    struct flb_http_client *c = NULL;
    struct flb_upstream *u_metadata = NULL;
    struct flb_upstream_conn *u_conn = NULL;
    int ret = -1;

    /* Create upstream for metadata server */
    u_metadata = flb_upstream_create(ctx->config, "metadata.google.internal", 80,
                                    FLB_IO_TCP, NULL);
    if (!u_metadata) {
        flb_plg_error(ctx->ins, "Failed to create metadata server upstream");
        return -1;
    }

    /* Get connection */
    u_conn = flb_upstream_conn_get(u_metadata);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "Failed to connect to metadata server");
        goto cleanup;
    }

    /* Request access token from metadata server */
    c = flb_http_client(u_metadata, FLB_HTTP_GET,
                        "/computeMetadata/v1/instance/service-accounts/default/token"
                        "?scopes=" FLB_GCS_SCOPE,
                        NULL, 0, NULL, 0, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "Failed to create metadata HTTP client");
        goto cleanup;
    }

    /* Add required metadata header */
    flb_http_add_header(c, "Metadata-Flavor", 15, "Google", 6);

    /* Send request */
    ret = flb_http_do(c, &u_conn);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to request token from metadata server");
        goto cleanup;
    }

    /* Check response */
    if (c->resp.status != 200) {
        flb_plg_error(ctx->ins, "Metadata server request failed with status %d",
                      c->resp.status);
        ret = -1;
        goto cleanup;
    }

    /* Parse response */
    ret = flb_oauth2_parse_response(ctx->oauth2, c->resp.payload, 
                                   c->resp.payload_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Failed to parse metadata server response");
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (c) flb_http_client_destroy(c);
    if (u_conn) flb_upstream_conn_release(u_conn);
    if (u_metadata) flb_upstream_destroy(u_metadata);

    return ret;
}

/* Main token refresh function */
int gcs_oauth2_token_refresh(struct flb_gcs *ctx)
{
    int ret;

    if (!ctx->oauth2) {
        flb_plg_error(ctx->ins, "OAuth2 context not initialized");
        return -1;
    }

    /* Choose authentication method based on configuration */
    switch (ctx->auth_type) {
    case FLB_GCS_AUTH_SERVICE_ACCOUNT:
        ret = gcs_service_account_auth(ctx);
        break;
    case FLB_GCS_AUTH_ADC:
        ret = gcs_metadata_server_auth(ctx);
        break;
    case FLB_GCS_AUTH_WORKLOAD_ID:
        /* TODO: Implement Workload Identity authentication */
        flb_plg_error(ctx->ins, "Workload Identity not yet implemented");
        ret = -1;
        break;
    default:
        flb_plg_error(ctx->ins, "Unknown authentication type: %d", ctx->auth_type);
        ret = -1;
    }

    if (ret == 0) {
        /* Update cached token information */
        char *token = flb_oauth2_token_get_property(ctx->oauth2, "access_token");
        time_t expires = flb_oauth2_token_get_expires(ctx->oauth2);

        if (ctx->access_token) {
            flb_sds_destroy(ctx->access_token);
        }
        
        if (token) {
            ctx->access_token = flb_sds_create(token);
            ctx->token_expires = expires;
            
            flb_plg_debug(ctx->ins, "Access token refreshed, expires in %ld seconds",
                          expires - time(NULL));
        }
        else {
            flb_plg_error(ctx->ins, "No access token in response");
            ret = -1;
        }
    }

    return ret;
}