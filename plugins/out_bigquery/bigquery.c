/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_oauth2.h>

#include <msgpack.h>

#include "bigquery.h"
#include "bigquery_conf.h"
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>

// TODO: The following code is copied from the Stackdriver plugin and should be
//       factored into common library functions.

/*
 * Base64 Encoding in JWT must:
 *
 * - remove any trailing padding '=' character
 * - replace '+' with '-'
 * - replace '/' with '_'
 *
 * ref: https://www.rfc-editor.org/rfc/rfc7515.txt Appendix C
 */
int bigquery_jwt_base64_url_encode(unsigned char *out_buf, size_t out_size,
                          unsigned char *in_buf, size_t in_size,
                          size_t *olen)

{
    int i;
    size_t len;

    /* do normal base64 encoding */
    mbedtls_base64_encode(out_buf, out_size - 1,
                          &len, in_buf, in_size);

    /* Replace '+' and '/' characters */
    for (i = 0; i < len && out_buf[i] != '='; i++) {
        if (out_buf[i] == '+') {
            out_buf[i] = '-';
        }
        else if (out_buf[i] == '/') {
            out_buf[i] = '_';
        }
    }

    /* Now 'i' becomes the new length */
    *olen = i;
    return 0;
}

static int bigquery_jwt_encode(struct flb_bigquery *ctx,
                               char *payload, char *secret,
                               char **out_signature, size_t *out_size)
{
    int ret;
    int len;
    int buf_size;
    size_t olen;
    char *buf;
    char *sigd;
    char *headers = "{\"alg\": \"RS256\", \"typ\": \"JWT\"}";
    unsigned char sha256_buf[32] = {0};
    mbedtls_sha256_context sha256_ctx;
    mbedtls_rsa_context *rsa;
    flb_sds_t out;
    mbedtls_pk_context pk_ctx;
    unsigned char sig[256] = {0};

    buf_size = (strlen(payload) + strlen(secret)) * 2;
    buf = flb_malloc(buf_size);
    if (!buf) {
        flb_errno();
        return -1;
    }

    /* Encode header */
    len = strlen(headers);
    mbedtls_base64_encode((unsigned char *) buf, buf_size - 1,
                          &olen, (unsigned char *) headers, len);

    /* Create buffer to store JWT */
    out = flb_sds_create_size(2048);
    if (!out) {
        flb_errno();
        flb_free(buf);
        return -1;
    }

    /* Append header */
    out = flb_sds_cat(out, buf, olen);
    out = flb_sds_cat(out, ".", 1);

    /* Encode Payload */
    len = strlen(payload);
    bigquery_jwt_base64_url_encode((unsigned char *) buf, buf_size,
                          (unsigned char *) payload, len, &olen);

    /* Append Payload */
    out = flb_sds_cat(out, buf, olen);

    /* do sha256() of base64(header).base64(payload) */
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (const unsigned char *) out,
                          flb_sds_len(out));
    mbedtls_sha256_finish(&sha256_ctx, sha256_buf);

    /* In mbedTLS cert length must include the null byte */
    len = strlen(secret) + 1;

    /* Load Private Key */
    mbedtls_pk_init(&pk_ctx);
    ret = mbedtls_pk_parse_key(&pk_ctx,
                               (unsigned char *) secret, len, NULL, 0);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error loading private key");
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    /* Create RSA context */
    rsa = mbedtls_pk_rsa(pk_ctx);
    if (!rsa) {
        flb_plg_error(ctx->ins, "error creating RSA context");
        flb_free(buf);
        flb_sds_destroy(out);
        mbedtls_pk_free(&pk_ctx);
        return -1;
    }

    ret = mbedtls_rsa_pkcs1_sign(rsa, NULL, NULL,
                                 MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                 0, (unsigned char *) sha256_buf, sig);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "error signing SHA256");
        flb_free(buf);
        flb_sds_destroy(out);
        mbedtls_pk_free(&pk_ctx);
        return -1;
    }

    sigd = flb_malloc(2048);
    if (!sigd) {
        flb_errno();
        flb_free(buf);
        flb_sds_destroy(out);
        mbedtls_pk_free(&pk_ctx);
        return -1;
    }

    bigquery_jwt_base64_url_encode((unsigned char *) sigd, 2048, sig, 256, &olen);

    out = flb_sds_cat(out, ".", 1);
    out = flb_sds_cat(out, sigd, olen);

    *out_signature = out;
    *out_size = flb_sds_len(out);

    flb_free(buf);
    flb_free(sigd);
    mbedtls_pk_free(&pk_ctx);

    return 0;
}

/* Create a new oauth2 context and get a oauth2 token */
static int bigquery_get_oauth2_token(struct flb_bigquery *ctx)
{
    int ret;
    char *token;
    char *sig_data;
    size_t sig_size;
    time_t issued;
    time_t expires;
    char payload[1024];

    /* JWT encode for oauth2 */
    issued = time(NULL);
    expires = issued + FLB_BIGQUERY_TOKEN_REFRESH;

    snprintf(payload, sizeof(payload) - 1,
             "{\"iss\": \"%s\", \"scope\": \"%s\", "
             "\"aud\": \"%s\", \"exp\": %lu, \"iat\": %lu}",
             ctx->oauth_credentials->client_email, FLB_BIGQUERY_SCOPE,
             FLB_BIGQUERY_AUTH_URL,
             expires, issued);

    /* Compose JWT signature */
    ret = bigquery_jwt_encode(ctx, payload, ctx->oauth_credentials->private_key,
                              &sig_data, &sig_size);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "JWT signature generation failed");
        return -1;
    }

    flb_plg_debug(ctx->ins, "JWT signature:\n%s", sig_data);

    /* Create oauth2 context */
    ctx->o = flb_oauth2_create(ctx->config, FLB_BIGQUERY_AUTH_URL, 3000);
    if (!ctx->o) {
        flb_sds_destroy(sig_data);
        flb_plg_error(ctx->ins, "cannot create oauth2 context");
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o,
                                    "grant_type", -1,
                                    "urn:ietf:params:oauth:"
                                    "grant-type:jwt-bearer", -1);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        flb_sds_destroy(sig_data);
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o,
                                    "assertion", -1,
                                    sig_data, sig_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error appending oauth2 params");
        flb_sds_destroy(sig_data);
        return -1;
    }
    flb_sds_destroy(sig_data);

    /* Retrieve access token */
    token = flb_oauth2_token_get(ctx->o);
    if (!token) {
        flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
        return -1;
    }

    return 0;
}

static char *get_google_token(struct flb_bigquery *ctx)
{
    int ret = 0;

    flb_plg_trace(ctx->ins, "getting google token");
    if (!ctx->o) {
        flb_plg_trace(ctx->ins, "acquiring new token");
        ret = bigquery_get_oauth2_token(ctx);
    }
    else if (flb_oauth2_token_expired(ctx->o) == FLB_TRUE) {
        flb_plg_trace(ctx->ins, "replacing expired token");
        flb_oauth2_destroy(ctx->o);
        ret = bigquery_get_oauth2_token(ctx);
    }

    if (ret != 0) {
        return NULL;
    }

    return ctx->o->access_token;
}


static int cb_bigquery_init(struct flb_output_instance *ins,
                            struct flb_config *config, void *data)
{
    char *token;
    int io_flags = FLB_IO_TLS;
    struct flb_bigquery *ctx;

    /* Create config context */
    ctx = flb_bigquery_conf_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }

    flb_output_set_context(ins, ctx);

    /* Network mode IPv6 */
    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /*
     * Create upstream context for BigQuery Streaming Inserts
     * (no oauth2 service)
     */
    ctx->u = flb_upstream_create_url(config, FLB_BIGQUERY_URL_BASE,
                                     io_flags, ins->tls);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "upstream creation failed");
        return -1;
    }

    /* Retrief oauth2 token */
    token = get_google_token(ctx);
    if (!token) {
        flb_plg_warn(ctx->ins, "token retrieval failed");
    }

    return 0;
}

static int bigquery_format(const void *data, size_t bytes,
                           const char *tag, size_t tag_len,
                           char **out_data, size_t *out_size,
                           struct flb_bigquery *ctx)
{
    int array_size = 0;
    size_t off = 0;
    struct flb_time tms;
    flb_sds_t out_buf;
    msgpack_object *obj;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    /* Count number of records */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        array_size++;
    }
    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Pack root map (kind & rows):
     *
     * {"kind": "bigquery#tableDataInsertAllRequest"
     *  "rows": []
     */
    msgpack_pack_map(&mp_pck, 2);

    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "kind", 4);

    msgpack_pack_str(&mp_pck, 34);
    msgpack_pack_str_body(&mp_pck, "bigquery#tableDataInsertAllRequest", 34);

    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "rows", 4);

    /* Append entries */
    msgpack_pack_array(&mp_pck, array_size);

    off = 0;
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /* Get timestamp */
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        /*
         * Pack entry
         *
         * {
         *  "json": {...}
         * }
         *
         * For now, we don't support the insertId that's required for duplicate detection.
         */
        msgpack_pack_map(&mp_pck, 1);

        /* json */
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "json", 4);
        msgpack_pack_object(&mp_pck, *obj);
    }

    /* Convert from msgpack to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!out_buf) {
        flb_plg_error(ctx->ins, "error formatting JSON payload");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    *out_data = out_buf;
    *out_size = flb_sds_len(out_buf);

    return 0;
}

static void set_authorization_header(struct flb_http_client *c,
                                     char *token)
{
    int len;
    char header[512];

    len = snprintf(header, sizeof(header) - 1,
                   "Bearer %s", token);
    flb_http_add_header(c, "Authorization", 13, header, len);
}

static void cb_bigquery_flush(const void *data, size_t bytes,
                              const char *tag, int tag_len,
                              struct flb_input_instance *i_ins,
                              void *out_context,
                              struct flb_config *config)
{
    (void) i_ins;
    (void) config;
    int ret;
    int ret_code = FLB_RETRY;
    size_t b_sent;
    char *token;
    flb_sds_t payload_buf;
    size_t payload_size;
    struct flb_bigquery *ctx = out_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;

    flb_plg_trace(ctx->ins, "flushing bytes %zu", bytes);

    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Reformat msgpack to bigquery JSON payload */
    ret = bigquery_format(data, bytes, tag, tag_len,
                          &payload_buf, &payload_size, ctx);
    if (ret != 0) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Get or renew Token */
    token = get_google_token(ctx);
    if (!token) {
        flb_plg_error(ctx->ins, "cannot retrieve oauth2 token");
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(payload_buf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        payload_buf, payload_size, NULL, 0, NULL, 0);

    flb_http_buffer_size(c, 4192);

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);

    /* Compose and append Authorization header */
    set_authorization_header(c, token);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* validate response */
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        ret_code = FLB_RETRY;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_plg_debug(ctx->ins, "HTTP Status=%i", c->resp.status);
        if (c->resp.status == 200) {
            ret_code = FLB_OK;
        }
        else {
            if (c->resp.payload_size > 0) {
                /* we got an error */
                flb_plg_warn(ctx->ins, "error\n%s",
                             c->resp.payload);
            }
            else {
                flb_plg_debug(ctx->ins, "response\n%s",
                              c->resp.payload);
            }
            ret_code = FLB_RETRY;
        }
    }

    /* Cleanup */
    flb_sds_destroy(payload_buf);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    /* Done */
    FLB_OUTPUT_RETURN(ret_code);
}

static int cb_bigquery_exit(void *data, struct flb_config *config)
{
    struct flb_bigquery *ctx = data;

    if (!ctx) {
        return -1;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_bigquery_conf_destroy(ctx);
    return 0;
}

struct flb_output_plugin out_bigquery_plugin = {
    .name         = "bigquery",
    .description  = "Send events to BigQuery via streaming insert",
    .cb_init      = cb_bigquery_init,
    .cb_flush     = cb_bigquery_flush,
    .cb_exit      = cb_bigquery_exit,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS,
};
